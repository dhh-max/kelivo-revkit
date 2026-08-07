#!/usr/bin/env python3
"""APK Standalone Runner - 专为 code_runner:run_python 设计
纯Python，零外部依赖，兼容第三方中转站
从同级 standalone_unpacker.py 导入，不依赖包路径

用法:
  python3 standalone_runner.py                          # 自动查找最新上传的APK
  python3 standalone_runner.py /path/to/app.apk         # 指定路径
  python3 standalone_runner.py --json                   # 输出JSON（默认输出自然语言摘要）
  python3 standalone_runner.py --inbox                  # 收件箱模式：批量扫描目录中的APK
"""
import sys, os, json, time

_self_dir = os.path.dirname(os.path.abspath(__file__))
if _self_dir not in sys.path:
    sys.path.insert(0, _self_dir)
from standalone_unpacker import unpack_apk_standalone, _fmt_size, _compact_result, process_inbox, _generate_summary


def auto_find_apk():
    """自动扫描常见目录，返回最新上传的 APK 文件路径（兼容单文件调用）"""
    apks = auto_find_apks(max_n=1)
    return apks[0] if apks else None


def auto_find_apks(max_n=10, out_dir=None, recent_hours=None):
    """自动扫描常见目录，返回**未分析过**的新APK列表（按上传时间倒序。

    Args:
        max_n: 最多返回多少个候选（默认10）
        out_dir: 已分析结果目录；若该目录下已有同名 .analysis.json 则视为已分析，跳过
        recent_hours: 只返回最近N小时内上传的APK；None=不过滤时间

    Returns:
        list[str]: 未分析过的APK路径列表，按时间新→旧
    """
    out_dir = out_dir or DEFAULT_OUT_DIR
    scan_dirs = [
        '/sdcard/Download',
        '/sdcard/MT2/apks',
        '/sdcard/MT2/backup',
        '/sdcard',
        '/home/kelivo-revkit/apk-rev-project',
        '/sdcard/Download/Operit/cleanOnExit',
        '/sdcard/Download/Operit/inbox',
    ]
    candidates = []
    seen = set()
    for d in scan_dirs:
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    if f.lower().endswith('.apk'):
                        fp = os.path.join(d, f)
                        if fp in seen:
                            continue
                        seen.add(fp)
                        candidates.append((os.path.getmtime(fp), fp))
            except:
                pass
    if not candidates:
        for root_dir in ['/sdcard', '/home/kelivo-revkit']:
            for root, dirs, files in os.walk(root_dir):
                for f in files:
                    if f.lower().endswith('.apk'):
                        fp = os.path.join(root, f)
                        if fp in seen:
                            continue
                        seen.add(fp)
                        candidates.append((os.path.getmtime(fp), fp))
                if root.count(os.sep) > 4:
                    dirs.clear()
    if not candidates:
        return []

    # 按时间倒序
    candidates.sort(key=lambda x: -x[0])

    # 过滤：跳过已分析过（out_dir 下已有同名 .analysis.json）
    analyzed = set()
    if os.path.isdir(out_dir):
        try:
            for f in os.listdir(out_dir):
                if f.endswith('.analysis.json'):
                    # 去掉 .analysis.json 后缀 → 得到原始APK的短名
                    base = f[:-len('.analysis.json')]
                    analyzed.add(base)
        except:
            pass
    fresh = []
    for mtime, fp in candidates:
        base = os.path.splitext(os.path.basename(fp))[0]
        if base in analyzed:
            continue  # 已分析，跳过
        if recent_hours is not None and (time.time() - mtime) > recent_hours * 3600:
            break  # 从新到旧，遇到超时的就停
        fresh.append(fp)
        if len(fresh) >= max_n:
            break
    return fresh


DEFAULT_OUT_DIR = '/sdcard/Download/Operit/analyzed'


def _short_apk_name(apk_path):
    """返回安全的APK文件名（不含路径和扩展名）"""
    return os.path.splitext(os.path.basename(apk_path))[0]


def write_result_file(full_result, apk_path, out_dir=None):
    """将全量分析结果写入JSON文件，返回文件路径
    
    Args:
        full_result: 全量分析结果dict
        apk_path: 原始APK路径
        out_dir: 输出目录（默认 DEFAULT_OUT_DIR）
    
    Returns:
        str: 写入的文件路径
    """
    out_dir = out_dir or DEFAULT_OUT_DIR
    os.makedirs(out_dir, exist_ok=True)
    safe = _short_apk_name(apk_path) or 'apk'
    result_path = os.path.join(out_dir, f'{safe}.analysis.json')
    with open(result_path, 'w', encoding='utf-8') as f:
        json.dump(full_result, f, ensure_ascii=False, indent=2)
    return result_path


def analyze_apk(apk_path, mode='quick', output_json=False, write_file=True, out_dir=None):
    """一站式APK分析入口（Operit风格：全量数据落盘，返回精简结果）
    
    Args:
        apk_path: APK文件路径
        mode: quick|social|sdk|full
        output_json: True=返回JSON dict, False=返回自然语言摘要
        write_file: 是否将全量结果写入JSON文件（默认True，避免撑爆上下文）
        out_dir: 结果输出目录（默认 DEFAULT_OUT_DIR）
    
    Returns:
        str 或 dict：取决于 output_json 参数（含文件路径字段）
    """
    # compact=False 拿全量数据用于落盘；对话只输出压缩版，全量不进入上下文
    full = unpack_apk_standalone(apk_path, compact=False)
    r = _compact_result(full) if full.get('success') else full
    if not r.get('success'):
        err = r.get('error', '分析失败')
        return json.dumps({'success': False, 'error': err}, ensure_ascii=False) if output_json else f"❌ 分析失败: {err}"

    # 全量结果写文件（对话不展示，避免上下文污染）
    result_path = None
    if write_file:
        try:
            result_path = write_result_file(full, apk_path, out_dir)
        except Exception as e:
            result_path = None
    
    # 构建精简摘要
    summary = {
        'success': True,
        'apk': os.path.basename(apk_path),
        'package': r.get('manifest', {}).get('package', ''),
        'size': r.get('structure', {}).get('size', 0),
        'size_human': _fmt_size(r.get('structure', {}).get('size', 0)),
        'dex_count': r.get('structure', {}).get('dex_count', 0),
        'so_count': r.get('structure', {}).get('so_count', 0),
        'total_files': r.get('structure', {}).get('total_files', 0),
        'total_classes': r.get('total_classes', 0),
        'obfuscation_level': r.get('obfuscation', {}).get('level', ''),
        'obfuscation_score': r.get('obfuscation', {}).get('score', 0),
        'packers': r.get('packers', []),
        'dangerous_permissions': r.get('dangerous_permissions', []),
        'security_issues': r.get('security_issues', []),
        'result_path': result_path,
    }
    if mode in ('social', 'full'):
        summary['social_login'] = r.get('social_login', {})
    if mode in ('sdk', 'full'):
        summary['sdk_detected'] = r.get('sdk_detected', {})
    if mode == 'full':
        summary['findings'] = r.get('findings', {})
    
    if output_json:
        return summary
    
    # 默认：自然语言摘要 + 文件路径
    text = _generate_summary(r)
    if result_path:
        text += f"\n📄 全量结果已保存: {result_path}"
    return text


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='APK Standalone Analyzer (Operit风格: 全量落盘, 对话输出摘要)')
    parser.add_argument('apk', nargs='?', default=None, help='APK file path (留空则自动查找最新上传的APK)')
    parser.add_argument('--mode', '-m', default='quick',
                        choices=['quick', 'full', 'social', 'sdk'],
                        help='Analysis mode (default: quick)')
    parser.add_argument('--json', '-j', action='store_true',
                        help='输出JSON格式（默认输出自然语言摘要）')
    parser.add_argument('--no-write', action='store_true',
                        help='不写出全量结果文件（默认会写入）')
    parser.add_argument('--out-dir', default=DEFAULT_OUT_DIR,
                        help='全量结果输出目录（默认: /sdcard/Download/Operit/analyzed）')
    parser.add_argument('--inbox', '-i', action='store_true',
                        help='收件箱模式：批量扫描目录中的APK并分析')
    parser.add_argument('--inbox-dir', default='/sdcard/Download/Operit/inbox',
                        help='收件箱目录（默认: /sdcard/Download/Operit/inbox）')
    parser.add_argument('--max-apks', type=int, default=10,
                        help='最多处理APK数量（默认: 10）')
    parser.add_argument('--delete-after', action='store_true',
                        help='分析完成后删除原APK')
    args = parser.parse_args()

    # 收件箱模式
    if args.inbox:
        report = process_inbox(
            inbox_dir=args.inbox_dir,
            output_dir=args.out_dir,
            mode=args.mode,
            max_apks=args.max_apks,
            delete_after=args.delete_after,
            output_json=args.json,
        )
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            for r in report.get('results', []):
                if r.get('success'):
                    print(r.get('summary', ''))
                    print()
            print(f"📊 共处理 {report.get('processed',0)} 个APK, {report.get('errors',0)} 个失败")
        sys.exit(0)

    apk_path = args.apk
    if not apk_path:
        # 批量模式：自动查找所有未分析的新APK，逐个处理
        apks = auto_find_apks(max_n=args.max_apks, out_dir=args.out_dir)
        if not apks:
            msg = '❌ 未找到未分析的新APK文件，请上传或指定路径'
            print(json.dumps({'success': False, 'error': msg}, ensure_ascii=False) if args.json else msg)
            sys.exit(1)
        if args.json:
            results = []
            for apk in apks:
                r = analyze_apk(apk, args.mode, output_json=True,
                                write_file=not args.no_write, out_dir=args.out_dir)
                results.append(r)
            print(json.dumps(results, ensure_ascii=False, indent=2))
        else:
            for i, apk in enumerate(apks):
                if i > 0:
                    print()
                print(f"📦 [{i+1}/{len(apks)}] {os.path.basename(apk)}")
                result = analyze_apk(apk, args.mode, output_json=False,
                                     write_file=not args.no_write, out_dir=args.out_dir)
                print(result)
            print(f"\n📊 共处理 {len(apks)} 个APK")
        sys.exit(0)

    # 单文件模式
    result = analyze_apk(apk_path, args.mode, output_json=args.json,
                         write_file=not args.no_write, out_dir=args.out_dir)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result)