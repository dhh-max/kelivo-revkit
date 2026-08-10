#!/usr/bin/env python3
"""APK Reverse Engineering Engine v2 - CLI (Rich终端UI)"""
import sys, os, json, zipfile, argparse

# 确保能找到 apk_reverse_engine 包
# 无论脚本从哪个目录运行，都定位到包根目录
_here = os.path.dirname(os.path.abspath(__file__))
_pkg_root = os.path.dirname(_here)  # apk_reverse_engine 的上一级
for p in (_pkg_root, '/home', '/home/kelivo-revkit'):
    if p and p not in sys.path:
        sys.path.insert(0, p)

from apk_reverse_engine import *
from apk_reverse_engine import open_apk, get_manifest_info, static_analyze, analyze_full
from apk_reverse_engine.tools.unpacker import APKUnpacker as _APKUnpacker
from apk_reverse_engine.tools.standalone_unpacker import unpack_apk_standalone as _standalone_unpack
from apk_reverse_engine.tools.info_extractor import APKInfoExtractor as _APKInfoExtractor
from apk_reverse_engine.tools.validator import APKValidator as _APKValidator
from apk_reverse_engine.tools.batch import APKBatchProcessor as _APKBatchProcessor

# ── Rich UI ──────────────────────────────────────────────────
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.tree import Tree
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.columns import Columns
from rich.layout import Layout
from rich.text import Text
from rich import box
from rich.markdown import Markdown
from datetime import datetime

console = Console()

# ── 主题系统 ──────────────────────────────────────────────────
"""统一UI主题：所有命令共用这套颜色/风格常量"""

# 色板
C = {
    'primary':   'cyan',
    'success':   'green',
    'warning':   'yellow',
    'danger':    'red',
    'info':      'blue',
    'accent':    'magenta',
    'dim':       'dim',
    'title':     'bold cyan',
    'num':       'bold yellow',
    'highlight': 'bold cyan',
}

# 图标
ICO = {
    'pkg':  '📦',
    'dex':  '📜',
    'so':   '🔧',
    'key':  '🔑',
    'cert': '📝',
    'lock': '🛡️',
    'risk': '⚠️',
    'mag':  '🔍',
    'star': '🎯',
    'gear': '⚙️',
    'ok':   '✅',
    'fail': '❌',
    'warn': '⚠️',
    'info': 'ℹ️',
    'app':  '📱',
    'url':  '🌐',
    'time': '⏱️',
}

def _fmt_size(n):
    for u in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            if u == 'B':
                return f"{n:.0f}B"
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}TB"

def _risk_icon(score):
    return '🔴' if score >= 8 else '🟡' if score >= 5 else '🟢'

def _risk_label(score):
    return '严重' if score >= 8 else '中等' if score >= 5 else '低风险'

def _bool_icon(v):
    return '✅' if v else '❌'

# ── 统一 UI 组件 ─────────────────────────────────────────────

def _header(title, subtitle='', style='cyan'):
    """命令主标题 — 双线面板"""
    text = f'[bold {style}]{title}[/]'
    if subtitle:
        text += f'  [dim]{subtitle}[/]'
    return Panel(text, border_style=style, box=box.DOUBLE)

def _section(title, style='cyan'):
    """章节标题 — 分隔线 + 标题"""
    console.print(f'\n[bold {style}]── {title} ──[/]')

def _kv_table(rows, title='', style='cyan'):
    """键值对表格（无边框, 紧凑）"""
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column('k', style=style, no_wrap=True)
    t.add_column('v')
    for k, v in rows:
        t.add_row(k, str(v))
    if title:
        return _make_panel(t, title, style)
    return t

def _make_table(title, columns, rows, style='cyan'):
    t = Table(title=title, title_style=f'bold {style}', box=box.ROUNDED, border_style=style)
    for i, c in enumerate(columns):
        t.add_column(c, style=style if i == 0 else 'white')
    for r in rows:
        t.add_row(*[str(x) for x in r])
    return t

def _make_panel(content, title='', style='cyan'):
    return Panel(content, title=title, title_align='left', border_style=style, box=box.ROUNDED)

def _success(msg):
    """统一成功提示（紧凑）"""
    console.print(f'  [bold green]✅ {msg}[/]')

def _error(msg):
    """统一错误提示"""
    console.print(f'  [bold red]❌ {msg}[/]')

def _warn(msg):
    console.print(f'  [bold yellow]⚠️ {msg}[/]')

def _info(msg):
    console.print(f'  [bold]{ICO["info"]} {msg}[/]')

def _spacer():
    console.print()

# ── 命令实现 ──────────────────────────────────────────────────

def cmd_inspect(args):
    """APK 基本信息概览"""
    with console.status(f"{ICO['mag']} 正在分析 APK 结构...", spinner="dots"):
        r = static_analyze(args.apk)
    size = _fmt_size(os.path.getsize(args.apk))

    console.print(_header(f"{ICO['pkg']} {os.path.basename(args.apk)}", size))

    info = r.get("manifest", {})
    sdk_info = info.get("sdk", {})
    rows = [
        ('包名', info.get("package", "?")),
        ('版本', f"{sdk_info.get('versionName','?')} (code={sdk_info.get('versionCode','?')})"),
        ('SDK', f"min={sdk_info.get('minSdk','?')}  target={sdk_info.get('targetSdk','?')}"),
        ('文件大小', size),
    ]
    console.print(_kv_table(rows, '📋 基本信息'))

    struct = r.get("structure", {})
    if struct:
        rows2 = [
            ('DEX 文件', str(struct.get("dex_count", 0))),
            ('SO 文件', str(struct.get("so_count", 0))),
            ('资源文件', str(struct.get("res_count", 0))),
            ('总文件数', str(struct.get("total_files", 0))),
        ]
        console.print(_kv_table(rows2, '📁 结构', 'green'))

    abis = r.get("abi_architectures", [])
    if abis:
        _info(f"ABI 架构: {' '.join(abis)}")

    sig = r.get("signature", {})
    if sig:
        v1 = bool(sig.get("v1", False))
        v2 = bool(sig.get("v2", False))
        console.print(f"  [bold]签名:[/]  V1={_bool_icon(v1)}  V2={_bool_icon(v2)}  V3={_bool_icon(bool(sig.get('v3')))}  "
                      f"级别={sig.get('security_level','?')}")

    dex_s = r.get("dex_summary", [])
    if dex_s:
        _section('DEX 摘要', 'yellow')
        for d in dex_s:
            console.print(f"  {ICO['dex']} [cyan]{d.get('name','?')}[/]  classes={d.get('classes',0)}  methods={d.get('methods',0)}  strings={d.get('strings',0)}")

    _spacer()

def cmd_analyze(args):
    """全面分析 APK"""
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), 
                  BarColumn(), console=console) as progress:
        progress.add_task(f"{ICO['mag']} 正在执行全量分析...", total=None)
        r = analyze_full(args.apk)

    sec = r.get("security", {})
    score = sec.get("score", 0)
    icon = _risk_icon(score)
    label = _risk_label(score)
    sev = 'red' if score >= 8 else 'yellow' if score >= 5 else 'green'
    console.print(_header(f"{icon} 安全评分: {score:.1f}/10 ({label})", '', sev))

    size = _fmt_size(r.get("file_size", 0))
    console.print(f"  {ICO['pkg']} [bold cyan]{os.path.basename(r['apk_path'])}[/]  ({size})")

    man = r.get("manifest", {})
    if man:
        sdk_info = man.get("sdk", {})
        perms = man.get("permissions", [])
        rows = [
            ('包名', man.get("package", "?")),
            ('SDK', f"min={sdk_info.get('minSdk','?')} target={sdk_info.get('targetSdk','?')}"),
            ('权限', f"{len(perms)} 项"),
        ]
        console.print(_kv_table(rows, '📋 Manifest'))

    perm_analysis = r.get("permissions", {})
    if perm_analysis:
        dangerous = perm_analysis.get("dangerous", []) or []
        rows = [
            ('🔴 危险权限', str(len(dangerous))),
            ('🟢 正常权限', str(len(perm_analysis.get("normal", [])))),
            ('⚙️ 自定义权限', str(len(perm_analysis.get("custom", [])))),
        ]
        console.print(_kv_table(rows, '🔐 权限分析', 'yellow'))
        if dangerous:
            console.print(Panel("\n".join(f"  • {p}" for p in dangerous[:10]),
                                title="⚠️ 危险权限列表", border_style="red", title_align="left"))

    dex_s = r.get("dex_summary", [])
    if dex_s:
        _section('DEX 文件', 'blue')
        t = _make_table("", ["文件", "大小", "Classes", "Methods", "Strings"], [], 'blue')
        for d in dex_s:
            if "error" in d:
                t.add_row(d["name"], "❌ error", "", "", "")
            else:
                t.add_row(d["name"], _fmt_size(d.get("size", 0)),
                          str(d.get("classes", 0)), str(d.get("methods", 0)),
                          str(d.get("strings", 0)))
        console.print(t)

    obf = r.get("obfuscation", {})
    if obf:
        obf_score = obf.get("score", 0)
        console.print(f"  [bold]混淆检测:[/] {_risk_icon(obf_score)} score={obf_score:.1f}  {obf.get('level','?')}")

    packers = r.get("packers", [])
    if packers:
        console.print(f"  [bold]加固检测:[/] [red]{', '.join(packers)}[/]")
    else:
        console.print(f"  [bold]加固检测:[/] 未检测到加固壳")

    native = r.get("native_analysis", {})
    if native:
        _section(f'SO 文件 ({len(native)} 个)', 'magenta')
        for name, info in native.items():
            if "error" in info:
                console.print(f"  [red]❌ {name}: {info['error']}[/]")
            else:
                console.print(f"  {ICO['so']} [cyan]{name}[/]  arch={info.get('machine','?')}  "
                              f"import={len(info.get('imports',[]))}  export={len(info.get('exports',[]))}")

    if sec:
        details = sec.get("details", [])
        if details:
            _section(f'安全发现 ({len(details)} 项)', 'red')
            for d in details:
                console.print(f"  • {d}")

    # ── SDK 检测 ──
    sdk = r.get("sdk_analysis", {})
    if sdk and 'error' not in sdk:
        sdk_summary = sdk.get('summary', {})
        sdk_count = sdk_summary.get('total_sdks', 0)
        if sdk_count:
            high = sdk_summary.get('high_risk_count', 0)
            trackers = sdk_summary.get('tracker_count', 0)
            risk = sdk.get('privacy_risk', {})
            console.print(f"  [bold]SDK检测:[/] {sdk_count}个SDK  [red]高风险{high}[/]  [yellow]追踪器{trackers}[/]  "
                          f"评分[{'red' if risk.get('risk_level')=='高' else 'yellow'}]{risk.get('risk_score',0)}/100[/]")

    # ── 字符串分析摘要 ──
    sa = r.get("string_analysis", {})
    if sa and 'error' not in sa:
        s = sa.get('summary', {})
        if s.get('has_sensitive') or s.get('has_private_ips'):
            console.print(f"  [bold]字符串分析:[/] [red]敏感信息{s.get('sensitive_count',0)}项[/]  "
                          f"[yellow]内网IP{s.get('private_ip_count',0)}个[/]  "
                          f"URL{s.get('url_count',0)}个  Base64{s.get('base64_count',0)}个")

    # ── 资源混淆摘要 ──
    ro = r.get("resource_obfuscation", {})
    if ro and 'error' not in ro:
        rs = ro.get('summary', {})
        score = rs.get('score', 0)
        level = rs.get('level', '低')
        lc = 'red' if level == '高' else 'yellow' if level == '中' else 'green'
        console.print(f"  [bold]资源混淆:[/] [{lc}]评分{score}/100 ({level})[/]  "
                      f"混淆率{rs.get('obfuscated_ratio',0):.1%}")

    # ── 广告检测摘要 ──
    ad = r.get("ad_analysis", {})
    if ad and 'error' not in ad:
        ad_summary = ad.get('summary', {})
        ad_level = ad_summary.get('level', '无广告')
        ad_score = ad_summary.get('score', 0)
        ad_color = 'red' if ad_level == '密集广告' else 'yellow' if ad_level == '有广告' else 'green'
        ad_sdks = ad_summary.get('ad_sdk_count', 0)
        ad_types = []
        if ad_summary.get('has_banner'): ad_types.append('Banner')
        if ad_summary.get('has_interstitial'): ad_types.append('插屏')
        if ad_summary.get('has_rewarded'): ad_types.append('激励视频')
        if ad_summary.get('has_native'): ad_types.append('原生')
        ad_type_str = f" [{','.join(ad_types)}]" if ad_types else ''
        console.print(f"  [bold]广告检测:[/] [{ad_color}]{ad_level} ({ad_score}/100)[/]  "
                      f"SDK{ad_sdks}个{ad_type_str}")

    _spacer()

def cmd_manifest(args):
    """解析 AndroidManifest.xml"""
    with console.status(f"{ICO['mag']} 解析 Manifest...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            data = ctx.get_manifest_xml()
            info = get_manifest_info(data)

    console.print(_header(f"{ICO['pkg']} {os.path.basename(args.apk)}", "AndroidManifest"))

    sdk_info = info.get("sdk", {})
    rows = [
        ('包名', info.get("package", "?")),
        ('版本', f"{sdk_info.get('versionName','?')} (code={sdk_info.get('versionCode','?')})"),
        ('SDK', f"min={sdk_info.get('minSdk','?')}  target={sdk_info.get('targetSdk','?')}"),
        ('屏幕', f"small={info.get('small_screen','?')} normal={info.get('normal_screen','?')} large={info.get('large_screen','?')} xlarge={info.get('xlarge_screen','?')}"),
    ]
    console.print(_kv_table(rows, '📋 基本信息'))

    perms = info.get("permissions", [])
    if perms:
        _section(f'权限 ({len(perms)})', 'yellow')
        t = _make_table("", ["#", "权限"], [], 'yellow')
        for i, p in enumerate(perms, 1):
            t.add_row(str(i), p)
        console.print(t)

    for comp_type in ["activities", "services", "receivers", "providers"]:
        comps = info.get(comp_type, [])
        if comps:
            labels = {"activities": "🎬 Activity", "services": "⚙️ Service", 
                      "receivers": "📡 BroadcastReceiver", "providers": "🗄️ ContentProvider"}
            _section(f'{labels.get(comp_type, comp_type)} ({len(comps)})', 'green')
            for c in comps:
                if isinstance(c, dict):
                    name = c.get('attrs', {}).get('name', c.get('attrs', {}).get('android:name', '?'))
                else:
                    name = str(c)
                console.print(f"  [cyan]{name}[/]")

    _spacer()

def cmd_dex(args):
    """DEX 文件分析（增强版：头信息/统计/搜索）"""
    from apk_reverse_engine.core.dex_parser import DexParser
    from apk_reverse_engine import dex_header, dex_summary, dex_search_methods, dex_search_classes
    
    with console.status(f"{ICO['dex']} 解析 DEX...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            dex_files = ctx.get_dex_files()
            dex_data = {}
            for d in dex_files:
                dex_data[d] = ctx.read_file(d)

    console.print(_header(f"{ICO['dex']} DEX 文件分析", f"{os.path.basename(args.apk)} | {len(dex_files)} 个 DEX", 'blue'))

    for d, data in dex_data.items():
        with console.status(f"{ICO['dex']} 分析 {d}..."):
            h = dex_header(data)
            summary = dex_summary(data)
        
        # 头信息摘要
        header_rows = [
            ('魔数', h.get('magic', '?')),
            ('校验和', f"0x{h.get('checksum', 0):08x}"),
            ('签名', h.get('signature', '?')[:16] + '...' if len(h.get('signature', '')) > 16 else h.get('signature', '?')),
            ('文件大小', _fmt_size(h.get('file_size', 0))),
            ('链接偏移', f"0x{h.get('link_offset', 0):x}"),
            ('映射偏移', f"0x{h.get('map_offset', 0):x}"),
        ]
        console.print(_kv_table(header_rows, f'{ICO["dex"]} {d} — 头信息', 'blue'))
        
        # 统计摘要
        summary_rows = [
            ('类', str(summary.get('classes', 0))),
            ('方法', str(summary.get('methods', 0))),
            ('字段', str(summary.get('fields', 0))),
            ('字符串', str(summary.get('strings', 0))),
            ('原型', str(summary.get('protos', 0))),
            ('类型', str(summary.get('types', 0))),
        ]
        console.print(_kv_table(summary_rows, '📊 统计', 'yellow'))

        if args.search:
            with console.status(f"{ICO['mag']} 搜索 '{args.search}'..."):
                methods = dex_search_methods(data, args.search)
                classes = dex_search_classes(data, args.search)
            if methods:
                _section(f'方法匹配 ({len(methods)})', 'green')
                t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
                t.add_column("#", style="dim", width=4)
                t.add_column("方法", style="cyan")
                for i, m in enumerate(methods[:20], 1):
                    t.add_row(str(i), m)
                console.print(t)
                if len(methods) > 20:
                    console.print(f"  [dim]... 还有 {len(methods) - 20} 个方法[/]")
            if classes:
                _section(f'类匹配 ({len(classes)})', 'green')
                t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
                t.add_column("#", style="dim", width=4)
                t.add_column("类", style="cyan")
                for i, c in enumerate(classes[:20], 1):
                    t.add_row(str(i), c)
                console.print(t)
                if len(classes) > 20:
                    console.print(f"  [dim]... 还有 {len(classes) - 20} 个类[/]")

    _spacer()

def cmd_classes(args):
    """列出 DEX 类名"""
    with console.status(f"{ICO['dex']} 提取类名...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            dex_classes_data = {}
            for d in ctx.get_dex_files():
                dex_classes_data[d] = ctx.read_file(d)

    for d, data in dex_classes_data.items():
        names = dex_class_names(data)
        total = len(names)
        shown = names[:args.max]

        t = Table(box=box.ROUNDED, border_style="green")
        t.add_column("#", justify="right", style="dim", width=6)
        t.add_column("类名", style="cyan")
        for i, n in enumerate(shown, 1):
            t.add_row(str(i), n)
        console.print(_make_panel(t, f'{ICO["dex"]} {d} ({total} classes)', 'green'))
        if total > args.max:
            console.print(f"  [dim]... 还有 {total - args.max} 个类未显示 (使用 --max 查看更多)[/]")

    _spacer()

def cmd_so(args):
    """分析 SO 文件"""
    with console.status(f"{ICO['so']} 分析 SO 文件...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            so_files = ctx.get_so_files()
            so_data = {}
            for s in so_files:
                so_data[s] = ctx.read_file(s)

    for s, data in so_data.items():
        with console.status(f"{ICO['so']} 分析 {s}..."):
            r = analyze_elf(data)

        if "error" in r:
            _error(f"{s}: {r['error']}")
            continue

        arch = r.get("machine", "?")
        cls = r.get("class", "?")
        endian = r.get("endian", "?")
        entry = r.get("entry", "?")
        sections = r.get("sections", "?")
        segments = r.get("segments", "?")

        rows = [
            ('架构', arch), ('Class', cls), ('字节序', endian),
            ('入口点', entry), ('段数', str(sections)), ('区段数', str(segments)),
        ]
        console.print(_kv_table(rows, f'{ICO["so"]} {s} — ELF 概览', 'magenta'))

        deps = r.get("dependencies", [])
        if deps:
            _section(f'依赖库 ({len(deps)})', 'blue')
            for dep in deps:
                console.print(f"  [cyan]{dep}[/]")

        imports = r.get("imports", [])
        exports = r.get("exports", [])
        if imports or exports:
            ie_table = Table(box=box.SIMPLE)
            ie_table.add_column("方向", style="cyan", width=8)
            ie_table.add_column("函数名", style="white")
            for imp in imports[:30]:
                ie_table.add_row("⬅️ 导入", imp)
            for exp in exports[:20]:
                ie_table.add_row("➡️ 导出", exp)
            console.print(_make_panel(ie_table, '🔌 导入/导出', 'blue'))
            if len(imports) > 30:
                console.print(f"  [dim]... 还有 {len(imports)-30} 个导入[/]")
            if len(exports) > 20:
                console.print(f"  [dim]... 还有 {len(exports)-20} 个导出[/]")

        packers = elf_detect_packer(data)
        if packers:
            _warn(f"加固壳: {', '.join(packers)}")

        crypto = elf_detect_crypto(data)
        if crypto:
            crypto_names = list(crypto.keys()) if isinstance(crypto, dict) else crypto
            _info(f"加密库: {', '.join(crypto_names)}")

    _spacer()

def cmd_search(args):
    """在 APK 中搜索"""
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        progress.add_task(f"{ICO['mag']} 搜索 '{args.query}'...", total=None)
        r = search_apk(args.apk, args.query, args.scope or "all", args.max or 100)

    total = r.get("total", 0)
    if total == 0:
        _warn(f"未找到包含 '{args.query}' 的结果")
        return

    console.print(_header(f"{ICO['mag']} 搜索结果: {total} 项匹配", f"\"{args.query}\"", 'green'))

    for scope_name in ["strings", "classes", "methods"]:
        items = r.get(scope_name, [])
        if not items:
            continue
        icons = {"strings": "📝", "classes": "📦", "methods": "⚙️"}
        t = Table(box=box.ROUNDED, border_style="cyan")
        t.add_column("#", justify="right", style="dim", width=4)
        t.add_column("内容", style="white")
        t.add_column("来源", style="dim")
        for i, item in enumerate(items[:args.max], 1):
            source = item.get("file", "") if isinstance(item, dict) else ""
            content = item.get("match", str(item)) if isinstance(item, dict) else str(item)
            t.add_row(str(i), content, source)
        console.print(_make_panel(t, f"{icons.get(scope_name, '📄')} {scope_name}", 'cyan'))

    _spacer()

def cmd_unpack(args):
    """解压 APK - 全面增强版"""
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID

    # ── 独立模式 (兼容第三方中转站) ──
    if args.standalone:
        with console.status(f"{ICO['pkg']} 独立模式解包中...", spinner="dots"):
            r = _standalone_unpack(args.apk, args.output, mode='full' if not args.dry_run else 'analyze')
        if r.get("success"):
            s = r.get("structure", {})
            rows = [
                ('总文件', str(s.get("total_files", 0))),
                ('DEX', str(s.get("dex_count", 0))),
                ('SO', str(s.get("so_count", 0))),
                ('资源', str(s.get("res_count", 0))),
                ('大小', _fmt_size(s.get("size", 0))),
                ('类数', str(r.get("total_classes", 0))),
                ('加固', ', '.join(r.get("packers", [])) or '无'),
                ('混淆', r.get("obfuscation", {}).get("level", '?')),
                ('输出目录', args.output),
            ]
            if r.get('extracted'):
                rows.insert(0, ('提取文件', str(r['extracted'])))
            console.print(_kv_table(rows, f'{ICO["ok"]} 独立解包: {os.path.basename(args.apk)}', 'green'))
        else:
            _error(f"独立解包失败: {r.get('error', '未知错误')}")
        return

    # 预览模式
    if args.dry_run:
        r = _APKUnpacker.extract_raw(args.apk, args.output, dry_run=True)
        if r.get("success"):
            rows = [
                ('总文件', str(r.get("total", 0))),
                ('DEX', str(r.get("dex_count", 0))),
                ('SO', str(r.get("so_count", 0))),
                ('资源文件', str(r.get("res_count", 0))),
                ('Assets', str(r.get("assets_count", 0))),
                ('大小', _fmt_size(r.get("size", 0))),
                ('输出目录', args.output),
            ]
            console.print(_kv_table(rows, f'{ICO["pkg"]} 预览: {os.path.basename(args.apk)}', 'cyan'))
            return
        _error(f"预览失败: {r.get('error', '未知错误')}")
        return

    # 分类提取
    if args.category:
        cats = [c.strip() for c in args.category.split(',')]
        with console.status(f"{ICO['pkg']} 按分类提取 {', '.join(cats)}..."):
            r = _APKUnpacker.extract_by_category(args.apk, args.output, categories=cats,
                                                  structure=args.structure)
        if r.get("success"):
            rows = [(cat, str(cnt)) for cat, cnt in sorted(r.get('categories', {}).items())]
            console.print(_kv_table(rows, f'{ICO["ok"]} 分类提取: {args.output}', 'green'))
        else:
            _error(f"提取失败: {r.get('error', '未知错误')}")
        return

    # 带进度条的实际解压
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=20),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task(f"{ICO['pkg']} 解压中...", total=None)

        def _progress(extracted, total, name):
            t = progress.tasks[task]
            if t.completed == 0 and total:
                progress.update(task, total=total)
            progress.update(task, completed=extracted, description=f"{ICO['pkg']} {os.path.basename(name)}")

        if args.parallel:
            r = _APKUnpacker.extract_parallel(args.apk, args.output, args.workers, structure=args.structure)
        elif args.incremental:
            r = _APKUnpacker.extract_incremental(args.apk, args.output, structure=args.structure,
                                                  flatten=args.flatten)
        elif args.manifest:
            import json
            with open(args.manifest, 'r') as fh:
                manifest_data = json.load(fh)
            r = _APKUnpacker.extract_manifest(args.apk, args.output,
                                              manifest=manifest_data,
                                              structure=args.structure,
                                              fail_on_missing=not args.no_fail_missing,
                                              verify=not args.no_verify)
        elif args.include or args.exclude:
            r = _APKUnpacker.extract_selective(args.apk, args.output,
                                  include_types=args.include.split(',') if args.include else None,
                                  exclude_types=args.exclude.split(',') if args.exclude else None,
                                  structure=args.structure)
        else:
            r = _APKUnpacker.extract_raw(args.apk, args.output, structure=args.structure,
                                          flatten=args.flatten, progress_callback=_progress)

    # 结果展示
    if r.get("success") or r.get('extracted', 0) > 0 or r.get('skipped', 0) > 0:
        rows = [('提取文件', f"{r.get('extracted', 0)}/{r.get('total', '?')}")]
        if r.get('skipped'):
            rows.append(('跳过(增量)', str(r.get('skipped', 0))))
        cats = r.get('categories', {})
        if cats:
            rows.append(("分类统计", ", ".join(f"{k}={v}" for k, v in sorted(cats.items()))))
        if r.get('sha256'):
            rows.append(("SHA256", r['sha256'][:16] + '...'))
        if r.get('verified') is not None:
            rows.append(("校验通过", f"{r.get('verified')}/{r.get('total', '?')} (SHA256)"))
        if r.get('missing'):
            rows.append(("清单缺失", ", ".join(r['missing'][:3])))
        errors = r.get('errors', [])
        if errors:
            rows.append(("错误", f"{len(errors)} 个: {', '.join(e['file'] for e in errors[:3])}"))
        console.print(_kv_table(rows, f'{ICO["ok"]} 解压: {args.output}', 'green'))
    else:
        _error(f"解压失败: {r.get('error', '未知错误')}")

def cmd_verify(args):
    """校验解压完整性"""
    with console.status(f"{ICO['mag']} 校验完整性..."):
        r = _APKUnpacker.verify_integrity(args.apk, args.output)
    ok = r.get('ok', False)
    rows = [
        ('原始文件', str(r.get('original', 0))),
        ('解压文件', str(r.get('extracted', 0))),
        ('缺失', str(r.get('missing', 0))),
        ('总大小', _fmt_size(r.get('size', 0))),
        ('SHA256', r.get('sha256', '')),
    ]
    console.print(_kv_table(rows, f"{'✅ 完整性校验通过' if ok else '❌ 文件缺失'}", 'green' if ok else 'red'))

def cmd_decode(args):
    """Apktool 解包"""
    with console.status(f"{ICO['gear']} Apktool 解包中..."):
        r = apktool_decode(args.apk, args.output, args.force or False)
    if r.get("success"):
        rows = [
            ('输入', args.apk),
            ('输出', args.output),
            ('大小', _fmt_size(os.path.getsize(args.apk)) if os.path.exists(args.apk) else '?'),
        ]
        if os.path.isdir(args.output):
            file_count = sum(len(files) for _, _, files in os.walk(args.output))
            rows.append(('文件数', str(file_count)))
        console.print(_kv_table(rows, f'{ICO["ok"]} Apktool 解包完成', 'green'))
    else:
        _error(f"解包失败: {r.get('error', '未知错误')}")

def cmd_build(args):
    """Apktool 重打包"""
    with console.status(f"{ICO['gear']} Apktool 重打包中..."):
        r = apktool_build(args.input, args.output, args.force or False)
    if r.get("success"):
        out_size = _fmt_size(os.path.getsize(args.output)) if os.path.exists(args.output) else '?'
        rows = [
            ('输入', args.input),
            ('输出', args.output),
            ('大小', out_size),
        ]
        console.print(_kv_table(rows, f'{ICO["ok"]} Apktool 重打包完成', 'green'))
    else:
        _error(f"重打包失败: {r.get('error', '未知错误')}")

def cmd_sign(args):
    """签名 APK"""
    with console.status(f"{ICO['cert']} 签名中..."):
        r = sign_debug(args.apk, args.output)
    if r.get("success"):
        rows = [
            ('输入', args.apk),
            ('输出', args.output),
            ('密钥', 'debug.keystore (Android 默认调试密钥)'),
            ('大小', _fmt_size(os.path.getsize(args.output)) if os.path.exists(args.output) else '?'),
        ]
        if r.get('signature_info'):
            rows.append(('签名方案', r['signature_info']))
        console.print(_kv_table(rows, f'{ICO["ok"]} 签名完成', 'green'))
        _warn("调试签名仅用于测试，发布请使用正式证书签名")
    else:
        _error(f"签名失败: {r.get('error', '未知错误')}")

def cmd_jadx(args):
    """JADX 反编译"""
    with console.status(f"{ICO['gear']} JADX 反编译中..."):
        r = jadx_decompile(args.apk, args.output, deobf=not args.no_deobf)
    if r.get("success"):
        rows = [
            ('输入', args.apk),
            ('输出', args.output),
            ('反混淆', '✅ 已启用' if not args.no_deobf else '❌ 已禁用'),
        ]
        if os.path.isdir(args.output):
            file_count = sum(len(files) for _, _, files in os.walk(args.output))
            rows.append(('Java 源文件数', str(file_count)))
        console.print(_kv_table(rows, f'{ICO["ok"]} JADX 反编译完成', 'green'))
    else:
        _error(f"反编译失败: {r.get('error', '未知错误')}")

def cmd_clue(args):
    """线索串联分析 - 自动发现跨模块可疑信号"""
    with console.status(f"{ICO['mag']} 线索串联分析中...", spinner="dots"):
        r = analyze_full(args.apk)
        cc = r.get("clue_chain", {})

    if "error" in cc:
        _error(f"线索分析异常: {cc['error']}")
        return

    score = cc.get("score", 0)
    level = cc.get("level", "low")
    level_color = {"high": "red", "medium": "yellow", "low": "green"}
    level_icon = {"high": ICO['risk'], "medium": "⚡", "low": ICO['ok']}
    clr = level_color.get(level, "white")
    icon = level_icon.get(level, "?")

    console.print(_header(f"{icon} 综合风险评分: {score}/100 ({level.upper()})", '', clr))

    summary = cc.get("summary", {})
    if summary:
        rows = [
            ('结论', f"[{clr}]{summary.get('conclusion', '?')}[/]"),
            ('风险标记', str(summary.get('risk_count', 0))),
            ('线索统计', summary.get('clue_summary', '?')),
        ]
        tags = summary.get('tags', [])
        if tags:
            rows.append(('特征标签', ", ".join(f"[bold]{t}[/]" for t in tags)))
        console.print(_kv_table(rows, '📊 分析总结', clr))

    clues = cc.get("clues", [])
    if clues:
        _section(f'发现 {len(clues)} 条线索', 'blue')
        sev_color = {"high": "red", "medium": "yellow", "info": "blue", "low": "green"}
        sev_icon = {"high": "🔴", "medium": "🟡", "info": "🔵", "low": "🟢"}
        for i, clue in enumerate(clues, 1):
            sev = clue.get("severity", "info")
            sc = sev_color.get(sev, "white")
            si = sev_icon.get(sev, "•")
            title = clue.get("title", "?")
            detail = clue.get("detail", "")
            cross = clue.get("cross_ref", [])
            text = Text()
            text.append(f"  {si} ", style=sc)
            text.append(f"[{i}] ", style="dim")
            text.append(title, style=f"bold {sc}")
            if detail:
                text.append(f"\n     {detail}")
            if cross:
                refs = ", ".join(str(c) for c in cross[:5])
                text.append(f"\n     [dim]关联: {refs}[/]")
            console.print(text)
            _spacer()

    risks = cc.get("risks", [])
    if risks:
        _section(f'风险标记 ({len(risks)} 项)', 'red')
        for r in risks:
            console.print(f"  • [red]{r}[/]")

    _spacer()

def cmd_merge(args):
    """合并多个APK或合并DEX"""
    if args.dex:
        with console.status(f"{ICO['gear']} 合并 DEX 文件..."):
            r = merge_dex(args.apk, args.output)
        if r.get("success"):
            rows = [
                ('输入', args.apk),
                ('输出', args.output),
                ('消息', r.get('message', '')),
            ]
            if os.path.exists(args.output):
                rows.append(('大小', _fmt_size(os.path.getsize(args.output))))
            console.print(_kv_table(rows, f'{ICO["ok"]} DEX 合并完成', 'green'))
        else:
            _error(f"DEX 合并失败: {r.get('error', '未知错误')}")
    else:
        apks = args.apk.split(',')
        with console.status(f"{ICO['gear']} 合并 {len(apks)} 个 APK..."):
            r = merge_apks(apks, args.output)
        if r.get("success"):
            rows = [
                ('输入', f"{len(apks)} 个 APK"),
                ('输出', args.output),
                ('合并文件数', str(r.get('files_merged', 0))),
            ]
            if os.path.exists(args.output):
                rows.append(('大小', _fmt_size(os.path.getsize(args.output))))
            console.print(_kv_table(rows, f'{ICO["ok"]} APK 合并完成', 'green'))
        else:
            _error(f"合并失败: {r.get('error', '未知错误')}")

def cmd_rebuild(args):
    """从目录重建APK (ZIP打包)"""
    with console.status(f"{ICO['pkg']} 重建 APK 从 {args.input}..."):
        r = zip_rebuild(args.input, args.output, args.store and zipfile.ZIP_STORED or zipfile.ZIP_DEFLATED)
    if r.get("success"):
        rows = [
            ('输入', args.input),
            ('输出', args.output),
            ('压缩模式', 'STORED (不压缩)' if args.store else 'DEFLATED (压缩)'),
        ]
        if os.path.exists(args.output):
            rows.append(('大小', _fmt_size(os.path.getsize(args.output))))
            # 统计输入目录文件数
            file_count = sum(len(files) for _, _, files in os.walk(args.input))
            rows.append(('文件数', str(file_count)))
        console.print(_kv_table(rows, f'{ICO["ok"]} 重建完成', 'green'))
    else:
        _error(f"重建失败: {r.get('error', '未知错误')}")

def cmd_zipalign(args):
    """对齐APK"""
    with console.status(f"{ICO['gear']} 对齐 {args.apk}..."):
        r = zipalign(args.apk, args.output)
    if r.get("success"):
        rows = [
            ('输入', args.apk),
            ('输出', args.output),
        ]
        if os.path.exists(args.output):
            in_size = os.path.getsize(args.apk) if os.path.exists(args.apk) else 0
            out_size = os.path.getsize(args.output)
            saved = in_size - out_size
            rows.append(('输入大小', _fmt_size(in_size)))
            rows.append(('输出大小', _fmt_size(out_size)))
            rows.append(('节省空间', f"[green]{_fmt_size(saved)}[/]" if saved >= 0 else f"[red]{_fmt_size(abs(saved))} (增加)[/]"))
        console.print(_kv_table(rows, f'{ICO["ok"]} 对齐完成 (4字节对齐)', 'green'))
    else:
        _error(f"对齐失败: {r.get('error', '未知错误')}")

def cmd_convert(args):
    """格式转换 (DEX↔JAR / DEX↔Smali)"""
    from apk_reverse_engine import dex2jar, jar2dex, dex2smali, smali2dex
    op_map = {'dex2jar': 'DEX→JAR', 'jar2dex': 'JAR→DEX', 'dex2smali': 'DEX→Smali', 'smali2dex': 'Smali→DEX'}
    label = op_map.get(args.type, args.type)
    with console.status(f"{ICO['gear']} {label}..."):
        fn = {'dex2jar': dex2jar, 'jar2dex': jar2dex, 'dex2smali': dex2smali, 'smali2dex': smali2dex}[args.type]
        r = fn(args.input, args.output)
    if r.get("success"):
        rows = [
            ('转换类型', label),
            ('输入', args.input),
            ('输出', args.output),
        ]
        if os.path.exists(args.output):
            rows.append(('大小', _fmt_size(os.path.getsize(args.output))))
        if r.get('classes_count'):
            rows.append(('类数', str(r['classes_count'])))
        console.print(_kv_table(rows, f'{ICO["ok"]} {label} 完成', 'green'))
    else:
        _error(f"转换失败: {r.get('error', '未知错误')}")

def cmd_patch(args):
    """原生 SO 补丁"""
    with console.status(f"{ICO['gear']} 执行 {args.type} 补丁..."):
        with open(args.apk, 'rb') as f:
            data = f.read()
        if args.type == 'hex':
            data = native_patch_hex(data, args.old, args.new)
            desc = f"hex: {args.old} -> {args.new}"
        elif args.type == 'string':
            data = native_patch_string(data, args.old, args.new)
            desc = f"string: {args.old} -> {args.new}"
        elif args.type == 'ret':
            data = native_patch_ret(data, int(args.offset, 0), args.arch or 'aarch64')
            desc = f"ret @ {args.offset}"
        elif args.type == 'nop':
            data = native_nop_out(data, int(args.offset, 0), int(args.count or 4))
            desc = f"nop x{args.count} @ {args.offset}"
        safe_write(args.output, data)

    rows = [('类型', args.type), ('操作', desc), ('输出', args.output), ('大小', _fmt_size(len(data)))]
    console.print(_kv_table(rows, f'{ICO["gear"]} 补丁结果', 'green'))

# ── 增强逆向新功能 ──────────────────────────────────────

def cmd_diff(args):
    """对比两个APK差异"""
    with console.status(f"{ICO['mag']} 对比APK差异中...", spinner="dots"):
        r1 = analyze_full(args.apk1)
        r2 = analyze_full(args.apk2)
        m1 = r1.get("manifest", {})
        m2 = r2.get("manifest", {})
        perms1 = [p.split('.')[-1] if '.' in p else p for p in m1.get("permissions", [])]
        perms2 = [p.split('.')[-1] if '.' in p else p for p in m2.get("permissions", [])]
        classes1 = []
        classes2 = []
        with open_apk(args.apk1) as ctx:
            for d in ctx.get_dex_files():
                from apk_reverse_engine import dex_class_names
                classes1.extend(dex_class_names(ctx.read_file(d)))
        with open_apk(args.apk2) as ctx:
            for d in ctx.get_dex_files():
                from apk_reverse_engine import dex_class_names
                classes2.extend(dex_class_names(ctx.read_file(d)))
        r = compare_apks(args.apk1, args.apk2, m1, m2, classes1, classes2, perms1, perms2)

    if args.json:
        console.print(json.dumps(r, indent=2, ensure_ascii=False, default=str))
        return

    console.print(_header(f"{ICO['mag']} {os.path.basename(args.apk1)} vs {os.path.basename(args.apk2)}", "APK 差异对比"))

    summary = r.get("summary", {})
    level = summary.get("change_level", "?")
    clr = {"微小": "green", "中等": "yellow", "显著": "red", "重大": "red"}.get(level, "white")
    _info(f"变更等级: [{clr}]{level}[/]  |  变更总数: {summary.get('total_changes', 0)}")

    sz = r.get("structure", {}).get("size", {})
    if sz:
        diff = sz.get('diff_raw', 0)
        diff_str = f"+{_fmt_size(diff)}" if diff > 0 else _fmt_size(diff)
        rows = [
            ('原始大小', _fmt_size(sz.get('old_raw', 0)), _fmt_size(sz.get('new_raw', 0))),
            ('压缩大小', _fmt_size(sz.get('old_compressed', 0)), _fmt_size(sz.get('new_compressed', 0))),
            ('差异', f"[{'red' if diff>0 else 'green'}]{diff_str}[/]", ""),
        ]
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("指标", style="cyan")
        t.add_column("旧", justify="right")
        t.add_column("新", justify="right")
        for row in rows:
            t.add_row(*row)
        console.print(_make_panel(t, "📊 大小对比", "green"))

    files = r.get("structure", {}).get("files", {})
    if files:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("类别", style="cyan")
        t.add_column("数量", justify="right")
        t.add_row("旧文件总数", str(files.get('total_old', 0)))
        t.add_row("新文件总数", str(files.get('total_new', 0)))
        t.add_row("新增文件", f"[green]+{len(files.get('added', []))}[/]")
        t.add_row("删除文件", f"[red]-{len(files.get('removed', []))}[/]")
        t.add_row("修改文件", f"[yellow]{len(files.get('modified', []))}[/]")
        t.add_row("未变更", str(files.get('unchanged', 0)))
        console.print(_make_panel(t, "📁 文件变更", "yellow"))
        _render_diff_panels(files, ['added', 'removed', 'modified'])

    man_diffs = r.get("manifest", [])
    if man_diffs:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("字段", style="cyan")
        t.add_column("旧值", style="red")
        t.add_column("新值", style="green")
        for d in man_diffs:
            t.add_row(d['field'], str(d.get('old', '?')), str(d.get('new', '?')))
        console.print(_make_panel(t, "📋 Manifest 变更", "blue"))

    perm_diff = r.get("permissions", {})
    if perm_diff:
        if perm_diff.get('added'):
            _info(f"新增权限 ({len(perm_diff['added'])}): {' '.join(perm_diff['added'][:10])}")
        if perm_diff.get('removed'):
            _warn(f"移除权限 ({len(perm_diff['removed'])}): {' '.join(perm_diff['removed'][:10])}")

    cls_diff = r.get("classes", {})
    if cls_diff:
        _info(f"类统计: 新增 [green]{len(cls_diff.get('added', []))}[/] 移除 [red]{len(cls_diff.get('removed', []))}[/] 共同 {cls_diff.get('common_count', 0)}")

    _spacer()

def _render_diff_panels(files, keys):
    """渲染差异文件面板"""
    styles = {'added': ('green', '➕'), 'removed': ('red', '➖'), 'modified': ('yellow', '✏️')}
    labels = {'added': '新增文件', 'removed': '删除文件', 'modified': '修改文件'}
    for key in keys:
        items = files.get(key, [])
        if not items:
            continue
        style, icon = styles.get(key, ('white', '•'))
        lines = []
        for item in items[:15]:
            if key == 'modified':
                m = item
                lines.append(f"  [{style}]{icon} {m['file']} ({_fmt_size(m['old_size'])} → {_fmt_size(m['new_size'])})[/]")
            else:
                lines.append(f"  [{style}]{icon} {item}[/]")
        console.print(_make_panel("\n".join(lines), f"{labels.get(key, key)} ({len(items)})", style))

def cmd_endpoints(args):
    """从DEX中提取网络端点"""
    with console.status(f"{ICO['url']} 提取网络端点...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            all_strings = []
            for d in ctx.get_dex_files():
                from apk_reverse_engine import dex_strings
                all_strings.extend(dex_strings(ctx.read_file(d)))
        r = extract_endpoints(all_strings)

    if args.json:
        console.print(json.dumps(r, indent=2, ensure_ascii=False, default=str))
        return

    console.print(_header(f"{ICO['url']} {os.path.basename(args.apk)}", "网络端点分析"))

    proto = r.get("protocols", {})
    urls = r.get("urls", [])
    domains = r.get("domains", [])
    public_ips = r.get("public_ips", [])
    private_ips = r.get("private_ips", [])
    api_paths = r.get("api_paths", [])
    ports = r.get("ports", [])

    summary_rows = [
        ('URL', str(len(urls))),
        ('域名', str(len(domains))),
        ('公网IP', str(len(public_ips))),
        ('API路径', str(len(api_paths))),
        ('端口', str(len(ports))),
        ('HTTP', str(proto.get('http_only', 0))),
        ('HTTPS', str(proto.get('https_only', 0))),
        ('不安全比例', f"[{'red' if proto.get('insecure_ratio',0)>10 else 'green'}]{proto.get('insecure_ratio',0)}%[/]"),
    ]
    console.print(_kv_table(summary_rows, '📊 端点概览', 'cyan'))

    if urls:
        console.print(_make_panel("\n".join(f"  {u}" for u in urls[:20]),
                                   f"📝 URL ({len(urls)})", 'blue'))
    if domains:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("标记", style="cyan", width=6)
        t.add_column("域名", style="white")
        for d in domains[:20]:
            tag = ""
            if d in r.get("cloud_hosts", []):
                tag = "☁️"
            elif d in r.get("cdn_hosts", []):
                tag = "🚀"
            elif d in r.get("internal_hosts", []):
                tag = "🔒"
            t.add_row(tag, d)
        console.print(_make_panel(t, f"🌐 域名 ({len(domains)})", 'cyan'))
    if public_ips:
        _info(f"公网IP ({len(public_ips)}): {' '.join(public_ips[:10])}")
    if api_paths:
        console.print(_make_panel("\n".join(f"  {p}" for p in api_paths[:20]),
                                   f"🔗 API路径 ({len(api_paths)})", 'magenta'))
    if ports:
        _info(f"端口: {', '.join(ports[:15])}")

    _spacer()

def cmd_keyscan(args):
    """扫描DEX中的硬编码密钥"""
    with console.status(f"{ICO['key']} 扫描密钥...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            all_strings = []
            for d in ctx.get_dex_files():
                from apk_reverse_engine import dex_strings
                all_strings.extend(dex_strings(ctx.read_file(d)))
        r = scan_keys(all_strings)
        weak_crypto = detect_weak_crypto(all_strings)

    if args.json:
        console.print(json.dumps(r, indent=2, ensure_ascii=False, default=str))
        return

    summary = r.get("summary", {})
    total = summary.get("total", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    risk_score = summary.get("risk_score", 0)
    risk_level = summary.get("risk_level", "低风险")
    clr = {"严重": "red", "中等": "yellow", "低风险": "green"}.get(risk_level, "white")

    console.print(_header(f"{ICO['key']} 密钥扫描: {risk_score}/100 ({risk_level})",
                          f"发现 {total} 项 (高危={high} 中危={medium})", clr))

    keys = r.get("keys", [])
    if keys:
        _section(f'敏感信息 ({len(keys)} 项)', 'yellow')
        sev_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "INFO": "🔵"}
        for k in keys[:30]:
            icon = sev_icon.get(k.get("severity", "INFO"), "•")
            console.print(f"  {icon} [bold]{k['category']}[/] [dim]{k['match'][:80]}[/]")
        if len(keys) > 30:
            console.print(f"  [dim]... 还有 {len(keys)-30} 项[/]")

    if weak_crypto:
        _section('弱加密告警', 'red')
        for w in weak_crypto:
            console.print(f"  • {w}")

    _spacer()

def cmd_cert(args):
    """深度分析签名证书"""
    with console.status(f"{ICO['cert']} 分析签名证书...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            sig = verify_signature(ctx.zip, args.apk)
            cert_info = sig.get("cert_info", {})
            cert_analysis = analyze_cert_deep(cert_info)

    if "error" in cert_analysis:
        _error(cert_analysis['error'])
        return

    # 签名方案概览
    v1, v2, v3 = bool(sig.get('v1', False)), bool(sig.get('v2', False)), bool(sig.get('v3', False))
    rows = [
        ('V1', _bool_icon(v1)), ('V2', _bool_icon(v2)), ('V3', _bool_icon(v3)),
        ('安全等级', sig.get('security_level', '?')),
    ]
    console.print(_kv_table(rows, f'{ICO["cert"]} 签名证书分析', 'cyan'))

    # 证书信息
    t_rows = [
        ('签发者', cert_analysis.get('issuer_str', '?')),
        ('主体', cert_analysis.get('subject_str', '?')),
        ('序列号', cert_analysis.get('serial', '?')),
    ]
    validity = cert_analysis.get('validity', {})
    if validity:
        t_rows.append(('有效期', f"{validity.get('not_before', '?')} → {validity.get('not_after', '?')}"))
    console.print(_kv_table(t_rows, '📋 证书信息', 'blue'))

    # 风险评分
    risk_score = cert_analysis.get('risk_score', 0)
    risk_level = cert_analysis.get('risk_level', '?')
    clr = {"安全": "green", "低风险": "yellow", "中风险": "red", "高风险": "red"}.get(risk_level, "white")
    _info(f"风险评分: [{clr}]{risk_score}/100 ({risk_level})[/]")
    for issue in cert_analysis.get('issues', []):
        console.print(f"  {issue}")
    for finding in cert_analysis.get('findings', []):
        console.print(f"  {finding}")

    _spacer()

def cmd_clean(args):
    """APK清理优化"""
    if not args.dry_run and args.output:
        with console.status(f"{ICO['pkg']} 清理APK中..."):
            r = clean_apk(args.apk, args.output, args.remove_debug, args.remove_meta, remove_backup=True)
        if r.get("success"):
            rows = [
                ('保留文件', str(r.get('kept', 0))),
                ('移除文件', str(r.get('removed', 0))),
                ('节省空间', _fmt_size(r.get('removed_size', 0))),
                ('压缩率', f"{r.get('saved_percent', 0)}%"),
            ]
            console.print(_kv_table(rows, f'{ICO["ok"]} 清理: {args.output}', 'green'))
            return

    with console.status(f"{ICO['pkg']} 分析APK冗余文件..."):
        r = analyze_apk_clean(args.apk)

    sz = r.get("size", 0)
    waste = r.get("total_waste", 0)
    level = r.get("clean_potential", {}).get("level", "?")
    clr = {"优秀": "green", "良好": "blue", "一般": "yellow", "需优化": "red"}.get(level, "white")

    rows = [
        ('APK大小', _fmt_size(sz)),
        ('可回收', f"[{'red' if waste>0 else 'green'}]{_fmt_size(waste)}[/]"),
        ('优化等级', f"[{clr}]{level}[/]"),
    ]
    console.print(_kv_table(rows, f'{ICO["pkg"]} APK清理分析', clr))

    debug_files = r.get("debug_files", [])
    if debug_files:
        _section(f'调试/测试文件 ({len(debug_files)})', 'red')
        for f in debug_files[:10]:
            console.print(f"  [red]🗑️ {f['file']} ({_fmt_size(f['size'])})[/]")

    large = r.get("large_files", [])
    if large:
        t = Table(box=box.SIMPLE)
        t.add_column("文件", style="cyan")
        t.add_column("大小", justify="right")
        for f in large[:10]:
            t.add_row(f['file'], _fmt_size(f['size']))
        console.print(_make_panel(t, f"大文件 Top {len(large[:10])}", 'yellow'))

    for rec in r.get("recommendations", []):
        ps = rec.get('potential_saving', '')
        if isinstance(ps, (int, float)):
            ps = _fmt_size(ps)
        console.print(f"  💡 [bold]{rec['type']}:[/] {rec['detail']} [dim](可节省: {ps})[/]")

    if not args.dry_run and not args.output:
        console.print(f"  [dim]💡 使用 reng clean {args.apk} output.apk 执行清理[/]")

    _spacer()

# ── AXML 解码/编码 ──────────────────────────────────────

def cmd_axml(args):
    """AXML 反编译/编译 (Android Binary XML ↔ 文本XML)"""
    from apk_reverse_engine.utils.axml_converter import AXMLConverter as _AXMLC

    action_labels = {
        'decode': 'AXML 解码',
        'encode': 'AXML 编码',
        'decode-apk': 'APK Manifest 解码',
        'encode-apk': 'APK Manifest 编码替换',
    }
    label = action_labels.get(args.action, args.action)

    if args.action == 'encode-apk':
        with open(args.xml_path, 'r', encoding='utf-8') as f:
            xml_text = f.read()
        r = _AXMLC.encode_apk_manifest(args.input, args.output, xml_text)
    else:
        fn = {'decode': _AXMLC.decode_file, 'encode': _AXMLC.encode_file,
              'decode-apk': _AXMLC.decode_apk_manifest}[args.action]
        r = fn(args.input, args.output)

    if isinstance(r, dict) and 'error' in r:
        _error(f"{label}失败: {r['error']}")
    else:
        _success(f"{label}: {r['output']}  ({_fmt_size(r['size'])} 字节)")
        if args.action == 'encode-apk':
            _warn("替换后请重新签名APK")

# ── 核心类定位 ──────────────────────────────────────────────

def cmd_core(args):
    """定位 DEX 中的核心类（多维度启发式评分）"""
    from apk_reverse_engine.analysis.core_class_locator import CoreClassLocator
    from collections import Counter

    # 自动检测应用包名（从 Manifest）
    app_package = args.app_package or ''
    with console.status("🔬 分析 DEX 核心类...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            # 尝试从 Manifest 读取包名
            if not app_package:
                try:
                    man_data = ctx.get_manifest_xml()
                    man_info = get_manifest_info(man_data)
                    app_package = man_info.get('package', '')
                except Exception as e:
                    from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/cli.py:1289 suppressed: %s", e)
                    pass

            dex_files = ctx.get_dex_files()
            all_results = []
            per_dex = {}
            # 用于自动检测应用包名前缀的计数器
            all_non_sdk_prefixes = Counter()

            for dex_name in dex_files:
                try:
                    data = ctx.read_file(dex_name)
                    from apk_reverse_engine.core.dex_parser import DexParser
                    parser = DexParser(data)
                    locator = CoreClassLocator(parser)
                    classes = locator.locate(top_n=args.max, min_score=args.min_score,
                                             include_sdk=args.include_sdk)

                    # 收集非 SDK 类的顶级包前缀
                    class_defs = parser.get_class_defs()
                    for c in class_defs:
                        name = c['class_name']
                        if not locator.is_known_sdk(name):
                            # 提取前两个包段作为前缀统计
                            parts = name.lstrip('L').split('/')
                            if len(parts) >= 2:
                                prefix = f"{parts[0]}.{parts[1]}"
                                all_non_sdk_prefixes[prefix] += 1

                    for c in classes:
                        c['dex_file'] = dex_name
                        c['is_app_class'] = False
                    per_dex[dex_name] = classes
                    all_results.extend(classes)
                except Exception as e:
                    per_dex[dex_name] = {'error': str(e)}

            # 自动检测应用包前缀（取出现次数最多的非SDK顶级包）
            # 有时 Manifest 包名与实际代码包名不一致，需要自动检测
            auto_package = ''
            if all_non_sdk_prefixes:
                top_prefixes = all_non_sdk_prefixes.most_common(5)
                for prefix, count in top_prefixes:
                    pkg_dot = prefix.replace('/', '.')
                    # 检查是否包含在 Manifest 声明的组件类中
                    is_manifest_match = False
                    try:
                        man_data = ctx.get_manifest_xml()
                        man_info = get_manifest_info(man_data)
                        for comp_type in ['activities', 'services', 'receivers', 'providers']:
                            for comp in man_info.get(comp_type, []):
                                if isinstance(comp, dict):
                                    comp_name = comp.get('attrs', {}).get('name', '')
                                    if comp_name.startswith(pkg_dot) or comp_name.startswith('.' + prefix.split('.')[-1]):
                                        is_manifest_match = True
                                        break
                    except Exception as e:
                        from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/cli.py:1345 suppressed: %s", e)
                        pass
                    if is_manifest_match or count > 10:
                        auto_package = pkg_dot
                        break

                # 如果没找到，取最常见的
                if not auto_package and top_prefixes:
                    auto_package = top_prefixes[0][0].replace('/', '.')

            # 合并应用包名检测：优先使用自动检测到的实际代码包名
            if auto_package:
                app_pkg_prefix = 'L' + auto_package.replace('.', '/')
                app_package = auto_package
            elif app_package:
                app_pkg_prefix = 'L' + app_package.replace('.', '/')
            else:
                app_pkg_prefix = ''

            # 标记应用自有类
            if app_pkg_prefix:
                for c in all_results:
                    c['is_app_class'] = c['class_name'].startswith(app_pkg_prefix)

            all_results.sort(key=lambda x: x['total_score'], reverse=True)
            for i, r in enumerate(all_results, 1):
                r['rank'] = i

    if not all_results:
        console.print("[yellow]⚠️ 未找到符合条件的核心类[/]")
        return

    # 统计应用自有类数量
    app_class_count = sum(1 for c in all_results if c.get('is_app_class'))
    app_tag = f" | [bold green]应用自有类: {app_class_count}[/]" if app_package else ""

    # 整体排名
    console.print(Panel(
        f"[bold cyan]核心类定位分析[/] | 共扫描 {len(dex_files)} 个 DEX | 筛选出 [bold]{len(all_results)}[/] 个核心类"
        f"{app_tag}\n"
        f"[dim]评分维度: 入口点(×1.5) | 方法量(×1.0) | 字段量(×0.5) | 引用度(×1.2) | 命名模式(×1.5) | 接口(×0.8) | 父类(×1.0)[/]"
        f"{f' | 包名: [cyan]{app_package}[/]' if app_package else ''}",
        title="🎯 核心类定位", border_style="cyan", box=box.DOUBLE
    ))

    # 按 DEX 分开展示
    for dex_name, classes in sorted(per_dex.items()):
        if isinstance(classes, dict) and 'error' in classes:
            console.print(f"[red]❌ {dex_name}: {classes['error']}[/]")
            continue
        if not classes:
            continue

        t = Table(title=f"📜 {dex_name} — 核心类 Top {len(classes)}", box=box.ROUNDED, border_style="blue")
        t.add_column("#", style="dim", width=4)
        t.add_column("类名", style="cyan", width=60, no_wrap=False)
        t.add_column("评分", justify="right", style="bold yellow", width=8)
        t.add_column("方法", justify="right", width=6)
        t.add_column("字段", justify="right", width=6)
        t.add_column("引用", justify="right", width=6)
        t.add_column("父类", style="dim", width=25)
        for c in classes:
            d = c['details']
            score_color = "green" if c['total_score'] >= 80 else "yellow" if c['total_score'] >= 50 else "white"
            # 应用自有类用亮青色高亮
            name_style = "bold cyan" if c.get('is_app_class') else "cyan"
            app_mark = "📱 " if c.get('is_app_class') else ""
            # 短类名：只显示最后两段
            simple_parts = c['simple_name'].split('.')
            short_name = '.'.join(simple_parts[-2:]) if len(simple_parts) > 2 else c['simple_name']
            t.add_row(
                str(c['rank']),
                f"[{name_style}]{app_mark}{short_name}[/]",
                f"[{score_color}]{c['total_score']:.1f}[/]",
                str(d['method_count']),
                str(d['field_count']),
                str(d['ref_count']),
                d.get('super_simple', '').split('.')[-1] if d.get('super_simple') else ''
            )
        console.print(t)

    # 评分明细
    if args.detail:
        console.print(f"\n[bold]📊 评分明细 (Top {min(args.detail, len(all_results))}):[/]")
        for c in all_results[:args.detail]:
            scores = c['scores']
            d = c['details']
            detail_parts = [
                f"入口={scores.get('entry_point', 0):.1f}",
                f"方法={scores.get('method_volume', 0):.1f}",
                f"字段={scores.get('field_volume', 0):.1f}",
                f"引用={scores.get('reference', 0):.1f}",
                f"命名={scores.get('name_pattern', 0):.1f}",
                f"接口={scores.get('interface', 0):.1f}",
                f"父类={scores.get('superclass', 0):.1f}",
            ]
            app_mark = "📱 " if c.get('is_app_class') else ""
            name_style = "bold cyan" if c.get('is_app_class') else "cyan"
            console.print(f"  [bold #{c['rank']}][/] [{name_style}]{app_mark}{c['simple_name']}[/] [yellow]{c['total_score']:.1f}[/]")
            console.print(f"    [dim]{' | '.join(detail_parts)}[/]")
            console.print(f"    [dim]父类: {d.get('super_simple', '')} | 方法: {d['method_count']} | 字段: {d['field_count']} | 引用: {d['ref_count']}[/]")

    # 导出 JSON
    if args.json:
        output_path = args.json if args.json != 'true' else f'core_classes_{os.path.basename(args.apk)}.json'
        import json as _json
        export_data = {'app_package': app_package, 'dex_files': per_dex, 'merged': all_results}
        with open(output_path, 'w', encoding='utf-8') as f:
            _json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"[green]✅ 已导出 JSON: {output_path}[/]")
# ── 多语言 / 资源语言 ──────────────────────────────────────

def cmd_lang(args):
    """切换 CLI 界面语言（工具自身 i18n）"""
    from apk_reverse_engine.utils.i18n import set_lang, get_lang, LANGUAGES, LANG_CODES, save_lang, language_name

    if args.set:
        lang_code = args.set
        if lang_code not in LANGUAGES:
            _error(f"不支持的语言: {lang_code}")
            _info(f"支持的语言: {', '.join(f'{k}={v}' for k, v in LANGUAGES.items())}")
            return
        set_lang(lang_code)
        saved = save_lang(lang_code)
        _success(f"语言切换: {language_name(lang_code)} ({lang_code})")
        if saved:
            console.print(f"  [dim]语言设置已持久化保存[/]")
        return

    if args.list:
        current = get_lang()
        t = Table(box=box.ROUNDED, border_style="cyan")
        t.add_column("代码", style="cyan")
        t.add_column("语言", style="white")
        t.add_column("状态", style="green")
        for code, name in LANGUAGES.items():
            status = "✅ 当前" if code == current else ""
            t.add_row(code, name, status)
        console.print(_make_panel(t, '🌐 支持的语言', 'cyan'))
        return

    current = get_lang()
    _info(f"当前语言: {language_name(current)} ({current})")
    console.print(f"  [dim]支持的语言: {', '.join(f'{k}={v}' for k, v in LANGUAGES.items())}[/]")
    console.print(f"  [dim]使用 `reng lang --set <code>` 切换语言[/]")

def cmd_reslang(args):
    """处理 APK 资源语言（strings.xml 多语言）"""
    from apk_reverse_engine.tools.resource_lang import ResourceLanguageTool

    if args.list:
        with ResourceLanguageTool(args.apk) as tool:
            langs = tool.list_languages()
        if not langs:
            _warn("未找到多语言资源")
            return
        t = Table(box=box.ROUNDED, border_style="green")
        t.add_column("#", justify="right", style="dim")
        t.add_column("代码", style="cyan")
        t.add_column("语言", style="white")
        t.add_column("目录", style="dim")
        t.add_column("字符串数", justify="right")
        for i, lang in enumerate(langs, 1):
            t.add_row(str(i), lang["code"], lang["name"], lang["dir"], str(lang["string_count"]))
        console.print(_make_panel(t, f'🌐 资源语言: {os.path.basename(args.apk)}', 'green'))
        return

    if args.extract:
        with ResourceLanguageTool(args.apk) as tool:
            result = tool.extract_strings(args.extract)
        if "error" in result:
            _error(result['error'])
            return
        t = Table(box=box.ROUNDED, border_style="blue")
        t.add_column("键", style="cyan")
        t.add_column("值", style="white")
        for key, value in result["strings"].items():
            t.add_row(str(key), str(value)[:80])
        console.print(_make_panel(t, f'📝 {args.extract} 字符串 ({result.get("count", 0)} 项)', 'blue'))
        return

    if args.compare:
        base = args.compare
        with ResourceLanguageTool(args.apk) as tool:
            result = tool.compare_translations(base)
        if "error" in result:
            _error(result['error'])
            return
        t = Table(box=box.ROUNDED, border_style="yellow")
        t.add_column("语言", style="cyan")
        t.add_column("代码", style="white")
        t.add_column("总数", justify="right")
        t.add_column("已翻译", justify="right")
        t.add_column("缺失", justify="right")
        t.add_column("完成率", justify="right")
        for lang in result["languages"]:
            t.add_row(lang["name"], lang["code"], str(lang["total"]), str(lang["translated"]),
                      str(lang["missing"]), f"{lang['completion']:.1f}%")
        console.print(_make_panel(t, f'📊 翻译完整性对比 (基准: {base})', 'yellow'))
        return

    if args.add:
        with ResourceLanguageTool(args.apk) as tool:
            result = tool.add_language(args.add)
        if "error" in result:
            _error(result['error'])
            return
        _success(f"添加语言 {args.add}: {result.get('message', '')}")
        return

    if args.remove:
        with ResourceLanguageTool(args.apk) as tool:
            result = tool.remove_language(args.remove)
        if "error" in result:
            _error(result['error'])
            return
        _success(f"移除语言 {args.remove}")
        return

    if args.replace and args.lang:
        kv_pairs = {}
        for pair in args.replace.split(','):
            if '=' in pair:
                k, v = pair.split('=', 1)
                kv_pairs[k.strip()] = v.strip()
        with ResourceLanguageTool(args.apk) as tool:
            result = tool.replace_strings(args.lang, kv_pairs)
        if "error" in result:
            _error(result['error'])
            return
        _success(f"替换 {len(kv_pairs)} 个字符串")
        if result.get("output"):
            console.print(f"  [dim]输出 APK: {result['output']}[/]")
        return

    _warn("请指定操作: --list, --extract, --compare, --add, --remove, 或 --replace")
    console.print(f"  [dim]使用 `reng reslang --help` 查看详细用法[/]")

# ── sdk - SDK/追踪器检测 ──────────────────────────────────────
def cmd_sdk(args):
    """检测APK中的第三方SDK/追踪器"""
    from apk_reverse_engine.analysis.sdk_detector import SDKDetector
    from apk_reverse_engine.core.dex_parser import DexParser
    with console.status(f"{ICO['mag']} 分析APK SDK...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            dex_files = ctx.get_dex_files()
            class_names = []
            strings = []
            for d in dex_files:
                data = ctx.read_file(d)
                dp = DexParser(data)
                dp.parse_header()
                class_names.extend(dp.get_class_names())
                strings.extend(dp.get_strings())
            manifest = get_manifest_info(ctx.get_manifest_xml())
            permissions = [p.split('.')[-1].upper() for p in manifest.get('permissions', [])]

            result = SDKDetector.analyze(class_names=class_names, strings=strings, permissions=permissions)

    # 输出
    console.print(_header(f"{ICO['pkg']} SDK/追踪器检测", os.path.basename(args.apk)))

    # 摘要
    s = result['summary']
    risk = result['privacy_risk']
    console.print(_make_panel(
        f"[bold]SDK 总数:[/] {s['total_sdks']}  "
        f"[red]高风险:[/] {s['high_risk_count']}  "
        f"[yellow]中风险:[/] {s['medium_risk_count']}  "
        f"[green]低风险:[/] {s['low_risk_count']}  "
        f"[bold]追踪器:[/] {s['tracker_count']}  "
        f"\n[bold]隐私风险评分:[/] {risk['risk_score']}/100  "
        f"[{'red' if risk['risk_level']=='高' else 'yellow' if risk['risk_level']=='中' else 'green'}]{_risk_icon(risk['risk_score'])} {risk['risk_level']}[/]",
        "📊 SDK 摘要", 'cyan'
    ))

    # SDK 详细列表
    if result['sdks']:
        _section("检测到的 SDK")
        t = Table(box=box.SIMPLE)
        t.add_column("SDK 名称", style="cyan")
        t.add_column("类别", style="white")
        t.add_column("风险", justify="center")
        t.add_column("出现次数", justify="right")
        t.add_column("样本", style="dim", max_width=40)
        for sdk in result['sdks']:
            risk_color = 'red' if sdk['risk'] == '高' else 'yellow' if sdk['risk'] == '中' else 'green'
            samples = ', '.join(sdk['samples'][:3])
            t.add_row(sdk['name'], sdk['category'], f"[{risk_color}]{sdk['risk']}[/]",
                      str(sdk['count']), samples)
        console.print(t)

    # 字符串检测
    if result.get('string_detected'):
        _section("字符串特征检测")
        console.print(f"  [dim]{', '.join(result['string_detected'])}[/]")

    # 隐私风险详情
    if risk.get('details'):
        _section("隐私风险详情")
        for d in risk['details']:
            console.print(f"  • {d}")

# ── strings - DEX 字符串深度分析 ─────────────────────────────
def cmd_strings(args):
    """深度分析DEX字符串"""
    from apk_reverse_engine.analysis.string_analyzer import StringAnalyzer
    from apk_reverse_engine.core.dex_parser import DexParser
    with console.status(f"{ICO['mag']} 提取DEX字符串...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            dex_files = ctx.get_dex_files()
            all_strings = []
            for d in dex_files:
                data = ctx.read_file(d)
                dp = DexParser(data)
                dp.parse_header()
                all_strings.extend(dp.get_strings())

        result = StringAnalyzer.analyze(all_strings)

    console.print(_header(f"{ICO['dex']} DEX 字符串深度分析", os.path.basename(args.apk)))

    # 摘要
    s = result['summary']
    _kv_table([
        ('字符串总数', str(s['total_strings'])),
        ('去重后', str(s['unique_strings'])),
        ('URL', str(s['url_count'])),
        ('IP地址', str(s['ip_count'])),
        ('Email', str(s['email_count'])),
        ('Base64编码', str(s['base64_count'])),
        ('Hex编码', str(s['hex_count'])),
        ('Java类/包名', str(s['java_class_count'])),
        ('敏感信息', str(s['sensitive_count'])),
        ('内网IP', str(s['private_ip_count'])),
    ], '📊 字符串统计')

    # 分类
    if result['classification']:
        _section("分类统计")
        t = Table(box=box.SIMPLE)
        t.add_column("类别", style="cyan")
        t.add_column("数量", justify="right")
        t.add_column("示例", style="dim", max_width=60)
        for cat, count in result['classification'].get('categories', {}).items():
            samples = result['classification'].get('classified', {}).get(cat, [])
            sample_text = samples[0] if samples else ''
            t.add_row(cat, str(count), sample_text[:60])
        console.print(t)

    # 敏感信息
    if result['sensitive']:
        _section("敏感信息")
        t = Table(box=box.SIMPLE)
        t.add_column("类型", style="red")
        t.add_column("内容", style="yellow", max_width=60)
        t.add_column("长度", justify="right")
        for item in result['sensitive'][:20]:
            t.add_row(item['category'], item['value'][:60], str(item['length']))
        console.print(t)

    # URL
    if result['urls']['urls']:
        _section("提取的 URL")
        for url in result['urls']['urls'][:15]:
            console.print(f"  [dim]🌐[/] {url}")

    # 内网IP
    if result['private_ips']:
        _section("内网 IP")
        for ip in result['private_ips']:
            console.print(f"  [yellow]⚠️ {ip}[/]")

    if args.json:
        import json as _json
        _json.dump(result, open(args.json, 'w'), indent=2, ensure_ascii=False)
        _success(f"JSON 已保存到 {args.json}")

# ── resobf - 资源混淆检测 ────────────────────────────────────
def cmd_resobf(args):
    """检测APK资源混淆程度"""
    from apk_reverse_engine.analysis.resource_obfuscation import ResourceObfuscationDetector
    with console.status(f"{ICO['mag']} 分析资源混淆...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            file_list = ctx.list_files()

        result = ResourceObfuscationDetector.analyze(file_list=file_list)

    console.print(_header(f"{ICO['pkg']} 资源混淆检测", os.path.basename(args.apk)))

    # 综合评分
    summary = result['summary']
    score = summary['score']
    level = summary['level']
    level_color = 'red' if level == '高' else 'yellow' if level == '中' else 'green'
    console.print(_make_panel(
        f"[bold]混淆评分:[/] [{level_color}]{score}/100[/]  "
        f"[{level_color}]{_risk_icon(score/25)} {level}[/]  "
        f"\n[bold]资源总数:[/] {summary['total_resources']}  "
        f"[bold]混淆比例:[/] {summary['obfuscated_ratio']:.1%}  "
        f"[bold]R类混淆:[/] {summary['r_class_obfuscated']}  "
        f"[bold]布局ID混淆:[/] {summary['layout_obfuscated_ids']}",
        "📊 资源混淆评估", 'cyan'
    ))

    # 资源命名分析
    ra = result.get('resource_analysis', {})
    naming = ra.get('naming_analysis', {})
    if naming:
        _section("资源命名分析")
        _kv_table([
            ('总资源名', str(naming['total_names'])),
            ('混淆命名', str(naming['obfuscated_count'])),
            ('单字母命名', str(naming['single_letter_count'])),
            ('有意义命名', str(naming['meaningful_count'])),
            ('混淆比例', f"{naming['obfuscation_ratio']:.1%}"),
        ])

        # 混淆样本
        samples = naming.get('samples', {})
        if samples.get('obfuscated'):
            _section("混淆命名样本")
            console.print(f"  [dim]{', '.join(samples['obfuscated'][:15])}[/]")

        # 按类型分析
        by_type = ra.get('by_type', {})
        if by_type:
            _section("按资源类型")
            t = Table(box=box.SIMPLE)
            t.add_column("类型", style="cyan")
            t.add_column("总数", justify="right")
            t.add_column("混淆数", justify="right")
            t.add_column("混淆率", justify="right")
            for rt, stats in sorted(by_type.items()):
                rate = stats['obfuscated'] / stats['total'] if stats['total'] else 0
                t.add_row(rt, str(stats['total']), str(stats['obfuscated']), f"{rate:.1%}")
            console.print(t)

    if args.json:
        import json as _json
        _json.dump(result, open(args.json, 'w'), indent=2, ensure_ascii=False)
        _success(f"JSON 已保存到 {args.json}")

# ── medit - AndroidManifest 快速编辑 ──────────────────────────
def cmd_medit(args):
    """编辑 AndroidManifest.xml 属性"""
    from apk_reverse_engine.analysis.manifest_editor import ManifestEditor
    from apk_reverse_engine.utils.axml_converter import AXMLConverter

    # 1. 读取 APK 中的 AndroidManifest.xml
    with console.status(f"{ICO['mag']} 读取 AndroidManifest...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            raw_data = ctx.get_manifest_xml()
        # 解码为文本 XML
        xml_text = AXMLConverter.to_xml(raw_data)

    # 2. 应用修改
    changes = {}
    if args.debuggable is not None:
        changes['debuggable'] = 'true' if args.debuggable else 'false'
    if args.backup is not None:
        changes['allowBackup'] = 'true' if args.backup else 'false'
    if args.test_only is not None:
        changes['testOnly'] = 'true' if args.test_only else 'false'
    if args.cleartext is not None:
        changes['usesCleartextTraffic'] = 'true' if args.cleartext else 'false'
    if args.extract_native is not None:
        changes['extractNativeLibs'] = 'true' if args.extract_native else 'false'
    if args.has_code is not None:
        changes['hasCode'] = 'true' if args.has_code else 'false'
    if args.hardware_accel is not None:
        changes['hardwareAccelerated'] = 'true' if args.hardware_accel else 'false'
    if args.large_heap is not None:
        changes['largeHeap'] = 'true' if args.large_heap else 'false'
    if args.network_config is not None:
        changes['networkSecurityConfig'] = args.network_config

    if not changes:
        # 无修改 → 显示当前状态
        console.print(_header(f"{ICO['pkg']} AndroidManifest 属性", os.path.basename(args.apk)))
        # 提取现有属性
        import re as _re
        attrs = {}
        for attr_name in ['debuggable', 'allowBackup', 'testOnly', 'extractNativeLibs',
                          'hasCode', 'hardwareAccelerated', 'largeHeap', 'usesCleartextTraffic',
                          'networkSecurityConfig']:
            m = _re.search(rf'android:{attr_name}="([^"]*)"', xml_text)
            attrs[attr_name] = m.group(1) if m else '(未设置)'

        t = Table(box=box.SIMPLE)
        t.add_column("属性", style="cyan")
        t.add_column("当前值", style="white")
        t.add_column("说明", style="dim")
        desc_map = {
            'debuggable': '调试模式', 'allowBackup': '允许备份',
            'testOnly': '测试模式', 'extractNativeLibs': 'SO提取',
            'hasCode': '代码加载', 'hardwareAccelerated': '硬件加速',
            'largeHeap': '大堆内存', 'usesCleartextTraffic': '明文流量',
            'networkSecurityConfig': '网络安全配置',
        }
        for attr, value in attrs.items():
            t.add_row(attr, value, desc_map.get(attr, ''))
        console.print(t)
        console.print(f"\n  [dim]使用 `reng medit app.apk --debuggable true` 修改属性[/]")
        return

    # 3. 执行修改
    xml_text = ManifestEditor.batch_set(xml_text, changes)

    # 4. 编码回 AXML 并写入 APK
    with console.status(f"{ICO['gear']} 写入 APK...", spinner="dots"):
        axml_data = AXMLConverter.to_axml(xml_text)
        from apk_reverse_engine.tools.repacker import APKRepacker
        APKRepacker.zip_update(args.apk, {'AndroidManifest.xml': axml_data})

    # 5. 输出结果
    console.print(_header(f"{ICO['ok']} Manifest 修改完成", os.path.basename(args.apk)))
    descs = ManifestEditor.get_changes_description(changes)
    for d in descs:
        console.print(f"  • [cyan]{d['属性']}[/] → [bold]{d['操作']}[/]")
    _warn("修改后 APK 签名已失效，需重新签名！")
    console.print(f"  [dim]使用: reng sign {args.apk} output.apk[/]")

# ── social - 社交登录检测 ────────────────────────────────────
def cmd_social(args):
    """检测APK中的社交登录集成（微信/QQ/GitHub/支付宝/Google/Facebook/Apple/Twitter/微博）"""
    from apk_reverse_engine.analysis.social_login_detector import SocialLoginDetector
    from apk_reverse_engine.core.dex_parser import DexParser
    with console.status(f"{ICO['mag']} 分析社交登录...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            dex_files = ctx.get_dex_files()
            class_names = []
            strings = []
            for d in dex_files:
                data = ctx.read_file(d)
                dp = DexParser(data)
                dp.parse_header()
                class_names.extend(dp.get_class_names())
                strings.extend(dp.get_strings())

            result = SocialLoginDetector.analyze(class_names=class_names, strings=strings)

    # 输出
    console.print(_header(f"{ICO['pkg']} 社交登录检测", os.path.basename(args.apk)))

    if not result.get('has_social_login'):
        console.print(f"\n  [green]✅ 未检测到社交登录集成[/]")
        _spacer()
        return

    # 综合评分
    s = result['summary']
    score = s['score']
    level = s['level']
    lc = 'red' if level == '密集集成' else 'yellow' if level == '多平台集成' else 'green'
    console.print(_make_panel(
        f"[bold]平台数:[/] {s['total_platforms']}  "
        f"[bold]综合评分:[/] [{lc}]{score}/100 ({level})[/]  "
        f"\n[bold]平台列表:[/] {' | '.join(s['platform_names'])}",
        "📊 社交登录摘要", lc
    ))

    # 各平台详情
    if result.get('platform_details'):
        _section("检测到的社交登录平台")
        for p in result['platform_details']:
            key = p['key']
            platform = result['detected_platforms'].get(key, {})
            risk_color = 'red' if p['risk'] == '高' else 'yellow' if p['risk'] == '中' else 'green'

            # 检测维度
            dims = []
            if platform.get('has_sdk'): dims.append('✅ SDK')
            if platform.get('has_code'): dims.append('✅ 代码模式')
            if platform.get('has_string'): dims.append('✅ 字符串特征')
            if platform.get('has_url'): dims.append('✅ URL')
            dim_str = ' | '.join(dims) if dims else '[dim]仅间接引用[/]'

            # AppID
            app_ids = platform.get('app_ids', [])
            app_id_str = f"  AppID: [yellow]{', '.join(app_ids)}[/]" if app_ids else ''

            console.print(f"\n  {p['icon']} [bold]{p['name']}[/]  "
                         f"[dim]置信度 {p['confidence']}%[/]  "
                         f"[{risk_color}]风险: {p['risk']}[/]")
            console.print(f"    {dim_str}")
            if app_id_str:
                console.print(app_id_str)

            # SDK匹配详情
            sdk_patterns = platform.get('sdk_patterns', [])
            if sdk_patterns:
                console.print(f"    [dim]SDK特征: {', '.join(sdk_patterns[:5])}[/]")

    _spacer()
def cmd_ads(args):
    """检测APK中的广告集成"""
    from apk_reverse_engine.analysis.ad_detector import AdDetector
    from apk_reverse_engine.core.dex_parser import DexParser
    with console.status(f"{ICO['mag']} 分析APK广告...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            dex_files = ctx.get_dex_files()
            class_names = []
            strings = []
            for d in dex_files:
                data = ctx.read_file(d)
                dp = DexParser(data)
                dp.parse_header()
                class_names.extend(dp.get_class_names())
                strings.extend(dp.get_strings())
            manifest = get_manifest_info(ctx.get_manifest_xml())
            permissions = [p.split('.')[-1].upper() for p in manifest.get('permissions', [])]

            result = AdDetector.analyze(class_names=class_names, strings=strings, permissions=permissions)

    # 输出
    s = result['summary']
    level = s['level']
    score = s['score']
    lc = 'red' if level == '密集广告' else 'yellow' if level == '有广告' else 'green'
    console.print(_header(f"{ICO['pkg']} 广告检测", os.path.basename(args.apk)))

    # 综合评分
    ad_types = []
    if s.get('has_banner'): ad_types.append('📺 Banner')
    if s.get('has_interstitial'): ad_types.append('🖼️ 插屏')
    if s.get('has_rewarded'): ad_types.append('🎬 激励视频')
    if s.get('has_native'): ad_types.append('📄 原生')
    if s.get('has_mediation'): ad_types.append('🔗 聚合')
    ad_type_str = ' | '.join(ad_types) if ad_types else '无'

    console.print(_make_panel(
        f"[bold]广告等级:[/] [{lc}]{level} ({score}/100)[/]  "
        f"[bold]SDK数量:[/] {s['ad_sdk_count']}  "
        f"[bold]广告类型:[/] {ad_type_str}  "
        f"\n[bold]广告权限:[/] {s['ad_permission_count']}项  "
        f"[bold]广告URL域名:[/] {s['ad_url_count']}个",
        "📊 广告检测摘要", lc
    ))

    # SDK列表
    if result['ad_sdks']:
        _section(f"检测到的广告SDK ({len(result['ad_sdks'])}个)")
        t = Table(box=box.SIMPLE)
        t.add_column("SDK 名称", style="cyan")
        t.add_column("出现次数", justify="right")
        t.add_column("样本", style="dim", max_width=40)
        for sdk in result['ad_sdks']:
            samples = ', '.join(sdk['samples'][:3])
            t.add_row(sdk['name'], str(sdk['count']), samples)
        console.print(t)

    # 代码模式
    cp = result['code_patterns']
    if cp.get('details'):
        _section("广告代码模式")
        for d in cp['details']:
            console.print(f"  • {d}")
        console.print(f"  [dim]代码特征匹配: {cp['patterns_found']}次[/]")

    # 权限
    perm = result['permissions']
    if perm.get('ad_related'):
        _section(f"广告相关权限 ({perm['count']}项)")
        console.print(f"  [dim]{', '.join(perm['ad_related'])}[/]")
        if perm.get('risk_level') == '高':
            _warn("广告SDK请求了过多敏感权限，隐私风险高")

    # URL域名
    urls = result['ad_urls']
    if urls.get('ad_domains'):
        _section("广告网络域名")
        for domain in urls['ad_domains'][:15]:
            console.print(f"  [dim]🌐[/] {domain}")

    # 字符串特征
    if result.get('ad_strings'):
        _section("广告字符串特征")
        console.print(f"  [dim]{', '.join(result['ad_strings'])}[/]")

    if args.json:
        import json as _json
        _json.dump(result, open(args.json, 'w'), indent=2, ensure_ascii=False)
        _success(f"JSON 已保存到 {args.json}")

# ── adremove - 广告移除 ───────────────────────────────────────────

def cmd_adremove(args):
    """移除APK中的广告（多SDK定向 + 正则通杀 + assets/manifest清理）"""
    import tempfile
    import shutil
    import subprocess
    from apk_reverse_engine.analysis.ad_remover import AdRemover

    apk_path = args.apk
    if not os.path.isfile(apk_path):
        _error(f"文件不存在: {apk_path}")
        return

    # 输出目录
    output = args.output
    if not output:
        base = os.path.splitext(os.path.basename(apk_path))[0]
        output = f"{base}_noads.apk"

    # 解码目录
    decode_dir = args.decode_dir
    cleanup_decode = False
    if not decode_dir:
        decode_dir = tempfile.mkdtemp(prefix='adremove_')
        cleanup_decode = True

    # 步骤1: Apktool 解码
    if not os.path.isdir(decode_dir) or not any(f.startswith('smali') for f in os.listdir(decode_dir)):
        console.print(f"{ICO['pkg']} [bold]步骤 1/4:[/] Apktool 解包中...")
        if os.path.isdir(decode_dir):
            shutil.rmtree(decode_dir)
        os.makedirs(decode_dir, exist_ok=True)
        apktool_cmd = ['apktool', 'd', '-f', '-o', decode_dir, apk_path]
        result = subprocess.run(apktool_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            _error(f"Apktool 解包失败:\n{result.stderr}")
            if cleanup_decode:
                shutil.rmtree(decode_dir, ignore_errors=True)
            return
        _success("解包完成")
    else:
        console.print(f"{ICO['pkg']} [dim]使用已有解包目录: {decode_dir}[/]")

    # 检测广告SDK
    console.print(f"{ICO['mag']} [bold]步骤 2/4:[/] 检测广告 SDK...")
    detected = AdRemover.detect_ad_sdks(decode_dir)
    if detected:
        sdk_names = [AdRemover.AD_SDKS[k]['icon'] + ' ' + AdRemover.AD_SDKS[k]['name'] for k in detected]
        console.print(f"  [yellow]检测到 {len(detected)} 个广告SDK:[/]")
        for name in sdk_names:
            console.print(f"    • {name}")
    else:
        console.print("  [green]未检测到已知广告SDK[/]")

    # 构建选项
    options = {}
    if args.sdks:
        # 只处理指定的SDK
        sdk_list = [s.strip() for s in args.sdks.split(',')]
        for k in ['tencent', 'kuaishou', 'pangle', 'baidu', 'toutiao', 'sigmob', 'google', 'miads']:
            options[k] = k in sdk_list
    if args.no_regex:
        options['regex'] = False
    if args.no_assets:
        options['assets'] = False
    if args.no_manifest:
        options['manifest'] = False

    # 步骤3: 执行广告移除
    console.print(f"{ICO['fix']} [bold]步骤 3/4:[/] 执行广告移除...")
    assets_dir = os.path.join(decode_dir, 'assets')
    manifest_path = os.path.join(decode_dir, 'AndroidManifest.xml')

    with console.status("[bold cyan]移除广告中...", spinner="dots"):
        report = AdRemover.remove_all(
            smali_root=decode_dir,
            assets_dir=assets_dir if os.path.isdir(assets_dir) else None,
            manifest_path=manifest_path if os.path.isfile(manifest_path) else None,
            options=options,
        )

    # 输出报告
    _spacer()
    console.print(_header("🧹 广告移除报告", os.path.basename(apk_path)))

    console.print(_make_panel(
        f"[bold]总补丁数:[/] {report['total_patched']}  "
        f"[bold]修改文件:[/] {report['total_files']}",
        "📊 移除摘要", "green"
    ))

    # SDK详情
    if report['sdks']:
        _section("SDK 定向移除")
        t = Table(box=box.SIMPLE)
        t.add_column("SDK", style="cyan")
        t.add_column("补丁数", justify="right")
        t.add_column("文件数", justify="right")
        t.add_column("Manifest", justify="right")
        for sdk_key, r in report['sdks'].items():
            icon = AdRemover.AD_SDKS.get(sdk_key, {}).get('icon', '')
            name = AdRemover.AD_SDKS.get(sdk_key, {}).get('name', sdk_key)
            mr = r.get('manifest_removed', '-')
            t.add_row(f"{icon} {name}", str(r.get('patched', 0)), str(r.get('files', 0)), str(mr))
        console.print(t)

    # 正则通杀
    if report.get('regex', {}).get('replacements', 0) > 0:
        _section("正则通杀")
        console.print(f"  [dim]模式数:[/] {report['regex']['patterns_applied']}  "
                      f"[dim]替换:[/] {report['regex']['replacements']}  "
                      f"[dim]文件:[/] {report['regex']['files']}")

    # Assets清理
    if report.get('assets', {}).get('count', 0) > 0:
        _section(f"Assets 清理 ({report['assets']['count']}个文件)")
        for f in report['assets']['deleted'][:20]:
            console.print(f"  [red]✗[/] {f}")
        if len(report['assets']['deleted']) > 20:
            console.print(f"  [dim]...还有 {len(report['assets']['deleted']) - 20} 个[/]")

    # Manifest清理
    if report.get('manifest', {}).get('removed', 0) > 0:
        _section(f"Manifest 清理 ({report['manifest']['removed']}个组件)")

    # 步骤4: 重打包 + 签名
    console.print(f"{ICO['build']} [bold]步骤 4/4:[/] 重打包 & 签名...")
    with console.status("[bold cyan]重打包中...", spinner="dots"):
        build_cmd = ['apktool', 'b', '-f', '-o', output, decode_dir]
        result = subprocess.run(build_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            _error(f"重打包失败:\n{result.stderr}")
            if cleanup_decode:
                shutil.rmtree(decode_dir, ignore_errors=True)
            return

    # 签名
    if not args.no_sign:
        with console.status("[bold cyan]签名中...", spinner="dots"):
            r = sign_debug(output, output)
            if not r.get('success'):
                _error(f"签名失败: {r.get('error', '未知错误')}")

    _success(f"广告移除完成: {output}")
    console.print(f"  [dim]解包目录: {decode_dir}[/]")
    if cleanup_decode and not args.keep_decode:
        shutil.rmtree(decode_dir, ignore_errors=True)
        console.print("  [dim]临时解包目录已清理[/]")

    if report['total_patched'] == 0 and not report.get('assets', {}).get('count', 0):
        _warn("未发现可移除的广告特征（可能使用了未知SDK或加固保护）")


# ── adai - AI广告分析 ──────────────────────────────────────────

def cmd_adai(args):
    """AI 广告识别分析 - 使用 LLM 智能分析 APK 中的广告接口和实现"""
    from apk_reverse_engine.analysis.ad_ai_engine import AdAIEngine

    api_key = args.api_key
    api_url = args.api_url or ""
    engine = AdAIEngine(api_key=api_key, api_url=api_url)

    # 多对话同时使用时禁用速率限制
    if getattr(args, 'no_rate_limit', False):
        AdAIEngine.set_rate_limit(False)

    # 列出模型模式
    if args.list_models:
        console.print(f"{ICO['mag']} [bold]可用 AI 模型列表[/]")
        _spacer()
        models = engine.get_available_models()
        for m in models:
            display = AdAIEngine.get_model_display_name(m)
            tag = " [yellow](思考模式)[/]" if AdAIEngine.is_thinking_model(m) else ""
            console.print(f"  • [cyan]{m}[/] [dim]({display})[/]{tag}")
        _spacer()
        console.print(f"  [dim]共 {len(models)} 个可用模型[/]")
        return

    # 检查模型
    model = args.model
    if not model:
        console.print(f"{ICO['mag']} [bold]未指定模型，列出可用模型:[/]")
        models = engine.get_available_models()
        for m in models:
            display = AdAIEngine.get_model_display_name(m)
            tag = " (思考模式)" if AdAIEngine.is_thinking_model(m) else ""
            console.print(f"  • {m} ({display}){tag}")
        console.print(f"\n  [dim]请使用 --model <model_id> 指定模型[/]")
        return

    # 从 APK 提取代码
    from apk_reverse_engine.core.dex_parser import DexParser

    code_snippets = []
    skipped_count = 0
    with console.status(f"{ICO['mag']} 提取 APK 代码...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            dex_files = ctx.get_dex_files()
            for d in dex_files:
                data = ctx.read_file(d)
                parser = DexParser(data)
                classes = parser.get_class_defs()
                for cls in classes:
                    class_name = cls.get('class_name', '')
                    if args.class_name and args.class_name.lower() not in class_name.lower():
                        continue
                    # 获取类中的方法
                    for mlist_name in ['direct_methods', 'virtual_methods']:
                        for m in cls.get(mlist_name, []):
                            try:
                                code_item = parser.get_code_item(m)
                                if code_item and code_item.get('instructions'):
                                    method_name = m.get('name', '')
                                    instructions = code_item['instructions']
                                    snippet = f"# Class: {class_name}\n# Method: {method_name}\n"
                                    # 取前 500 条指令
                                    snippet += '\n'.join(
                                        f"  {i['mnemonic']} {i.get('operands', [])}"
                                        for i in instructions[:AdAIEngine.MAX_INSTRUCTIONS]
                                    )
                                    # 智能预筛选（使用 AdAIEngine.prefilter_ad_code）
                                    is_ad, score = AdAIEngine.prefilter_ad_code(
                                        snippet, class_name, method_name,
                                        args.custom_keywords or ''
                                    )
                                    if is_ad:
                                        code_snippets.append({
                                            'class': class_name,
                                            'method': method_name,
                                            'code': snippet,
                                            'score': score,
                                        })
                                    else:
                                        skipped_count += 1
                            except Exception:
                                continue

    if not code_snippets:
        _warn("未找到包含广告相关关键词的代码片段")
        console.print(f"  [dim]已跳过 {skipped_count} 个无广告特征的代码片段[/]")
        console.print(f"  [dim]尝试分析所有代码可能耗时较长，建议指定 --class-name[/]")
        return

    # 按相关度排序
    code_snippets.sort(key=lambda x: x['score'], reverse=True)

    console.print(f"{ICO['mag']} 找到 {len(code_snippets)} 个候选代码片段"
                  f" [dim](已跳过 {skipped_count} 个无关片段)[/]")

    # 构建分析选项
    options = {
        'show_ad_blocking_suggestions': not args.no_blocking,
    }
    if args.custom_keywords:
        options['custom_ad_keywords'] = args.custom_keywords

    # 分析模式
    question_mode = 'supplement' if (args.supplement or args.question) else 'direct'

    # 流式或非流式
    use_stream = args.stream and not args.json

    # 并发数（默认5，可通过 --concurrent 调整）
    max_workers = getattr(args, 'concurrent', 5) or AdAIEngine.MAX_CONCURRENT

    max_analyze = min(len(code_snippets), args.max_snippets if hasattr(args, 'max_snippets') else 20)
    to_analyze = code_snippets[:max_analyze]

    # ── 并发分析 ──
    results = []
    if use_stream:
        # 并发流式输出
        console.print(f"\n{ICO['gear']} [bold]并发流式分析 {len(to_analyze)} 个片段"
                      f" [dim]({max_workers} 路同时)[/]\n")
        # 为每个片段维护独立缓冲区
        buffers = {i: [] for i in range(len(to_analyze))}
        done_flags = [False] * len(to_analyze)

        for idx, chunk in engine.analyze_stream_batch(
            snippets=to_analyze,
            source_language=args.language,
            model=model,
            question=args.question or '',
            question_mode=question_mode,
            options=options,
            max_workers=max_workers,
        ):
            buffers[idx].append(chunk)
            # 带标签的实时输出
            snippet = to_analyze[idx]
            short_class = snippet['class'].split('/')[-1].split(';')[0] if snippet['class'] else f'#{idx}'
            console.print(f"[dim][{idx+1}/{len(to_analyze)} {short_class}][/]", end='', style="dim")
            console.print(chunk, end='', style="cyan")

        console.print()

        # 收集结果
        for i, snippet in enumerate(to_analyze):
            full = ''.join(buffers[i])
            if full:
                results.append({
                    'class': snippet['class'],
                    'method': snippet['method'],
                    'analysis': full,
                    'score': snippet['score'],
                })
            else:
                results.append({
                    'class': snippet['class'],
                    'method': snippet['method'],
                    'score': snippet['score'],
                    'error': '流式分析未返回内容',
                })
    else:
        # 并发非流式
        console.print(f"\n{ICO['gear']} [bold]并发分析 {len(to_analyze)} 个片段"
                      f" [dim]({max_workers} 路同时)[/]\n")

        completed_count = 0
        total_count = len(to_analyze)

        def _on_complete(index, result):
            nonlocal completed_count
            completed_count += 1
            snippet = to_analyze[index]
            short_class = snippet['class'].split('/')[-1].split(';')[0] if snippet['class'] else f'#{index}'
            if 'error' in result:
                console.print(f"  [red]✗[/] [{completed_count}/{total_count}] "
                              f"{short_class} :: {snippet['method']} [red]{result['error']}[/]")
            else:
                console.print(f"  [green]✓[/] [{completed_count}/{total_count}] "
                              f"{short_class} :: {snippet['method']} [dim](相关度: {snippet['score']})[/]")

        results = engine.analyze_batch(
            snippets=to_analyze,
            source_language=args.language,
            model=model,
            question=args.question or '',
            question_mode=question_mode,
            options=options,
            max_workers=max_workers,
            on_complete=_on_complete,
        )

    # 输出结果
    _spacer()
    console.print(_header("🤖 AI 广告分析报告", os.path.basename(args.apk)))

    for r in results:
        _section(f"{r['class']} :: {r['method']} [dim](相关度: {r.get('score', 0)})[/]")
        if 'error' in r:
            console.print(f"  [red]分析失败: {r['error']}[/]")
        else:
            console.print(r['analysis'])

    if args.json:
        import json as _json
        _json.dump(results, open(args.json, 'w'), indent=2, ensure_ascii=False)
        _success(f"JSON 已保存到 {args.json}")


# ── disasm - DEX 反汇编 ──────────────────────────────────────────

def cmd_disasm(args):
    """反汇编DEX中的方法（增强版：支持Smali输出/统计/调试信息）"""
    from apk_reverse_engine.core.dex_parser import DexParser
    from apk_reverse_engine.core.dex.disassembler import Disassembler
    
    with console.status(f"{ICO['dex']} 反汇编 DEX...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            total_instructions = 0
            total_methods = 0
            for dex_name in ctx.get_dex_files():
                data = ctx.read_file(dex_name)
                parser = DexParser(data)
                classes = parser.get_class_defs()
                found = 0
                for cls in classes:
                    for mlist_name in ['direct_methods', 'virtual_methods']:
                        for m in cls.get(mlist_name, []):
                            if args.method and args.method.lower() not in m['name'].lower():
                                continue
                            if args.class_name and args.class_name.lower() not in cls['class_name'].lower():
                                continue
                            found += 1
                            total_methods += 1
                            if found > args.max:
                                break
                            
                            # 尝试反汇编
                            instructions = []
                            try:
                                code_item = parser.get_code_item(m)
                                if code_item:
                                    disasm = Disassembler(code_item)
                                    instructions = disasm.disassemble()
                                    total_instructions += len(instructions)
                            except Exception as e:
                                from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/cli.py:2430 suppressed: %s", e)
                                pass
                            
                            # 显示方法头
                            access_flags = m.get('access_flags', '')
                            regs = m.get('registers_size', m.get('registers', '?'))
                            code_sz = m.get('code_size', m.get('code_len', 0))
                            
                            console.print(_header(
                                f"{ICO['dex']} {cls['class_name'].split('/')[-1]}.{m['name']}",
                                f"{dex_name}", 'blue'
                            ))
                            
                            # 方法元信息
                            meta_rows = [
                                ('类', cls['class_name']),
                                ('签名', parser.get_method_signature(m)),
                                ('寄存器', str(regs)),
                                ('代码大小', f"{code_sz} 字节" if code_sz else "? (native/abstract)"),
                                ('指令数', str(len(instructions)) if instructions else "N/A"),
                                ('访问标志', access_flags or '?'),
                            ]
                            console.print(_kv_table(meta_rows, '📋 方法信息', 'cyan'))
                            
                            # 显示反汇编指令
                            if instructions and args.detail:
                                _section(f'指令列表 ({len(instructions)} 条)', 'yellow')
                                t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
                                t.add_column("偏移", style="dim", width=10)
                                t.add_column("操作码", style="bold cyan", width=14)
                                t.add_column("操作数", style="white", width=50)
                                t.add_column("注释", style="dim italic", width=40)
                                
                                for inst in instructions[:args.max]:
                                    offset = inst.get('offset', 0)
                                    opcode = inst.get('opcode_str', inst.get('opcode', ''))
                                    operands = inst.get('operands_str', inst.get('operands', ''))
                                    comment = inst.get('comment', '')
                                    
                                    # 安全相关的指令高亮
                                    op_style = "bold cyan"
                                    if 'invoke' in str(opcode).lower():
                                        op_style = "bold green"
                                    elif opcode in ('return', 'return-void', 'return-wide', 'return-object'):
                                        op_style = "bold magenta"
                                    elif opcode in ('throw', 'monitor-enter', 'monitor-exit'):
                                        op_style = "bold red"
                                    elif opcode in ('if-eq', 'if-ne', 'if-lt', 'if-ge', 'if-gt', 'if-le',
                                                    'goto', 'packed-switch', 'sparse-switch'):
                                        op_style = "bold yellow"
                                    
                                    t.add_row(
                                        f"0x{offset:04x}",
                                        f"[{op_style}]{opcode}[/]",
                                        str(operands)[:50],
                                        f"[dim]{comment}[/]" if comment else ''
                                    )
                                console.print(t)
                                
                                if len(instructions) > args.max:
                                    console.print(f"  [dim]... 还有 {len(instructions) - args.max} 条指令 (使用 --max 查看更多)[/]")
                            elif instructions and not args.detail:
                                # 简洁模式：显示指令统计
                                op_counts = {}
                                for inst in instructions:
                                    op = inst.get('opcode_str', inst.get('opcode', ''))
                                    op_counts[op] = op_counts.get(op, 0) + 1
                                
                                top_ops = sorted(op_counts.items(), key=lambda x: -x[1])[:8]
                                op_summary = " | ".join(f"[cyan]{op}[/] x{count}" for op, count in top_ops)
                                console.print(f"  [dim]指令统计 ({len(instructions)} 条):[/] {op_summary}")
                                if len(instructions) > sum(c for _, c in top_ops):
                                    console.print(f"  [dim]... 以及其他 {len(instructions) - sum(c for _, c in top_ops)} 条指令[/]")
                                console.print(f"  [dim]💡 使用 --detail 查看完整指令列表[/]")
                            
                            console.print()
                
                if found == 0 and args.method:
                    _warn(f"在 {dex_name} 中未找到匹配方法 '{args.method}'")
    
    if total_methods > 0:
        _info(f"共反汇编 {total_methods} 个方法, {total_instructions} 条指令")
    
    _spacer()

# ── smali - Smali 修补 ────────────────────────────────────────────

def cmd_smali(args):
    """Smali 代码修补 (注入/修改/绕过签名)"""
    from apk_reverse_engine.patching.smali_patcher import SmaliPatcher
    
    with console.status(f"{ICO['gear']} 执行 Smali 修补...", spinner="dots"):
        if args.action == 'bypass':
            smali = open(args.file, 'r').read()
            result = SmaliPatcher.bypass_signature_check(smali)
            _success("签名检查绕过完成")
            if args.output:
                with open(args.output, 'w') as f: f.write(result)
                _info(f"输出已保存到 {args.output}")
            else: console.print(result)
        elif args.action == 'nop':
            smali = open(args.file, 'r').read()
            result = SmaliPatcher.nop_out_method(smali, args.method)
            _success(f"方法 {args.method} 已NOP填充")
            if args.output:
                with open(args.output, 'w') as f: f.write(result)
        elif args.action == 'log':
            smali = open(args.file, 'r').read()
            result = SmaliPatcher.add_log_inject(smali, args.method, args.tag or 'DEBUG', args.msg or 'injected')
            _success(f"方法 {args.method} 已注入日志")
            if args.output:
                with open(args.output, 'w') as f: f.write(result)
        elif args.action == 'return':
            smali = open(args.file, 'r').read()
            result = SmaliPatcher.add_return_inject(smali, args.method, args.value or '0')
            _success(f"方法 {args.method} 已注入返回值")
            if args.output:
                with open(args.output, 'w') as f: f.write(result)
        elif args.action == 'remove':
            smali = open(args.file, 'r').read()
            result = SmaliPatcher.remove_method(smali, args.method)
            _success(f"方法 {args.method} 已移除")
            if args.output:
                with open(args.output, 'w') as f: f.write(result)
        elif args.action == 'stub':
            result = SmaliPatcher.generate_method_stub(args.return_type or 'V', args.method, args.params.split(',') if args.params else [])
            _success(f"方法存根生成完成")
            console.print(result)

# ── deobf - 去混淆分析 ────────────────────────────────────────────

def cmd_deobf(args):
    """去混淆分析 (类名混淆/控制流平坦化/XOR解密)"""
    from apk_reverse_engine.analysis.deobfuscator import Deobfuscator
    from apk_reverse_engine.core.dex_parser import DexParser
    
    with console.status(f"{ICO['mag']} 执行去混淆分析...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            all_class_names = []
            all_strings = []
            for dex_name in ctx.get_dex_files():
                data = ctx.read_file(dex_name)
                parser = DexParser(data)
                all_class_names.extend(parser.get_class_names())
                all_strings.extend(parser.get_strings())
            text = '\n'.join(all_strings)
            result = Deobfuscator.analyze_full(text, class_names=all_class_names)
    
    console.print(_header(f"{ICO['mag']} 去混淆分析", os.path.basename(args.apk)))
    if result.get('obfuscated_class_count', 0) > 0:
        _section(f"混淆类名: {result['obfuscated_class_count']}个")
        for orig, new in list(result.get('class_rename', {}).items())[:10]:
            console.print(f"  [dim]{orig}[/] → [green]{new}[/]")
        if result['obfuscated_class_count'] > 10:
            console.print(f"  [dim]... 还有 {result['obfuscated_class_count'] - 10} 个[/]")
    if result.get('xor_keys'):
        _section(f"XOR密钥候选 ({len(result['xor_keys'])}个)")
        console.print(f"  [yellow]{', '.join(f'0x{k:x}' for k in result['xor_keys'][:10])}[/]")
    arith = result.get('arithmetic_obfuscation', {})
    if arith.get('detected'):
        _section("算术混淆检测")
        for ind in arith['indicators']:
            console.print(f"  [yellow]⚠ {ind}[/]")
    _spacer()

# ── cfg - 控制流图 ────────────────────────────────────────────────

def cmd_cfg(args):
    """构建DEX方法控制流图（基本块分割 + 边推导 + 可视化）"""
    from apk_reverse_engine.core.dex_parser import DexParser
    from apk_reverse_engine.core.dex.disassembler import Disassembler
    from apk_reverse_engine.analysis.code_analyzer import CFGBuilder
    
    with console.status(f"{ICO['dex']} 构建控制流图...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            total_blocks = 0
            total_edges = 0
            for dex_name in ctx.get_dex_files():
                data = ctx.read_file(dex_name)
                parser = DexParser(data)
                classes = parser.get_class_defs()
                for cls in classes:
                    if args.class_name and args.class_name not in cls['class_name']:
                        continue
                    for mlist_name in ['direct_methods', 'virtual_methods']:
                        for m in cls.get(mlist_name, []):
                            if args.method and args.method.lower() not in m['name'].lower():
                                continue
                            
                            # 获取指令列表
                            instructions = []
                            try:
                                code_item = parser.get_code_item(m)
                                if code_item:
                                    disasm = Disassembler(code_item)
                                    instructions = disasm.disassemble()
                            except Exception as e:
                                from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/cli.py:2626 suppressed: %s", e)
                                pass
                            
                            if not instructions:
                                continue
                            
                            # 构建 CFG
                            cfg = CFGBuilder.build(instructions)
                            blocks = cfg.get('blocks', [])
                            edges = cfg.get('edges', [])
                            total_blocks += len(blocks)
                            total_edges += len(edges)
                            
                            # 方法头
                            access_flags = m.get('access_flags', '')
                            console.print(_header(
                                f"{ICO['dex']} {cls['class_name'].split('/')[-1]}.{m['name']}",
                                f"{dex_name} | {len(blocks)} 个基本块, {len(edges)} 条边", 'magenta'
                            ))
                            
                            # 方法信息
                            meta_rows = [
                                ('类', cls['class_name']),
                                ('签名', parser.get_method_signature(m)),
                                ('指令数', str(len(instructions))),
                                ('基本块', str(len(blocks))),
                                ('边', str(len(edges))),
                                ('复杂度', cfg.get('cyclomatic_complexity', '?')),
                                ('访问标志', access_flags or '?'),
                            ]
                            console.print(_kv_table(meta_rows, '📋 CFG 信息', 'magenta'))
                            
                            # 基本块详情
                            if blocks:
                                _section('基本块列表', 'yellow')
                                for i, block in enumerate(blocks):
                                    start = block.get('start', 0)
                                    end = block.get('end', 0)
                                    inst_count = block.get('instruction_count', 0)
                                    block_type = block.get('type', 'normal')
                                    type_icon = {'entry': '🟢', 'exit': '🔴', 'normal': '⬜', 'condition': '🟡', 'loop': '🔄'}.get(block_type, '⬜')
                                    
                                    # 显示块摘要
                                    first_ops = []
                                    if 'instructions' in block:
                                        first_ops = [inst.get('opcode_str', inst.get('opcode', '')) for inst in block['instructions'][:3]]
                                    elif 'first_instructions' in block:
                                        first_ops = block['first_instructions']
                                    
                                    ops_str = ', '.join(str(o) for o in first_ops) if first_ops else ''
                                    console.print(f"  {type_icon} [bold]Block {i+1}[/] [dim]0x{start:04x}-0x{end:04x}[/] ({inst_count} 条指令) {ops_str}")
                                
                                # 边可视化
                                if edges:
                                    _section('控制流边', 'blue')
                                    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
                                    t.add_column("从", style="cyan", width=10)
                                    t.add_column("→", style="dim", width=4)
                                    t.add_column("到", style="cyan", width=10)
                                    t.add_column("类型", style="yellow", width=12)
                                    for edge in edges:
                                        src = f"B{edge.get('from', edge.get('source', 0)) + 1}"
                                        dst = f"B{edge.get('to', edge.get('target', 0)) + 1}"
                                        etype = edge.get('type', '无条件跳转')
                                        eicon = {'条件跳转': '🔀', '无条件跳转': '➡️', '异常': '⚠️', 'fallthrough': '⬇️'}.get(etype, '➡️')
                                        t.add_row(src, '→', dst, f"{eicon} {etype}")
                                    console.print(t)
                            
                            console.print()
    
    if total_blocks > 0:
        _info(f"共分析 {total_blocks} 个基本块, {total_edges} 条控制流边")
    
    _spacer()

# ── dataflow - DEX 数据流分析 ────────────────────────────────────

def cmd_dataflow(args):
    """DEX 数据流分析 (寄存器追踪/污点分析/常量传播)"""
    from apk_reverse_engine.analysis.enhanced import DexDataFlowAnalyzer
    from apk_reverse_engine.core.dex_parser import DexParser

    with console.status(f"{ICO['blue']} 执行数据流分析...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            dex_data = ctx.read_file(ctx.get_dex_files()[0])
            dp = DexParser(dex_data)
            analyzer = DexDataFlowAnalyzer(dp)
            result = analyzer.analyze_method_dataflow(args.class_name, method_name=args.method)

    console.print(_header(f"{ICO['blue']} 数据流分析", f"{args.class_name}{'.' + args.method if args.method else ''}"))
    if 'error' in result:
        _error(result['error'])
        return

    # 寄存器追踪
    regs = result.get('registers', {})
    if regs:
        _section(f"寄存器状态 ({len(regs)}个)")
        t = Table(box=box.SIMPLE)
        t.add_column("寄存器", style="cyan")
        t.add_column("类型", style="yellow")
        t.add_column("值/来源", style="dim")
        for reg, info in list(regs.items())[:20]:
            t.add_row(reg, info.get('type', ''), str(info.get('value', info.get('source', ''))))
        console.print(t)

    # 污点传播
    taint = result.get('taint', {})
    if taint.get('sources') or taint.get('sinks'):
        _section("污点分析")
        if taint.get('sources'):
            console.print(f"  [red]📍 污点源: {', '.join(taint['sources'][:10])}[/]")
        if taint.get('sinks'):
            console.print(f"  [red]🎯 污点汇: {', '.join(taint['sinks'][:10])}[/]")
        if taint.get('paths'):
            _section("污点传播路径")
            for path in taint['paths'][:5]:
                console.print(f"  [dim]{' → '.join(path)}[/]")

    # 常量传播
    consts = result.get('constants', {})
    if consts:
        _section(f"常量传播 ({len(consts)}个)")
        for reg, val in list(consts.items())[:15]:
            console.print(f"  [cyan]{reg}[/] = [yellow]{val}[/]")

    _spacer()

# ── callgraph - 调用图分析 ──────────────────────────────────────

def cmd_callgraph(args):
    """构建 DEX 方法调用图并分析"""
    from apk_reverse_engine.analysis.enhanced import CallGraphBuilder
    from apk_reverse_engine.core.dex_parser import DexParser

    with console.status(f"{ICO['blue']} 构建调用图...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            dex_data = ctx.read_file(ctx.get_dex_files()[0])
            dp = DexParser(dex_data)
            cg = CallGraphBuilder.build_call_graph(dp)

    console.print(_header(f"{ICO['blue']} 调用图分析", os.path.basename(args.apk)))
    _info(f"总方法数: {cg.get('total_methods', 0)}  |  总调用边: {cg.get('total_edges', 0)}")

    # 入口点
    entries = CallGraphBuilder.find_entry_points(cg)
    if entries:
        _section(f"入口点 ({len(entries)}个) - 未被内部调用的方法")
        for e in entries[:15]:
            console.print(f"  [green]📍 {e}[/]")
        if len(entries) > 15:
            console.print(f"  [dim]... 还有 {len(entries) - 15} 个[/]")

    # 热点方法
    hotspots = CallGraphBuilder.find_hotspots(cg, top_n=15)
    if hotspots:
        _section("热点方法 (被调用次数最多)")
        t = Table(box=box.SIMPLE)
        t.add_column("排名", justify="right", style="dim")
        t.add_column("方法", style="cyan")
        t.add_column("被调用次数", justify="right", style="yellow")
        for i, (method, count) in enumerate(hotspots, 1):
            t.add_row(str(i), method, str(count))
        console.print(t)

    # 递归调用
    recursive = CallGraphBuilder.detect_recursive(cg)
    if recursive:
        _section(f"递归调用 ({len(recursive)}个)")
        for r in recursive[:10]:
            console.print(f"  [yellow]🔄 {r}[/]")
        if len(recursive) > 10:
            console.print(f"  [dim]... 还有 {len(recursive) - 10} 个[/]")

    _spacer()

# ── decrypt - 字符串解密分析 ────────────────────────────────────

def cmd_decrypt(args):
    """DEX 加密字符串检测与自动解密"""
    from apk_reverse_engine.analysis.enhanced import StringDecryptor
    from apk_reverse_engine.core.dex_parser import DexParser

    with console.status(f"{ICO['mag']} 分析加密字符串...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            dex_data = ctx.read_file(ctx.get_dex_files()[0])
            dp = DexParser(dex_data)
            result = StringDecryptor.analyze_decrypt_pattern(dp, class_name=args.class_name)

    console.print(_header(f"{ICO['mag']} 字符串解密分析", os.path.basename(args.apk)))
    if 'error' in result:
        _error(result['error'])
        return

    patterns = result.get('decrypt_patterns', [])
    if patterns:
        _section(f"解密模式 ({len(patterns)}个)")
        for p in patterns[:15]:
            console.print(f"  [cyan]算法: {p.get('algorithm', 'unknown')}[/]  "
                         f"[dim]密钥: {p.get('key', '')}[/]")
            if p.get('decrypted'):
                console.print(f"    [green]✅ {p['decrypted'][:60]}[/]")
    else:
        console.print("  [green]✅ 未检测到加密字符串模式[/]")

    # 自动解密结果
    decrypted = result.get('auto_decrypted', [])
    if decrypted:
        _section(f"自动解密成功 ({len(decrypted)}个)")
        for d in decrypted[:15]:
            console.print(f"  [green]{d[:60]}[/]")

    _spacer()

# ── anti - 反分析检测 ───────────────────────────────────────────

def cmd_anti(args):
    """检测 APK 中的反调试/反Root/反模拟器/完整性校验等"""
    from apk_reverse_engine.analysis.enhanced import AntiAnalysisDetector
    from apk_reverse_engine.core.dex_parser import DexParser

    with console.status(f"{ICO['red']} 检测反分析措施...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            class_names = []
            strings = []
            for dex_name in ctx.get_dex_files():
                data = ctx.read_file(dex_name)
                dp = DexParser(data)
                class_names.extend(dp.get_class_names())
                strings.extend(dp.get_strings())
            text = '\n'.join(strings)
            result = AntiAnalysisDetector.detect_all(text, class_names=class_names, strings=strings)

    console.print(_header(f"{ICO['red']} 反分析检测", os.path.basename(args.apk)))

    categories = [
        ('anti_debug', '反调试', '🔴'),
        ('anti_root', '反Root', '🟠'),
        ('anti_emulator', '反模拟器', '🟡'),
        ('integrity_check', '完整性校验', '🟣'),
        ('anti_tamper', '防篡改', '🔵'),
    ]

    total_detected = 0
    for key, label, icon in categories:
        cat = result.get(key, {})
        if cat.get('detected'):
            total_detected += 1
            _section(f"{icon} {label} - 检测到 {cat.get('count', 0)} 项")
            for ind in cat.get('indicators', [])[:8]:
                console.print(f"  [yellow]⚠ {ind}[/]")
            if len(cat.get('indicators', [])) > 8:
                console.print(f"  [dim]... 还有 {len(cat['indicators']) - 8} 项[/]")

    if total_detected == 0:
        console.print("  [green]✅ 未检测到明显反分析措施[/]")
    else:
        console.print()
        _warn(f"共检测到 {total_detected} 类反分析措施，逆向难度较高")

    _spacer()

# ── crypto - 加密分析 ───────────────────────────────────────────

def cmd_crypto(args):
    """全面加密分析 (算法/模式/哈希/弱加密/密钥管理)"""
    from apk_reverse_engine.analysis.enhanced import CryptoAnalyzer
    from apk_reverse_engine.core.dex_parser import DexParser

    with console.status(f"{ICO['yellow']} 执行加密分析...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            class_names = []
            strings = []
            for dex_name in ctx.get_dex_files():
                data = ctx.read_file(dex_name)
                dp = DexParser(data)
                class_names.extend(dp.get_class_names())
                strings.extend(dp.get_strings())
            result = CryptoAnalyzer.analyze(class_names=class_names, strings=strings)

    console.print(_header(f"{ICO['yellow']} 加密分析", os.path.basename(args.apk)))

    # 加密算法
    algos = result.get('algorithms', {})
    if algos:
        _section(f"检测到的加密算法 ({sum(algos.values()) if isinstance(algos, dict) and all(isinstance(v, int) for v in algos.values()) else len(algos)}种)")
        if isinstance(algos, dict):
            for algo, count in algos.items():
                if isinstance(count, int):
                    console.print(f"  [cyan]{algo}[/]: {count}次")
                else:
                    console.print(f"  [cyan]{algo}[/]: {count}")

    # 哈希算法
    hashes = result.get('hashes', {})
    if hashes:
        _section(f"哈希算法 ({len(hashes) if isinstance(hashes, (list, dict)) else hashes}种)")
        if isinstance(hashes, dict):
            for h, c in hashes.items():
                console.print(f"  [cyan]{h}[/]: {c}")
        elif isinstance(hashes, list):
            for h in hashes:
                console.print(f"  [cyan]{h}[/]")

    # 弱加密
    weak = result.get('weak_crypto', {})
    if weak.get('detected'):
        _section("⚠️ 弱加密/不安全算法")
        for w in weak.get('findings', [])[:10]:
            console.print(f"  [red]❌ {w}[/]")
        _warn("检测到弱加密算法，存在安全风险")

    # 密钥
    keys = result.get('keys', {})
    if keys.get('found'):
        _section(f"硬编码密钥 ({keys.get('count', 0)}个)")
        for k in keys.get('keys', [])[:10]:
            console.print(f"  [yellow]🔑 {k}[/]")

    _spacer()

# ── hook - Hook 脚本生成 ────────────────────────────────────────

def cmd_hook(args):
    """生成 Frida/Xposed hook 脚本或 Smali 补丁"""
    from apk_reverse_engine.analysis.enhanced import HookGenerator

    console.print(_header(f"{ICO['green']} Hook 脚本生成", args.target_class))

    bypass_flags = []
    if args.bypass_debug:
        bypass_flags.append('anti_debug')
    if args.bypass_root:
        bypass_flags.append('anti_root')
    if args.bypass_emulator:
        bypass_flags.append('anti_emulator')

    if args.format == 'frida':
        script = HookGenerator.generate_frida_script(
            args.target_class, args.method,
            verbose=args.verbose, trace_args=args.trace_args,
            trace_return=args.trace_return, bypass_flags=bypass_flags or None
        )
        _section("Frida 脚本")
        console.print(script)
    elif args.format == 'xposed':
        if not args.package:
            _error("Xposed 模块需要 --package 参数")
            return
        script = HookGenerator.generate_xposed_module(
            args.package, args.target_class, args.method, bypass_flags=bypass_flags or None
        )
        _section("Xposed 模块代码")
        console.print(script)
    elif args.format == 'smali':
        script = HookGenerator.generate_smali_patch(
            args.target_class, args.method, args.patch_type, args.value or '0x0'
        )
        _section("Smali 补丁")
        console.print(script)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(script)
        _success(f"已保存到 {args.output}")

    _spacer()

# ── cmd_info - 信息一站式提取 ─────────────────────────────────
def cmd_info(args):
    """提取 APK 一站式元信息"""
    from apk_reverse_engine.tools.info_extractor import APKInfoExtractor
    r = APKInfoExtractor.extract_all(args.apk)
    if args.json:
        console.print_json(json.dumps(r, ensure_ascii=False, default=str))
        return
    console.print(_header('📦 APK 信息提取', os.path.basename(args.apk)))
    _section('基本信息')
    _kv_table([
        ('文件名', r.get('file_name', '')),
        ('大小', r.get('file_size_display', '')),
        ('SHA256', r.get('sha256', '')),
        ('包名', r.get('package_name', '')),
        ('版本名', r.get('version_name', '')),
        ('版本号', r.get('version_code', '')),
        ('最小SDK', r.get('min_sdk', '')),
        ('目标SDK', r.get('target_sdk', '')),
    ])
    _section('统计')
    _kv_table([
        ('DEX文件数', r.get('dex_count', 0)),
        ('类总数', r.get('total_classes', 0)),
        ('方法总数', r.get('total_methods', 0)),
        ('字符串总数', r.get('total_strings', 0)),
        ('SO文件数', r.get('so_files', {}).get('count', 0)),
        ('ABI架构', ', '.join(r.get('so_files', {}).get('architectures', {}).keys()) or '无'),
    ])
    _section('签名')
    sig = r.get('signature', {})
    _kv_table([
        ('已签名', '✅' if sig.get('is_signed') else '❌'),
        ('v1签名', '✅' if sig.get('v1_signature') else '❌'),
        ('v2签名', '✅' if sig.get('v2_signature') else '❌'),
        ('v3签名', '✅' if sig.get('v3_signature') else '❌'),
        ('证书SHA256', sig.get('cert_sha256', '')),
    ])


# ── cmd_validate - APK 完整性验证 ─────────────────────────────
def cmd_validate(args):
    """验证 APK 完整性"""
    from apk_reverse_engine.tools.validator import APKValidator
    if args.compare:
        r = APKValidator.compare_checksums(args.apk, args.compare)
        console.print(_header('🔍 APK 校验和对比'))
        _kv_table([
            ('文件A', r.get('file_a', '')),
            ('文件B', r.get('file_b', '')),
            ('SHA256(A)', r.get('sha256_a', '')),
            ('SHA256(B)', r.get('sha256_b', '')),
            ('一致', '✅' if r.get('match') else '❌'),
        ])
        return
    r = APKValidator.validate_apk(args.apk)
    console.print(_header('🛡️ APK 完整性验证', os.path.basename(args.apk)))
    console.print(_make_panel(
        f"[bold]{'✅ 验证通过' if r.get('valid') else '❌ 验证失败'}[/]",
        '结 果', 'green' if r.get('valid') else 'red'))
    info = r.get('info', {})
    _section('文件信息')
    _kv_table([
        ('大小', info.get('file_size', '')),
        ('SHA256', info.get('sha256', '')),
        ('包名', info.get('package', '')),
        ('版本号', info.get('version_code', '')),
        ('目标SDK', info.get('target_sdk', '')),
        ('条目数', info.get('entry_count', '')),
        ('已签名', '✅' if info.get('is_signed') else '❌'),
    ])
    if r.get('errors'):
        _section('错误')
        for e in r['errors']:
            console.print(f'  [bold red]❌ {e}[/]')
    if r.get('warnings'):
        _section('警告')
        for w in r['warnings']:
            console.print(f'  [bold yellow]⚠️ {w}[/]')


# ── cmd_batch - 批量处理 ──────────────────────────────────────
def cmd_batch(args):
    """批量处理 APK"""
    from apk_reverse_engine.tools.batch import APKBatchProcessor
    if args.mode == 'analyze':
        r = APKBatchProcessor.batch_analyze(args.dir, recursive=not args.no_recursive, max_workers=args.workers)
        console.print(_header('📊 批量分析', args.dir))
        if not r.get('success'):
            _error(r.get('error', '未知错误'))
            return
        console.print(f'  [bold]共发现 {r["total"]} 个 APK[/]')
        for path, info in r.get('results', {}).items():
            if 'error' in info:
                console.print(f'  [red]❌ {os.path.basename(path)}: {info["error"]}[/]')
            else:
                cert = (info.get('cert_sha256') or '')[:12]
                console.print(f'  [green]✅ {os.path.basename(path)}[/] [dim]{info.get("package_name","")} v{info.get("version_name","")}[/] '
                              f'[dim]{info.get("dex_count",0)}dex {info.get("so_count",0)}so[/] [dim]{cert}...[/]')
    elif args.mode == 'validate':
        r = APKBatchProcessor.batch_validate(args.dir, recursive=not args.no_recursive, max_workers=args.workers)
        console.print(_header('🛡️ 批量验证', args.dir))
        console.print(f'  [bold]共 {r.get("total",0)} 个 APK，通过 {r.get("valid_count",0)}，失败 {r.get("invalid_count",0)}[/]')
        for path, info in r.get('results', {}).items():
            ok = info.get('valid')
            console.print(f'  {"[green]✅" if ok else "[red]❌"} {os.path.basename(path)}[/]'
                          + (f'  [dim]{", ".join(info.get("errors",[])[:2])}[/]' if not ok else ''))
    elif args.mode == 'sign':
        r = APKBatchProcessor.batch_sign(args.dir, output_dir=args.output, recursive=not args.no_recursive)
        console.print(_header('📝 批量签名', args.dir))
        console.print(f'  [bold]共 {r.get("total",0)} 个 APK，成功 {r.get("signed_count",0)}，失败 {r.get("failed_count",0)}[/]')
        for path, info in r.get('results', {}).items():
            console.print(f'  {"[green]✅" if info.get("success") else "[red]❌"} {os.path.basename(path)}[/] '
                          f'[dim]{info.get("output","") or info.get("error","")}[/]')
    elif args.mode == 'report':
        r = APKBatchProcessor.batch_report(args.dir, recursive=not args.no_recursive, output_json=args.json_out)
        console.print(_header('📄 批量报告', args.dir))
        if r.get('success'):
            console.print(r.get('markdown', ''))
        else:
            _error(r.get('error', '未知错误'))


# ── 交互式模式 ───────────────────────────────────────────────


# 最近使用的 APK 历史（持久化到 ~/.apk_rev_history）
_HIST_FILE = os.path.expanduser('~/.apk_rev_history')
_HIST_MAX = 8

def _load_history():
    try:
        if os.path.exists(_HIST_FILE):
            with open(_HIST_FILE, 'r', encoding='utf-8') as f:
                return [l.strip() for l in f if l.strip()]
    except Exception as e:
        from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/cli.py:3129 suppressed: %s", e)
        pass
    return []

def _save_history(apk):
    hist = _load_history()
    if apk in hist:
        hist.remove(apk)
    hist.insert(0, apk)
    hist = hist[:_HIST_MAX]
    try:
        with open(_HIST_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(hist))
    except Exception as e:
        from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/cli.py:3142 suppressed: %s", e)
        pass

# 交互式命令注册表: 名称 -> (分类, 说明, 需要的输入字段)
_INTERACTIVE_COMMANDS = {
    "inspect":  ("基本信息", "📦 APK 基本信息概览", ["apk"]),
    "info":     ("基本信息", "📊 信息一站式提取 (包名/版本/DEX/SO/签名)", ["apk"]),
    "validate": ("基本信息", "🛡️ APK 完整性验证", ["apk"]),
    "analyze":  ("基本信息", "🔬 全面分析 (权限/混淆/加固/安全)", ["apk"]),
    "manifest": ("基本信息", "📋 解析 AndroidManifest.xml", ["apk"]),
    "dex":      ("基本信息", "📜 DEX 文件分析", ["apk"]),
    "classes":  ("基本信息", "📦 列出 DEX 类名", ["apk"]),
    "so":       ("基本信息", "🔧 分析 SO 文件", ["apk"]),
    "search":   ("分析与搜索", "🔍 搜索关键字 (字符串/类/方法)", ["apk", "query"]),
    "clue":     ("分析与搜索", "🔗 线索串联分析", ["apk"]),
    "core":     ("分析与搜索", "🎯 核心类定位", ["apk"]),
    "sdk":      ("分析与搜索", "🌐 SDK/追踪器检测", ["apk"]),
    "strings":  ("分析与搜索", "📜 字符串深度分析", ["apk"]),
    "resobf":   ("分析与搜索", "🎨 资源混淆检测", ["apk"]),
    "ads":      ("分析与搜索", "📢 广告检测", ["apk"]),
    "adremove": ("分析与搜索", "🧹 一键移除广告", ["apk", "output"]),
    "social":   ("分析与搜索", "💬 社交登录检测", ["apk"]),
    "deobf":    ("分析与搜索", "🎭 去混淆分析", ["apk"]),
    "cert":     ("分析与搜索", "📝 签名证书分析", ["apk"]),
    "endpoints":("分析与搜索", "🌐 提取网络端点", ["apk"]),
    "keyscan":  ("分析与搜索", "🔑 扫描硬编码密钥", ["apk"]),
    "unpack":   ("打包与转换", "📦 解压 APK", ["apk", "output"]),
    "verify":   ("打包与转换", "🔍 校验解压完整性", ["apk", "output"]),
    "rebuild":  ("打包与转换", "📦 从目录重建 APK", ["input", "output"]),
    "sign":     ("打包与转换", "📝 签名 APK", ["apk", "output"]),
    "zipalign": ("打包与转换", "📐 对齐 APK", ["apk", "output"]),
}

def _interactive_prompt(prompt, default=''):
    """带默认值的输入提示（纯文本，避免 Rich 标记开销）"""
    try:
        if default:
            val = input(f"  {prompt} ({default}): ") or default
        else:
            val = input(f"  {prompt}: ")
    except (EOFError, KeyboardInterrupt):
        return None
    return val.strip()

def _interactive_choose_apk():
    """让用户选择 APK 文件（支持历史记录/路径输入/目录浏览）— Rich 增强版"""
    hist = _load_history()
    while True:
        console.print()
        if hist:
            console.print(f"  [bold cyan]📦 最近使用的 APK ({len(hist[:5])} 条):[/]")
            t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            t.add_column("#", justify="right", style="dim", width=4)
            t.add_column("文件名", style="bold cyan")
            t.add_column("目录", style="dim")
            for i, h in enumerate(hist[:5], 1):
                t.add_row(str(i), os.path.basename(h), os.path.dirname(h))
            console.print(t)
            console.print(f"  [dim]输入 [bold]c[/] 清除历史 | [bold].[/] 扫描当前目录[/]")
        else:
            console.print(f"  [dim]无历史记录 | 输入路径或 [bold].[/] 扫描当前目录[/]")
        console.print(f"  [dim]{'─' * 50}[/]")
        p = _interactive_prompt(
            "APK 路径 (历史编号/直接路径/. 扫描当前目录/目录路径)"
        )
        if p is None:
            return None
        p = p.strip()
        if not p:
            continue
        # 清除历史
        if p.lower() == 'c':
            try:
                os.remove(_HIST_FILE)
            except Exception as e:
                from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/cli.py:3216 suppressed: %s", e)
                pass
            hist = []
            _success("历史已清除")
            continue
        # 历史编号选择
        if p.isdigit() and hist:
            idx = int(p)
            if 1 <= idx <= len(hist):
                apk = hist[idx - 1]
                if os.path.isfile(apk):
                    return apk
                _warn("文件已不存在")
                hist.pop(idx - 1)
                continue
        # 目录 -> 列出其中的归档文件（非递归，避免卡顿）
        if os.path.isdir(p):
            try:
                _archive_exts = ('.apk', '.zip', '.jar', '.war', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.dex', '.so', '.aar')
                apks = sorted([os.path.join(p, f) for f in os.listdir(p)
                               if f.lower().endswith(_archive_exts) and os.path.isfile(os.path.join(p, f))])
            except PermissionError:
                _error("无权限访问目录")
                continue
            if not apks:
                _warn("该目录下未找到支持的归档文件")
                continue
            console.print(f"  [bold cyan]📂 找到 {len(apks)} 个文件:[/]")
            t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            t.add_column("#", justify="right", style="dim", width=4)
            t.add_column("文件名", style="cyan")
            t.add_column("大小", justify="right", style="yellow")
            for i, a in enumerate(apks[:20], 1):
                try:
                    sz = _fmt_size(os.path.getsize(a))
                except Exception:
                    sz = '?'
                t.add_row(str(i), os.path.basename(a), sz)
            console.print(t)
            if len(apks) > 20:
                console.print(f"  [dim]... 还有 {len(apks)-20} 个 (输入完整路径直接指定)[/]")
            sel = _interactive_prompt("选择编号")
            try:
                return apks[int(sel) - 1]
            except (ValueError, IndexError):
                _error("无效编号")
                continue
        if os.path.isfile(p):
            return p
        _error("路径不存在")

def interactive_mode():
    """交互式菜单模式 — Rich 增强版"""
    console.print()
    console.print(Panel.fit(
        "[bold cyan]⚡ APK Reverse Engineering Engine v2[/]\n"
        "[dim]  交互模式  |  47 命令  |  全链路逆向工具集  [/]",
        border_style="cyan", box=box.DOUBLE_EDGE
    ))

    # 按分类分组
    groups = {}
    for name, (cat, desc, _) in _INTERACTIVE_COMMANDS.items():
        groups.setdefault(cat, []).append((name, desc))

    def _status_bar():
        """底部状态栏：显示上次执行的命令"""
        if last_cmd:
            console.print(f"  [dim]┄┄ 上次: [bold cyan]{last_cmd}[/]  [dim]| 输入 r 重跑 | b 返回菜单 | q 退出[/]")
        else:
            console.print(f"  [dim]┄┄ 输入类别编号或命令名 | b 返回菜单 | q 退出[/]")

    def show_menu():
        cat_list = list(groups.keys())
        console.print()
        t = Table(box=box.ROUNDED, border_style="cyan", show_header=True, padding=(0, 2))
        t.add_column("#", justify="right", style="dim", width=4)
        t.add_column("类别", style="bold cyan")
        t.add_column("命令数", justify="right", style="yellow")
        t.add_column("说明", style="dim")
        cat_descs = {
            "基本信息": "APK 结构/版本/签名/DEX/SO 概览",
            "分析与搜索": "线索串联/核心定位/SDK/字符串/混淆/广告/安全",
            "打包与转换": "解包/重建/签名/对齐/格式转换",
        }
        for i, cat in enumerate(cat_list, 1):
            cnt = len(groups[cat])
            t.add_row(str(i), cat, str(cnt), cat_descs.get(cat, ""))
        console.print(t)
        _status_bar()
        return cat_list

    def show_category(cat_name):
        """以 Rich 表格展示某个类别下的所有命令"""
        cmds = groups[cat_name]
        console.print()
        console.print(f"  [bold cyan]📂 {cat_name}[/]  [dim]({len(cmds)} 个命令)[/]")
        console.print(f"  [dim]{'─' * 50}[/]")
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column("#", justify="right", style="dim", width=4)
        t.add_column("命令", style="bold cyan", width=14)
        t.add_column("说明", style="white")
        for i, (name, desc) in enumerate(cmds, 1):
            t.add_row(str(i), name, desc)
        console.print(t)
        console.print(f"  [bold yellow]0[/]. [dim]返回菜单[/]  [bold yellow]b[/]. [dim]返回[/]  [bold yellow]q[/]. [dim]退出[/]  [bold yellow]r[/]. [dim]重跑[/]")
        return cmds

    def run_command(cmd_name):
        """收集参数并执行指定命令"""
        nonlocal last_cmd, last_values
        if cmd_name not in _INTERACTIVE_COMMANDS:
            _error(f"未知命令: {cmd_name}")
            return
        _, _, fields = _INTERACTIVE_COMMANDS[cmd_name]
        # 收集参数
        values = {}
        for f in fields:
            if f == 'apk':
                apk = _interactive_choose_apk()
                if apk is None:
                    return
                _save_history(apk)
                values['apk'] = apk
            elif f == 'query':
                q = _interactive_prompt("搜索关键字")
                if q is None:
                    return
                values['query'] = q
            elif f == 'output':
                out = _interactive_prompt("输出路径", cmd_name + '_out')
                if out is None:
                    return
                values['output'] = out
            elif f == 'input':
                inp = _interactive_prompt("输入目录")
                if inp is None:
                    return
                values['input'] = inp

        # 保存为上一条命令
        last_cmd = cmd_name
        last_values = values

        # 构造 argparse.Namespace 并调用（使用模块级分发表，避免重复构建）
        ns = argparse.Namespace()
        for k, v in values.items():
            setattr(ns, k, v)
        # 常见可选参数默认值
        for opt in ('json', 'max', 'workers', 'force', 'output', 'compare'):
            if not hasattr(ns, opt):
                if opt == 'max':
                    setattr(ns, opt, 100)
                elif opt == 'workers':
                    setattr(ns, opt, 4)
                else:
                    setattr(ns, opt, None)
        console.print()
        console.print(f"  [bold cyan]▶ 执行: {cmd_name}[/]")
        console.print(f"  [dim]{'─' * 40}[/]")
        try:
            _INTERACTIVE_DISPATCH[cmd_name](ns)
        except Exception as e:
            _error(f"执行失败: {e}")
        console.print()

    last_cat = None
    last_cmd = None
    last_values = None
    while True:
        try:
            if last_cat is None:
                cats = show_menu()
                sel = _interactive_prompt("选择")
                if sel is None:
                    return
                s = sel.strip().lower()
                if s in ('exit', 'quit', 'q'):
                    break
                if s in ('menu', 'b'):
                    continue
                # 快捷重新执行上一条命令
                if s in ('r', 'rr') and last_cmd:
                    run_command(last_cmd)
                    continue
                if s == 'help' or s == '?':
                    console.print()
                    console.print(Panel(
                        f"[bold]快捷操作:[/]\n"
                        f"  [cyan]数字[/]    选择类别/命令\n"
                        f"  [cyan]命令名[/]  直接执行（支持前缀模糊匹配）\n"
                        f"  [cyan]r[/]       重跑上一条命令\n"
                        f"  [cyan]b / menu[/]  返回上级菜单\n"
                        f"  [cyan]q / exit[/]  退出\n\n"
                        f"[bold]可用命令 ({len(_INTERACTIVE_COMMANDS)}):[/]\n"
                        f"  [cyan]{', '.join(_INTERACTIVE_COMMANDS.keys())}[/]",
                        title="❓ 帮助", border_style="yellow", title_align="left"
                    ))
                    continue
                # 命令名模糊匹配（支持前缀/子串）
                if s not in _INTERACTIVE_COMMANDS:
                    matches = [n for n in _INTERACTIVE_COMMANDS if s in n or n.startswith(s)]
                    if len(matches) == 1:
                        console.print(f"  [dim]▶ 匹配到命令 [bold cyan]{matches[0]}[/][/]")
                        run_command(matches[0])
                        continue
                    elif len(matches) > 1:
                        _warn(f"匹配到多个命令: {', '.join(matches)}")
                        continue
                # 直接输入命令名
                if s in _INTERACTIVE_COMMANDS:
                    run_command(s)
                    continue
                try:
                    idx = int(sel)
                except ValueError:
                    _error("无效输入 (输入命令名或类别编号)")
                    continue
                if idx == 0:
                    break
                if idx < 1 or idx > len(cats):
                    _error("无效类别")
                    continue
                last_cat = cats[idx - 1]
            # 显示该类别下的命令
            cmds = show_category(last_cat)
            sel = _interactive_prompt("选择命令")
            if sel is None:
                return
            s = sel.strip().lower()
            if s in ('exit', 'quit', 'q'):
                break
            if s in ('menu', 'b'):
                last_cat = None
                continue
            # 快捷重新执行上一条命令
            if s in ('r', 'rr') and last_cmd:
                run_command(last_cmd)
                last_cat = None
                continue
            # 直接输入命令名
            if s in _INTERACTIVE_COMMANDS:
                run_command(s)
                last_cat = None
                continue
            # 模糊匹配
            if s not in _INTERACTIVE_COMMANDS:
                matches = [n for n in _INTERACTIVE_COMMANDS if s in n or n.startswith(s)]
                if len(matches) == 1:
                    console.print(f"  [dim]▶ 匹配到命令 [bold cyan]{matches[0]}[/][/]")
                    run_command(matches[0])
                    last_cat = None
                    continue
                elif len(matches) > 1:
                    _warn(f"匹配到多个命令: {', '.join(matches)}")
                    continue
            try:
                idx = int(sel)
            except ValueError:
                _error("无效输入 (输入编号或命令名)")
                continue
            if idx == 0:
                last_cat = None
                continue
            if idx < 1 or idx > len(cmds):
                _error("无效编号")
                continue

            cmd_name = cmds[idx - 1][0]
            run_command(cmd_name)
            last_cat = None
        except KeyboardInterrupt:
            break
    console.print()
    console.print(Panel.fit(
        "[bold cyan]再见！👋[/]  [dim]感谢使用 APK Reverse Engine[/]",
        border_style="dim", box=box.SIMPLE
    ))

def _safe_dispatch(cmd_name):
    """动态获取命令函数"""
    fn = globals().get('cmd_' + cmd_name)
    return fn if fn else (lambda a: console.print(f"  [red]命令 {cmd_name} 不可用[/]"))


# 模块级命令分发表（避免每次执行时重复构建，减少卡顿）
_INTERACTIVE_DISPATCH = {
    "inspect": lambda a: globals().get('cmd_inspect', lambda x: None)(a),
    "info": lambda a: globals().get('cmd_info', lambda x: None)(a),
    "validate": lambda a: globals().get('cmd_validate', lambda x: None)(a),
    "analyze": lambda a: globals().get('cmd_analyze', lambda x: None)(a),
    "manifest": lambda a: globals().get('cmd_manifest', lambda x: None)(a),
    "dex": lambda a: globals().get('cmd_dex', lambda x: None)(a),
    "classes": lambda a: globals().get('cmd_classes', lambda x: None)(a),
    "so": lambda a: globals().get('cmd_so', lambda x: None)(a),
    "search": lambda a: globals().get('cmd_search', lambda x: None)(a),
    "unpack": lambda a: globals().get('cmd_unpack', lambda x: None)(a),
    "verify": lambda a: globals().get('cmd_verify', lambda x: None)(a),
}
# 其余命令使用动态分发
for _n in ("clue", "core", "sdk", "strings", "resobf", "ads", "social",
           "deobf", "cert", "endpoints", "keyscan", "rebuild", "sign", "zipalign",
           "dataflow", "callgraph", "decrypt", "anti", "crypto", "hook",
           "metadata", "multidex", "native-xref", "report"):
    _INTERACTIVE_DISPATCH.setdefault(_n, _safe_dispatch(_n))


# ── 增强分析命令 ──────────────────────────────────────────────

def cmd_metadata(args):
    """DEX 元数据深度分析 - Annotation/Debug/Hidden API 检测"""
    import json
    from apk_reverse_engine.core.apk_file_ops import ApkFileOps
    from apk_reverse_engine.core.dex_parser import DexParser
    from apk_reverse_engine.analysis.enhanced.dex_metadata import DexMetadataAnalyzer

    ops = ApkFileOps(args.apk)
    dex_data = ops.get_dex_data()
    if not dex_data:
        console.print("[red]未找到 DEX 文件[/]")
        return

    dp = DexParser(dex_data[0])
    max_cls = getattr(args, 'max_classes', 200)
    only = getattr(args, 'only', None)

    if only == 'annotations':
        result = DexMetadataAnalyzer.analyze_annotations(dp)
    elif only == 'debug':
        result = DexMetadataAnalyzer.analyze_debug_info(dp, max_cls)
    elif only == 'hidden_api':
        result = DexMetadataAnalyzer.detect_hidden_api(dp)
    elif only == 'processors':
        result = DexMetadataAnalyzer.detect_annotation_processors(dp)
    elif only == 'serialization':
        result = DexMetadataAnalyzer.detect_serialization(dp)
    else:
        result = DexMetadataAnalyzer.analyze(dp, max_cls)

    console.print(json.dumps(result, ensure_ascii=False, indent=2, default=str))


def cmd_multidex(args):
    """多 DEX 关联分析"""
    import json
    from apk_reverse_engine.core.apk_file_ops import ApkFileOps
    from apk_reverse_engine.core.dex_parser import DexParser
    from apk_reverse_engine.analysis.enhanced.multidex_analyzer import MultiDexAnalyzer

    ops = ApkFileOps(args.apk)
    dex_datas = ops.get_dex_data()
    if not dex_datas:
        console.print("[red]未找到 DEX 文件[/]")
        return

    dex_parsers = {}
    for i, dd in enumerate(dex_datas):
        dex_parsers[f'classes{i+1 if i > 0 else ""}.dex'] = DexParser(dd)

    only = getattr(args, 'only', None)
    if only == 'distribution':
        result = MultiDexAnalyzer.analyze_dex_distribution(dex_parsers)
    elif only == 'cross_refs':
        result = MultiDexAnalyzer.analyze_cross_references(dex_parsers)
    elif only == 'duplicates':
        result = MultiDexAnalyzer.detect_duplicate_classes(dex_parsers)
    else:
        result = MultiDexAnalyzer.analyze(dex_parsers)

    console.print(json.dumps(result, ensure_ascii=False, indent=2, default=str))


def cmd_native_xref(args):
    """Native-Java 交叉引用分析"""
    import json
    from apk_reverse_engine.core.apk_file_ops import ApkFileOps
    from apk_reverse_engine.core.dex_parser import DexParser
    from apk_reverse_engine.core.native_analyzer import ElfImage
    from apk_reverse_engine.analysis.enhanced.native_crossref import NativeCrossRefAnalyzer

    ops = ApkFileOps(args.apk)
    dex_data = ops.get_dex_data()
    if not dex_data:
        console.print("[red]未找到 DEX 文件[/]")
        return

    dp = DexParser(dex_data[0])

    # 获取 SO 符号
    so_symbols_map = {}
    so_files = ops.get_so_files() if hasattr(ops, 'get_so_files') else []
    if args.so:
        so_files = [args.so]

    for so_path in so_files:
        try:
            with open(so_path, 'rb') as f:
                so_data = f.read()
            elf = ElfImage(so_data)
            symbols = [s.name for s in elf.symbols if s.name]
            so_name = so_path.split('/')[-1]
            so_symbols_map[so_name] = symbols
        except Exception:
            continue

    result = NativeCrossRefAnalyzer.analyze(
        dex_parser=dp,
        so_symbols_map=so_symbols_map if so_symbols_map else None,
    )

    console.print(json.dumps(result, ensure_ascii=False, indent=2, default=str))


def cmd_report(args):
    """生成分析报告"""
    import json as json_mod
    from apk_reverse_engine.core.apk_file_ops import ApkFileOps
    from apk_reverse_engine.core.dex_parser import DexParser
    from apk_reverse_engine.analysis.enhanced.report_generator import ReportGenerator
    from apk_reverse_engine.analysis.enhanced.vulnerability_scanner import VulnerabilityScanner

    ops = ApkFileOps(args.apk)
    apk_name = args.apk.split('/')[-1]

    results = {}

    # 基本信息
    try:
        from apk_reverse_engine.tools.info_extractor import InfoExtractor
        info = InfoExtractor(args.apk).extract()
        results['basic_info'] = info
    except Exception:
        results['basic_info'] = {'file': apk_name}

    # DEX 分析
    try:
        dex_datas = ops.get_dex_data()
        if dex_datas:
            dp = DexParser(dex_datas[0])
            strings = dp.get_strings()
            results['dex_info'] = {
                'class_count': len(dp.get_class_defs()),
                'string_count': len(strings),
                'method_count': len(dp.get_methods()),
            }

            # 漏洞扫描
            vuln = VulnerabilityScanner.scan_strings(strings)
            results['vulnerability_scan'] = vuln

            if getattr(args, 'full', False):
                from apk_reverse_engine.analysis.enhanced.dex_metadata import DexMetadataAnalyzer
                results['dex_metadata'] = DexMetadataAnalyzer.analyze(dp, max_classes=100)
    except Exception as e:
        results['dex_error'] = str(e)

    fmt = args.format
    output_path = args.output

    report = ReportGenerator.generate(results, apk_name, output_path, fmt)
    console.print(f"[green]✅ 报告已生成[/] ({fmt})")
    if output_path:
        console.print(f"[dim]输出: {output_path}[/]")
    else:
        console.print(report[:500] + '...' if len(report) > 500 else report)


# ── 主入口 ──────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="[bold cyan]APK Reverse Engineering Engine v2[/] - 全功能 APK 逆向工具集",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
[bold]示例:[/]
  reng inspect app.apk         查看 APK 基本信息
  reng analyze app.apk         全面分析 APK
  reng manifest app.apk        解析 AndroidManifest.xml
  reng classes app.apk         列出所有类名
  reng so app.apk              分析 SO 文件
  reng search app.apk key      搜索关键字
  reng unpack app.apk ./out    解压 APK (分类归档)
  reng unpack app.apk ./out -i  增量解压
  reng unpack app.apk ./out -p  并行解压
  reng unpack app.apk ./out -n  预览（不解压）
  reng unpack app.apk ./out -c dex,so  只提取 DEX 和 SO
  reng unpack app.apk ./out -f  扁平化输出
  reng decode app.apk ./out    Apktool 解包
  reng build ./dir out.apk     Apktool 重打包
  reng sign app.apk signed.apk 签名 APK
  reng jadx app.apk ./src      JADX 反编译
  reng clue app.apk            线索串联分析
  reng merge app1.apk,app2.apk out.apk 合并多个APK
  reng merge classes.dex out.dex --dex  合并DEX
  reng rebuild ./dir out.apk   从目录重建APK
  reng zipalign in.apk out.apk 对齐APK
  reng convert dex2jar classes.dex out.jar  DEX→JAR
  reng convert dex2smali classes.dex ./smali  DEX→Smali
  reng patch app.apk out --type hex --old 9090 --new 9091  SO 补丁
        """
    )
    parser.add_argument('--version', action='version', version='APK Reverse Engine v2.4.0')
    parser.add_argument('--interactive', '-i', action='store_true', help='🎮 进入交互式菜单模式')
    sub = parser.add_subparsers(dest="command")

    # inspect
    p = sub.add_parser("inspect", help="📦 APK 基本信息概览")
    p.add_argument("apk", help="APK 文件路径")
    p.set_defaults(func=cmd_inspect)

    # info - 信息一站式提取
    p = sub.add_parser("info", help="📊 APK 信息一站式提取 (包名/版本/DEX/SO/签名/证书)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--json", action="store_true", help="以JSON格式输出")
    p.set_defaults(func=cmd_info)

    # validate - APK 完整性验证
    p = sub.add_parser("validate", help="🛡️ APK 完整性验证 (ZIP/签名/Manifest/SHA256)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--compare", help="对比另一个 APK 的 SHA256 校验和")
    p.set_defaults(func=cmd_validate)

    # batch - 批量处理
    p = sub.add_parser("batch", help="📦 批量处理 APK (分析/验证/签名/报告)")
    p.add_argument("mode", choices=['analyze', 'validate', 'sign', 'report'],
                   help="模式: analyze分析 / validate验证 / sign签名 / report报告")
    p.add_argument("dir", help="APK 目录路径")
    p.add_argument("--output", "-o", help="输出目录 (sign/report模式)")
    p.add_argument("--workers", "-w", type=int, default=4, help="并发线程数 [默认=4]")
    p.add_argument("--no-recursive", action="store_true", help="不递归子目录")
    p.add_argument("--json-out", help="报告输出为 JSON 文件路径 (report模式)")
    p.set_defaults(func=cmd_batch)

    # analyze
    p = sub.add_parser("analyze", help="🔬 全面分析 APK (权限/混淆/加固/安全/SO)")
    p.add_argument("apk", help="APK 文件路径")
    p.set_defaults(func=cmd_analyze)

    # manifest
    p = sub.add_parser("manifest", help="📋 解析 AndroidManifest.xml")
    p.add_argument("apk", help="APK 文件路径")
    p.set_defaults(func=cmd_manifest)

    # dex
    p = sub.add_parser("dex", help="📜 DEX 文件分析")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--search", "-s", help="搜索类/方法关键字")
    p.set_defaults(func=cmd_dex)

    # classes
    p = sub.add_parser("classes", help="📦 列出 DEX 类名")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--max", "-n", type=int, default=100, help="最大显示数量")
    p.set_defaults(func=cmd_classes)

    # so
    p = sub.add_parser("so", help="🔧 分析 SO 文件")
    p.add_argument("apk", help="APK 文件路径")
    p.set_defaults(func=cmd_so)

    # search
    p = sub.add_parser("search", help="🔍 在 APK 中搜索")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("query", help="搜索关键字")
    p.add_argument("--scope", default="all", choices=["strings", "classes", "methods", "all"], help="搜索范围")
    p.add_argument("--max", "-n", type=int, default=100, help="最大结果数")
    p.set_defaults(func=cmd_search)

    # unpack
    p = sub.add_parser("unpack", help="📦 解压任意归档 (APK/ZIP/JAR/WAR/TAR/单文件/目录 - 分类归档/并行/增量/过滤/预览)")
    p.add_argument("apk", help="文件路径 (支持 APK/ZIP/JAR/WAR/TAR/单文件/目录)")
    p.add_argument("output", help="输出目录")
    p.add_argument("--structure", "-s", action="store_true", default=True,
                   help="按分类归档子目录 (dex/lib/res/assets/META-INF) [默认开启]")
    p.add_argument("--no-structure", action="store_false", dest="structure",
                   help="不解分类，直接解压到根目录")
    p.add_argument("--parallel", "-p", action="store_true", help="多线程并行解压 (大APK加速)")
    p.add_argument("--workers", "-w", type=int, default=4, help="并行线程数 [默认=4]")
    p.add_argument("--incremental", "-i", action="store_true", help="增量模式 (跳过已存在且大小一致的文件)")
    p.add_argument("--include", help="仅提取指定类型，逗号分隔，如 .dex,.so")
    p.add_argument("--exclude", help="排除指定类型，逗号分隔，如 .png,.jpg")
    p.add_argument("--flatten", "-f", action="store_true", help="扁平化，不保留子目录结构")
    p.add_argument("--dry-run", "-n", action="store_true", help="仅预览不解压")
    p.add_argument("--category", "-c", help="按分类提取 (dex/lib/res/assets/meta_inf/all)，支持别名 so→lib, cert→meta_inf")
    p.add_argument("--manifest", "-m", help="JSON清单文件路径，精确指定要提取的文件列表（原子性+校验）")
    p.add_argument("--no-verify", action="store_true", help="使用清单时跳过SHA256校验")
    p.add_argument("--no-fail-missing", action="store_true", help="使用清单时允许缺失条目不报错")
    p.add_argument("--standalone", action="store_true", help="纯Python独立模式 (兼容第三方中转站，不依赖apktool等外部工具)")
    p.set_defaults(func=cmd_unpack)

    # verify
    p = sub.add_parser("verify", help="🔍 校验解压完整性")
    p.add_argument("apk", help="原始 APK 文件路径")
    p.add_argument("output", help="解压目录路径")
    p.set_defaults(func=cmd_verify)

    # decode
    p = sub.add_parser("decode", help="🔧 Apktool 解包")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("output", help="输出目录")
    p.add_argument("--force", "-f", action="store_true", help="强制覆盖")
    p.set_defaults(func=cmd_decode)

    # build
    p = sub.add_parser("build", help="🔧 Apktool 重打包")
    p.add_argument("input", help="解包目录")
    p.add_argument("output", help="输出 APK 路径")
    p.add_argument("--force", "-f", action="store_true", help="强制覆盖")
    p.set_defaults(func=cmd_build)

    # sign
    p = sub.add_parser("sign", help="📝 签名 APK (debug key)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("output", help="输出 APK 路径")
    p.set_defaults(func=cmd_sign)

    # jadx
    p = sub.add_parser("jadx", help="☕ JADX 反编译")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("output", help="输出目录")
    p.add_argument("--no-deobf", action="store_true", help="禁用反混淆")
    p.set_defaults(func=cmd_jadx)

    # clue
    p = sub.add_parser("clue", help="🔗 线索串联分析 (跨模块自动关联)")
    p.add_argument("apk", help="APK 文件路径")
    p.set_defaults(func=cmd_clue)

    # patch
    p = sub.add_parser("patch", help="🔧 原生 SO 补丁")
    p.add_argument("apk", help="SO 文件路径")
    p.add_argument("output", help="输出文件路径")
    p.add_argument("--type", choices=['hex','string','ret','nop'], required=True, help="补丁类型")
    p.add_argument("--old", default="", help="原 hex/string (hex/string 模式)")
    p.add_argument("--new", default="", help="新 hex/string (hex/string 模式)")
    p.add_argument("--offset", default="0", help="偏移地址 (ret/nop 模式)")
    p.add_argument("--count", default="4", help="NOP 数量 (nop 模式)")
    p.add_argument("--arch", default="aarch64", help="架构 (ret 模式)")
    p.set_defaults(func=cmd_patch)

    # merge
    p = sub.add_parser("merge", help="🔄 合并多个APK或合并DEX")
    p.add_argument("apk", help="APK文件路径（多个以逗号分隔）或DEX文件路径")
    p.add_argument("output", help="输出APK/DEX路径")
    p.add_argument("--dex", action="store_true", help="DEX合并模式")
    p.set_defaults(func=cmd_merge)

    # rebuild
    p = sub.add_parser("rebuild", help="📦 从目录重建APK (ZIP打包)")
    p.add_argument("input", help="输入目录")
    p.add_argument("output", help="输出APK路径")
    p.add_argument("--store", action="store_true", help="不压缩存储 (ZIP_STORED)")
    p.set_defaults(func=cmd_rebuild)

    # zipalign
    p = sub.add_parser("zipalign", help="📐 对齐APK (4字节对齐)")
    p.add_argument("apk", help="APK文件路径")
    p.add_argument("output", help="输出APK路径")
    p.set_defaults(func=cmd_zipalign)

    # convert
    p = sub.add_parser("convert", help="🔄 格式转换 (DEX↔JAR / DEX↔Smali)")
    p.add_argument("type", choices=["dex2jar", "jar2dex", "dex2smali", "smali2dex"],
                   help="转换类型: dex2jar / jar2dex / dex2smali / smali2dex")
    p.add_argument("input", help="输入文件路径")
    p.add_argument("output", help="输出文件路径")
    p.set_defaults(func=cmd_convert)

    # ── 增强逆向新功能 ────────────────────────────────────

    # diff
    p = sub.add_parser("diff", help="🔍 对比两个APK差异 (结构/文件/类/权限)")
    p.add_argument("apk1", help="旧APK文件路径")
    p.add_argument("apk2", help="新APK文件路径")
    p.add_argument("--json", action="store_true", help="以JSON格式输出")
    p.set_defaults(func=cmd_diff)

    # endpoints
    p = sub.add_parser("endpoints", help="🌐 从DEX中提取网络端点 (URL/IP/域名/API路径)")
    p.add_argument("apk", help="APK文件路径")
    p.add_argument("--json", action="store_true", help="以JSON格式输出")
    p.set_defaults(func=cmd_endpoints)

    # keyscan
    p = sub.add_parser("keyscan", help="🔑 扫描DEX中的硬编码密钥/凭证/令牌")
    p.add_argument("apk", help="APK文件路径")
    p.add_argument("--json", action="store_true", help="以JSON格式输出")
    p.set_defaults(func=cmd_keyscan)

    # cert
    p = sub.add_parser("cert", help="📜 深度分析签名证书 (调试证书/有效期/CA)")
    p.add_argument("apk", help="APK文件路径")
    p.set_defaults(func=cmd_cert)

    # clean
    p = sub.add_parser("clean", help="🧹 分析APK冗余文件并清理优化")
    p.add_argument("apk", help="APK文件路径")
    p.add_argument("output", nargs="?", default="", help="输出APK路径（清理后需重新签名）")
    p.add_argument("--remove-debug", action="store_true", default=True, help="移除调试/测试文件")
    p.add_argument("--remove-meta", action="store_true", help="移除META-INF签名文件（重签名前）")
    p.add_argument("--dry-run", action="store_true", help="仅分析，不执行清理")
    p.set_defaults(func=cmd_clean)

    # axml - AXML 反编译/编译
    p = sub.add_parser("axml", help="📄 AXML 反编译/编译 (Android Binary XML ↔ 文本XML) - 纯Python实现")
    axml_sub = p.add_subparsers(dest="action", metavar="<action>", required=True)

    # axml decode
    dp = axml_sub.add_parser("decode", help="将二进制AXML解码为文本XML")
    dp.add_argument("input", help="输入AXML文件路径")
    dp.add_argument("output", nargs="?", default=None, help="输出XML文件路径（默认: input.xml）")
    dp.set_defaults(func=cmd_axml)

    # axml encode
    ep = axml_sub.add_parser("encode", help="将文本XML编译为二进制AXML")
    ep.add_argument("input", help="输入XML文件路径")
    ep.add_argument("output", help="输出AXML文件路径")
    ep.set_defaults(func=cmd_axml)

    # axml decode-apk
    dap = axml_sub.add_parser("decode-apk", help="从APK中提取并解码AndroidManifest.xml")
    dap.add_argument("input", help="APK文件路径")
    dap.add_argument("output", nargs="?", default=None, help="输出XML文件路径")
    dap.set_defaults(func=cmd_axml)

    # axml encode-apk
    eap = axml_sub.add_parser("encode-apk", help="替换APK中的AndroidManifest.xml（需重新签名）")
    eap.add_argument("input", help="APK文件路径")
    eap.add_argument("output", help="输出APK路径")
    eap.add_argument("xml_path", help="编辑后的文本XML文件路径")
    eap.set_defaults(func=cmd_axml)

    # ── core - 核心类定位 ─────────────────────────────────
    p = sub.add_parser("core", help="🎯 定位 DEX 中的核心类（多维度启发式评分）")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--max", "-n", type=int, default=20, help="每个 DEX 返回的最大核心类数 [默认=20]")
    p.add_argument("--min-score", "-m", type=int, default=10, help="最低评分阈值 [默认=10]")
    p.add_argument("--include-sdk", action="store_true", help="是否包含 SDK 类")
    p.add_argument("--detail", "-d", type=int, nargs="?", const=5, default=0, help="显示评分明细（可选指定数量）")
    p.add_argument("--json", "-j", nargs="?", const="true", help="导出结果为 JSON 文件")
    p.add_argument("--app-package", help="指定应用包名（自动从 Manifest 检测，也可手动指定）")
    p.set_defaults(func=cmd_core)

    # ── lang - 工具自身多语言切换 ──────────────────────────────
    p = sub.add_parser("lang", help="🌐 切换 CLI 界面语言 (i18n)")
    p.add_argument("--set", "-s", help="设置语言代码: zh_CN/en/ja/ko/ru/zh_TW/hi")
    p.add_argument("--list", "-l", action="store_true", help="列出所有支持的语言")
    p.set_defaults(func=cmd_lang)
    # ── reslang - APK 资源语言处理 ────────────────────────────
    p = sub.add_parser("reslang", help="🌍 处理 APK 资源语言 (strings.xml 多语言)")
    p.add_argument("apk", nargs="?", help="APK 文件路径")
    p.add_argument("--list", "-l", action="store_true", help="列出 APK 中所有支持的语言")
    p.add_argument("--extract", "-e", metavar="<code>", help="提取指定语言的字符串 (如 en, zh_CN)")
    p.add_argument("--compare", "-c", metavar="<base>", help="对比各语言翻译完整性 (基准代码, 如 en)")
    p.add_argument("--replace", "-r", metavar="<kv>", help="替换字符串 key1=val1,key2=val2")
    p.add_argument("--lang", "-L", help="替换/操作的目标语言代码")
    p.add_argument("--add", "-a", metavar="<code>", help="添加新语言支持")
    p.add_argument("--remove", "-R", metavar="<code>", help="移除语言支持")
    p.add_argument("--output", "-o", help="输出 APK 路径")
    p.set_defaults(func=cmd_reslang)

    # ── sdk - SDK/追踪器检测 ──────────────────────────────────
    p = sub.add_parser("sdk", help="🔍 检测 SDK/追踪器 (第三方SDK+隐私风险评估)")
    p.add_argument("apk", help="APK 文件路径")
    p.set_defaults(func=cmd_sdk)
    # ── strings - DEX 字符串深度分析 ──────────────────────────
    p = sub.add_parser("strings", help="📜 DEX 字符串深度分析 (分类/敏感信息/URL/内网IP)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--json", "-j", nargs="?", const="true", help="导出结果为 JSON 文件")
    p.set_defaults(func=cmd_strings)
    # ── resobf - 资源混淆检测 ─────────────────────────────────
    p = sub.add_parser("resobf", help="🎨 资源混淆检测 (分析资源命名/R类/布局混淆程度)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--json", "-j", nargs="?", const="true", help="导出结果为 JSON 文件")
    p.set_defaults(func=cmd_resobf)
    # ── medit - AndroidManifest 编辑 ────────────────────────────
    p = sub.add_parser("medit", help="📝 AndroidManifest 属性编辑 (调试/备份/加密/组件)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--debuggable", type=lambda x: x.lower() in ('true','1','yes'), nargs='?',
                   const=True, help="调试模式: true/false (不传值=查看当前)")
    p.add_argument("--backup", type=lambda x: x.lower() in ('true','1','yes'), nargs='?',
                   const=True, help="允许备份: true/false")
    p.add_argument("--test-only", dest="test_only", type=lambda x: x.lower() in ('true','1','yes'),
                   nargs='?', const=True, help="测试模式: true/false")
    p.add_argument("--cleartext", type=lambda x: x.lower() in ('true','1','yes'), nargs='?',
                   const=True, help="明文流量: true/false")
    p.add_argument("--extract-native", dest="extract_native", type=lambda x: x.lower() in ('true','1','yes'),
                   nargs='?', const=True, help="SO提取: true/false")
    p.add_argument("--has-code", dest="has_code", type=lambda x: x.lower() in ('true','1','yes'),
                   nargs='?', const=True, help="代码加载: true/false")
    p.add_argument("--hardware-accel", dest="hardware_accel", type=lambda x: x.lower() in ('true','1','yes'),
                   nargs='?', const=True, help="硬件加速: true/false")
    p.add_argument("--large-heap", dest="large_heap", type=lambda x: x.lower() in ('true','1','yes'),
                   nargs='?', const=True, help="大堆内存: true/false")
    p.add_argument("--network-config", dest="network_config", help="设置网络安全配置路径")
    p.set_defaults(func=cmd_medit)
    # ── social - 社交登录检测 ─────────────────────────────────
    p = sub.add_parser("social", help="💬 社交登录检测 (微信/QQ/GitHub/支付宝/Google/Facebook/Apple/Twitter/微博)")
    p.add_argument("apk", help="APK 文件路径")
    p.set_defaults(func=cmd_social)
    # ── ads - 广告检测 ───────────────────────────────────────
    p = sub.add_parser("ads", help="📢 广告检测 (SDK/代码模式/权限/URL/等级评分)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--json", "-j", nargs="?", const="true", help="导出结果为 JSON 文件")
    p.set_defaults(func=cmd_ads)

    # ── adremove - 广告移除 ───────────────────────────────────────
    p = sub.add_parser("adremove", help="🧹 一键移除广告 (8大SDK定向+正则通杀+assets清理+重打包)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("output", nargs='?', help="输出 APK 路径 (默认: <name>_noads.apk)")
    p.add_argument("--decode-dir", "-d", help="指定已解包目录 (跳过 apktool 解包)")
    p.add_argument("--sdks", "-s", help="只处理指定SDK，逗号分隔 (tencent,kuaishou,pangle,baidu,toutiao,sigmob,google,miads)")
    p.add_argument("--no-regex", action="store_true", help="禁用正则通杀")
    p.add_argument("--no-assets", action="store_true", help="禁用 assets 清理")
    p.add_argument("--no-manifest", action="store_true", help="禁用 manifest 清理")
    p.add_argument("--no-sign", action="store_true", help="跳过签名")
    p.add_argument("--keep-decode", action="store_true", help="保留临时解包目录")
    p.set_defaults(func=cmd_adremove)

    # ── adai - AI广告分析 ────────────────────────────────────────
    p = sub.add_parser("adai", help="🤖 AI广告识别分析 (LLM智能分析广告接口)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--api-key", "-k", required=True, help="API 密钥 (SiliconFlow/OpenAI)")
    p.add_argument("--api-url", "-u", help="自定义 API 地址 (默认: SiliconFlow)")
    p.add_argument("--model", "-m", help="模型ID (不指定则列出可用模型)")
    p.add_argument("--language", "-l", choices=['smali', 'java', 'xml', 'javascript'], default='smali', help="源代码语言")
    p.add_argument("--class-name", "-c", help="指定类名过滤 (仅分析该类的代码)")
    p.add_argument("--question", "-q", help="补充问题 (使用补充问答模式)")
    p.add_argument("--supplement", action="store_true", help="使用补充问答模式")
    p.add_argument("--list-models", action="store_true", help="列出可用AI模型后退出")
    p.add_argument("--no-blocking", action="store_true", help="不显示广告屏蔽建议")
    p.add_argument("--stream", action="store_true", help="流式输出 AI 分析结果")
    p.add_argument("--custom-keywords", help="自定义广告关键词（逗号分隔）")
    p.add_argument("--max-snippets", type=int, default=20, help="最大分析代码片段数")
    p.add_argument("--concurrent", type=int, default=5, help="最大并发分析数（默认5路同时）")
    p.add_argument("--no-rate-limit", action="store_true", help="禁用速率限制（多对话同时使用时推荐）")
    p.add_argument("--json", "-j", nargs="?", const="true", help="导出结果为 JSON 文件")
    p.set_defaults(func=cmd_adai)

    # ── disasm - DEX 反汇编 ────────────────────────────────────
    p = sub.add_parser("disasm", help="🔄 DEX 反汇编 (列出方法/签名)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--method", "-m", help="方法名过滤")
    p.add_argument("--class-name", "-c", help="类名过滤")
    p.add_argument("--max", type=int, default=20, help="最大显示数")
    p.add_argument("--detail", "-d", action="store_true", help="显示详细信息")
    p.set_defaults(func=cmd_disasm)

    # ── smali - Smali 修补 ─────────────────────────────────────
    p = sub.add_parser("smali", help="🔧 Smali 修补 (绕过签名/NOP/注入/移除)")
    p.add_argument("action", choices=['bypass', 'nop', 'log', 'return', 'remove', 'stub'],
                   help="修补操作: bypass签名绕过/nop方法体/log日志注入/return返回值注入/remove移除/stub存根")
    p.add_argument("file", help="Smali 文件路径")
    p.add_argument("--method", "-m", help="目标方法名")
    p.add_argument("--output", "-o", help="输出文件路径")
    p.add_argument("--tag", help="日志标签 (log操作)")
    p.add_argument("--msg", help="日志消息 (log操作)")
    p.add_argument("--value", "-v", help="返回值 (return操作)")
    p.add_argument("--return-type", "-r", help="返回类型 (stub操作)")
    p.add_argument("--params", "-p", help="参数类型列表,逗号分隔 (stub操作)")
    p.set_defaults(func=cmd_smali)

    # ── deobf - 去混淆分析 ─────────────────────────────────────
    p = sub.add_parser("deobf", help="🎭 去混淆分析 (类名混淆/XOR/算术混淆)")
    p.add_argument("apk", help="APK 文件路径")
    p.set_defaults(func=cmd_deobf)

    # ── cfg - 控制流图 ─────────────────────────────────────────
    p = sub.add_parser("cfg", help="🔀 控制流图分析 (方法CFG)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--method", "-m", help="方法名过滤")
    p.add_argument("--class-name", "-c", help="类名过滤")
    p.set_defaults(func=cmd_cfg)

    # ── 增强分析命令 ─────────────────────────────────────────────
    # dataflow - DEX 数据流分析
    p = sub.add_parser("dataflow", help="🔬 DEX 数据流分析 (寄存器追踪/污点分析/常量传播)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("class_name", help="目标类名 (如 Lcom/example/Main;)")
    p.add_argument("--method", "-m", help="目标方法名 (不指定则分析整个类)")
    p.set_defaults(func=cmd_dataflow)

    # callgraph - 调用图分析
    p = sub.add_parser("callgraph", help="🕸️ 调用图分析 (入口点/热点/递归检测)")
    p.add_argument("apk", help="APK 文件路径")
    p.set_defaults(func=cmd_callgraph)

    # decrypt - 字符串解密分析
    p = sub.add_parser("decrypt", help="🔐 加密字符串检测与自动解密")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--class-name", "-c", help="限定类名 (不指定则全DEX扫描)")
    p.set_defaults(func=cmd_decrypt)

    # anti - 反分析检测
    p = sub.add_parser("anti", help="🛡️ 反分析检测 (反调试/反Root/反模拟器/完整性校验)")
    p.add_argument("apk", help="APK 文件路径")
    p.set_defaults(func=cmd_anti)

    # crypto - 加密分析
    p = sub.add_parser("crypto", help="🔑 加密分析 (算法/模式/哈希/弱加密/密钥)")
    p.add_argument("apk", help="APK 文件路径")
    p.set_defaults(func=cmd_crypto)

    # hook - Hook 脚本生成
    p = sub.add_parser("hook", help="🪝 Hook 脚本生成 (Frida/Xposed/Smali)")
    p.add_argument("target_class", help="目标类名 (如 com.example.Main)")
    p.add_argument("--method", "-m", help="目标方法名")
    p.add_argument("--format", "-f", choices=['frida', 'xposed', 'smali'], default='frida',
                   help="输出格式: frida(默认) / xposed / smali")
    p.add_argument("--package", "-p", help="应用包名 (xposed 模式必需)")
    p.add_argument("--patch-type", "-t", default='bypass_return',
                   choices=['bypass_return', 'nop', 'log', 'return', 'stub'],
                   help="Smali 补丁类型 (smali 模式)")
    p.add_argument("--value", "-v", help="返回值 (smali return 模式)")
    p.add_argument("--verbose", action="store_true", help="详细输出 (frida 模式)")
    p.add_argument("--trace-args", action="store_true", help="追踪参数 (frida 模式)")
    p.add_argument("--trace-return", action="store_true", help="追踪返回值 (frida 模式)")
    p.add_argument("--bypass-debug", action="store_true", help="生成反调试绕过代码")
    p.add_argument("--bypass-root", action="store_true", help="生成反Root绕过代码")
    p.add_argument("--bypass-emulator", action="store_true", help="生成反模拟器绕过代码")
    p.add_argument("--output", "-o", help="输出文件路径")
    p.set_defaults(func=cmd_hook)

    # metadata - DEX 元数据深度分析
    p = sub.add_parser("metadata", help="🏷️ DEX 元数据分析 (Annotation/Debug/Hidden API)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--max-classes", type=int, default=200, help="最大分析类数")
    p.add_argument("--only", choices=['annotations', 'debug', 'hidden_api', 'processors', 'serialization'], help="仅输出指定分析项")
    p.set_defaults(func=cmd_metadata)

    # multidex - 多 DEX 关联分析
    p = sub.add_parser("multidex", help="🔀 多 DEX 关联分析 (跨DEX引用/类分布/重复检测)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--only", choices=['distribution', 'cross_refs', 'duplicates'], help="仅输出指定分析项")
    p.set_defaults(func=cmd_multidex)

    # native-xref - Native-Java 交叉引用分析
    p = sub.add_parser("native-xref", help="🔗 Native-Java 交叉引用 (JNI函数/SO符号匹配)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--so", help="指定 SO 文件路径（可选，默认自动提取 APK 中所有 SO）")
    p.set_defaults(func=cmd_native_xref)

    # report - 生成分析报告
    p = sub.add_parser("report", help="📄 生成分析报告 (JSON/HTML/Markdown)")
    p.add_argument("apk", help="APK 文件路径")
    p.add_argument("--format", "-f", choices=['json', 'html', 'markdown'], default='html', help="输出格式")
    p.add_argument("--output", "-o", help="输出文件路径")
    p.add_argument("--full", action="store_true", help="完整报告（包含所有分析项）")
    p.set_defaults(func=cmd_report)

    args = parser.parse_args()

    # 交互式模式
    if getattr(args, 'interactive', False):
        interactive_mode()
        return
    
    if not hasattr(args, "func"):
        # 显示欢迎界面 - Rich 增强版
        console.print()
        console.print(Panel.fit(
            "[bold cyan]⚡ APK Reverse Engineering Engine v2[/]\n"
            "[dim]  全功能 APK 逆向工具集  |  47 命令  |  16,000+ 行核心引擎  [/]",
            border_style="cyan", box=box.DOUBLE_EDGE
        ))
        console.print()

        # 按类别分组展示所有命令 — 统一 Rich 表格
        cmd_groups = [
            ("📋 基本信息", "cyan", [
                ("inspect", "APK 基本信息概览"),
                ("info", "📊 信息一站式提取 (包名/版本/DEX/SO/签名)"),
                ("validate", "🛡️ APK 完整性验证"),
                ("analyze", "全面分析 APK (安全/混淆/加固/SDK)"),
                ("manifest", "解析 AndroidManifest.xml"),
                ("dex", "DEX 文件分析 (头信息/搜索)"),
                ("classes", "列出 DEX 类名"),
                ("so", "分析 SO 文件 (ELF/导入导出/加固)"),
            ]),
            ("🔬 深度分析", "blue", [
                ("clue", "线索串联分析 (跨模块自动关联)"),
                ("core", "核心类定位 (多维度启发式评分)"),
                ("sdk", "SDK/追踪器检测 (隐私风险评估)"),
                ("strings", "字符串深度分析 (分类/敏感信息)"),
                ("resobf", "资源混淆检测 (命名/R类/布局)"),
                ("ads", "广告检测 (SDK/代码模式/权限)"),
                ("adremove", "🧹 一键移除广告 (8大SDK+正则通杀+清理)"),
                ("adai", "🤖 AI广告识别分析 (LLM智能分析广告接口)"),
                ("social", "社交登录检测 (微信/QQ/GitHub/支付宝等)"),
                ("deobf", "去混淆分析 (类名/XOR/算术混淆)"),
                ("cert", "签名证书深度分析"),
                ("dataflow", "🔬 数据流分析 (寄存器/污点/常量传播)"),
                ("callgraph", "🕸️ 调用图分析 (入口点/热点/递归)"),
                ("decrypt", "🔐 加密字符串检测与自动解密"),
                ("anti", "🛡️ 反分析检测 (反调试/反Root/反模拟器)"),
                ("crypto", "🔑 加密分析 (算法/模式/弱加密/密钥)"),
                ("hook", "🪝 Hook 脚本生成 (Frida/Xposed/Smali)"),
            ]),
            ("🔍 搜索与提取", "yellow", [
                ("search", "搜索关键字 (字符串/类/方法)"),
                ("endpoints", "提取网络端点 (URL/IP/域名/API)"),
                ("keyscan", "扫描硬编码密钥/凭证/令牌"),
                ("clean", "分析冗余文件并清理优化"),
            ]),
            ("🛠️ 反编译与修补", "magenta", [
                ("disasm", "DEX 反汇编 (方法指令/统计)"),
                ("cfg", "控制流图分析 (基本块/边)"),
                ("smali", "Smali 修补 (绕过/NOP/注入/移除)"),
                ("jadx", "JADX 反编译为 Java 源码"),
                ("decode", "Apktool 解包为 Smali"),
                ("build", "Apktool 重打包"),
                ("patch", "原生 SO 补丁 (hex/string/ret/nop)"),
            ]),
            ("📦 打包与转换", "green", [
                ("unpack", "解压 APK (分类/并行/增量/过滤)"),
                ("verify", "校验解压完整性"),
                ("rebuild", "从目录重建 APK (ZIP 打包)"),
                ("merge", "合并多个 APK 或 DEX"),
                ("convert", "格式转换 (DEX↔JAR / DEX↔Smali)"),
                ("zipalign", "4 字节对齐 APK"),
                ("sign", "签名 APK (debug key)"),
            ]),
            ("🔧 高级工具", "red", [
                ("diff", "对比两个 APK 差异"),
                ("axml", "AXML 反编译/编译 (纯 Python)"),
                ("medit", "Manifest 属性编辑 (调试/备份等)"),
                ("lang", "CLI 界面语言切换 (i18n)"),
                ("reslang", "APK 资源语言处理 (多语言)"),
            ]),
        ]

        for group_name, group_color, cmds in cmd_groups:
            t = Table(box=box.ROUNDED, border_style=group_color, show_header=True, padding=(0, 2))
            t.add_column("命令", style=f"bold {group_color}", width=16)
            t.add_column("说明", style="dim")
            for cmd, desc in cmds:
                t.add_row(cmd, desc)
            console.print(Panel(t, title=group_name, title_align='left', border_style=group_color, box=box.ROUNDED))
            console.print()

        # 底部统计信息
        total_cmds = sum(len(g[2]) for g in cmd_groups)
        console.print(Panel(
            f"[bold]完整命令集:[/] {total_cmds} 个命令  |  "
            f"[bold]帮助:[/] [cyan]reng <command> --help[/]  |  "
            f"[bold]交互模式:[/] [magenta]reng --interactive[/]  |  "
            f"[bold]版本:[/] [yellow]v2.0.0[/]",
            border_style="dim", box=box.SIMPLE
        ))
        console.print()
        return

    args.func(args)

if __name__ == "__main__":
    main()