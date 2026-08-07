#!/usr/bin/env python3
"""APK Reverse Engineering Engine v2 - CLI (Rich终端UI)"""
import sys, os, json, zipfile

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
                except:
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
                    except:
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
                            except Exception:
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
                            except Exception:
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

# ── 主入口 ──────────────────────────────────────────────────

def main():
    import argparse

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
    parser.add_argument('--version', action='version', version='APK Reverse Engine v2.0.0')
    sub = parser.add_subparsers(dest="command")

    # inspect
    p = sub.add_parser("inspect", help="📦 APK 基本信息概览")
    p.add_argument("apk", help="APK 文件路径")
    p.set_defaults(func=cmd_inspect)

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
    p = sub.add_parser("unpack", help="📦 解压 APK (分类归档/并行/增量/过滤/预览)")
    p.add_argument("apk", help="APK 文件路径")
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

    args = parser.parse_args()
    
    if not hasattr(args, "func"):
        # 显示欢迎界面 - 增强版
        console.print()
        console.print(Panel.fit(
            "[bold cyan]  ⚡ APK Reverse Engineering Engine v2  [/]\n"
            "[dim]  全功能 APK 逆向工具集  |  37 命令  |  15,000+ 行核心引擎  [/]",
            border_style="cyan", box=box.DOUBLE_EDGE
        ))
        console.print()
        
        # 按类别分组展示所有命令
        cmd_groups = [
            ("📋 基本信息", "cyan", [
                ("inspect", "APK 基本信息概览"),
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
                ("social", "社交登录检测 (微信/QQ/GitHub/支付宝等)"),
                ("deobf", "去混淆分析 (类名/XOR/算术混淆)"),
                ("cert", "签名证书深度分析"),
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
            t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2, 0, 0))
            t.add_column("命令", style="bold", width=16)
            t.add_column("说明", style="dim")
            for cmd, desc in cmds:
                t.add_row(f"[{group_color}]{cmd}[/]", desc)
            console.print(_make_panel(t, f'{group_name}', group_color))
            console.print()
        
        # 底部统计信息
        total_cmds = sum(len(g[2]) for g in cmd_groups)
        console.print(Panel(
            f"[bold]完整命令集:[/] {total_cmds} 个命令  |  "
            f"[bold]帮助:[/] [cyan]reng <command> --help[/]  |  "
            f"[bold]版本:[/] [yellow]v2.0.0[/]",
            border_style="dim", box=box.SIMPLE
        ))
        console.print()
        return

    args.func(args)

if __name__ == "__main__":
    main()