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

# ── 工具函数 ──────────────────────────────────────────────────

def _fmt_size(n):
    for u in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            if u == 'B':
                return f"{n:.0f}B"
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}TB"

def _risk_icon(score):
    """风险等级图标"""
    if score >= 8:
        return "🔴"
    if score >= 5:
        return "🟡"
    return "🟢"

def _risk_label(score):
    if score >= 8:
        return "严重"
    if score >= 5:
        return "中等"
    return "低风险"

def _bool_icon(v):
    return "✅" if v else "❌"

def _make_table(title, columns, rows, style="bright_blue"):
    """创建统一风格表格"""
    t = Table(title=title, title_style=f"bold {style}", box=box.ROUNDED, border_style=style)
    for c in columns:
        t.add_column(c, style="cyan" if c == columns[0] else "white")
    for r in rows:
        t.add_row(*[str(x) for x in r])
    return t

def _make_panel(content, title="", style="bright_blue"):
    return Panel(content, title=title, title_align="left", border_style=style, box=box.ROUNDED)

# ── 命令实现 ──────────────────────────────────────────────────

def cmd_inspect(args):
    """APK 基本信息概览"""
    with console.status("🔍 正在分析 APK 结构...", spinner="dots"):
        r = static_analyze(args.apk)
    size = _fmt_size(os.path.getsize(args.apk))

    # 标题
    console.print(Panel(f"[bold cyan]{os.path.basename(args.apk)}[/]  [dim]{size}[/]", 
                        title="📦 APK 概览", border_style="cyan", box=box.DOUBLE))
    
    # 基本信息
    info = r.get("manifest", {})
    pkg = info.get("package", "?")
    sdk_info = info.get("sdk", {})
    vn = sdk_info.get("versionName", "?")
    vc = sdk_info.get("versionCode", "?")
    minsdk = sdk_info.get("minSdk", "?")
    targetsdk = sdk_info.get("targetSdk", "?")
    t = Table(box=box.SIMPLE, show_header=False)
    t.add_column("Key", style="cyan")
    t.add_column("Value")
    t.add_row("包名", pkg)
    t.add_row("版本", f"{vn} (code={vc})")
    t.add_row("SDK", f"min={minsdk}  target={targetsdk}")
    t.add_row("文件大小", size)
    console.print(_make_panel(t, "📋 基本信息", "cyan"))

    # 结构摘要
    struct = r.get("structure", {})
    if struct:
        t2 = Table(box=box.SIMPLE, show_header=False)
        t2.add_column("项", style="green")
        t2.add_column("数量")
        t2.add_row("DEX 文件", str(struct.get("dex_count", 0)))
        t2.add_row("SO 文件", str(struct.get("so_count", 0)))
        t2.add_row("资源文件", str(struct.get("res_count", 0)))
        t2.add_row("总文件数", str(struct.get("total_files", 0)))
        console.print(_make_panel(t2, "📁 结构", "green"))

    # ABI
    abis = r.get("abi_architectures", [])
    if abis:
        console.print(f"[bold magenta]🔧 ABI 架构:[/] {' '.join(abis)}")

    # 签名
    sig = r.get("signature", {})
    if sig:
        # verify_all 返回的 v1/v2/v3 是 bool 值
        v1 = bool(sig.get("v1", False))
        v2 = bool(sig.get("v2", False))
        console.print(f"[bold]📝 签名:[/]  V1={_bool_icon(v1)}  V2={_bool_icon(v2)}  V3={_bool_icon(bool(sig.get('v3')))}  "
                      f"级别={sig.get('security_level','?')}")

    # DEX 摘要
    dex_s = r.get("dex_summary", [])
    for d in dex_s:
        console.print(f"  [yellow]📜 {d.get('name','?')}[/]  classes={d.get('classes',0)}  methods={d.get('methods',0)}  strings={d.get('strings',0)}")

    console.print()

def cmd_analyze(args):
    """全面分析 APK"""
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), 
                  BarColumn(), console=console) as progress:
        progress.add_task("🔬 正在执行全量分析...", total=None)
        r = analyze_full(args.apk)

    # 安全评分
    sec = r.get("security", {})
    score = sec.get("score", 0)
    icon = _risk_icon(score)
    label = _risk_label(score)
    console.print(Panel(f"[bold]{icon} 安全评分: [{'red' if score>=8 else 'yellow' if score>=5 else 'green'}]{score:.1f}/10[/] ({label})",
                        title="🛡️ 安全评估", border_style="red" if score>=8 else "yellow" if score>=5 else "green",
                        box=box.DOUBLE))

    # 文件信息
    size = _fmt_size(r.get("file_size", 0))
    console.print(f"[bold cyan]📦 {os.path.basename(r['apk_path'])}[/]  ({size})")

    # Manifest
    man = r.get("manifest", {})
    if man:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("属性", style="cyan")
        t.add_column("值")
        t.add_row("包名", man.get("package", "?"))
        sdk_info = man.get("sdk", {})
        t.add_row("SDK", f"min={sdk_info.get('minSdk','?')} target={sdk_info.get('targetSdk','?')}")
        perms = man.get("permissions", [])
        t.add_row("权限", f"{len(perms)} 项")
        console.print(_make_panel(t, "📋 Manifest", "cyan"))

    # 权限风险
    perm_analysis = r.get("permissions", {})
    if perm_analysis:
        dangerous = perm_analysis.get("dangerous", [])
        dangerous = dangerous if dangerous else []
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("类别", style="yellow")
        t.add_column("数量")
        t.add_row("🔴 危险权限", str(len(dangerous)))
        t.add_row("🟢 正常权限", str(len(perm_analysis.get("normal", []))))
        t.add_row("⚙️ 自定义权限", str(len(perm_analysis.get("custom", []))))
        console.print(_make_panel(t, "🔐 权限分析", "yellow"))
        if dangerous:
            console.print(Panel("\n".join(f"  • {p}" for p in dangerous[:10]),
                                title="⚠️ 危险权限列表", border_style="red", title_align="left"))

    # DEX 摘要
    dex_s = r.get("dex_summary", [])
    if dex_s:
        t = Table(title="📜 DEX 文件", box=box.ROUNDED, border_style="blue")
        t.add_column("文件", style="cyan")
        t.add_column("大小", justify="right")
        t.add_column("Classes", justify="right")
        t.add_column("Methods", justify="right")
        t.add_column("Strings", justify="right")
        for d in dex_s:
            if "error" in d:
                t.add_row(d["name"], "❌ error", "", "", "")
            else:
                t.add_row(d["name"], _fmt_size(d.get("size", 0)),
                          str(d.get("classes", 0)), str(d.get("methods", 0)),
                          str(d.get("strings", 0)))
        console.print(t)

    # 混淆检测
    obf = r.get("obfuscation", {})
    if obf:
        obf_score = obf.get("score", 0)
        obf_icon = _risk_icon(obf_score)
        console.print(f"[bold]🎭 混淆检测:[/] {obf_icon} score={obf_score:.1f}  {obf.get('level','?')}")

    # 加固检测
    packers = r.get("packers", [])
    if packers:
        console.print(f"[bold]🛡️ 加固检测:[/] [red]{', '.join(packers) if packers else '无'}[/]")
    else:
        console.print("[bold]🛡️ 加固检测:[/] 未检测到加固壳")

    # SO 分析
    native = r.get("native_analysis", {})
    if native:
        console.print(f"\n[bold magenta]🔧 SO 文件 ({len(native)} 个)[/]")
        for name, info in native.items():
            if "error" in info:
                console.print(f"  [red]❌ {name}: {info['error']}[/]")
            else:
                arch = info.get("machine", "?")
                imports = info.get("imports", [])
                exports = info.get("exports", [])
                console.print(f"  📄 [cyan]{name}[/]  arch={arch}  import={len(imports)}  export={len(exports)}")

    # 安全详情
    if sec:
        details = sec.get("details", [])
        if details:
            console.print(f"\n[bold red]⚠️ 安全发现 ({len(details)} 项)[/]")
            for d in details:
                console.print(f"  • {d}")

    console.print()

def cmd_manifest(args):
    """解析 AndroidManifest.xml"""
    with console.status("📋 解析 Manifest...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            data = ctx.get_manifest_xml()
            info = get_manifest_info(data)

    t = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
    t.add_column("属性", style="cyan bold")
    t.add_column("值")
    t.add_row("📦 包名", info.get("package", "?"))
    sdk_info = info.get("sdk", {})
    t.add_row("📌 版本", f"{sdk_info.get('versionName', '?')} (code={sdk_info.get('versionCode', '?')})")
    t.add_row("📱 SDK", f"min={sdk_info.get('minSdk','?')}  target={sdk_info.get('targetSdk','?')}")
    t.add_row("📐 屏幕", f"small={info.get('small_screen','?')} normal={info.get('normal_screen','?')} large={info.get('large_screen','?')} xlarge={info.get('xlarge_screen','?')}")
    console.print(_make_panel(t, "📋 AndroidManifest 信息", "cyan"))

    # 权限
    perms = info.get("permissions", [])
    if perms:
        t2 = Table(title="🔐 权限列表", box=box.ROUNDED, border_style="yellow")
        t2.add_column("#", justify="right", style="dim")
        t2.add_column("权限", style="cyan")
        for i, p in enumerate(perms, 1):
            t2.add_row(str(i), p)
        console.print(t2)

    # 组件
    for comp_type in ["activities", "services", "receivers", "providers"]:
        comps = info.get(comp_type, [])
        if comps:
            label = {"activities": "🎬 Activity", "services": "⚙️ Service", 
                     "receivers": "📡 BroadcastReceiver", "providers": "🗄️ ContentProvider"}
            t3 = Table(title=label.get(comp_type, comp_type), box=box.SIMPLE, border_style="green")
            t3.add_column("组件名", style="cyan")
            for c in comps:
                # 新格式: {'type':..., 'attrs':{...}}
                if isinstance(c, dict):
                    name = c.get('attrs', {}).get('name', c.get('attrs', {}).get('android:name', '?'))
                else:
                    name = str(c)
                t3.add_row(name)
            console.print(t3)

    console.print()

def cmd_dex(args):
    """DEX 文件分析"""
    with console.status("📜 解析 DEX...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            dex_files = ctx.get_dex_files()
            dex_data = {}
            for d in dex_files:
                dex_data[d] = ctx.read_file(d)

    for d, data in dex_data.items():
        with console.status(f"📜 分析 {d}...", spinner="dots"):
            h = dex_header(data)
            summary = dex_summary(data)

        t = Table(title=f"📜 {d}", box=box.ROUNDED, border_style="blue")
        t.add_column("属性", style="cyan")
        t.add_column("值", justify="right")
        for k, v in summary.items():
            t.add_row(k, str(v))
        console.print(t)

        # 搜索方法
        if args.search:
            with console.status(f"🔍 搜索 '{args.search}'..."):
                methods = dex_search_methods(data, args.search)
                classes = dex_search_classes(data, args.search)
            if methods:
                console.print(f"[bold green]🔍 方法匹配 ({len(methods)}):[/]")
                for m in methods[:20]:
                    console.print(f"  [dim]{m}[/]")
            if classes:
                console.print(f"[bold green]🔍 类匹配 ({len(classes)}):[/]")
                for c in classes[:20]:
                    console.print(f"  [dim]{c}[/]")

    console.print()

def cmd_classes(args):
    """列出 DEX 类名"""
    with console.status("📜 提取类名...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            dex_classes_data = {}
            for d in ctx.get_dex_files():
                dex_classes_data[d] = ctx.read_file(d)

    for d, data in dex_classes_data.items():
        names = dex_class_names(data)
        total = len(names)
        shown = names[:args.max]

        t = Table(title=f"📜 {d} ({total} classes)", box=box.ROUNDED, border_style="green")
        t.add_column("#", justify="right", style="dim", width=6)
        t.add_column("类名", style="cyan")
        for i, n in enumerate(shown, 1):
            t.add_row(str(i), n)
        console.print(t)
        if total > args.max:
            console.print(f"[dim]... 还有 {total - args.max} 个类未显示 (使用 --max 查看更多)[/]")

    console.print()

def cmd_so(args):
    """分析 SO 文件"""
    with console.status("🔧 分析 SO 文件...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            so_files = ctx.get_so_files()
            so_data = {}
            for s in so_files:
                so_data[s] = ctx.read_file(s)

    for s, data in so_data.items():
        with console.status(f"🔧 分析 {s}...", spinner="dots"):
            r = analyze_elf(data)

        if "error" in r:
            console.print(f"[red]❌ {s}: {r['error']}[/]")
            continue

        # 概览面板
        arch = r.get("machine", "?")
        cls = r.get("class", "?")
        endian = r.get("endian", "?")
        entry = r.get("entry", "?")
        sections = r.get("sections", "?")
        segments = r.get("segments", "?")

        info_text = Text()
        info_text.append(f"🔧 {s}\n", style="bold cyan")
        info_text.append(f"  Architecture: {arch}  |  Class: {cls}  |  Endian: {endian}\n")
        info_text.append(f"  Entry: {entry}  |  Sections: {sections}  |  Segments: {segments}")
        console.print(Panel(info_text, title="ELF 概览", border_style="magenta", box=box.ROUNDED))

        # 依赖
        deps = r.get("dependencies", [])
        if deps:
            t = Table(box=box.SIMPLE, border_style="dim")
            t.add_column("📦 依赖库", style="cyan")
            for dep in deps:
                t.add_row(dep)
            console.print(_make_panel(t, "依赖", "blue"))

        # 导入导出
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
            console.print(ie_table)
            if len(imports) > 30:
                console.print(f"[dim]... 还有 {len(imports)-30} 个导入[/]")
            if len(exports) > 20:
                console.print(f"[dim]... 还有 {len(exports)-20} 个导出[/]")

        # 加固检测（单独调用，不在 summary 中）
        packers = elf_detect_packer(data)
        if packers:
            console.print(f"[red]🛡️ 加固壳: {', '.join(packers)}[/]")

        # 加密库检测（单独调用，不在 summary 中）
        crypto = elf_detect_crypto(data)
        if crypto:
            crypto_names = list(crypto.keys()) if isinstance(crypto, dict) else crypto
            console.print(f"[yellow]🔐 加密库: {', '.join(crypto_names)}[/]")

    console.print()

def cmd_search(args):
    """在 APK 中搜索"""
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        progress.add_task(f"🔍 搜索 '{args.query}'...", total=None)
        r = search_apk(args.apk, args.query, args.scope or "all", args.max or 100)

    total = r.get("total", 0)
    if total == 0:
        console.print(f"[yellow]⚠️ 未找到包含 '{args.query}' 的结果[/]")
        return

    console.print(f"[bold green]✅ 找到 {total} 个匹配结果:[/]")

    for scope_name in ["strings", "classes", "methods"]:
        items = r.get(scope_name, [])
        if not items:
            continue
        icons = {"strings": "📝", "classes": "📦", "methods": "⚙️"}
        t = Table(title=f"{icons.get(scope_name, '📄')} {scope_name}", box=box.ROUNDED, border_style="cyan")
        t.add_column("#", justify="right", style="dim", width=4)
        t.add_column("内容", style="white")
        t.add_column("来源", style="dim")
        for i, item in enumerate(items[:args.max], 1):
            source = item.get("file", "") if isinstance(item, dict) else ""
            content = item.get("match", str(item)) if isinstance(item, dict) else str(item)
            t.add_row(str(i), content, source)
        console.print(t)

    console.print()

def cmd_unpack(args):
    """解压 APK - 全面增强版"""
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID

    # 预览模式
    if args.dry_run:
        r = _APKUnpacker.extract_raw(args.apk, args.output, dry_run=True)
        if r.get("success"):
            console.print(f"[bold cyan]📦 预览: {os.path.basename(args.apk)}[/]")
            t = Table(box=box.SIMPLE, show_header=False)
            t.add_column("项", style="cyan")
            t.add_column("值")
            t.add_row("总文件", str(r.get("total", 0)))
            t.add_row("DEX", str(r.get("dex_count", 0)))
            t.add_row("SO", str(r.get("so_count", 0)))
            t.add_row("资源文件", str(r.get("res_count", 0)))
            t.add_row("Assets", str(r.get("assets_count", 0)))
            t.add_row("大小", _fmt_size(r.get("size", 0)))
            t.add_row("输出目录", args.output)
            console.print(_make_panel(t, "📋 解压预览（仅列出，不解压）", "cyan"))
            return
        else:
            console.print(f"[red]❌ 预览失败: {r.get('error', '未知错误')}[/]")
            return

    # 分类提取
    if args.category:
        cats = [c.strip() for c in args.category.split(',')]
        with console.status(f"📦 按分类提取 {', '.join(cats)}..."):
            r = _APKUnpacker.extract_by_category(args.apk, args.output, categories=cats,
                                                  structure=args.structure)
        if r.get("success"):
            console.print(f"[bold green]✅ 分类提取成功: {args.output}[/]")
            t = Table(box=box.SIMPLE, show_header=False)
            t.add_column("分类", style="cyan")
            t.add_column("文件数", justify="right")
            for cat, cnt in sorted(r.get('categories', {}).items()):
                t.add_row(cat, str(cnt))
            console.print(_make_panel(t, "📊 提取结果", "green"))
        else:
            console.print(f"[red]❌ 提取失败: {r.get('error', '未知错误')}[/]")
        return

    # 带进度条的实际解压
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=20),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("📦 解压中...", total=None)

        def _progress(extracted, total, name):
            t = progress.tasks[task]
            if t.completed == 0 and total:
                progress.update(task, total=total)
            progress.update(task, completed=extracted, description=f"📦 {os.path.basename(name)}")

        if args.parallel:
            r = _APKUnpacker.extract_parallel(args.apk, args.output, args.workers, structure=args.structure)
        elif args.incremental:
            r = _APKUnpacker.extract_incremental(args.apk, args.output, structure=args.structure,
                                                  flatten=args.flatten)
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
        console.print(f"[bold green]✅ 解压成功: {args.output}[/]")
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("项", style="cyan")
        t.add_column("值")
        t.add_row("提取文件", f"{r.get('extracted', 0)}/{r.get('total', '?')}")
        if r.get('skipped'):
            t.add_row("跳过(增量)", str(r.get('skipped', 0)))
        cats = r.get('categories', {})
        if cats:
            cats_str = ", ".join(f"{k}={v}" for k, v in sorted(cats.items()))
            t.add_row("分类统计", cats_str)
        if r.get('sha256'):
            t.add_row("SHA256", r['sha256'][:16] + '...')
        errors = r.get('errors', [])
        if errors:
            t.add_row("错误", f"{len(errors)} 个 (显示前3): {', '.join(e['file'] for e in errors[:3])}")
        console.print(_make_panel(t, "📊 解压结果", "green"))
    else:
        console.print(f"[red]❌ 解压失败: {r.get('error', '未知错误')}[/]")

def cmd_verify(args):
    """校验解压完整性"""
    with console.status("🔍 校验完整性..."):
        r = _APKUnpacker.verify_integrity(args.apk, args.output)
    ok = r.get('ok', False)
    console.print(_make_panel(
        f"[{'green' if ok else 'red'}]{'✅ 完整性校验通过' if ok else '❌ 文件缺失'}"
        f"\n原始文件: {r.get('original', 0)}"
        f"\n解压文件: {r.get('extracted', 0)}"
        f"\n缺失: {r.get('missing', 0)}"
        f"\n总大小: {_fmt_size(r.get('size', 0))}"
        f"\nSHA256: {r.get('sha256', '')}",
        title="🔍 完整性校验", style="green" if ok else "red"
    ))

def cmd_decode(args):
    """Apktool 解包"""
    with console.status("🔧 Apktool 解包中..."):
        r = apktool_decode(args.apk, args.output, args.force or False)
    if r.get("success"):
        console.print(f"[bold green]✅ Apktool 解包成功: {args.output}[/]")
    else:
        console.print(f"[red]❌ 解包失败: {r.get('error', '未知错误')}[/]")

def cmd_build(args):
    """Apktool 重打包"""
    with console.status("🔧 Apktool 重打包中..."):
        r = apktool_build(args.input, args.output, args.force or False)
    if r.get("success"):
        console.print(f"[bold green]✅ Apktool 重打包成功: {args.output}[/]")
    else:
        console.print(f"[red]❌ 重打包失败: {r.get('error', '未知错误')}[/]")

def cmd_sign(args):
    """签名 APK"""
    with console.status("📝 签名中..."):
        r = sign_debug(args.apk, args.output)
    if r.get("success"):
        console.print(f"[bold green]✅ 签名成功: {args.output}[/]")
    else:
        console.print(f"[red]❌ 签名失败: {r.get('error', '未知错误')}[/]")

def cmd_jadx(args):
    """JADX 反编译"""
    with console.status("☕ JADX 反编译中..."):
        r = jadx_decompile(args.apk, args.output, deobf=not args.no_deobf)
    if r.get("success"):
        console.print(f"[bold green]✅ JADX 反编译成功: {args.output}[/]")
    else:
        console.print(f"[red]❌ JADX 反编译失败: {r.get('error', '未知错误')}[/]")

def cmd_clue(args):
    """线索串联分析 - 自动发现跨模块可疑信号"""
    with console.status("🔗 线索串联分析中...", spinner="dots"):
        r = analyze_full(args.apk)
        cc = r.get("clue_chain", {})

    if "error" in cc:
        console.print(f"[red]❌ 线索分析异常: {cc['error']}[/]")
        return

    # 风险评分大标题
    score = cc.get("score", 0)
    level = cc.get("level", "low")
    level_color = {"high": "red", "medium": "yellow", "low": "green"}
    level_icon = {"high": "⚠️", "medium": "⚡", "low": "✅"}
    clr = level_color.get(level, "white")
    icon = level_icon.get(level, "?")

    console.print(Panel(
        f"[bold {clr}]{icon} 综合风险评分: {score}/100 ({level.upper()})[/]",
        title="🔗 线索串联分析", border_style=clr, box=box.DOUBLE
    ))

    # 总结
    summary = cc.get("summary", {})
    if summary:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("项", style="cyan")
        t.add_column("值")
        t.add_row("结论", f"[{clr}]{summary.get('conclusion', '?')}[/]")
        t.add_row("风险标记", str(summary.get('risk_count', 0)))
        t.add_row("线索统计", summary.get('clue_summary', '?'))
        tags = summary.get('tags', [])
        if tags:
            t.add_row("特征标签", ", ".join(f"[bold]{t}[/]" for t in tags))
        console.print(_make_panel(t, "📊 分析总结", clr))

    # 逐个线索展示
    clues = cc.get("clues", [])
    if clues:
        console.print(f"\n[bold]🔍 发现 {len(clues)} 条线索:[/]")
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
            console.print()

    # 风险标记
    risks = cc.get("risks", [])
    if risks:
        console.print(f"\n[bold red]⚠️ 风险标记 ({len(risks)} 项):[/]")
        for r in risks:
            console.print(f"  • [red]{r}[/]")

    console.print()

def cmd_merge(args):
    """合并多个APK或合并DEX"""
    if args.dex:
        with console.status("🔄 合并 DEX 文件..."):
            r = merge_dex(args.apk, args.output)
        if r.get("success"):
            console.print(f"[bold green]✅ DEX 合并成功: {args.output}[/]")
            console.print(f"  [dim]{r.get('message', '')}[/]")
        else:
            console.print(f"[red]❌ DEX 合并失败: {r.get('error', '未知错误')}[/]")
    else:
        apks = args.apk.split(',')
        with console.status(f"🔄 合并 {len(apks)} 个 APK..."):
            r = merge_apks(apks, args.output)
        if r.get("success"):
            console.print(f"[bold green]✅ APK 合并成功: {args.output}[/]")
            console.print(f"  合并 {r.get('files_merged', 0)} 个 APK")
        else:
            console.print(f"[red]❌ 合并失败: {r.get('error', '未知错误')}[/]")

def cmd_rebuild(args):
    """从目录重建APK (ZIP打包)"""
    with console.status(f"📦 重建 APK 从 {args.input}..."):
        r = zip_rebuild(args.input, args.output, args.store and zipfile.ZIP_STORED or zipfile.ZIP_DEFLATED)
    if r.get("success"):
        console.print(f"[bold green]✅ 重建成功: {args.output}[/]")
        console.print(f"  大小: {_fmt_size(os.path.getsize(args.output))}")
    else:
        console.print(f"[red]❌ 重建失败: {r.get('error', '未知错误')}[/]")

def cmd_zipalign(args):
    """对齐APK"""
    with console.status(f"📐 对齐 {args.apk}..."):
        r = zipalign(args.apk, args.output)
    if r.get("success"):
        console.print(f"[bold green]✅ 对齐成功: {args.output}[/]")
    else:
        console.print(f"[red]❌ 对齐失败: {r.get('error', '未知错误')}[/]")

def cmd_convert(args):
    """格式转换 (DEX↔JAR / DEX↔Smali)"""
    from apk_reverse_engine import dex2jar, jar2dex, dex2smali, smali2dex

    if args.type == 'dex2jar':
        with console.status(f"🔄 DEX → JAR..."):
            r = dex2jar(args.input, args.output)
    elif args.type == 'jar2dex':
        with console.status(f"🔄 JAR → DEX..."):
            r = jar2dex(args.input, args.output)
    elif args.type == 'dex2smali':
        with console.status(f"🔄 DEX → Smali..."):
            r = dex2smali(args.input, args.output)
    elif args.type == 'smali2dex':
        with console.status(f"🔄 Smali → DEX..."):
            r = smali2dex(args.input, args.output)
    else:
        console.print(f"[red]❌ 不支持的转换类型: {args.type}[/]")
        return

    if r.get("success"):
        console.print(f"[bold green]✅ 转换成功: {args.output}[/]")
    else:
        console.print(f"[red]❌ 转换失败: {r.get('error', '未知错误')}[/]")

def cmd_patch(args):
    """原生 SO 补丁"""
    with console.status(f"🔧 执行 {args.type} 补丁..."):
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

    console.print(f"[bold green]✅ 补丁成功[/]")
    t = Table(box=box.SIMPLE, show_header=False)
    t.add_column("属性", style="cyan")
    t.add_column("值")
    t.add_row("类型", args.type)
    t.add_row("操作", desc)
    t.add_row("输出", args.output)
    t.add_row("大小", _fmt_size(len(data)))
    console.print(_make_panel(t, "🔧 补丁结果", "green"))

# ── 增强逆向新功能 ──────────────────────────────────────

def cmd_diff(args):
    """对比两个APK差异"""
    with console.status("🔍 对比APK差异中...", spinner="dots"):
        # 同时分析两个APK获取manifest/classes/permissions
        r1 = analyze_full(args.apk1)
        r2 = analyze_full(args.apk2)
        m1 = r1.get("manifest", {})
        m2 = r2.get("manifest", {})
        perms1 = [p.split('.')[-1] if '.' in p else p for p in m1.get("permissions", [])]
        perms2 = [p.split('.')[-1] if '.' in p else p for p in m2.get("permissions", [])]

        # 收集类名
        dex1 = r1.get("dex_summary", [])
        dex2 = r2.get("dex_summary", [])
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

    # 标题
    console.print(Panel(
        f"[bold cyan]{os.path.basename(args.apk1)}[/] vs [bold cyan]{os.path.basename(args.apk2)}[/]",
        title="🔍 APK 差异对比", border_style="cyan", box=box.DOUBLE
    ))

    # 摘要
    summary = r.get("summary", {})
    level = summary.get("change_level", "?")
    clr = {"微小": "green", "中等": "yellow", "显著": "red", "重大": "red"}.get(level, "white")
    console.print(f"[bold]变更等级:[/] [{clr}]{level}[/]  [dim]变更总数: {summary.get('total_changes', 0)}[/]")

    # 大小对比
    sz = r.get("structure", {}).get("size", {})
    if sz:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("指标", style="cyan")
        t.add_column("旧", justify="right")
        t.add_column("新", justify="right")
        t.add_row("原始大小", _fmt_size(sz.get('old_raw', 0)), _fmt_size(sz.get('new_raw', 0)))
        t.add_row("压缩大小", _fmt_size(sz.get('old_compressed', 0)), _fmt_size(sz.get('new_compressed', 0)))
        diff = sz.get('diff_raw', 0)
        diff_str = f"+{_fmt_size(diff)}" if diff > 0 else _fmt_size(diff)
        t.add_row("差异", f"[{'red' if diff>0 else 'green'}]{diff_str}[/]", "")
        console.print(_make_panel(t, "📊 大小对比", "green"))

    # 文件差异
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

        if files.get('added'):
            console.print(Panel("\n".join(f"  [green]➕ {f}[/]" for f in files['added'][:15]),
                                title="新增文件", border_style="green", title_align="left"))
        if files.get('removed'):
            console.print(Panel("\n".join(f"  [red]➖ {f}[/]" for f in files['removed'][:15]),
                                title="删除文件", border_style="red", title_align="left"))
        if files.get('modified'):
            console.print(Panel("\n".join(f"  [yellow]✏️ {m['file']} ({_fmt_size(m['old_size'])} → {_fmt_size(m['new_size'])})[/]" for m in files['modified'][:15]),
                                title="修改文件", border_style="yellow", title_align="left"))

    # Manifest差异
    man_diffs = r.get("manifest", [])
    if man_diffs:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("字段", style="cyan")
        t.add_column("旧值", style="red")
        t.add_column("新值", style="green")
        for d in man_diffs:
            t.add_row(d['field'], str(d.get('old', '?')), str(d.get('new', '?')))
        console.print(_make_panel(t, "📋 Manifest 变更", "blue"))

    # 权限差异
    perm_diff = r.get("permissions", {})
    if perm_diff:
        if perm_diff.get('added'):
            console.print(f"[green]➕ 新增权限 ({len(perm_diff['added'])}):[/] {' '.join(perm_diff['added'][:10])}")
        if perm_diff.get('removed'):
            console.print(f"[red]➖ 移除权限 ({len(perm_diff['removed'])}):[/] {' '.join(perm_diff['removed'][:10])}")

    # 类差异
    cls_diff = r.get("classes", {})
    if cls_diff:
        console.print(f"[bold]📦 类统计:[/] 新增 [green]{len(cls_diff.get('added', []))}[/] 移除 [red]{len(cls_diff.get('removed', []))}[/] 共同 {cls_diff.get('common_count', 0)}")

    console.print()

def cmd_endpoints(args):
    """从DEX中提取网络端点"""
    with console.status("🌐 提取网络端点...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            all_strings = []
            for d in ctx.get_dex_files():
                from apk_reverse_engine import dex_strings
                all_strings.extend(dex_strings(ctx.read_file(d)))
        r = extract_endpoints(all_strings)

    if args.json:
        console.print(json.dumps(r, indent=2, ensure_ascii=False, default=str))
        return

    console.print(Panel(
        f"[bold cyan]{os.path.basename(args.apk)}[/]",
        title="🌐 网络端点分析", border_style="cyan", box=box.DOUBLE
    ))

    # 协议概览
    proto = r.get("protocols", {})
    console.print(f"[bold]📊 协议:[/] HTTP={proto.get('http_only',0)}  HTTPS={proto.get('https_only',0)}  "
                  f"不安全比例=[{'red' if proto.get('insecure_ratio',0)>10 else 'green'}]{proto.get('insecure_ratio',0)}%[/]")

    # URL列表
    urls = r.get("urls", [])
    if urls:
        console.print(Panel("\n".join(f"  {u}" for u in urls[:20]),
                            title=f"📝 URL ({len(urls)})", border_style="blue", title_align="left"))

    # 域名
    domains = r.get("domains", [])
    if domains:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("类型", style="cyan")
        t.add_column("域名", style="white")
        for d in domains[:20]:
            tag = ""
            if d in r.get("cloud_hosts", []):
                tag = " ☁️云"
            elif d in r.get("cdn_hosts", []):
                tag = " 🚀CDN"
            elif d in r.get("internal_hosts", []):
                tag = " 🔒内网"
            t.add_row(tag, d)
        console.print(_make_panel(t, f"🌐 域名 ({len(domains)})", "cyan"))

    # IP
    public_ips = r.get("public_ips", [])
    private_ips = r.get("private_ips", [])
    if public_ips or private_ips:
        console.print(f"[bold]📡 IP:[/] 公网 [red]{len(public_ips)}[/] 内网 [dim]{len(private_ips)}[/]")
        if public_ips:
            console.print(f"  [red]{' '.join(public_ips[:10])}[/]")

    # API路径
    api_paths = r.get("api_paths", [])
    if api_paths:
        console.print(Panel("\n".join(f"  {p}" for p in api_paths[:20]),
                            title=f"🔗 API路径 ({len(api_paths)})", border_style="magenta", title_align="left"))

    # 端口
    ports = r.get("ports", [])
    if ports:
        console.print(f"[bold]🔌 端口:[/] {', '.join(ports[:15])}")

    console.print()

def cmd_keyscan(args):
    """扫描DEX中的硬编码密钥"""
    with console.status("🔑 扫描密钥...", spinner="dots"):
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
    console.print(Panel(
        f"[bold {clr}]风险评分: {risk_score}/100 ({risk_level})[/]\n"
        f"发现 {total} 个敏感信息 (高危={high} 中危={medium})",
        title="🔑 密钥扫描结果", border_style=clr, box=box.DOUBLE
    ))

    keys = r.get("keys", [])
    if keys:
        sev_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "INFO": "🔵"}
        for k in keys[:30]:
            icon = sev_icon.get(k.get("severity", "INFO"), "•")
            console.print(f"  {icon} [bold]{k['category']}[/] [dim]{k['match'][:80]}[/]")
        if len(keys) > 30:
            console.print(f"[dim]... 还有 {len(keys)-30} 项[/]")

    if weak_crypto:
        console.print(f"\n[bold yellow]⚠️ 弱加密告警:[/]")
        for w in weak_crypto:
            console.print(f"  • {w}")

    console.print()

def cmd_cert(args):
    """深度分析签名证书"""
    with console.status("📜 分析签名证书...", spinner="dots"):
        with open_apk(args.apk) as ctx:
            sig = verify_signature(ctx.zip, args.apk)
            cert_info = sig.get("cert_info", {})
            cert_analysis = analyze_cert_deep(cert_info)

    # 签名方案
    console.print(Panel(
        f"[bold]签名方案:[/] V1={_bool_icon(sig.get('v1', False))}  "
        f"V2={_bool_icon(sig.get('v2', False))}  V3={_bool_icon(sig.get('v3', False))}\n"
        f"[bold]安全等级:[/] {sig.get('security_level', '?')}",
        title="📜 签名证书分析", border_style="cyan", box=box.DOUBLE
    ))

    if "error" in cert_analysis:
        console.print(f"[red]❌ {cert_analysis['error']}[/]")
        return

    # 签发者/主题
    t = Table(box=box.SIMPLE, show_header=False)
    t.add_column("属性", style="cyan")
    t.add_column("值")
    t.add_row("签发者", cert_analysis.get('issuer_str', '?'))
    t.add_row("主体", cert_analysis.get('subject_str', '?'))
    t.add_row("序列号", cert_analysis.get('serial', '?'))
    validity = cert_analysis.get('validity', {})
    if validity:
        t.add_row("有效期", f"{validity.get('not_before', '?')} → {validity.get('not_after', '?')}")
    console.print(_make_panel(t, "📋 证书信息", "blue"))

    # 风险评分
    risk_score = cert_analysis.get('risk_score', 0)
    risk_level = cert_analysis.get('risk_level', '?')
    clr = {"安全": "green", "低风险": "yellow", "中风险": "red", "高风险": "red"}.get(risk_level, "white")
    console.print(f"[bold]风险评分:[/] [{clr}]{risk_score}/100 ({risk_level})[/]")

    for issue in cert_analysis.get('issues', []):
        console.print(f"  {issue}")
    for finding in cert_analysis.get('findings', []):
        console.print(f"  {finding}")

    console.print()

def cmd_clean(args):
    """APK清理优化"""
    if not args.dry_run and args.output:
        with console.status("🧹 清理APK中..."):
            r = clean_apk(args.apk, args.output, args.remove_debug, args.remove_meta, remove_backup=True)
        if r.get("success"):
            console.print(f"[bold green]✅ 清理成功: {args.output}[/]")
            t = Table(box=box.SIMPLE, show_header=False)
            t.add_column("指标", style="cyan")
            t.add_column("值")
            t.add_row("保留文件", str(r.get('kept', 0)))
            t.add_row("移除文件", str(r.get('removed', 0)))
            t.add_row("节省空间", _fmt_size(r.get('removed_size', 0)))
            t.add_row("压缩率", f"{r.get('saved_percent', 0)}%")
            console.print(_make_panel(t, "📊 清理结果", "green"))
            return

    # 分析模式
    with console.status("🧹 分析APK冗余文件..."):
        r = analyze_apk_clean(args.apk)

    sz = r.get("size", 0)
    waste = r.get("total_waste", 0)
    ratio = r.get("waste_ratio", 0)
    level = r.get("clean_potential", {}).get("level", "?")
    clr = {"优秀": "green", "良好": "blue", "一般": "yellow", "需优化": "red"}.get(level, "white")

    console.print(Panel(
        f"[bold]APK大小:[/] {_fmt_size(sz)}  |  "
        f"[bold]可回收:[/] [{'red' if waste>0 else 'green'}]{_fmt_size(waste)}[/]  |  "
        f"[bold {clr}]优化等级: {level} ({ratio})[/]",
        title="🧹 APK清理分析", border_style=clr, box=box.DOUBLE
    ))

    # 调试文件
    debug_files = r.get("debug_files", [])
    if debug_files:
        console.print(Panel("\n".join(f"  [red]🗑️ {f['file']} ({_fmt_size(f['size'])})[/]" for f in debug_files[:10]),
                            title=f"调试/测试文件 ({len(debug_files)})", border_style="red", title_align="left"))

    # 大文件
    large = r.get("large_files", [])
    if large:
        t = Table(box=box.SIMPLE)
        t.add_column("文件", style="cyan")
        t.add_column("大小", justify="right")
        for f in large[:10]:
            t.add_row(f['file'], _fmt_size(f['size']))
        console.print(_make_panel(t, f"大文件 Top {len(large[:10])}", "yellow"))

    # 建议
    for rec in r.get("recommendations", []):
        ps = rec.get('potential_saving', '')
        if isinstance(ps, (int, float)):
            ps = _fmt_size(ps)
        console.print(f"  💡 [bold]{rec['type']}:[/] {rec['detail']} [dim](可节省: {ps})[/]")

    if not args.dry_run and not args.output:
        console.print(f"\n[dim]💡 使用 reng clean {args.apk} output.apk 执行清理[/]")

    console.print()

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

    args = parser.parse_args()
    
    if not hasattr(args, "func"):
        # 显示欢迎界面
        console.print()
        console.print(Panel.fit(
            "[bold cyan]  APK Reverse Engineering Engine v2  [/]\n"
            "[dim]  全功能 APK 逆向工具集  |  90+ 基础功能  |  36 模块  [/]",
            border_style="cyan", box=box.DOUBLE_EDGE
        ))
        console.print()
        console.print("[bold]可用命令:[/]")
        
        cmds = [
            ("📦  inspect", "APK 基本信息概览", "cyan"),
            ("🔬  analyze", "全面分析 APK", "green"),
            ("📋  manifest", "解析 AndroidManifest", "blue"),
            ("📜  dex", "DEX 文件分析", "yellow"),
            ("📦  classes", "列出 DEX 类名", "green"),
            ("🔧  so", "分析 SO 文件", "magenta"),
            ("🔍  search", "搜索关键字", "cyan"),
            ("📦  unpack", "解压 APK (分类/并行/增量)", "blue"),
            ("🔍  verify", "校验解压完整性", "cyan"),
            ("🔗  clue", "线索串联分析", "red"),
            ("🔧  decode", "Apktool 解包", "yellow"),
            ("🔧  build", "Apktool 重打包", "yellow"),
            ("📝  sign", "签名 APK", "green"),
            ("☕  jadx", "JADX 反编译", "magenta"),
            ("🔧  patch", "SO 补丁", "red"),
        ]
        
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("命令", style="bold")
        t.add_column("说明", style="dim")
        for cmd, desc, color in cmds:
            t.add_row(f"[{color}]{cmd}[/]", desc)
        console.print(t)
        
        console.print()
        console.print("[dim]使用 reng <command> --help 查看详细用法[/]")
        console.print()
        return

    args.func(args)

if __name__ == "__main__":
    main()