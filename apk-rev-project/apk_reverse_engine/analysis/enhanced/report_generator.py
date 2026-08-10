"""分析报告生成器 - HTML/JSON/Markdown 结构化报告输出

支持多种格式：
- JSON: 机器可读的结构化报告
- HTML: 带样式的可视化报告（含表格、统计图描述）
- Markdown: 适合版本控制和文档集成
"""
import json
import os
import time
from html import escape


class ReportGenerator:
    """逆向分析报告生成器"""

    @staticmethod
    def generate_json(results, apk_name='', output_path=None):
        """生成 JSON 格式报告

        Args:
            results: dict 或 list，分析结果
            apk_name: APK 文件名
            output_path: 输出路径（可选）

        Returns:
            str: JSON 字符串
        """
        report = {
            'meta': {
                'tool': 'APK Reverse Engineering Engine v2',
                'apk_name': os.path.basename(apk_name) if apk_name else '',
                'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'timestamp': time.time(),
            },
            'results': results,
        }
        json_str = json.dumps(report, ensure_ascii=False, indent=2, default=str)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
        return json_str

    @staticmethod
    def generate_markdown(results, apk_name='', output_path=None):
        """生成 Markdown 格式报告"""
        lines = [
            '# APK 逆向分析报告',
            '',
            f'- **文件**: {os.path.basename(apk_name) if apk_name else "N/A"}',
            f'- **生成时间**: {time.strftime("%Y-%m-%d %H:%M:%S")}',
            '- **工具**: APK Reverse Engineering Engine v2',
            '',
            '---',
            '',
        ]

        if isinstance(results, dict):
            for section, data in results.items():
                lines.append(f'## {section}')
                lines.append('')
                lines.append(ReportGenerator._md_section(data))
                lines.append('')
        elif isinstance(results, list):
            lines.append(ReportGenerator._md_section(results))

        md_str = '\n'.join(lines)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(md_str)
        return md_str

    @staticmethod
    def _md_section(data, depth=0):
        """递归生成 Markdown 片段"""
        lines = []
        indent = '  ' * depth
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, (dict, list)) and v:
                    lines.append(f'{indent}**{k}**:')
                    lines.append(ReportGenerator._md_section(v, depth + 1))
                else:
                    lines.append(f'{indent}- **{k}**: {v}')
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    lines.append(f'{indent}{i + 1}.')
                    lines.append(ReportGenerator._md_section(item, depth + 1))
                else:
                    lines.append(f'{indent}- {item}')
        else:
            lines.append(f'{indent}{data}')
        return '\n'.join(lines)

    @staticmethod
    def generate_html(results, apk_name='', output_path=None):
        """生成 HTML 格式报告（带样式）"""
        sections_html = ReportGenerator._html_section(results, 0)

        html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK 逆向分析报告 - {escape(os.path.basename(apk_name) if apk_name else "N/A")}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #16213e, #0f3460); padding: 30px; border-radius: 12px; margin-bottom: 20px; }}
        .header h1 {{ color: #e94560; font-size: 24px; margin-bottom: 10px; }}
        .header .meta {{ color: #a0a0b0; font-size: 13px; }}
        .header .meta span {{ margin-right: 20px; }}
        .section {{ background: #16213e; border-radius: 10px; padding: 20px; margin-bottom: 15px; border-left: 4px solid #e94560; }}
        .section h2 {{ color: #e94560; font-size: 18px; margin-bottom: 12px; }}
        .subsection {{ background: #0f3460; border-radius: 8px; padding: 15px; margin-bottom: 10px; }}
        .subsection h3 {{ color: #f5a623; font-size: 15px; margin-bottom: 8px; }}
        .kv {{ display: grid; grid-template-columns: 200px 1fr; gap: 4px; font-size: 13px; }}
        .kv .key {{ color: #8888aa; }}
        .kv .val {{ color: #e0e0e0; word-break: break-all; }}
        .item {{ background: #1a1a3e; border-radius: 6px; padding: 10px; margin-bottom: 6px; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
        .badge-critical {{ background: #e94560; color: white; }}
        .badge-high {{ background: #f5a623; color: white; }}
        .badge-medium {{ background: #f5d142; color: #1a1a2e; }}
        .badge-low {{ background: #4ecca3; color: #1a1a2e; }}
        .badge-info {{ background: #4a90d9; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th {{ background: #0f3460; color: #e94560; padding: 8px; text-align: left; font-size: 13px; }}
        td {{ padding: 8px; border-bottom: 1px solid #1a1a3e; font-size: 13px; }}
        .summary {{ display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 20px; }}
        .stat-card {{ background: #16213e; border-radius: 10px; padding: 20px; min-width: 120px; text-align: center; }}
        .stat-card .num {{ font-size: 28px; font-weight: bold; color: #e94560; }}
        .stat-card .label {{ font-size: 12px; color: #8888aa; margin-top: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ APK 逆向分析报告</h1>
        <div class="meta">
            <span>📦 文件: {escape(os.path.basename(apk_name) if apk_name else "N/A")}</span>
            <span>🕐 {escape(time.strftime("%Y-%m-%d %H:%M:%S"))}</span>
            <span>🔧 APK Reverse Engineering Engine v2</span>
        </div>
    </div>
    {sections_html}
</body>
</html>'''

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
        return html

    @staticmethod
    def _html_section(data, depth=0):
        """递归生成 HTML 片段"""
        html_parts = []

        if isinstance(data, dict):
            # 检查是否有 summary 统计信息
            if 'total_findings' in data and isinstance(data.get('total_findings'), int):
                return ReportGenerator._html_summary_card(data)

            for k, v in data.items():
                if isinstance(v, (dict, list)) and v:
                    if depth == 0:
                        html_parts.append(f'<div class="section"><h2>{escape(str(k))}</h2>')
                        html_parts.append(ReportGenerator._html_section(v, depth + 1))
                        html_parts.append('</div>')
                    else:
                        html_parts.append(f'<div class="subsection"><h3>{escape(str(k))}</h3>')
                        html_parts.append(ReportGenerator._html_section(v, depth + 1))
                        html_parts.append('</div>')
                else:
                    html_parts.append(
                        f'<div class="kv"><span class="key">{escape(str(k))}</span>'
                        f'<span class="val">{escape(str(v))}</span></div>'
                    )
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    severity = item.get('severity', '')
                    badge = f'<span class="badge badge-{severity}">{severity.upper()}</span>' if severity else ''
                    parts = []
                    for ik, iv in item.items():
                        parts.append(f'{escape(str(ik))}: {escape(str(iv)[:200])}')
                    html_parts.append(f'<div class="item">{badge} {escape(" | ".join(parts))}</div>')
                else:
                    html_parts.append(f'<div class="item">{escape(str(item))}</div>')

        return '\n'.join(html_parts)

    @staticmethod
    def _html_summary_card(data):
        """生成统计卡片 HTML"""
        total = data.get('total_findings', 0)
        summary = data.get('summary', {})
        categories = data.get('categories', {})
        critical = data.get('critical_findings', [])

        cards = []
        cards.append(f'<div class="stat-card"><div class="num">{total}</div><div class="label">总发现</div></div>')
        for sev in ['critical', 'high', 'medium', 'low']:
            count = summary.get(sev, 0)
            cards.append(f'<div class="stat-card"><div class="num">{count}</div><div class="label">{sev.upper()}</div></div>')

        cat_table = '<table><tr><th>类别</th><th>数量</th></tr>'
        for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
            cat_table += f'<tr><td>{escape(str(cat))}</td><td>{cnt}</td></tr>'
        cat_table += '</table>'

        crit_html = ''
        if critical:
            crit_html = '<div class="subsection"><h3>🔴 严重风险</h3>'
            for c in critical[:20]:
                cat = escape(str(c.get("category", "")))
                desc = escape(str(c.get("description", ""))[:150])
                crit_html += f'<div class="item"><span class="badge badge-critical">CRITICAL</span> {cat}: {desc}</div>'
            crit_html += '</div>'

        return f'''
        <div class="section">
            <h2>📊 安全漏洞扫描结果</h2>
            <div class="summary">{"".join(cards)}</div>
            {cat_table}
            {crit_html}
        </div>'''

    @staticmethod
    def generate(results, apk_name='', output_path=None, fmt='json'):
        """统一报告生成接口

        Args:
            results: 分析结果
            apk_name: APK 文件名
            output_path: 输出路径（根据格式自动加扩展名）
            fmt: 格式 json/html/markdown

        Returns:
            str: 报告内容
        """
        if output_path and not output_path.endswith(f'.{fmt}'):
            output_path = f'{output_path}.{fmt}'

        if fmt == 'json':
            return ReportGenerator.generate_json(results, apk_name, output_path)
        elif fmt == 'html':
            return ReportGenerator.generate_html(results, apk_name, output_path)
        elif fmt == 'markdown':
            return ReportGenerator.generate_markdown(results, apk_name, output_path)
        else:
            raise ValueError(f'不支持的格式: {fmt}')
