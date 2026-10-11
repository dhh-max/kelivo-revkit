"""广告分析提示词模板库

从 XML 资源文件加载广告识别/分析/屏蔽的提示词模板，
供 AI 辅助分析模块调用。

模板分类：
  - 通用分析：ad_analysis_template, no_ad_found_template
  - 屏蔽建议：ad_blocking_suggestions
  - SDK专项：google_admob, facebook_audience_network, unity_ads,
             tencent_ads, byte_dance, baidu
  - 辅助识别：ad_common_keywords, ad_obfuscated_code_analysis
"""
import os
import xml.etree.ElementTree as ET
from typing import Dict, Optional

# XML 资源文件路径
_XML_PATH = os.path.join(os.path.dirname(__file__), 'res', 'ad_analysis_templates.xml')

# 单例缓存
_cache: Optional[Dict[str, str]] = None


def _load() -> Dict[str, str]:
    """解析 XML 资源文件，返回 {name: value} 映射"""
    global _cache
    if _cache is not None:
        return _cache

    templates: Dict[str, str] = {}
    if not os.path.isfile(_XML_PATH):
        raise FileNotFoundError(f"广告分析模板文件不存在: {_XML_PATH}")

    tree = ET.parse(_XML_PATH)
    root = tree.getroot()
    for node in root.findall('string'):
        name = node.get('name', '')
        value = node.text or ''
        if name:
            templates[name] = value.strip()

    _cache = templates
    return templates


def get_template(name: str) -> str:
    """按名称获取提示词模板文本

    Args:
        name: 模板名称，如 'ad_analysis_template', 'google_admob_analysis'

    Returns:
        模板文本字符串；找不到时返回空字符串
    """
    return _load().get(name, '')


def get_all_templates() -> Dict[str, str]:
    """获取全部模板"""
    return dict(_load())


def get_sdk_template(sdk_key: str) -> str:
    """按 SDK 标识获取对应的专项分析模板

    Args:
        sdk_key: SDK 标识，如 'google', 'facebook', 'unity',
                 'tencent', 'pangle'(穿山甲), 'baidu'

    Returns:
        对应的提示词模板；无匹配时返回通用分析模板
    """
    mapping = {
        'google':    'google_admob_analysis',
        'admob':     'google_admob_analysis',
        'facebook':  'facebook_audience_network_analysis',
        'unity':     'unity_ads_analysis',
        'tencent':   'tencent_ads_analysis',
        'pangle':    'byte_dance_ads_analysis',
        'bytedance': 'byte_dance_ads_analysis',
        'toutiao':   'byte_dance_ads_analysis',
        'baidu':     'baidu_ads_analysis',
    }
    tpl_name = mapping.get(sdk_key.lower(), 'ad_analysis_template')
    return get_template(tpl_name)


def format_analysis_prompt(code_snippet: str, sdk_hint: str = '') -> str:
    """组装完整的广告分析提示词

    Args:
        code_snippet: 待分析的代码片段
        sdk_hint: 可选的 SDK 提示（如 'google', 'tencent'），
                  会附加对应 SDK 的专项分析要点

    Returns:
        组装后的完整提示词
    """
    base = get_template('ad_analysis_template')
    if sdk_hint:
        sdk_tpl = get_sdk_template(sdk_hint)
        if sdk_tpl:
            base += '\n\n--- ' + sdk_hint.upper() + ' 专项分析要点 ---\n' + sdk_tpl
    return base + code_snippet


def get_blocking_suggestions() -> str:
    """获取广告屏蔽建议模板"""
    return get_template('ad_blocking_suggestions')


def get_common_keywords() -> str:
    """获取广告识别通用关键词列表"""
    return get_template('ad_common_keywords')


def get_obfuscated_analysis_guide() -> str:
    """获取广告混淆代码识别指南"""
    return get_template('ad_obfuscated_code_analysis')


def reload():
    """清除缓存，强制重新加载 XML 文件"""
    global _cache
    _cache = None
    return _load()