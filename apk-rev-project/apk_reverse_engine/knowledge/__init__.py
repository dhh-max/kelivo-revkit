"""知识库 - 持久化加固/SDK/混淆模式数据库（参照 Operit 持久记忆能力）

子模块：
  kb           持久化知识库（加固/SDK/混淆特征，JSON 存储）
  ad_templates 广告分析提示词模板（XML 资源加载）
"""

from .kb import KnowledgeBase, seed_default_knowledge
from .ad_templates import (
    get_template,
    get_all_templates,
    get_sdk_template,
    format_analysis_prompt,
    get_blocking_suggestions,
    get_common_keywords,
    get_obfuscated_analysis_guide,
    reload as reload_templates,
)

__all__ = [
    'KnowledgeBase',
    'seed_default_knowledge',
    'get_template',
    'get_all_templates',
    'get_sdk_template',
    'format_analysis_prompt',
    'get_blocking_suggestions',
    'get_common_keywords',
    'get_obfuscated_analysis_guide',
    'reload_templates',
]