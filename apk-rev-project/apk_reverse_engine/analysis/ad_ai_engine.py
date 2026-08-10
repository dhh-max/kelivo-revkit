"""AI 广告识别分析引擎

基于 LLM（SiliconFlow/OpenAI 兼容接口）对 Smali/Java/XML/JavaScript 代码
进行广告相关接口和实现方式的智能分析。

功能：
  - 支持 SiliconFlow、OpenAI 及任何兼容 /v1/chat/completions 的 API
  - 动态获取可用模型列表（30分钟缓存）
  - 思考模型（R1/Thinking）深度分析模式
  - 两种提问模式：直连分析 / 补充问答
  - 与 ad_templates 提示词模板库联动
  - 可配置广告SDK检测范围（AdMob/Facebook/Unity/腾讯/字节跳动等）
  - 支持自定义关键词
  - 流式输出 (streaming) 支持
  - 自动重试与可配置速率限制
  - 与 AdDetector 联动，智能预筛选广告相关代码
  - 并发批量分析（最多5路同时）
  - 结果缓存（避免重复分析相同代码，LRU淘汰）
  - 代码去重（相似片段合并，指纹哈希）
  - Token 估算与自动截断
  - 系统提示词优化分析质量
  - 失败自动切换备用模型
  - 请求超时分级（思考模型/普通模型/流式）
  - 进度回调与流式回调
  - 连接池复用（urllib opener 缓存）
  - 批量请求熔断保护（连续失败阈值）
  - 流式 SSE 解析支持 CRLF
  - 响应截断检测（finish_reason）
  - 线程安全速率限制器（锁外等待）
  - 预编译正则缓存

Author: APK Reverse Engine
"""


from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

import os
import json
import time
import re
import hashlib
import threading
import queue
import urllib.request
import urllib.error
import ssl
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Iterator, Callable
__all__ = [
    "AdAIEngine",
    "analyze_ad_code",
    "analyze_ad_code_stream",
    "prefilter_ad_code",
    "list_ai_models",
    "analyze_ad_code_batch",
    "analyze_ad_code_stream_batch",
]


class AdAIEngine:
    """AI 广告识别分析引擎"""

    DEFAULT_API_URL = "https://api.siliconflow.cn/v1/chat/completions"
    MODELS_API_URL = "https://api.siliconflow.cn/v1/models"

    # 默认模型列表（API 不可用时回退）
    FALLBACK_MODELS = [
        "tencent/Hunyuan-MT-7B",
        "THUDM/GLM-4.1V-9B-Thinking",
        "deepseek-ai/DeepSeek-R1-0528-Qwen3-8B",
        "Qwen/Qwen3-8B",
        "THUDM/GLM-Z1-9B-0414",
        "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B",
        "Qwen/Qwen2.5-7B-Instruct",
        "THUDM/glm-4-9b-chat",
        "Qwen/Qwen2.5-Coder-7B-Instruct",
    ]

    # 备用模型链：主模型失败后按顺序尝试
    FALLBACK_CHAIN = [
        "Qwen/Qwen2.5-7B-Instruct",
        "THUDM/glm-4-9b-chat",
        "Qwen/Qwen2.5-Coder-7B-Instruct",
    ]

    # 模型缓存
    MODEL_CACHE_DURATION = 30 * 60  # 30分钟（秒）
    _cached_models: Optional[List[str]] = None
    _last_model_fetch: float = 0
    _model_cache_lock = threading.Lock()

    # 重试配置
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # 秒
    RETRY_BACKOFF = 1.5  # 指数退避因子

    # 速率限制
    MIN_REQUEST_INTERVAL = 1.0  # 最小请求间隔（秒），设为0则禁用
    _last_request_time: float = 0
    _rate_lock: threading.Lock = threading.Lock()
    _rate_limit_enabled: bool = True  # 全局开关

    # 代码片段截断限制
    MAX_CODE_LENGTH = 12000  # 单次分析最大代码长度（字符）
    MAX_INSTRUCTIONS = 500   # 单个方法最大提取指令数

    # 并发控制
    MAX_CONCURRENT = 5       # 最大并发 AI 分析请求数

    # Token 估算（粗略：1 token ≈ 3.5 字符）
    TOKEN_CHAR_RATIO = 3.5
    MAX_CONTEXT_TOKENS = 32000  # 模型上下文窗口上限（保守值）
    RESERVE_TOKENS = 2000       # 为输出预留的 token 数

    # 结果缓存（OrderedDict 实现 LRU 淘汰）
    _result_cache: "OrderedDict[str, str]" = OrderedDict()
    _cache_lock: threading.Lock = threading.Lock()
    _CACHE_MAX_SIZE = 500

    # 熔断保护
    _consecutive_failures: int = 0
    _circuit_lock: threading.Lock = threading.Lock()
    CIRCUIT_BREAK_THRESHOLD = 5  # 连续失败5次后熔断
    CIRCUIT_BREAK_COOLDOWN = 30  # 熔断后冷却30秒
    _circuit_opened_at: float = 0

    # ── 模型显示名映射 ──────────────────────────────────────
    MODEL_DISPLAY_NAMES = {
        "tencent/Hunyuan-MT-7B": "腾讯混元-MT-7B",
        "THUDM/GLM-4.1V-9B-Thinking": "智谱GLM-4V-9B(思考模式)",
        "deepseek-ai/DeepSeek-R1-0528-Qwen3-8B": "DeepSeek-R1-0528",
        "Qwen/Qwen3-8B": "通义千问3-8B",
        "THUDM/GLM-Z1-9B-0414": "智谱GLM-Z1-9B",
        "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B": "DeepSeek-R1-Distill",
        "Qwen/Qwen2.5-7B-Instruct": "通义千问2.5-7B",
        "THUDM/glm-4-9b-chat": "智谱GLM-4-9B",
        "Qwen/Qwen2.5-Coder-7B-Instruct": "通义千问2.5-代码专家",
    }

    # 源语言显示名
    LANG_DISPLAY = {
        "smali": "Smali代码",
        "java": "Java代码",
        "xml": "XML布局",
        "javascript": "JavaScript",
    }

    # ── 预编译正则缓存 ──────────────────────────────────────
    _RE_SDK_PACKAGES: List[re.Pattern] = [
        re.compile(p, re.IGNORECASE) for p in [
            r'com/google/ads?', r'com/google/android/gms/ads',
            r'com/facebook/ads', r'com/unity3d/ads',
            r'com/tencent/mttads', r'com/bytedance/sdk',
            r'com/ss/android', r'com/mintegral', r'com/applovin',
            r'com/vungle', r'com/adcolony', r'com/chartboost',
            r'com/ironsource', r'com/startapp', r'com/inmobi',
            r'com/mbridge', r'com/sigmob',
        ]
    ]
    _RE_AD_API: List[re.Pattern] = [
        re.compile(p, re.IGNORECASE) for p in [
            r'adview', r'adlistener', r'adrequest', r'adsize', r'adloader',
            r'interstitialad', r'rewardedvideoad', r'rewardedad', r'nativead',
            r'bannerad', r'admanager', r'mobileads', r'admob',
            r'loadad\b', r'showad\b', r'destroyad',
            r'adunitid', r'ad_unit_id', r'placementid', r'placement_id',
            r'onadloaded', r'onadfailed', r'onadclosed', r'onadclicked',
            r'onadimpression', r'onadshow', r'onaddismiss',
            r'ttad', r'buadsdk', r'pangle', r'gdt', r'sigmob',
            r'applovin', r'vungle', r'adcolony', r'chartboost',
            r'ironsource', r'startapp', r'inmobi', r'mintegral',
            r'doubleclick', r'googlesyndication', r'adsrvr',
            r'mbridge', r'mintegraladsdk',
            r'adcontainer', r'adlayout', r'admobflex',
            r'google_admob', r'advertiser', r'advertising',
            r'adset', r'adsetups', r'adnetwork',
        ]
    ]
    _RE_AD_WORD = re.compile(r'\bad\b', re.IGNORECASE)
    _RE_THINKING_TAG = re.compile(r'<thinking>|思考过程|思考[:：]')
    _RE_THINKING_SPLIT = re.compile(
        r'(?=<thinking>)|(?=</thinking>)|(?=思考过程)|(?=最终答案)|(?=结论)'
    )
    _RE_THINKING_CLEAN = re.compile(
        r'</?thinking>|</?think>|最终答案|结论|思考过程|思考[:：]'
    )
    _RE_SSE_DONE = re.compile(r'^data:\s*\[DONE\]', re.IGNORECASE)

    def __init__(self, api_key: str = "", api_url: str = ""):
        self.api_key = api_key
        self.api_url = api_url or self.DEFAULT_API_URL
        # 复用 HTTPS 连接的 opener
        self._ssl_ctx = ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ssl_ctx)
        )

    # ================================================================
    # 配置
    # ================================================================

    def configure(self, api_key: str, api_url: str = ""):
        """配置 API 密钥和地址"""
        self.api_key = api_key
        if api_url:
            self.api_url = api_url

    def is_configured(self) -> bool:
        """检查是否已配置 API 密钥"""
        return bool(self.api_key)

    # ================================================================
    # 熔断保护
    # ================================================================

    @classmethod
    def _check_circuit(cls) -> bool:
        """检查熔断状态，返回是否可以继续请求"""
        with cls._circuit_lock:
            if cls._consecutive_failures >= cls.CIRCUIT_BREAK_THRESHOLD:
                elapsed = time.time() - cls._circuit_opened_at
                if elapsed < cls.CIRCUIT_BREAK_COOLDOWN:
                    return False
                # 冷却期结束，重置
                cls._consecutive_failures = 0
                cls._circuit_opened_at = 0
            return True

    @classmethod
    def _record_success(cls):
        """记录一次成功请求"""
        with cls._circuit_lock:
            cls._consecutive_failures = 0

    @classmethod
    def _record_failure(cls):
        """记录一次失败请求"""
        with cls._circuit_lock:
            cls._consecutive_failures += 1
            if cls._consecutive_failures >= cls.CIRCUIT_BREAK_THRESHOLD:
                cls._circuit_opened_at = time.time()

    # ================================================================
    # 模型管理
    # ================================================================

    @classmethod
    def fetch_available_models(cls, api_key: str, api_url: str = "") -> Optional[List[str]]:
        """从 API 动态获取可用模型列表（带缓存）"""
        now = time.time()
        # 快速路径：不加锁检查缓存
        if cls._cached_models is not None and (now - cls._last_model_fetch) < cls.MODEL_CACHE_DURATION:
            return cls._cached_models

        with cls._model_cache_lock:
            # 双重检查
            now = time.time()
            if cls._cached_models is not None and (now - cls._last_model_fetch) < cls.MODEL_CACHE_DURATION:
                return cls._cached_models

            if not api_key:
                return None

            models_url = api_url.replace('/chat/completions', '/models') if api_url else cls.MODELS_API_URL

            try:
                req = urllib.request.Request(
                    models_url,
                    headers={"Authorization": f"Bearer {api_key}"},
                    method="GET",
                )
                ssl_ctx = ssl.create_default_context()
                with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
                    data = json.loads(resp.read().decode('utf-8'))

                models = []
                if 'data' in data:
                    for item in data['data']:
                        model_id = item.get('id', '')
                        if model_id and cls._is_chat_model(model_id):
                            models.append(model_id)

                cls._cached_models = models
                cls._last_model_fetch = now
                return models
            except Exception as e:
                from apk_reverse_engine.utils.logutil import get_logger
                get_logger(__name__).warning("fetch_available_models failed: %s", e)
                return None

    @staticmethod
    def _is_chat_model(model_id: str) -> bool:
        """判断是否为对话/聊天模型"""
        model_lower = model_id.lower()
        chat_keywords = [
            'chat', 'instruct', 'conversation', 'qwen', 'glm', 'deepseek',
            'claude', 'gpt', 'llama', 'mistral', 'yi', 'baichuan', 'internlm',
            'mixtral', 'chatglm', 'moonshot', 'hunyuan', 'sparkdesk', 'ernie',
            'sensechat', '360',
        ]
        if 'embedding' in model_lower or 'bge' in model_lower:
            if not any(kw in model_lower for kw in ['chat', 'instruct']):
                return False
        return any(kw in model_lower for kw in chat_keywords)

    def get_available_models(self) -> List[str]:
        """获取可用模型列表（优先动态获取，回退默认列表）"""
        if not self.is_configured():
            return list(self.FALLBACK_MODELS)
        dynamic = self.fetch_available_models(self.api_key, self.api_url)
        if dynamic:
            return dynamic
        return list(self.FALLBACK_MODELS)

    @classmethod
    def get_model_display_name(cls, model_id: str) -> str:
        """获取模型显示名称"""
        if model_id in cls.MODEL_DISPLAY_NAMES:
            return cls.MODEL_DISPLAY_NAMES[model_id]
        return cls._extract_model_display_name(model_id)

    @staticmethod
    def _extract_model_display_name(model_id: str) -> str:
        """从模型ID提取显示名"""
        if '/' in model_id:
            parts = model_id.split('/')
            if len(parts) >= 2:
                name = parts[1]
                for suffix in ['-Instruct', '-Chat', '-Base',
                               '-v1', '-v2', '-v3',
                               '-01', '-02', '-03', '-04', '-05', '-06', '-07', '-08', '-09',
                               '-1', '-2', '-3', '-4', '-5', '-6', '-7', '-8', '-9', '-0']:
                    name = name.replace(suffix, '')
                if 'Thinking' in model_id or 'R1' in model_id:
                    name += "(思考模式)"
                if 'Coder' in model_id or 'Code' in model_id:
                    name += "(代码专家)"
                return name
        return model_id

    @staticmethod
    def is_thinking_model(model: str) -> bool:
        """判断是否为思考模型"""
        return 'Thinking' in model or 'R1' in model

    # ================================================================
    # Token 估算
    # ================================================================

    @classmethod
    def estimate_tokens(cls, text: str) -> int:
        """粗略估算文本的 token 数量"""
        return max(1, int(len(text) / cls.TOKEN_CHAR_RATIO))

    @classmethod
    def truncate_to_token_limit(cls, code: str, reserve: int = None) -> str:
        """按 token 上限截断代码"""
        reserve = reserve if reserve is not None else cls.RESERVE_TOKENS
        max_code_tokens = cls.MAX_CONTEXT_TOKENS - reserve - 500  # 500 for prompt overhead
        max_chars = int(max_code_tokens * cls.TOKEN_CHAR_RATIO)
        if len(code) <= max_chars:
            return code
        truncated = code[:max_chars]
        last_nl = truncated.rfind('\n')
        if last_nl > max_chars * 0.8:
            truncated = truncated[:last_nl]
        truncated += f"\n# ... (代码已截断，原始约 {cls.estimate_tokens(code)} tokens)"
        return truncated

    # ================================================================
    # 结果缓存（OrderedDict LRU）
    # ================================================================

    @staticmethod
    def _cache_key(code: str, model: str, mode: str, question: str = '') -> str:
        """生成缓存键"""
        raw = f"{model}|{mode}|{question}|{code}"
        return hashlib.md5(raw.encode('utf-8')).hexdigest()

    @classmethod
    def _cache_get(cls, key: str) -> Optional[str]:
        with cls._cache_lock:
            if key not in cls._result_cache:
                return None
            # 移到末尾（最近使用）
            cls._result_cache.move_to_end(key)
            return cls._result_cache[key]

    @classmethod
    def _cache_set(cls, key: str, value: str):
        with cls._cache_lock:
            if key in cls._result_cache:
                cls._result_cache.move_to_end(key)
            cls._result_cache[key] = value
            while len(cls._result_cache) > cls._CACHE_MAX_SIZE:
                # 弹出最旧的条目（LRU）
                cls._result_cache.popitem(last=False)

    @classmethod
    def clear_cache(cls):
        """清空结果缓存"""
        with cls._cache_lock:
            cls._result_cache.clear()

    # ================================================================
    # 代码去重
    # ================================================================

    @staticmethod
    def deduplicate_snippets(snippets: List[Dict]) -> Tuple[List[Dict], int]:
        """去除高度相似的代码片段

        通过代码指纹（关键特征提取）判断相似性，
        相似的片段只保留相关度最高的一个。

        Returns:
            (deduplicated_list, removed_count)
        """
        if len(snippets) <= 1:
            return snippets, 0

        def _fingerprint(code: str) -> str:
            """提取代码指纹：去掉行号、空白行、注释行，归一化后取关键特征"""
            lines = code.split('\n')
            sig_lines = []
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # 去掉行首行号（smali 格式）
                line = re.sub(r'^\d+\s+', '', line)
                # 归一化：去掉连续空白
                line = re.sub(r'\s+', ' ', line)
                sig_lines.append(line)
            # 用前 80 行特征做指纹（覆盖更大的方法体）
            joined = '\n'.join(sig_lines[:80])
            return hashlib.md5(joined.encode('utf-8')).hexdigest()

        seen: Dict[str, int] = {}
        result: List[Dict] = []
        removed = 0
        for snip in snippets:
            fp = _fingerprint(snip.get('code', ''))
            if fp in seen:
                existing_idx = seen[fp]
                if snip.get('score', 0) > result[existing_idx].get('score', 0):
                    result[existing_idx] = snip
                removed += 1
            else:
                seen[fp] = len(result)
                result.append(snip)

        return result, removed

    # ================================================================
    # 系统提示词
    # ================================================================

    SYSTEM_PROMPT = (
        "你是一个专业的安卓逆向工程与广告识别分析专家。"
        "你精通 Smali 字节码、Java 反编译、XML 布局和 JavaScript 代码的分析。"
        "你的任务是精准识别 APK 中的广告 SDK 集成、广告接口调用、广告加载流程和潜在屏蔽点。\n\n"
        "分析原则：\n"
        "1. 精确性：准确指出广告 SDK 名称、版本、类名和方法名\n"
        "2. 结构化：使用清晰的标题和列表组织分析结果\n"
        "3. 实用性：提供可操作的建议（如屏蔽点、修改方案）\n"
        "4. 简洁性：避免冗余描述，直击要点\n"
        "5. 完整性：覆盖广告加载→展示→点击→关闭的完整链路"
    )

    SYSTEM_PROMPT_THINKING = (
        "你是一个专业的安卓逆向工程与广告识别分析专家。\n"
        "请先深入思考代码逻辑，然后给出结构化的广告分析报告。\n"
        "思考时关注：方法调用链、广告 SDK 初始化流程、广告位配置、回调机制。\n"
        "最终输出必须包含：SDK 标识、关键代码位置、广告流程、屏蔽建议。"
    )

    def _get_system_prompt(self, model: str) -> str:
        """根据模型类型选择系统提示词"""
        if self.is_thinking_model(model):
            return self.SYSTEM_PROMPT_THINKING
        return self.SYSTEM_PROMPT

    # ================================================================
    # 提示词构建
    # ================================================================

    def build_direct_prompt(self, code: str, source_language: str,
                            options: Optional[Dict] = None) -> str:
        """构建直连分析模式的提示词"""
        opts = options or {}
        lang_display = self.LANG_DISPLAY.get(source_language, source_language)

        template_hints = ''
        try:
            from apk_reverse_engine.knowledge.ad_templates import get_common_keywords
            common_kws = get_common_keywords()
            if common_kws:
                template_hints = f"\n### 参考广告关键词库\n{', '.join(common_kws[:30])}\n"
        except Exception as e:
            logger.debug("apk_reverse_engine/analysis/ad_ai_engine.py:500 suppressed: %s", e)
            logger.debug(f"e")

        safe_code = self.truncate_to_token_limit(code)

        prompt = []
        prompt.append(f"## 任务\n分析以下{lang_display}中的广告相关接口和实现方式\n")

        lang_tag = source_language if source_language != 'javascript' else 'javascript'
        if source_language == 'xml':
            lang_tag = 'xml'
        prompt.append(f"### 代码\n```{lang_tag}\n{safe_code}\n```\n")

        if template_hints:
            prompt.append(template_hints)

        prompt.append("## 分析要求")
        prompt.append("请按以下结构输出分析报告：\n")
        prompt.append("### 1. SDK 识别")
        prompt.append("   - 识别到的广告 SDK（如 AdMob/Facebook/Unity/腾讯/字节跳动等）")
        prompt.append("   - SDK 版本信息（如可从代码推断）")
        prompt.append("### 2. 关键接口")
        prompt.append("   - 广告加载方法（loadAd/fetchAd 等）")
        prompt.append("   - 广告展示方法（showAd/present 等）")
        prompt.append("   - 广告回调接口（onAdLoaded/onAdFailed 等）")
        prompt.append("### 3. 广告配置")
        prompt.append("   - 广告位 ID / Placement ID")
        prompt.append("   - 广告类型（横幅/插屏/激励/原生）")
        prompt.append("### 4. 广告流程")
        prompt.append("   - 加载→展示→点击→关闭 完整链路")
        prompt.append("### 5. 网络请求")
        prompt.append("   - 广告数据请求 URL / API 端点")
        prompt.append("   - 请求参数和响应处理")

        idx = 6
        if opts.get('show_ad_blocking_suggestions', True):
            prompt.append(f"### {idx}. 屏蔽方案")
            prompt.append("   - 可屏蔽的代码位置（类名+方法名）")
            prompt.append("   - 具体修改建议（如空实现/返回值修改）")
            idx += 1

        prompt.append(f"\n### SDK 检测范围")

        sdk_list = []
        if opts.get('enable_admob_detection', True):
            sdk_list.append("- **Google AdMob**: AdView, InterstitialAd, RewardedVideoAd, AdRequest, MobileAds, AdLoader, Adapter")
        if opts.get('enable_fan_detection', True):
            sdk_list.append("- **Facebook Audience Network**: AdView, InterstitialAd, NativeAd, AdSettings, AudienceNetwork")
        if opts.get('enable_unity_ads_detection', True):
            sdk_list.append("- **Unity Ads**: Advertisement, IUnityAdsListener, IUnityAdsShowListener, ShowOptions")
        if opts.get('enable_tencent_ads_detection', True):
            sdk_list.append("- **腾讯广告**: TTAdSdk, TTAdNative, TTAdManager, TTAdDislike, CSJAdManager")
        if opts.get('enable_bytedance_ads_detection', True):
            sdk_list.append("- **字节跳动/穿山甲**: BUAdSDK, TTRewardVideoAd, TTFeedAd, TTInterstitialAd, PAGAdSdk")
        sdk_list.append("- **AppLovin**: AppLovinSdk, AdView, InterstitialAd, RewardedAd")
        sdk_list.append("- **Mintegral**: MintegralAdSdk, MBridgeNativeAd, MBridgeRewardVideoAd")
        sdk_list.append("- **Vungle**: VungleNativeAd, VungleBannerAd, VungleInterstitialAd")
        sdk_list.append("- **AdColony**: AdColony, AdColonyAdListener, AdColonyInterstitial")
        sdk_list.append("- **IronSource**: IronSource, ISRewardedVideo, ISInterstitial, ISBanner")
        prompt.extend(sdk_list)

        custom_kw = opts.get('custom_ad_keywords', '')
        if custom_kw:
            prompt.append(f"- **自定义关键词**: {custom_kw}")

        prompt.append("\n### 注意事项")
        prompt.append("- 包含 ad/ads/advertisement/promotion/banner 等关键词的方法")
        prompt.append("- 广告相关的 URL、包名（com.google.ads / com.facebook.ads 等）")
        prompt.append("- 反射调用和动态加载的广告组件")

        if opts.get('show_no_ad_hints', True):
            prompt.append('\n如果代码中没有明显广告接口，请明确说明"未发现广告接口"，并建议可能需要检查的相关代码区域。')
        else:
            prompt.append('\n如果没有发现广告接口，请简明说明"无广告相关代码"。')

        return '\n'.join(prompt)

    def build_supplement_prompt(self, code: str, question: str,
                                source_language: str,
                                options: Optional[Dict] = None) -> str:
        """构建补充问答模式的提示词"""
        opts = options or {}
        lang_display = self.LANG_DISPLAY.get(source_language, source_language)

        safe_code = self.truncate_to_token_limit(code)

        prompt = []
        prompt.append(f"## 任务\n针对以下{lang_display}回答广告识别相关问题\n")

        lang_tag = source_language
        if source_language == 'xml':
            lang_tag = 'xml'
        elif source_language == 'javascript':
            lang_tag = 'javascript'

        prompt.append(f"### 代码\n```{lang_tag}\n{safe_code}\n```\n")

        if question:
            prompt.append(f"### 问题\n{question}\n")

        prompt.append("## 回答要求")
        prompt.append("请按以下结构输出：\n")
        prompt.append("### 1. SDK 集成方式")
        prompt.append("   - 集成的广告 SDK 及版本")
        prompt.append("### 2. 广告流程")
        prompt.append("   - 请求→加载→展示→回调 完整链路")
        prompt.append("### 3. 关键参数")
        prompt.append("   - 广告位 ID、请求参数、配置项")
        prompt.append("### 4. 回调处理")
        prompt.append("   - 广告事件监听和回调方法")

        idx = 5
        if opts.get('show_ad_blocking_suggestions', True):
            prompt.append(f"### {idx}. 屏蔽方案")
            prompt.append("   - 具体屏蔽位置和修改方案")
            idx += 1

        prompt.append("\n### 具体指出")
        prompt.append("- 负责广告加载和展示的类与方法")
        prompt.append("- 控制广告内容和行为的参数")
        prompt.append("- 与广告相关的网络请求 URL")

        if opts.get('show_ad_blocking_suggestions', True):
            prompt.append("- 可能的广告屏蔽点和代码修改方案")

        if opts.get('show_no_ad_hints', True):
            prompt.append("- 如果没有广告接口，请建议需要检查的其他代码区域")
        else:
            prompt.append("- 如果没有广告接口，请简明说明")

        return '\n'.join(prompt)

    # ================================================================
    # API 调用
    # ================================================================

    def analyze(self, code: str, source_language: str = "smali",
                model: str = "Qwen/Qwen2.5-7B-Instruct",
                question: str = "",
                question_mode: str = "direct",
                options: Optional[Dict] = None,
                use_cache: bool = True,
                allow_fallback: bool = True) -> str:
        """执行 AI 广告分析（带缓存、自动重试、速率限制和备用模型）

        Args:
            code: 待分析的代码片段
            source_language: 源语言 (smali/java/xml/javascript)
            model: 模型ID
            question: 补充模式下的问题
            question_mode: 提问模式 ('direct' 或 'supplement')
            options: 可选配置字典
            use_cache: 是否使用结果缓存
            allow_fallback: 主模型失败后是否尝试备用模型

        Returns:
            AI 分析结果文本

        Raises:
            RuntimeError: API 未配置或所有模型均失败
        """
        if not self.is_configured():
            raise RuntimeError("请先配置 API 密钥 (api_key)")

        # 检查缓存
        cache_key = self._cache_key(code, model, question_mode, question)
        if use_cache:
            cached = self._cache_get(cache_key)
            if cached is not None:
                return cached

        # 熔断检查
        if not self._check_circuit():
            raise RuntimeError(f"熔断保护已触发（连续失败 {self._consecutive_failures} 次），"
                               f"请等待 {self.CIRCUIT_BREAK_COOLDOWN} 秒后重试")

        # 构建提示词
        if question_mode == "supplement":
            content = self.build_supplement_prompt(code, question, source_language, options)
        else:
            content = self.build_direct_prompt(code, source_language, options)

        # 构建模型链：主模型 + 备用模型
        model_chain = [model]
        if allow_fallback:
            for fb in self.FALLBACK_CHAIN:
                if fb not in model_chain:
                    model_chain.append(fb)

        last_error = None
        for try_model in model_chain:
            try:
                result = self._analyze_with_model(content, try_model)
                self._record_success()
                if use_cache:
                    self._cache_set(cache_key, result)
                return result
            except RuntimeError as e:
                last_error = e
                err_msg = str(e)
                is_client_error = any(code in err_msg for code in ['400', '401', '403', '404'])
                is_rate_limit = '429' in err_msg
                if is_client_error and not is_rate_limit:
                    # 客户端错误（认证/权限），不重试其他模型
                    self._record_failure()
                    raise
                # 服务端/限流/超时错误，记录并尝试下一模型
                self._record_failure()
                continue

        raise RuntimeError(f"所有模型均失败（最后错误: {last_error}）")

    def _analyze_with_model(self, content: str, model: str) -> str:
        """使用指定模型执行分析（带重试、指数退避）"""
        system_prompt = self._get_system_prompt(model)
        body = self._build_request_body(model, content, system_prompt)
        timeout = 180 if self.is_thinking_model(model) else 60

        last_error = None
        for attempt in range(1, self.MAX_RETRIES + 1):
            self._wait_rate_limit()

            try:
                resp_data = self._call_api(body, timeout)
                return self._parse_response(resp_data, model)
            except RuntimeError as e:
                last_error = e
                err_msg = str(e)
                should_retry = ('429' in err_msg or '500' in err_msg or
                                '502' in err_msg or '503' in err_msg or
                                'timeout' in err_msg.lower() or
                                'timed out' in err_msg.lower())
                if not should_retry or attempt == self.MAX_RETRIES:
                    raise
                # 指数退避
                wait = self.RETRY_DELAY * (self.RETRY_BACKOFF ** (attempt - 1))
                time.sleep(wait)

        raise RuntimeError(f"AI分析失败（重试 {self.MAX_RETRIES} 次后）: {last_error}")

    @classmethod
    def _wait_rate_limit(cls):
        """速率限制：确保请求间隔不小于 MIN_REQUEST_INTERVAL

        线程安全设计：在锁内计算等待时间，在锁外执行 sleep，
        避免持锁等待阻塞其他线程。
        """
        if not cls._rate_limit_enabled or cls.MIN_REQUEST_INTERVAL <= 0:
            return
        with cls._rate_lock:
            now = time.time()
            elapsed = now - cls._last_request_time
            wait_time = max(0, cls.MIN_REQUEST_INTERVAL - elapsed)
            if wait_time > 0:
                cls._last_request_time = now + wait_time  # 预约下一次时间
            else:
                cls._last_request_time = now
        # 在锁外 sleep，不阻塞其他线程获取锁
        if wait_time > 0:
            time.sleep(wait_time)

    @classmethod
    def set_rate_limit(cls, enabled: bool):
        """全局开关：启用/禁用速率限制"""
        cls._rate_limit_enabled = enabled

    def analyze_stream(self, code: str, source_language: str = "smali",
                       model: str = "Qwen/Qwen2.5-7B-Instruct",
                       question: str = "",
                       question_mode: str = "direct",
                       options: Optional[Dict] = None,
                       use_cache: bool = False) -> Iterator[str]:
        """流式 AI 广告分析 - 逐步返回分析结果"""
        if not self.is_configured():
            raise RuntimeError("请先配置 API 密钥 (api_key)")
            return  # type: ignore[unreachable]

        if use_cache:
            cache_key = self._cache_key(code, model, question_mode, question)
            cached = self._cache_get(cache_key)
            if cached is not None:
                chunk_size = 200
                for i in range(0, len(cached), chunk_size):
                    yield cached[i:i+chunk_size]
                return

        # 熔断检查
        if not self._check_circuit():
            raise RuntimeError(f"熔断保护已触发（连续失败 {self._consecutive_failures} 次），"
                               f"请等待 {self.CIRCUIT_BREAK_COOLDOWN} 秒后重试")

        if question_mode == "supplement":
            content = self.build_supplement_prompt(code, question, source_language, options)
        else:
            content = self.build_direct_prompt(code, source_language, options)

        system_prompt = self._get_system_prompt(model)
        body_dict = self._build_request_body(model, content, system_prompt)
        body_dict['stream'] = True
        body = json.dumps(body_dict, ensure_ascii=False)

        timeout = 300 if self.is_thinking_model(model) else 120
        self._wait_rate_limit()

        data = body.encode('utf-8')
        req = urllib.request.Request(
            self.api_url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        full_result = []
        finish_reason = None
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                buffer = b''
                for chunk in iter(lambda: resp.read(1024), b''):
                    buffer += chunk
                    # SSE 规范支持 \n 和 \r\n 行分隔
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        line = line.rstrip(b'\r').strip()
                        if not line:
                            continue
                        if self._RE_SSE_DONE.match(line.decode('utf-8', errors='replace')):
                            continue
                        if line.startswith(b'data: '):
                            line = line[6:]
                        elif line.startswith(b'data:'):
                            line = line[5:]
                        else:
                            continue
                        try:
                            obj = json.loads(line.decode('utf-8'))
                            choice = obj.get('choices', [{}])[0]
                            delta = choice.get('delta', {})
                            content_piece = delta.get('content', '')
                            if content_piece:
                                full_result.append(content_piece)
                                yield content_piece
                            # 检测 finish_reason
                            fr = choice.get('finish_reason')
                            if fr:
                                finish_reason = fr
                        except (json.JSONDecodeError, IndexError, KeyError):
                            continue
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8', errors='replace')
            raise RuntimeError(f"API请求失败: {e.code} {e.reason} - {err_body}") from e
        except urllib.error.URLError as e:
            reason = str(e.reason)
            if 'timeout' in reason.lower() or 'timed out' in reason.lower():
                raise RuntimeError(f"请求超时: {reason}") from e
            raise RuntimeError(f"网络请求失败: {reason}") from e

        if full_result:
            self._record_success()
        else:
            self._record_failure()
            raise RuntimeError("流式响应为空，未收到任何内容")

        # 截断检测
        if finish_reason == 'length':
            yield "\n\n⚠️ **[AI 响应被截断 (finish_reason=length)，建议增大 max_tokens 或缩短代码]**"

        if use_cache and full_result:
            cache_key = self._cache_key(code, model, question_mode, question)
            self._cache_set(cache_key, ''.join(full_result))

    # ================================================================
    # 知识库联动 — 将 AI 分析结果持久化到 KnowledgeBase
    # ================================================================

    def save_analysis_to_kb(self, kb, code: str, analysis: str,
                            class_name: str = '', method_name: str = '',
                            model: str = '', score: int = 0):
        """将 AI 广告分析结果保存到知识库，供后续会话复用

        Args:
            kb: KnowledgeBase 实例
            code: 原始代码片段
            analysis: AI 分析结果文本
            class_name: 类名
            method_name: 方法名
            model: 使用的模型
            score: 预筛选分数

        Returns:
            创建的知识条目
        """
        code_hash = hashlib.md5(code.encode('utf-8')).hexdigest()[:12]
        name = f"ad_analysis:{class_name}:{method_name}:{code_hash}"
        return kb.add(
            category='custom',
            name=name,
            patterns=[code_hash, f"{class_name}:{method_name}"],
            desc=analysis[:500],  # 知识库描述字段截断
            meta={
                'class': class_name,
                'method': method_name,
                'model': model,
                'score': score,
                'code_hash': code_hash,
                'full_analysis': analysis,
                'saved_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            },
        )

    def load_analysis_from_kb(self, kb, code: str,
                              class_name: str = '', method_name: str = '') -> Optional[str]:
        """从知识库查找已保存的 AI 分析结果

        Args:
            kb: KnowledgeBase 实例
            code: 原始代码片段
            class_name: 类名
            method_name: 方法名

        Returns:
            分析结果文本，未找到返回 None
        """
        code_hash = hashlib.md5(code.encode('utf-8')).hexdigest()[:12]
        results = kb.query(category='custom', keyword=code_hash)
        for r in results:
            if r.get('meta', {}).get('code_hash') == code_hash:
                return r.get('meta', {}).get('full_analysis') or r.get('desc', '')
        # 退化搜索：只匹配类名+方法名
        if class_name and method_name:
            results = kb.query(category='custom', keyword=f"{class_name}:{method_name}")
            for r in results:
                if r.get('meta', {}).get('class') == class_name:
                    return r.get('meta', {}).get('full_analysis') or r.get('desc', '')
        return None

    # ================================================================
    # 预筛选
    # ================================================================

    @classmethod
    def prefilter_ad_code(cls, code: str, class_name: str = '', method_name: str = '',
                          custom_keywords: str = '') -> Tuple[bool, int]:
        """智能预筛选：判断代码片段是否包含广告相关内容

        使用多维度匹配策略（三级评分）进行快速预筛

        Returns:
            (is_ad_related, score): 是否广告相关, 相关度分数
        """
        combined = f"{class_name} {method_name} {code}".lower()
        score = 0

        # Tier 1: 精确 SDK 包名/类名匹配（高分）
        for pattern in cls._RE_SDK_PACKAGES:
            if pattern.search(combined):
                score += 15

        # Tier 2: 广告 API 方法名匹配（中高分）
        for pattern in cls._RE_AD_API:
            matches = pattern.findall(combined)
            score += len(matches) * 3

        # Tier 3: 通用广告关键词（低分补充）
        general_ad_kw = ['advert', 'banner', 'interstitial',
                        'reward', 'promot', 'splash', 'sponsor']
        for kw in general_ad_kw:
            count = combined.count(kw)
            if count > 0:
                score += count

        # 'ad' 作为独立词匹配（严格判断避免误判）
        name_combined = f"{class_name} {method_name}".lower()
        if cls._RE_AD_WORD.search(name_combined):
            score += 5
        code_ad_count = len(cls._RE_AD_WORD.findall(combined))
        if code_ad_count > 0:
            score += min(code_ad_count, 3)

        if custom_keywords:
            for kw in custom_keywords.split(','):
                kw = kw.strip().lower()
                if kw and kw in combined:
                    score += 5

        for kw in ['ad', 'ads', 'advert', 'banner', 'interstitial', 'reward', 'promot']:
            if kw in name_combined:
                score += 3

        return (score > 0, score)

    # ================================================================
    # 请求构建与发送
    # ================================================================

    def _build_request_body(self, model: str, content: str,
                            system_prompt: str = "") -> dict:
        """构建 API 请求 dict（含系统提示词）

        Returns:
            可直接 json.dumps 的 dict（调用方可追加字段如 stream=True）
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": content})

        body = {
            "model": model,
            "messages": messages,
        }

        if self.is_thinking_model(model):
            body.update({
                "temperature": 0.7,
                "max_tokens": 6000,
                "top_p": 0.95,
                "stream": False,
            })
        elif 'deepseek' in model:
            body.update({
                "temperature": 0.1,
                "max_tokens": 4000,
                "top_p": 0.9,
            })
        elif 'Coder' in model:
            body.update({
                "temperature": 0.1,
                "max_tokens": 5000,
                "top_p": 0.8,
            })
        elif 'glm-4' in model:
            body.update({
                "temperature": 0.3,
                "max_tokens": 3000,
                "top_p": 0.9,
            })
        else:
            body.update({
                "temperature": 0.3,
                "max_tokens": 3000,
                "top_p": 0.85,
            })

        return body

    def _call_api(self, body: dict, timeout: int = 45) -> dict:
        """发送 API 请求并返回解析后的 JSON（复用连接池）

        Args:
            body: 请求体 dict（会被 json.dumps）
            timeout: 超时秒数
        """
        data = json.dumps(body, ensure_ascii=False).encode('utf-8')
        req = urllib.request.Request(
            self.api_url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with self._opener.open(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8', errors='replace')
            raise RuntimeError(f"API请求失败: {e.code} {e.reason} - {err_body}") from e
        except urllib.error.URLError as e:
            reason = str(e.reason)
            if 'timeout' in reason.lower() or 'timed out' in reason.lower():
                raise RuntimeError(f"请求超时: {reason}") from e
            raise RuntimeError(f"网络请求失败: {reason}") from e
        except Exception as e:
            if 'timeout' in str(e).lower() or 'timed out' in str(e).lower():
                raise RuntimeError(f"请求超时: {e}") from e
            raise RuntimeError(f"请求异常: {e}") from e

    # ================================================================
    # 响应解析
    # ================================================================

    def _parse_response(self, response: dict, model: str) -> str:
        """解析 AI 响应"""
        choices = response.get('choices', [])
        if not choices:
            raise RuntimeError("无法解析AI响应: 无 choices")

        choice = choices[0]
        content = None

        if 'message' in choice:
            content = choice['message'].get('content', '')
        elif 'text' in choice:
            content = choice.get('text', '')

        if not content:
            finish_reason = choice.get('finish_reason', '')
            if finish_reason == 'length':
                raise RuntimeError("AI响应被截断(max_tokens不足)")
            raise RuntimeError("无法解析AI响应: 无内容")

        # 截断警告
        if choice.get('finish_reason') == 'length':
            content += "\n\n⚠️ **[AI 响应被截断 (finish_reason=length)，建议增大 max_tokens 或缩短代码]**"

        if self.is_thinking_model(model):
            return self._parse_thinking_response(content)
        return content

    @classmethod
    def _parse_thinking_response(cls, content: str) -> str:
        """解析思考模型的响应（格式化输出）"""
        has_thinking = bool(cls._RE_THINKING_TAG.search(content))

        if not has_thinking:
            return "【思考模式分析结果】\n\n" + content

        result = ["【思考模式分析结果】\n"]

        parts = cls._RE_THINKING_SPLIT.split(content)

        if len(parts) > 1:
            in_thinking = False
            in_answer = False
            for part in parts:
                if '<thinking>' in part or '思考过程' in part or '思考' in part:
                    in_thinking = True
                    in_answer = False
                    result.append("### 思考过程\n")
                elif '</thinking>' in part:
                    in_thinking = False
                    result.append("\n")
                elif '最终答案' in part or '结论' in part:
                    in_answer = True
                    in_thinking = False
                    result.append("### 分析结果\n")

                if in_thinking or in_answer:
                    cleaned = part.strip()
                    cleaned = cls._RE_THINKING_CLEAN.sub('', cleaned).strip()
                    if cleaned:
                        result.append(cleaned + "\n")
        else:
            result.append(content)

        return '\n'.join(result)

    # ================================================================
    # 并发批量分析
    # ================================================================

    def analyze_batch(self, snippets: List[Dict], source_language: str = "smali",
                      model: str = "Qwen/Qwen2.5-7B-Instruct",
                      question: str = "",
                      question_mode: str = "direct",
                      options: Optional[Dict] = None,
                      max_workers: int = 0,
                      on_complete: Optional[Callable[[int, Dict], None]] = None,
                      on_stream: Optional[Callable[[int, str], None]] = None,
                      use_cache: bool = True,
                      dedup: bool = True) -> List[Dict]:
        """并发批量分析多个代码片段

        最多同时发起 MAX_CONCURRENT（默认5）个 AI 分析请求。
        自动去重相似片段、使用结果缓存、失败自动切换备用模型。

        Args:
            snippets: 代码片段列表
            source_language: 源语言
            model: 模型ID
            question: 补充问题
            question_mode: 'direct' 或 'supplement'
            options: 可选配置
            max_workers: 并发数（0=自动使用 MAX_CONCURRENT）
            on_complete: 回调 fn(index, result_dict)
            on_stream: 回调 fn(index, text_chunk)
            use_cache: 是否使用结果缓存
            dedup: 是否自动去重相似片段

        Returns:
            结果列表，顺序与输入一致
        """
        if dedup:
            snippets, _ = self.deduplicate_snippets(snippets)

        n = len(snippets)
        if n == 0:
            return []
        workers = max_workers if max_workers > 0 else self.MAX_CONCURRENT
        workers = min(workers, n)

        results: List[Optional[Dict]] = [None] * n

        def _analyze_one(idx: int, snippet: Dict) -> Dict:
            result = {
                'class': snippet.get('class', ''),
                'method': snippet.get('method', ''),
                'score': snippet.get('score', 0),
            }
            try:
                if on_stream:
                    full = []
                    for chunk in self.analyze_stream(
                        code=snippet['code'],
                        source_language=source_language,
                        model=model,
                        question=question,
                        question_mode=question_mode,
                        options=options,
                        use_cache=use_cache,
                    ):
                        full.append(chunk)
                        try:
                            on_stream(idx, chunk)
                        except Exception as e:
                            logger.debug("apk_reverse_engine/analysis/ad_ai_engine.py:1219 suppressed: %s", e)
                            logger.debug(f"e")
                    result['analysis'] = ''.join(full)
                else:
                    result['analysis'] = self.analyze(
                        code=snippet['code'],
                        source_language=source_language,
                        model=model,
                        question=question,
                        question_mode=question_mode,
                        options=options,
                        use_cache=use_cache,
                    )
            except RuntimeError as e:
                result['error'] = str(e)
            except Exception as e:
                result['error'] = f"未预期错误: {e}"
            return result

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="AdAI") as executor:
            future_map = {
                executor.submit(_analyze_one, i, snip): i
                for i, snip in enumerate(snippets)
            }
            for future in as_completed(future_map):
                idx = future_map[future]
                try:
                    result = future.result()
                except Exception as e:
                    result = {
                        'class': snippets[idx].get('class', ''),
                        'method': snippets[idx].get('method', ''),
                        'score': snippets[idx].get('score', 0),
                        'error': str(e),
                    }
                results[idx] = result
                if on_complete:
                    try:
                        on_complete(idx, result)
                    except Exception as e:
                        logger.debug("apk_reverse_engine/analysis/ad_ai_engine.py:1258 suppressed: %s", e)
                        logger.debug(f"e")

        return results  # type: ignore[return-value]

    def analyze_stream_batch(self, snippets: List[Dict], source_language: str = "smali",
                             model: str = "Qwen/Qwen2.5-7B-Instruct",
                             question: str = "",
                             question_mode: str = "direct",
                             options: Optional[Dict] = None,
                             max_workers: int = 0,
                             use_cache: bool = False,
                             dedup: bool = True) -> Iterator[Tuple[int, str]]:
        """并发流式批量分析 - 逐步 yield (index, text_chunk)"""
        if dedup:
            snippets, _ = self.deduplicate_snippets(snippets)

        n = len(snippets)
        if n == 0:
            return
        workers = max_workers if max_workers > 0 else self.MAX_CONCURRENT
        workers = min(workers, n)

        chunk_queue: queue.Queue = queue.Queue()
        SENTINEL = None

        def _stream_one(idx: int, snippet: Dict):
            try:
                for chunk in self.analyze_stream(
                    code=snippet['code'],
                    source_language=source_language,
                    model=model,
                    question=question,
                    question_mode=question_mode,
                    options=options,
                    use_cache=use_cache,
                ):
                    chunk_queue.put((idx, chunk))
            except RuntimeError as e:
                chunk_queue.put((idx, f"\n[ERROR] {e}\n"))
            except Exception as e:
                chunk_queue.put((idx, f"\n[ERROR] 未预期错误: {e}\n"))
            finally:
                chunk_queue.put((idx, SENTINEL))

        executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="AdAI-Stream")
        try:
            for i, snip in enumerate(snippets):
                executor.submit(_stream_one, i, snip)

            completed_count = 0
            while completed_count < n:
                idx, chunk = chunk_queue.get()
                if chunk is SENTINEL:
                    completed_count += 1
                    continue
                yield (idx, chunk)
        finally:
            # 确保消费者停止迭代时线程池也能被清理
            executor.shutdown(wait=False, cancel_futures=True)


# ── 快捷函数 ──────────────────────────────────────────────────

def analyze_ad_code(code: str, api_key: str, model: str = "Qwen/Qwen2.5-7B-Instruct",
                    source_language: str = "smali", question: str = "",
                    question_mode: str = "direct", api_url: str = "",
                    options: Optional[Dict] = None) -> str:
    """一键 AI 广告分析（带缓存、自动重试、速率限制和备用模型）"""
    engine = AdAIEngine(api_key=api_key, api_url=api_url)
    return engine.analyze(code, source_language, model, question, question_mode, options)


def analyze_ad_code_stream(code: str, api_key: str, model: str = "Qwen/Qwen2.5-7B-Instruct",
                           source_language: str = "smali", question: str = "",
                           question_mode: str = "direct", api_url: str = "",
                           options: Optional[Dict] = None) -> Iterator[str]:
    """流式 AI 广告分析 - 逐步返回结果"""
    engine = AdAIEngine(api_key=api_key, api_url=api_url)
    yield from engine.analyze_stream(code, source_language, model, question, question_mode, options)


def prefilter_ad_code(code: str, class_name: str = '', method_name: str = '',
                      custom_keywords: str = '') -> Tuple[bool, int]:
    """智能预筛选代码片段是否包含广告相关内容"""
    return AdAIEngine.prefilter_ad_code(code, class_name, method_name, custom_keywords)


def list_ai_models(api_key: str, api_url: str = "") -> List[str]:
    """获取可用 AI 模型列表"""
    return AdAIEngine.fetch_available_models(api_key, api_url) or list(AdAIEngine.FALLBACK_MODELS)


def analyze_ad_code_batch(snippets: List[Dict], api_key: str,
                          model: str = "Qwen/Qwen2.5-7B-Instruct",
                          source_language: str = "smali",
                          question: str = "",
                          question_mode: str = "direct",
                          api_url: str = "",
                          options: Optional[Dict] = None,
                          max_workers: int = 0,
                          on_complete: Optional[Callable[[int, Dict], None]] = None,
                          on_stream: Optional[Callable[[int, str], None]] = None) -> List[Dict]:
    """并发批量 AI 广告分析（最多5路同时输出）

    自动去重相似片段、使用结果缓存、失败自动切换备用模型。
    """
    engine = AdAIEngine(api_key=api_key, api_url=api_url)
    return engine.analyze_batch(snippets, source_language, model, question,
                                question_mode, options, max_workers, on_complete, on_stream)


def analyze_ad_code_stream_batch(snippets: List[Dict], api_key: str,
                                 model: str = "Qwen/Qwen2.5-7B-Instruct",
                                 source_language: str = "smali",
                                 question: str = "",
                                 question_mode: str = "direct",
                                 api_url: str = "",
                                 options: Optional[Dict] = None,
                                 max_workers: int = 0) -> Iterator[Tuple[int, str]]:
    """并发流式批量 AI 广告分析 - 逐步 yield (index, text_chunk)"""
    engine = AdAIEngine(api_key=api_key, api_url=api_url)
    yield from engine.analyze_stream_batch(snippets, source_language, model,
                                           question, question_mode, options, max_workers)
