"""广告移除模块 - 多SDK广告移除 + 正则通杀 + VIP解锁 + assets清理 + manifest清理

支持:
  - 100+ 广告SDK包名检测与定向移除（腾讯/快手/穿山甲/百度/Sigmob/谷歌/米盟等）
  - 9组正则通杀
  - VIP/Pro/Premium 方法强制返回 true（180+ 方法名模式）
  - 广告URL替换（150+ 域名模式）
  - assets清理 + manifest清理
  - 外部JSON配置文件支持

工作流程: 解码APK → 补丁smali → VIP解锁 → 清理assets → 清理manifest → 重打包签名
"""

import os
import re
import json
import glob
from typing import Optional, List, Dict, Tuple

from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)


class AdRemover:
    """APK广告移除引擎"""

    # ============================================================
    # 外部配置加载
    # ============================================================
    _CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'ad_patterns.json')
    _config_cache: Optional[dict] = None

    @classmethod
    def _load_config(cls) -> dict:
        """从 ad_patterns.json 加载配置，失败时使用内置默认"""
        if cls._config_cache is not None:
            return cls._config_cache
        try:
            with open(cls._CONFIG_PATH, 'r', encoding='utf-8') as f:
                cls._config_cache = json.load(f)
                logger.info(f"加载广告模式配置: {cls._CONFIG_PATH}")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"配置加载失败，使用内置默认: {e}")
            cls._config_cache = {}
        return cls._config_cache

    # ============================================================
    # SDK 配置 (内置核心SDK，外部配置提供扩展包名)
    # ============================================================
    AD_SDKS = {
        'tencent':   {'name': '腾讯广告',   'icon': '🐧', 'packages': ['com/qq/e', 'com/gdt/ad', 'com/tencent/qqads']},
        'kuaishou':  {'name': '快手广告',   'icon': '🎬', 'packages': ['com/kwad', 'com/kuaishou/ad', 'com/kuaishou/sdk/ad']},
        'pangle':    {'name': '穿山甲广告', 'icon': '🐜', 'packages': ['com/bytedance/pangle', 'com/bytedance/sdk/openadsdk', 'com/pangle/ads']},
        'baidu':     {'name': '百度广告',   'icon': '🔍', 'packages': ['com/bd', 'com/baidu/mobads', 'com/baidu/mobad', 'com/baidu/mobstat']},
        'toutiao':   {'name': '头条广告',   'icon': '📰', 'packages': ['toutiao', 'com/bytedance/toutiao', 'com/bytedance/applog']},
        'sigmob':    {'name': 'Sigmob广告', 'icon': '🎯', 'packages': ['sigmob', 'com/sigmob/sdk', 'com/sigmob/ads']},
        'google':    {'name': '谷歌广告',   'icon': '📱', 'packages': ['com/google/android/gms/ads', 'com/google/ads', 'com/google/android/ads', 'com/admob/android/ads']},
        'miads':     {'name': '米盟广告',   'icon': '📲', 'packages': ['com/miui/zeus/mimo', 'com/xiaomi/ad']},
        'unity':     {'name': 'Unity广告',  'icon': '🎮', 'packages': ['com/unity3d/ads', 'com/unity3d/services/ads']},
        'mintegral': {'name': 'Mintegral',  'icon': '🌐', 'packages': ['com/mintegral/msdk', 'com/mobvista/msdk', 'com/mobvista/ads']},
        'vungle':    {'name': 'Vungle',    'icon': '🎥', 'packages': ['com/vungle/warren', 'com/vungle/ads']},
        'chartboost': {'name': 'Chartboost', 'icon': '📊', 'packages': ['com/chartboost/sdk', 'com/chartboost/mediationsdk']},
        'applovin':  {'name': 'AppLovin',  'icon': '💚', 'packages': ['com/applovin/sdk', 'com/applovin/adview']},
        'ironsource': {'name': 'IronSource', 'icon': '⚙️', 'packages': ['com/ironsource/sdk', 'com/ironsource/mediationsdk', 'com/ironsource/adapters']},
        'inmobi':    {'name': 'InMobi',    'icon': '📱', 'packages': ['com/inmobi/ads', 'com/inmobi/sdk']},
        'adcolony':  {'name': 'AdColony',  'icon': '🎯', 'packages': ['com/adcolony/sdk']},
        'facebook':  {'name': 'Facebook广告', 'icon': '📘', 'packages': ['com/facebook/ads', 'com/facebook/ad']},
        'huawei':    {'name': '华为广告',   'icon': '🔴', 'packages': ['com/huawei/hms/ads']},
        'oppo':      {'name': 'OPPO广告',   'icon': '🟢', 'packages': ['com/oppo/ads']},
        'vivo':      {'name': 'vivo广告',   'icon': '🔵', 'packages': ['com/vivo/mobilead']},
        'startapp':  {'name': 'StartApp',  'icon': '🚀', 'packages': ['com/startapp/sdk', 'com/startapp/android/publish/ads']},
        'appnext':   {'name': 'AppNext',   'icon': '➡️', 'packages': ['com/appnext/ads']},
        'smaato':    {'name': 'Smaato',    'icon': '📈', 'packages': ['com/smaato/sdk']},
        'amazon':    {'name': 'Amazon广告', 'icon': '📦', 'packages': ['com/amazon/device/ads']},
        'yandex':    {'name': 'Yandex广告', 'icon': '🔍', 'packages': ['com/yandex/mobile/ads']},
        'mytarget':  {'name': 'myTarget',  'icon': '🎯', 'packages': ['com/my/target/ads', 'com/my/target/core', 'ru/mail/android/mytarget']},
        'anythink':  {'name': 'AnyThink',  'icon': '🧠', 'packages': ['com/anythink/sdk', 'com/anythink/core']},
        'topon':     {'name': 'TopOn',     'icon': '🔝', 'packages': ['com/topon/sdk', 'com/topon/ads']},
        'fyber':     {'name': 'Fyber',     'icon': '💎', 'packages': ['com/fyber/inneractive/sdk', 'com/fyber/ads', 'com/fyber/mobileads']},
        'mbridge':   {'name': 'MBridge',   'icon': '🌉', 'packages': ['com/mbridge/msdk', 'com/mbridge/msdk/out']},
        'bidmachine': {'name': 'BidMachine', 'icon': '🏗️', 'packages': ['io/bidmachine']},
        'pubnative': {'name': 'PubNative', 'icon': '📢', 'packages': ['net/pubnative']},
        'pollfish':  {'name': 'Pollfish',  'icon': '🐟', 'packages': ['com/pollfish']},
    }

    # 需要删除的 assets 文件（前缀/全名匹配）
    AD_ASSET_PATTERNS = [
        'gdt_plugin',
        'bdxadsdk.jar',
        'ksad_common_encrypt_image_png',
        'ksad_idc.json',
        'toutiao_ad',
        'toutiao_adsdk',
        'pangle_adsdk',
        'baidu_ad',
        'baidumobads',
        'admob_adsdk',
        'sigmob_ad',
        'unity_ads',
        'vungle_ad',
        'applovin_ad',
        'ironsource_ad',
        'mintegral_ad',
        'adcolony_ad',
        'chartboost_ad',
        'mbridge_ad',
        'anythink_ad',
        'topon_ad',
        'fyber_ad',
        'bidmachine_ad',
    ]

    # ============================================================
    # 正则通杀模式 (pattern, replacement, description)
    # ============================================================
    REGEX_PATTERNS = [
        # ① loadAd()V → 注入 return-void
        (
            r'(\.method\s+(?:public|private|static)\s+(?!.*(?:abstract|native)).*loadAd\(.*\)V\s*\n\s*\.registers\s+\d+\n)',
            r'\1    return-void\n',
            'loadAd()V 方法注入 return-void'
        ),
        # ② loadAd()Z → 注入 const/4 v0, 0x0 + return v0
        (
            r'(\.method\s+(?:public|private|static)\s+(?!.*(?:abstract|native)).*loadAd\(.*\)Z\s*\n\s*\.registers\s+\d+\n)',
            r'\1    const/4 v0, 0x0\n    return v0\n',
            'loadAd()Z 方法注入 false 返回'
        ),
        # ③ 注释掉 invoke...loadAd() 调用
        (
            r'(invoke[^\n]*loadAd\([^\n]*\)[VZ])',
            r'#\1',
            '注释掉 loadAd 调用'
        ),
        # ④ 注释掉广告相关 invoke 调用
        (
            r'((invoke[^\n]*AdListener\([^\n]*\)V)|(invoke[^\n]*loadAd\([^\n]*\)V)|(invoke[^\n]*gms[^\n]*(?:loadUrl|loadDataWithBaseURL|requestInterstitialAd|showInterstitial|showVideo|showAd|loadData|onAdClicked|onAdLoaded|isLoading|loadAds|AdLoader|AdRequest|AdListener|AdView)[^\n]*V))',
            r'#\1',
            '注释掉广告相关 invoke 调用'
        ),
        # ⑤ 替换广告 URL
        (
            r'"[^"]*(?:61\.145\.124\.238|-ads\.|\.ad\.|\.ads\.|\.analytics\.localytics\.com|\.mobfox\.com|adcolony|admob|admost|adsafeprotected|adservice|adtag|advert|adwhirl|amazon-ads|amobee|analytics|applovin|appnext|appodeal|burstly|cauly|cloudfront|doubleclick|flurry|googleads|googlesyndication|googletagmanager|greystripe|inmobi|inneractive|madnet|millennialmedia|moatads|mopub|pagead|pubnative|smaato|supersonicads|tapjoy|unityads|vungle)[^"]*"',
            '"="',
            '替换广告 URL 为空'
        ),
        # ⑥ 替换 AdMob ID
        (
            r'ca-app-pub-\d{16}/\d{10}',
            r'ca-app-pub-0000000000000000/0000000000',
            '替换 AdMob ID 为零'
        ),
        # ⑦ 替换广告 invoke 为 nop
        (
            r'invoke-[^\n]*\{[^\n]*\},\s*L[^;]+;->(?:loadAd|requestNativeAd|showInterstitial|fetchad|fetchads|onadloaded|requestInterstitialAd|showAd|loadAds|AdRequest|requestBannerAd|loadNextAd|createInterstitialAd|setNativeAd|loadBannerAd|loadNativeAd|loadRewardedAd|loadRewardedInterstitialAd|loadAdViewAd|showInterstitialAd|shownativead|showbannerad|showvideoad|onAdFailedToLoad)\([^\n]*\)V',
            r'nop',
            '替换广告 invoke 为 nop'
        ),
        # ⑧ 特定广告 invoke 模式 → nop
        (
            r'invoke-[^\n]*\{[^\n]*\},\s*Lcom[^;]*;->(?:requestInterstitialAd|loadAds|loadAd|requestBannerAd)\([^\n]*\)V|invoke-[^\n]*\s\{[vp]\d\},\s*Lcom/(?:facebook|google)[^;]*;->show\([^\n]*\)V',
            r'nop',
            '替换特定广告 invoke 为 nop'
        ),
        # ⑨ 清空广告方法体
        (
            r'(\.method[^\n]*(?:loadAd|requestNativeAd|showInterstitial|fetchad|fetchads|onadloaded|requestInterstitialAd|showAd|loadAds|AdRequest|requestBannerAd|loadNextAd|createInterstitialAd|setNativeAd|loadBannerAd|loadNativeAd|loadRewardedAd|loadRewardedInterstitialAd|loadAdViewAd|showInterstitialAd|shownativead|showbannerad|showvideoad|onAdFailedToLoad)\([^\n]*\)V\n\s*\.registers\s+\d+)[\s\S]*?(\.end method)',
            r'\1\n    return-void\n\2',
            '清空广告方法体'
        ),
        # ⑩ 清空广告初始化和展示方法（扩展）
        (
            r'(\.method[^\n]*(?:initAd|initAds|initSdk|destroyAd|pauseAd|resumeAd|showAppOpenAd|loadAppOpenAd|onAdOpened|onAdLeftApplication|onAdDismiss|onRewarded|setAdListener|setAdUnitId|setAdSize|setAdId|getAdPosition|getAdSlot|getAdConfig)\([^\n]*\)V\n\s*\.registers\s+\d+)[\s\S]*?(\.end method)',
            r'\1\n    return-void\n\2',
            '清空广告初始化/回调方法体'
        ),
    ]

    # ============================================================
    # Smali 工具方法
    # ============================================================

    @staticmethod
    def _find_smali_dirs(smali_root: str) -> List[str]:
        """找到所有 smali 目录 (smali, smali_classes2, ...)"""
        dirs = []
        for d in sorted(glob.glob(os.path.join(smali_root, 'smali*'))):
            if os.path.isdir(d):
                dirs.append(d)
        return dirs

    @staticmethod
    def _class_to_path(class_name: str) -> str:
        """类名 → smali 相对路径
        com.qq.e.comm.managers.b.d → com/qq/e/comm/managers/b/d.smali
        Lcom/qq/e/...; → com/qq/e/....smali
        """
        cn = class_name.strip()
        if cn.startswith('L') and cn.endswith(';'):
            cn = cn[1:-1]
        cn = cn.replace('.', '/')
        return cn + '.smali'

    @staticmethod
    def _find_class_file(smali_root: str, class_name: str) -> Optional[str]:
        """在所有 smali 目录中查找类文件"""
        rel_path = AdRemover._class_to_path(class_name)
        for sd in AdRemover._find_smali_dirs(smali_root):
            fp = os.path.join(sd, rel_path)
            if os.path.isfile(fp):
                return fp
        return None

    @staticmethod
    def _iter_smali_files(smali_root: str):
        """遍历所有 smali 文件"""
        for sd in AdRemover._find_smali_dirs(smali_root):
            for root, dirs, files in os.walk(sd):
                for f in files:
                    if f.endswith('.smali'):
                        yield os.path.join(root, f)

    @staticmethod
    def _read_file(path: str) -> str:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()

    @staticmethod
    def _write_file(path: str, content: str):
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

    # ============================================================
    # 方法补丁工具
    # ============================================================

    @staticmethod
    def _get_return_type(method_decl: str) -> str:
        """从方法声明中提取返回类型"""
        m = re.search(r'\)(.+)', method_decl)
        return m.group(1).strip() if m else 'V'

    @staticmethod
    def _build_return_body(ret_type: str, value: str = '0x0',
                           const_type: str = '4', reg: str = 'v0') -> str:
        """根据返回类型构建最小方法体"""
        if ret_type == 'V':
            return f'    .registers 1\n    return-void\n'
        if ret_type == 'J':
            return f'    .registers 2\n    const-wide/{const_type} {reg}, {value}\n    return-wide {reg}\n'
        if ret_type == 'D':
            return f'    .registers 2\n    const-wide/{const_type} {reg}, {value}\n    return-wide {reg}\n'
        if ret_type == 'F':
            return f'    .registers 1\n    const/{const_type} {reg}, {value}\n    return {reg}\n'
        if ret_type.startswith('L') or ret_type.startswith('['):
            return f'    .registers 1\n    const/{const_type} {reg}, {value}\n    return-object {reg}\n'
        # Z, I, B, S, C
        return f'    .registers 1\n    const/{const_type} {reg}, {value}\n    return {reg}\n'

    @staticmethod
    def _patch_method_return(content: str, method_name: str,
                             value: str = '0x0', const_type: str = '4',
                             reg: str = 'v0') -> Tuple[str, int]:
        """将指定方法体替换为返回特定值"""
        pattern = rf'(\.method\s+[^\n]*\b{re.escape(method_name)}\s*\([^)]*\)[^\n]*\n)(.*?)(\.end method)'

        count = 0

        def replacer(m):
            nonlocal count
            decl = m.group(1)
            end = m.group(3)
            # 跳过 abstract / native
            if 'abstract' in decl or 'native' in decl:
                return m.group(0)
            ret_type = AdRemover._get_return_type(decl)
            body = AdRemover._build_return_body(ret_type, value, const_type, reg)
            count += 1
            return decl + body + end

        new_content = re.sub(pattern, replacer, content, flags=re.DOTALL)
        return new_content, count

    @staticmethod
    def _inject_return_void(content: str, method_name: str) -> Tuple[str, int]:
        """在方法开头注入 return-void"""
        pattern = rf'(\.method\s+[^\n]*\b{re.escape(method_name)}\s*\([^)]*\)[^\n]*\n\s*\.registers\s+\d+\n)'
        new_content, count = re.subn(pattern, r'\1    return-void\n', content)
        return new_content, count

    @staticmethod
    def _clear_method_body(content: str, method_name: str) -> Tuple[str, int]:
        """清空方法体（保留 return）"""
        pattern = rf'(\.method\s+[^\n]*\b{re.escape(method_name)}\s*\([^)]*\)[^\n]*\n)(.*?)(\.end method)'

        count = 0

        def replacer(m):
            nonlocal count
            decl = m.group(1)
            end = m.group(3)
            if 'abstract' in decl or 'native' in decl:
                return m.group(0)
            ret_type = AdRemover._get_return_type(decl)
            if ret_type == 'V':
                body = '    .registers 1\n    return-void\n'
            else:
                body = AdRemover._build_return_body(ret_type, '0x0', '4', 'v0')
            count += 1
            return decl + body + end

        new_content = re.sub(pattern, replacer, content, flags=re.DOTALL)
        return new_content, count

    @staticmethod
    def _clear_methods_by_pattern(content: str, name_pattern: str,
                                   case_insensitive: bool = True) -> Tuple[str, int]:
        """清空所有方法名匹配 pattern 的方法体"""
        flags = re.DOTALL | (re.IGNORECASE if case_insensitive else 0)
        pattern = rf'(\.method\s+[^\n]*\b\w*{re.escape(name_pattern)}\w*\s*\([^)]*\)[^\n]*\n)(.*?)(\.end method)'

        count = 0

        def replacer(m):
            nonlocal count
            decl = m.group(1)
            end = m.group(3)
            if 'abstract' in decl or 'native' in decl:
                return m.group(0)
            ret_type = AdRemover._get_return_type(decl)
            if ret_type == 'V':
                body = '    .registers 1\n    return-void\n'
            else:
                body = AdRemover._build_return_body(ret_type, '0x0', '4', 'v0')
            count += 1
            return decl + body + end

        new_content = re.sub(pattern, replacer, content, flags=flags)
        return new_content, count

    @staticmethod
    def _replace_instruction(content: str, old: str, new: str) -> Tuple[str, int]:
        """替换指令"""
        return content.replace(old, new), content.count(old)

    # ============================================================
    # 字符串/常量操作
    # ============================================================

    @staticmethod
    def _clear_string_constants(content: str, pattern_str: str,
                                 exact_match: bool = False) -> Tuple[str, int]:
        """清除匹配的字符串常量（const-string）"""
        if exact_match:
            regex = rf'(const-string(?:/jumbo)?\s+v\d+,\s*)"{re.escape(pattern_str)}"'
        else:
            regex = rf'(const-string(?:/jumbo)?\s+v\d+,\s*)"[^"]*{re.escape(pattern_str)}[^"]*"'
        new_content, count = re.subn(regex, r'\1""', content)
        return new_content, count

    @staticmethod
    def _replace_string_constant(content: str, old_str: str,
                                  new_str: str) -> Tuple[str, int]:
        """替换字符串常量值"""
        old_val = f'"{old_str}"'
        new_val = f'"{new_str}"'
        count = content.count(old_val)
        return content.replace(old_val, new_val), count

    @staticmethod
    def _inject_return_void_for_string_methods(content: str, string_val: str) -> Tuple[str, int]:
        """在包含特定字符串的方法中注入 return-void"""
        # 同时支持原始 UTF-8 和 \uXXXX 转义
        unicode_val = ''.join(f'\\u{ord(c):04x}' for c in string_val)

        method_pattern = r'(\.method\s+[^\n]+\n)(.*?)(\.end method)'
        count = 0

        def replacer(m):
            nonlocal count
            decl = m.group(1)
            body = m.group(2)
            end = m.group(3)
            if 'abstract' in decl or 'native' in decl:
                return m.group(0)
            if string_val in body or unicode_val in body:
                reg_match = re.search(r'(\.registers\s+\d+\n)', body)
                if reg_match:
                    new_body = body[:reg_match.end()] + '    return-void\n' + body[reg_match.end():]
                    count += 1
                    return decl + new_body + end
            return m.group(0)

        new_content = re.sub(method_pattern, replacer, content, flags=re.DOTALL)
        return new_content, count

    # ============================================================
    # SDK 定向移除
    # ============================================================

    @staticmethod
    def _remove_tencent(smali_root: str) -> Dict:
        """移除腾讯广告"""
        r = {'patched': 0, 'files': 0}
        # 1. com.qq.e.comm.managers.b.d → const/4 v0, 0x1 改 0x0
        fp = AdRemover._find_class_file(smali_root, 'com.qq.e.comm.managers.b.d')
        if fp:
            c = AdRemover._read_file(fp)
            nc, n = AdRemover._replace_instruction(c, 'const/4 v0, 0x1', 'const/4 v0, 0x0')
            if n > 0:
                AdRemover._write_file(fp, nc)
                r['patched'] += n
                r['files'] += 1
        # 2. com.qq.e.comm.adevent.ADEvent.getType → const/16 v0, 0x65
        fp = AdRemover._find_class_file(smali_root, 'com.qq.e.comm.adevent.ADEvent')
        if fp:
            c = AdRemover._read_file(fp)
            nc, n = AdRemover._patch_method_return(c, 'getType', '0x65', '16')
            if n > 0:
                AdRemover._write_file(fp, nc)
                r['patched'] += n
                r['files'] += 1
        # 3. 另类：清除所有包含 "qq.e" 的字符串常量
        for sf in AdRemover._iter_smali_files(smali_root):
            c = AdRemover._read_file(sf)
            nc, n = AdRemover._clear_string_constants(c, 'qq.e', exact_match=False)
            if n > 0:
                AdRemover._write_file(sf, nc)
                r['patched'] += n
                r['files'] += 1
        return r

    @staticmethod
    def _remove_kuaishou(smali_root: str) -> Dict:
        """移除快手广告"""
        r = {'patched': 0, 'files': 0}
        # 1. isresultok → const/4 v0, 0x0
        for cls in ['com.kwad.sdk.core.network.BaseResultData',
                     'com.kwad.components.offline.api.core.network.model.BaseOfflineCompoResultData']:
            fp = AdRemover._find_class_file(smali_root, cls)
            if fp:
                c = AdRemover._read_file(fp)
                nc, n = AdRemover._patch_method_return(c, 'isresultok', '0x0', '4')
                if n > 0:
                    AdRemover._write_file(fp, nc)
                    r['patched'] += n
                    r['files'] += 1
        # 2. BaseResultData 中搜索 isResultOk 清空代码
        fp = AdRemover._find_class_file(smali_root, 'com.kwad.sdk.core.network.BaseResultData')
        if fp:
            c = AdRemover._read_file(fp)
            nc, n = AdRemover._clear_methods_by_pattern(c, 'isResultOk')
            if n > 0:
                AdRemover._write_file(fp, nc)
                r['patched'] += n
                r['files'] += 1
        # 3. 清除 "ksad" (完全匹配) 和 "kuaishou.com" (完全匹配)
        for sf in AdRemover._iter_smali_files(smali_root):
            c = AdRemover._read_file(sf)
            total = 0
            nc, n = AdRemover._clear_string_constants(c, 'ksad', exact_match=True)
            total += n
            nc, n = AdRemover._clear_string_constants(nc, 'kuaishou.com', exact_match=True)
            total += n
            if total > 0:
                AdRemover._write_file(sf, nc)
                r['patched'] += total
                r['files'] += 1
        return r

    @staticmethod
    def _remove_pangle(smali_root: str) -> Dict:
        """移除穿山甲广告"""
        r = {'patched': 0, 'files': 0}
        # 1. hasinit → const/4 v0, 0x0
        fp = AdRemover._find_class_file(smali_root, 'com.bytedance.pangle.Zeus')
        if fp:
            c = AdRemover._read_file(fp)
            nc, n = AdRemover._patch_method_return(c, 'hasinit', '0x0', '4')
            if n > 0:
                AdRemover._write_file(fp, nc)
                r['patched'] += n
                r['files'] += 1
        # 2. getAppId / getSdkInfo → const/4 v0, 0x0
        fp = AdRemover._find_class_file(smali_root, 'com.bytedance.sdk.openadsdk.TTAdConfig')
        if fp:
            c = AdRemover._read_file(fp)
            nc, n = AdRemover._patch_method_return(c, 'getAppId', '0x0', '4')
            nc, n2 = AdRemover._patch_method_return(nc, 'getSdkInfo', '0x0', '4')
            if n + n2 > 0:
                AdRemover._write_file(fp, nc)
                r['patched'] += n + n2
                r['files'] += 1
        # 3. 另类：AdSlot 中搜索 "getad" 清空方法
        fp = AdRemover._find_class_file(smali_root, 'Lcom/bytedance/sdk/openadsdk/AdSlot;')
        if not fp:
            fp = AdRemover._find_class_file(smali_root, 'com.bytedance.sdk.openadsdk.AdSlot')
        if fp:
            c = AdRemover._read_file(fp)
            nc, n = AdRemover._clear_methods_by_pattern(c, 'getad')
            if n > 0:
                AdRemover._write_file(fp, nc)
                r['patched'] += n
                r['files'] += 1
        # 4. com.byted.pangle 字符串 → "null"
        for sf in AdRemover._iter_smali_files(smali_root):
            c = AdRemover._read_file(sf)
            nc, n = AdRemover._replace_string_constant(c, 'com.byted.pangle', 'null')
            if n > 0:
                AdRemover._write_file(sf, nc)
                r['patched'] += n
                r['files'] += 1
        return r

    @staticmethod
    def _remove_baidu(smali_root: str) -> Dict:
        """移除百度广告 - 回调成功方法注入 return-void"""
        r = {'patched': 0, 'files': 0}
        for sf in AdRemover._iter_smali_files(smali_root):
            c = AdRemover._read_file(sf)
            nc, n = AdRemover._inject_return_void_for_string_methods(c, '回调成功')
            if n > 0:
                AdRemover._write_file(sf, nc)
                r['patched'] += n
                r['files'] += 1
        return r

    @staticmethod
    def _remove_toutiao(smali_root: str) -> Dict:
        """移除头条广告 - 清空头条广告相关方法体 + 清除字符串"""
        r = {'patched': 0, 'files': 0}
        # 1. 清空包含 "toutiao" 的类中的广告方法体
        for sf in AdRemover._iter_smali_files(smali_root):
            if 'toutiao' in sf.lower():
                c = AdRemover._read_file(sf)
                nc, n = AdRemover._clear_methods_by_pattern(c, 'loadAd')
                nc, n2 = AdRemover._clear_methods_by_pattern(nc, 'showAd')
                nc, n3 = AdRemover._clear_methods_by_pattern(nc, 'requestAd')
                total = n + n2 + n3
                if total > 0:
                    AdRemover._write_file(sf, nc)
                    r['patched'] += total
                    r['files'] += 1
        # 2. 清除 toutiao 相关字符串常量
        for sf in AdRemover._iter_smali_files(smali_root):
            c = AdRemover._read_file(sf)
            nc, n = AdRemover._clear_string_constants(c, 'toutiao', exact_match=False)
            if n > 0:
                AdRemover._write_file(sf, nc)
                r['patched'] += n
                r['files'] += 1
        return r

    @staticmethod
    def _remove_sigmob(smali_root: str, manifest_path: str = None) -> Dict:
        """移除 Sigmob 广告 - const/4 v0, 0x0 → 0x1 + manifest 清理"""
        r = {'patched': 0, 'files': 0}
        # 在 sigmob 类中将 const/4 v0, 0x0 改为 const/4 v0, 0x1
        for sf in AdRemover._iter_smali_files(smali_root):
            if 'sigmob' in sf.lower():
                c = AdRemover._read_file(sf)
                nc, n = AdRemover._replace_instruction(c, 'const/4 v0, 0x0', 'const/4 v0, 0x1')
                if n > 0:
                    AdRemover._write_file(sf, nc)
                    r['patched'] += n
                    r['files'] += 1
        # manifest 中删除 sigmob activity
        if manifest_path and os.path.isfile(manifest_path):
            c = AdRemover._read_file(manifest_path)
            nc, n = AdRemover._remove_manifest_components(c, 'sigmob')
            if n > 0:
                AdRemover._write_file(manifest_path, nc)
                r.setdefault('manifest_removed', 0)
                r['manifest_removed'] += n
        return r

    @staticmethod
    def _remove_google(smali_root: str, manifest_path: str = None) -> Dict:
        """移除谷歌广告"""
        r = {'patched': 0, 'files': 0}
        # 1. getInterstitialAdapter 中 0x1 → 0x0
        fp = AdRemover._find_class_file(smali_root, 'com.google.ads.mediation.AbstractAdViewAdapter')
        if fp:
            c = AdRemover._read_file(fp)
            # 定位方法并替换
            method_pattern = r'(\.method\s+[^\n]*\bgetInterstitialAdapter[^\n]*\n.*?)(\.end method)'
            def _repl(m):
                body = m.group(1)
                end = m.group(2)
                body = body.replace('const/4 v0, 0x1', 'const/4 v0, 0x0')
                return body + end
            nc = re.sub(method_pattern, _repl, c, flags=re.DOTALL)
            if nc != c:
                AdRemover._write_file(fp, nc)
                r['patched'] += 1
                r['files'] += 1
        # 2. 包含特定字符串的方法注入 return-void
        target_strings = [
            '#008 Must be called on the main UI thread',
            'The ad size and ad unit ID must be set before loadAd is called.',
        ]
        for sf in AdRemover._iter_smali_files(smali_root):
            c = AdRemover._read_file(sf)
            total = 0
            for s in target_strings:
                nc, n = AdRemover._inject_return_void_for_string_methods(c, s)
                total += n
                c = nc
            if total > 0:
                AdRemover._write_file(sf, c)
                r['patched'] += total
                r['files'] += 1
        # 3. manifest 中删除 com.google.gms + ad 相关组件
        if manifest_path and os.path.isfile(manifest_path):
            c = AdRemover._read_file(manifest_path)
            nc, n = AdRemover._remove_manifest_components(c, 'com.google.gms.*ad')
            if n > 0:
                AdRemover._write_file(manifest_path, nc)
                r.setdefault('manifest_removed', 0)
                r['manifest_removed'] += n
        return r

    @staticmethod
    def _remove_miads(smali_root: str) -> Dict:
        """移除米盟广告 - MimoSdk.init 注入 return-void"""
        r = {'patched': 0, 'files': 0}
        fp = AdRemover._find_class_file(smali_root, 'com.miui.zeus.mimo.sdk.MimoSdk')
        if fp:
            c = AdRemover._read_file(fp)
            nc, n = AdRemover._inject_return_void(c, 'init')
            if n > 0:
                AdRemover._write_file(fp, nc)
                r['patched'] += n
                r['files'] += 1
        return r

    # ============================================================
    # 正则通杀
    # ============================================================

    @staticmethod
    def _apply_regex_all(smali_root: str) -> Dict:
        """对所有 smali 文件应用正则通杀"""
        r = {'patterns_applied': len(AdRemover.REGEX_PATTERNS), 'replacements': 0, 'files': 0}
        for sf in AdRemover._iter_smali_files(smali_root):
            c = AdRemover._read_file(sf)
            total = 0
            changed = False
            for pattern, replacement, desc in AdRemover.REGEX_PATTERNS:
                nc, n = re.subn(pattern, replacement, c, flags=re.DOTALL)
                if n > 0:
                    total += n
                    changed = True
                    c = nc
            if changed:
                AdRemover._write_file(sf, c)
                r['replacements'] += total
                r['files'] += 1
        return r

    # ============================================================
    # VIP/Pro/Premium 解锁
    # ============================================================

    @staticmethod
    def _force_true_methods(smali_root: str) -> Dict:
        """将 VIP/Pro/Premium 相关方法强制返回 true (const/4 v0, 0x1 + return v0)"""
        config = AdRemover._load_config()
        method_names = config.get('force_true_methods', [])
        if not method_names:
            method_names = [
                'isVip', 'isPro', 'isPremium', 'isVipUser', 'isProUser',
                'isPremiumUser', 'isMember', 'isSubscribed', 'isPurchased',
                'isPaid', 'isUnlocked', 'isActivated', 'isLifetime',
            ]
        
        r = {'patched': 0, 'files': 0, 'methods': []}
        for sf in AdRemover._iter_smali_files(smali_root):
            c = AdRemover._read_file(sf)
            total = 0
            changed = False
            for method_name in method_names:
                nc, n = AdRemover._patch_method_return(c, method_name, '0x1', '4', 'v0')
                if n > 0:
                    total += n
                    changed = True
                    c = nc
            if changed:
                AdRemover._write_file(sf, c)
                r['patched'] += total
                r['files'] += 1
        return r

    @staticmethod
    def _replace_ad_urls(smali_root: str) -> Dict:
        """替换广告URL为空字符串"""
        config = AdRemover._load_config()
        url_patterns = config.get('url_patterns', [])
        if not url_patterns:
            return {'replacements': 0, 'files': 0}
        
        r = {'replacements': 0, 'files': 0}
        for sf in AdRemover._iter_smali_files(smali_root):
            c = AdRemover._read_file(sf)
            total = 0
            changed = False
            for url_pat in url_patterns:
                nc, n = AdRemover._clear_string_constants(c, url_pat, exact_match=False)
                if n > 0:
                    total += n
                    changed = True
                    c = nc
            if changed:
                AdRemover._write_file(sf, c)
                r['replacements'] += total
                r['files'] += 1
        return r

    @staticmethod
    def _remove_manifest_by_config(manifest_path: str) -> Dict:
        """从 manifest 中删除广告组件，使用配置中的 ad_activities/ad_services/ad_receivers"""
        r = {'removed': 0, 'components': []}
        if not os.path.isfile(manifest_path):
            return r
        
        config = AdRemover._load_config()
        c = AdRemover._read_file(manifest_path)
        total = 0
        
        # 从配置中获取 SDK 包名模式
        sdk_packages = config.get('sdk_packages', [])
        # 转换为 manifest 匹配模式（将 . 替换为 /）
        manifest_patterns = []
        for pkg in sdk_packages:
            if pkg.startswith('.'):
                continue
            manifest_patterns.append(pkg.replace('.', '/'))
        
        # 内置模式
        builtin_patterns = [
            'sigmob', 'com/google/gms.*ad', 'com/google/android/gms/ads',
            'com/qq/e', 'com/bytedance/sdk/openadsdk', 'com/bytedance/pangle',
            'com/kwad', 'com/baidu/mobads', 'toutiao', 'com/bytedance/toutiao',
        ]
        
        all_patterns = manifest_patterns + builtin_patterns
        for pat in all_patterns:
            nc, n = AdRemover._remove_manifest_components(c, pat)
            c = nc
            total += n
        
        # 使用 ad_activities 配置删除广告 Activity
        ad_activities = config.get('ad_activities', [])
        for act_name in ad_activities:
            pattern = rf'<activity\b[^>]*android:name="[^"]*{re.escape(act_name)}[^"]*"[^>]*>.*?</activity>|<activity\b[^>]*android:name="[^"]*{re.escape(act_name)}[^"]*"[^>]*/>'
            nc, n = re.subn(pattern, '', c, flags=re.DOTALL | re.IGNORECASE)
            c = nc
            total += n
        
        # ad_services
        ad_services = config.get('ad_services', [])
        for svc_name in ad_services:
            pattern = rf'<service\b[^>]*android:name="[^"]*{re.escape(svc_name)}[^"]*"[^>]*>.*?</service>|<service\b[^>]*android:name="[^"]*{re.escape(svc_name)}[^"]*"[^>]*/>'
            nc, n = re.subn(pattern, '', c, flags=re.DOTALL | re.IGNORECASE)
            c = nc
            total += n
        
        # ad_receivers
        ad_receivers = config.get('ad_receivers', [])
        for rcv_name in ad_receivers:
            pattern = rf'<receiver\b[^>]*android:name="[^"]*{re.escape(rcv_name)}[^"]*"[^>]*>.*?</receiver>|<receiver\b[^>]*android:name="[^"]*{re.escape(rcv_name)}[^"]*"[^>]*/>'
            nc, n = re.subn(pattern, '', c, flags=re.DOTALL | re.IGNORECASE)
            c = nc
            total += n
        
        if total > 0:
            AdRemover._write_file(manifest_path, c)
            r['removed'] = total
            r['components'] = all_patterns
        return r

    # ============================================================
    # Assets 清理
    # ============================================================

    @staticmethod
    def _clean_assets(assets_dir: str) -> Dict:
        """清理广告 assets 文件"""
        r = {'deleted': [], 'count': 0}
        if not os.path.isdir(assets_dir):
            return r

        for root, dirs, files in os.walk(assets_dir):
            for f in files:
                full_path = os.path.join(root, f)
                should_delete = False

                # 匹配已知广告文件
                for pat in AdRemover.AD_ASSET_PATTERNS:
                    if f == pat or f.startswith(pat):
                        should_delete = True
                        break

                # 纯数字文件名
                if not should_delete:
                    name_no_ext = os.path.splitext(f)[0]
                    if name_no_ext.isdigit():
                        should_delete = True

                if should_delete:
                    try:
                        os.remove(full_path)
                        r['deleted'].append(os.path.relpath(full_path, assets_dir))
                        r['count'] += 1
                    except OSError as e:
                        logger.debug(f"删除失败 {f}: {e}")
        return r

    # ============================================================
    # Manifest 清理
    # ============================================================

    @staticmethod
    def _remove_manifest_components(xml_content: str, name_pattern: str) -> Tuple[str, int]:
        """从 manifest XML 中删除名称匹配的广告组件"""
        count = 0
        # 匹配 <activity ...>...</activity> 和 <activity ... />
        for tag in ['activity', 'service', 'receiver', 'provider']:
            # 带子节点的标签
            pattern = rf'<{tag}\b[^>]*android:name="[^"]*{name_pattern}[^"]*"[^>]*>.*?</{tag}>'
            nc, n = re.subn(pattern, '', xml_content, flags=re.DOTALL | re.IGNORECASE)
            xml_content = nc
            count += n
            # 自闭合标签
            pattern = rf'<{tag}\b[^>]*android:name="[^"]*{name_pattern}[^"]*"[^>]*/>'
            nc, n = re.subn(pattern, '', xml_content, flags=re.IGNORECASE)
            xml_content = nc
            count += n
            # name 属性在前面的情况
            pattern = rf'<{tag}\b[^>]*android:name="[^"]*{name_pattern}[^"]*"[^>]*>\s*</{tag}>'
            nc, n = re.subn(pattern, '', xml_content, flags=re.DOTALL | re.IGNORECASE)
            xml_content = nc
            count += n
        return xml_content, count

    @staticmethod
    def _clean_manifest(manifest_path: str) -> Dict:
        """清理 manifest 中的广告组件"""
        r = {'removed': 0, 'components': []}
        if not os.path.isfile(manifest_path):
            return r
        c = AdRemover._read_file(manifest_path)
        total = 0
        # 各 SDK 包名模式
        patterns = [
            'sigmob', 'com.google.gms.*ad', 'com.google.android.gms.ads',
            'com.qq.e', 'com.bytedance.sdk.openadsdk', 'com.bytedance.pangle',
            'com.kwad', 'com.baidu.mobads', 'toutiao', 'com.bytedance.toutiao',
        ]
        for pat in patterns:
            nc, n = AdRemover._remove_manifest_components(c, pat)
            c = nc
            total += n
        if total > 0:
            AdRemover._write_file(manifest_path, c)
            r['removed'] = total
            r['components'] = patterns
        return r

    # ============================================================
    # 主入口
    # ============================================================

    @staticmethod
    def remove_all(smali_root: str, assets_dir: str = None,
                   manifest_path: str = None,
                   options: dict = None) -> Dict:
        """一键移除所有广告 + VIP解锁

        Args:
            smali_root: 解码后的 APK 根目录（含 smali/ 目录）
            assets_dir: assets 目录路径（可选）
            manifest_path: AndroidManifest.xml 路径（可选）
            options: 选项字典，控制各模块开关

        Returns:
            操作报告字典
        """
        if options is None:
            options = {}
        # 默认全部开启
        for k in ['tencent', 'kuaishou', 'pangle', 'baidu', 'toutiao', 'sigmob',
                   'google', 'miads', 'regex', 'assets', 'manifest',
                   'vip_unlock', 'url_replace', 'manifest_config',
                   'unity', 'mintegral', 'vungle', 'chartboost',
                   'applovin', 'ironsource', 'facebook', 'huawei',
                   'oppo', 'vivo', 'startapp', 'inmobi', 'adcolony',
                   'anythink', 'topon', 'fyber', 'mbridge', 'bidmachine',
                   'pubnative', 'pollfish', 'smaato', 'amazon', 'yandex', 'mytarget']:
            options.setdefault(k, True)

        report = {
            'total_patched': 0,
            'total_files': 0,
            'sdks': {},
            'regex': {},
            'vip_unlock': {},
            'url_replace': {},
            'assets': {},
            'manifest': {},
            'manifest_config': {},
            'generic_sdks': {},
        }

        # SDK 定向移除（有精确移除策略的SDK）
        sdk_map = {
            'tencent':  ('_remove_tencent',  smali_root),
            'kuaishou': ('_remove_kuaishou', smali_root),
            'pangle':   ('_remove_pangle',   smali_root),
            'baidu':    ('_remove_baidu',    smali_root),
            'toutiao':  ('_remove_toutiao',  smali_root),
            'sigmob':   ('_remove_sigmob',   smali_root),
            'google':   ('_remove_google',   smali_root),
            'miads':    ('_remove_miads',    smali_root),
        }
        for sdk_key, (method_name, *args) in sdk_map.items():
            if not options.get(sdk_key, True):
                continue
            method = getattr(AdRemover, method_name)
            # sigmob 和 google 需要 manifest_path
            if sdk_key == 'sigmob':
                r = method(smali_root, manifest_path)
            elif sdk_key == 'google':
                r = method(smali_root, manifest_path)
            else:
                r = method(smali_root)
            report['sdks'][sdk_key] = r
            report['total_patched'] += r.get('patched', 0)
            report['total_files'] += r.get('files', 0)

        # 通用SDK移除（通过包名匹配清空广告方法 + 清除字符串）
        generic_sdks = [
            'unity', 'mintegral', 'vungle', 'chartboost',
            'applovin', 'ironsource', 'facebook', 'huawei',
            'oppo', 'vivo', 'startapp', 'inmobi', 'adcolony',
            'anythink', 'topon', 'fyber', 'mbridge', 'bidmachine',
            'pubnative', 'pollfish', 'smaato', 'amazon', 'yandex', 'mytarget',
        ]
        for sdk_key in generic_sdks:
            if not options.get(sdk_key, True):
                continue
            sdk_config = AdRemover.AD_SDKS.get(sdk_key)
            if not sdk_config:
                continue
            r = AdRemover._remove_generic_sdk(smali_root, sdk_config['packages'])
            report['generic_sdks'][sdk_key] = r
            report['total_patched'] += r.get('patched', 0)
            report['total_files'] += r.get('files', 0)

        # 正则通杀
        if options.get('regex', True):
            r = AdRemover._apply_regex_all(smali_root)
            report['regex'] = r
            report['total_patched'] += r.get('replacements', 0)
            report['total_files'] += r.get('files', 0)

        # VIP/Pro/Premium 解锁
        if options.get('vip_unlock', True):
            r = AdRemover._force_true_methods(smali_root)
            report['vip_unlock'] = r
            report['total_patched'] += r.get('patched', 0)
            report['total_files'] += r.get('files', 0)

        # 广告URL替换
        if options.get('url_replace', True):
            r = AdRemover._replace_ad_urls(smali_root)
            report['url_replace'] = r
            report['total_patched'] += r.get('replacements', 0)
            report['total_files'] += r.get('files', 0)

        # Assets 清理
        if options.get('assets', True) and assets_dir:
            report['assets'] = AdRemover._clean_assets(assets_dir)

        # Manifest 清理 (内置模式)
        if options.get('manifest', True) and manifest_path:
            report['manifest'] = AdRemover._clean_manifest(manifest_path)

        # Manifest 清理 (配置模式 - ad_activities/ad_services/ad_receivers)
        if options.get('manifest_config', True) and manifest_path:
            report['manifest_config'] = AdRemover._remove_manifest_by_config(manifest_path)

        return report

    # ============================================================
    # 通用SDK移除（包名匹配模式）
    # ============================================================

    @staticmethod
    def _remove_generic_sdk(smali_root: str, packages: List[str]) -> Dict:
        """通用SDK移除：通过包名前缀匹配，清空广告方法体 + 清除字符串常量

        Args:
            smali_root: smali根目录
            packages: SDK包名列表（如 ['com/unity3d/ads', 'com/unity3d/services/ads']）

        Returns:
            操作报告
        """
        r = {'patched': 0, 'files': 0}
        ad_method_patterns = [
            'loadAd', 'showAd', 'requestAd', 'initAd', 'destroyAd',
            'onAdLoaded', 'onAdFailed', 'onAdClosed', 'onAdClicked',
            'onAdShow', 'onAdImpression', 'loadAds', 'showAds',
            'fetchAd', 'preloadAd', 'cacheAd',
            'showInterstitial', 'showRewarded', 'showBanner',
            'showSplash', 'showNative', 'showExpress',
            'loadInterstitial', 'loadRewarded', 'loadBanner',
            'loadNative', 'loadSplash', 'loadExpress',
        ]
        for sf in AdRemover._iter_smali_files(smali_root):
            sf_lower = sf.lower()
            matched = False
            for pkg in packages:
                pkg_path = pkg.replace('.', '/').lower()
                if pkg_path in sf_lower:
                    matched = True
                    break
            if not matched:
                continue
            c = AdRemover._read_file(sf)
            total = 0
            for method_pat in ad_method_patterns:
                nc, n = AdRemover._clear_methods_by_pattern(c, method_pat)
                total += n
                c = nc
            # 清除SDK相关字符串常量
            for pkg in packages:
                pkg_str = pkg.replace('/', '.')
                nc, n = AdRemover._clear_string_constants(c, pkg_str, exact_match=False)
                total += n
                c = nc
            if total > 0:
                AdRemover._write_file(sf, c)
                r['patched'] += total
                r['files'] += 1
        return r

    @staticmethod
    def detect_ad_sdks(smali_root: str) -> List[str]:
        """检测 APK 中集成的广告 SDK"""
        detected = []
        all_files = list(AdRemover._iter_smali_files(smali_root))
        file_paths = ' '.join(f.replace(smali_root, '') for f in all_files[:5000])

        # 检测内置 SDK
        for sdk_key, config in AdRemover.AD_SDKS.items():
            for pkg in config['packages']:
                if pkg in file_paths:
                    if sdk_key not in detected:
                        detected.append(sdk_key)
                    break
        
        # 检测配置文件中的额外 SDK 包名
        ext_config = AdRemover._load_config()
        ext_packages = ext_config.get('sdk_packages', [])
        for pkg in ext_packages:
            pkg_path = pkg.replace('.', '/')
            if pkg_path in file_paths:
                # 找到匹配的内置 SDK key
                matched = False
                for sdk_key, sdk_config in AdRemover.AD_SDKS.items():
                    for sdk_pkg in sdk_config['packages']:
                        if pkg_path.startswith(sdk_pkg):
                            if sdk_key not in detected:
                                detected.append(sdk_key)
                            matched = True
                            break
                    if matched:
                        break
                if not matched and pkg not in detected:
                    # 额外 SDK，添加包名作为标识
                    detected.append(pkg)
        return detected
