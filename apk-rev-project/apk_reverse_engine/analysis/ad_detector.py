#!/usr/bin/env python3
"""广告检测模块 - 多维度识别 APK 中的广告集成

检测维度:
1. SDK检测: 识别已知广告SDK（AdMob/Facebook/Unity Ads等）— 内置 + 外部JSON配置
2. 代码模式: 检测广告相关类/方法调用（AdView/Interstitial/Rewarded等）— 内置 + 外部JSON配置
3. 权限特征: 广告SDK典型请求权限
4. URL/域名: 广告网络请求地址
5. 字符串特征: 广告相关硬编码字符串
6. 组件检测: 广告 Activity/Service/Receiver
7. 综合评分: 给出广告集成密度评分
"""
import os
import re
import json
from collections import Counter, defaultdict
from typing import Optional


class AdDetector:
    """APK 广告检测器 - 多维度识别"""

    # ── 外部配置加载 ──────────────────────────────────────────
    _CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'ad_patterns.json')
    _config_cache: Optional[dict] = None

    @classmethod
    def _load_config(cls) -> dict:
        """从 ad_patterns.json 加载配置，失败时返回空字典"""
        if cls._config_cache is not None:
            return cls._config_cache
        try:
            with open(cls._CONFIG_PATH, 'r', encoding='utf-8') as f:
                cls._config_cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            cls._config_cache = {}
        return cls._config_cache

    # ── 广告SDK特征库（包名前缀） ─────────────────────────────
    AD_SDK_SIGNATURES = [
        # ── 主流广告平台 ────────────────────────────────────
        (r'com\.google\.android\.gms\.ads',       'Google AdMob/AdX'),
        (r'com\.google\.android\.ads',             'Google AdMob'),
        (r'com\.google\.ads',                      'Google Ads'),
        (r'com\.facebook\.ads',                    'Facebook Audience Network'),
        (r'com\.facebook\.react',                  'Facebook Ads (React)'),
        (r'com\.applovin\.',                       'AppLovin'),
        (r'com\.unity3d\.ads',                     'Unity Ads'),
        (r'com\.unity3d\.player',                  'Unity Ads (Player)'),
        (r'com\.vungle\.',                         'Vungle'),
        (r'com\.ironsource\.',                     'ironSource'),
        (r'com\.chartboost\.',                     'Chartboost'),
        (r'com\.adcolony\.',                       'AdColony'),
        (r'com\.tapjoy\.',                         'Tapjoy'),
        (r'com\.startapp\.',                       'StartApp'),
        (r'com\.inmobi\.',                         'InMobi'),
        (r'com\.mopub\.',                          'MoPub'),
        (r'com\.amazon\.ads',                      'Amazon Ads'),
        (r'com\.bytedance\.',                      'ByteDance/Pangle'),
        (r'com\.pangolin\.',                       'Pangle'),
        (r'com\.mintegral\.',                      'Mintegral'),
        (r'com\.huawei\.hms\.ads',                 'Huawei Ads'),
        (r'com\.vivo\.ad',                         'Vivo Ads'),
        (r'com\.oppo\.ad',                         'OPPO Ads'),
        (r'com\.xiaomi\.ad',                       'Xiaomi Ads'),
        (r'com\.huawei\.ad',                       'Huawei Ads'),
        (r'com\.tencent\.gdt',                     'Tencent GDT/广点通'),
        (r'com\.qq\.e',                            'Tencent GDT'),
        (r'com\.baidu\.ad',                        'Baidu Ads'),
        (r'com\.baidu\.mobads',                    'Baidu MobAds'),
        (r'com\.alibaba\.ad',                      'Alibaba Ads'),
        (r'com\.sigmob\.',                         'Sigmob'),
        (r'com\.kuaishou\.ad',                     'Kuaishou Ads'),
        (r'com\.yy\.ad',                           'YY Ads'),
        (r'com\.mobvista\.',                       'Mobvista'),
        (r'net\.pubnative\.',                      'PubNative'),
        (r'com\.fyber\.',                          'Fyber'),
        (r'com\.adx\.',                            'AdX'),
        (r'com\.adserver\.',                       'AdServer'),
        (r'com\.smaato\.',                         'Smaato'),
        (r'com\.verizon\.ads',                     'Verizon Ads'),
        (r'com\.appnexus\.',                       'AppNexus'),
        (r'com\.rubicon\.',                        'Rubicon'),
        (r'com\.openx\.',                          'OpenX'),
        (r'com\.indexexchange\.',                  'IndexExchange'),
        (r'com\.criteo\.',                         'Criteo'),
        # ── 中介/聚合平台 ─────────────────────────────────
        (r'com\.google\.android\.gms\.ads\.mediation', 'AdMob Mediation'),
        (r'com\.ironsource\.mediationsdk',         'ironSource Mediation'),
        (r'com\.fyber\.mediation',                 'Fyber Mediation'),
        (r'com\.applovin\.mediation',              'AppLovin Mediation'),
        # ── 扩展SDK ────────────────────────────────────────
        (r'com\.mbridge\.msdk',                    'MBridge/Mintegral'),
        (r'io\.bidmachine\.',                      'BidMachine'),
        (r'com\.anythink\.',                       'AnyThink/TopOn'),
        (r'com\.topon\.',                          'TopOn'),
        (r'com\.pollfish\.',                       'Pollfish'),
        (r'com\.beizi\.ad',                        'Beizi Ads'),
        (r'com\.qumeng\.',                         'QuMeng Ads'),
        (r'com\.wangmai\.',                        'WangMai Ads'),
        (r'com\.oneway\.ads',                      'OneWay Ads'),
        (r'com\.taptap\.ad',                       'TapTap Ads'),
        (r'com\.wangmeng\.ads',                    'WangMeng Ads'),
        (r'com\.volcengine\.onekit',               'VolcEngine Ads'),
        (r'com\.bykv\.vk',                         'Bykv Ads'),
        (r'com\.adgain\.sdk',                      'AdGain SDK'),
        (r'com\.meishu\.',                         'MeiShu Ads'),
        (r'com\.inno\.innosdk',                    'Inno SDK'),
        (r'com\.cat\.sdk',                         'CAT SDK'),
        (r'com\.ptg\.',                            'PTG Ads'),
        (r'com\.octopus\.',                        'Octopus Ads'),
        (r'com\.ubix\.',                           'Ubix Ads'),
        (r'com\.zhpan\.',                          'ZhPan Ads'),
        (r'com\.zm\.adxsdk',                       'ZM AdX SDK'),
        (r'com\.honor\.ads',                       'Honor Ads'),
        (r'com\.zui\.ads',                         'ZUI Ads'),
        (r'com\.tdc\.ads',                         'TDC Ads'),
        (r'com\.bun\.miitmdid',                    'MIIT MDID (广告标识)'),
    ]

    # ── 广告代码模式（类名/方法名关键词） ────────────────────
    AD_CODE_PATTERNS = [
        # AdView 相关
        r'AdView',
        r'AdListener',
        r'AdRequest',
        r'AdSize',
        r'AdLoader',
        r'InterstitialAd',
        r'RewardedVideoAd',
        r'RewardedAd',
        r'NativeAd',
        r'BannerAd',
        r'AdManager',
        # 广告生命周期
        r'onAdLoaded',
        r'onAdFailed',
        r'onAdClosed',
        r'onAdOpened',
        r'onAdImpression',
        r'onAdClicked',
        r'onAdLeftApplication',
        r'loadAd\b',
        r'showAd\b',
        r'isAdLoaded',
        r'destroyAd',
        # 广告参数
        r'adUnitId',
        r'ad_unit_id',
        r'adUnit',
        r'placementId',
        r'placement_id',
        r'APP_ID',
        r'BANNER_ID',
        r'INTERSTITIAL_ID',
        r'REWARDED_ID',
        r'NATIVE_ID',
        # 广告相关类
        r'MobileAds',
        r'AdMob',
        r'AdColony',
        r'Vungle',
        r'Chartboost',
        r'AppLovin',
        r'UnityAds',
        r'ironSource',
        r'StartApp',
        r'InMobi',
        r'AdFit',
        r'AdAgent',
        r'AdViewAd',
        r'AdmobAd',
        r'FacebookAd',
        r'BaiduAd',
        r'GDTAd',
        r'PangleAd',
        r'MintegralAd',
    ]

    # ── 广告相关权限 ─────────────────────────────────────────
    AD_PERMISSIONS = [
        'READ_PHONE_STATE',
        'ACCESS_FINE_LOCATION',
        'ACCESS_COARSE_LOCATION',
        'ACCESS_WIFI_STATE',
        'READ_EXTERNAL_STORAGE',
        'WRITE_EXTERNAL_STORAGE',
        'GET_ACCOUNTS',
        'ACCESS_NETWORK_STATE',
        'INTERNET',
        'READ_LOGS',
        'ACCESS_ADSERVICES_ATTRIBUTION',
        'ACCESS_ADSERVICES_AD_ID',
        'WAKE_LOCK',
        'VIBRATE',
        'RECEIVE_BOOT_COMPLETED',
        'BILLING',
        'QUERY_ALL_PACKAGES',
        'PACKAGE_USAGE_STATS',
        'AD_ID',
    ]

    # ── 广告网络 URL 域名特征 ────────────────────────────────
    AD_DOMAIN_PATTERNS = [
        r'googleads\.g\.doubleclick\.net',
        r'google\.com/(?:ads|adbanners|adservices)',
        r'doubleclick\.net',
        r'googlesyndication\.com',
        r'googletagservices\.com',
        r'facebook\.com/ad',
        r'fbcdn\.net.*ad',
        r'applovin\.com',
        r'vungle\.com',
        r'ironsrc\.com',
        r'adcolony\.com',
        r'chartboost\.com',
        r'tapjoy\.com',
        r'startapp\.com',
        r'inmobi\.com',
        r'mopub\.com',
        r'pangolin\.sdk',
        r'mintegral\.com',
        r'bytedance\.com/ad',
        r'pangle\.com',
        r'adsrvr\.org',
        r'adsymptotic\.com',
        r'crashlytics\.com',
        r'adjust\.com',
        r'appsflyer\.com',
        r'ads\.xiaomi\.com',
        r'ads\.huawei\.com',
        r'ads\.vivo\.com',
        r'ads\.oppo\.com',
        r'gdt\.qq\.com',
        r'ads\.baidu\.com',
        r'c\.baidu\.com',
        r'e\.qq\.com',
        r'ad\.alibaba\.com',
        r'sigmob\.com',
        r'ks\.ad',
        r'ads\.kuaishou\.com',
        r'ad\.yy\.com',
        r'mobvista\.com',
        r'pubnative\.net',
        r'fyber\.com',
        r'smaato\.com',
        r'criteo\.com',
        r'openx\.net',
        r'rubiconproject\.com',
        r'appnexus\.com',
        r'adnxs\.com',
        r'cas\.alibaba\.com',
        r'toponad\.com',
        r'anythinktech\.com',
        r'sigmob\.cn',
        r'bidmachine\.io',
        r'pangolin-sdk-toutiao\.com',
        r'pangolin\.snssdk\.com',
        r'toblog\.ctobsnssdk\.com',
        r'sdk\.e\.qq\.com',
        r'adnet\.qq\.com',
        r'ads\.mopub\.com',
        r'ads\.api\.vungle\.com',
        r'edge\.adcolony\.com',
        r'live\.chartboost\.com',
        r'a\.applovin\.com',
        r'config\.unityads\.unity3d\.com',
        r'config\.mintegral\.com',
        r'huawei\.com/ads',
        r'hihonor\.com/ads',
        r'oppo\.com/ads',
        r'vivo\.com\.cn/ad',
        r'scorecardresearch\.com',
        r'moatads\.com',
        r'pagead2\.googlesyndication\.com',
        r'admob\.com',
        r'app-measurement\.com',
        r'google-analytics\.com',
        r'startappelb\.com',
        r'startappnetwork\.com',
        r'smaato\.net',
        r'pubmatic\.com',
        r'amazon-adsystem\.com',
        r'yandexadexchange\.net',
        r'mytarget\.ru',
    ]

    @classmethod
    def _get_extended_sdk_patterns(cls):
        """合并内置签名和外部配置的SDK包名"""
        signatures = list(cls.AD_SDK_SIGNATURES)
        config = cls._load_config()
        for pkg in config.get('sdk_packages', []):
            if pkg.startswith('.'):
                continue
            # 转换为正则
            regex = re.escape(pkg).replace(r'\.', r'\.')
            sdk_name = pkg.split('.')[-1].capitalize() + ' SDK'
            signatures.append((regex, sdk_name))
        return signatures

    @classmethod
    def detect_from_class_names(cls, class_names):
        """从DEX类名检测广告SDK

        Args:
            class_names: list[str], DEX类名列表

        Returns:
            list[dict]: 检测到的广告SDK列表
        """
        detected = {}
        signatures = cls._get_extended_sdk_patterns()
        for name in class_names:
            java_name = name.replace('/', '.').lstrip('L').rstrip(';')
            for pattern, sdk_name in signatures:
                if re.search(pattern, java_name):
                    if sdk_name not in detected:
                        detected[sdk_name] = {
                            'name': sdk_name,
                            'count': 0,
                            'samples': [],
                        }
                    detected[sdk_name]['count'] += 1
                    if len(detected[sdk_name]['samples']) < 3:
                        short = java_name.split('.')[-1] if '.' in java_name else java_name
                        if short not in detected[sdk_name]['samples']:
                            detected[sdk_name]['samples'].append(short)

        return sorted(detected.values(), key=lambda x: x['count'], reverse=True)

    @classmethod
    def detect_code_patterns(cls, class_names, strings):
        """检测广告相关代码模式

        Args:
            class_names: list[str], 类名列表
            strings: list[str], DEX字符串列表

        Returns:
            dict: {
                'ad_view': bool,       # 是否存在AdView
                'interstitial': bool,  # 插屏广告
                'rewarded': bool,      # 激励视频
                'native_ad': bool,     # 原生广告
                'banner': bool,        # Banner广告
                'mediation': bool,     # 广告聚合
                'patterns_found': int, # 匹配总次数
                'details': list,       # 详情
                'ad_activities': list, # 检测到的广告Activity
                'ad_services': list,   # 检测到的广告Service
            }
        """
        result = {
            'ad_view': False,
            'interstitial': False,
            'rewarded': False,
            'native_ad': False,
            'banner': False,
            'mediation': False,
            'patterns_found': 0,
            'details': [],
            'ad_activities': [],
            'ad_services': [],
        }

        # 从类名检测
        combined = ' '.join(class_names) if class_names else ''
        combined += ' '
        combined += ' '.join(strings) if strings else ''

        # 分类检测
        if re.search(r'AdView|BannerAd', combined):
            result['ad_view'] = True
            result['details'].append('AdView/Banner广告组件')
        if re.search(r'InterstitialAd|Interstitial', combined):
            result['interstitial'] = True
            result['details'].append('插屏广告(Interstitial)')
        if re.search(r'RewardedVideoAd|RewardedAd|Rewarded', combined):
            result['rewarded'] = True
            result['details'].append('激励视频广告(Rewarded)')
        if re.search(r'NativeAd|NativeAdView|Native', combined):
            result['native_ad'] = True
            result['details'].append('原生广告(Native)')
        if re.search(r'BannerAd|BannerAdView|Banner', combined):
            result['banner'] = True
            result['details'].append('Banner广告')
        if re.search(r'Mediat|AdNetwork|adapter', combined):
            result['mediation'] = True
            result['details'].append('广告聚合平台(Mediation)')

        # 从配置中加载 class_keywords 并检测
        config = cls._load_config()
        ext_keywords = config.get('class_keywords', [])
        if ext_keywords:
            for kw in ext_keywords:
                if kw in combined:
                    if kw not in [d.split('(')[0] if '(' in d else d for d in result['details']]:
                        result['details'].append(f'广告类关键词: {kw}')

        # 检测广告 Activity/Service（从配置）
        ad_activities = config.get('ad_activities', [])
        ad_services = config.get('ad_services', [])
        for act in ad_activities:
            if act in combined:
                result['ad_activities'].append(act)
        for svc in ad_services:
            if svc in combined:
                result['ad_services'].append(svc)

        # 统计模式匹配次数（内置 + 配置）
        count = 0
        for pattern in cls.AD_CODE_PATTERNS:
            count += len(re.findall(pattern, combined))
        # 配置中的 method_patterns
        ext_methods = config.get('method_patterns', [])
        for method in ext_methods:
            count += len(re.findall(re.escape(method), combined))
        result['patterns_found'] = count

        return result

    @classmethod
    def detect_ad_permissions(cls, permissions):
        """检测广告相关权限

        Args:
            permissions: list[str], 权限列表

        Returns:
            dict: {
                'ad_related': list[str], 广告相关权限
                'count': int,
                'risk_level': str,       # 高/中/低
            }
        """
        if not permissions:
            return {'ad_related': [], 'count': 0, 'risk_level': '低'}

        perm_set = set(p.upper().split('.')[-1] if '.' in p else p.upper() for p in permissions)
        ad_perms = [p for p in cls.AD_PERMISSIONS if p in perm_set]

        # 风险等级
        critical = {'READ_PHONE_STATE', 'ACCESS_FINE_LOCATION', 'GET_ACCOUNTS'}
        critical_matched = [p for p in ad_perms if p in critical]
        count = len(ad_perms)

        if count >= 5 or len(critical_matched) >= 2:
            level = '高'
        elif count >= 3:
            level = '中'
        else:
            level = '低'

        return {
            'ad_related': ad_perms,
            'count': count,
            'critical_count': len(critical_matched),
            'risk_level': level,
        }

    @classmethod
    def detect_ad_urls(cls, strings):
        """从字符串中检测广告网络URL

        Args:
            strings: list[str], DEX字符串列表

        Returns:
            dict: {
                'ad_domains': list[str],  匹配的广告域名
                'ad_urls': list[str],     完整广告URL
                'total': int,
            }
        """
        if not strings:
            return {'ad_domains': [], 'ad_urls': [], 'total': 0}

        ad_domains = set()
        ad_urls = set()

        # 合并内置 + 外部配置的URL模式
        all_patterns = list(cls.AD_DOMAIN_PATTERNS)
        config = cls._load_config()
        for url_pat in config.get('url_patterns', []):
            if not url_pat.startswith('.') and url_pat not in all_patterns:
                all_patterns.append(re.escape(url_pat))

        for s in strings:
            for pattern in all_patterns:
                m = re.search(pattern, s, re.I)
                if m:
                    domain = m.group()
                    ad_domains.add(domain)
                    if s.startswith('http'):
                        ad_urls.add(s[:150])
                    break

        return {
            'ad_domains': sorted(ad_domains)[:30],
            'ad_urls': sorted(ad_urls)[:20],
            'total': len(ad_domains),
        }

    @classmethod
    def detect_ad_strings(cls, strings):
        """检测广告相关字符串特征

        Args:
            strings: list[str], DEX字符串列表

        Returns:
            list[str]: 检测到的广告相关关键词
        """
        if not strings:
            return []

        ad_keywords = {
            '广告平台ID': ['ca-app-pub-', 'pub-', 'adunit', 'placement'],
            '广告开关': ['is_ad_enabled', 'show_ad', 'ad_enabled', 'enable_ads'],
            '广告配置': ['ad_config', 'ad_settings', 'ad_timeout', 'ad_retry'],
            '广告测试': ['test_ad', 'test_ads', 'debug_ad', 'ad_test_mode'],
            '广告统计': ['ad_impression', 'ad_click', 'ad_revenue', 'ad_show_count'],
            '广告SDK标识': ['applovin', 'vungle', 'adcolony', 'chartboost',
                          'tapjoy', 'ironsource', 'startapp', 'inmobi',
                          'mintegral', 'pangle', 'bytedance'],
        }

        detected = []
        s_lower = ' '.join(s.lower() for s in strings)

        for category, keywords in ad_keywords.items():
            for kw in keywords:
                if kw in s_lower:
                    detected.append(category)
                    break

        return list(set(detected))

    @classmethod
    def analyze(cls, class_names=None, strings=None, permissions=None):
        """一站式广告检测分析

        Args:
            class_names: list[str], DEX类名列表
            strings: list[str], DEX字符串列表
            permissions: list[str], 权限列表

        Returns:
            dict: 完整广告检测报告
        """
        result = {
            'ad_sdks': [],
            'code_patterns': {},
            'permissions': {},
            'ad_urls': {},
            'ad_strings': [],
            'score': 0,
            'level': '无广告',
            'summary': {},
            'ad_activities': [],
            'ad_services': [],
        }

        # 1. SDK检测
        if class_names:
            result['ad_sdks'] = cls.detect_from_class_names(class_names)

        # 2. 代码模式
        result['code_patterns'] = cls.detect_code_patterns(class_names, strings)
        result['ad_activities'] = result['code_patterns'].get('ad_activities', [])
        result['ad_services'] = result['code_patterns'].get('ad_services', [])

        # 3. 权限检测
        result['permissions'] = cls.detect_ad_permissions(permissions)

        # 4. URL检测
        if strings:
            result['ad_urls'] = cls.detect_ad_urls(strings)
            result['ad_strings'] = cls.detect_ad_strings(strings)

        # 5. 综合评分 (0-100)
        score = 0
        details = []

        # SDK评分
        sdk_count = len(result['ad_sdks'])
        if sdk_count >= 5:
            score += 40
            details.append(f'集成了 {sdk_count} 个广告SDK')
        elif sdk_count >= 3:
            score += 30
            details.append(f'集成了 {sdk_count} 个广告SDK')
        elif sdk_count >= 1:
            score += 15
            details.append(f'集成了 {sdk_count} 个广告SDK')

        # 代码模式评分
        cp = result['code_patterns']
        if cp.get('ad_view') or cp.get('banner'):
            score += 10
        if cp.get('interstitial'):
            score += 10
        if cp.get('rewarded'):
            score += 10
        if cp.get('native_ad'):
            score += 8
        if cp.get('mediation'):
            score += 10
        pattern_count = cp.get('patterns_found', 0)
        if pattern_count > 10:
            score += min(15, pattern_count // 2)

        # 权限评分
        perm = result['permissions']
        if perm.get('count', 0) >= 5:
            score += 15
        elif perm.get('count', 0) >= 3:
            score += 10
        if perm.get('critical_count', 0) >= 2:
            score += 10

        # URL评分
        url_count = result['ad_urls'].get('total', 0)
        if url_count > 0:
            score += min(10, url_count * 2)

        score = min(100, score)

        # 等级判定
        if score >= 60:
            level = '密集广告'
        elif score >= 35:
            level = '有广告'
        elif score >= 10:
            level = '轻度广告'
        else:
            level = '无广告'

        result['score'] = score
        result['level'] = level
        result['summary'] = {
            'score': score,
            'level': level,
            'ad_sdk_count': sdk_count,
            'ad_sdk_names': [s['name'] for s in result['ad_sdks']],
            'has_ad_view': cp.get('ad_view', False),
            'has_interstitial': cp.get('interstitial', False),
            'has_rewarded': cp.get('rewarded', False),
            'has_native': cp.get('native_ad', False),
            'has_banner': cp.get('banner', False),
            'has_mediation': cp.get('mediation', False),
            'ad_permission_count': perm.get('count', 0),
            'ad_url_count': url_count,
            'ad_activities': result.get('ad_activities', []),
            'ad_services': result.get('ad_services', []),
            'details': details,
        }

        return result


# ── 快捷函数 ──────────────────────────────────────────────────
def detect_ads(class_names=None, strings=None, permissions=None):
    """一站式广告检测"""
    return AdDetector.analyze(class_names, strings, permissions)

def detect_ad_sdks(class_names):
    """检测广告SDK"""
    return AdDetector.detect_from_class_names(class_names)