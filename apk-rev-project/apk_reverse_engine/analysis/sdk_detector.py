#!/usr/bin/env python3
"""SDK/Tracker 检测模块 - 识别APK中集成的第三方SDK和追踪器
从DEX类名、字符串、权限等维度识别常见的第三方SDK，
评估隐私风险和数据收集行为。
"""
import re
from collections import Counter

class SDKDetector:
    """第三方SDK检测引擎"""

    # ── SDK 特征库: 包名前缀 + 标签 + 风险等级 ────────────────
    SDK_SIGNATURES = [
        # ─── 广告/追踪 ───
        (r'com\.google\.android\.gms\.ads',         'Google Ads', '广告', '高'),
        (r'com\.google\.android\.ads',               'Google AdMob', '广告', '高'),
        (r'com\.facebook\.ads',                      'Facebook Ads', '广告', '高'),
        (r'com\.facebook\.react',                    'Facebook React', '社交', '中'),
        (r'com\.facebook\.',                         'Facebook SDK', '社交/追踪', '高'),
        (r'com\.applovin\.',                         'AppLovin', '广告', '高'),
        (r'com\.unity3d\.player',                    'Unity3D', '游戏引擎', '低'),
        (r'com\.unity3d\.ads',                       'Unity Ads', '广告', '高'),
        (r'com\.vungle\.',                           'Vungle', '广告', '高'),
        (r'com\.ironsource\.',                       'IronSource', '广告', '高'),
        (r'com\.chartboost\.',                       'Chartboost', '广告', '高'),
        (r'com\.adcolony\.',                         'AdColony', '广告', '高'),
        (r'com\.tapjoy\.',                           'Tapjoy', '广告', '高'),
        (r'com\.startapp\.',                         'StartApp', '广告', '高'),
        (r'com\.inmobi\.',                           'InMobi', '广告', '高'),
        (r'com\.mopub\.',                            'MoPub', '广告', '高'),
        (r'com\.amazon\.ads',                        'Amazon Ads', '广告', '高'),
        (r'com\.bytedance\.',                        'ByteDance/Pangle', '广告', '高'),
        (r'com\.pangolin\.',                         'Pangle', '广告', '高'),
        (r'com\.mintegral\.',                        'Mintegral', '广告', '高'),
        (r'com\.huawei\.hms\.ads',                   'Huawei Ads', '广告', '高'),
        (r'com\.adjust\.sdk',                        'Adjust', '归因/追踪', '高'),
        (r'com\.appsflyer\.',                        'AppsFlyer', '归因/追踪', '高'),
        (r'com\.branch\.io',                         'Branch.io', '深度链接', '中'),
        (r'com\.kochava\.',                          'Kochava', '归因/追踪', '高'),
        (r'com\.tenjin\.',                           'Tenjin', '归因/追踪', '高'),
        (r'com\.singular\.',                         'Singular', '归因/追踪', '高'),
        # ─── 分析/统计 ───
        (r'com\.google\.firebase\.analytics',        'Firebase Analytics', '分析', '中'),
        (r'com\.google\.firebase\.',                 'Firebase SDK', '云服务', '中'),
        (r'com\.google\.analytics',                  'Google Analytics', '分析', '中'),
        (r'com\.mixpanel\.',                         'Mixpanel', '分析', '中'),
        (r'com\.amplitude\.',                        'Amplitude', '分析', '中'),
        (r'com\.flurry\.',                           'Flurry', '分析', '中'),
        (r'com\.localytics\.',                       'Localytics', '分析', '中'),
        (r'com\.countly\.',                          'Countly', '分析', '中'),
        (r'com\.segment\.',                          'Segment', '分析', '中'),
        (r'com\.sentry\.',                           'Sentry', '错误追踪', '低'),
        (r'io\.sentry\.',                            'Sentry', '错误追踪', '低'),
        (r'com\.bugsnag\.',                          'Bugsnag', '错误追踪', '低'),
        (r'com\.fabric\.',                           'Fabric/Crashlytics', '分析', '中'),
        (r'com\.crashlytics\.',                      'Crashlytics', '错误追踪', '低'),
        (r'com\.newrelic\.',                         'New Relic', 'APM', '中'),
        (r'com\.datadog\.',                          'Datadog', 'APM', '中'),
        (r'com\.dynatrace\.',                        'Dynatrace', 'APM', '中'),
        (r'com\.appdynamics\.',                      'AppDynamics', 'APM', '中'),
        (r'com\.umeng\.',                            'Umeng/友盟', '分析', '高'),
        (r'com\.tencent\.bugly',                     'Tencent Bugly', '错误追踪', '低'),
        (r'com\.tencent\.stat',                      'Tencent Stat', '分析', '中'),
        (r'com\.baidu\.stat',                        'Baidu Stat', '分析', '中'),
        # ─── 推送/消息 ───
        (r'com\.google\.firebase\.messaging',        'Firebase FCM', '推送', '中'),
        (r'com\.huawei\.hms\.push',                  'Huawei Push', '推送', '中'),
        (r'com\.xiaomi\.push',                       'Xiaomi Push', '推送', '中'),
        (r'com\.meizu\.push',                        'Meizu Push', '推送', '中'),
        (r'com\.oppo\.push',                         'OPPO Push', '推送', '中'),
        (r'com\.vivo\.push',                         'Vivo Push', '推送', '中'),
        (r'com\.igexin\.push',                       'GeTui Push', '推送', '中'),
        (r'com\.jpush\.',                            'JPush', '推送', '中'),
        (r'io\.jpush\.',                             'JPush', '推送', '中'),
        (r'cn\.jpush\.',                             'JPush', '推送', '中'),
        (r'com\.tencent\.tpns',                      'Tencent TPNS', '推送', '中'),
        (r'com\.baidu\.push',                        'Baidu Push', '推送', '中'),
        (r'com\.oneplus\.push',                      'OnePlus Push', '推送', '中'),
        (r'com\.onesignal\.',                        'OneSignal', '推送', '中'),
        # ─── 支付 ───
        (r'com\.google\.android\.gms\.wallet',       'Google Pay', '支付', '中'),
        (r'com\.google\.android\.gms\.pay',          'Google Pay', '支付', '中'),
        (r'com\.stripe\.',                           'Stripe', '支付', '中'),
        (r'com\.braintree\.',                        'Braintree', '支付', '中'),
        (r'com\.paypal\.',                           'PayPal', '支付', '中'),
        (r'com\.alipay\.',                           'Alipay', '支付', '中'),
        (r'com\.alibaba\.walle',                     'Alibaba Walle', '支付', '中'),
        (r'com\.tencent\.mmpay',                     'WeChat Pay', '支付', '中'),
        (r'com\.unionpay\.',                         'UnionPay', '支付', '中'),
        (r'com\.squareup\.',                         'Square', '支付', '中'),
        # ─── 社交/登录 ───
        (r'com\.google\.android\.gms\.auth',         'Google Auth', '登录', '中'),
        (r'com\.facebook\.login',                    'Facebook Login', '登录', '中'),
        (r'com\.tencent\.connect',                   'Tencent QQ', '社交', '中'),
        (r'com\.tencent\.mm',                        'WeChat SDK', '社交', '中'),
        (r'com\.sina\.weibo',                        'Sina Weibo', '社交', '中'),
        (r'com\.alibaba\.android',                   'Alibaba SDK', '电商', '中'),
        (r'com\.taobao\.',                           'Taobao SDK', '电商', '中'),
        (r'io\.agora\.',                             'Agora/声网', 'RTC', '低'),
        (r'com\.twilio\.',                           'Twilio', '通信', '低'),
        (r'com\.sendbird\.',                         'Sendbird', '聊天', '低'),
        # ─── 地图/LBS ───
        (r'com\.google\.android\.gms\.maps',         'Google Maps', '地图', '低'),
        (r'com\.google\.android\.gms\.location',     'Google Location', '位置', '中'),
        (r'com\.baidu\.location',                    'Baidu Location', '位置', '中'),
        (r'com\.baidu\.mapapi',                      'Baidu Maps', '地图', '低'),
        (r'com\.amap\.',                             'AMap/高德', '地图', '低'),
        (r'com\.tencent\.map',                       'Tencent Maps', '地图', '低'),
        # ─── 加固/保护 ───
        (r'com\.tencent\.legacy',                    'Tencent Legu', '加固', '低'),
        (r'com\.tencent\.stub',                      'Tencent Stub', '加固', '低'),
        (r'com\.qihoo\.',                            'Qihoo 360', '加固', '低'),
        (r'com\.shell\.',                            'Shell', '加固壳', '低'),
        (r'com\.stub\.',                             'Stub', '加固壳', '低'),
        (r'com\.secneo\.',                           'SecNeo', '加固', '低'),
        (r'com\.netease\.',                          'Netease', '加固', '低'),
        (r'com\.dptsec\.',                           'Dptsec', '加固', '低'),
        # ─── 其他常见 ───
        (r'com\.squareup\.okhttp',                   'OkHttp', '网络', '低'),
        (r'com\.squareup\.picasso',                  'Picasso', '图片', '低'),
        (r'com\.facebook\.fresco',                   'Fresco', '图片', '低'),
        (r'com\.bumptech\.glide',                    'Glide', '图片', '低'),
        (r'com\.google\.gson',                       'Gson', 'JSON', '低'),
        (r'com\.google\.protobuf',                   'Protobuf', '序列化', '低'),
        (r'com\.fasterxml\.jackson',                 'Jackson', 'JSON', '低'),
        (r'io\.reactivex',                           'RxJava', '响应式', '低'),
        (r'org\.apache\.http',                       'Apache HTTP', '网络', '低'),
        (r'com\.android\.volley',                    'Volley', '网络', '低'),
        (r'com\.squareup\.retrofit',                 'Retrofit', '网络', '低'),
        (r'com\.google\.dagger',                     'Dagger', 'DI', '低'),
        (r'org\.greenrobot\.eventbus',               'EventBus', '事件', '低'),
        (r'com\.tencent\.mmkv',                      'MMKV', '存储', '低'),
        (r'com\.tencent\.tinker',                    'Tinker', '热修复', '低'),
        (r'com\.alibaba\.fastjson',                  'FastJson', 'JSON', '低'),
        (r'com\.google\.android\.gms\.',             'Google Play Services', '基础服务', '低'),
        (r'org\.chromium\.',                         'Chromium/WebView', '浏览器', '低'),
        (r'com\.android\.webview',                   'WebView', '浏览器', '低'),
    ]

    # ── 权限级联追踪: 某些SDK会请求的权限 ────────────────
    SDK_PERMISSION_MAP = {
        '广告': ['READ_PHONE_STATE', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
                'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
                'ACCESS_WIFI_STATE', 'GET_ACCOUNTS'],
        '分析': ['READ_PHONE_STATE', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
                'ACCESS_WIFI_STATE'],
        '推送': ['READ_PHONE_STATE', 'WAKE_LOCK', 'VIBRATE'],
        '位置': ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
                'ACCESS_BACKGROUND_LOCATION'],
    }

    @classmethod
    def detect_from_class_names(cls, class_names):
        """从DEX类名列表中检测SDK
        Args:
            class_names: list[str], DEX类名列表
        Returns:
            list[dict]: 检测到的SDK列表
        """
        detected = {}
        for name in class_names:
            # 转换为Java包名格式
            java_name = name.replace('/', '.').lstrip('L').rstrip(';')
            for pattern, sdk_name, category, risk in cls.SDK_SIGNATURES:
                if re.search(pattern, java_name):
                    key = (sdk_name, category)
                    if key not in detected:
                        detected[key] = {
                            'name': sdk_name,
                            'category': category,
                            'risk': risk,
                            'count': 0,
                            'samples': [],
                        }
                    detected[key]['count'] += 1
                    if len(detected[key]['samples']) < 3:
                        # 提取简短类名作为样本
                        short = java_name.split('.')[-1] if '.' in java_name else java_name
                        if short not in detected[key]['samples']:
                            detected[key]['samples'].append(short)

        result = sorted(detected.values(), key=lambda x: x['count'], reverse=True)
        return result

    @classmethod
    def detect_from_strings(cls, strings):
        """从DEX字符串中检测SDK特征（包名、URL等）"""
        detected = set()
        sdk_strings = {
            'Firebase': ['firebase', 'google-services'],
            'Facebook': ['facebook', 'fb_ad'],
            'Adjust': ['adjust', 'app_adtracking'],
            'AppsFlyer': ['appsflyer', 'apps.flyer'],
            'Umeng': ['umeng', 'analytics'],
            'Bugly': ['bugly', 'crashreport'],
            'JPush': ['jpush', 'jmessage'],
            'Alipay': ['alipay', 'alipaySdk'],
            'WeChat': ['wechat', 'wxapi', 'micromsg'],
            'Baidu': ['baidu', 'bdpush'],
            'Huawei': ['huawei', 'hms', 'pushkit'],
            'Xiaomi': ['xiaomi', 'mi_push'],
        }
        for s in strings:
            s_lower = s.lower()
            for sdk_name, keywords in sdk_strings.items():
                for kw in keywords:
                    if kw in s_lower:
                        detected.add(sdk_name)
                        break
        return sorted(detected)

    @classmethod
    def assess_privacy_risk(cls, detected_sdks, permissions):
        """基于检测到的SDK和权限列表评估隐私风险
        Returns:
            dict: { 'risk_score': int, 'risk_level': str, 'details': [] }
        """
        risk_score = 0
        details = []

        # 高SDK风险累加
        for sdk in detected_sdks:
            if sdk['risk'] == '高':
                risk_score += 15
                details.append(f"高风险SDK: {sdk['name']} ({sdk['category']})")
            elif sdk['risk'] == '中':
                risk_score += 8
                details.append(f"中风险SDK: {sdk['name']} ({sdk['category']})")

        # 权限-广告SDK关联分析
        if permissions:
            perm_set = set(p.split('.')[-1].upper() if '.' in p else p.upper()
                          for p in permissions)
            for sdk in detected_sdks:
                cat = sdk['category']
                risky_perms = cls.SDK_PERMISSION_MAP.get(cat, [])
                matched = [p for p in risky_perms if p in perm_set]
                if matched:
                    risk_score += len(matched) * 5
                    details.append(f"{sdk['name']} 请求敏感权限: {', '.join(matched)}")

        # 追踪器数量过多
        tracker_count = sum(1 for s in detected_sdks if s['category'] in ('广告', '追踪', '归因/追踪'))
        if tracker_count >= 3:
            risk_score += 20
            details.append(f"集成了 {tracker_count} 个广告/追踪SDK")

        risk_score = min(risk_score, 100)
        level = '高' if risk_score >= 60 else '中' if risk_score >= 30 else '低'

        return {
            'risk_score': risk_score,
            'risk_level': level,
            'details': details,
            'tracker_count': tracker_count if 'tracker_count' in dir() else sum(1 for s in detected_sdks if s['category'] in ('广告', '追踪', '归因/追踪')),
        }

    @classmethod
    def analyze(cls, class_names=None, strings=None, permissions=None):
        """一站式SDK检测分析
        Args:
            class_names: list[str], 类名列表
            strings: list[str], 字符串列表
            permissions: list[str], 权限列表
        Returns:
            dict: 完整的SDK分析报告
        """
        result = {
            'sdks': [],
            'string_detected': [],
            'privacy_risk': {},
            'summary': {},
        }

        if class_names:
            result['sdks'] = cls.detect_from_class_names(class_names)

        if strings:
            result['string_detected'] = cls.detect_from_strings(strings)

        # 隐私风险评估
        result['privacy_risk'] = cls.assess_privacy_risk(result['sdks'], permissions)

        # 汇总
        categories = Counter(s['category'] for s in result['sdks'])
        result['summary'] = {
            'total_sdks': len(result['sdks']),
            'categories': dict(categories),
            'high_risk_count': sum(1 for s in result['sdks'] if s['risk'] == '高'),
            'medium_risk_count': sum(1 for s in result['sdks'] if s['risk'] == '中'),
            'low_risk_count': sum(1 for s in result['sdks'] if s['risk'] == '低'),
            'tracker_count': sum(1 for s in result['sdks'] if s['category'] in ('广告', '追踪', '归因/追踪')),
        }

        return result


# ── 快捷函数 ──────────────────────────────────────────────
def detect_sdks(class_names):
    """从类名列表检测SDK"""
    return SDKDetector.detect_from_class_names(class_names)

def analyze_sdk_privacy(class_names=None, strings=None, permissions=None):
    """一站式SDK检测与隐私风险评估"""
    return SDKDetector.analyze(class_names, strings, permissions)