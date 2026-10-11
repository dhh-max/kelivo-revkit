"""API 调用统计 — 统计 DEX 中各种 API 的使用频率和分布"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
import re
from collections import Counter, defaultdict

# API 分类规则
API_CATEGORIES = {
    '网络通信': [
        r'okhttp3\.', r'retrofit2\.', r'com\.android\.volley',
        r'java\.net\.HttpURLConnection', r'java\.net\.URL',
        r'java\.net\.Socket', r'javax\.net\.ssl\.',
        r'android\.webview\.WebView', r'WebSocket',
        r'org\.apache\.http', r'cn\.leaq\.goood_http',
    ],
    '数据存储': [
        r'android\.database\.sqlite', r'android\.content\.SharedPreferences',
        r'java\.io\.File', r'java\.io\.FileInputStream', r'java\.io\.FileOutputStream',
        r'android\.content\.OpenFile', r'realm\.', r'greenrobot\.',
        r'androidx\.room\.', r'dao\.',
    ],
    '设备标识': [
        r'TelephonyManager', r'getDeviceId', r'getImei', r'getMeid',
        r'getSubscriberId', r'getLine1Number', r'getSimSerialNumber',
        r'android\.provider\.Settings\$Secure', r'android\.os\.Build',
        r'getAndroidId', r'ANDROID_ID',
    ],
    '位置服务': [
        r'LocationManager', r'FusedLocationProviderClient',
        r'getLastKnownLocation', r'requestLocationUpdates',
        r'getLatitude', r'getLongitude', r'Geocoder',
        r'com\.amap\.api\.location', r'com\.baidu\.location',
        r'com\.google\.android\.gms\.location',
    ],
    '加密/安全': [
        r'javax\.crypto\.', r'java\.security\.',
        r'android\.keystore\.', r'android\.security\.KeyChain',
        r'AES', r'RSA', r'DES', r'SHA', r'MD5', r'HMAC',
        r'BouncyCastle', r'org\.spongycastle',
    ],
    'UI/视图': [
        r'android\.widget\.', r'android\.view\.',
        r'androidx\.recyclerview', r'androidx\.viewpager',
        r'com\.google\.android\.material',
        r'androidx\.constraintlayout', r'androidx\.compose',
    ],
    '日志/调试': [
        r'android\.util\.Log', r'java\.util\.logging',
        r'println', r'printStackTrace',
        r'org\.slf4j\.', r'org\.apache\.commons\.logging',
    ],
    '反射': [
        r'java\.lang\.reflect\.', r'Class\.forName', r'getMethod',
        r'getDeclaredMethod', r'setAccessible', r'invoke',
        r'getDeclaredField', r'getField',
    ],
    '序列化': [
        r'java\.io\.Serializable', r'Parcelable',
        r'writeToParcel', r'CREATOR',
        r'Gson', r'Moshi', r'Jackson', r'kotlinx\.serialization',
        r'fastjson', r'com\.alibaba\.fastjson',
    ],
    '线程/异步': [
        r'Thread', r'Runnable', r'AsyncTask',
        r'ExecutorService', r'ThreadPoolExecutor',
        r'kotlinx\.coroutines', r'rx\.java\.', r'io\.reactivex\.',
        r'Handler', r'Looper', r'CountDownLatch',
    ],
    'JNI/Native': [
        r'System\.loadLibrary', r'System\.load',
        r'native\s+\w+', r'JNI', r'native-lib',
    ],
    '多媒体': [
        r'MediaPlayer', r'MediaRecorder', r'AudioRecord',
        r'Camera', r'ExifInterface', r'MediaStore',
        r'VideoView', r'SurfaceView', r'TextureView',
    ],
    '服务/组件': [
        r'StartService', r'startActivity', r'sendBroadcast',
        r'registerReceiver', r'ContentResolver',
        r'ContentProvider', r'ActivityThread',
    ],
}

# 反射模式
REFLECTION_PATTERNS = [
    r'Class\.forName\(',
    r'getDeclaredMethod\(',
    r'getMethod\(',
    r'setAccessible\(',
    r'\.invoke\(',
    r'getDeclaredField\(',
    r'getField\(',
    r'Constructor',
    r'newInstance\(',
]

class ApiUsageAnalyzer:
    """API 调用统计分析引擎"""

    @staticmethod
    def analyze(dex_strings_list):
        """
        分析 DEX 字符串中的 API 使用情况
        Args:
            dex_strings_list: list of (dex_name, [strings])
        Returns:
            dict: {categories, top_apis, reflection_usage, summary}
        """
        category_hits = defaultdict(list)
        all_string_counter = Counter()
        reflection_hits = []

        for dex_name, strings in dex_strings_list:
            for s in strings:
                all_string_counter[s] += 1
                # 检查 API 分类
                for cat, patterns in API_CATEGORIES.items():
                    for pat in patterns:
                        if re.search(pat, s):
                            category_hits[cat].append({
                                'string': s[:200],
                                'dex': dex_name,
                                'pattern': pat,
                            })
                            break
                # 检查反射
                for pat in REFLECTION_PATTERNS:
                    if re.search(pat, s):
                        reflection_hits.append({
                            'string': s[:200],
                            'dex': dex_name,
                            'pattern': pat,
                        })

        # 统计每个分类
        categories = []
        for cat in sorted(category_hits.keys(), key=lambda c: len(category_hits[c]), reverse=True):
            hits = category_hits[cat]
            unique_apis = set(h['string'] for h in hits)
            categories.append({
                'category': cat,
                'total_hits': len(hits),
                'unique_apis': len(unique_apis),
                'top_strings': list(unique_apis)[:10],
            })

        # 最频繁出现的字符串（可能是热点 API）
        top_apis = []
        for s, count in all_string_counter.most_common(50):
            if len(s) > 5 and any(c.isalpha() for c in s):
                top_apis.append({
                    'string': s[:200],
                    'count': count,
                })

        return {
            'categories': categories,
            'top_apis': top_apis[:20],
            'reflection': {
                'total': len(reflection_hits),
                'unique': len(set(h['string'] for h in reflection_hits)),
                'samples': reflection_hits[:10],
            },
            'summary': {
                'total_strings': sum(all_string_counter.values()),
                'unique_strings': len(all_string_counter),
                'categories_detected': len(categories),
                'reflection_detected': len(reflection_hits),
                'top_category': categories[0]['category'] if categories else '无',
            }
        }
