"""DEX 第三方库/框架分析 — SDK识别/库版本/库混淆/依赖评估"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict
import re


class DexLibAnalysisAnalyzer:
    """DEX 第三方库/框架深度分析 — SDK识别/库签名/版本检测/依赖膨胀评分"""

    # 知名SDK/库签名
    KNOWN_LIBS = {
        # 广告/分析
        'com.google.android.gms.ads': 'Google AdMob',
        'com.google.ads': 'Google Ads (旧版)',
        'com.facebook.ads': 'Facebook Audience Network',
        'com.facebook.ads.internal': 'Facebook Audience Network (内部)',
        'com.vungle.warren': 'Vungle',
        'com.applovin': 'AppLovin',
        'com.unity3d.ads': 'Unity Ads',
        'com.ironsource': 'IronSource',
        'com.chartboost': 'Chartboost',
        'com.startapp': 'StartApp',
        'com.inmobi': 'InMobi',
        'com.mopub': 'MoPub (已弃用)',
        'com.tapjoy': 'Tapjoy',
        'com.adcolony': 'AdColony',
        'com.bytedance.sdk': 'Pangle/穿山甲',
        'com.bytedance': '字节跳动SDK',
        'com.qq.e': '腾讯优量汇',
        'com.baidu.mobads': '百度广告',
        'com.xiaomi.ad': '小米广告',
        'com.huawei.hms.ads': '华为广告',

        # 推送
        'com.google.firebase.messaging': 'Firebase Cloud Messaging',
        'com.huawei.hms.push': '华为推送',
        'com.xiaomi.push': '小米推送',
        'com.meizu.push': '魅族推送',
        'com.igexin': '个推',
        'com.umeng.message': '友盟推送',
        'cn.jpush': '极光推送',
        'com.vivo.push': 'Vivo推送',
        'com.oppo.push': 'OPPO推送',

        # 社交/登录
        'com.tencent.mm.opensdk': '微信SDK',
        'com.tencent.connect': 'QQ/腾讯开放平台',
        'com.tencent.tauth': 'QQ登录',
        'com.weibo.sdk': '微博SDK',
        'com.google.android.gms.auth': 'Google登录',
        'com.facebook.login': 'Facebook登录',
        'com.facebook.share': 'Facebook分享',
        'com.apple.android': 'Apple登录',
        'com.alipay': '支付宝SDK',
        'com.alibaba.baichuan': '阿里巴巴百川',
        'com.paypal': 'PayPal',

        # 地图
        'com.google.android.gms.maps': 'Google Maps',
        'com.amap.api': '高德地图',
        'com.baidu.map': '百度地图',
        'com.tencent.map': '腾讯地图',
        'com.mapbox': 'Mapbox',

        # 网络/HTTP
        'com.squareup.okhttp': 'OkHttp',
        'com.squareup.retrofit': 'Retrofit',
        'io.reactivex': 'RxJava',
        'io.reactivex.rxjava3': 'RxJava 3',
        'org.apache.http': 'Apache HttpClient',
        'com.android.volley': 'Volley',
        'com.loopj.android': 'AsyncHttpClient',
        'com.koushikdutta': 'Ion/Async',

        # JSON/序列化
        'com.google.gson': 'Gson',
        'com.fasterxml.jackson': 'Jackson',
        'com.alibaba.fastjson': 'FastJson',
        'org.json': 'org.json (内置)',
        'com.google.protobuf': 'Protobuf',
        'org.msgpack': 'MessagePack',

        # 图片/UI
        'com.bumptech.glide': 'Glide',
        'com.squareup.picasso': 'Picasso',
        'com.facebook.drawee': 'Fresco',
        'com.facebook.imagepipeline': 'Fresco ImagePipeline',
        'com.nostra13.universalimageloader': 'Universal Image Loader',
        'com.github.bumptech.glide': 'Glide (GitHub)',
        'androidx.compose': 'Jetpack Compose',
        'com.airbnb.lottie': 'Lottie',
        'com.google.android.material': 'Material Design',
        'com.taobao.android': '淘宝/千牛/Weex',
        'com.facebook.react': 'React Native',
        'io.flutter': 'Flutter',
        'org.jetbrains.compose': 'Compose Multiplatform',
        'com.jakewharton': 'ButterKnife/JakeWharton',
        'com.jakewharton.rxbinding': 'RxBinding',
        'com.jakewharton.threetenabp': 'ThreeTenABP',
        'com.jakewharton.timber': 'Timber',

        # 数据库
        'androidx.room': 'Room',
        'org.greenrobot.greendao': 'GreenDAO',
        'com.j256.ormlite': 'ORMLite',
        'io.objectbox': 'ObjectBox',
        'com.squareup.sqlbrite': 'SQLBrite',
        'com.tencent.wcdb': 'WCDB (微信)',
        'org.litepal': 'LitePal',
        'com.google.firebase.firestore': 'Firebase Firestore',
        'com.google.firebase.database': 'Firebase Realtime DB',

        # DI/框架
        'dagger': 'Dagger',
        'dagger.hilt': 'Hilt',
        'com.google.inject': 'Guice',
        'org.koin': 'Koin',
        'javax.inject': 'JSR-330 Inject',

        # 事件总线
        'org.greenrobot.eventbus': 'EventBus',
        'com.squareup.otto': 'Otto (已弃用)',
        'io.reactivex.rxbus': 'RxBus',

        # 性能/监控
        'com.squareup.leakcanary': 'LeakCanary',
        'com.facebook.stetho': 'Stetho',
        'com.google.firebase.crashlytics': 'Firebase Crashlytics',
        'com.google.firebase.analytics': 'Firebase Analytics',
        'com.google.firebase.perf': 'Firebase Performance',
        'com.tencent.bugly': 'Bugly',
        'com.umeng.analytics': '友盟统计',
        'com.sensorsdata.analytics': '神策数据',
        'com.baidu.mobstat': '百度统计',
        'com.talkingdata': 'TalkingData',
        'com.tencent.stat': '腾讯移动分析',

        # 工具
        'org.apache.commons': 'Apache Commons',
        'com.google.common': 'Guava',
        'com.google.guava': 'Guava',
        'org.jetbrains.kotlin': 'Kotlin Stdlib',
        'kotlin': 'Kotlin',
        'com.google.zxing': 'ZXing (二维码)',
        'com.journeyapps': 'ZXing Android Embedded',
        'com.google.mlkit': 'ML Kit',
        'com.tensorflow': 'TensorFlow Lite',
        'org.opencv': 'OpenCV',
        'com.tencent.sonic': '腾讯Sonic',
        'com.tencent.tinker': 'Tinker (热修复)',
        'com.meituan.robust': 'Robust (热修复)',
        'com.didichuxing': '滴滴出行SDK',
        'com.netflix': 'Netflix SDK',
        'com.tencent.mars': 'Mars (微信终端)',
        'com.tencent.xweb': 'X5 WebView',
        'org.chromium': 'Chromium WebView',
        'com.nvidia': 'NVIDIA',
        'com.qualcomm': 'Qualcomm',
        'com.mediatek': 'MediaTek',
    }

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 第三方库依赖"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        if not class_defs:
            return {'error': '无类定义数据'}

        # 提取所有类名
        all_class_names = [cd.get('class_name', '') for cd in class_defs]

        # 检测已知库
        detected_libs = Counter()
        lib_class_map = defaultdict(list)
        total_classes = len(all_class_names)

        # 按包名分组统计
        pkg_counter = Counter()
        for cls_name in all_class_names:
            parts = cls_name.split('/')
            if len(parts) >= 3:
                pkg = '/'.join(parts[:3])
                pkg_counter[pkg] += 1

        # 检查已知库签名
        for cls_name in all_class_names:
            for signature, lib_name in DexLibAnalysisAnalyzer.KNOWN_LIBS.items():
                if cls_name.startswith(signature) or cls_name.startswith('L' + signature.replace('.', '/')):
                    detected_libs[lib_name] += 1
                    lib_class_map[lib_name].append(cls_name)
                    break

        # 检测未知大型包（>=5个类）作为潜在第三方库
        unknown_large_pkgs = []
        for pkg, count in pkg_counter.most_common(50):
            if count >= 5:
                # 检查是否已被已知库覆盖
                is_known = False
                for lib_name in detected_libs:
                    lib_sig = lib_name.lower().replace(' ', '')
                    if lib_sig[:6] in pkg.lower():
                        is_known = True
                        break
                if not is_known:
                    unknown_large_pkgs.append({'package': pkg, 'class_count': count})

        # 按类别统计SDK
        category_map = {
            '广告/变现': ['AdMob', 'Facebook', 'Vungle', 'AppLovin', 'Unity Ads', 'IronSource',
                       'Chartboost', 'StartApp', 'InMobi', 'MoPub', 'Tapjoy', 'AdColony',
                       'Pangle', '字节跳动SDK', '腾讯优量汇', '百度广告', '小米广告', '华为广告'],
            '推送': ['Firebase', '华为推送', '小米推送', '魅族推送', '个推', '友盟推送', '极光推送', 'Vivo推送', 'OPPO推送'],
            '社交/登录': ['微信SDK', 'QQ', '微博SDK', 'Google登录', 'Facebook登录', 'Apple登录', '支付宝SDK', 'PayPal'],
            '地图': ['Google Maps', '高德地图', '百度地图', '腾讯地图', 'Mapbox'],
            '网络': ['OkHttp', 'Retrofit', 'RxJava', 'Apache HttpClient', 'Volley', 'AsyncHttpClient'],
            'JSON/序列化': ['Gson', 'Jackson', 'FastJson', 'Protobuf', 'MessagePack'],
            '图片/UI': ['Glide', 'Picasso', 'Fresco', 'Universal Image Loader', 'Lottie', 'Material Design',
                      'Jetpack Compose', 'React Native', 'Flutter', 'Compose Multiplatform'],
            '数据库': ['Room', 'GreenDAO', 'ORMLite', 'ObjectBox', 'WCDB', 'LitePal', 'Firebase Firestore'],
            'DI/框架': ['Dagger', 'Hilt', 'Guice', 'Koin'],
            '性能/监控': ['LeakCanary', 'Stetho', 'Firebase Crashlytics', 'Firebase Analytics', 'Bugly',
                       '友盟统计', '神策数据', '百度统计', 'TalkingData'],
            '工具': ['Guava', 'Apache Commons', 'Kotlin', 'ZXing', 'ML Kit', 'TensorFlow Lite', 'OpenCV'],
        }

        lib_categories = {}
        seen_libs = set()
        for cat, libs in category_map.items():
            count = sum(detected_libs.get(l, 0) for l in libs if l in detected_libs)
            names = [l for l in libs if l in detected_libs]
            if count > 0:
                lib_categories[cat] = {'count': count, 'libs': names}

        # 第三方库占比
        total_lib_classes = sum(detected_libs.values())
        lib_ratio = round(total_lib_classes / max(total_classes, 1) * 100, 2)

        # 依赖膨胀评分
        lib_count = len(detected_libs)
        large_libs = sum(1 for c in detected_libs.values() if c >= 50)
        lib_ratio_score = min(40, int(lib_ratio * 0.8))
        lib_count_score = min(30, lib_count * 3)
        large_lib_penalty = min(30, large_libs * 10)

        bloat_score = min(100, lib_ratio_score + lib_count_score + large_lib_penalty)
        if bloat_score >= 60:
            bloat_level = '严重膨胀'
        elif bloat_score >= 30:
            bloat_level = '中度膨胀'
        else:
            bloat_level = '精炼'

        # 检测库混淆迹象（包名被重命名但类数过多）
        obfuscation_indicators = 0
        common_obf_pkgs = ['a/a/', 'b/b/', 'c/c/', 'a/b/', 'b/a/']
        for pkg, count in pkg_counter.most_common(20):
            if any(pkg.startswith(op) for op in common_obf_pkgs) and count >= 10:
                obfuscation_indicators += 1

        return {
            'total_classes': total_classes,
            'total_lib_classes': total_lib_classes,
            'lib_ratio': f'{lib_ratio}%',
            'lib_count': lib_count,
            'detected_libs': dict(detected_libs.most_common()),
            'lib_categories': lib_categories,
            'top_unknown_pkgs': unknown_large_pkgs[:15],
            'bloat_score': bloat_score,
            'bloat_level': bloat_level,
            'obfuscation_indicators': obfuscation_indicators,
            'top5_libs': [{'name': name, 'classes': count} for name, count in detected_libs.most_common(5)],
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'lib_count': result['lib_count'],
            'lib_ratio': result['lib_ratio'],
            'bloat_score': result['bloat_score'],
            'bloat_level': result['bloat_level'],
            'total_lib_classes': result['total_lib_classes'],
            'top5_libs': result['top5_libs'],
        }