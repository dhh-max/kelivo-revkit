#!/usr/bin/env python3
"""核心类定位器 - 通过多维度启发式算法自动定位 DEX 中的核心入口类"""

import re
from collections import defaultdict

# ── 核心类名称模式（权重由高到低） ──────────────────────────
CORE_NAME_PATTERNS = [
    # Application 入口类（最高权重）
    (r'^L.*/Application;$', 100),
    (r'^L.*/App;$', 95),
    (r'^L.*/MainApplication;$', 100),
    (r'^L.*/BaseApplication;$', 90),
    # Activity 入口
    (r'^L.*/MainActivity;$', 80),
    (r'^L.*/SplashActivity;$', 70),
    (r'^L.*/HomeActivity;$', 70),
    (r'^L.*/Launcher.*Activity;$', 75),
    # 核心框架类
    (r'^L.*/Core;', 85),
    (r'^L.*/Manager;', 60),
    (r'^L.*/Engine;', 65),
    (r'^L.*/Helper;', 40),
    (r'^L.*/Utils;$', 30),
    # 常见核心后缀
    (r'^L.*/(SDK|Sdk|Api|API|Client|Bridge|Proxy|Facade|Router|Dispatcher|Bootstrap|Initializer|Context|Session|Provider|Factory|Builder|Database|DB|Service|Repository|ViewModel|Presenter|Controller|Handler|Worker|Task|Job|Loader|Cache|Config|Setting|Preference|Theme|Style|Module|Plugin|Native|JNI|Bridge|Interface|Adapter|Holder|Manager|Processor|Executor|Scheduler|Registry|Container|Component|Resource|Storage|Network|Http|Socket|WebSocket|Sync|Auth|Account|Login|Share|Push|Notification|Message|Event|Tracker|Analytics|Logger|Monitor|Fetcher|Parser|Mapper|Generator|Validator|Filter|Interceptor|Pipeline|Strategy|Template|Singleton|Factory|Pool|Queue|Thread|Pool|Timer|Clock|Clock|Date|Time|Format|Codec|Cipher|Crypto|Secure|Safety|Guard|Permission|Location|Map|Media|Audio|Video|Image|Camera|Record|Player|Download|Upload|Stream|File|IO|ImageLoader|Glide|Fresco|Picasso|OkHttp|Retrofit|RxJava|Dagger|ButterKnife|EventBus|GreenDao|Realm|Room|ViewModel|LiveData|DataBinding|Navigation|WorkManager|Hilt|Koin|Coroutine|Flow|State|Store|Reducer|Middleware|Effect|Selector|Action|Dispatch|Connect|Module|Component|Scope|Feature|Page|Fragment|Dialog|Toast|Snackbar|Banner|Tab|Menu|Drawer|Toolbar|ActionBar|StatusBar|NavigationBar|Recycler|ListView|GridView|ViewPager|Pager|Adapter|ViewHolder|Item|Decoration|Animation|Transition|Layout|Constraint|Linear|Relative|Frame|Scroll|Nested|Coordinator|AppBar|Collapsing|Toolbar|Bottom|Top|Center|Left|Right|Fill|Wrap|Match|Weight|Gravity|Padding|Margin|Border|Shadow|Elevation|Alpha|Scale|Rotate|Translate|Fade|Slide|Bounce|Spring|Interpolator|Evaluator|Typeface|Font|Color|Drawable|Shape|Selector|StateList|Layer|Level|Clip|Inset|Scale|Bitmap|NinePatch|Vector|Animated|Ripple|Circular|Progress|Seek|Rating|Switch|Toggle|Check|Radio|Spinner|AutoComplete|MultiAuto|EditText|TextInput|AutoSize|Password|Phone|Email|Number|Date|Time|Search|WebView|VideoView|SurfaceView|TextureView|GLSurface|Camera|Texture|MediaController|MediaPlayer|ExoPlayer|IjkPlayer|AliPlayer|TencentPlayer|YoukuPlayer|Live|Stream|Record|Capture|Encoder|Decoder|Muxer|Demuxer|Extractor|Remuxer|Transcoder|Filter|Effect|Overlay|Watermark|Subtitle|Caption|TimedText|Metadata|Chapter|Segment|Dash|HLS|SS|RTMP|RTSP|HTTP|UDP|TCP|Socket|Channel|Pipe|FIFO|Queue|Stack|Deque|List|Set|Map|Tree|Graph|Node|Edge|Vertex|Path|Route|Link|Chain|Mesh|Grid|Cell|Tile|Layer|Mask|Blend|Composite|Alpha|Color|Matrix|Vector|Point|Size|Rect|Region|Path|Bezier|Curve|Line|Arc|Circle|Ellipse|Polygon|Polyline|Rectangle|Square|Triangle|Diamond|Pentagon|Hexagon|Octagon|Star|Cross|Arrow|Check|Tick|Cross|Heart|Star|Circle|Square|Triangle|Diamond|Pentagon|Hexagon|Octagon|Decagon|Dodecagon|Penta|Hexa|Hepta|Octa|Nona|Deca|Hendeca|Dodeca|Icosa|Poly|Mono|Bi|Tri|Quad|Penta|Hexa|Hepta|Octa|Nona|Deca|Multi|Semi|Full|Half|Quarter|Third|Two|Three|Four|Five|Six|Seven|Eight|Nine|Ten|Hundred|Thousand|Million|Billion|Trillion|Zillion|Infinity|Zero|One|Two|Three|Four|Five|Six|Seven|Eight|Nine|Ten|Eleven|Twelve|Thirteen|Fourteen|Fifteen|Sixteen|Seventeen|Eighteen|Nineteen|Twenty|Thirty|Forty|Fifty|Sixty|Seventy|Eighty|Ninety|Hundred|Thousand|Million|Billion|Trillion);$', 50),
]

# Android 框架组件类（入口类）
ANDROID_COMPONENT_TYPES = {
    'Landroid/app/Application;': 100,
    'Landroid/app/Activity;': 80,
    'Landroidx/fragment/app/FragmentActivity;': 80,
    'Landroidx/activity/ComponentActivity;': 75,
    'Landroid/app/Service;': 70,
    'Landroid/app/Fragment;': 60,
    'Landroidx/fragment/app/Fragment;': 60,
    'Landroid/content/BroadcastReceiver;': 65,
    'Landroid/content/ContentProvider;': 65,
    'Landroid/app/IntentService;': 60,
    'Landroid/app/JobService;': 55,
    'Landroid/app/AlarmManager;': 40,
    'Landroid/app/NotificationManager;': 40,
    'Landroid/app/KeyguardManager;': 40,
    'Landroid/app/WallpaperManager;': 40,
    'Landroid/appwidget/AppWidgetProvider;': 50,
    'Landroid/accounts/AbstractAccountAuthenticator;': 50,
    'Landroid/inputmethodservice/InputMethodService;': 50,
    'Landroid/service/notification/NotificationListenerService;': 50,
    'Landroid/service/autofill/AutofillService;': 50,
    'Landroid/service/voice/VoiceInteractionService;': 50,
    'Landroid/app/backup/BackupAgent;': 45,
    'Landroid/accessibilityservice/AccessibilityService;': 50,
    'Landroid/nfc/NfcAdapter;': 40,
    'Landroid/hardware/SensorEventListener;': 30,
}

# 常见框架类前缀（第三方SDK核心类会被忽略）
KNOWN_SDK_PREFIXES = [
    'Landroid/',
    'Landroidx/',
    'Lcom/google/',
    'Lcom/android/',
    'Ldalvik/',
    'Ljava/',
    'Ljavax/',
    'Lkotlin/',
    'Lkotlinx/',
    'Lorg/jetbrains/',
    'Lorg/apache/',
    'Lorg/json/',
    'Lorg/xml/',
    'Lorg/w3c/',
    'Lorg/junit/',
    'Lokhttp3/',
    'Lokio/',
    'Lretrofit2/',
    'Lrx/',
    'Lio/reactivex/',
    'Lcom/squareup/',
    'Lcom/facebook/',
    'Lcom/tencent/',
    'Lcom/alibaba/',
    'Lcom/taobao/',
    'Lcom/xiaomi/',
    'Lcom/huawei/',
    'Lcom/meizu/',
    'Lcom/umeng/',
    'Lcom/sina/',
    'Lcom/baidu/',
    'Lcom/qq/',
    'Lcom/wechat/',
    'Lcom/aliyun/',
    'Lcom/amap/',
    'Lcom/google/gson/',
    'Lcom/google/protobuf/',
    'Lcom/google/android/',
    'Lcom/google/common/',
    'Lcom/google/firebase/',
    'Lcom/google/ads/',
    'Lcom/google/analytics/',
    'Lcom/google/unity/',
    'Lcom/unity3d/',
    'Lcom/adobe/',
    'Lcom/amazon/',
    'Lcom/applovin/',
    'Lcom/chartboost/',
    'Lcom/vungle/',
    'Lcom/ironsource/',
    'Lcom/playhaven/',
    'Lcom/revmob/',
    'Lcom/tapjoy/',
    'Lcom/flurry/',
    'Lcom/inmobi/',
    'Lcom/mopub/',
    'Lcom/startapp/',
    'Lcom/supersonic/',
    'Lcom/vk/',
    'Lcom/yandex/',
    'Lcom/zendesk/',
    'Lcom/adjust/',
    'Lcom/appsflyer/',
    'Lcom/branch/',
    'Lcom/kochava/',
    'Lcom/mixpanel/',
    'Lcom/segment/',
    'Lcom/tune/',
    'Lcom/urbanairship/',
    'Lorg/cocos2dx/',
    'Lorg/libsdl/',
    'Lcom/badlogic/',
    # 广告/统计 SDK
    'Lcom/kwad/',
    'Lcom/anythink/',
    'Lcom/bytedance/',
    'Lcom/ss/',
    'Lcom/mintegral/',
    'Lcom/mbridge/',
    'Lcom/sigmob/',
    'Lcom/heytap/',
    'Lcom/vivo/',
    'Lcom/oppo/',
    'Lcom/bun/',
    'Lcom/iqiyi/',
    'Lcom/sankuai/',
    'Lcom/dianping/',
    'Lcom/ctrip/',
    'Lcom/didi/',
    'Lcom/gotokeep/',
    'Lcom/zhihu/',
    'Lcom/bilibili/',
    'Lcom/douyin/',
    'Lcom/kuaishou/',
    'Lcom/pinduoduo/',
    'Lcom/jd/',
    'Lcom/sohu/',
    'Lcom/sogou/',
    'Lcom/youku/',
    'Lcom/tudou/',
    'Lcom/letv/',
    'Lcom/pptv/',
    'Lcom/wasu/',
    'Lcom/mgtv/',
    'Lcom/cctv/',
    'Lcom/cnki/',
    'Lcom/kingsoft/',
    'Lcom/qihoo/',
    'Lorg/chromium/',
    'Lorg/webrtc/',
    'Lcom/google/mlkit/',
    'Lcom/google/android/gms/',
    'Lcom/google/android/play/',
    'Lcom/google/android/material/',
]


class CoreClassLocator:
    """核心类定位器 - 多维度启发式分析 DEX 中的核心类"""

    def __init__(self, dex_parser):
        self.dex = dex_parser
        self._class_defs = None
        self._all_methods = None
        self._ref_counts = None

    def _ensure_data(self):
        if self._class_defs is None:
            self._class_defs = self.dex.get_class_defs()
            self._all_methods = self.dex.get_methods()
            self._build_ref_count()

    def _build_ref_count(self):
        """统计每个类被引用的次数（在其他类的方法/字段中被引用）"""
        self._ref_counts = defaultdict(int)
        for c in self._class_defs:
            name = c['class_name']
            # 父类引用
            if c['super_name']:
                self._ref_counts[self._clean_name(c['super_name'])] += 1
            # 接口引用
            for itf in c['interfaces']:
                self._ref_counts[self._clean_name(itf)] += 1
            # 方法中引用的类
            for m in c.get('direct_methods', []):
                proto = m.get('proto', {})
                if proto:
                    for p in proto.get('parameters', []):
                        self._ref_counts[self._clean_name(p)] += 1
            for m in c.get('virtual_methods', []):
                proto = m.get('proto', {})
                if proto:
                    for p in proto.get('parameters', []):
                        self._ref_counts[self._clean_name(p)] += 1

    def _clean_name(self, name):
        """从带 flag byte 的类名中提取实际类名（从 L 开始）"""
        idx = name.find('L')
        return name[idx:] if idx >= 0 else name

    def is_known_sdk(self, class_name):
        """判断是否为已知 SDK 框架类
        
        class_name 格式: <access_flags_byte>Lpackage/Class;
        需要先提取出实际的类名部分（从 L 开始到 ; 结束）
        """
        actual_name = self._clean_name(class_name)
        for prefix in KNOWN_SDK_PREFIXES:
            if actual_name.startswith(prefix):
                return True
        return False

    def is_application_class(self, class_name):
        """判断是否为应用自有类（非 SDK）"""
        return not self.is_known_sdk(class_name)

    def score_entry_point(self, class_def):
        """评分1: 入口点分数 - 继承 Application/Activity 等组件"""
        score = 0
        super_name = class_def.get('super_name', '')
        clean_super = self._clean_name(super_name)

        # 直接匹配 Android 组件类型
        if clean_super in ANDROID_COMPONENT_TYPES:
            score += ANDROID_COMPONENT_TYPES[clean_super]

        # 递归匹配父类链（通过接口）
        for itf_name in class_def.get('interfaces', []):
            clean_itf = self._clean_name(itf_name)
            if clean_itf in ANDROID_COMPONENT_TYPES:
                score += ANDROID_COMPONENT_TYPES[clean_itf] * 0.5

        # 访问标志检查：public 类加分
        flags = class_def.get('access_flags', '')
        if 'public' in flags.lower():
            score += 5

        return score

    def score_method_volume(self, class_def):
        """评分2: 方法数量分数 - 方法越多越可能是核心类"""
        direct_count = len(class_def.get('direct_methods', []))
        virtual_count = len(class_def.get('virtual_methods', []))

        # 虚拟方法权重更高（业务逻辑）
        score = direct_count * 0.5 + virtual_count * 1.0

        # 阈值加成
        if virtual_count > 50:
            score += 20
        elif virtual_count > 20:
            score += 10
        elif virtual_count > 10:
            score += 5

        if direct_count + virtual_count > 100:
            score += 30
        elif direct_count + virtual_count > 50:
            score += 15

        return score

    def score_field_volume(self, class_def):
        """评分3: 字段数量分数"""
        static_count = len(class_def.get('static_fields', []))
        instance_count = len(class_def.get('instance_fields', []))
        score = static_count * 0.3 + instance_count * 0.5

        if instance_count > 20:
            score += 10
        elif instance_count > 10:
            score += 5

        return score

    def score_reference(self, class_name):
        """评分4: 被引用分数 - 被越多类引用越核心"""
        clean_name = self._clean_name(class_name)
        count = self._ref_counts.get(clean_name, 0)
        if count > 100:
            return 50
        elif count > 50:
            return 30
        elif count > 20:
            return 20
        elif count > 10:
            return 10
        elif count > 5:
            return 5
        return count * 0.5

    def score_name_pattern(self, class_name):
        """评分5: 名称模式分数 - 匹配核心类命名模式"""
        score = 0
        clean_name = self._clean_name(class_name)
        for pattern, weight in CORE_NAME_PATTERNS:
            if re.search(pattern, clean_name):
                score += weight
                break  # 只匹配第一个最高权重的模式

        # 短名称加成（包名深度浅的类更可能是核心）
        parts = clean_name.split('/')
        if len(parts) >= 3:
            class_simple = parts[-1].rstrip(';')
            # 首字母大写的类加分
            if class_simple and class_simple[0].isupper():
                score += 5

        return score

    def score_interface(self, class_def):
        """评分6: 接口分数 - 实现多个接口的类更核心"""
        interfaces = class_def.get('interfaces', [])
        app_interfaces = [i for i in interfaces if self.is_application_class(i)]
        return len(app_interfaces) * 5

    def score_superclass(self, class_def):
        """评分7: 父类分数 - 有意义的继承关系"""
        super_name = class_def.get('super_name', '')
        clean_super = self._clean_name(super_name)
        if not clean_super or clean_super == 'Ljava/lang/Object;':
            return 0

        # 自定义父类（非SDK）加分
        if self.is_application_class(super_name):
            return 15

        return 0

    def score_all(self, class_def):
        """综合评分 - 计算所有维度加权总分"""
        class_name = class_def['class_name']

        scores = {
            'entry_point': self.score_entry_point(class_def) * 1.5,
            'method_volume': self.score_method_volume(class_def) * 1.0,
            'field_volume': self.score_field_volume(class_def) * 0.5,
            'reference': self.score_reference(class_name) * 1.2,
            'name_pattern': self.score_name_pattern(class_name) * 1.5,
            'interface': self.score_interface(class_def) * 0.8,
            'superclass': self.score_superclass(class_def) * 1.0,
        }

        total = sum(scores.values())
        return total, scores

    def locate(self, top_n=20, min_score=10, include_sdk=False):
        """
        定位核心类，返回按综合评分排序的列表

        Args:
            top_n: 返回前N个核心类
            min_score: 最低分数阈值
            include_sdk: 是否包含SDK类

        Returns:
            [
                {
                    'rank': 1,
                    'class_name': 'Lcom/example/App;',
                    'total_score': 95.5,
                    'scores': {...},
                    'details': {...}
                },
                ...
            ]
        """
        self._ensure_data()

        results = []
        for c in self._class_defs:
            class_name = c['class_name']

            # 跳过 SDK 类（除非要求包含）
            if not include_sdk and self.is_known_sdk(class_name):
                continue

            total, scores = self.score_all(c)

            if total < min_score:
                continue

            # 提取详细信息
            super_name = c.get('super_name', '')
            interfaces = c.get('interfaces', [])
            direct_methods = c.get('direct_methods', [])
            virtual_methods = c.get('virtual_methods', [])
            static_fields = c.get('static_fields', [])
            instance_fields = c.get('instance_fields', [])

            # 简化类名（去掉L前缀和分号后缀）
            # class_name 格式为 <flag_byte>Lpackage/Class;
            clean_name = self._clean_name(class_name)
            simple_name = clean_name.lstrip('L').rstrip(';').replace('/', '.')

            # 简化父类名
            clean_super = self._clean_name(super_name)
            super_simple = clean_super.lstrip('L').rstrip(';').replace('/', '.') if super_name else ''

            results.append({
                'class_name': class_name,
                'simple_name': simple_name,
                'total_score': round(total, 1),
                'scores': {k: round(v, 1) for k, v in scores.items()},
                'details': {
                    'super_name': super_name,
                    'super_simple': super_simple,
                    'interfaces': [i.lstrip('L').rstrip(';').replace('/', '.') for i in interfaces],
                    'method_count': len(direct_methods) + len(virtual_methods),
                    'direct_methods': len(direct_methods),
                    'virtual_methods': len(virtual_methods),
                    'field_count': len(static_fields) + len(instance_fields),
                    'static_fields': len(static_fields),
                    'instance_fields': len(instance_fields),
                    'ref_count': self._ref_counts.get(self._clean_name(class_name), 0),
                    'access_flags': c.get('access_flags', ''),
                    'source_file': c.get('source_file', ''),
                }
            })

        # 按总分降序排序
        results.sort(key=lambda x: x['total_score'], reverse=True)

        # 添加排名
        for i, r in enumerate(results, 1):
            r['rank'] = i

        return results[:top_n]

    def locate_by_manifest(self, manifest_info, top_n=20):
        """
        结合 Manifest 信息定位核心类，优先标记声明的组件

        Args:
            manifest_info: get_manifest_info() 返回的字典
            top_n: 返回前N个

        Returns:
            同 locate() 格式，但附带 manifest 标记
        """
        self._ensure_data()

        # 收集 Manifest 中声明的组件类
        manifest_classes = set()
        for comp_type in ['activities', 'services', 'receivers', 'providers']:
            comps = manifest_info.get(comp_type, [])
            for c in comps:
                if isinstance(c, dict):
                    name = c.get('attrs', {}).get('name', '')
                    if name:
                        # 转成DEX内部格式
                        if name.startswith('.'):
                            pkg = manifest_info.get('package', '')
                            name = pkg + name
                        dex_name = 'L' + name.replace('.', '/') + ';'
                        manifest_classes.add(dex_name)

        # 应用包名
        app_package = manifest_info.get('package', '')

        results = []
        for c in self._class_defs:
            class_name = c['class_name']

            # 跳过 SDK 类
            if self.is_known_sdk(class_name):
                continue

            total, scores = self.score_all(c)

            # Manifest 中声明的组件强制纳入
            clean_class = self._clean_name(class_name)
            in_manifest = clean_class in manifest_classes
            if in_manifest:
                total += 30  # 大幅加分
                scores['manifest'] = 30

            if total < 5 and not in_manifest:
                continue

            # 简化类名（去掉L前缀和分号后缀）
            # class_name 格式为 <flag_byte>Lpackage/Class;
            clean_name = self._clean_name(class_name)
            simple_name = clean_name.lstrip('L').rstrip(';').replace('/', '.')

            # 简化父类名
            super_name = c.get('super_name', '')
            clean_super = self._clean_name(super_name)
            super_simple = clean_super.lstrip('L').rstrip(';').replace('/', '.') if super_name else ''

            results.append({
                'class_name': class_name,
                'simple_name': simple_name,
                'total_score': round(total, 1),
                'scores': {k: round(v, 1) for k, v in scores.items()},
                'in_manifest': in_manifest,
                'details': {
                    'super_name': super_name,
                    'super_simple': super_simple,
                    'method_count': len(c.get('direct_methods', [])) + len(c.get('virtual_methods', [])),
                    'field_count': len(c.get('static_fields', [])) + len(c.get('instance_fields', [])),
                    'ref_count': self._ref_counts.get(self._clean_name(class_name), 0),
                    'access_flags': c.get('access_flags', ''),
                    'source_file': c.get('source_file', ''),
                }
            })

        results.sort(key=lambda x: x['total_score'], reverse=True)
        for i, r in enumerate(results, 1):
            r['rank'] = i

        return results[:top_n]


def locate_core_classes(dex_data, top_n=20, min_score=10, include_sdk=False):
    """
    便捷函数：从 DEX 原始数据中定位核心类

    Args:
        dex_data: DEX 文件的二进制数据
        top_n: 返回前N个
        min_score: 最低分数
        include_sdk: 是否包含SDK类

    Returns:
        同 CoreClassLocator.locate()
    """
    from apk_reverse_engine.core.dex_parser import DexParser
    parser = DexParser(dex_data)
    locator = CoreClassLocator(parser)
    return locator.locate(top_n=top_n, min_score=min_score, include_sdk=include_sdk)


def locate_core_classes_from_apk(apk_path, top_n=20, min_score=10, include_sdk=False, use_manifest=False):
    """
    便捷函数：从 APK 中读取所有 DEX 文件并定位核心类

    Args:
        apk_path: APK 文件路径
        top_n: 每个 DEX 返回前N个
        min_score: 最低分数
        include_sdk: 是否包含SDK类
        use_manifest: 是否结合 Manifest 信息

    Returns:
        {
            'dex_files': { 'classes.dex': [...], 'classes2.dex': [...] },
            'merged': [...]  # 所有 DEX 合并排序后的结果
        }
    """
    import zipfile
    from apk_reverse_engine.core.dex_parser import DexParser
    from apk_reverse_engine.core.manifest_parser import ManifestParser

    result = {}
    all_results = []

    with zipfile.ZipFile(apk_path, 'r') as zf:
        # 获取 Manifest 信息
        manifest_info = None
        if use_manifest:
            try:
                manifest_data = zf.read('AndroidManifest.xml')
                manifest_info = ManifestParser.get_simple(manifest_data)
            except Exception:
                pass

        # 处理所有 DEX 文件
        dex_files = sorted([n for n in zf.namelist() if n.startswith('classes') and n.endswith('.dex')])
        if not dex_files:
            # 尝试直接找 .dex
            dex_files = [n for n in zf.namelist() if n.endswith('.dex')]

        for dex_name in dex_files:
            try:
                dex_data = zf.read(dex_name)
                parser = DexParser(dex_data)

                if use_manifest and manifest_info:
                    locator = CoreClassLocator(parser)
                    classes = locator.locate_by_manifest(manifest_info, top_n=top_n)
                else:
                    locator = CoreClassLocator(parser)
                    classes = locator.locate(top_n=top_n, min_score=min_score, include_sdk=include_sdk)

                for c in classes:
                    c['dex_file'] = dex_name

                result[dex_name] = classes
                all_results.extend(classes)
            except Exception as e:
                result[dex_name] = {'error': str(e)}

    # 所有 DEX 合并排序
    all_results.sort(key=lambda x: x['total_score'], reverse=True)
    for i, r in enumerate(all_results, 1):
        r['rank'] = i

    result['merged'] = all_results[:top_n]
    return result
