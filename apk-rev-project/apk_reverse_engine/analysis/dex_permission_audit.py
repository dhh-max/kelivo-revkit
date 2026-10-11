"""DEX 权限审计分析 — 敏感权限使用/权限调用链/过度授权检测"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict


class DexPermissionAuditAnalyzer:
    """DEX 权限审计分析 — 敏感权限使用追踪/权限-API映射/过度授权评分"""

    # 敏感权限 -> 相关API模式
    SENSITIVE_PERMS = {
        'CAMERA': ['Camera', 'android.hardware.camera', 'MediaRecorder', 'takePicture'],
        'RECORD_AUDIO': ['MediaRecorder', 'AudioRecord', 'startRecording'],
        'ACCESS_FINE_LOCATION': ['LocationManager', 'FusedLocation', 'getLastKnownLocation', 'requestLocationUpdates'],
        'ACCESS_COARSE_LOCATION': ['LocationManager', 'NetworkProvider', 'getLastKnownLocation'],
        'READ_CONTACTS': ['ContactsContract', 'ContentResolver', 'query.*Contacts'],
        'WRITE_CONTACTS': ['ContactsContract', 'ContentResolver', 'insert.*Contacts'],
        'READ_SMS': ['SmsManager', 'ContentResolver', 'query.*Sms'],
        'SEND_SMS': ['SmsManager', 'sendTextMessage', 'sendMultipartTextMessage'],
        'READ_PHONE_STATE': ['TelephonyManager', 'getDeviceId', 'getImei', 'getSubscriberId'],
        'CALL_PHONE': ['Intent.*ACTION_CALL', 'TelephonyManager', 'call'],
        'READ_CALL_LOG': ['CallLog', 'ContentResolver', 'query.*Calls'],
        'WRITE_EXTERNAL_STORAGE': ['File', 'FileOutputStream', 'Environment.getExternalStorage'],
        'READ_EXTERNAL_STORAGE': ['File', 'Environment.getExternalStorage'],
        'INTERNET': ['HttpURLConnection', 'HttpClient', 'OkHttp', 'Retrofit', 'Socket', 'URL'],
        'ACCESS_NETWORK_STATE': ['ConnectivityManager', 'NetworkInfo', 'getActiveNetworkInfo'],
        'ACCESS_WIFI_STATE': ['WifiManager', 'getConnectionInfo', 'getScanResults'],
        'BLUETOOTH': ['BluetoothAdapter', 'BluetoothDevice', 'BluetoothSocket'],
        'BLUETOOTH_ADVERTISE': ['BluetoothLeAdvertiser', 'startAdvertising'],
        'BODY_SENSORS': ['SensorManager', 'Sensor.TYPE_HEART_RATE'],
        'READ_CALENDAR': ['CalendarContract', 'ContentResolver', 'query.*Events'],
        'WRITE_CALENDAR': ['CalendarContract', 'ContentResolver', 'insert.*Events'],
        'PROCESS_OUTGOING_CALLS': ['BroadcastReceiver', 'NEW_OUTGOING_CALL'],
        'USE_BIOMETRIC': ['BiometricManager', 'BiometricPrompt', 'authenticate'],
        'ACTIVITY_RECOGNITION': ['ActivityRecognitionClient', 'ActivityRecognitionResult'],
        'MANAGE_EXTERNAL_STORAGE': ['Environment.isExternalStorageManager', 'MANAGE_EXTERNAL_STORAGE'],
        'QUERY_ALL_PACKAGES': ['PackageManager', 'getInstalledPackages', 'queryIntentActivities'],
        'POST_NOTIFICATIONS': ['NotificationManager', 'NotificationChannel', 'notify'],
        'READ_MEDIA_IMAGES': ['MediaStore.Images', 'ContentResolver', 'query.*Images'],
        'READ_MEDIA_VIDEO': ['MediaStore.Video', 'ContentResolver', 'query.*Video'],
        'READ_MEDIA_AUDIO': ['MediaStore.Audio', 'ContentResolver', 'query.*Audio'],
    }

    # 危险权限组合（过度授权指标）
    DANGEROUS_COMBOS = [
        ('CAMERA', 'RECORD_AUDIO', '录音+摄像头 — 监控风险'),
        ('ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', '精确+粗略定位 — 过度定位'),
        ('READ_CONTACTS', 'READ_CALL_LOG', '通讯录+通话记录 — 隐私聚合'),
        ('READ_SMS', 'SEND_SMS', '短信读写 — 短信拦截风险'),
        ('READ_PHONE_STATE', 'READ_SMS', '设备信息+短信 — 设备指纹'),
        ('CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION', '摄像头+录音+定位 — 全面监控'),
    ]

    @staticmethod
    def analyze(dex_parser, manifest_permissions=None):
        """分析 DEX 权限使用特征"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()
        if not class_defs:
            return {'error': '无类定义数据'}

        # 权限使用统计
        perm_usage = Counter()          # 权限 -> 使用次数
        perm_api_map = defaultdict(list)  # 权限 -> 相关API/类
        perm_classes = defaultdict(set)   # 权限 -> 使用类
        total_methods = 0
        methods_with_perm = 0

        # 扫描每个类中的方法
        for cd in class_defs:
            cls_name = cd.get('class_name', '')
            for m in (cd.get('direct_methods', []) + cd.get('virtual_methods', [])):
                total_methods += 1
                code = m.get('code')
                if not code or isinstance(code, dict) and 'error' in code:
                    continue
                method_used_perm = False
                for perm, patterns in DexPermissionAuditAnalyzer.SENSITIVE_PERMS.items():
                    # 简化：检查方法名和代码中的类型引用
                    method_text = f"{m.get('name', '')} {m.get('proto', {})}"
                    code_text = str(code)
                    combined = method_text + ' ' + code_text
                    for pat in patterns:
                        if pat.lower() in combined.lower():
                            perm_usage[perm] += 1
                            perm_api_map[perm].append(pat)
                            perm_classes[perm].add(cls_name)
                            method_used_perm = True
                            break
                if method_used_perm:
                    methods_with_perm += 1

        # 如果传入了Manifest权限，做交叉引用分析
        declared_perms = set(manifest_permissions or [])
        used_perms = set(perm_usage.keys())
        undeclared_used = used_perms - declared_perms   # 使用但未声明
        declared_unused = declared_perms - used_perms    # 声明但未使用

        # 危险权限组合检测
        dangerous_combos_found = []
        for combo in DexPermissionAuditAnalyzer.DANGEROUS_COMBOS:
            combo_perms = combo[:-1]
            combo_label = combo[-1]
            found = [p for p in combo_perms if p in used_perms]
            if len(found) >= 2:
                dangerous_combos_found.append({
                    'perms': found,
                    'description': combo_label,
                    'severity': '高' if len(found) >= 3 else '中',
                })

        # 过度授权评分
        perm_count = len(used_perms)
        sensitive_ratio = round(methods_with_perm / max(total_methods, 1) * 100, 2)
        undeclared_count = len(undeclared_used)
        combo_penalty = len(dangerous_combos_found) * 15

        over_privilege_score = min(100, int(
            min(perm_count * 5, 30) +
            min(sensitive_ratio * 2, 25) +
            min(undeclared_count * 10, 25) +
            combo_penalty
        ))

        if over_privilege_score >= 60:
            privilege_level = '严重过度授权'
        elif over_privilege_score >= 30:
            privilege_level = '中度过度授权'
        else:
            privilege_level = '正常'

        # 权限类别分布
        category_map = {
            '定位': ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION'],
            '摄像头/录音': ['CAMERA', 'RECORD_AUDIO'],
            '通讯录/短信/通话': ['READ_CONTACTS', 'WRITE_CONTACTS', 'READ_SMS', 'SEND_SMS', 'READ_PHONE_STATE', 'CALL_PHONE', 'READ_CALL_LOG', 'PROCESS_OUTGOING_CALLS'],
            '存储': ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'MANAGE_EXTERNAL_STORAGE'],
            '网络': ['INTERNET', 'ACCESS_NETWORK_STATE', 'ACCESS_WIFI_STATE'],
            '传感器/生物': ['BODY_SENSORS', 'USE_BIOMETRIC', 'ACTIVITY_RECOGNITION'],
            '通知/日历': ['POST_NOTIFICATIONS', 'READ_CALENDAR', 'WRITE_CALENDAR'],
            '蓝牙': ['BLUETOOTH', 'BLUETOOTH_ADVERTISE'],
            '媒体文件': ['READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_AUDIO'],
            '包管理': ['QUERY_ALL_PACKAGES'],
        }
        perm_categories = {}
        for cat, perms in category_map.items():
            count = sum(perm_usage.get(p, 0) for p in perms if p in used_perms)
            if count > 0:
                perm_categories[cat] = count

        return {
            'total_methods': total_methods,
            'methods_with_perm_access': methods_with_perm,
            'sensitive_perm_ratio': f'{sensitive_ratio}%',
            'perm_count': perm_count,
            'perm_usage': dict(perm_usage.most_common()),
            'perm_categories': perm_categories,
            'top_perm_api_map': {perm: list(set(apis))[:5] for perm, apis in
                                  sorted(perm_api_map.items(), key=lambda x: perm_usage[x[0]], reverse=True)[:10]},
            'top_perm_classes': {perm: list(cls_set)[:5] for perm, cls_set in
                                  sorted(perm_classes.items(), key=lambda x: perm_usage[x[0]], reverse=True)[:10]},
            'declared_perm_count': len(declared_perms),
            'declared_perm_list': sorted(declared_perms) if declared_perms else [],
            'undeclared_used_perms': sorted(undeclared_used),
            'declared_unused_perms': sorted(declared_unused),
            'dangerous_combos': dangerous_combos_found,
            'over_privilege_score': over_privilege_score,
            'privilege_level': privilege_level,
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'perm_count': result['perm_count'],
            'sensitive_perm_ratio': result['sensitive_perm_ratio'],
            'over_privilege_score': result['over_privilege_score'],
            'privilege_level': result['privilege_level'],
            'undeclared_used_count': len(result['undeclared_used_perms']),
            'dangerous_combo_count': len(result['dangerous_combos']),
        }