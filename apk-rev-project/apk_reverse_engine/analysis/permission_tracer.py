"""权限使用追溯分析 — 追踪权限在 DEX 中的实际 API 调用路径"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
import re
from collections import defaultdict

# 权限 → 对应 API 类/方法映射
PERMISSION_API_MAP = {
    'ACCESS_FINE_LOCATION': {
        'apis': ['getLastKnownLocation', 'requestLocationUpdates', 'getLatitude', 'getLongitude',
                 'LocationManager', 'FusedLocationProviderClient', 'getCurrentLocation',
                 'requestSingleLocationUpdate'],
        'desc': '精确定位',
        'severity': 'dangerous',
    },
    'ACCESS_COARSE_LOCATION': {
        'apis': ['getLastKnownLocation', 'requestLocationUpdates', 'LocationManager',
                 'FusedLocationProviderClient'],
        'desc': '粗略定位',
        'severity': 'dangerous',
    },
    'READ_CONTACTS': {
        'apis': ['ContactsContract', 'queryContacts', 'RawContacts', 'PhoneLookup',
                 'content://com.android.contacts'],
        'desc': '读取联系人',
        'severity': 'dangerous',
    },
    'WRITE_CONTACTS': {
        'apis': ['ContactsContract', 'RawContacts', 'insertContact'],
        'desc': '写入联系人',
        'severity': 'dangerous',
    },
    'READ_SMS': {
        'apis': ['SmsManager', 'Telephony.Sms', 'content://sms', 'READ_SMS'],
        'desc': '读取短信',
        'severity': 'dangerous',
    },
    'SEND_SMS': {
        'apis': ['SmsManager', 'sendTextMessage', 'sendMultipartTextMessage'],
        'desc': '发送短信',
        'severity': 'dangerous',
    },
    'RECEIVE_SMS': {
        'apis': ['SmsMessage', 'createFromPdu', 'RECEIVE_SMS'],
        'desc': '接收短信',
        'severity': 'dangerous',
    },
    'READ_CALL_LOG': {
        'apis': ['CallLog', 'CallLog$Calls', 'content://call_log'],
        'desc': '读取通话记录',
        'severity': 'dangerous',
    },
    'CAMERA': {
        'apis': ['Camera.open', 'Camera2', 'CameraManager', 'openCamera', 'takePicture',
                 'SurfaceTexture', 'ImageReader'],
        'desc': '相机',
        'severity': 'dangerous',
    },
    'RECORD_AUDIO': {
        'apis': ['MediaRecorder', 'AudioRecord', 'startRecording', 'MediaRecorder$AudioSource'],
        'desc': '录音',
        'severity': 'dangerous',
    },
    'READ_EXTERNAL_STORAGE': {
        'apis': ['Environment.getExternalStorageDirectory', 'getExternalStoragePublicDirectory',
                 'MediaStore', 'openFileInput', 'openFileOutput'],
        'desc': '读取外部存储',
        'severity': 'dangerous',
    },
    'WRITE_EXTERNAL_STORAGE': {
        'apis': ['Environment.getExternalStorageDirectory', 'getExternalStoragePublicDirectory',
                 'MediaStore', 'openFileOutput', 'FileOutputStream'],
        'desc': '写入外部存储',
        'severity': 'dangerous',
    },
    'READ_PHONE_STATE': {
        'apis': ['TelephonyManager', 'getDeviceId', 'getImei', 'getMeid', 'getSubscriberId',
                 'getLine1Number', 'getSimSerialNumber', 'getNetworkOperator'],
        'desc': '读取手机状态',
        'severity': 'dangerous',
    },
    'CALL_PHONE': {
        'apis': ['ACTION_CALL', 'ACTION_DIAL', 'startActivity.*tel:'],
        'desc': '拨打电话',
        'severity': 'dangerous',
    },
    'GET_ACCOUNTS': {
        'apis': ['AccountManager', 'getAccounts', 'getAccountsByType'],
        'desc': '获取账户列表',
        'severity': 'dangerous',
    },
    'READ_CALENDAR': {
        'apis': ['CalendarContract', 'Calendars', 'Events', 'content://com.android.calendar'],
        'desc': '读取日历',
        'severity': 'dangerous',
    },
    'BLUETOOTH_SCAN': {
        'apis': ['BluetoothAdapter', 'BluetoothLeScanner', 'startScan', 'startDiscovery'],
        'desc': '蓝牙扫描',
        'severity': 'dangerous',
    },
    'BLUETOOTH_CONNECT': {
        'apis': ['BluetoothDevice', 'BluetoothGatt', 'connectGatt', 'BluetoothSocket'],
        'desc': '蓝牙连接',
        'severity': 'dangerous',
    },
    'BODY_SENSORS': {
        'apis': ['SensorManager', 'Sensor.TYPE_HEART_RATE', 'BodySensorClient'],
        'desc': '身体传感器',
        'severity': 'dangerous',
    },
    'ACCESS_BACKGROUND_LOCATION': {
        'apis': ['requestLocationUpdates', 'FusedLocationProviderClient'],
        'desc': '后台定位',
        'severity': 'dangerous',
    },
    'SYSTEM_ALERT_WINDOW': {
        'apis': ['TYPE_APPLICATION_OVERLAY', 'TYPE_SYSTEM_ALERT', 'WindowManager$LayoutParams',
                 'addView.*FLAG'],
        'desc': '悬浮窗',
        'severity': 'dangerous',
    },
    'REQUEST_INSTALL_PACKAGES': {
        'apis': ['ACTION_INSTALL_PACKAGE', 'PackageInstaller', 'content://downloads'],
        'desc': '安装包请求',
        'severity': 'dangerous',
    },
    'READ_MEDIA_IMAGES': {
        'apis': ['MediaStore$Images', 'content://media/external/images'],
        'desc': '读取图片',
        'severity': 'dangerous',
    },
    'READ_MEDIA_VIDEO': {
        'apis': ['MediaStore$Video', 'content://media/external/video'],
        'desc': '读取视频',
        'severity': 'dangerous',
    },
    'POST_NOTIFICATIONS': {
        'apis': ['NotificationManager', 'notify', 'NotificationChannel', 'NotificationCompat'],
        'desc': '发送通知',
        'severity': 'dangerous',
    },
    # 正常权限
    'INTERNET': {
        'apis': ['HttpURLConnection', 'OkHttpClient', 'Retrofit', 'Volley', 'WebSocket',
                 'URL(', 'openConnection', 'socket'],
        'desc': '网络访问',
        'severity': 'normal',
    },
    'ACCESS_NETWORK_STATE': {
        'apis': ['ConnectivityManager', 'getActiveNetworkInfo', 'getNetworkInfo'],
        'desc': '网络状态',
        'severity': 'normal',
    },
    'ACCESS_WIFI_STATE': {
        'apis': ['WifiManager', 'getConnectionInfo', 'getScanResults'],
        'desc': 'WiFi状态',
        'severity': 'normal',
    },
    'VIBRATE': {
        'apis': ['Vibrator', 'vibrate', 'VibrationEffect'],
        'desc': '振动',
        'severity': 'normal',
    },
    'WAKE_LOCK': {
        'apis': ['PowerManager', 'WakeLock', 'newWakeLock', 'acquire'],
        'desc': '唤醒锁',
        'severity': 'normal',
    },
    'FOREGROUND_SERVICE': {
        'apis': ['startForeground', 'startForegroundService', 'Service.startForeground'],
        'desc': '前台服务',
        'severity': 'normal',
    },
    'NFC': {
        'apis': ['NfcAdapter', 'enableForegroundDispatch', 'Tag', 'NdefMessage'],
        'desc': 'NFC',
        'severity': 'normal',
    },
    'CHANGE_WIFI_STATE': {
        'apis': ['WifiManager', 'setWifiEnabled', 'startScan', 'disconnect'],
        'desc': '修改WiFi状态',
        'severity': 'normal',
    },
}

# 反向映射：API → 可能需要的权限
API_TO_PERMS = defaultdict(list)
for perm, info in PERMISSION_API_MAP.items():
    for api in info['apis']:
        API_TO_PERMS[api].append(perm)


class PermissionTracer:
    """权限使用追溯分析引擎"""

    @staticmethod
    def analyze(manifest_info, dex_strings_list):
        """
        分析权限在 DEX 中的实际使用情况
        Args:
            manifest_info: get_manifest_info() 返回的 manifest 信息
            dex_strings_list: list of (dex_name, [strings])
        Returns:
            dict: {declared_perms, used_perms, unused_perms, missing_perms, api_usage, summary}
        """
        declared_perms = set(manifest_info.get('permissions', []))
        # 合并所有 DEX 字符串
        all_strings = []
        dex_sources = defaultdict(list)  # string → [dex_names]
        for dex_name, strings in dex_strings_list:
            for s in strings:
                all_strings.append(s)
                dex_sources[s].append(dex_name)

        # 对每个声明权限，检查是否有对应的 API 调用
        used_perms = []
        unused_perms = []
        api_usage = {}

        for perm in sorted(declared_perms):
            perm_info = PERMISSION_API_MAP.get(perm)
            if not perm_info:
                # 未知权限，跳过
                continue

            found_apis = []
            for api_pattern in perm_info['apis']:
                # 在字符串中搜索 API
                for s in all_strings:
                    if api_pattern in s:
                        found_apis.append({
                            'api': api_pattern,
                            'context': s[:200],
                            'dex': dex_sources.get(s, ['?'])[0],
                        })
                        break

            if found_apis:
                used_perms.append({
                    'permission': perm,
                    'description': perm_info['desc'],
                    'severity': perm_info['severity'],
                    'api_count': len(found_apis),
                    'apis': found_apis[:10],  # 限制显示数量
                })
                api_usage[perm] = found_apis
            else:
                unused_perms.append({
                    'permission': perm,
                    'description': perm_info['desc'],
                    'severity': perm_info['severity'],
                })

        # 检测"使用但未声明"的权限
        missing_perms = []
        for api, perms in API_TO_PERMS.items():
            for s in all_strings:
                if api in s:
                    for perm in perms:
                        if perm not in declared_perms:
                            # 确认这个权限不是已经在 used_perms 中的
                            already = any(p['permission'] == perm for p in missing_perms)
                            if not already:
                                missing_perms.append({
                                    'permission': perm,
                                    'description': PERMISSION_API_MAP[perm]['desc'],
                                    'severity': PERMISSION_API_MAP[perm]['severity'],
                                    'api_found': api,
                                    'context': s[:200],
                                })
                    break

        # 统计摘要
        dangerous_used = sum(1 for p in used_perms if p['severity'] == 'dangerous')
        dangerous_unused = sum(1 for p in unused_perms if p['severity'] == 'dangerous')
        dangerous_missing = sum(1 for p in missing_perms if p['severity'] == 'dangerous')

        return {
            'declared_count': len(declared_perms),
            'used_count': len(used_perms),
            'unused_count': len(unused_perms),
            'missing_count': len(missing_perms),
            'used_perms': used_perms,
            'unused_perms': unused_perms,
            'missing_perms': missing_perms[:20],
            'api_usage': api_usage,
            'summary': {
                'declared': len(declared_perms),
                'used': len(used_perms),
                'unused': len(unused_perms),
                'missing': len(missing_perms),
                'dangerous_used': dangerous_used,
                'dangerous_unused': dangerous_unused,
                'dangerous_missing': dangerous_missing,
                'risk_score': min(100, dangerous_used * 15 + dangerous_missing * 20 + dangerous_unused * 5),
            }
        }
