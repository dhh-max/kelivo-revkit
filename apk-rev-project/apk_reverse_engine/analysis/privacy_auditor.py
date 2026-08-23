"""APK 隐私审计器 - 综合隐私风险评估"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
import re
from collections import defaultdict

class PrivacyAuditor:
    """综合隐私风险评估引擎"""

    # 数据收集行为模式
    DATA_COLLECTION_PATTERNS = {
        'location': {
            'apis': ['getLastKnownLocation', 'requestLocationUpdates', 'getLatitude', 'getLongitude', 'Geocoder', 'LocationManager'],
            'permissions': ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION'],
            'severity': 'high',
            'description': '位置信息收集',
        },
        'contacts': {
            'apis': ['ContactsContract', 'queryContacts', 'RawContacts', 'PhoneLookup'],
            'permissions': ['READ_CONTACTS', 'WRITE_CONTACTS'],
            'severity': 'high',
            'description': '联系人读取',
        },
        'sms': {
            'apis': ['SmsManager', 'Telephony.Sms', 'content://sms', 'READ_SMS'],
            'permissions': ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'RECEIVE_MMS'],
            'severity': 'high',
            'description': '短信读写',
        },
        'call_log': {
            'apis': ['CallLog', 'CallLog$Calls'],
            'permissions': ['READ_CALL_LOG', 'WRITE_CALL_LOG'],
            'severity': 'high',
            'description': '通话记录',
        },
        'camera': {
            'apis': ['Camera.open', 'Camera2', 'SurfaceTexture', 'takePicture'],
            'permissions': ['CAMERA'],
            'severity': 'medium',
            'description': '相机访问',
        },
        'microphone': {
            'apis': ['MediaRecorder', 'AudioRecord', 'startRecording'],
            'permissions': ['RECORD_AUDIO'],
            'severity': 'medium',
            'description': '麦克风录音',
        },
        'storage': {
            'apis': ['Environment.getExternalStorageDirectory', 'getExternalStoragePublicDirectory', 'MediaStore'],
            'permissions': ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'MANAGE_EXTERNAL_STORAGE'],
            'severity': 'medium',
            'description': '文件存储访问',
        },
        'phone_state': {
            'apis': ['TelephonyManager', 'getDeviceId', 'getImei', 'getMeid', 'getSubscriberId', 'getLine1Number'],
            'permissions': ['READ_PHONE_STATE', 'READ_SMS', 'CALL_PHONE'],
            'severity': 'high',
            'description': '设备标识/电话状态',
        },
        'accounts': {
            'apis': ['AccountManager', 'getAccounts', 'getAccountsByType'],
            'permissions': ['GET_ACCOUNTS', 'AUTHENTICATE_ACCOUNTS'],
            'severity': 'medium',
            'description': '账户信息',
        },
        'calendar': {
            'apis': ['CalendarContract', 'Calendars', 'Events'],
            'permissions': ['READ_CALENDAR', 'WRITE_CALENDAR'],
            'severity': 'medium',
            'description': '日历数据',
        },
        'sensors': {
            'apis': ['SensorManager', 'Sensor.TYPE_', 'BodySensorClient'],
            'permissions': ['BODY_SENSORS'],
            'severity': 'low',
            'description': '传感器数据',
        },
        'bluetooth': {
            'apis': ['BluetoothAdapter', 'BluetoothDevice', 'BluetoothManager', 'startDiscovery', 'getBondedDevices'],
            'permissions': ['BLUETOOTH_SCAN', 'BLUETOOTH_CONNECT', 'BLUETOOTH_ADMIN'],
            'severity': 'medium',
            'description': '蓝牙扫描/连接',
        },
        'network_identity': {
            'apis': ['WifiInfo', 'getMacAddress', 'DhcpInfo', 'NetworkInterface', 'getHardwareAddress'],
            'permissions': ['ACCESS_WIFI_STATE', 'ACCESS_NETWORK_STATE'],
            'severity': 'medium',
            'description': '网络标识(MAC/WiFi)',
        },
    }

    # 敏感数据外传模式
    EXFIL_PATTERNS = {
        'http_upload': {
            'pattern': re.compile(r'POST|upload|multipart|RequestBody|OutputStream', re.I),
            'description': 'HTTP 上传行为',
        },
        'socket': {
            'pattern': re.compile(r'Socket\(|ServerSocket|DatagramSocket', re.I),
            'description': '原始 Socket 连接',
        },
        'content_provider_export': {
            'pattern': re.compile(r'ContentProvider|ContentResolver|openOutputStream|insert\(', re.I),
            'description': 'ContentProvider 数据共享',
        },
        'clipboard': {
            'pattern': re.compile(r'ClipboardManager|setText|getText', re.I),
            'description': '剪贴板读写',
        },
    }

    @staticmethod
    def audit(dex_parser=None, permissions=None, manifest_xml=None, strings=None, component_analysis=None):
        """综合隐私审计
        Args:
            dex_parser: DexParser 实例 (可选)
            permissions: list[str], 声明的权限列表
            manifest_xml: str, AndroidManifest 文本 (可选)
            strings: list[str], DEX 字符串列表 (可选)
            component_analysis: dict, 组件分析结果 (可选)
        Returns:
            dict: 审计报告
        """
        permissions = permissions or []
        perm_set = set(permissions)
        all_strings = strings or []

        # 如果有 dex_parser，提取字符串
        if dex_parser and not all_strings:
            try:
                dex_parser._ensure_parsed()
                all_strings = dex_parser.get_strings()
            except Exception:
                all_strings = []

        # 1. 检测数据收集行为
        data_behaviors = []
        for behavior_name, info in PrivacyAuditor.DATA_COLLECTION_PATTERNS.items():
            perm_matched = [p for p in info['permissions'] if p in perm_set or 'android.permission.' + p in perm_set]
            api_matched = []
            for api in info['apis']:
                for s in all_strings:
                    if api.lower() in s.lower():
                        api_matched.append(api)
                        break
            if perm_matched or api_matched:
                data_behaviors.append({
                    'behavior': behavior_name,
                    'description': info['description'],
                    'severity': info['severity'],
                    'matched_permissions': perm_matched,
                    'matched_apis': list(set(api_matched)),
                    'risk_score': PrivacyAuditor._calc_behavior_score(info['severity'], len(perm_matched), len(api_matched)),
                })

        # 2. 检测数据外传行为
        exfil_behaviors = []
        combined_text = ' '.join(all_strings[:5000]) if all_strings else ''
        for exfil_name, info in PrivacyAuditor.EXFIL_PATTERNS.items():
            matches = info['pattern'].findall(combined_text)
            if matches:
                exfil_behaviors.append({
                    'behavior': exfil_name,
                    'description': info['description'],
                    'match_count': len(matches),
                })

        # 3. 导出组件风险
        exported_risks = []
        if component_analysis:
            exported_summary = component_analysis.get('exported_summary', {})
            total_exported = exported_summary.get('total_exported', 0)
            if total_exported > 0:
                exported_risks.append({
                    'issue': '导出组件',
                    'count': total_exported,
                    'detail': f"显式导出: {exported_summary.get('explicitly_exported', 0)}, 隐式导出: {exported_summary.get('implicitly_exported', 0)}",
                    'severity': 'medium' if total_exported < 10 else 'high',
                })

        # 4. 计算总隐私风险评分
        risk_score = 0
        for b in data_behaviors:
            risk_score += b['risk_score']
        for e in exfil_behaviors:
            risk_score += 5
        for r in exported_risks:
            if r['severity'] == 'high':
                risk_score += 15
            else:
                risk_score += 8

        risk_level = 'low'
        if risk_score >= 80:
            risk_level = 'critical'
        elif risk_score >= 50:
            risk_level = 'high'
        elif risk_score >= 25:
            risk_level = 'medium'

        return {
            'privacy_risk_score': risk_score,
            'privacy_risk_level': risk_level,
            'data_collection_behaviors': data_behaviors,
            'data_exfiltration_behaviors': exfil_behaviors,
            'exported_component_risks': exported_risks,
            'total_behaviors_detected': len(data_behaviors) + len(exfil_behaviors),
            'permissions_analyzed': len(permissions),
            'high_severity_behaviors': [b for b in data_behaviors if b['severity'] == 'high'],
            'recommendations': PrivacyAuditor._generate_recommendations(risk_level, data_behaviors, exfil_behaviors, exported_risks),
        }

    @staticmethod
    def _calc_behavior_score(severity, perm_count, api_count):
        base = {'high': 15, 'medium': 8, 'low': 4}[severity]
        return base + perm_count * 3 + api_count * 2

    @staticmethod
    def _generate_recommendations(risk_level, data_behaviors, exfil_behaviors, exported_risks):
        recs = []
        if risk_level in ('critical', 'high'):
            recs.append('隐私风险较高，建议仔细审查数据收集行为是否必要')
        high_behaviors = [b for b in data_behaviors if b['severity'] == 'high']
        if high_behaviors:
            recs.append(f"检测到 {len(high_behaviors)} 个高风险数据收集行为: {', '.join(b['behavior'] for b in high_behaviors)}")
        if exfil_behaviors:
            recs.append(f"检测到 {len(exfil_behaviors)} 个潜在数据外传行为")
        if exported_risks:
            recs.append('检查导出组件是否有权限保护')
        if not recs:
            recs.append('未检测到明显隐私风险')
        return recs
