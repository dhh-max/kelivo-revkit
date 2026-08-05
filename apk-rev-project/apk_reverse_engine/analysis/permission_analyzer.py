class PermissionAnalyzer:
    DANGEROUS = {
        'CAMERA': '拍照/录像', 'RECORD_AUDIO': '录音',
        'ACCESS_FINE_LOCATION': '精确定位', 'ACCESS_COARSE_LOCATION': '粗略定位',
        'ACCESS_BACKGROUND_LOCATION': '后台定位',
        'READ_EXTERNAL_STORAGE': '读取存储', 'WRITE_EXTERNAL_STORAGE': '写入存储',
        'READ_CONTACTS': '读取联系人', 'WRITE_CONTACTS': '写入联系人',
        'READ_SMS': '读取短信', 'SEND_SMS': '发送短信', 'RECEIVE_SMS': '接收短信',
        'CALL_PHONE': '拨打电话', 'READ_CALL_LOG': '读取通话记录',
        'WRITE_CALL_LOG': '写入通话记录',
        'BODY_SENSORS': '身体传感器',
        'READ_CALENDAR': '读取日历', 'WRITE_CALENDAR': '写入日历',
        'GET_ACCOUNTS': '获取账户',
        'POST_NOTIFICATIONS': '发送通知',
    }
    NORMAL = {
        'INTERNET': '访问网络', 'ACCESS_NETWORK_STATE': '网络状态',
        'ACCESS_WIFI_STATE': 'WiFi状态',
        'VIBRATE': '振动', 'WAKE_LOCK': '唤醒锁定',
        'FOREGROUND_SERVICE': '前台服务',
        'RECEIVE_BOOT_COMPLETED': '开机启动',
        'SET_ALARM': '设置闹钟',
        'USE_BIOMETRIC': '使用生物识别', 'USE_FINGERPRINT': '使用指纹',
        'NFC': 'NFC', 'QUERY_ALL_PACKAGES': '查询所有包',
        'REQUEST_INSTALL_PACKAGES': '请求安装包',
    }

    @staticmethod
    def analyze(permissions):
        if not permissions:
            return {'total': 0, 'dangerous_count': 0, 'dangerous': [], 'normal': [], 'other': [], 'custom': [], 'summary': '无权限'}
        dangerous = []
        normal = []
        other = []
        custom = []
        for p in permissions:
            name = p.split('.')[-1] if '.' in p else p
            if name in PermissionAnalyzer.DANGEROUS:
                dangerous.append({'name': p, 'desc': PermissionAnalyzer.DANGEROUS[name]})
            elif name in PermissionAnalyzer.NORMAL:
                normal.append({'name': p, 'desc': PermissionAnalyzer.NORMAL[name]})
            elif not p.startswith('android.permission.'):
                custom.append(p)
            else:
                other.append(p)
        risk_groups = []
        perm_names = [p.get('name', '') for p in dangerous]
        location = [p for p in perm_names if 'LOCATION' in p]
        if len(location) >= 2: risk_groups.append({'name': '位置追踪', 'risk': 'HIGH'})
        privacy = [p for p in perm_names if any(x in p for x in ['CONTACTS','CALENDAR','CALL_LOG','SMS'])]
        if len(privacy) >= 3: risk_groups.append({'name': '隐私窃取', 'risk': 'HIGH'})
        charge = [p for p in perm_names if any(x in p for x in ['SMS','PHONE','CALL'])]
        if len(charge) >= 2: risk_groups.append({'name': '恶意扣费', 'risk': 'HIGH'})
        monitor = [p for p in perm_names if any(x in p for x in ['CAMERA','RECORD_AUDIO'])]
        if len(monitor) >= 2: risk_groups.append({'name': '监控', 'risk': 'MEDIUM'})
        return {'total': len(permissions), 'dangerous_count': len(dangerous), 'normal_count': len(normal),
                'dangerous': dangerous, 'normal': normal, 'other': other, 'custom': custom,
                'risk_groups': risk_groups, 'summary': f'共{len(permissions)}个权限，{len(dangerous)}个危险'}
