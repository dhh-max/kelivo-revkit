#!/usr/bin/env python3
"""权限分析器增强版 - 权限分类 + 合规检查 + 广告权限关联 + 隐私信号

功能:
  1. 权限分类（危险/正常/自定义/系统）
  2. 风险组合检测（隐私窃取/恶意扣费/监控等）
  3. 广告SDK常用权限关联
  4. 合规检查（GDPR/COPPA/CCPA 相关权限）
  5. 隐私信号评分
  6. 权限过度申请分析
  7. API 版本兼容性检查
"""
import re


class PermissionAnalyzer:
    """权限分析引擎"""

    # 危险权限（Android 原生）
    DANGEROUS = {
        'CAMERA': '拍照/录像', 'RECORD_AUDIO': '录音',
        'ACCESS_FINE_LOCATION': '精确定位', 'ACCESS_COARSE_LOCATION': '粗略定位',
        'ACCESS_BACKGROUND_LOCATION': '后台定位',
        'READ_EXTERNAL_STORAGE': '读取存储', 'WRITE_EXTERNAL_STORAGE': '写入存储',
        'READ_MEDIA_IMAGES': '读取图片', 'READ_MEDIA_VIDEO': '读取视频',
        'READ_MEDIA_AUDIO': '读取音频',
        'READ_CONTACTS': '读取联系人', 'WRITE_CONTACTS': '写入联系人',
        'READ_SMS': '读取短信', 'SEND_SMS': '发送短信', 'RECEIVE_SMS': '接收短信',
        'CALL_PHONE': '拨打电话', 'READ_CALL_LOG': '读取通话记录',
        'WRITE_CALL_LOG': '写入通话记录',
        'BODY_SENSORS': '身体传感器',
        'READ_CALENDAR': '读取日历', 'WRITE_CALENDAR': '写入日历',
        'GET_ACCOUNTS': '获取账户',
        'POST_NOTIFICATIONS': '发送通知',
        'NEARBY_WIFI_DEVICES': '附近WiFi设备',
        'BLUETOOTH_SCAN': '蓝牙扫描', 'BLUETOOTH_ADVERTISE': '蓝牙广播',
        'BLUETOOTH_CONNECT': '蓝牙连接',
        'ACTIVITY_RECOGNITION': '活动识别',
    }

    # 正常权限
    NORMAL = {
        'INTERNET': '访问网络', 'ACCESS_NETWORK_STATE': '网络状态',
        'ACCESS_WIFI_STATE': 'WiFi状态',
        'VIBRATE': '振动', 'WAKE_LOCK': '唤醒锁定',
        'FOREGROUND_SERVICE': '前台服务',
        'RECEIVE_BOOT_COMPLETED': '开机启动',
        'SET_ALARM': '设置闹钟',
        'USE_BIOMETRIC': '使用生物识别', 'USE_FINGERPRINT': '使用指纹',
        'NFC': 'NFC',
        'QUERY_ALL_PACKAGES': '查询所有包',
        'REQUEST_INSTALL_PACKAGES': '请求安装包',
        'BIND_ACCESSIBILITY_SERVICE': '无障碍服务绑定',
        'ACCESS_MEDIA_LOCATION': '访问媒体位置',
        'CHANGE_NETWORK_STATE': '修改网络状态',
        'CHANGE_WIFI_STATE': '修改WiFi状态',
        'ACCESS_NOTIFICATION_POLICY': '通知策略',
        'BLUETOOTH': '蓝牙',
        'INTERACT_ACROSS_USERS': '跨用户交互',
        'EXPAND_STATUS_BAR': '展开状态栏',
        'KILL_BACKGROUND_PROCESSES': '结束后台进程',
        'MANAGE_OWN_CALLS': '管理通话',
        'READ_SYNC_SETTINGS': '读取同步设置',
        'RECEIVE_MMS': '接收彩信', 'RECEIVE_WAP_PUSH': '接收WAP推送',
        'REQUEST_DELETE_PACKAGES': '请求删除包',
        'SCHEDULE_EXACT_ALARM': '精确闹钟',
        'SET_WALLPAPER': '设置壁纸',
        'TRANSMIT_IR': '红外传输',
        'UNINSTALL_SHORTCUT': '卸载快捷方式',
        'USE_EXACT_ALARM': '精确闹钟',
        'USE_FULL_SCREEN_INTENT': '全屏Intent',
    }

    # 签名级别权限
    SIGNATURE = {
        'INSTALL_PACKAGES': '安装应用', 'DELETE_PACKAGES': '删除应用',
        'CLEAR_APP_CACHE': '清除应用缓存',
        'READ_LOGS': '读取日志', 'DUMP': 'Dump信息',
        'PACKAGE_USAGE_STATS': '应用使用统计',
        'ACCESS_SUPERUSER': '超级用户',
        'BATTERY_STATS': '电池统计',
        'BLUETOOTH_PRIVILEGED': '蓝牙特权',
        'BIND_DEVICE_ADMIN': '设备管理',
        'BIND_NOTIFICATION_LISTENER_SERVICE': '通知监听',
        'BIND_VPN_SERVICE': 'VPN服务',
        'CAPTURE_AUDIO_OUTPUT': '音频输出捕获',
        'CONTROL_LOCATION_UPDATES': '控制位置更新',
        'DEVICE_POWER': '设备电源',
        'MANAGE_ACCOUNTS': '管理账户',
        'MANAGE_DOCUMENTS': '管理文档',
        'MANAGE_USERS': '管理用户',
        'MEDIA_CONTENT_CONTROL': '媒体内容控制',
        'MODIFY_AUDIO_SETTINGS': '修改音频设置',
        'MOUNT_UNMOUNT_FILESYSTEMS': '挂载卸载文件系统',
        'PROCESS_OUTGOING_CALLS': '处理拨出电话',
        'REBOOT': '重启',
        'SET_ANIMATION_SCALE': '设置动画缩放',
        'SET_TIME': '设置时间',
        'SYSTEM_ALERT_WINDOW': '悬浮窗',
        'UPDATE_APP_OPS_STATS': '更新应用操作统计',
        'WRITE_APN_SETTINGS': '写入APN设置',
        'WRITE_SETTINGS': '写入设置',
        'WRITE_SYNC_SETTINGS': '写入同步设置',
    }

    # 广告SDK常用权限
    AD_PERMISSIONS = {
        'INTERNET': '广告网络请求',
        'ACCESS_NETWORK_STATE': '广告网络状态',
        'ACCESS_WIFI_STATE': '广告WiFi状态',
        'READ_EXTERNAL_STORAGE': '广告缓存读取',
        'WRITE_EXTERNAL_STORAGE': '广告缓存写入',
        'ACCESS_FINE_LOCATION': '广告精准定位',
        'ACCESS_COARSE_LOCATION': '广告粗略定位',
        'ACCESS_BACKGROUND_LOCATION': '广告后台定位',
        'READ_PHONE_STATE': '广告设备标识',
        'VIBRATE': '广告振动',
        'WAKE_LOCK': '广告唤醒锁定',
        'RECEIVE_BOOT_COMPLETED': '广告开机自启',
        'QUERY_ALL_PACKAGES': '广告应用列表',
        'REQUEST_INSTALL_PACKAGES': '广告安装包',
        'POST_NOTIFICATIONS': '广告通知',
        'CAMERA': '广告AR/扫码',
        'RECORD_AUDIO': '广告语音',
        'BLUETOOTH': '广告蓝牙',
        'ACTIVITY_RECOGNITION': '广告活动识别',
    }

    # 合规相关权限 (GDPR/COPPA/CCPA)
    COMPLIANCE_PERMISSIONS = {
        'GDPR': {
            'ACCESS_FINE_LOCATION': 'GDPR - 位置数据',
            'ACCESS_BACKGROUND_LOCATION': 'GDPR - 后台位置追踪',
            'READ_CONTACTS': 'GDPR - 联系人数据',
            'READ_CALENDAR': 'GDPR - 日历数据',
            'READ_EXTERNAL_STORAGE': 'GDPR - 存储数据',
            'CAMERA': 'GDPR - 图像数据',
            'RECORD_AUDIO': 'GDPR - 音频数据',
            'READ_SMS': 'GDPR - 短信数据',
            'READ_CALL_LOG': 'GDPR - 通话记录',
            'GET_ACCOUNTS': 'GDPR - 账户信息',
            'ACTIVITY_RECOGNITION': 'GDPR - 活动数据',
        },
        'COPPA': {  # 儿童隐私
            'ACCESS_FINE_LOCATION': 'COPPA - 儿童位置',
            'CAMERA': 'COPPA - 儿童摄像头',
            'RECORD_AUDIO': 'COPPA - 儿童录音',
            'READ_CONTACTS': 'COPPA - 儿童联系人',
        },
        'CCPA': {  # 加州消费者隐私
            'ACCESS_FINE_LOCATION': 'CCPA - 地理位置',
            'READ_CONTACTS': 'CCPA - 联系人',
            'READ_CALENDAR': 'CCPA - 日历',
            'CAMERA': 'CCPA - 生物识别',
            'READ_EXTERNAL_STORAGE': 'CCPA - 个人文件',
        },
    }

    # 过度申请检测阈值
    OVERREQUEST_THRESHOLDS = {
        'dangerous_count': 5,    # 危险权限超过5个 → 过度
        'total_count': 15,       # 总权限超过15个 → 过度
        'sensitive_ratio': 0.4,  # 危险权限占比超过40% → 过度
    }

    @staticmethod
    def analyze(permissions):
        """多维度权限分析

        Args:
            permissions: list[str] 权限列表

        Returns:
            dict: 权限分析结果
        """
        if not permissions:
            return {
                'total': 0, 'dangerous_count': 0, 'normal_count': 0,
                'dangerous': [], 'normal': [], 'other': [], 'custom': [],
                'signature': [], 'risk_groups': [], 'summary': '无权限',
                'ad_permissions': [], 'ad_permission_count': 0,
                'compliance': {}, 'overrequest': {},
                'privacy_score': 100, 'privacy_level': '优秀',
            }

        # 1. 分类
        dangerous = []
        normal = []
        signature = []
        other = []
        custom = []

        for p in permissions:
            name = p.split('.')[-1] if '.' in p else p
            if name in PermissionAnalyzer.DANGEROUS:
                dangerous.append({'name': p, 'desc': PermissionAnalyzer.DANGEROUS[name]})
            elif name in PermissionAnalyzer.NORMAL:
                normal.append({'name': p, 'desc': PermissionAnalyzer.NORMAL[name]})
            elif name in PermissionAnalyzer.SIGNATURE:
                signature.append({'name': p, 'desc': PermissionAnalyzer.SIGNATURE[name]})
            elif not p.startswith('android.permission.'):
                custom.append(p)
            else:
                other.append(p)

        perm_names = [d.get('name', '') for d in dangerous]

        # 2. 风险组合
        risk_groups = PermissionAnalyzer._detect_risk_groups(perm_names)

        # 3. 广告权限关联
        ad_permissions = PermissionAnalyzer._detect_ad_permissions(
            dangerous + normal + signature)

        # 4. 合规检查
        compliance = PermissionAnalyzer._check_compliance(perm_names)

        # 5. 过度申请分析
        overrequest = PermissionAnalyzer._check_overrequest(
            len(permissions), len(dangerous), len(normal), len(signature))

        # 6. 隐私评分
        privacy = PermissionAnalyzer._calc_privacy_score(
            len(dangerous), risk_groups, overrequest)

        return {
            'total': len(permissions),
            'dangerous_count': len(dangerous),
            'normal_count': len(normal),
            'signature_count': len(signature),
            'custom_count': len(custom),
            'dangerous': dangerous,
            'normal': normal,
            'signature': signature,
            'other': other,
            'custom': custom,
            'risk_groups': risk_groups,
            'ad_permissions': ad_permissions,
            'ad_permission_count': len(ad_permissions),
            'compliance': compliance,
            'overrequest': overrequest,
            'privacy_score': privacy['score'],
            'privacy_level': privacy['level'],
            'summary': f'共{len(permissions)}个权限，{len(dangerous)}个危险，'
                       f'{len(signature)}个签名级，{len(risk_groups)}个风险组合',
        }

    @staticmethod
    def _detect_risk_groups(perm_names):
        """检测风险权限组合"""
        risk_groups = []
        perm_set = set(perm_names)

        # 获取简化后的权限名（去掉前缀）
        short_names = set()
        for p in perm_names:
            short = p.split('.')[-1] if '.' in p else p
            short_names.add(short.upper())

        # 组合检测
        combos = [
            {
                'name': '位置追踪', 'risk': 'HIGH',
                'perms': {'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
                          'ACCESS_BACKGROUND_LOCATION'},
                'desc': '多重定位权限，可精确定位用户位置',
            },
            {
                'name': '隐私窃取', 'risk': 'HIGH',
                'perms': {'READ_CONTACTS', 'READ_CALENDAR', 'READ_CALL_LOG',
                          'READ_SMS', 'GET_ACCOUNTS'},
                'desc': '可批量读取用户隐私数据',
            },
            {
                'name': '恶意扣费', 'risk': 'HIGH',
                'perms': {'SEND_SMS', 'CALL_PHONE', 'INTERNET'},
                'desc': '可发送付费短信或拨打电话',
            },
            {
                'name': '监控', 'risk': 'MEDIUM',
                'perms': {'CAMERA', 'RECORD_AUDIO'},
                'desc': '可录制音视频',
            },
            {
                'name': '短信拦截', 'risk': 'HIGH',
                'perms': {'READ_SMS', 'RECEIVE_SMS'},
                'desc': '可读取和拦截短信（含验证码）',
            },
            {
                'name': '存储泄露', 'risk': 'MEDIUM',
                'perms': {'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'},
                'desc': '可读写外部存储数据',
            },
            {
                'name': '后台追踪', 'risk': 'HIGH',
                'perms': {'ACCESS_BACKGROUND_LOCATION', 'ACCESS_FINE_LOCATION', 'INTERNET'},
                'desc': '后台持续定位并上传',
            },
            {
                'name': '安装攻击', 'risk': 'HIGH',
                'perms': {'INSTALL_PACKAGES', 'DELETE_PACKAGES'},
                'desc': '可静默安装/卸载应用',
            },
            {
                'name': '覆盖攻击', 'risk': 'HIGH',
                'perms': {'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE'},
                'desc': '悬浮窗+无障碍，典型钓鱼手段',
            },
            {
                'name': '设备管理', 'risk': 'MEDIUM',
                'perms': {'BIND_DEVICE_ADMIN', 'MANAGE_ACCOUNTS'},
                'desc': '设备管理权限，可远程锁定/擦除',
            },
            {
                'name': '广告追踪', 'risk': 'LOW',
                'perms': {'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
                          'GET_ACCOUNTS', 'READ_EXTERNAL_STORAGE'},
                'desc': '广告SDK收集用户画像数据',
            },
        ]

        for combo in combos:
            matched = combo['perms'] & short_names
            match_ratio = len(matched) / max(1, len(combo['perms']))
            # 匹配超过66%即标记
            if match_ratio >= 0.66:
                risk_groups.append({
                    'name': combo['name'],
                    'risk': combo['risk'],
                    'matched': sorted(matched),
                    'match_count': len(matched),
                    'total_count': len(combo['perms']),
                    'desc': combo['desc'],
                })

        return risk_groups

    @staticmethod
    def _detect_ad_permissions(permissions):
        """检测广告SDK常用权限"""
        ad_perms = []
        for p in permissions:
            name = p['name'].split('.')[-1] if '.' in p['name'] else p['name']
            if name in PermissionAnalyzer.AD_PERMISSIONS:
                ad_perms.append({
                    'name': p['name'],
                    'desc': PermissionAnalyzer.AD_PERMISSIONS[name],
                    'category': p.get('desc', ''),
                })
        return ad_perms

    @staticmethod
    def _check_compliance(perm_names):
        """合规检查"""
        short_names = set()
        for p in perm_names:
            short = p.split('.')[-1] if '.' in p else p
            short_names.add(short.upper())

        result = {}
        for regulation, perms in PermissionAnalyzer.COMPLIANCE_PERMISSIONS.items():
            matched = []
            for perm, desc in perms.items():
                if perm in short_names:
                    matched.append({'permission': perm, 'description': desc})
            if matched:
                result[regulation] = {
                    'count': len(matched),
                    'permissions': matched,
                    'requires_consent': True,
                }
        return result

    @staticmethod
    def _check_overrequest(total, dangerous_count, normal_count, signature_count):
        """过度申请分析"""
        issues = []
        is_overrequest = False

        if dangerous_count >= PermissionAnalyzer.OVERREQUEST_THRESHOLDS['dangerous_count']:
            issues.append(f'危险权限过多: {dangerous_count}个 '
                          f'(阈值: {PermissionAnalyzer.OVERREQUEST_THRESHOLDS["dangerous_count"]})')
            is_overrequest = True

        if total >= PermissionAnalyzer.OVERREQUEST_THRESHOLDS['total_count']:
            issues.append(f'总权限过多: {total}个 '
                          f'(阈值: {PermissionAnalyzer.OVERREQUEST_THRESHOLDS["total_count"]})')
            is_overrequest = True

        if total > 0:
            sensitive_ratio = dangerous_count / total
            if sensitive_ratio >= PermissionAnalyzer.OVERREQUEST_THRESHOLDS['sensitive_ratio']:
                issues.append(f'敏感权限占比过高: {sensitive_ratio:.0%} '
                              f'(阈值: {PermissionAnalyzer.OVERREQUEST_THRESHOLDS["sensitive_ratio"]:.0%})')
                is_overrequest = True

        if signature_count > 0:
            issues.append(f'请求了签名级权限: {signature_count}个，非系统应用无法获取')
            is_overrequest = True

        return {
            'is_overrequest': is_overrequest,
            'issues': issues,
            'issue_count': len(issues),
        }

    @staticmethod
    def _calc_privacy_score(dangerous_count, risk_groups, overrequest):
        """隐私评分 0-100"""
        score = 100

        # 每个危险权限扣5分
        score -= dangerous_count * 5

        # 每个高风险组合扣15分
        high_risks = sum(1 for g in risk_groups if g.get('risk') == 'HIGH')
        score -= high_risks * 15

        # 每个中风险组合扣8分
        medium_risks = sum(1 for g in risk_groups if g.get('risk') == 'MEDIUM')
        score -= medium_risks * 8

        # 过度申请扣20分
        if overrequest.get('is_overrequest'):
            score -= 20

        score = max(0, min(100, score))

        if score >= 80:
            level = '优秀'
        elif score >= 60:
            level = '良好'
        elif score >= 40:
            level = '一般'
        elif score >= 20:
            level = '较差'
        else:
            level = '极差'

        return {'score': score, 'level': level}