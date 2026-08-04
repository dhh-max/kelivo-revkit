class PermissionAnalyzer:
    DANGEROUS = {
        "CAMERA": "拍照/录像", "RECORD_AUDIO": "录音",
        "ACCESS_FINE_LOCATION": "精确定位", "ACCESS_COARSE_LOCATION": "粗略定位",
        "READ_EXTERNAL_STORAGE": "读取存储", "WRITE_EXTERNAL_STORAGE": "写入存储",
        "READ_CONTACTS": "读取联系人", "READ_SMS": "读取短信",
        "SEND_SMS": "发送短信", "CALL_PHONE": "拨打电话",
        "READ_CALL_LOG": "读取通话记录", "BODY_SENSORS": "身体传感器",
        "READ_CALENDAR": "读取日历", "WRITE_CALENDAR": "写入日历",
        "GET_ACCOUNTS": "获取账户", "ACCESS_BACKGROUND_LOCATION": "后台定位",
    }
    NORMAL = {
        "INTERNET": "访问网络", "ACCESS_NETWORK_STATE": "网络状态",
        "ACCESS_WIFI_STATE": "WiFi状态", "VIBRATE": "振动",
        "WAKE_LOCK": "唤醒锁定", "FOREGROUND_SERVICE": "前台服务",
        "POST_NOTIFICATIONS": "通知", "RECEIVE_BOOT_COMPLETED": "开机启动",
    }
    @staticmethod
    def analyze(permissions):
        dangerous = [p for p in permissions if any(d in p.upper() for d in PermissionAnalyzer.DANGEROUS)]
        normal = [p for p in permissions if any(n in p.upper() for n in PermissionAnalyzer.NORMAL)]
        other = [p for p in permissions if p not in dangerous and p not in normal]
        custom = [p for p in permissions if not p.startswith("android.permission.")]
        return {
            "total": len(permissions), "dangerous_count": len(dangerous),
            "dangerous": [{"name": p, "desc": PermissionAnalyzer.DANGEROUS.get(p.split(".")[-1], "")} for p in dangerous],
            "normal": [{"name": p, "desc": PermissionAnalyzer.NORMAL.get(p.split(".")[-1], "")} for p in normal],
            "other": other, "custom": custom,
        }