"""安全分析器 - 综合安全风险评估"""

class SecurityAnalyzer:
    """综合安全分析引擎，基于多项指标评估APK安全风险等级"""
    
    # 高危权限完全列表
    CRITICAL_PERMISSIONS = [
        'android.permission.READ_SMS', 'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS', 'android.permission.RECEIVE_MMS',
        'android.permission.CALL_PHONE', 'android.permission.PROCESS_OUTGOING_CALLS',
        'android.permission.READ_CALL_LOG', 'android.permission.WRITE_CALL_LOG',
        'android.permission.READ_CONTACTS', 'android.permission.WRITE_CONTACTS',
        'android.permission.ACCESS_FINE_LOCATION', 'android.permission.ACCESS_BACKGROUND_LOCATION',
        'android.permission.CAMERA', 'android.permission.RECORD_AUDIO',
        'android.permission.BIND_ACCESSIBILITY_SERVICE',
        'android.permission.QUERY_ALL_PACKAGES',
        'android.permission.REQUEST_INSTALL_PACKAGES',
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.MANAGE_EXTERNAL_STORAGE',
    ]

    # 组件暴露风险
    COMPONENT_RISKS = {
        'activity': {'exported': 'Activity可被外部启动', 'grant_uri': 'URI权限泄露'},
        'service': {'exported': 'Service可被外部绑定'},
        'receiver': {'exported': 'BroadcastReceiver可被外部触发'},
        'provider': {'exported': 'ContentProvider数据可被外部访问'},
    }

    @staticmethod
    def analyze(manifest_simple, permissions, obfuscation_score, packers, additional=None):
        """全面的安全风险分析"""
        issues = []
        score = 0
        max_score = 0

        # 1. Manifest安全检测
        manifest = manifest_simple or {}
        sdk = manifest.get('sdk', {})
        components = manifest.get('components', [])

        # 1.1 Debuggable
        max_score += 3
        for c in components:
            attrs = c.get('attrs', {})
            if attrs.get('android:debuggable') == 'true' or attrs.get('debuggable') == 'true':
                issues.append({
                    'severity': 'HIGH', 'type': '可调试',
                    'desc': '应用被标记为可调试(android:debuggable=true)，生产环境应关闭',
                    'cwe': 'CWE-489', 'cvss': 7.5
                })
                score += 3
                break

        # 1.2 allowBackup
        max_score += 2
        for c in components:
            attrs = c.get('attrs', {})
            if attrs.get('android:allowBackup') == 'true' or attrs.get('allowBackup') == 'true':
                issues.append({
                    'severity': 'MEDIUM', 'type': '数据备份',
                    'desc': '允许应用数据备份(android:allowBackup=true)，可能导致数据泄露',
                    'cwe': 'CWE-200', 'cvss': 5.0
                })
                score += 2
                break

        # 1.3 导出组件分析
        for c in components:
            attrs = c.get('attrs', {})
            exported = attrs.get('android:exported') == 'true' or attrs.get('exported') == 'true'
            has_intent_filter = 'intent_filter' in attrs or any('intent' in k.lower() for k in attrs)
            
            if exported or (has_intent_filter and attrs.get('android:exported') != 'false'):
                max_score += 2
                risk_info = SecurityAnalyzer.COMPONENT_RISKS.get(c['type'], {})
                desc = risk_info.get('exported', f'{c["type"]}被导出')
                issues.append({
                    'severity': 'MEDIUM' if c['type'] != 'provider' else 'HIGH',
                    'type': f'暴露{c["type"]}',
                    'desc': f'{desc}: {attrs.get("android:name", "unknown")}',
                    'cwe': 'CWE-926', 'cvss': 6.0 if c['type'] == 'provider' else 4.0
                })
                score += 2 if c['type'] == 'provider' else 1

        # 2. 加固检测
        if packers:
            max_score += 3
            issues.append({
                'severity': 'INFO', 'type': '加固壳',
                'desc': f'检测到加固: {', '.join(packers)}',
                'cwe': 'N/A', 'cvss': 0
            })

        # 3. 权限分析
        max_score += 5
        dangerous_perms = permissions.get('dangerous', [])
        dangerous_count = len(dangerous_perms)
        
        if dangerous_count > 10:
            issues.append({
                'severity': 'HIGH', 'type': '过度权限',
                'desc': f'请求{dangerous_count}个危险权限，远超正常应用需求',
                'cwe': 'CWE-250', 'cvss': 6.0
            })
            score += 4
        elif dangerous_count > 5:
            issues.append({
                'severity': 'MEDIUM', 'type': '敏感权限',
                'desc': f'请求{dangerous_count}个危险权限',
                'cwe': 'CWE-250', 'cvss': 4.0
            })
            score += 2

        # 3.1 高危权限组合检测
        perm_names = [p.get('name', '') for p in dangerous_perms]
        critical_found = [p for p in perm_names if p in SecurityAnalyzer.CRITICAL_PERMISSIONS]
        if critical_found:
            issues.append({
                'severity': 'MEDIUM', 'type': '高危权限',
                'desc': f'包含高危权限: {critical_found[:5]}',
                'cwe': 'CWE-272', 'cvss': 5.0
            })
            score += 1

        # 3.2 短信+电话组合（恶意软件特征）
        has_sms = any('SMS' in p for p in perm_names)
        has_phone = any('PHONE' in p or 'CALL' in p for p in perm_names)
        if has_sms and has_phone:
            issues.append({
                'severity': 'HIGH', 'type': '恶意行为模式',
                'desc': '同时请求短信和电话权限，可能是恶意软件特征',
                'cwe': 'CWE-250', 'cvss': 7.0
            })
            score += 3

        # 4. 混淆评分
        max_score += 3
        if obfuscation_score >= 5:
            issues.append({
                'severity': 'MEDIUM', 'type': '高度混淆',
                'desc': '代码高度混淆，增加逆向分析难度',
                'cwe': 'N/A', 'cvss': 3.0
            })
            score += 2

        # 5. SDK版本检查
        max_score += 2
        min_sdk = sdk.get('minSdk', '')
        target_sdk = sdk.get('targetSdk', '')
        try:
            if min_sdk and int(min_sdk) < 21:
                issues.append({
                    'severity': 'HIGH', 'type': '低SDK版本',
                    'desc': f'minSdkVersion={min_sdk}，低于Android 5.0，存在已知安全漏洞',
                    'cwe': 'CWE-1104', 'cvss': 6.0
                })
                score += 2
        except: pass

        # 6. 自定义权限
        custom_perms = permissions.get('custom', [])
        if custom_perms:
            issues.append({
                'severity': 'INFO', 'type': '自定义权限',
                'desc': f'声明{custom_perms}个自定义权限，需评估安全性',
                'cwe': 'N/A', 'cvss': 0
            })

        # 计算安全等级
        risk_level = '安全' if score <= 2 else '低风险' if score <= 5 else '中风险' if score <= 10 else '高风险' if score <= 15 else '严重'
        risk_score = min(100, int((score / max(1, max_score)) * 100)) if max_score else 0

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'total_issues': len(issues),
            'high_count': sum(1 for i in issues if i['severity'] == 'HIGH'),
            'medium_count': sum(1 for i in issues if i['severity'] == 'MEDIUM'),
            'info_count': sum(1 for i in issues if i['severity'] == 'INFO'),
            'issues': issues,
            'summary': f"风险等级: {risk_level}({risk_score}/100)，发现{len(issues)}个安全问题"
        }
