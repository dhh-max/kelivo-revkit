"""反分析检测器 - 检测反调试、反Root、反模拟器、完整性校验、动态检测等"""
import re

class AntiAnalysisDetector:
    """检测APK中的反分析措施"""

    # ── 反调试检测 ──
    ANTI_DEBUG_PATTERNS = [
        (r'android\.os\.Debug\.isDebuggerConnected', 'isDebuggerConnected', 'high'),
        (r'Debug\.isDebuggerConnected', 'isDebuggerConnected', 'high'),
        (r'ptrace', 'ptrace反调试', 'high'),
        (r'/proc/self/status', '读取TracerPid', 'high'),
        (r'TracerPid', '检查TracerPid', 'high'),
        (r'ro\.debuggable', '检查debuggable属性', 'medium'),
        (r'System\.getProperty.*ro\.debuggable', '检查debuggable', 'medium'),
        (r'waitForDebugger', '等待调试器', 'medium'),
        (r'timing.*check|elapsed.*time|System\.nanoTime.*diff', '时间差检测', 'medium'),
        (r'isEmulator|isRunningOnEmulator|checkEmulator', '模拟器检测函数', 'high'),
    ]

    # ── 反Root检测 ──
    ANTI_ROOT_PATTERNS = [
        (r'/system/xbin/su', 'su二进制路径', 'high'),
        (r'/system/bin/su', 'su二进制路径', 'high'),
        (r'/sbin/su', 'su二进制路径', 'high'),
        (r'superuser\.apk', 'Superuser应用', 'high'),
        (r'Superuser\.apk', 'Superuser应用', 'high'),
        (r'com\.noshufou\.android\.su', 'Superuser包名', 'high'),
        (r'com\.koushikdutta\.superuser', 'Koush Superuser', 'high'),
        (r'eu\.chainfire\.supersu', 'SuperSU', 'high'),
        (r'com\.topjohnwu\.magisk', 'Magisk', 'high'),
        (r'magisk', 'Magisk', 'high'),
        (r'\bsu\s+-c', 'su命令执行', 'high'),
        (r'which\s+su', 'which su', 'medium'),
        (r'RootBeer|rootbeer', 'RootBeer库', 'medium'),
        (r'checkRootMethod|isRooted|detectRoot', 'Root检测方法', 'high'),
        (r'busybox', 'BusyBox', 'medium'),
        (r'/system/app/Superuser\.apk', 'Superuser路径', 'medium'),
        (r'test-keys', 'test-keys构建标签', 'medium'),
    ]

    # ── 反模拟器检测 ──
    ANTI_EMULATOR_PATTERNS = [
        (r'goldfish', 'Goldfish设备', 'medium'),
        (r'rdfinger', 'RDFinger', 'medium'),
        (r'qemu', 'QEMU', 'high'),
        (r'genymotion', 'Genymotion', 'medium'),
        (r'nox|noxapp|bignox', 'Nox模拟器', 'medium'),
        (r'bluestacks|bstk', 'BlueStacks', 'medium'),
        (r'ldplayer|changzhi', 'LDPlayer', 'medium'),
        (r'muMu|mumuglobal', 'MuMu模拟器', 'medium'),
        (r'x86_64.*android|android.*x86_64', 'x86 Android', 'low'),
        (r'google_sdk|sdk_gphone', 'SDK模拟器', 'medium'),
        (r'generic_x86|generic_x64', 'Generic x86', 'low'),
        (r'Build\.MODEL.*sdk|Build\.PRODUCT.*sdk', 'Build属性检测', 'medium'),
        (r'Build\.FINGERPRINT.*generic|Build\.HARDWARE.*goldfish', 'Build指纹检测', 'medium'),
        (r' telnetd|socket.*5555|socket.*5554', '模拟器端口', 'medium'),
        (r'/sys/qemu_trace', 'QEMU trace', 'medium'),
        (r'/dev/socket/qemud', 'QEMU daemon', 'medium'),
        (r'/dev/qemu_pipe', 'QEMU pipe', 'medium'),
        (r'init\.svc\.adbd', 'adbd服务', 'low'),
        (r'ro\.kernel\.qemu', 'QEMU属性', 'medium'),
    ]

    # ── 完整性校验检测 ──
    INTEGRITY_CHECK_PATTERNS = [
        (r'signature.*check|checkSignature|verifySignature', '签名校验', 'high'),
        (r'getPackageCodePath|getPackageResourcePath', '获取APK路径', 'medium'),
        (r'checksum|crc32|md5.*verify|sha.*verify', '文件完整性校验', 'high'),
        (r'PackageManager\.GET_SIGNATURES', '获取签名', 'high'),
        (r'getApplicationContext.*getPackageManager.*getPackageInfo', '签名检查链', 'high'),
        (r'signatures\[0\]\.toCharsString', '签名比较', 'high'),
        (r'MessageDigest.*getInstance.*SHA|MD5', '哈希计算', 'medium'),
        (r'checkInstallerPackage|getInstallerPackageName', '安装来源检查', 'medium'),
        (r'loadClass.*dex|DexFile.*loadDex', 'DEX动态加载', 'high'),
    ]

    # ── 反Hook检测 ──
    ANTI_HOOK_PATTERNS = [
        (r'XposedBridge|de\.robv\.android\.xposed', 'Xposed框架', 'high'),
        (r'XposedHelpers', 'Xposed辅助类', 'high'),
        (r'findAndHookMethod', 'Xposed Hook', 'high'),
        (r'hookMethod|callHookedMethod', 'Xposed Hook方法', 'high'),
        (r'Frida|frida-server|frida-gadget', 'Frida', 'high'),
        (r'libfrida|frida-agent', 'Frida Agent', 'high'),
        (r'gum-js-loop|gmain', 'Frida Gum', 'high'),
        (r'linjector|frida.*inject', 'Frida注入', 'high'),
        (r'Substrate|MSHookFunction|cydia', 'Cydia Substrate', 'high'),
        (r'com\.saurik\.substrate', 'Substrate包名', 'high'),
        (r'ArtMethod|hookedMethod', 'ArtMethod Hook', 'high'),
        (r'libepic|libwhale|libdexvm', 'ART Hook框架', 'high'),
        (r'bytehook|shadowhook', '字节级Hook', 'high'),
    ]

    # ── 反VPN/代理检测 ──
    ANTI_VPN_PATTERNS = [
        (r'tun0|tap0', 'VPN网卡', 'medium'),
        (r'VPNService|prepare.*VPN', 'VPN服务', 'medium'),
        (r'NetworkInterface.*getNetworkInterfaces.*tun', 'VPN接口检查', 'medium'),
        (r'Proxy\.getDefaultProxy|ProxyHost', '代理检测', 'medium'),
        (r'System\.getProperty.*http\.proxyHost', 'HTTP代理检测', 'medium'),
        (r'ProxySelector\.getDefault', '代理选择器', 'low'),
    ]

    # ── 反多开/虚拟化检测 ──
    ANTI_VIRTUAL_APP_PATTERNS = [
        (r'multi.*droid|parallel.*space|dual.*app', '多开应用', 'medium'),
        (r'virtualapp|virtualapp\.app', 'VirtualApp框架', 'high'),
        (r'VApp\.SDK|VClient\.SDK', 'VirtualApp SDK', 'high'),
        (r'com\.lbe\.parallel|com\.excelliance\.dualaid', '多开包名', 'medium'),
        (r'com\.ludashi\.dual|com\.boly\.dual', '双开包名', 'medium'),
        (r'/proc/self/cgroup|/proc/self/maps', '虚拟环境检测', 'medium'),
        (r'shared_userspace|shared_space', '共享空间', 'medium'),
        (r'getFilesDir.*virtual|getCodeCacheDir.*virtual', '虚拟文件路径', 'medium'),
    ]

    @staticmethod
    def detect_all(text, class_names=None, strings=None):
        """一站式检测所有反分析措施"""
        combined = text
        if strings:
            combined += '\n' + '\n'.join(strings)

        results = {
            'anti_debug': AntiAnalysisDetector._scan_patterns(combined, AntiAnalysisDetector.ANTI_DEBUG_PATTERNS),
            'anti_root': AntiAnalysisDetector._scan_patterns(combined, AntiAnalysisDetector.ANTI_ROOT_PATTERNS),
            'anti_emulator': AntiAnalysisDetector._scan_patterns(combined, AntiAnalysisDetector.ANTI_EMULATOR_PATTERNS),
            'integrity_check': AntiAnalysisDetector._scan_patterns(combined, AntiAnalysisDetector.INTEGRITY_CHECK_PATTERNS),
            'anti_hook': AntiAnalysisDetector._scan_patterns(combined, AntiAnalysisDetector.ANTI_HOOK_PATTERNS),
            'anti_vpn': AntiAnalysisDetector._scan_patterns(combined, AntiAnalysisDetector.ANTI_VPN_PATTERNS),
            'anti_virtual': AntiAnalysisDetector._scan_patterns(combined, AntiAnalysisDetector.ANTI_VIRTUAL_APP_PATTERNS),
        }

        # 汇总
        total = sum(len(v) for v in results.values())
        high_count = sum(1 for v in results.values() for item in v if item.get('severity') == 'high')

        results['summary'] = {
            'total_detections': total,
            'high_severity': high_count,
            'categories_found': [k for k, v in results.items() if v and k != 'summary'],
            'protection_level': 'heavy' if total > 15 else ('moderate' if total > 5 else ('light' if total > 0 else 'none')),
        }

        return results

    @staticmethod
    def _scan_patterns(text, patterns):
        findings = []
        seen = set()
        for pattern, desc, severity in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches and desc not in seen:
                seen.add(desc)
                findings.append({
                    'pattern': pattern,
                    'description': desc,
                    'severity': severity,
                    'match_count': len(matches),
                })
        return findings

    @staticmethod
    def detect_timing_checks(instructions):
        """检测基于时间差的反调试"""
        if not instructions:
            return {'detected': False}

        nano_time_calls = 0
        current_millis_calls = 0
        sub_long_ops = 0

        for inst in instructions:
            if not hasattr(inst, 'opcode'):
                continue
            # invoke-static with nanoTime/currentTimeMillis
            if inst.opcode in {0x71, 0x77}:  # invoke-static / invoke-static/range
                ref = inst.operands.get('ref', -1)
                # We can't resolve method names without method table
                nano_time_calls += 1
            # sub-long operations (time difference calculation)
            if inst.opcode in {0x9c, 0xbc}:  # sub-long / sub-long/2addr
                sub_long_ops += 1

        detected = nano_time_calls >= 2 and sub_long_ops >= 1
        return {
            'detected': detected,
            'nano_time_calls': nano_time_calls,
            'sub_long_ops': sub_long_ops,
            'confidence': 0.7 if detected else 0.0,
        }