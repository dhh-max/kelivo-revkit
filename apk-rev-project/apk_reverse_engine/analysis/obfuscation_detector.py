"""混淆检测器 - 检测代码混淆、加固、反调试、反篡改"""
import re

class ObfuscationDetector:
    """多层混淆检测器：类名混淆、字符串加密、反射调用、加固壳检测"""
    
    # 已知加固壳特征库
    PACKER_SIGNATURES = {
        'libsecexe.so': '360加固', 'libsecmain.so': '360加固', 'libjiagu.so': '360加固',
        'libDexHelper.so': '腾讯加固', 'libexec.so': '腾讯加固', 'libtup.so': '腾讯加固',
        'libegis.so': '娜迦加固', 'libnese.so': '娜迦加固', 'libnesec.so': '娜迦加固',
        'libchaos.so': '网易加固', 'libddog.so': '网易加固', 'libcate.so': '网易加固',
        'libshella.so': '爱加密', 'libshell.so': '爱加密',
        'libSecShell.so': '梆梆加固', 'libSecShell_x86.so': '梆梆加固',
        'libprotect.so': '通付盾', 'libprotectClass.so': '通付盾',
        'libxguard.so': '几维安全', 'libnqshield.so': '几维安全',
        'libmobisec.so': 'Mobisec', 'mobisec.jar': 'Mobisec',
        'libAPKProtect.so': 'APKProtect', 'libAPKProtect_x86.so': 'APKProtect',
        'libDexProtector.so': 'DexProtector',
        'liboasf.so': '御安全', 'liboasf_x86.so': '御安全',
        'libNSApplication.so': '网易易盾',
        'libddshl.so': '顶像加固',
    }

    # 反调试/反篡改特征
    ANTI_TAMPER_SIGNATURES = [
        r'checkSignatures', r'getPackageManager\(\).*?checkSign',
        r'PackageManager->checkSignatures',
        r'Signature\[\s*\d+\s*\]',
        r'getInstallerPackageName',
        r'verifyInstall', r'VERIFY_INSTALL',
        r'getApkSigningBlockDigest',
        r'isTestOnlyInstall',
        r'certificateInstaller',
        r'android\.content\.pm\.PackageManager.*signature',
        r'Signature\s*\(\s*\)',
        r'android\.app\.ActivityManager.*runningTask',
        r'isDebuggerConnected',
        r'android\.os\.Debug.*isDebuggerConnected',
        r'Debug\.waitForDebugger',
        r'android\.os\.Process.*myTid',
        r'ptrace\(',
        r'Process\.myTid\(\)\s*==\s*[0-9]',
    ]

    # 反射/动态加载特征
    REFLECTION_PATTERNS = [
        r'Class\.forName', r'java\.lang\.reflect',
        r'Method\.invoke', r'Field\.setAccessible',
        r'DexClassLoader', r'PathClassLoader',
        r'InMemoryDexClassLoader',
        r'loadDex', r'openDexFile',
        r'java\.lang\.reflect\.Method',
        r'getDeclaredMethod', r'getDeclaredField',
    ]

    # 混淆类名模式
    OBFUSCATED_PATTERNS = [
        r'^[a-z]$', r'^[a-z]{2}$', r'^[a-z]{3}$',
        r'^[a-z]+\d+$', r'^[a-z]\d+[a-z]?$',
        r'^[a-z]{2}\d+$', r'^[A-Z][a-z]\d+$',
        r'^[a-z]{1,2}\.[a-z]{1,2}$',
        r'^[a-z]{1,3}\.[a-z]{1,3}\.[a-z]{1,3}$',
    ]

    @staticmethod
    def detect_class_names(class_names):
        """检测类名混淆程度"""
        if not class_names:
            return {'score': 0, 'max_score': 10, 'level': '未知', 'details': ['无类名数据'], 'is_obfuscated': False}
        
        score = 0
        details = []
        
        # 1. 短类名检测
        short_count = sum(1 for c in class_names if len(c.split("/")[-1]) <= 2)
        short_ratio = short_count / len(class_names) if class_names else 0
        if short_ratio > 0.5:
            score += 3
            details.append(f"短类名比例极高: {short_count}/{len(class_names)} ({short_ratio:.0%})")
        elif short_ratio > 0.3:
            score += 2
            details.append(f"短类名比例高: {short_count}/{len(class_names)} ({short_ratio:.0%})")
        elif short_ratio > 0.1:
            score += 1
            details.append(f"短类名比例中: {short_count}/{len(class_names)} ({short_ratio:.0%})")

        # 2. 单字符包名
        pkg_single = sum(1 for c in class_names if len(c.split("/")) >= 2 and len(c.split("/")[-2]) == 1)
        if pkg_single > 10:
            score += 2
            details.append(f"单字符包名: {pkg_single}个类")
        elif pkg_single > 5:
            score += 1
            details.append(f"少量单字符包名")

        # 3. 正则匹配混淆模式
        obfuscated_count = 0
        for c in class_names:
            simple_name = c.split("/")[-1]
            for pat in ObfuscationDetector.OBFUSCATED_PATTERNS:
                if re.match(pat, simple_name) and simple_name not in ['R', 'Manifest', 'BuildConfig']:
                    obfuscated_count += 1
                    break
        obf_ratio = obfuscated_count / len(class_names) if class_names else 0
        if obf_ratio > 0.6:
            score += 3
            details.append(f"混淆类名模式匹配: {obfuscated_count}/{len(class_names)} ({obf_ratio:.0%})")
        elif obf_ratio > 0.3:
            score += 2
            details.append(f"部分混淆类名: {obfuscated_count}/{len(class_names)} ({obf_ratio:.0%})")

        # 4. ProGuard特征
        proguard_classes = [c for c in class_names if any(p in c.lower() for p in ['proguard', 'a', 'b', 'c'])]
        if proguard_classes:
            score += 1
            details.append("ProGuard/混淆类名特征")

        # 5. 加固壳类名
        packer_classes = [c for c in class_names if any(p in c.lower() for p in
            ['stub', 'shell', 'protect', 'safe', 'guard', 'encrypt', 'packer', 'loader', 'wrapper', 'proxy'])]
        if packer_classes:
            score += 2
            details.append(f"疑似加固壳类: {packer_classes[:5]}")

        level = '高' if score >= 5 else '中' if score >= 3 else '低'
        return {
            'score': score,
            'max_score': 10,
            'level': level,
            'details': details,
            'is_obfuscated': score >= 3,
            'short_name_ratio': short_ratio,
            'obfuscated_name_ratio': obf_ratio,
        }

    @staticmethod
    def detect_packer(apk_zip):
        """通过文件特征检测加固壳"""
        files = apk_zip.namelist()
        found = []
        indicators = {}
        
        for f in files:
            name = f.split("/")[-1]
            if name in ObfuscationDetector.PACKER_SIGNATURES:
                packer = ObfuscationDetector.PACKER_SIGNATURES[name]
                if packer not in indicators:
                    indicators[packer] = []
                indicators[packer].append(f)
                found.append(packer)
        
        # 额外检测：multi-dex + stub
        dex_files = [f for f in files if f.endswith('.dex')]
        if len(dex_files) > 5 and any('stub' in f.lower() for f in dex_files):
            found.append('MultiDex + Stub壳')
        
        # 检测特定特征目录
        if any('assets/0' in f and f.endswith('.dat') for f in files):
            if '360加固' not in found:
                found.append('疑似加固(assets/0*.dat特征)')
        
        return list(set(found))

    @staticmethod
    def detect_anti_tamper(text):
        """检测反篡改/反调试代码"""
        findings = []
        for pat in ObfuscationDetector.ANTI_TAMPER_SIGNATURES:
            matches = re.findall(pat, text, re.IGNORECASE | re.MULTILINE)
            if matches:
                findings.append({
                    'pattern': pat,
                    'count': len(matches),
                    'type': 'anti_tamper' if 'signature' in pat.lower() or 'check' in pat.lower() else 'anti_debug',
                })
        return findings

    @staticmethod
    def detect_reflection(text):
        """检测反射/动态加载使用"""
        findings = []
        for pat in ObfuscationDetector.REFLECTION_PATTERNS:
            matches = re.findall(pat, text, re.IGNORECASE)
            if matches:
                findings.append({
                    'pattern': pat,
                    'count': len(matches),
                })
        return findings

    @staticmethod
    def detect_string_encryption(text):
        """检测字符串加密特征"""
        indicators = []
        # 大量硬编码字节数组
        byte_arrays = re.findall(r'new byte\[\]\s*\{([^}]+)\}', text)
        if len(byte_arrays) > 5:
            indicators.append(f'大量byte数组({len(byte_arrays)}个)，可能用于字符串解密')
        
        # XOR解密模式
        if re.search(r'\bxor\b|\^\s*0x[0-9a-fA-F]+', text, re.IGNORECASE):
            indicators.append('检测到XOR解密模式')
        
        # 自定义解密方法
        decrypt_methods = re.findall(r'\b(decode|decrypt|deobfuscate|unpack|unxor|getString)\s*\(', text, re.IGNORECASE)
        if decrypt_methods:
            indicators.append(f'疑似解密方法: {list(set(decrypt_methods))[:5]}')
        
        return indicators
