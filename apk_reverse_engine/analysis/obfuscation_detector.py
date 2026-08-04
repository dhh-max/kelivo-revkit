import re
class ObfuscationDetector:
    @staticmethod
    def detect_class_names(class_names):
        score = 0
        details = []
        short_count = sum(1 for c in class_names if len(c.split("/")[-1]) <= 2)
        if short_count > len(class_names) * 0.3:
            score += 2; details.append(f"短类名比例高: {short_count}/{len(class_names)}")
        pkg_single = sum(1 for c in class_names if len(c.split("/")) >= 2 and len(c.split("/")[-2]) == 1)
        if pkg_single > 5: score += 2; details.append("单字符包名")
        if any("proguard" in c.lower() for c in class_names): score += 1; details.append("ProGuard混淆")
        packer = [c for c in class_names if any(p in c.lower() for p in ["stub","shell","protect","safe","guard","encrypt","packer","loader"])]
        if packer: score += 3; details.append(f"疑似加固壳: {packer[:5]}")
        return {"score": score, "max_score": 10, "level": "高" if score >= 5 else "中" if score >= 3 else "低",
                "details": details, "is_obfuscated": score >= 3}
    @staticmethod
    def detect_packer(apk_zip):
        files = apk_zip.namelist()
        indicators = {
            "libsecexe.so":"360加固","libsecmain.so":"360加固","libjiagu.so":"360加固",
            "libDexHelper.so":"腾讯加固","libexec.so":"腾讯加固","libtup.so":"腾讯加固",
            "libegis.so":"娜迦加固","libnese.so":"娜迦加固","libnesec.so":"娜迦加固",
            "libchaos.so":"网易加固","libddog.so":"网易加固","libcate.so":"网易加固",
            "libshella.so":"爱加密","libshell.so":"爱加密",
            "libSecShell.so":"梆梆加固","libSecShell_x86.so":"梆梆加固",
        }
        found = []
        for f in files:
            name = f.split("/")[-1]
            if name in indicators: found.append(indicators[name])
        return list(set(found))