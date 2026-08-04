
class IntegrityPatcher:
    @staticmethod
    def disable_signature_check(smali_code):
        smali_code = smali_code.replace("getPackageManager().*?checkSignatures", "// disabled")
        smali_code = smali_code.replace("signatures[.*?].*?equals", "// disabled")
        smali_code = smali_code.replace("PackageManager->signatures", "// disabled")
        return smali_code
    @staticmethod
    def patch_verify_install(smali_code):
        smali_code = smali_code.replace(
            "invoke-static, {v0}, Landroid/app/Instrumentation;->newApplication",
            "invoke-static, {v0}, Lmy/app/Instrumentation;->newApplication")
        return smali_code
