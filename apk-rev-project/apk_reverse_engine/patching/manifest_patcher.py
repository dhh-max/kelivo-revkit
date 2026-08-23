class ManifestPatcher:
    @staticmethod
    def patch_attribute(data, attr_name, new_value):
        old = attr_name + '=\"'
        idx = data.find(old.encode())
        if idx == -1:
            return data
        start = idx + len(old.encode())
        end = data.find(b'"', start)
        if end == -1:
            return data
        return data[:start] + new_value.encode() + data[end:]

    @staticmethod
    def add_debuggable(data):
        return ManifestPatcher.patch_attribute(data, 'debuggable', 'true')

    @staticmethod
    def remove_backup(data):
        return ManifestPatcher.patch_attribute(data, 'allowBackup', 'false')

    @staticmethod
    def add_network_security_config(data, config_file='network_security_config.xml'):
        """添加网络安全配置引用"""
        return ManifestPatcher.patch_attribute(data, 'networkSecurityConfig', config_file)

    @staticmethod
    def add_extract_native_libs(data):
        """添加提取native库属性"""
        return ManifestPatcher.patch_attribute(data, 'extractNativeLibs', 'true')

    @staticmethod
    def add_uses_cleartext(data):
        """允许明文HTTP流量"""
        return ManifestPatcher.patch_attribute(data, 'usesCleartextTraffic', 'true')
