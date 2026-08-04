
class ManifestPatcher:
    @staticmethod
    def patch_attribute(data, attr_name, new_value):
        old = attr_name + '="'
        idx = data.find(old.encode())
        if idx == -1: return data
        start = idx + len(old.encode())
        end = data.find(b'"', start)
        if end == -1: return data
        return data[:start] + new_value.encode() + data[end:]
    @staticmethod
    def add_debuggable(data): return ManifestPatcher.patch_attribute(data, "debuggable", "true")
    @staticmethod
    def remove_backup(data): return ManifestPatcher.patch_attribute(data, "allowBackup", "false")
