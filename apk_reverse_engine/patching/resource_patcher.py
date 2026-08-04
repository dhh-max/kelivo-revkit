
class ResourcePatcher:
    @staticmethod
    def patch_arsc(data, old_str, new_str):
        return data.replace(old_str.encode("utf-16le"), new_str.encode("utf-16le"))
    @staticmethod
    def replace_in_xml(data, old, new):
        return data.replace(old.encode(), new.encode())
