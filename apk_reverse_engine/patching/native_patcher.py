
class NativePatcher:
    @staticmethod
    def patch_hex(data, old_hex, new_hex):
        old = bytes.fromhex(old_hex.replace(" ", ""))
        new = bytes.fromhex(new_hex.replace(" ", ""))
        return data.replace(old, new)
    @staticmethod
    def patch_string(data, old_str, new_str, max_replace=1):
        old = old_str.encode() + b"\x00"
        new = new_str.encode() + b"\x00"
        if len(new) > len(old): new = new[:len(old)]
        count = 0; result = data
        while count < max_replace:
            idx = result.find(old)
            if idx == -1: break
            result = result[:idx] + new + result[idx+len(old):]
            count += 1
        return result
