class ResourcePatcher:
    """资源文件补丁工具"""

    @staticmethod
    def patch_arsc(data, old_str, new_str):
        """替换ARSC中的UTF-16LE字符串"""
        return data.replace(old_str.encode('utf-16le'), new_str.encode('utf-16le'))

    @staticmethod
    def replace_in_xml(data, old, new):
        """替换XML中的文本"""
        return data.replace(old.encode(), new.encode())

    @staticmethod
    def patch_image_file(data, old_hex, new_hex):
        """二进制替换图片资源"""
        old = bytes.fromhex(old_hex.replace(' ', ''))
        new = bytes.fromhex(new_hex.replace(' ', ''))
        if len(old) != len(new):
            raise ValueError('old_hex and new_hex must have same length')
        return data.replace(old, new, 1)

    @staticmethod
    def replace_asset(data, old_str, new_str):
        """替换assets中的字符串"""
        return data.replace(old_str.encode(), new_str.encode())

    @staticmethod
    def patch_arsc_package_name(data, new_package_name):
        """修改ARSC中的包名"""
        # ARSC中包名以UTF-16LE存储，在package chunk中
        # 包名偏移通常在头部后12字节处，长度256字节
        if len(data) < 12:
            return data
        # 跳过前12字节，找到包名字段
        old_pkg = data[12:12+256]
        # 解码原包名
        try:
            old_name = old_pkg.decode('utf-16le', errors='replace').split('\x00')[0]
        except Exception:
            return data
        # 用新包名替换
        new_pkg_data = new_package_name.encode('utf-16le') + b'\x00' * (256 - len(new_package_name.encode('utf-16le')))
        return data[:12] + new_pkg_data[:256] + data[12+256:]
