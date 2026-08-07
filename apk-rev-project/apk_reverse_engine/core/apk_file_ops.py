"""APK/ZIP 文件操作基础工具 - 直接在 APK 存档层面增删改文件

不依赖解包，直接操作 zipfile 内的条目。
"""
import zipfile, os, io


def list_apk_files(apk_path, pattern=None):
    """列出 APK 内所有文件路径（可选正则过滤）"""
    import re
    with zipfile.ZipFile(apk_path, 'r') as zf:
        names = zf.namelist()
    if pattern:
        names = [n for n in names if re.search(pattern, n)]
    return names


def delete_files_from_apk(apk_path, output_path, file_paths):
    """从 APK 中删除指定文件，输出新 APK

    Args:
        apk_path: 原始 APK 路径
        output_path: 输出 APK 路径
        file_paths: 要删除的文件路径列表（支持 str 或 [str]）

    Returns:
        dict: {'deleted': [...], 'not_found': [...], 'output': output_path}
    """
    if isinstance(file_paths, str):
        file_paths = [file_paths]
    file_set = set(file_paths)
    deleted = []
    not_found = []
    with zipfile.ZipFile(apk_path, 'r') as zin:
        names = zin.namelist()
        for f in file_set:
            if f in names:
                deleted.append(f)
            else:
                not_found.append(f)
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                if info.filename not in file_set:
                    data = zin.read(info.filename)
                    zout.writestr(info, data)
    return {'deleted': deleted, 'not_found': not_found, 'output': output_path}


def delete_files_by_pattern(apk_path, output_path, pattern):
    """从 APK 中按正则匹配删除文件

    Args:
        apk_path: 原始 APK 路径
        output_path: 输出 APK 路径
        pattern: 正则表达式，匹配的文件将被删除

    Returns:
        dict: {'deleted': [...], 'matched': int, 'output': output_path}
    """
    import re
    pat = re.compile(pattern)
    with zipfile.ZipFile(apk_path, 'r') as zin:
        names = zin.namelist()
        to_delete = [n for n in names if pat.search(n)]
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                if info.filename not in to_delete:
                    data = zin.read(info.filename)
                    zout.writestr(info, data)
    return {'deleted': to_delete, 'matched': len(to_delete), 'output': output_path}


def update_file_in_apk(apk_path, output_path, file_path, data):
    """更新 APK 中指定文件的内容

    Args:
        apk_path: 原始 APK 路径
        output_path: 输出 APK 路径
        file_path: 要更新的文件路径（如 'AndroidManifest.xml'）
        data: 新文件内容（bytes）

    Returns:
        dict: {'updated': file_path, 'output': output_path}
    """
    replaced = False
    with zipfile.ZipFile(apk_path, 'r') as zin:
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                if info.filename == file_path:
                    zout.writestr(info, data)
                    replaced = True
                else:
                    zout.writestr(info, zin.read(info.filename))
    return {'updated': file_path if replaced else None, 'output': output_path}


def add_file_to_apk(apk_path, output_path, file_path, data):
    """向 APK 中添加新文件（若已存在则覆盖）

    Args:
        apk_path: 原始 APK 路径
        output_path: 输出 APK 路径
        file_path: 新增文件路径（如 'assets/new_file.txt'）
        data: 文件内容（bytes）

    Returns:
        dict: {'added': file_path, 'output': output_path}
    """
    with zipfile.ZipFile(apk_path, 'r') as zin:
        existing = set(zin.namelist())
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                zout.writestr(info, zin.read(info.filename))
            if file_path not in existing:
                zout.writestr(file_path, data)
            else:
                # 覆盖
                pass  # 上面已写出旧内容，但需要重新写
    # 覆盖模式：重新打包
    if file_path in existing:
        with zipfile.ZipFile(apk_path, 'r') as zin:
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
                for info in zin.infolist():
                    if info.filename == file_path:
                        zout.writestr(info, data)
                    else:
                        zout.writestr(info, zin.read(info.filename))
    return {'added': file_path, 'output': output_path}