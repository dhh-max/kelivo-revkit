"""APK清理优化器 - 移除无用文件、冗余资源，优化APK尺寸"""
import os, zipfile, re

class APKCleaner:
    """APK清理优化引擎：分析冗余文件、建议删除项，执行清理"""

    # 通常可安全删除的调试/测试文件
    DEBUG_FILES = [
        r'res/raw/.*\.txt$',
        r'res/raw/.*test.*',
        r'res/raw/.*debug.*',
        r'res/raw/.*sample.*',
        r'res/raw/.*example.*',
        r'res/raw/.*demo.*',
        r'res/raw/.*mock.*',
        r'res/raw/.*stub.*',
        r'res/raw/.*placeholder.*',
        r'res/drawable.*/.*placeholder.*',
        r'res/drawable.*/.*_test_.*',
        r'res/drawable.*/.*debug.*',
        r'res/drawable.*/.*sample.*',
        r'assets/.*test.*',
        r'assets/.*debug.*',
        r'assets/.*sample.*',
        r'assets/.*example.*',
    ]

    # 可安全删除的META-INF（重签名后）
    META_CLEANUP = [
        r'META-INF/.*\.SF$',
        r'META-INF/.*\.RSA$',
        r'META-INF/.*\.DSA$',
        r'META-INF/.*\.MF$',
        r'META-INF/.*\.EC$',
        r'META-INF/MANIFEST\.MF$',
    ]

    # 冗余备份文件
    BACKUP_FILES = [
        r'.*\.bak$',
        r'.*\.backup$',
        r'.*~$',
        r'.*\.orig$',
        r'.*/\.DS_Store$',
        r'.*/Thumbs\.db$',
        r'.*\.swp$',
    ]

    # 可能无用的资源类型
    UNUSED_RES_TYPES = [
        'drawable-ldrtl-', 'drawable-ldltr-',
        'drawable-anydpi-v26', 'drawable-anydpi-v21',
        'mipmap-anydpi-v26',
    ]

    @staticmethod
    def analyze(apk_path):
        """分析APK中可清理的冗余文件"""
        results = {
            'apk_path': apk_path,
            'size': os.path.getsize(apk_path),
            'debug_files': [],
            'backup_files': [],
            'meta_inf_files': [],
            'unused_resources': [],
            'large_files': [],
            'duplicates': [],
            'total_waste': 0,
            'recommendations': [],
        }

        with zipfile.ZipFile(apk_path, 'r') as z:
            infos = z.infolist()
            files_by_size = {}
            file_contents = {}

            for info in infos:
                name = info.filename
                size = info.file_size
                files_by_size[name] = size

                # 1. 调试/测试文件
                for pat in APKCleaner.DEBUG_FILES:
                    if re.match(pat, name, re.IGNORECASE):
                        results['debug_files'].append({'file': name, 'size': size})
                        results['total_waste'] += size
                        break

                # 2. META-INF签名文件
                for pat in APKCleaner.META_CLEANUP:
                    if re.match(pat, name, re.IGNORECASE):
                        results['meta_inf_files'].append({'file': name, 'size': size})
                        break

                # 3. 备份文件
                for pat in APKCleaner.BACKUP_FILES:
                    if re.match(pat, name, re.IGNORECASE):
                        results['backup_files'].append({'file': name, 'size': size})
                        results['total_waste'] += size
                        break

                # 4. 大文件排名
                if size > 1024 * 1024:  # > 1MB
                    results['large_files'].append({'file': name, 'size': size})

                # 5. 重复文件检测 (按CRC)
                if not info.is_dir():
                    try:
                        data = z.read(name)
                        file_contents[name] = data
                    except:
                        pass

            # 5. 重复文件检测
            seen = {}
            for name, data in file_contents.items():
                crc = hash(data)  # 简化：用hash做近似
                if crc in seen:
                    if data == seen[crc]['data']:
                        results['duplicates'].append({
                            'original': seen[crc]['name'],
                            'duplicate': name,
                            'size': len(data),
                        })
                        results['total_waste'] += len(data)
                else:
                    seen[crc] = {'name': name, 'data': data}

            # 6. 未使用的资源目录
            res_dirs = set()
            for name in files_by_size:
                if name.startswith('res/') and '/' in name:
                    parts = name.split('/')
                    if len(parts) >= 2:
                        res_dirs.add(parts[1])

            # 检测低密度资源目录（可能不需要）
            alt_density_dirs = [d for d in res_dirs if any(
                suffix in d for suffix in ['-ldpi', '-mdpi', '-tvdpi', '-nodpi', '-anydpi']
            )]
            if alt_density_dirs:
                results['recommendations'].append({
                    'type': '资源密度',
                    'detail': f'包含低密度资源目录: {alt_density_dirs}，可考虑移除不需要的密度',
                    'potential_saving': '视情况',
                })

        # 大文件排名
        results['large_files'].sort(key=lambda x: x['size'], reverse=True)
        results['large_files'] = results['large_files'][:20]

        # 生成建议
        if results['debug_files']:
            results['recommendations'].append({
                'type': '调试文件',
                'detail': f'发现 {len(results["debug_files"])} 个调试/测试文件，可安全删除',
                'potential_saving': sum(f['size'] for f in results['debug_files']),
            })

        if results['duplicates']:
            results['recommendations'].append({
                'type': '重复文件',
                'detail': f'发现 {len(results["duplicates"])} 组重复文件，可删除冗余副本',
                'potential_saving': sum(f['size'] for f in results['duplicates']),
            })

        # 综合评分
        waste_ratio = results['total_waste'] / max(1, results['size']) * 100
        results['waste_ratio'] = round(waste_ratio, 1)
        results['clean_potential'] = {
            'waste_bytes': results['total_waste'],
            'waste_ratio': f'{waste_ratio:.1f}%',
            'level': '优秀' if waste_ratio < 1 else '良好' if waste_ratio < 5 else '一般' if waste_ratio < 10 else '需优化',
        }

        return results

    @staticmethod
    def clean_apk(apk_path, output_path, remove_debug=True, remove_meta=False, remove_backup=True):
        """清理APK并保存为新文件（重签名后需重新签名）"""
        kept = 0
        removed = 0
        removed_size = 0

        def _should_remove(name):
            if remove_debug:
                for pat in APKCleaner.DEBUG_FILES:
                    if re.match(pat, name, re.IGNORECASE):
                        return True
            if remove_meta:
                for pat in APKCleaner.META_CLEANUP:
                    if re.match(pat, name, re.IGNORECASE):
                        return True
            if remove_backup:
                for pat in APKCleaner.BACKUP_FILES:
                    if re.match(pat, name, re.IGNORECASE):
                        return True
            return False

        with zipfile.ZipFile(apk_path, 'r') as zin:
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
                for info in zin.infolist():
                    name = info.filename
                    if _should_remove(name):
                        removed += 1
                        removed_size += info.file_size
                        continue
                    data = zin.read(name)
                    zout.writestr(info, data)
                    kept += 1

        return {
            'success': True,
            'output': output_path,
            'kept': kept,
            'removed': removed,
            'removed_size': removed_size,
            'original_size': os.path.getsize(apk_path),
            'new_size': os.path.getsize(output_path),
            'saved_percent': round((1 - os.path.getsize(output_path) / max(1, os.path.getsize(apk_path))) * 100, 1),
        }