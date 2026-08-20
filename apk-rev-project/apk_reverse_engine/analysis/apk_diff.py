"""APK差异对比引擎 - 深度对比两个APK的结构、类、方法、权限、资源差异"""
from collections import defaultdict
import os, zipfile, hashlib

class APKDiffEngine:
    """APK差异对比分析器"""

    @staticmethod
    def _file_list(zip_fp):
        """获取ZIP内文件列表及大小、CRC"""
        files = {}
        for info in zip_fp.infolist():
            files[info.filename] = {
                'size': info.file_size,
                'compress_size': info.compress_size,
                'crc': f'{info.CRC:08x}',
            }
        return files

    @staticmethod
    def _categorize_files(files):
        """按类别分类文件"""
        cats = defaultdict(list)
        for name in files:
            if name.startswith('META-INF/'):
                cats['META-INF'].append(name)
            elif name.startswith('classes') and name.endswith('.dex'):
                cats['DEX'].append(name)
            elif name.startswith('lib/'):
                cats['SO'].append(name)
            elif name.startswith('res/'):
                cats['Resources'].append(name)
            elif name.startswith('assets/'):
                cats['Assets'].append(name)
            elif name.startswith('kotlin/'):
                cats['Kotlin'].append(name)
            elif name == 'AndroidManifest.xml':
                cats['Manifest'].append(name)
            elif name == 'resources.arsc':
                cats['ARSC'].append(name)
            else:
                cats['Other'].append(name)
        return dict(cats)

    @staticmethod
    def compare_manifest(m1, m2):
        """对比manifest关键信息"""
        diffs = []
        for key in ['package', 'versionName', 'versionCode', 'minSdk', 'targetSdk']:
            v1 = m1.get(key, m1.get('sdk', {}).get(key) if key in ('minSdk','targetSdk') else None)
            v2 = m2.get(key, m2.get('sdk', {}).get(key) if key in ('minSdk','targetSdk') else None)
            if key in ('minSdk','targetSdk'):
                v1 = m1.get('sdk', {}).get(key)
                v2 = m2.get('sdk', {}).get(key)
            if key == 'versionCode':
                v1 = m1.get('sdk', {}).get('versionCode')
                v2 = m2.get('sdk', {}).get('versionCode')
            if key == 'versionName':
                v1 = m1.get('sdk', {}).get('versionName')
                v2 = m2.get('sdk', {}).get('versionName')
            if v1 != v2:
                diffs.append({'field': key, 'old': v1, 'new': v2})
        return diffs

    @staticmethod
    def compare_permissions(perms1, perms2):
        """对比权限差异"""
        s1, s2 = set(perms1), set(perms2)
        return {
            'added': sorted(s2 - s1)[:50],
            'removed': sorted(s1 - s2)[:50],
            'common': sorted(s1 & s2)[:50],
        }

    @staticmethod
    def compare_classes(names1, names2):
        """对比类名差异"""
        s1, s2 = set(names1), set(names2)
        return {
            'added': sorted(s2 - s1)[:100],
            'removed': sorted(s1 - s2)[:100],
            'common_count': len(s1 & s2),
        }

    @staticmethod
    def compare_apis(apk1_path, apk2_path):
        """对比两个APK结构差异"""
        result = {}
        with zipfile.ZipFile(apk1_path, 'r') as z1, zipfile.ZipFile(apk2_path, 'r') as z2:
            files1 = APKDiffEngine._file_list(z1)
            files2 = APKDiffEngine._file_list(z2)

            names1 = set(files1.keys())
            names2 = set(files2.keys())

            # 文件增删
            added_files = names2 - names1
            removed_files = names1 - names2
            common = names1 & names2

            # 修改的文件
            modified = []
            for f in sorted(common):
                if files1[f]['crc'] != files2[f]['crc']:
                    modified.append({
                        'file': f,
                        'old_size': files1[f]['size'],
                        'new_size': files2[f]['size'],
                        'old_crc': files1[f]['crc'],
                        'new_crc': files2[f]['crc'],
                    })

            result['files'] = {
                'total_old': len(names1),
                'total_new': len(names2),
                'added': sorted(added_files)[:100],
                'removed': sorted(removed_files)[:100],
                'modified': modified[:100],
                'unchanged': len(common) - len(modified),
            }

            # 分类统计
            cats1 = APKDiffEngine._categorize_files(files1)
            cats2 = APKDiffEngine._categorize_files(files2)
            result['categories'] = {}
            all_cats = set(list(cats1.keys()) + list(cats2.keys()))
            for cat in sorted(all_cats):
                c1 = len(cats1.get(cat, []))
                c2 = len(cats2.get(cat, []))
                if c1 != c2:
                    result['categories'][cat] = {'old': c1, 'new': c2}

            # 文件大小对比
            size1 = sum(f['size'] for f in files1.values())
            size2 = sum(f['size'] for f in files2.values())
            result['size'] = {
                'old_raw': size1,
                'new_raw': size2,
                'old_compressed': sum(f['compress_size'] for f in files1.values()),
                'new_compressed': sum(f['compress_size'] for f in files2.values()),
                'diff_raw': size2 - size1,
                'diff_compressed': sum(f['compress_size'] for f in files2.values()) - sum(f['compress_size'] for f in files1.values()),
            }

        return result

    @staticmethod
    def compare_full(apk1_path, apk2_path, manifest1=None, manifest2=None,
                     classes1=None, classes2=None, perms1=None, perms2=None):
        """全量对比两个APK"""
        result = {'apk1': apk1_path, 'apk2': apk2_path}

        # 结构对比
        result['structure'] = APKDiffEngine.compare_apis(apk1_path, apk2_path)

        # Manifest对比
        if manifest1 and manifest2:
            result['manifest'] = APKDiffEngine.compare_manifest(manifest1, manifest2)

        # 权限对比
        if perms1 is not None and perms2 is not None:
            result['permissions'] = APKDiffEngine.compare_permissions(perms1, perms2)

        # 类对比
        if classes1 is not None and classes2 is not None:
            result['classes'] = APKDiffEngine.compare_classes(classes1, classes2)

        # 综合评分
        changes = 0
        changes += len(result.get('structure', {}).get('files', {}).get('added', []))
        changes += len(result.get('structure', {}).get('files', {}).get('removed', []))
        changes += len(result.get('structure', {}).get('files', {}).get('modified', []))
        changes += len(result.get('manifest', []))
        changes += len(result.get('permissions', {}).get('added', []))
        changes += len(result.get('permissions', {}).get('removed', []))
        changes += len(result.get('classes', {}).get('added', []))
        changes += len(result.get('classes', {}).get('removed', []))

        result['summary'] = {
            'total_changes': changes,
            'change_level': '微小' if changes < 5 else '中等' if changes < 20 else '显著' if changes < 100 else '重大',
        }

        return result