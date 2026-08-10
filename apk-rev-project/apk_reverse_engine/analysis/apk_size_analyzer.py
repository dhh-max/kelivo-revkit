"""APK 体积分析器 - 按类别拆解 APK 大小组成"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
import os
import zipfile
from collections import defaultdict

class ApkSizeAnalyzer:
    """分析 APK 文件大小组成"""

    # 文件分类规则
    CATEGORY_RULES = [
        ('DEX',         lambda n: n.endswith('.dex')),
        ('Native Lib',  lambda n: n.startswith('lib/') and n.endswith('.so')),
        ('Resources',   lambda n: n.startswith('res/') or n == 'resources.arsc'),
        ('Assets',      lambda n: n.startswith('assets/')),
        ('META-INF',    lambda n: n.startswith('META-INF/')),
        ('Manifest',    lambda n: n == 'AndroidManifest.xml'),
        ('Kotlin',      lambda n: n.startswith('kotlin/') or '/kotlin/' in n),
        ('Other',       lambda n: True),
    ]

    @staticmethod
    def analyze(apk_path):
        """分析 APK 大小组成
        Args:
            apk_path: APK 文件路径
        Returns:
            dict: {total_size, categories, top_files, dex_details, native_details, recommendations}
        """
        if not os.path.isfile(apk_path):
            return {'error': f'File not found: {apk_path}'}

        total_apk_size = os.path.getsize(apk_path)
        categories = defaultdict(lambda: {'count': 0, 'size': 0, 'files': []})

        try:
            zf = zipfile.ZipFile(apk_path)
        except zipfile.BadZipFile:
            return {'error': 'Invalid ZIP/APK file'}

        all_files = []
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            compressed = info.compress_size
            uncompressed = info.file_size
            all_files.append({
                'name': name,
                'compressed': compressed,
                'uncompressed': uncompressed,
                'ratio': (1 - compressed / uncompressed * 100) if uncompressed > 0 else 0,
            })

            # 分类
            for cat_name, matcher in ApkSizeAnalyzer.CATEGORY_RULES:
                if matcher(name):
                    categories[cat_name]['count'] += 1
                    categories[cat_name]['size'] += uncompressed
                    categories[cat_name]['compressed_size'] = categories[cat_name].get('compressed_size', 0) + compressed
                    break

        zf.close()

        # 计算压缩后总大小
        total_compressed = sum(f['compressed'] for f in all_files)
        total_uncompressed = sum(f['uncompressed'] for f in all_files)

        # 排序类别
        cat_list = []
        for cat_name, data in sorted(categories.items(), key=lambda x: -x[1]['size']):
            cat_list.append({
                'category': cat_name,
                'file_count': data['count'],
                'uncompressed_size': data['size'],
                'compressed_size': data.get('compressed_size', 0),
                'uncompressed_kb': round(data['size'] / 1024, 1),
                'compressed_kb': round(data.get('compressed_size', 0) / 1024, 1),
                'percentage': round(data['size'] / total_uncompressed * 100, 1) if total_uncompressed > 0 else 0,
            })

        # Top 20 大文件
        top_files = sorted(all_files, key=lambda f: -f['uncompressed'])[:20]
        top_files_fmt = [{
            'name': f['name'],
            'uncompressed_kb': round(f['uncompressed'] / 1024, 1),
            'compressed_kb': round(f['compressed'] / 1024, 1),
            'compression_ratio': round(f['ratio'], 1),
        } for f in top_files]

        # DEX 详情
        dex_details = ApkSizeAnalyzer._analyze_dex_details(all_files)

        # Native Lib 详情
        native_details = ApkSizeAnalyzer._analyze_native_details(all_files)

        # 优化建议
        recommendations = ApkSizeAnalyzer._generate_recommendations(cat_list, top_files_fmt, total_uncompressed)

        return {
            'apk_path': apk_path,
            'total_apk_size': total_apk_size,
            'total_apk_kb': round(total_apk_size / 1024, 1),
            'total_apk_mb': round(total_apk_size / 1024 / 1024, 2),
            'total_uncompressed': total_uncompressed,
            'total_uncompressed_kb': round(total_uncompressed / 1024, 1),
            'total_compressed': total_compressed,
            'total_compressed_kb': round(total_compressed / 1024, 1),
            'compression_ratio': round((1 - total_compressed / total_uncompressed) * 100, 1) if total_uncompressed > 0 else 0,
            'total_file_count': len(all_files),
            'categories': cat_list,
            'top_20_files': top_files_fmt,
            'dex_details': dex_details,
            'native_details': native_details,
            'recommendations': recommendations,
        }

    @staticmethod
    def _analyze_dex_details(all_files):
        """分析 DEX 文件详情"""
        dex_files = [f for f in all_files if f['name'].endswith('.dex')]
        return [{
            'name': f['name'],
            'uncompressed_kb': round(f['uncompressed'] / 1024, 1),
            'compressed_kb': round(f['compressed'] / 1024, 1),
        } for f in sorted(dex_files, key=lambda x: -x['uncompressed'])]

    @staticmethod
    def _analyze_native_details(all_files):
        """分析 Native Lib 详情"""
        so_files = [f for f in all_files if f['name'].startswith('lib/') and f['name'].endswith('.so')]
        # 按 ABI 分组
        abi_groups = defaultdict(list)
        for f in so_files:
            parts = f['name'].split('/')
            if len(parts) >= 2:
                abi = parts[1]
                abi_groups[abi].append(f)
        result = {}
        for abi, files in abi_groups.items():
            total = sum(f['uncompressed'] for f in files)
            result[abi] = {
                'file_count': len(files),
                'total_kb': round(total / 1024, 1),
                'files': [{
                    'name': f['name'].split('/')[-1],
                    'uncompressed_kb': round(f['uncompressed'] / 1024, 1),
                } for f in sorted(files, key=lambda x: -x['uncompressed'])],
            }
        return result

    @staticmethod
    def _generate_recommendations(categories, top_files, total_uncompressed):
        """生成优化建议"""
        recs = []
        cat_map = {c['category']: c for c in categories}

        # DEX 过大
        if 'DEX' in cat_map:
            dex_pct = cat_map['DEX']['percentage']
            if dex_pct > 40:
                recs.append({
                    'category': 'DEX',
                    'severity': 'high',
                    'suggestion': f"DEX 占比 {dex_pct}%，建议启用 R8/ProGuard 混淆和代码缩减",
                })

        # Native Lib 多 ABI
        # (由调用方传入 native_details)

        # Resources 过大
        if 'Resources' in cat_map:
            res_pct = cat_map['Resources']['percentage']
            if res_pct > 30:
                recs.append({
                    'category': 'Resources',
                    'severity': 'medium',
                    'suggestion': f"资源文件占比 {res_pct}%，建议使用 WebP 格式、移除无用资源",
                })

        # Assets 过大
        if 'Assets' in cat_map:
            assets_kb = cat_map['Assets']['uncompressed_kb']
            if assets_kb > 5000:
                recs.append({
                    'category': 'Assets',
                    'severity': 'medium',
                    'suggestion': f"Assets 文件夹 {assets_kb}KB，检查是否有大体积字体/模型/数据库文件",
                })

        # 大文件检测
        for f in top_files[:5]:
            if f['uncompressed_kb'] > 2000:
                recs.append({
                    'category': 'Large File',
                    'severity': 'low',
                    'suggestion': f"大文件 {f['name']} ({f['uncompressed_kb']}KB)，考虑是否必要",
                })

        return recs

    @staticmethod
    def get_summary(analysis_result):
        """生成简洁摘要"""
        return {
            'total_apk_mb': analysis_result.get('total_apk_mb', 0),
            'total_uncompressed_mb': round(analysis_result.get('total_uncompressed_kb', 0) / 1024, 2),
            'compression_ratio': analysis_result.get('compression_ratio', 0),
            'file_count': analysis_result.get('total_file_count', 0),
            'top_categories': [{
                'category': c['category'],
                'size_kb': c['uncompressed_kb'],
                'percentage': c['percentage'],
            } for c in analysis_result.get('categories', [])[:5]],
            'recommendations_count': len(analysis_result.get('recommendations', [])),
        }
