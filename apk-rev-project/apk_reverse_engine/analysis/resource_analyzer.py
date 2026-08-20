"""APK 资源分析器 — 资源大小分布/冗余资源/图片格式/布局复杂度"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
import os, zipfile
from collections import defaultdict, Counter

class ResourceAnalyzer:
    """APK 资源分析引擎"""

    # 资源类型分类
    RESOURCE_CATEGORIES = {
        'images': {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg'},
        'layouts': {'.xml'},
        'drawables': {'.9.png'},
        'fonts': {'.ttf', '.otf', '.woff', '.woff2'},
        'audio': {'.mp3', '.wav', '.ogg', '.aac', '.m4a'},
        'video': {'.mp4', '.webm', '.3gp', '.avi'},
        'native': {'.so'},
        'dex': {'.dex'},
        'assets': set(),
        'resources': {'arsc'},
        'meta': {'.mf', '.rsa', '.dsa', '.sf'},
        'config': {'.json', '.properties', '.cfg', '.conf', '.xml'},
    }

    # 大文件阈值
    LARGE_FILE_THRESHOLD = 100 * 1024  # 100KB

    @staticmethod
    def analyze(apk_path):
        """分析 APK 中的资源"""
        if not os.path.exists(apk_path):
            return {'error': f'文件不存在: {apk_path}'}

        try:
            with zipfile.ZipFile(apk_path) as zf:
                entries = zf.infolist()
        except Exception as e:
            return {'error': f'无法打开 APK: {e}'}

        total_size = 0
        total_compressed = 0
        category_stats = defaultdict(lambda: {'count': 0, 'size': 0, 'compressed': 0, 'files': []})
        large_files = []
        duplicate_sizes = defaultdict(list)
        all_files = []

        for entry in entries:
            if entry.is_dir():
                continue
            name = entry.filename
            file_size = entry.file_size
            compressed_size = entry.compress_size
            total_size += file_size
            total_compressed += compressed_size

            ext = os.path.splitext(name)[1].lower()
            if not ext:
                if name.endswith('resources.arsc'):
                    ext = '.arsc'
                elif name.startswith('META-INF/'):
                    ext = '.meta'
                elif name.startswith('assets/'):
                    ext = '.asset'
                elif name.startswith('res/'):
                    ext = '.res'

            category = ResourceAnalyzer._categorize(name, ext)
            cat_stat = category_stats[category]
            cat_stat['count'] += 1
            cat_stat['size'] += file_size
            cat_stat['compressed'] += compressed_size
            if len(cat_stat['files']) < 20:
                cat_stat['files'].append(name)

            if file_size >= ResourceAnalyzer.LARGE_FILE_THRESHOLD:
                large_files.append({
                    'name': name,
                    'size': file_size,
                    'compressed': compressed_size,
                    'compression_ratio': round(compressed_size / max(file_size, 1), 4),
                })

            duplicate_sizes[file_size].append(name)
            all_files.append({
                'name': name,
                'size': file_size,
                'compressed': compressed_size,
                'category': category,
            })

        # 找出可能重复的文件（相同大小）
        potential_duplicates = {
            size: names for size, names in duplicate_sizes.items()
            if len(names) > 1 and size > 100
        }

        # 压缩率
        compression_ratio = round(total_compressed / max(total_size, 1), 4)
        compression_saved = total_size - total_compressed

        # 图片资源分析
        image_stats = ResourceAnalyzer._analyze_images(category_stats.get('images', {}), all_files)

        # 顶层目录统计
        dir_stats = defaultdict(lambda: {'count': 0, 'size': 0})
        for f in all_files:
            top_dir = f['name'].split('/')[0] if '/' in f['name'] else '(root)'
            dir_stats[top_dir]['count'] += 1
            dir_stats[top_dir]['size'] += f['size']

        large_files.sort(key=lambda x: x['size'], reverse=True)

        return {
            'total_files': len(all_files),
            'total_size': total_size,
            'total_compressed': total_compressed,
            'compression_ratio': compression_ratio,
            'compression_saved_bytes': compression_saved,
            'compression_saved_pct': round(compression_saved / max(total_size, 1) * 100, 2),
            'category_stats': {
                cat: {
                    'count': s['count'],
                    'size': s['size'],
                    'compressed': s['compressed'],
                    'pct': round(s['size'] / max(total_size, 1) * 100, 2),
                    'sample_files': s['files'],
                }
                for cat, s in sorted(category_stats.items(), key=lambda x: x[1]['size'], reverse=True)
            },
            'directory_stats': {
                d: {'count': s['count'], 'size': s['size']}
                for d, s in sorted(dir_stats.items(), key=lambda x: x[1]['size'], reverse=True)
            },
            'large_files': large_files[:30],
            'potential_duplicates': {
                str(size): names for size, names in list(potential_duplicates.items())[:20]
            },
            'image_analysis': image_stats,
        }

    @staticmethod
    def _categorize(name, ext):
        if name.startswith('META-INF/'):
            return 'meta_inf'
        if name.startswith('assets/'):
            return 'assets'
        if name == 'resources.arsc' or ext == '.arsc':
            return 'resources'
        if name.startswith('res/'):
            if ext in {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.9.png'}:
                return 'res_images'
            if ext == '.xml':
                return 'res_xml'
            return 'res_other'
        if ext in {'.dex'}:
            return 'dex'
        if ext in {'.so'}:
            return 'native'
        if ext in {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg'}:
            return 'images'
        if ext in {'.ttf', '.otf', '.woff', '.woff2'}:
            return 'fonts'
        if ext in {'.mp3', '.wav', '.ogg', '.aac', '.m4a'}:
            return 'audio'
        if ext in {'.mp4', '.webm', '.3gp', '.avi'}:
            return 'video'
        return 'other'

    @staticmethod
    def _analyze_images(image_cat, all_files):
        """分析图片资源"""
        image_files = [f for f in all_files if f['category'] in ('images', 'res_images')]
        if not image_files:
            return {'count': 0}

        format_dist = Counter()
        total_image_size = 0
        for f in image_files:
            ext = os.path.splitext(f['name'])[1].lower()
            format_dist[ext] += 1
            total_image_size += f['size']

        largest_images = sorted(image_files, key=lambda x: x['size'], reverse=True)[:10]

        return {
            'count': len(image_files),
            'total_size': total_image_size,
            'format_distribution': dict(format_dist),
            'largest_images': [
                {'name': f['name'], 'size': f['size']} for f in largest_images
            ],
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'total_files': result['total_files'],
            'total_size': result['total_size'],
            'total_compressed': result['total_compressed'],
            'compression_ratio': result['compression_ratio'],
            'compression_saved_pct': result['compression_saved_pct'],
            'categories': {k: {'count': v['count'], 'size': v['size']} for k, v in result['category_stats'].items()},
            'large_files_count': len(result['large_files']),
            'potential_dup_groups': len(result['potential_duplicates']),
            'image_count': result['image_analysis'].get('count', 0),
        }