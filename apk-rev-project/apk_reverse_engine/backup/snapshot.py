"""备份/恢复 - 分析会话导出/导入可移植JSON

参照 Operit 本地备份与恢复能力：
- 导出完整分析会话（配置、分析结果、知识库、产物索引）
- 导入到另一机器恢复工作区
- 单文件可移植，不依赖原始路径
"""
from datetime import datetime
import os, json, base64, shutil


class Snapshot:
    """APK 分析快照 - 导出/导入整个工作区"""

    @staticmethod
    def export(workspace_dir, output_path=None, include_artifacts=False):
        """将工作区导出为单个 JSON 文件

        参数:
            workspace_dir: 工作区目录
            output_path: 输出路径，默认 workspace_dir/../<name>_backup_<date>.json
            include_artifacts: 是否包含中间产物（base64 编码，可能很大）
        """
        if not os.path.isdir(workspace_dir):
            raise FileNotFoundError(f'工作区未找到: {workspace_dir}')
        ws_name = os.path.basename(workspace_dir)

        snapshot = {
            'type': 'apk-rev-workspace',
            'version': 2,
            'exported': datetime.now().isoformat(),
            'workspace': ws_name,
            'meta': None,
            'config': None,
            'results': {},
            'artifacts': {},
        }

        # meta
        mp = os.path.join(workspace_dir, 'meta.json')
        if os.path.isfile(mp):
            with open(mp) as f:
                snapshot['meta'] = json.load(f)

        # config
        cp = os.path.join(workspace_dir, 'config.json')
        if os.path.isfile(cp):
            with open(cp) as f:
                snapshot['config'] = json.load(f)

        # results
        rdir = os.path.join(workspace_dir, 'results')
        if os.path.isdir(rdir):
            for fname in sorted(os.listdir(rdir)):
                if fname.endswith('.json'):
                    with open(os.path.join(rdir, fname)) as f:
                        snapshot['results'][fname[:-5]] = json.load(f)

        # artifacts (可选)
        if include_artifacts:
            adir = os.path.join(workspace_dir, 'artifacts')
            if os.path.isdir(adir):
                for root, dirs, files in os.walk(adir):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        rel = os.path.relpath(fpath, adir)
                        with open(fpath, 'rb') as f:
                            snapshot['artifacts'][rel] = base64.b64encode(f.read()).decode()

        # 写入
        if not output_path:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(os.path.dirname(workspace_dir), f'{ws_name}_backup_{ts}.json')
        with open(output_path, 'w') as f:
            json.dump(snapshot, f, ensure_ascii=False, indent=2, default=str)
        return output_path

    @staticmethod
    def import_(snapshot_path, target_dir=None, extract_artifacts=False):
        """从快照恢复工作区"""
        with open(snapshot_path) as f:
            snap = json.load(f)

        if snap.get('type') != 'apk-rev-workspace':
            raise ValueError('无效的快照文件')

        ws_name = snap.get('workspace', 'imported')
        if not target_dir:
            target_dir = os.path.join(os.path.expanduser('~'), '.apk-rev', 'workspaces', ws_name)
        os.makedirs(target_dir, exist_ok=True)
        os.makedirs(os.path.join(target_dir, 'results'), exist_ok=True)
        os.makedirs(os.path.join(target_dir, 'artifacts'), exist_ok=True)

        # meta
        if snap.get('meta'):
            with open(os.path.join(target_dir, 'meta.json'), 'w') as f:
                json.dump(snap['meta'], f, ensure_ascii=False, indent=2)

        # config
        if snap.get('config'):
            with open(os.path.join(target_dir, 'config.json'), 'w') as f:
                json.dump(snap['config'], f, ensure_ascii=False, indent=2)

        # results
        for key, data in snap.get('results', {}).items():
            with open(os.path.join(target_dir, 'results', f'{key}.json'), 'w') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)

        # artifacts
        if extract_artifacts:
            for rel, b64data in snap.get('artifacts', {}).items():
                fpath = os.path.join(target_dir, 'artifacts', rel)
                os.makedirs(os.path.dirname(fpath), exist_ok=True)
                with open(fpath, 'wb') as f:
                    f.write(base64.b64decode(b64data))

        return target_dir


def export_analysis_result(apk_path, result, output_path=None, include_raw=False):
    """导出单次分析结果的可移植 JSON（快速分享/备份）"""
    import hashlib
    h = hashlib.sha256()
    with open(apk_path, 'rb') as f:
        h.update(f.read(65536))
    doc = {
        'type': 'apk-rev-analysis',
        'version': 1,
        'exported': datetime.now().isoformat(),
        'apk': {
            'name': os.path.basename(apk_path),
            'sha256_prefix': h.hexdigest()[:16],
            'size': os.path.getsize(apk_path),
        },
        'result': result,
        'raw': result if include_raw else None,
    }
    if not output_path:
        base = os.path.splitext(os.path.basename(apk_path))[0]
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = os.path.join(os.path.dirname(apk_path) or '.', f'{base}_analysis_{ts}.json')
    with open(output_path, 'w') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2, default=str)
    return output_path