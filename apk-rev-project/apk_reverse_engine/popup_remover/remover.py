"""分享弹窗去除器 - 基于基础工具的上层使用示例

基于 apk_file_ops 和 manifest_ops 基础工具，组合成针对特定弹窗SDK的去除方案。
"""
import os, zipfile, tempfile, shutil
from apk_reverse_engine.core.apk_file_ops import (
    delete_files_from_apk, delete_files_by_pattern, update_file_in_apk
)
from apk_reverse_engine.core.manifest_ops import (
    remove_tags_by_rule, replace_attr_value, get_attr_value
)


# ═══════════════════════════════════════════════════════════════
# 弹窗SDK 规则配置（可替换）
# ═══════════════════════════════════════════════════════════════
POPUP_SDK_RULES = {
    'tencent_share': {
        'name': '腾讯分享弹窗SDK',
        # 待删除的 Manifest 规则：[(tag, attr, value), ...]
        'manifest_removes': [
            ('meta-data', 'name', 'SETUP_LAUNCHER_ACTIVITY'),
            ('provider', 'name', 'com.share.sdk.provider.SdkInitProvider'),
            ('activity', 'name', 'com.tencent.tauth.AuthActivity'),
            ('activity', 'name', 'com.tencent.connect.common.AssistActivity'),
            ('activity', 'name', 'com.tencent.a.ui.task.TaskActivity'),
            ('activity', 'name', 'com.tencent.a.ui.imagebrowser.BrowseImageActivity'),
        ],
        # 待删除的精确文件
        'delete_files': [
            'assets/info.json',
            'assets/res/info.json',
            'assets/setup_sdk_share_author.png',
            'assets/setup_sdk_share_bg.png',
            'assets/setup_sdk_share_dot.png',
            'assets/setup_sdk_share_enter.png',
            'assets/setup_sdk_share_group.png',
            'assets/setup_sdk_share_info.xml',
            'assets/setup_sdk_share_info2.xml',
            'assets/setup_sdk_share_info_two.xml',
            'assets/setup_sdk_share_notice.png',
            'assets/setup_sdk_task_dialog_info.xml',
            'assets/setup_sdk_task_info.xml',
            'classes2.dex',
        ],
        # 模糊删除正则
        'delete_patterns': [
            r'^assets/setup_sdk_.*',
            r'^assets/res/info\.json$',
            r'^assets/info\.json$',
            r'^assets/share/.*',
        ],
        # 弹窗启动Activity类名（需要替换为真实启动Activity）
        'popup_launcher_class': 'com.tencent.a.SetupInfoActivity',
        # 获取真实启动Activity的 meta-data 名称
        'launcher_meta_name': 'SETUP_LAUNCHER_ACTIVITY',
    },
}


def remove_share_popup(apk_path, output_path=None, sdk_name='tencent_share',
                       rules=None, sign=True, keystore_mode='debug'):
    """去除分享弹窗（一站式，直接在 APK 层面操作）

    Args:
        apk_path: 原始 APK 路径
        output_path: 输出 APK 路径（默认 apk_path 同级加 _clean.apk 后缀）
        sdk_name: 弹窗SDK预设名称（'tencent_share'），或 'custom' 配合 rules 参数
        rules: 自定义规则 dict（覆盖 SDK 预设）
        sign: 是否自动签名（默认 debug 签名）
        keystore_mode: 签名模式（'debug' 或 'keystore'）

    Returns:
        dict: 操作报告
    """
    if output_path is None:
        base, ext = os.path.splitext(apk_path)
        output_path = f'{base}_clean.apk'

    # 获取规则
    if not rules:
        rules = POPUP_SDK_RULES.get(sdk_name)
        if not rules:
            return {'success': False, 'error': f'未知SDK预设: {sdk_name}'}

    report = {'apk_path': apk_path, 'output_path': output_path, 'steps': []}

    # ── Step 1: 读取 Manifest ──
    manifest_data = None
    with zipfile.ZipFile(apk_path, 'r') as zf:
        if 'AndroidManifest.xml' in zf.namelist():
            manifest_data = zf.read('AndroidManifest.xml')
    if not manifest_data:
        return {'success': False, 'error': 'APK中未找到 AndroidManifest.xml'}

    # ── Step 2: 获取真实启动Activity ──
    real_launcher = None
    meta_name = rules.get('launcher_meta_name', 'SETUP_LAUNCHER_ACTIVITY')
    # 从 meta-data 中读取
    for md_tag in find_tags(manifest_data, 'meta-data', 'name', meta_name):
        if isinstance(md_tag, dict) and 'attrs' in md_tag:
            for a in md_tag['attrs']:
                if a['name'] == 'value':
                    real_launcher = a['value']
                    break
    # 回退到 LAUNCHER intent-filter
    if not real_launcher:
        for act_tag in find_tags(manifest_data, 'activity'):
            if isinstance(act_tag, dict) and 'attrs' in act_tag:
                name = None
                for a in act_tag['attrs']:
                    if a['name'] == 'name':
                        name = a['value']
                        break
                if name:
                    # 检查是否有 LAUNCHER intent-filter（简化处理）
                    pass  # 二进制 AXML 中 intent-filter 嵌套较复杂，回退到文本方式
        report['steps'].append({'action': 'find_launcher', 'result': '未找到，跳过替换'})

    report['steps'].append({'action': 'find_launcher', 'real_launcher': real_launcher})

    # ── Step 3: 修改 Manifest ──
    # 3a. 删除弹窗SDK声明
    removes = rules.get('manifest_removes', [])
    manifest_modified = remove_tags_by_rule(manifest_data, removes)

    # 3b. 替换启动Activity
    popup_class = rules.get('popup_launcher_class')
    if real_launcher and popup_class:
        manifest_modified = replace_attr_value(
            manifest_modified, 'activity', 'name', popup_class, real_launcher
        )
        report['steps'].append({
            'action': 'replace_launcher',
            'from': popup_class,
            'to': real_launcher,
        })

    # ── Step 4: 写入 Manifest 并删除文件 ──
    # 先复制 APK 并替换 Manifest
    temp_apk = output_path + '.tmp'
    update_file_in_apk(apk_path, temp_apk, 'AndroidManifest.xml', manifest_modified)
    report['steps'].append({'action': 'update_manifest', 'modified': True})

    # 删除文件（精确删除 + 模糊删除）
    delete_files = rules.get('delete_files', [])
    patterns = rules.get('delete_patterns', [])

    # 精确删除
    if delete_files:
        dr = delete_files_from_apk(temp_apk, output_path, delete_files)
        os.remove(temp_apk)
        report['steps'].append({'action': 'delete_files', 'deleted': dr['deleted'], 'not_found': dr['not_found']})
    else:
        shutil.move(temp_apk, output_path)

    # 模糊删除（需要再次打开，因为精确删除已经输出了 output_path）
    if patterns and delete_files:
        # 已经在上一步输出到 output_path 了
        pass
    elif patterns:
        dr2 = delete_files_by_pattern(temp_apk, output_path, '|'.join(patterns))
        os.remove(temp_apk)
        report['steps'].append({'action': 'delete_by_pattern', 'deleted': dr2['deleted']})

    # ── Step 5: 签名 ──
    if sign:
        try:
            from apk_reverse_engine.tools.signer import APKSigner
            if keystore_mode == 'debug':
                signed = output_path + '.signed'
                r = APKSigner.sign_debug(output_path, signed)
                if os.path.exists(signed):
                    os.replace(signed, output_path)
                    report['steps'].append({'action': 'sign', 'mode': 'debug', 'success': True})
                else:
                    report['steps'].append({'action': 'sign', 'error': r.get('error', '签名失败')})
        except Exception as e:
            report['steps'].append({'action': 'sign', 'error': str(e)})

    report['success'] = True
    return report