#!/usr/bin/env python3
"""AndroidManifest 快速编辑工具 - 一键修改常见属性

提供常见清单属性的快速修改能力：
- debuggable: 开启/关闭调试模式
- allowBackup: 允许/禁止备份
- testOnly: 开启/关闭测试模式
- networkSecurityConfig: 添加/移除网络安全配置
- extractNativeLibs: 控制SO提取
- hasCode: 控制代码加载
- 指定Activity的导出/权限
"""
import re
from copy import deepcopy

# ── AXML 二进制操作辅助 ──────────────────────────────────────
# 对于纯文本 XML 的修改，支持正则替换
# 对于 AXML 二进制，需要借助 axml_parser 的修改能力

# 常见 manifest 属性修改的 XPath/正则模式
PATTERNS = {
    'debuggable': (
        r'android:debuggable="(?:true|false)"',
        'android:debuggable="{val}"'
    ),
    'allowBackup': (
        r'android:allowBackup="(?:true|false)"',
        'android:allowBackup="{val}"'
    ),
    'testOnly': (
        r'android:testOnly="(?:true|false)"',
        'android:testOnly="{val}"'
    ),
    'extractNativeLibs': (
        r'android:extractNativeLibs="(?:true|false)"',
        'android:extractNativeLibs="{val}"'
    ),
    'hasCode': (
        r'android:hasCode="(?:true|false)"',
        'android:hasCode="{val}"'
    ),
    'networkSecurityConfig': (
        r'android:networkSecurityConfig="[^"]*"',
        'android:networkSecurityConfig="{val}"'
    ),
    'hardwareAccelerated': (
        r'android:hardwareAccelerated="(?:true|false)"',
        'android:hardwareAccelerated="{val}"'
    ),
    'largeHeap': (
        r'android:largeHeap="(?:true|false)"',
        'android:largeHeap="{val}"'
    ),
    'resizeableActivity': (
        r'android:resizeableActivity="(?:true|false)"',
        'android:resizeableActivity="{val}"'
    ),
    'supportsRtl': (
        r'android:supportsRtl="(?:true|false)"',
        'android:supportsRtl="{val}"'
    ),
    'usesCleartextTraffic': (
        r'android:usesCleartextTraffic="(?:true|false)"',
        'android:usesCleartextTraffic="{val}"'
    ),
}

# 需要插入到 <application 标签中的属性
APP_ATTRIBUTES = {
    'debuggable': ('android:debuggable="true"', 'android:debuggable="false"'),
    'allowBackup': ('android:allowBackup="true"', 'android:allowBackup="false"'),
    'testOnly': ('android:testOnly="true"', 'android:testOnly="false"'),
    'extractNativeLibs': ('android:extractNativeLibs="true"', 'android:extractNativeLibs="false"'),
    'hasCode': ('android:hasCode="true"', 'android:hasCode="false"'),
    'networkSecurityConfig': ('android:networkSecurityConfig="@xml/network_security_config"', None),
    'hardwareAccelerated': ('android:hardwareAccelerated="true"', 'android:hardwareAccelerated="false"'),
    'largeHeap': ('android:largeHeap="true"', 'android:largeHeap="false"'),
    'resizeableActivity': ('android:resizeableActivity="true"', 'android:resizeableActivity="false"'),
    'supportsRtl': ('android:supportsRtl="true"', 'android:supportsRtl="false"'),
    'usesCleartextTraffic': ('android:usesCleartextTraffic="true"', 'android:usesCleartextTraffic="false"'),
}


class ManifestEditor:
    """AndroidManifest.xml 快速编辑工具"""

    @staticmethod
    def set_attribute(xml_text, attr_name, value):
        """设置 manifest 中的 application 标签属性

        Args:
            xml_text: 文本格式的 AndroidManifest.xml
            attr_name: 属性名 (如 'debuggable', 'allowBackup')
            value: 属性值 (如 'true', 'false', 或自定义路径)

        Returns:
            str: 修改后的 XML 文本
        """
        if attr_name not in PATTERNS:
            raise ValueError(f"不支持的属性: {attr_name}，支持: {list(PATTERNS.keys())}")

        pattern, template = PATTERNS[attr_name]
        replacement = template.format(val=value)

        # 如果属性已存在，替换值
        new_xml = re.sub(pattern, replacement, xml_text)

        if new_xml == xml_text:
            # 属性不存在，需要插入到 <application 标签中
            insert_text = f' {replacement}'
            # 在 <application 标签的末尾插入
            new_xml = re.sub(
                r'(<application\s[^>]*?)(\s*>)',
                lambda m: m.group(1) + insert_text + m.group(2),
                xml_text, count=1
            )

        return new_xml

    @staticmethod
    def batch_set(xml_text, changes):
        """批量设置多个属性

        Args:
            xml_text: 文本格式的 AndroidManifest.xml
            changes: dict, {attr_name: value}

        Returns:
            str: 修改后的 XML 文本
        """
        result = xml_text
        for attr, value in changes.items():
            result = ManifestEditor.set_attribute(result, attr, value)
        return result

    @staticmethod
    def enable_debuggable(xml_text):
        """开启 debuggable"""
        return ManifestEditor.set_attribute(xml_text, 'debuggable', 'true')

    @staticmethod
    def disable_debuggable(xml_text):
        """关闭 debuggable"""
        return ManifestEditor.set_attribute(xml_text, 'debuggable', 'false')

    @staticmethod
    def enable_backup(xml_text):
        """开启 allowBackup"""
        return ManifestEditor.set_attribute(xml_text, 'allowBackup', 'true')

    @staticmethod
    def disable_backup(xml_text):
        """关闭 allowBackup"""
        return ManifestEditor.set_attribute(xml_text, 'allowBackup', 'false')

    @staticmethod
    def enable_test_only(xml_text):
        """开启 testOnly"""
        return ManifestEditor.set_attribute(xml_text, 'testOnly', 'true')

    @staticmethod
    def disable_test_only(xml_text):
        """关闭 testOnly"""
        return ManifestEditor.set_attribute(xml_text, 'testOnly', 'false')

    @staticmethod
    def add_network_security_config(xml_text, config_path='@xml/network_security_config'):
        """添加网络安全配置引用"""
        return ManifestEditor.set_attribute(xml_text, 'networkSecurityConfig', config_path)

    @staticmethod
    def remove_network_security_config(xml_text):
        """移除网络安全配置引用"""
        return re.sub(
            r'\s*android:networkSecurityConfig="[^"]*"',
            '',
            xml_text
        )

    @staticmethod
    def set_exported(xml_text, component_name, exported=True):
        """设置指定组件(Activity/Service/Receiver/Provider)的 exported 属性

        Args:
            xml_text: 文本格式的 XML
            component_name: 组件名 (如 '.MainActivity')
            exported: True/False

        Returns:
            str: 修改后的 XML
        """
        val = 'true' if exported else 'false'
        # 查找组件标签
        for tag in ('activity', 'service', 'receiver', 'provider'):
            # 找到目标组件
            pattern = rf'<{tag}\s[^>]*android:name="[^"]*{re.escape(component_name)}"[^>]*>'
            match = re.search(pattern, xml_text, re.IGNORECASE)
            if match:
                tag_text = match.group()
                # 检查是否已有 exported
                if 'android:exported=' in tag_text:
                    # 替换现有值
                    new_tag = re.sub(
                        r'android:exported="(?:true|false)"',
                        f'android:exported="{val}"',
                        tag_text
                    )
                else:
                    # 插入 exported
                    new_tag = re.sub(
                        r'(android:name="[^"]*")',
                        lambda m: m.group(1) + f' android:exported="{val}"',
                        tag_text, count=1
                    )
                xml_text = xml_text.replace(tag_text, new_tag)
                return xml_text

        raise ValueError(f"未找到组件: {component_name}")

    @staticmethod
    def add_activity(xml_text, activity_name, exported=False):
        """添加 Activity 声明

        Args:
            xml_text: 文本格式的 XML
            activity_name: Activity 完整类名
            exported: 是否导出

        Returns:
            str: 修改后的 XML
        """
        exported_str = 'true' if exported else 'false'
        activity_xml = (
            f'        <activity android:name="{activity_name}" '
            f'android:exported="{exported_str}">\n'
            f'            <intent-filter>\n'
            f'                <action android:name="android.intent.action.MAIN"/>\n'
            f'                <category android:name="android.intent.category.LAUNCHER"/>\n'
            f'            </intent-filter>\n'
            f'        </activity>'
        )
        # 在 </application> 前插入
        new_xml = re.sub(
            r'(\s*)(</application>)',
            lambda m: m.group(1) + activity_xml + '\n' + m.group(1) + m.group(2),
            xml_text, count=1
        )
        return new_xml

    @staticmethod
    def remove_debug_attributes(xml_text):
        """移除所有调试相关属性

        移除: debuggable, testOnly, 以及调试权限
        """
        result = xml_text
        # 移除 debuggable
        result = re.sub(r'\s*android:debuggable="(?:true|false)"', '', result)
        # 移除 testOnly
        result = re.sub(r'\s*android:testOnly="(?:true|false)"', '', result)
        # 移除调试权限
        result = re.sub(
            r'\s*<uses-permission android:name="android\.permission\.(?:ENABLE_TEST_HOOKS|DEBUG_APPLICATION)"/>',
            '',
            result
        )
        return result

    @staticmethod
    def get_changes_description(changes):
        """生成修改描述文本

        Args:
            changes: dict, {attr_name: value}

        Returns:
            list[dict]: 描述列表
        """
        desc_map = {
            'debuggable': ('调试模式', {'true': '开启', 'false': '关闭'}),
            'allowBackup': ('允许备份', {'true': '开启', 'false': '关闭'}),
            'testOnly': ('测试模式', {'true': '开启', 'false': '关闭'}),
            'extractNativeLibs': ('SO提取', {'true': '开启', 'false': '关闭'}),
            'hasCode': ('代码加载', {'true': '开启', 'false': '关闭'}),
            'networkSecurityConfig': ('网络安全配置', {}),
            'hardwareAccelerated': ('硬件加速', {'true': '开启', 'false': '关闭'}),
            'largeHeap': ('大堆内存', {'true': '开启', 'false': '关闭'}),
            'resizeableActivity': ('多窗口模式', {'true': '开启', 'false': '关闭'}),
            'supportsRtl': ('RTL支持', {'true': '开启', 'false': '关闭'}),
            'usesCleartextTraffic': ('明文流量', {'true': '允许', 'false': '禁止'}),
        }
        result = []
        for attr, value in changes.items():
            if attr in desc_map:
                name, val_map = desc_map[attr]
                desc = val_map.get(value, value)
                result.append({'属性': name, '操作': desc})
            else:
                result.append({'属性': attr, '操作': str(value)})
        return result