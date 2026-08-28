"""APK 组件浏览器 - 提取并分析四大组件、Intent Filter、导出状态、权限"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

import re
from xml.etree import ElementTree as ET

# Android命名空间
NS_ANDROID = 'http://schemas.android.com/apk/res/android'

# 组件类型映射
COMPONENT_TYPES = ['activity', 'activity-alias', 'service', 'receiver', 'provider']

# 组件中文名称
COMPONENT_CN = {
    'activity': 'Activity',
    'activity-alias': 'Activity别名',
    'service': 'Service',
    'receiver': 'BroadcastReceiver',
    'provider': 'ContentProvider',
}


class ComponentExplorer:
    """APK 四大组件分析器"""

    @staticmethod
    def analyze(manifest_xml_text):
        """分析 AndroidManifest.xml 文本，提取所有组件信息
        Args:
            manifest_xml_text: str, 文本格式的 AndroidManifest.xml
        Returns:
            dict: {components, exported_summary, intent_filters, deep_links}
        """
        try:
            root = ET.fromstring(manifest_xml_text)
        except ET.ParseError:
            # 尝试修复常见XML问题
            fixed = manifest_xml_text.replace('&', '&amp;')
            fixed = fixed.replace('android:&amp;', 'android:')
            root = ET.fromstring(fixed)

        application = root.find('application')
        if application is None:
            return {
                'components': {},
                'exported_summary': {},
                'intent_filters': [],
                'deep_links': [],
                'errors': ['<application> tag not found']
            }

        result = {
            'components': {},
            'exported_summary': {
                'total_exported': 0,
                'explicitly_exported': 0,
                'implicitly_exported': 0,
                'exported_by_type': {ct: 0 for ct in COMPONENT_TYPES}
            },
            'intent_filters': [],
            'deep_links': [],
            'permission_gates': [],
        }

        all_deep_links = set()

        for comp_type in COMPONENT_TYPES:
            components = application.findall(comp_type)
            comp_list = []

            for comp in components:
                info = ComponentExplorer._parse_component(comp, comp_type)
                comp_list.append(info)

                # 统计导出
                if info['exported']:
                    result['exported_summary']['total_exported'] += 1
                    result['exported_summary']['exported_by_type'][comp_type] = result['exported_summary']['exported_by_type'].get(comp_type, 0) + 1
                    if info['exported_explicit']:
                        result['exported_summary']['explicitly_exported'] += 1
                    else:
                        result['exported_summary']['implicitly_exported'] += 1

                # 收集 Intent Filter
                for intent in info.get('intent_filters', []):
                    intent_entry = {
                        'component': info['name'],
                        'component_type': comp_type,
                        'actions': intent.get('actions', []),
                        'categories': intent.get('categories', []),
                        'data_schemes': intent.get('data_schemes', []),
                        'data_hosts': intent.get('data_hosts', []),
                        'data_paths': intent.get('data_paths', []),
                        'data_mime_types': intent.get('data_mime_types', []),
                    }
                    result['intent_filters'].append(intent_entry)

                    # 收集 Deep Links
                    for scheme in intent.get('data_schemes', []):
                        for host in intent.get('data_hosts', ['']):
                            for path in intent.get('data_paths', ['']):
                                link = f"{scheme}://{host}{path}" if host else f"{scheme}://{path}"
                                all_deep_links.add(link)

                # 权限门控
                if info.get('permission'):
                    result['permission_gates'].append({
                        'component': info['name'],
                        'component_type': comp_type,
                        'permission': info['permission'],
                    })

            result['components'][comp_type] = comp_list

        result['deep_links'] = sorted(all_deep_links)
        return result

    @staticmethod
    def _parse_component(elem, comp_type):
        """解析单个组件元素"""
        name = elem.get(f'{{{NS_ANDROID}}}name', elem.get('name', ''))
        exported_attr = elem.get(f'{{{NS_ANDROID}}}exported', None)
        permission = elem.get(f'{{{NS_ANDROID}}}permission', '')
        enabled = elem.get(f'{{{NS_ANDROID}}}enabled', 'true')
        process = elem.get(f'{{{NS_ANDROID}}}process', '')
        task_affinity = ''
        launch_mode = ''
        if comp_type in ('activity', 'activity-alias'):
            launch_mode = elem.get(f'{{{NS_ANDROID}}}launchMode', '')
            task_affinity = elem.get(f'{{{NS_ANDROID}}}taskAffinity', '')

        target_activity = ''
        if comp_type == 'activity-alias':
            target_activity = elem.get(f'{{{NS_ANDROID}}}targetActivity', '')

        authorities = ''
        if comp_type == 'provider':
            authorities = elem.get(f'{{{NS_ANDROID}}}authorities', '')
            grant_uri_perms = elem.get(f'{{{NS_ANDROID}}}grantUriPermissions', 'false')
            uri_permission_patterns = elem.get(f'{{{NS_ANDROID}}}uriPermissionPatterns', '')

        # 解析导出状态
        if exported_attr is not None:
            exported_explicit = exported_attr.lower() == 'true'
            exported = exported_explicit
        else:
            # 隐式导出规则：带 intent-filter 的组件在 targetSdk <= 30 隐式导出
            # targetSdk >= 31 必须显式声明
            has_intent_filter = len(elem.findall('intent-filter')) > 0
            exported_explicit = False
            exported = has_intent_filter  # 简化：有 intent-filter 视为隐式导出

        # 解析 intent filters
        intent_filters = []
        for if_elem in elem.findall('intent-filter'):
            intent = ComponentExplorer._parse_intent_filter(if_elem)
            intent_filters.append(intent)

        info = {
            'name': name,
            'type': comp_type,
            'type_cn': COMPONENT_CN.get(comp_type, comp_type),
            'exported': exported,
            'exported_explicit': exported_explicit,
            'permission': permission,
            'enabled': enabled.lower() != 'false',
            'process': process,
            'intent_filters': intent_filters,
            'has_intent_filter': len(intent_filters) > 0,
        }

        if comp_type in ('activity', 'activity-alias'):
            info['launch_mode'] = launch_mode
            info['task_affinity'] = task_affinity
        if comp_type == 'activity-alias':
            info['target_activity'] = target_activity
        if comp_type == 'provider':
            info['authorities'] = authorities
            info['grant_uri_permissions'] = grant_uri_perms
            info['uri_permission_patterns'] = uri_permission_patterns

        return info

    @staticmethod
    def _parse_intent_filter(if_elem):
        """解析 intent-filter 元素"""
        actions = []
        categories = []
        data_schemes = set()
        data_hosts = set()
        data_paths = set()
        data_mime_types = set()

        for action_elem in if_elem.findall('action'):
            act = action_elem.get(f'{{{NS_ANDROID}}}name', action_elem.get('name', ''))
            if act:
                actions.append(act)

        for cat_elem in if_elem.findall('category'):
            cat = cat_elem.get(f'{{{NS_ANDROID}}}name', cat_elem.get('name', ''))
            if cat:
                categories.append(cat)

        for data_elem in if_elem.findall('data'):
            scheme = data_elem.get(f'{{{NS_ANDROID}}}scheme', data_elem.get('scheme', ''))
            host = data_elem.get(f'{{{NS_ANDROID}}}host', data_elem.get('host', ''))
            path = data_elem.get(f'{{{NS_ANDROID}}}path', data_elem.get('path', ''))
            path_prefix = data_elem.get(f'{{{NS_ANDROID}}}pathPrefix', data_elem.get('pathPrefix', ''))
            path_pattern = data_elem.get(f'{{{NS_ANDROID}}}pathPattern', data_elem.get('pathPattern', ''))
            mime_type = data_elem.get(f'{{{NS_ANDROID}}}mimeType', data_elem.get('mimeType', ''))

            if scheme:
                data_schemes.add(scheme)
            if host:
                data_hosts.add(host)
            if path:
                data_paths.add(path)
            elif path_prefix:
                data_paths.add(path_prefix + '*')
            elif path_pattern:
                data_paths.add(path_pattern)
            if mime_type:
                data_mime_types.add(mime_type)

        return {
            'actions': actions,
            'categories': categories,
            'data_schemes': sorted(data_schemes),
            'data_hosts': sorted(data_hosts),
            'data_paths': sorted(data_paths),
            'data_mime_types': sorted(data_mime_types),
        }

    @staticmethod
    def get_security_issues(analysis_result):
        """从分析结果中提取安全问题"""
        issues = []

        # 1. 导出组件检查
        for comp_type, components in analysis_result.get('components', {}).items():
            for comp in components:
                if not comp['exported']:
                    continue

                name = comp['name']
                severity = 'medium'

                # ContentProvider 导出风险更高
                if comp_type == 'provider':
                    severity = 'high'
                    issues.append({
                        'severity': severity,
                        'component': name,
                        'type': comp_type,
                        'issue': 'ContentProvider exported',
                        'detail': f"Authorities: {comp.get('authorities', 'N/A')}",
                    })
                # Service 导出
                elif comp_type == 'service':
                    severity = 'medium'
                    issues.append({
                        'severity': severity,
                        'component': name,
                        'type': comp_type,
                        'issue': 'Service exported',
                        'detail': f"Permission: {comp.get('permission') or 'none'}",
                    })
                # Receiver 导出
                elif comp_type == 'receiver':
                    issues.append({
                        'severity': severity,
                        'component': name,
                        'type': comp_type,
                        'issue': 'BroadcastReceiver exported',
                        'detail': f"Permission: {comp.get('permission') or 'none'}",
                    })
                # Activity 导出（一般风险较低）
                elif comp_type in ('activity', 'activity-alias'):
                    # 只标记没有权限保护的导出Activity
                    if not comp.get('permission'):
                        issues.append({
                            'severity': 'low',
                            'component': name,
                            'type': comp_type,
                            'issue': 'Activity exported without permission',
                            'detail': '',
                        })

                # 检查是否未授权就导出
                if comp['exported'] and not comp.get('permission'):
                    if comp_type in ('service', 'receiver', 'provider'):
                        issues.append({
                            'severity': 'high',
                            'component': name,
                            'type': comp_type,
                            'issue': 'Exported without permission protection',
                            'detail': 'Component is exported but has no permission gate',
                        })

        # 2. Deep Link 检查
        deep_links = analysis_result.get('deep_links', [])
        if deep_links:
            http_links = [l for l in deep_links if l.startswith('http://')]
            if http_links:
                issues.append({
                    'severity': 'low',
                    'component': '*',
                    'type': 'intent-filter',
                    'issue': 'Cleartext deep link scheme (http://)',
                    'detail': f'{len(http_links)} http deep links found',
                })

        return issues
