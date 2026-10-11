"""AndroidManifest.xml 解析器增强版 - 完整结构化提取"""
from ..utils.axml_parser import AXMLParser


class ManifestParser:
    """AndroidManifest.xml 解析器 - 完整结构化提取"""

    @staticmethod
    def parse(data):
        return AXMLParser(data).parse()

    @staticmethod
    def get_simple(data):
        return AXMLParser(data).get_manifest_simple()

    @staticmethod
    def get_full(data):
        parser = AXMLParser(data)
        result = parser.parse()
        if isinstance(result, dict):
            return result
        return parser.get_manifest_simple()

    @staticmethod
    def extract_components(data):
        info = AXMLParser(data).get_manifest_simple()
        components = info.get('components', {})
        if isinstance(components, dict):
            return {
                'activities': components.get('activities', []),
                'services': components.get('services', []),
                'receivers': components.get('receivers', []),
                'providers': components.get('providers', []),
            }
        return {'activities': [], 'services': [], 'receivers': [], 'providers': []}

    @staticmethod
    def extract_permissions(data):
        info = AXMLParser(data).get_manifest_simple()
        return info.get('permissions', [])

    @staticmethod
    def extract_sdk_info(data):
        info = AXMLParser(data).get_manifest_simple()
        sdk = info.get('sdk', {})
        return {
            'min_sdk': sdk.get('minSdk', '?'),
            'target_sdk': sdk.get('targetSdk', '?'),
            'max_sdk': sdk.get('maxSdk', '?'),
        }

    @staticmethod
    def extract_network_config(data):
        info = AXMLParser(data).get_manifest_simple()
        attrs = info.get('attributes', {})
        return {
            'usesCleartextTraffic': attrs.get('usesCleartextTraffic', False),
            'networkSecurityConfig': attrs.get('networkSecurityConfig', ''),
        }

    @staticmethod
    def extract_intents(data, component_type='activity'):
        components = ManifestParser.extract_components(data)
        targets = components.get(component_type + 's', [])
        result = []
        for comp in targets:
            if isinstance(comp, dict):
                name = comp.get('name', '')
                intents = comp.get('intent_filters', [])
                if intents:
                    result.append({'name': name, 'intents': intents})
            elif isinstance(comp, str):
                result.append({'name': comp, 'intents': []})
        return result
