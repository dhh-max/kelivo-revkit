from ..utils.axml_parser import AXMLParser
class ManifestParser:
    """AndroidManifest.xml解析器"""
    @staticmethod
    def parse(data): return AXMLParser(data).parse()
    @staticmethod
    def get_simple(data): return AXMLParser(data).get_manifest_simple()
