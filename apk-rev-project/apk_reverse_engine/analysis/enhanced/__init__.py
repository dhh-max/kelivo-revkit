"""增强逆向分析模块 - DEX指令级深度分析、调用图构建、数据流追踪、反混淆增强"""
from .dex_dataflow import DexDataFlowAnalyzer, TaintTracker
from .callgraph import CallGraphBuilder
from .string_decrypt import StringDecryptor
from .anti_analysis import AntiAnalysisDetector
from .crypto_analyzer import CryptoAnalyzer
from .hook_generator import HookGenerator
from .vulnerability_scanner import VulnerabilityScanner
from .dex_optimizer_patterns import OptimizationPatternDetector
from .dex_metadata import DexMetadataAnalyzer
from .multidex_analyzer import MultiDexAnalyzer
from .report_generator import ReportGenerator
from .native_crossref import NativeCrossRefAnalyzer
