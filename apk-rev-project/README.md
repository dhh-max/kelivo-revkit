# APK Reverse Engineering Engine v2
全功能 APK 逆向工程工具集 — 解包/分析/反编译/修补/重打包/签名 一站式工具。
**版本**: 2.3.0
---
## 特性

- **APK 解包/打包/签名/对齐** — 完整 APK 生命周期操作
- **DEX/ELF 解析分析** — 类/方法/字段/字符串/原生库深度解析
- **Manifest 解析与编辑** — 二进制 AXML 直接解析与修改
- **混淆/加固/SDK/隐私检测** — 自动识别常用 SDK、加固方案、隐私风险
- **线索串联/核心类定位** — 基于字符串和行为模式定位核心逻辑
- **Smali 补丁/原生补丁/资源补丁** — 动态修改 APK 行为
- **多语言支持(i18n)** — 资源字符串提取与翻译
- **签名证书指纹提取** — 直接解析 v2/v3 Signing Block 提取证书 SHA-256（纯标准库，无需 apksigner/keytool）
- **工作区隔离** — 多项目并行分析上下文隔离，持久化结果/产物/配置
- **快照备份** — 分析会话导出/导入可移植 JSON
- **设备集成** — ADB 真机/模拟器操作
- **知识库** — 持久化加固/SDK/混淆模式数据库
- **沙盒环境** — 内置沙盒运行目录结构
## 基础工具（v2.1.0 新增）
提供可直接在二进制/ZIP层面操作的基础工具，无需解包：
### APK 文件操作 (`core/apk_file_ops.py`)
| 函数 | 功能 |
|---|---|
| `delete_files_from_apk(apk, out, paths)` | 从 APK 精确删除指定文件 |
| `delete_files_by_pattern(apk, out, pattern)` | 按正则匹配删除文件 |
| `update_file_in_apk(apk, out, path, data)` | 更新 APK 内指定文件内容 |
| `add_file_to_apk(apk, out, path, data)` | 向 APK 添加新文件 |
| `list_apk_files(apk, pattern)` | 列出 APK 内文件列表 |
### Manifest 二进制操作 (`core/manifest_ops.py`)
直接在二进制 AXML 层面操作，不经过文本转换：
| 函数 | 功能 |
|---|---|
| `find_tags(axml, tag, attr, val)` | 在二进制 AXML 中查找标签 |
| `remove_tags(axml, tag, attr, val)` | 删除标签及其子标签 |
| `remove_tags_by_rule(axml, rules)` | 批量删除规则 |
| `remove_component(axml, type, class)` | 删除组件声明 |
| `replace_attr_value(axml, tag, attr, old, new)` | 替换属性值（字符串池原地修改） |
| `replace_launcher_activity(axml, old, new)` | 替换启动 Activity 类名 |
| `get_attr_value(axml, tag, attr)` | 读取属性值 |
### 弹窗去除器（默认关闭，按需加载）
```python
from apk_reverse_engine.popup_remover import remove_share_popup
```
基于基础工具组合的上层使用示例，直接在 APK 层面完成：
1. 删除弹窗 SDK 资源文件与 dex
2. 删除 Manifest 中弹窗组件声明
3. 替换启动 Activity 为真实类名
4. 自动 Debug 签名
## 签名证书指纹提取（v2.2.0 新增，移植自 RikkaMinis）
直接解析 APK v2/v3 Signing Block 提取签名证书 SHA-256 指纹，纯 Python 标准库实现，
无需 apksigner / keytool，可用于验证 APK 是否携带期望的签名密钥。
```python
from apk_reverse_engine import extract_cert_sha256, verify_signature
# 提取证书 SHA-256（小写十六进制）
sha = extract_cert_sha256('app-release.apk')
print(sha)                       # e.g. fc0c40...b16113
# 获取原始 DER 证书字节
cert_der = extract_cert_sha256('app-release.apk', raw=True)
# verify_signature 现在也自动附带 cert_sha256
with open_apk('app-release.apk') as ctx:
    sig = verify_signature(ctx.zip, 'app-release.apk')
    print(sig.get('cert_sha256'))   # 与 extract_cert_sha256 一致
```
## 工作区管理（v2.3.0 新增）
多项目并行分析上下文隔离，每个工作区独立元信息/结果/产物/配置：
```python
from apk_reverse_engine.workspace.manager import Workspace
# 创建工作区
ws = Workspace.create('demo', apk_path='test.apk', description='示例分析')
# 保存/读取分析结果
ws.save_result('summary', {'classes': 123})
data = ws.load_result('summary')
# 中间产物路径
art = ws.artifact('decoded/')
# 工作区配置
ws.set_config('target', 'com.example.app')
# 列出所有工作区
for meta in Workspace.list():
    print(meta['name'], meta['dir'])
```
## 快照备份（v2.3.0 新增）
```python
from apk_reverse_engine.backup.snapshot import snapshot_to_json, restore_from_json
```
分析会话导出/导入为可移植 JSON，便于跨环境迁移与审计留档。
## 设备集成（v2.3.0 新增）
```python
from apk_reverse_engine.device.adb import get_devices, push, pull, shell
```
ADB 真机/模拟器操作：设备枚举、文件推送/拉取、shell 命令执行等。
## 知识库（v2.3.0 新增）
```python
from apk_reverse_engine.knowledge.kb import KnowledgeBase
```
持久化加固方案 / SDK / 混淆模式数据库，自动记忆识别特征，供后续解包分析复用。
## 沙盒环境（v2.3.0 新增）
内置 `sandbox/` 沙盒运行目录结构，提供隔离的执行目录用于解包/修补等中间产物落地。
## 快速开始
```python
import sys
sys.path.insert(0, '/path/to/apk-rev-project')
from apk_reverse_engine import unpack_apk_standalone
# 分析 APK
result = unpack_apk_standalone('test.apk')
print(result['summary'])
```
## 安装
```bash
pip install -e .
```
## 许可

## 广告移除（v2.4.0 新增）

### CLI 命令

```bash
# 一键移除广告（自动解包→移除→重打包→签名）
reng adremove app.apk

# 指定输出路径
reng adremove app.apk -o app_noads.apk

# 只处理指定SDK
reng adremove app.apk --sdks tencent,sigmob,pangle

# 跳过正则通杀 / assets清理 / manifest清理
reng adremove app.apk --no-regex --no-assets

# 跳过签名
reng adremove app.apk --no-sign

# 使用已有解包目录
reng adremove app.apk --decode-dir ./decoded/
```

### 支持的广告SDK

| SDK | 包名特征 | 移除策略 |
|-----|---------|----------|
| 🐧 腾讯广告 | `com/qq/e` | const翻转 + ADEvent返回值 + 字符串清除 |
| 🎬 快手广告 | `com/kwad` | isResultOk返回false + 字符串清除 |
| 🐜 穿山甲 | `com/bytedance/pangle` | Zeus.hasInit返回false + AdSlot清空 |
| 🔍 百度广告 | `com/bd`, `com/bytedance/sdk` | 回调成功注入return-void |
| 📰 头条广告 | `toutiao` | 广告方法体清空 + 字符串清除 |
| 🎯 Sigmob | `sigmob` | const/4 v0, 0x0→0x1 + manifest清理 |
| 📱 谷歌广告 | `com/google/android/gms/ads` | getInterstitialAdapter翻转 + manifest清理 |
| 📲 米盟广告 | `com/miui/zeus/mimo` | MimoSdk.init注入return-void |

### 正则通杀（9组）

| # | 模式 | 说明 |
|---|------|------|
| ① | loadAd()V | 注入 return-void |
| ② | loadAd()Z | 注入 false 返回 |
| ③ | invoke...loadAd() | 注释掉调用 |
| ④ | 广告相关 invoke | 注释调用 |
| ⑤ | 广告URL | 替换为空 |
| ⑥ | AdMob ID | 置零 |
| ⑦ | 广告 invoke → nop | 替换为 nop |
| ⑧ | 特定广告 invoke | 替换为 nop |
| ⑨ | 广告方法体 | 清空（return-void） |

### Python API

```python
from apk_reverse_engine import remove_ads, detect_ad_sdks

# 检测广告SDK
detected = detect_ad_sdks('/path/to/decoded')

# 一键移除
report = remove_ads(
    smali_root='/path/to/decoded',
    assets_dir='/path/to/decoded/assets',
    manifest_path='/path/to/decoded/AndroidManifest.xml',
    options={'tencent': True, 'sigmob': True}  # 可选：只处理指定SDK
)
print(f"补丁数: {report['total_patched']}, 文件数: {report['total_files']}")
```

## 广告分析提示词模板（v2.4.0 新增）

内置 XML 资源文件，提供广告识别/分析/屏蔽的提示词模板，供 AI 辅助分析使用。

### Python API

```python
from apk_reverse_engine import (
    get_ad_template,           # 按名称获取模板
    get_ad_sdk_template,      # 按 SDK 标识获取专项分析模板
    format_ad_analysis_prompt, # 组装完整分析提示词（含 SDK 专项要点）
    get_ad_blocking_suggestions, # 广告屏蔽建议
)

# 组装带 SDK 专项要点的分析提示词
prompt = format_ad_analysis_prompt(code_snippet, sdk_hint='tencent')

# 获取 Google AdMob 专项分析模板
tpl = get_ad_sdk_template('google')

# 获取广告屏蔽建议
suggestions = get_ad_blocking_suggestions()
```

### 模板清单

| 模板名称 | 用途 |
|----------|------|
| `ad_analysis_template` | 通用广告分析提示词 |
| `no_ad_found_template` | 无广告发现时的分析建议 |
| `ad_blocking_suggestions` | 广告屏蔽建议（5大类技术） |
| `google_admob_analysis` | Google AdMob 专项分析要点 |
| `facebook_audience_network_analysis` | Facebook Audience Network 专项 |
| `unity_ads_analysis` | Unity Ads 专项分析要点 |
| `tencent_ads_analysis` | 腾讯广告专项分析要点 |
| `byte_dance_ads_analysis` | 字节跳动/穿山甲专项分析要点 |
| `baidu_ads_analysis` | 百度广告专项分析要点 |
| `ad_common_keywords` | 广告识别通用关键词列表 |
| `ad_obfuscated_code_analysis` | 广告混淆代码识别指南 |

### 文件结构

```
knowledge/
├── __init__.py           # 知识库导出
├── kb.py                 # 持久化知识库（加固/SDK/混淆特征）
├── ad_templates.py       # 广告分析提示词模板加载器
└── res/
    └── ad_analysis_templates.xml  # XML 模板资源文件
```

## AI 广告识别分析（v2.4.0 新增）

基于 LLM（SiliconFlow/OpenAI 兼容接口）对 Smali/Java/XML/JavaScript 代码进行广告接口的智能分析。

### CLI 命令

```bash
# 列出可用 AI 模型
reng adai app.apk --api-key sk-xxx --list-models

# 使用指定模型分析 APK 中的广告代码
reng adai app.apk --api-key sk-xxx --model Qwen/Qwen2.5-7B-Instruct

# 补充问答模式（带自定义问题）
reng adai app.apk --api-key sk-xxx --model deepseek-ai/DeepSeek-R1-0528-Qwen3-8B \
  --supplement --question "这个广告SDK的初始化流程是什么？"

# 指定类名过滤 + Java 语言
reng adai app.apk --api-key sk-xxx --model THUDM/glm-4-9b-chat \
  --class-name "com/example/Ad" --language java

# 导出 JSON 结果
reng adai app.apk --api-key sk-xxx --model Qwen/Qwen3-8B --json result.json
```

### Python API

```python
from apk_reverse_engine import (
    ai_analyze_ad_code,  # AI 广告分析
    ai_list_ad_models,   # 获取可用模型列表
)

# 列出可用模型
models = ai_list_ad_models(api_key="sk-xxx")

# AI 广告分析
result = ai_analyze_ad_code(
    code=smali_code,
    api_key="sk-xxx",
    model="Qwen/Qwen2.5-7B-Instruct",
    source_language="smali",
    question_mode="direct",
    options={
        'enable_admob_detection': True,
        'enable_tencent_ads_detection': True,
        'show_ad_blocking_suggestions': True,
        'custom_ad_keywords': 'myAdSDK',
    }
)

# 思考模型（深度分析模式）
result = ai_analyze_ad_code(
    code=smali_code,
    api_key="sk-xxx",
    model="deepseek-ai/DeepSeek-R1-0528-Qwen3-8B",
    source_language="smali",
)
```

### 支持的模型

| 模型 ID | 说明 |
|---------|------|
| `Qwen/Qwen2.5-7B-Instruct` | 通义千问2.5-7B（默认） |
| `deepseek-ai/DeepSeek-R1-0528-Qwen3-8B` | DeepSeek-R1（思考模式） |
| `THUDM/GLM-4.1V-9B-Thinking` | 智谱GLM-4V（思考模式） |
| `Qwen/Qwen2.5-Coder-7B-Instruct` | 通义千问2.5-代码专家 |
| `tencent/Hunyuan-MT-7B` | 腾讯混元-MT-7B |

> 支持动态获取 API 端点可用模型列表（30分钟缓存），未配置 API Key 时回退到默认列表。

## 增强逆向分析（v2.4.0 新增）

### CLI 命令

| 命令 | 说明 |
|---|---|
| `reng dataflow app.apk Lcom/example/Main;` | 🔬 DEX 数据流分析（寄存器追踪/污点分析/常量传播） |
| `reng callgraph app.apk` | 🕸️ 调用图分析（入口点/热点方法/递归检测） |
| `reng decrypt app.apk` | 🔐 加密字符串检测与自动解密 |
| `reng anti app.apk` | 🛡️ 反分析检测（反调试/反Root/反模拟器/完整性校验） |
| `reng crypto app.apk` | 🔑 加密分析（算法/模式/哈希/弱加密/密钥管理） |
| `reng hook com.example.Main -m onCreate -f frida` | 🪝 Hook 脚本生成（Frida/Xposed/Smali） |

### Python API

```python
from apk_reverse_engine import (
    # 数据流分析
    analyze_dataflow, trace_register, propagate_constants,
    # 调用图
    build_call_graph, find_callers, find_callees,
    find_entry_points, find_hotspots, detect_recursive,
    # 字符串解密
    auto_decrypt_strings, find_encrypted_strings, analyze_decrypt_pattern,
    # 反分析检测
    detect_anti_analysis, detect_timing_checks,
    # 加密分析
    analyze_crypto,
    # Hook 生成
    generate_frida_hook, generate_xposed_module, generate_smali_patch,
    # APK 对比
    compare_apks,
    # 网络端点/密钥扫描
    extract_endpoints, scan_keys, detect_weak_crypto,
)
```

### 增强分析模块结构

```
analysis/enhanced/
├── __init__.py          # 模块导出
├── dex_dataflow.py      # 数据流分析（寄存器追踪/污点/常量传播）
├── callgraph.py         # 调用图构建（入口点/热点/递归）
├── string_decrypt.py    # 字符串解密（XOR/Base64/AES 自动识别）
├── anti_analysis.py     # 反分析检测（反调试/反Root/反模拟器/完整性校验）
├── crypto_analyzer.py   # 加密分析（算法/模式/哈希/弱加密/密钥）
└── hook_generator.py    # Hook 脚本生成（Frida/Xposed/Smali 补丁）
```
