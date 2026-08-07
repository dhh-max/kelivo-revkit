# APK Reverse Engineering Engine v2

全功能 APK 逆向工程工具集 — 解包/分析/反编译/修补/重打包/签名 一站式工具。

**版本**: 2.2.0

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

MIT License