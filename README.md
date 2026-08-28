# Kelivo RevKit

[简体中文](README_ZH_CN.md) | English

This repository (`dhh-max/kelivo-revkit`) is a second-level fork of [Kelivo Plus](https://github.com/MuMu-0604/kelivo), which is itself a fork of [Chevey339/kelivo](https://github.com/Chevey339/kelivo). It fully inherits every Kelivo Plus capability and adds a deeper focus on **Android security and reverse engineering** (RevKit = Reverse Engineering Kit).

> Fork notice: this repository is not the official upstream repository. It is a secondary development build based on Kelivo Plus and the original Kelivo project. Original copyright, acknowledgements, and license terms are preserved. This project remains licensed under AGPL-3.0.

## What Changed From Kelivo Plus

| Area | Kelivo Plus | kelivo-revkit (this repo) |
| --- | --- | --- |
| Positioning | Mobile AI self-configuration + general enhancements | Fully inherits Plus; focused on Android security & reverse engineering |
| Built-in MCP | fetch / files / images / github / so / reverse (basic) | All inherited + new `@kelivo/dex` (DEX bytecode parsing) and `@kelivo/context` (conversation context management) |
| APK reverse engineering | Basic static analysis and triage | `@kelivo/reverse` deepened to 20 tools: manifest deep parsing, SO/DEX aggregate analysis, JNI bridge discovery, cross-target string search, packer detection, signature bypass, APK resign & DEX injection, etc. |
| Preset assistants | General-purpose assistants | Adds a "Reverse Analyst" preset bound to `@kelivo/reverse` by default |
| RelayGo gateway | Basic proxy | Fully inherited + **request dedup** (2s deduplication window, body-hash key), **exponential backoff with jitter** for all 4xx/5xx/timeout errors, **cleanup timer** to prevent dedup map unbounded growth |
| 神经权能网关 | Included | Fully inherited |
| Skills | Included | Fully inherited |
| GitHub write tools | Included | Fully inherited |
| Local hybrid search | Included | Fully inherited |
| Mobile import flow | Included | Fully inherited |
| Tool UX | Chinese tool descriptions + grouped tools | Fully inherited |
| Documentation | Basic README | **3 major technical reference docs**: App reference (19 ch.), Gateway reference (19 ch.), Credits (11 ch. / 532 lines) |

## Highlights

### 神经权能网关

- Enable per assistant through the “Allow this assistant to use 神经权能网关” switch.
- Import user-provided instructions, pasted text, shared files, or newly generated content into app configuration targets.
- Supported targets include assistant system prompts, memory, Skills, instruction injection, world books, MCP bindings, local tools, quick phrases, and search settings.
- Adds delete/update/list/detail operations, world-book entry editing, quick-phrase reorder, Skill version snapshots/rollback, batch import/export, and an audit log.
- Recent changes can be undone.
- Disabled by default and intended only for trusted assistants.

Example prompts:

```text
Import the content you just generated as a Skill, bind it to the current assistant, and use review/code-review as trigger keywords.
```

```text
Create a world book from this setting document and use character and location names as keywords.
```

### Skills

- Create, edit, delete, and import reusable Skills.
- Import Markdown, JSON, YAML, DOCX, and ZIP-based skill files.
- Bind Skills to assistants or activate them with trigger keywords.

### Built-In MCP Tools

- `@kelivo/fetch`: fetch and extract web content.
- `@kelivo/files`: local file read/write and directory operations.
- `@kelivo/images`: image-oriented helper tools.
- `@kelivo/github`: GitHub repository, file, issue, PR, release, Actions, secrets, and variables operations.
- `@kelivo/so`: pure-Dart ELF/.so reverse engineering toolkit (26 tools). No native dependencies required.
- `@kelivo/dex`: pure-Dart DEX/ODEX bytecode parsing and analysis toolkit (39 tools). No native dependencies required.
- `@kelivo/context`: conversation context management toolkit (6 tools) — stats, summary, search, export, and boundary management.
- `@kelivo/reverse`: APK-oriented static analysis and triage toolkit (20 tools, incl. signature bypass, APK resign & DEX injection) for Android reverse engineering.
- `@kelivo/memory`: per-assistant memory persistence toolkit — list/add/update/delete/search/clear/stats of structured memories and preference key-values.

### SO/ELF Reverse Engineering Tools

`@kelivo/so` provides a comprehensive set of in-memory ELF analysis tools, enabled by default for all new assistants:

| Category | Tools |
| --- | --- |
| Basic analysis | `so_parse_header`, `so_list_sections`, `so_list_symbols`, `so_list_imports`, `so_list_exports`, `so_list_dependencies` |
| Content extraction | `so_list_strings`, `so_read_hexdump`, `so_section_details` |
| Segments & relocations | `so_analyze_segments`, `so_analyze_dynamic`, `so_analyze_relocations` |
| Search | `so_search_bytes`, `so_search_strings`, `so_section_search` |
| Symbol query | `so_symbol_lookup` |
| Address conversion | `so_addr_to_offset`, `so_offset_to_addr` |
| Compare & notes | `so_compare_headers`, `so_list_notes` |
| Init analysis | `so_list_init_array` (.init_array/.fini_array pointers + symbol names) |
| Cross-reference | `so_xref_symbol` (all relocations referencing a symbol) |
| Packer detection | `so_detect_packer` (UPX/Bangcle/Ijiami/360/Nagain/Legu/Baidu/DexGuard/Alibaba etc.) |
| Anti-debug | `so_find_anti_debug` (detect ptrace/inotify/frida/TracerPid anti-debug patterns) |
| GOT/PLT | `so_got_plt_analysis` (GOT/PLT table analysis for hook point discovery) |
| Disassembly | `so_disassemble` (ARM64 AArch64 instruction disassembler, by symbol or offset) |

### DEX Bytecode Parsing Tools

`@kelivo/dex` provides pure-Dart DEX/ODEX bytecode-level parsing and static analysis:

| Category | Tools |
| --- | --- |
| Header | `dex_parse_header` |
| Strings | `dex_list_strings`, `dex_string_pool`, `dex_search_strings` (regex/substring search over string pool) |
| Types | `dex_list_types`, `dex_type_ref` |
| Classes | `dex_list_classes`, `dex_inner_class`, `dex_inherit_tree`, `dex_debug_info` |
| Methods | `dex_list_methods`, `dex_method_signatures`, `dex_disassemble_method` (per-method Dalvik bytecode disassembly) |
| Fields | `dex_list_fields`, `dex_field_stats` |
| Annotations | `dex_list_annotations`, `dex_annotation_stats` (annotation extraction and statistics) |
| Cross-reference | `dex_xref_method` (method-level call graph — find all callers), `dex_call_graph` |
| Control flow | `dex_ctrl_flow`, `dex_exception_flow`, `dex_access_flow` |
| Complexity | `dex_complexity` (per-method cyclomatic/size complexity), `dex_reg_pressure`, `dex_insn_stats`, `dex_insn_density`, `dex_class_density` |
| Security scan | `dex_crypto_scan`, `dex_const_scan`, `dex_serialization_scan`, `dex_reflection_scan`, `dex_obfuscation_scan`, `dex_lib_analysis`, `dex_native_analysis`, `dex_resource_ref`, `dex_access_pattern` |
| Protocol | `dex_proto_analysis`, `dex_proto_matrix` |
| Permission | `dex_perm_audit` |

### Conversation Context Management Tools

`@kelivo/context` helps models perceive and manage their own conversation context:

| Category | Tools |
| --- | --- |
| Stats | `context_get_stats` |
| Summary | `context_get_summary` |
| Search | `context_search` |
| Export | `context_export` |
| Boundary | `context_set_boundary` |
| Messages | `context_get_messages` |

### Memory Tools

`@kelivo/memory` provides per-assistant structured memory persistence (built on the `AssistantMemory` system):

| Category | Tools |
| --- | --- |
| List | `memory_list` |
| Add | `memory_add` |
| Update | `memory_update` |
| Delete | `memory_delete` |
| Search | `memory_search` |
| Clear | `memory_clear` |
| Stats | `memory_stats` |

### APK Reverse Engineering Tools

`@kelivo/reverse` provides APK-oriented static analysis, modification, and triage tools (20 tools) for Android reverse engineering:
| Category | Tools |
| --- | --- |
| Overview | `reverse_meta_info`, `reverse_quick_triage` |
| APK structure | `reverse_open_apk`, `reverse_list_targets`, `reverse_manifest_summary`, `reverse_list_native_libs`, `reverse_list_dex_files`, `reverse_component_audit`, `reverse_diff_apk` |
| Deep analysis | `reverse_analyze_so`, `reverse_analyze_dex`, `reverse_find_jni_bridges`, `reverse_search_strings` |
| Security analysis | `reverse_signature_audit`, `reverse_packer_detect`, `reverse_secret_scan` |
| Modification | `reverse_kill_signature` (strip signature verification), `reverse_resign_apk` (repackage & sign), `reverse_inject_dex` (inject DEX payload into APK) |
| Reporting | `reverse_report` |

Recommended workflow:

1. Open the APK with `reverse_open_apk`.
2. Run `reverse_quick_triage` for a fast overview.
3. Use `reverse_signature_audit`, `reverse_packer_detect`, and `reverse_secret_scan` for security checks.
4. Use `reverse_component_audit` and `reverse_diff_apk` for deeper APK comparison and exported-component inspection.
5. Finish with `reverse_report` to generate a structured summary.


### APK Reverse Toolkit
The `apk_reverse` package bundles an in-process APK reverse engineering toolkit based on the built-in `dex-jar` runtime. It exposes low-level tools for decoding, searching, building, and signing APKs directly without network dependencies.

| Tool | Description |
| --- | --- |
| `usage_advice` | Returns usage advice for the APK reverse toolkit. |
| `apk_reverse_inspect` | Inspect APK basics: components, permissions, signatures, and general metadata. |
| `apk_reverse_decode` | Decode an APK with apktool into an editable directory. |
| `apk_reverse_jadx` | Decompile DEX with the bundled JADX `dex-jar` runtime. |
| `apk_reverse_search_text` | Search text inside the decoded directory, JADX output, or target files. |
| `apk_reverse_search_address` | Search resources, smali, JADX output, and native library addresses. |
| `apk_reverse_build` | Execute apktool build from a decoded directory to rebuild an APK. |

These tools are intended for low-level reverse tasks. For higher-level workflows, prefer the `reverse_*` tools listed above.

### APK Modification Pipeline (Experimental)
`@kelivo/reverse` also provides in-process APK modification capabilities. Combined with the build toolchain (`apktool`, `zipalign`, `apksigner`, `keytool`), a full modify-resign workflow is available:

| Step | Tool / Command | Description |
| --- | --- | --- |
| Unpack | `apktool d app.apk -o out/` | Decode APK to editable form (smali + resources + manifest) |
| Modify | Direct file edits | Patch smali / resources / manifest / DEX / SO |
| Repack | `apktool b out/ -o new.apk` | Rebuild APK from decoded directory |
| Align | `zipalign -p 4 new.apk aligned.apk` | Align APK for optimal memory mapping |
| Sign | `apksigner sign --ks debug.jks aligned.apk` | Sign with debug/release key |

Alternatively, the built-in tools provide a streamlined path:
1. `reverse_kill_signature` — strip native signature verification (libjiagu.so, etc.)
2. `reverse_inject_dex` — inject a DEX payload (e.g., hook.dex) into the APK's `classes.dex` chain
3. `reverse_resign_apk` — re-package and sign the APK in one step (generates debug keystore if needed)

**Example: Bypass signature verification and resign:**
```text
1. reverse_open_apk → load target.apk
2. reverse_kill_signature → remove libjiagu.so checks
3. reverse_inject_dex → add hook payload (optional)
4. reverse_resign_apk → output signed, ready-to-install APK
```

> ⚠️ **Disclaimer:** Modifying third-party APKs may violate terms of service or laws. Use only on APKs you own or have explicit permission to modify.

All tools accept either a local file `path` or `base64`-encoded bytes. No external native libraries (Rizin, LIEF, etc.) are needed — the parser is implemented in pure Dart and runs entirely in-process.

### GitHub Write Tools

The GitHub MCP server exposes grouped tools instead of one tool per API endpoint:

- Repository and file operations.
- Branch, tag, commit, directory, and file management.
- Issue and pull request workflows.
- Pull request merge and review comments, including inline and file-level comments.
- Release management.
- GitHub Actions workflow/run/job/log operations.
- Repository/environment secrets and variables.

The wrapper layer also follows GitHub API constraints more strictly: empty repositories are initialized before branch creation, reserved `GITHUB_` variable names are rejected early, fresh writes are verified with strong read APIs instead of code search, PR updates use minimal payloads, and review-comment creation is separated from reply-comment payloads.

### Local Hybrid Search

- API-key-free local search mode.
- Aggregates Bing Local, DuckDuckGo, Baidu, Sogou, and 360.
- Isolates provider failures, deduplicates URLs, removes low-value results, and ranks by provider/source quality.

### MCP Enhancements

- ✅ **Global Tool Search**: Search across all MCP servers' tools by name/description with fuzzy matching
- ✅ **Call Statistics Dashboard**: Visualize per-server call volume, success rate, average latency, and error distribution
- ✅ **One-Tap Reconnect**: Batch reconnect all unhealthy MCP servers
- ✅ **Background Health Check**: Periodic connectivity monitoring with auto-reconnect
- ✅ **Auto-Approval Rules**: Configure rules by tool name/parameters to skip manual confirmation
- ✅ **Tool Call History**: Automatic logging of all invocations (params, results, latency, status) with query/filter/export
- ✅ **Batch Tool Management**: Enable/disable all tools for a server in one action
- ✅ **Reverse MCP Extensions**: Built-in `@kelivo/reverse` with 28+ tools, including:
  - DEX string batch replace: regex matching, class-scope filter, replace preview
  - APK batch resign: custom keystore, v1/v2 scheme selection, auto-clear old signatures
  - One-tap unpacking wizard: auto-detect 12+ packers, output tailored unpack steps
- ✅ **Tool Favorites & Grouping**: Custom tool collections by use-case scenario, quick-filter and one-tap invoke
- ✅ **Parameter Template Presets**: Save reusable parameter configs for any tool, auto-fill on next call, exportable
- ✅ **Server Tag Grouping**: Tag MCP servers, batch reconnect/enable/disable/export by group
- ✅ **Auto-Retry on Failure**: Per-tool retry rules (count, interval, trigger condition), no manual intervention
- ✅ **Built-in Template Marketplace**: 20+ pre-configured MCP tool templates (batch web scraping, multi-format conversion, structured data analysis, etc.)
- ✅ **One-Tap APK Unpacking**: No-root unpacking of installed apps/local APKs, auto-merge Split APKs, extract resources/DEX/Manifest, decompile binary XML/ARSC
  - 🔧 Auto packer detection: 18+ packers (Bangcle/360/Tencent Legu etc.), suggest tailored unpack strategy
  - 📂 Smart output classification: DEX/resources/native libs/Manifest/signatures auto-sorted, filter by type
  - ⚡ Batch unpacking: Multi-select APKs/apps, async background execution
  - 🔍 Resource obfuscation auto-restore: Detect & restore AndResGuard-style obfuscated filenames
  - 🔗 MCP tool chaining: Directly invoke DEX replace/batch resign after unpacking, no re-upload
  - 📤 Multi-format export: ZIP archive or filtered file type export (DEX/resources/.so), share to other apps
  - 📸 Unpacking snapshots: Auto-save unpack records (APK info, timestamp, output path), review history anytime
  - ⚙️ Custom unpack rules: Configure filters (skip .so, decompile Manifest/resources only, skip large files)
  - ✅ Integrity verification: Auto MD5/SHA1 hash check against source APK blocks
  - 📊 One-tap analysis report: Security analysis — permission risks, exposed components, SDK identification, packer status
  - 🧠 Large APK analysis optimization: 100MB+/multi-DEX auto chunked incremental analysis, dynamic memory control, prevent OOM
  - ⏱️ Analysis timeout fallback: Configurable timeout, auto-degrade to lightweight mode (core info only)
  - 📶 Offline background analysis: Large APKs queued as background tasks, progress query, pause/resume, push notification on completion
  - 💡 Lightweight analysis mode: Extract basic info/permissions/components/SDK list in 10s, no full decompilation
  - 🔁 Checkpoint resume: Resume from interruption point after process kill/device reboot
  - 🎯 Obfuscation smart-tagging: Auto-detect obfuscated classes/methods, link mapping files for symbol restore
  - 🛡️ Malicious code pre-scan: Built-in threat signatures (mining/fraud/privacy theft/adware)
  - 📱 Full APK category support: Regular apps, system apps, automotive/wearable/IoT APKs, Split APKs
  - 🤝 Ecosystem integration: Generate Frida Hook templates, export to JADX-GUI/APKToolBox, generate Xposed module scaffolding
  - 📈 Progress visualization: Real-time progress, current step, ETA, memory usage at a glance

## Usage

### Install Android APK

Download links:

- Latest Release page: [Kelivo RevKit Releases](https://github.com/dhh-max/kelivo-revkit/releases)

The public APK keeps the Android package name `com.psyche.kelivo`, the same as Kelivo Plus / upstream Kelivo, so Android treats it as the same app:

- It cannot be installed over the official upstream Kelivo or Kelivo Plus app unless the signing certificate matches, which it normally does not.
- It cannot coexist with upstream Kelivo or Kelivo Plus because Android only allows one installed app per package name.
- It can update an older Kelivo RevKit build only when the signing certificate is the same and the version code is not lower.

Recommended installation path:

1. Back up or export data from upstream Kelivo / Kelivo Plus if needed.
2. Uninstall upstream Kelivo / Kelivo Plus.
3. Install the Kelivo RevKit APK from this repo's Releases.
4. Import backups or reconfigure providers, assistants, MCP, and GitHub Token.

To coexist with Kelivo Plus / upstream, build a separate package-name variant:

1. Change Android `applicationId`, for example to `com.psyche.kelivo.revkit`.
2. Optionally change the app label to `Kelivo RevKit` to avoid launcher confusion.
3. Sign the APK with your own key.
4. Treat it as a separate app with separate app data; migrate data through backup/import rather than direct private-data sharing.

The current Release APK is a same-package build, not a coexistence build.

### Configure Models

1. Open Kelivo RevKit.
2. Add a model provider such as OpenAI, Gemini, Anthropic, or another compatible endpoint.
3. Select the model in chat and start using it.

### Enable 神经权能网关

1. Open an assistant settings page.
2. Enable “Allow this assistant to use 神经权能网关”.
3. Ask the assistant to import or edit a supported configuration target from chat.
4. Review the generated action and undo recent changes when needed.

### Configure GitHub Token

1. Open the MCP page.
2. Edit the built-in GitHub MCP server.
3. Paste a GitHub token into the GitHub Token field.
4. Grant only the scopes you need, commonly `repo` and `workflow` for write workflows.

### Use Local Hybrid Search

1. Open Search service settings.
2. Enable Local Hybrid Search.
3. No API key is required.

## Build From Source

Recommended environment:

- Flutter 3.44.1 or newer
- Dart 3.12.1 or newer
- Android SDK/NDK for Android builds

Common commands:

```powershell
flutter pub get
flutter test test/core/providers/mcp_provider_builtin_test.dart test/kelivo_github_mcp_server_test.dart
flutter build apk --release --target-platform android-arm64
```

The repository does not include signing secrets. Configure your own `android/key.properties` or Android signing workflow before publishing APKs.

## Security Notes

- 神经权能网关 is a high-permission capability and is disabled by default. Destructive, overwrite, and batch import operations remain confirmation-driven and undoable where supported.
- GitHub write tools can modify remote repositories; use least-privilege tokens.
- Do not commit tokens, secrets, keystores, `android/key.properties`, build caches, or APK outputs.
- AGPL-3.0 obligations apply when distributing modified builds.

## Documentation

### Main App

- [Chinese README](README_ZH_CN.md)
- [Kelivo RevKit change notes (vs Kelivo Plus)](docs/KELIVO_PLUS_CHANGES_ZH.md)
- [Android installation and coexistence guide](docs/ANDROID_INSTALLATION_ZH.md)
- [Release notes](docs/RELEASE_NOTES_1.1.17_PLUS.md)
- [Search upgrade notes](docs/KELIVO_SEARCH_UPGRADE_NOTES.md)
- [APK analysis anti-crash & performance optimization](docs/APK_ANALYSIS_ANTI_CRASH_ZH.md)
- [Kelivo App technical reference (19 chapters)](docs/KELIVO_APP_REFERENCE_ZH.md)

### RelayGo Gateway

- [RelayGo Gateway technical reference (19 chapters)](docs/RELAYGO_GATEWAY_REFERENCE_ZH.md)

### Acknowledgements

- [Full credits (11 chapters / 532 lines)](docs/CREDITS_ZH.md)

## License

Kelivo RevKit is licensed under AGPL-3.0. See [LICENSE](LICENSE) for details.
