import 'dart:convert';

class SolabApkSkills {
  const SolabApkSkills._();

  static const activationHints = <String, String>{
    'apk_base_analysis': 'APK analysis without a narrower goal',
    'apk_reverse_playbook': 'Reverse engineering, decompilation, obfuscation, code location',
    'apk_ad_review': 'Ad identification, location and review',
    'apk_cleanup_review': 'Package slimming, size and resource review',
    'apk_permission_review': 'Permissions, components and Manifest review',
    'apk_change_plan': 'Membership, capture or other modification planning',
    'apk_apply_patch': 'User explicitly requests modify, fix or build',
    'apk_verify_patch': 'Signature, install, launch and effect verification',
    'apk_flutter_locate': 'Flutter, Blutter and libapp location',
    'flutter_vip_unlock': 'Confirmed Flutter membership/subscription/ad task',
    'apk_crypto_locate': 'Locate signature, check, encryption or decryption logic',
    'apk_patch_migrate': 'Migrate old patches to a new app version',
    'apk_emulation_verify': 'Unidbg/Unicorn emulation, signature pre-verification, anti-emulation',
    'apk_struct_recovery': 'Rebuild struct and field layout from cross-function access patterns',
    'apk_network_evidence': 'Network evidence via an optional capture MCP (ProxyPin etc.), server-side vs local verdict',
    'apk_symbol_recovery': 'Recover function symbols from exports/imports/strings',
  };

  static const activationRules = <String, List<String>>{
    'apk_base_analysis': ['Reuse the current session fresh report first; only fill the missing sections.', 'Output report facts, rule inferences and to-verify items separately.'],
    'apk_reverse_playbook': [
      'Decide the target layer first, then start from the most discriminating evidence; never run a fixed pipeline.',
      'Obfuscated names are clues only; judge by code, data flow, call sites, constants and real bytes.',
    ],
    'apk_ad_review': [
      'Judge SDK init, display triggers, remote config and container UI separately.',
      'Candidates become patchable only after converging on real code and call relations.',
    ],
    'apk_cleanup_review': [
      'Classify safe / needs-confirmation / high-risk; never auto-delete unknown binaries or SO files.',
      'Slimming conclusions must cite reference evidence and expected savings.',
    ],
    'apk_permission_review': [
      'Judge static risk from the current report only; no call found does not mean safe to remove.',
      'Check permissions together with their components and code references.',
    ],
    'apk_change_plan': ['List evidence, minimal change, risk and verification for the user goal.', 'Do not re-ask when the goal is clear; analysis tasks never drift into writes.'],
    'apk_apply_patch': [
      'Continue from the session resume snapshot; verify an existing locator directly instead of re-running full analysis.',
      'Unless the user asks to skip it or the Workbench disables it, run standalone signature bypass on the original before the first business write; continue along that prepared chain.',
      'Write only verified minimal targets; after producing the signed artifact, wait for the user install verification.',
    ],
    'apk_verify_patch': [
      'Verify install, launch and target behavior; a successful tool step is not verified user effect.',
      'Merge the single per-app memory only after user confirmation; clean intermediates after success.',
      'Before install, a unidbg session can machine-verify signature compatibility (see apk_emulation_verify); simulation evidence is not device verification — installation confirmation is still required.',
    ],
    'apk_flutter_locate': [
      'Reuse existing Blutter indexes and saved reports first; never re-analyze the same APK.',
      'Identify the real business system first, then locate via strings, numbers, field data flow and call sites.',
    ],
    'flutter_vip_unlock': [
      'Decide the Dart, DEX, SO or resource layer first; every evidence route starts and combines independently.',
      'Level values must be proven by this app own numbers and data flow; never copy another app mapping.',
      'After patching, verify real bytes on the current delivered artifact; Blutter cache is never acceptance evidence.',
    ],
    'apk_crypto_locate': [
      'Start with so_analyze(action=crypto_scan) for crypto constants and import symbols, then decide whether DEX or SO carries the algorithm.',
      'Intersect so_analyze(action=jni_bridge) classes with DEX native declarations; bridges outrank blind search.',
      'After an AES/TEA constant hit, close the Key/IV data flow with trace; never write bytes without plaintext evidence.',
      'Generic-library hits (pointycastle, Conscrypt) are background only; consumerExclude filters trace noise.',
    ],
    'apk_patch_migrate': [
      'After analyzing both old and new packages, call blutterAction=diff with compareToJobId=new jobId.',
      'similarity=1: reuse the old locator va directly; 0.45~0.8: re-verify the branch with disasm before reuse.',
      'After migration follow the existing dryRun preview and applyAfterPreview contract; never substitute long-term memory for the live report.',
    ],
    'apk_emulation_verify': [
      'Single-path simulation goes through so_analyze(action=emulate); attribute failures by error.stage. Interactive control uses the unidbg_dispatch session (session_open/session_call/session_registers).',
      'Patch JNI/syscall/anti-emulation gaps one by one per framework_matrix; the same gap failing three times stops the route (policy rule 2).',
      'Simulation evidence is machine-level but not device verification; label it accordingly and never call it "verified on device".',
    ],
    'apk_struct_recovery': [
      'A field is only promoted when >=2 functions access the same offset with the same width; a single access is a lead.',
      'Layout table columns: offset / width / accessor count / evidence; naming goes to notes, never to the original library.',
    ],
    'apk_network_evidence': [
      'Network evidence comes only from a connected capture MCP; without one, say so and decide from local evidence alone.',
      'Attribute a host to the target only when it also appears in the target APK\'s own strings/resources; otherwise it is a lead.',
      'Requests that cannot be decrypted (certificate pinning/custom protocol) are a finding, never a reason to guess server behaviour.',
    ],
    'apk_symbol_recovery': [
      'Read the export/import/Java_* JNI surface first; intersect DEX native declarations with SO exports to find bridges.',
      'Dart symbols go through Blutter (search/locate/xref/values); never hammer rz_functions on an AOT snapshot (always 0 hits).',
      'Every name carries evidence and confidence; renaming is an analysis artifact, never an ELF symbol-table change.',
    ],
  };

  static const skillNames = <String>[
    'apk_base_analysis',
    'apk_reverse_playbook',
    'apk_ad_review',
    'apk_cleanup_review',
    'apk_permission_review',
    'apk_change_plan',
    'apk_apply_patch',
    'apk_verify_patch',
    'apk_flutter_locate',
    'flutter_vip_unlock',
    'apk_crypto_locate',
    'apk_patch_migrate',
    'apk_emulation_verify',
    'apk_struct_recovery',
    'apk_symbol_recovery',
    'apk_network_evidence',
  ];

  static Map<String, dynamic>? activation(String skill) {
    if (!skillNames.contains(skill)) return null;
    final payload = jsonDecode(read(skill)) as Map<String, dynamic>;
    return <String, dynamic>{
      'id': skill,
      'name': payload['name'],
      'trigger': activationHints[skill],
      'rules': activationRules[skill] ?? const <String>[],
      'fullSkillTool': 'get_solab_skill(skill=$skill)',
    };
  }

  static String read(String skill) {
    final payload = switch (skill) {
      'apk_base_analysis' => {
        'name': 'APK Base Analysis',
        'requiredReportSections': ['summary', 'components', 'permissions'],
        'steps': [
          'Read the current APK report\'s summary, components and permissions.',
          'Separate report facts, rule inferences and to-verify items.',
          'List package info, signature, exported components, risky permissions, DEX, resources, SO and ABI.',
        ],
        'output': ['Conclusion', 'Key evidence', 'Risk', 'Next step'],
      },
      'apk_reverse_playbook' => {
        'name': 'Reverse Engineering Playbook',
        'source': 'reverse-engineering-playbook.md',
        'workflow': [
          'An APK is a ZIP container. Inspect Manifest, lib, assets, DEX and resources.arsc first, then decide the modification path.',
          'Analysis, signature compatibility, minimal modification, signing and install verification each run independently; unless the user asks to skip it or the Workbench disables it, generate a standalone bypass artifact from the original before the first business modification and use only that artifact for later edits.',
          'If packed, stop structural changes and require an unpacked APK; unpacking is not decompilation.',
          'Before static modification, locate evidence via UI text, resource IDs, layouts, capture fields, logs and cross references.',
        ],
        'terms': {
          'manifest': 'Components, permissions, entries and export state; confirm no code references remain before removing a component.',
          'dex_smali': 'Patch only the minimal method set the report proves; void-to-empty, boolean true/false, and long time values are bounded by current native patch capability.',
          'assets_res': 'assets may hold configs and H5 resources; unknown proto/pb/bin files and SO files are flagged for review only.',
          'native_lib':
              'lib/*.so identifies packers and engines; a native instruction patch must first close function, call-chain and stack-balance evidence via so_analyze, then write back through so_patch_into_apk.',
          'signing': 'Re-sign after any modification; on install or launch failure check signature, packer and component references first.',
        },
        'engineSignals': {
          'Flutter': ['assets/flutter_assets/', 'libflutter.so', 'libapp.so'],
          'React Native': ['assets/index.android.bundle'],
          'H5': ['assets/www/', 'html/js/css'],
          'Unity IL2CPP': ['libil2cpp.so', 'global-metadata.dat'],
          'Unity Mono': ['assets/bin/Data/Managed/', '.dll'],
          'Cocos': ['assets/src/', '.jsc', 'libcocos2djs.so'],
          'Xamarin': ['libmonodroid.so', '.dll'],
        },
        'ruleMapping': {
          'Ads': [
            'sdk_packages',
            'method_patterns',
            'ad_key_strings',
            'ad_asset_files',
          ],
          'Membership': ['force_true_methods'],
          'Time': ['time_methods'],
          'Device checks': [
            'detection_vpn',
            'detection_emulator',
            'detection_root',
            'detection_debug',
          ],
          'Packer': ['shell_signatures'],
        },
        'guardrails': [
          'Rule hits are candidates, not patchable facts; always dryRun-preview first, and execute directly once the user has made the goal explicit.',
          'Smali regexes from notes are folded into the rule library semantically; automatic patching never executes raw regex text.',
          'Without local evidence for network protocols, payments, signature algorithms, native instructions or server state, give locating leads only — never invented conclusions.',
        ],
      },
      'apk_ad_review' => {
        'name': 'Ad Rule Review',
        'requiredReportSections': ['summary', 'ads', 'components'],
        'steps': [
          'Read ad rule hits and related components; for Flutter call report(ads) first, locate(goal=find the ad display switch) only when no saved report exists.',
          'Group ad leads into SDK init, display trigger, remote config and container UI; cite evidence per SDK, class, URL and keyword.',
          'A display-trigger candidate must combine a clear system, bool/void return and a call chain that truly is business display; init, remote config or container UI hits alone are leads.',
          'When nothing hits, state clearly: no rule hit does not mean no ads.',
          'Produce candidate changes only; never execute them here.',
        ],
        'output': ['Hits', 'Confidence', 'Candidate changes', 'Verification method'],
      },
      'apk_cleanup_review' => {
        'name': 'Package Slimming Review',
        'requiredReportSections': ['summary', 'files'],
        'steps': [
          'Read the largest files, SO files, candidate files and file-type statistics.',
          'Empty files may be marked safe; proto/pb/bin are review-only; SO files are always high-risk.',
          'Output three groups: safe, needs-confirmation, high-risk.',
        ],
        'output': ['Expected savings', 'Safe candidates', 'Needs-confirmation items', 'Never-auto-delete items'],
      },
      'apk_permission_review' => {
        'name': 'Permission Review',
        'requiredReportSections': ['summary', 'permissions', 'components'],
        'steps': [
          'Read permissions, risky permissions and exported components.',
          'Judge static risk from the report only; no call found never means safe to remove.',
          'Group permissions into keep, needs-confirmation, and removable-along-with-removed-components.',
        ],
        'output': ['Permission list', 'Risk source', 'Needs-confirmation items', 'Preconditions'],
      },
      'apk_change_plan' => {
        'name': 'APK Change Plan',
        'requiredReportSections': ['summary', 'ads', 'files', 'permissions'],
        'steps': [
          'Read the user-stated goal; ask only when the goal is unclear or the plan involves a real trade-off.',
          'Read the report sections and rule hits relevant to the goal.',
          'Unless the user asks to skip it or the Workbench disables it, run standalone signature bypass on the unmodified original before the first business write: an explicit user mode wins, otherwise follow the Workbench setting. Later patches only consume the artifact this step returned.',
          'List each change target with evidence, impact, rollback point and verification method.',
          'Once the user has explicitly requested modifying the current APK, go straight to the preview-capable execution tool; never re-ask for confirmation.',
        ],
        'output': ['Goal', 'Change set', 'Risk', 'Confirmations', 'Verification'],
      },
      'apk_apply_patch' => {
        'name': 'APK Patch Execution',
        'requiredReportSections': ['summary', 'ads'],
        'steps': [
          'Read decision via get_current_apk_report first to confirm target scope and unpacking state (if packed, confirm unpacking first).',
          'route_task returns candidate evidence routes, not a fixed call chain. With an existing qualifiedId, VA, field locator, string reference or reference artifact, start directly from the matching tool; read the world book, user skills or runtime guide only when new information could change the decision.',
          'Before calling, trust the current tools/list and tool schemas; if a tool is missing, check the available-tool entry or use a currently declared tool — never use stale tool names or guess parameters or paths.',
          'Use exactly one workspace named after the app for the same source APK; pass every outputPath, nextInputPath, qualifiedId, VA and previewToken downstream verbatim.',
          'Unless the user asks to skip it or the Workbench disables it, run the standalone signature_bypass tool on the unmodified original before the first business write: an explicit mode wins, otherwise follow the Workbench setting. Both dpatch and original_apk must continue from the returned outputPath; never modify the original directly; keep signatureBypass=false explicitly afterward. Never re-run or back-fill bypass on an already modified APK. If install crashes, keep the original, regenerate the artifact with another mode, and retest.',
          'Prefer single-point fixes: distinguish entries (adEntryMethodMatches, init*/register*/manager*) from call sites (adMethodMatches).'
              'Change one most-upstream entry per feature class; never submit dozens of methods at once.',
          'Priority by target type (pick a verified single point; no scattergun):'
              'Ads: separate SDK init, display trigger, remote config and container UI first; prefer local bool gates like shouldShowAd/canShowAd or void display triggers like show/play.'
              'Modify initSdk/initAd only when the call chain proves it is the sole upstream entry and skipping it leaves no placeholder or crash; stopping init is never equal to disabling ad display.'
              'Membership: prefer the innermost pure bool/int decision function (force true); leave the outer getter chain untouched.'
              'Expiry/trial: the time-computation or counter source (far-future / large value).'
              'Check/signature/integrity: unless the user asks to skip it or the Workbench disables it, run standalone signature_bypass on the unmodified original before the first business write (explicit mode first, otherwise the Workbench setting); later patches never mix in signature injection.'
              'Both dpatch and original_apk produce standalone artifacts; later steps use only that outputPath.'
              'Anti-debug/anti-tamper: flip the detector return value or void its entry.',
          'Compute every value another tool will write with value_calc first — never by hand.'
              'action=convert gives hex/dec/bin/oct, 8/16/32/64-bit signed and unsigned, little-endian hex and ASCII in one call;'
              'action=float turns a smali const/high16 or const-wide machine code into the float it holds (and back);'
              'action=bitwise/endian cover flag masks and byte order, codec decodes base64/hex/URL string constants,'
              'crc/hash reproduce checksums and mod covers modular arithmetic.'
              'Chain several of them in ONE call with steps[] and {"\$step":0,"field":"bitWidths.bit32.littleEndianHex"}.'
              'Hand-computed constants are a top silent failure (unsigned vs signed, float32 vs float64, endianness) — the tool returns every representation so the written bytes can be re-checked.',
          'Modification paths are combinable options, not a fixed escalation chain: method returns, field reads/writes, upstream entries, call-site branches, Dart decisions and native loading each verify independently. Choose the smallest change with explainable side effects; after a failure on the same parameters, switch the observation dimension instead of retrying in place.',
          'When the user has authorized the exact modification, preview-capable tools run dryRun=true+applyAfterPreview=true in one call; after a pure dryRun you must execute the returned applyArguments verbatim — never forget the write or re-preview. Warnings, no change, and target mismatch block auto-apply.',
          'In Agent mode every question must go through ask_user_input_v0 — plain text is not a substitute; MCP callers without a question tool may confirm in text.',
          'Report each finished stage and continue to the next without waiting for step-by-step instructions.',
          'There is no hard call-count cap; stage token budgets are soft hints, with ~80K visible evidence text as the anti-runaway hard cap. Every call must be able to change candidate ranking, evidence level or patch approach; otherwise conclude from current evidence. Paginate only when hasMore/nextOffset exists and the next page would change the decision.',
          'The modification process writes no long-term memory. After apk_sign produces the artifact, stage a to-verify draft via save_apk_patch_memory (not long-term), then immediately ask the user via ask_user_input_v0 whether the install works (text confirmation for MCP without a question tool). Stop once verified — no extra changes.',
          'When the report misses but the user names a feature: ask for locating leads (UI text / capture fields / log TAGs),'
              'then cross-confirm the modification site via strings, field reads/writes, call chains and disassembly evidence (verify before modifying).',
          'After a direct DEX patch, sign with the built-in apk_sign (v1/v2/v3) before installing; run apk_rebuild only when a decoded directory, resources or the Manifest were edited.',
        ],
        'output': ['Selected tool', 'Preview hits', 'Confirmation record', 'Artifact path', 'Next step'],
      },
      'apk_verify_patch' => {
        'name': 'APK Patch Verification',
        'requiredReportSections': ['summary'],
        'steps': [
          'Have the user install the signed package (after built-in apk_sign) and launch it, watching whether it reaches the home screen.',
          'Verify item by item against the goal: ad entries, membership state, VPN/emulator behavior, component navigation.',
          'On crash, check signature state (v1/v2), packer state, and whether removed components are still referenced.',
          'Classify conclusions into: effective, ineffective (possible server-side check), and regression risk.',
          'When the user reports the signed package effective or not, immediately call record_apk_patch_verification with the outcome and minimal verification result; not-installed, dryRun and successful tool returns are never recorded as verified.',
          'After the user confirms a valid install, record_apk_patch_verification saves long-term memory then auto-cleans the work directory, keeping only the original and the final signed artifact; on an invalid report, keep the scene for further fixes.',
        ],
        'output': ['Verification items', 'Result', 'Regression risk', 'Next step'],
      },
      'apk_flutter_locate' => {
        'name': 'Flutter Business-System Location',
        'applicability':
            'The report confirms flutterApp.detected=true and you need to locate membership, subscription, ad, capture or other Dart business state.',
        'steps': [
          'Read any saved Blutter report in the current workspace first; locate only on REPORT_NOT_READY, and analyze only when no reusable succeeded job exists. Never re-analyze the same APK.',
          'Run one keyword-family census over pp.txt with hit counts first; never conclude from a single word. Membership distinguishes at least bool state (是否会员), level (等级/至尊/钻石), Pro/one-time purchase (专业版/完整版), subscription (订阅/续费), expiry/permanent (到期/永久) and UI/payment copy; ads distinguish SDK init, display trigger, remote config and container UI.',
          'Decide the app\'s real system from the hit combination, then xref/callers only against that system\'s strings or pool offsets; UI and payment copy are leads only.',
          'When the user gives values like 5/55, query with values/assembly immediates matching decimal, hex and pool ints. Never treat ldr/str field offsets or List<T>(N) lengths as levels.',
          'Prefer locating the real state read/write or decision function. A function body or field data flow that directly expresses the target behavior can conclude alone; otherwise cross-confirm with two independent sources among keyword families, reference chains, function shape, return semantics, constants or user-supplied artifacts.',
          'Read only summaries, target functions and at most one necessary page; never feed pp.txt, asm or 500-row results end to end.',
        ],
        'output': ['System classification', 'Hit statistics', 'Target function and VA', 'Numeric evidence', 'Next tool'],
        'guardrails': [
          'A string search missing numeric constants is a dimension limit, not proof the value is absent',
          'A lone getter, display class or payment-copy hit is never a patch target',
          'Level values differ per app; never reuse another app\'s 5/10/55 mapping',
        ],
      },
      // Flutter 会员解锁/去广告通用方法论：只固化思维顺序，不固化任何具体
      // 地址/等级值/关键词命中——每个 App 的等级体系、混淆方式、SDK 接入
      // 都不同，参数一律由现场证据决定（先定位后修改，禁止猜测）。
      'flutter_vip_unlock' => {
        'name': 'Flutter Membership Unlock / Ad Removal',
        'applicability':
            'The report shows flutterApp.detected=true and the goal is membership/level/subscription/ads.'
            'Non-Flutter packages use apk_apply_patch; Flutter packages with a native-layer goal (ad SDK/downloads/permissions) also use the dex toolchain.',
        'steps': [
          '0 Free composition: the layering, Dart, DEX, numeric, call-chain and reference-artifact probes below are independent evidence probes, not a numbered pipeline. Verify directly when an exact locator exists; stop once one direct behavioral proof suffices — combine a second independent route only for indirect leads.',
          // 第一步永远判定目标属层，位置不固定
          '1 Layer decision (differs per app; locate first): read flutterApp.dualTrackRouting from the report.'
              'Membership/VIP/level/subscription/player behavior decisions -> Dart business layer (libapp.so via Blutter);'
              'Ad SDK init/load, downloads, permissions, syscalls -> native layer (dex+assets+Manifest via methods/fields/dex_search).'
              'One task may span both layers (unlock on Dart + ad removal on native); locate them separately.',
          // 轨道 A：Dart 层——关键词是词族不是固定清单，命中不了要换词
          '2a Dart-layer location (Blutter): start with blutterAction=report(report=membership/capture/ads) to reuse the saved report from the last locate;'
              'call blutterAction=analyze only on REPORT_NOT_READY or RESULT_NOT_FOUND (path takes the APK or a directory containing '
              'libapp.so+libflutter.so; a bare .so is rejected); it returns a jobId asynchronously,'
              'wait for succeeded via status+wait=true (on timeout continue per the hint; never poll rapidly by hand);'
              'With a succeeded jobId, locate directly — never re-analyze; locate returns compact evidence and saves a report, never read long-result pages;'
              'Artifacts are consumed on demand: result reads the result.json summary, result(kind) pages through the libraries/classes/functions/objects indexes, search reads pp.txt/asm, xref/locate/values/trace use the semantic, pool, field-access and ARM64 function indexes automatically, disasm/callers read asm; never feed whole files to the model.'
              'Merge similar words into one search with | (e.g. isVip|isMember|vipLevel); ASM defaults to the semantic index - fullScan=true only when the index misses and raw non-semantic lines are truly needed. Full scans skip common third-party packages by default and narrow with includePath/excludePath; includeThirdParty=true only when the target truly lives in a dependency. Never rescan the whole ASM tree word by word.'
              'On FLUTTER_VERSION_NOT_SUPPORTED or analysis failure, immediately use blutterAction=raw_strings(path, goal) '
              'to scan libapp.so raw strings directly as preserved evidence; switch to dex only when the goal truly is native-layer.'
              'blutter locate first runs a keyword census over pp.txt; never conclude from one word. For membership, count:'
              'bool state (isVip/isMember/是否会员), level types (vipType/memberLevel/至尊/钻石),'
              'Pro/paid unlock (isPro/fullVersion/专业版/完整版), subscription purchase (subscription/productId/订阅/续费),'
              'expiry/permanent (expiresAt/lifetime/到期/永久) and UI display words. For capture, count proxy/VPN, TLS pinning,'
              'certificate trust chains and network-stack words; for ads, count SDK init, display trigger, remote config and container UI separately.'
              'Read intentProfile hit counts, samples and classificationStatus first to pin the app\'s actual system;'
              'when ambiguous, cross-compare the top two classes; a lone UI/payment-copy hit is never a patch point. Once the system is fixed,'
              'xref only that system\'s pool offsets; when the field key appears only in a parser or the real decision function is obfuscated/separated, immediately use trace from the key reference to field writes and reads. Prefer candidates with sliceConfidence=high whose decisionEvidence enters a comparison/branch; low only proves the offset matches and is never a conclusion.',
          // 等级语义必须由证据反推，禁止假设；直接证据可单点定案，
          // 间接线索才需要两个来源交叉。
          '2b Numeric and field-semantics confirmation (multi-signal): locate reads observedValues/valueEvidence; when the user gives any known business value,'
              'immediately call blutterAction=values(query=that value, goal=current goal, va=candidate VA), matching raw ints, Dart Smis, pool ints and mov/cmp '
              'immediates and pool ints together. A bracketed #0x37 in ldr/ldur/str/stur is a field or stack offset, not level 55;'
              'List<T>(N)\'s N is an element count, not the top level. Level systems differ per app; never assume a value equals max level. Follow the call chain to the innermost decoder/decision function;'
              'when value search and name search cannot connect, use blutterAction=trace(poolOffset=field-key offset, goal=current goal) to build the parser-write -> field-offset -> read -> register-consumption chain automatically, then confirm the compared value, branch direction and return semantics.'
              'A high-confidence rawDecisionFlow candidate means the tool already connected display copy -> compared value -> call chain -> level-return function from the current libapp bytes; run one native disasm on the first candidate\'s functionVa only — never re-search words, browse asm/classes/functions, or scan from incomplete function heads.'
              'Judge candidates by evidence strength: a function body or field data flow expressing the target behavior concludes alone; otherwise take two mutually independent sources among PP keyword families, pool/call chains, numbers, function shape and return semantics. Rule hits, UI copy and same-name functions remain leads.',
          // 补丁规范：先 disasm 读函数体判形态，再选手法
          '2c Patching (mandatory): after one complete blutterAction=locate, go straight to so_analyze(action=edit_open) then so_analyze(action=edit_asm) dryRun,'
              'choose the mode by function shape:'
              'pure bool/int decision functions -> force_return_constant with a stackless stub'
              '(int -> mov w0,#N;ret, bool -> 0/1, object -> return null; values >0xFFFF auto movz+movk);'
              'state-writing/void functions (like _recompute; a forced constant breaks the write) -> '
              'nop the tbnz/tbz/b.cond branch with mode=nop_out, or use mode=replace_instructions '
              'with writeAsm="b <target VA>" for an unconditional jump (keeping the rest of the function).'
              'Change only the innermost decision; leave outer getters untouched — minimal footprint.'
              'Never hand-write prologue/epilogue rewrites — the engine blocks stack breakage with STACK_IMBALANCE;'
              'dryRun only validates the bytes to be written; after execution, accept once with a hexdump/native disasm against the real entry in the current output SO or signed APK. Blutter disasm is a historical analysis artifact — it locates, never proves a write.',
          // 轨道 B：原生层
          '2d Native-layer location: read adSdkMatches/vendorSignals to confirm the dominant vendor;'
              'Display-trigger functions outrank SDK init and container classes. Hand existing class/field/method names, strings, numbers or instruction sequences to dex_search(auto) and let the tool intersect, branch and rank. Never expose locating routes to the user or treat candidates as results; auto-run nextActions to verify real code, call sites and rewritten implementations until the conclusion is patchable and re-readable. dex_xref(includeGraph=true) returns nodes/edges for flowcharts.'
              'patch_apk_dex_methods makes minimal method edits; patch_apk_manifest removes permissions or components only with evidence. A string hit'
              'is a lead only; converge it to a qualifiedId before patching.',
          // 打包验证沉淀
          '3 Build & deliver: so_analyze(action=build) writes the patched SO -> so_patch_into_apk writes it back into the current APK (keeping original compression, verifying entries) -> '
              'apk_sign signs (built-in apksigner check; success is effective, no re-verify) -> user installs and verifies -> '
              'record_apk_patch_verification records the outcome; when distilling with save_apk_patch_memory, put pitfalls in pitfall'
              '(this run\'s level-semantics basis, traps hit, and negative cases that crash/trigger detection/break behavior;'
              'negative cases are auto-avoided or down-weighted next time).'
              'Trust boundary: an ok from edit_asm/so_patch_into_apk/apk_sign only proves that step ran; the final patch point needs one real-byte acceptance on the current delivered file; Blutter cache never accepts, and the same result is never re-verified repeatedly.'
              'For incremental changes re-run only the affected single tool (a .so change means so_patch_into_apk+sign, not the dex/analysis chain);'
              'installation is the only human verification point.',
          // 目标降级链：VIP 搞不定时的本地等效路径，不轻易说做不到
          '4 Local equivalent paths (evidence-selected, alone or combined): when the VIP decision may be server-checked, evaluate these local targets:'
              'a) Grant rewarded-video rewards directly (locate the reward callback; skip the video and call success);'
              'b) Inflate or reset the trial/free-use counter (find the counter field and its consumers via fields);'
              'c) Time-hijack to extend validity (timeMethods returns a far-future value);'
              'd) Cut init/connection points (void the init/register entry to disable the class; dismantle load/show point by point).'
              'Verify only paths evidentially tied to current artifacts; with no local consumer, report the server-side limit honestly — never enumerate to pad the flow.',
        ],
        'guardrails': [
          'Patch sites vary by vendor/SDK version/obfuscation: locate before modifying; evidence decides the site; never guess or reuse another app\'s addresses/method names',
          'A DEX miss negates that search dimension only, never the target. Switch freely among Blutter, field data flow, resource references or native SO per APK structure; with a locator from a user artifact, verify it directly',
          'Constant returns must use force_return_constant; never raw-hex a stack frame (STACK_IMBALANCE blocks it)',
          'Change the innermost only, leave outer getters; with a normal-version reference package, hash + byte-diff first to locate differences fast',
          'Membership may be server-issued: if a local patch still fails to work, honestly say a server-side check may exist — never fake success',
          'When the front door fails, try the side: never conclude impossibility before trying reward-grant/trial-counter/time-hijack/init-cut local equivalents',
        ],
        'output': [
          'Layer decision',
          'Locating evidence (functions/VA/qualifiedId returned by tools)',
          'Patch and verification results',
          'Pitfall takeaways',
        ],
      },
      'apk_crypto_locate' => {
        'name': 'Crypto & Signature Location',
        'steps': [
          'Start with so_analyze(action=crypto_scan) for crypto constants, import symbols and trusted hits.',
          'Cross-locate JNI bridges via so_analyze(action=jni_bridge) against DEX native declarations.',
          'For candidates track only this APK\'s Key, IV, algorithm choice and callers; generic-library hits are never modification conclusions.',
        ],
        'output': ['Algorithm evidence', 'JNI/DEX location', 'Call relations', 'Next step'],
      },
      'apk_patch_migrate' => {
        'name': 'Patch Migration',
        'steps': [
          'Confirm file identity of both old and new APKs and their finished Blutter jobs.',
          'Call blutterAction=diff to map old locators onto new-version VAs.',
          'Reuse only similarity=1 mappings; re-read the current function body before previewing the rest.',
        ],
        'output': ['Version mapping', 'Reusable locators', 'Items to recheck', 'Migration result'],
      },
      'apk_emulation_verify' => {
        'name': 'Emulation & Pre-Verification',
        'source': 'Adapted from reverse-skills rev-unicorn-debug (MIT) for this toolchain',
        'when': [
          'Verify without installing: whether the signature-bypass injection is accepted by the target check, whether JNI_OnLoad passes, and whether anti-emulation blocks.',
          'Static evidence cannot settle a function\'s input/output relation and the target function can run standalone.',
        ],
        'steps': [
          'Locate the execution surface first: so_analyze(action=overview/read_elf) confirms architecture and dependencies; never parse the whole program — prepare only the target function and its data.',
          'Trial-run the default path: so_analyze(action=emulate) once; on failure classify by error.stage — missing symbol, missing mapping and unhandled JNI/syscall take different step-4 patches.',
          'Enter session control: unidbg_dispatch(op=session_open) returns emulatorSessionId; session_call(symbol, args) runs one function and session_registers reads the return; for paths use session_trace_code narrowed to a small range — never full instruction trace on big functions.',
          'Patch environment gaps: unimplemented JNI -> stub_template/hook_template generates a targeted stub; syscalls (read/write/mmap/ioctl) -> session_hook_start(hook=syscall); anti-emulation checks like Build/Telephony/procfs are handled item by item per framework_matrix\'s targeted-hook list.',
          'Signature pre-verification: session_memory_write puts the data under test (forged signature/certificate fields) into the target structure -> session_call the check entry -> derive a machine-level conclusion from the register return; it only proves that function holds in that environment.',
          'Iteration discipline: on a crash read callbacks/register snapshots, add memory or hooks, then retry; a gap failing three times stops the route and reports (policy rule 2).',
        ],
        'terms': {
          'session': 'The unidbg_dispatch session persists across calls: emulatorSessionId reuses the same VM, and memory writes/hooks stay effective within the session.',
          'evidenceLevel': 'Simulation evidence is machine-level (above speculation, below a real install); label it that way and never phrase it as "verified on device".',
        },
        'output': ['Simulation result and stage', 'Key registers/return values', 'Environment gaps and stubs applied', 'What this proves / does not prove'],
      },
      'apk_struct_recovery' => {
        'name': 'Struct & Field Layout Recovery',
        'source': 'Adapted from reverse-skills rev-struct (MIT) for this toolchain',
        'steps': [
          'Start from access points: so_analyze(action=disasm/rz_decompile) reads the target function and collects ldr/str-family accesses of "base register + immediate offset".',
          'Aggregate across functions: so_analyze(action=rz_xrefs) gathers callers/callees and samples the same object family\'s accesses; tabulate by offset, recording access width (w/x/b/h) and nearby symbol names.',
          'Rebuild the layout: sort offsets, infer types from width, promote fields by cross-function consistency; single-point accesses are leads only (same bar as policy rule 3).',
          'Minimal recheck: cross-confirm at least one offset with hexdump or a second disassembly view; write names via apk_note_write and never touch the original library.',
        ],
        'terms': {
          'consistency': 'An offset becomes a field only when >=2 independent functions access it with the same width; otherwise it is suspected only.',
          'editing': 'Struct conclusions guide patches (field consumers = patch targets); they never produce modifications by themselves.',
        },
        'output': ['Layout table (offset/width/accessor count/evidence)', 'Suspected fields and uncertainties', 'Suggested next reads'],
      },
      'apk_network_evidence' => {
        'name': 'Network Evidence (optional capture MCP)',
        'requiredReportSections': ['summary'],
        'steps': [
          'Check the external MCP catalog first (list_available_mcp_tools with no arguments): a connected capture tool such as ProxyPin exposes its request list, domain summary and request details. If nothing is connected, say "no network evidence available" and decide from local evidence alone — never guess what a server would return.',
          'Start from aggregates (domain summary, request stats, search) and open a single request detail or body only when it can change the decision; request bodies are the most expensive read.',
          'Attribution: traffic seen on this device is not automatically this app\'s. Treat a host as belonging to the target only when it also appears in the target APK\'s own strings/resources (dex_search / string_scan), or the request is unambiguously caused by the target acting; otherwise label it "source unknown — lead only" and never build a server-side conclusion on it.',
          'A capture that shows no readable content is itself a result: pinned/custom-protocol traffic is common, so report "request observed but content not decryptable" or "no request observed" as the finding, and keep the patch decision on local evidence.',
          'Capture tools are read-only by default: replay/rewrite/breakpoint actions change real traffic, so run them only when the user explicitly asks, and treat the replayed response as a new observation rather than proof.',
        ],
        'output': ['Server-side vs local verdict', 'Endpoint evidence with attribution', 'What the capture could not show', 'Next discriminating action'],
      },
      'apk_symbol_recovery' => {
        'name': 'Function Symbol Recovery',
        'source': 'Adapted from reverse-skills rev-symbol (MIT) for this toolchain',
        'steps': [
          'Read the existing symbol surface first: so_analyze(action=read_elf/overview) export/import tables and the Java_* JNI face; when empty, rz_functions falls back to LIEF dynsym and marks source.',
          'Cross-naming: name anonymous functions from string references (so_analyze(action=strings/search)), constants and call relations (rz_xrefs); every name carries its basis and confidence.',
          'Dart/Flutter targets: libapp symbols go through Blutter (search/locate/xref/values); when symbols detach from field names use trace to verify data flow; never hammer rz_functions on an AOT snapshot for business functions (no symbol table, always 0 hits).',
          'Intersect DEX JNI declarations with SO exports to locate bridges (so_analyze(action=jni_bridge)); bridges outrank blind search.',
        ],
        'terms': {
          'anchor': 'Java_ prefixes and string references are the highest-confidence anchors; naming from call position alone is a low-confidence lead.',
          'rename': 'Symbol naming is an analysis artifact (notes/report); this round never edits the ELF symbol table.',
        },
        'output': ['Symbol table (name/address/basis/confidence)', 'Still-unknown functions and suggested probes'],
      },
      _ => {'error': 'unknown_skill', 'availableSkills': skillNames},
    };
    if (payload['error'] == null) {
      payload['id'] = skill;
      payload['activation'] = {
        'mode': 'task_router',
        'status': 'active',
        'trigger': activationHints[skill],
        'rules': activationRules[skill] ?? const <String>[],
      };
    }
    return jsonEncode(payload);
  }
}
