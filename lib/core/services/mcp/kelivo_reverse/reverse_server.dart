part of kelivo_reverse_server;

// ---------------------------------------------------------------------------
// MCP Server Engine
// ---------------------------------------------------------------------------

class KelivoReverseMcpServerEngine implements KelivoInMemoryMcpServerEngine {
  bool _closed = false;

  @override
  Future<dynamic> handleMessage(dynamic message) async {
    if (_closed) return null;
    if (message is List) {
      final out = <dynamic>[];
      for (final m in message) {
        out.add(await _handleSingle(m));
      }
      return out;
    }
    return await _handleSingle(message);
  }

  Future<Map<String, dynamic>> _handleSingle(dynamic raw) async {
    try {
      if (raw is! Map) {
        return _error(null, code: -32600, message: 'Invalid Request');
      }
      final req = raw.cast<String, dynamic>();
      final id = req['id'];
      final method = (req['method'] ?? '').toString();
      final params = (req['params'] is Map)
          ? (req['params'] as Map).cast<String, dynamic>()
          : <String, dynamic>{};

      switch (method) {
        case mcp.McpProtocol.methodInitialize:
          return _ok(id, result: {
            'serverInfo': {'name': '@kelivo/reverse', 'version': '0.1.0'},
            'protocolVersion': mcp.McpProtocol.defaultVersion,
            'capabilities': {
              'tools': {'listChanged': false},
            },
          });

        case mcp.McpProtocol.methodListTools:
          return _ok(id, result: {'tools': _toolDefinitions()});

        case mcp.McpProtocol.methodCallTool:
          final name = (params['name'] ?? '').toString();
          final arguments = (params['arguments'] is Map)
              ? (params['arguments'] as Map).cast<String, dynamic>()
              : <String, dynamic>{};

          // Special handling: meta_info doesn't need payload
          if (name == 'reverse_meta_info') {
            return _ok(id, result: KelivoReverseAnalyzer.metaInfo(arguments));
          }

          // All other tools need APK payload
          KelivoReverseRequestPayload payload;
          try {
            payload = await KelivoReverseRequestPayload.parse(arguments);
          } catch (e) {
            return _ok(id, result: KelivoReverseAnalyzer._err(e.toString()));
          }

          switch (name) {
            case 'reverse_open_apk':
              return _ok(id, result: KelivoReverseAnalyzer.openApk(payload));
            case 'reverse_list_targets':
              return _ok(id, result: KelivoReverseAnalyzer.listTargets(payload));
            case 'reverse_manifest_summary':
              return _ok(id, result: KelivoReverseAnalyzer.manifestSummary(payload));
            case 'reverse_list_native_libs':
              return _ok(id, result: KelivoReverseAnalyzer.listNativeLibs(payload));
            case 'reverse_list_dex_files':
              return _ok(id, result: KelivoReverseAnalyzer.listDexFiles(payload));
            case 'reverse_analyze_so':
              return _ok(id, result: KelivoReverseAnalyzer.analyzeSo(payload, arguments));
            case 'reverse_analyze_dex':
              return _ok(id, result: KelivoReverseAnalyzer.analyzeDex(payload, arguments));
            case 'reverse_find_jni_bridges':
              return _ok(id, result: KelivoReverseAnalyzer.findJniBridges(payload));
            case 'reverse_search_strings':
              return _ok(id, result: KelivoReverseAnalyzer.searchStrings(payload, arguments));
            case 'reverse_report':
              return _ok(id, result: KelivoReverseAnalyzer.report(payload, arguments));
            case 'reverse_quick_triage':
              return _ok(id, result: KelivoReverseAnalyzer.quickTriage(payload, arguments));
            case 'reverse_signature_audit':
              return _ok(id, result: KelivoReverseAnalyzer.signatureAudit(payload));
            case 'reverse_packer_detect':
              return _ok(id, result: KelivoReverseAnalyzer.packerDetect(payload));
            case 'reverse_secret_scan':
              return _ok(id, result: KelivoReverseAnalyzer.secretScan(payload, arguments));
            case 'reverse_component_audit':
              return _ok(id, result: KelivoReverseAnalyzer.componentAudit(payload));
            case 'reverse_diff_apk':
              return _ok(id, result: await KelivoReverseAnalyzer.diffApk(payload, arguments));
            case 'reverse_kill_signature':
              return _ok(id, result: await KelivoReverseAnalyzer.killSignature(payload, arguments));
            case 'reverse_resign_apk':
              return _ok(id, result: await KelivoReverseAnalyzer.resignApk(payload, arguments));
            case 'reverse_inject_dex':
              return _ok(id, result: await KelivoReverseAnalyzer.injectDex(payload, arguments));
            case 'reverse_smali_decompile':
              return _ok(id, result: KelivoReverseAnalyzer.smaliDecompile(payload, arguments));
            case 'reverse_obfuscator_detect':
              return _ok(id, result: KelivoReverseAnalyzer.obfuscatorDetect(payload));
            case 'reverse_resource_extract':
              return _ok(id, result: KelivoReverseAnalyzer.resourceExtract(payload, arguments));
            case 'reverse_string_decrypt':
              return _ok(id, result: KelivoReverseAnalyzer.stringDecrypt(payload, arguments));
            case 'reverse_jni_method_map':
              return _ok(id, result: KelivoReverseAnalyzer.jniMethodMap(payload));
            case 'reverse_dex_string_replace':
              return _ok(id, result: await KelivoReverseAnalyzer.dexStringReplace(payload, arguments));
            case 'reverse_batch_resign':
              return _ok(id, result: await KelivoReverseAnalyzer.batchResign(payload, arguments));
            case 'reverse_unpack_guide':
              return _ok(id, result: KelivoReverseAnalyzer.unpackGuide(payload));
            case 'reverse_apk_rebuild':
              return _ok(id, result: await KelivoReverseAnalyzer.apkRebuild(payload, arguments));
            case 'reverse_apk_sign':
              return _ok(id, result: await KelivoReverseAnalyzer.apkSign(payload, arguments));
            case 'reverse_axml_edit':
              return _ok(id, result: await KelivoReverseAnalyzer.axmlEdit(payload, arguments));
            case 'reverse_manifest_edit':
              return _ok(id, result: await KelivoReverseAnalyzer.manifestEdit(payload, arguments));
            case 'reverse_smali_patch':
              return _ok(id, result: await KelivoReverseAnalyzer.smaliPatch(payload, arguments));
            case 'reverse_zipalign':
              return _ok(id, result: await KelivoReverseAnalyzer.zipalign(payload, arguments));
            case 'reverse_hook_gen':
              return _ok(id, result: await KelivoReverseAnalyzer.hookGen(payload, arguments));
            case 'reverse_dex_merge':
              return _ok(id, result: await KelivoReverseAnalyzer.dexMerge(payload, arguments));
            case 'reverse_anti_analysis':
              return _ok(id, result: await KelivoReverseAnalyzer.antiAnalysis(payload, arguments));
            case 'reverse_callgraph':
              return _ok(id, result: await KelivoReverseAnalyzer.callgraphBuild(payload, arguments));
            case 'reverse_crypto_analyzer':
              return _ok(id, result: await KelivoReverseAnalyzer.cryptoAnalyze(payload, arguments));
            case 'reverse_dataflow':
              return _ok(id, result: await KelivoReverseAnalyzer.dataflowAnalyze(payload, arguments));
            case 'reverse_dex_metadata':
              return _ok(id, result: await KelivoReverseAnalyzer.dexMetadata(payload, arguments));
            case 'reverse_multidex':
              return _ok(id, result: await KelivoReverseAnalyzer.multidexAnalyze(payload, arguments));
            case 'reverse_native_xref':
              return _ok(id, result: await KelivoReverseAnalyzer.nativeXref(payload, arguments));
            case 'reverse_vuln_scan':
              return _ok(id, result: await KelivoReverseAnalyzer.vulnScan(payload, arguments));
            case 'reverse_privacy_audit':
              return _ok(id, result: await KelivoReverseAnalyzer.privacyAudit(payload, arguments));
            case 'reverse_sdk_detect':
              return _ok(id, result: await KelivoReverseAnalyzer.sdkDetect(payload, arguments));
            case 'reverse_endpoint_extract':
              return _ok(id, result: await KelivoReverseAnalyzer.endpointExtract(payload, arguments));
            case 'reverse_social_login':
              return _ok(id, result: await KelivoReverseAnalyzer.socialLoginDetect(payload, arguments));
            case 'reverse_apk_size':
              return _ok(id, result: await KelivoReverseAnalyzer.apkSize(payload, arguments));
            case 'reverse_security_score':
              return _ok(id, result: await KelivoReverseAnalyzer.securityScore(payload, arguments));
            case 'reverse_api_usage':
              return _ok(id, result: await KelivoReverseAnalyzer.apiUsage(payload, arguments));
            case 'reverse_permission_trace':
              return _ok(id, result: await KelivoReverseAnalyzer.permissionTrace(payload, arguments));
            case 'reverse_clone_detect':
              return _ok(id, result: await KelivoReverseAnalyzer.cloneDetect(payload, arguments));
            case 'reverse_network_analysis':
              return _ok(id, result: await KelivoReverseAnalyzer.networkAnalysis(payload, arguments));
            case 'reverse_string_analyze':
              return _ok(id, result: await KelivoReverseAnalyzer.stringAnalyze(payload, arguments));
            case 'reverse_key_scan':
              return _ok(id, result: await KelivoReverseAnalyzer.keyScan(payload, arguments));
            case 'reverse_cert_deep':
              return _ok(id, result: await KelivoReverseAnalyzer.certDeep(payload, arguments));
            case 'reverse_sig_scheme':
              return _ok(id, result: await KelivoReverseAnalyzer.sigScheme(payload, arguments));
            case 'reverse_deobfuscate':
              return _ok(id, result: await KelivoReverseAnalyzer.deobfuscate(payload, arguments));
            case 'reverse_code_analyze':
              return _ok(id, result: await KelivoReverseAnalyzer.codeAnalyze(payload, arguments));
            case 'reverse_resource_analyze':
              return _ok(id, result: await KelivoReverseAnalyzer.resourceAnalyze(payload, arguments));
            case 'reverse_resource_obfuscation':
              return _ok(id, result: await KelivoReverseAnalyzer.resourceObfuscation(payload, arguments));
            case 'reverse_apk_clean':
              return _ok(id, result: await KelivoReverseAnalyzer.apkClean(payload, arguments));
            case 'reverse_component_explore':
              return _ok(id, result: await KelivoReverseAnalyzer.componentExplore(payload, arguments));
            case 'reverse_core_class_locate':
              return _ok(id, result: await KelivoReverseAnalyzer.coreClassLocate(payload, arguments));
            case 'reverse_ad_detect':
              return _ok(id, result: await KelivoReverseAnalyzer.adDetect(payload, arguments));
            case 'reverse_clue_chain':
              return _ok(id, result: await KelivoReverseAnalyzer.clueChain(payload, arguments));
            case 'reverse_dex_lib_analysis':
              return _ok(id, result: await KelivoReverseAnalyzer.dexLibAnalysis(payload, arguments));
            case 'reverse_dex_reflection':
              return _ok(id, result: await KelivoReverseAnalyzer.dexReflection(payload, arguments));
            case 'reverse_dex_resource_ref':
              return _ok(id, result: await KelivoReverseAnalyzer.dexResourceRef(payload, arguments));
            case 'reverse_dex_serialization':
              return _ok(id, result: await KelivoReverseAnalyzer.dexSerialization(payload, arguments));
            case 'reverse_dex_string_pool':
              return _ok(id, result: await KelivoReverseAnalyzer.dexStringPool(payload, arguments));
            case 'reverse_dex_obfuscation_scan':
              return _ok(id, result: await KelivoReverseAnalyzer.dexObfuscationScan(payload, arguments));
            case 'reverse_dex_crypto':
              return _ok(id, result: await KelivoReverseAnalyzer.dexCrypto(payload, arguments));
            case 'reverse_dex_class_density':
              return _ok(id, result: await KelivoReverseAnalyzer.dexClassDensity(payload, arguments));
            case 'reverse_dex_inner_class':
              return _ok(id, result: await KelivoReverseAnalyzer.dexInnerClass(payload, arguments));
            case 'reverse_dex_native':
              return _ok(id, result: await KelivoReverseAnalyzer.dexNative(payload, arguments));
            case 'reverse_dex_const_scan':
              return _ok(id, result: await KelivoReverseAnalyzer.dexConstScan(payload, arguments));
            case 'reverse_dex_inheritance':
              return _ok(id, result: await KelivoReverseAnalyzer.dexInheritance(payload, arguments));
            case 'reverse_dex_method_stats':
              return _ok(id, result: await KelivoReverseAnalyzer.dexMethodStats(payload, arguments));
            case 'reverse_dex_access_flow':
              return _ok(id, result: await KelivoReverseAnalyzer.dexAccessFlow(payload, arguments));
            case 'reverse_dex_permission_audit':
              return _ok(id, result: await KelivoReverseAnalyzer.dexPermissionAudit(payload, arguments));
            case 'reverse_dex_access_pattern':
              return _ok(id, result: await KelivoReverseAnalyzer.dexAccessPattern(payload, arguments));
            case 'reverse_dex_annotation':
              return _ok(id, result: await KelivoReverseAnalyzer.dexAnnotation(payload, arguments));
            case 'reverse_dex_complexity':
              return _ok(id, result: await KelivoReverseAnalyzer.dexComplexity(payload, arguments));
            case 'reverse_dex_control_flow':
              return _ok(id, result: await KelivoReverseAnalyzer.dexControlFlow(payload, arguments));
            case 'reverse_dex_debug_info':
              return _ok(id, result: await KelivoReverseAnalyzer.dexDebugInfo(payload, arguments));
            case 'reverse_dex_exception_flow':
              return _ok(id, result: await KelivoReverseAnalyzer.dexExceptionFlow(payload, arguments));
            case 'reverse_dex_field_analyzer':
              return _ok(id, result: await KelivoReverseAnalyzer.dexFieldAnalyzer(payload, arguments));
            case 'reverse_dex_field_usage':
              return _ok(id, result: await KelivoReverseAnalyzer.dexFieldUsage(payload, arguments));
            case 'reverse_dex_insn_density':
              return _ok(id, result: await KelivoReverseAnalyzer.dexInsnDensity(payload, arguments));
            case 'reverse_dex_instruction_stats':
              return _ok(id, result: await KelivoReverseAnalyzer.dexInstructionStats(payload, arguments));
            case 'reverse_dex_proto_analyzer':
              return _ok(id, result: await KelivoReverseAnalyzer.dexProtoAnalyzer(payload, arguments));
            case 'reverse_dex_proto_matrix':
              return _ok(id, result: await KelivoReverseAnalyzer.dexProtoMatrix(payload, arguments));
            case 'reverse_dex_register_pressure':
              return _ok(id, result: await KelivoReverseAnalyzer.dexRegisterPressure(payload, arguments));
            case 'reverse_dex_type_ref':
              return _ok(id, result: await KelivoReverseAnalyzer.dexTypeRef(payload, arguments));
            case 'reverse_dex_optimizer_patterns':
              return _ok(id, result: await KelivoReverseAnalyzer.dexOptimizerPatterns(payload, arguments));
            case 'reverse_permission_analyze':
              return _ok(id, result: await KelivoReverseAnalyzer.permissionAnalyze(payload, arguments));
            case 'reverse_ad_remove':
              return _ok(id, result: await KelivoReverseAnalyzer.adRemove(payload, arguments));
            case 'reverse_smali_patch_advanced':
              return _ok(id, result: await KelivoReverseAnalyzer.smaliPatchAdvanced(payload, arguments));
            case 'reverse_native_patch':
              return _ok(id, result: await KelivoReverseAnalyzer.nativePatch(payload, arguments));
            case 'reverse_integrity_patch':
              return _ok(id, result: await KelivoReverseAnalyzer.integrityPatch(payload, arguments));
            case 'reverse_resource_patch':
              return _ok(id, result: await KelivoReverseAnalyzer.resourcePatch(payload, arguments));
            case 'reverse_popup_remove':
              return _ok(id, result: await KelivoReverseAnalyzer.popupRemove(payload, arguments));

            // ---- APK file-level operations (移植自 apk_reverse_engine/core/apk_file_ops.py) ----
            case 'reverse_apk_file_list':
              return _ok(id, result: await _ApkFileOps.listFiles(payload!.apkBytes, pattern: arguments['pattern'] as String?) != null
                  ? {'files': _ApkFileOps.listFiles(payload.apkBytes, pattern: arguments['pattern'] as String?)}
                  : {'error': 'No APK data'});
            case 'reverse_apk_file_delete':
              return _ok(id, result: await _ApkFileOps.deleteFiles(payload!.apkBytes, (arguments['files'] as String).split(','), arguments['output'] as String));
            case 'reverse_apk_file_delete_pattern':
              return _ok(id, result: await _ApkFileOps.deleteFilesByPattern(payload!.apkBytes, arguments['pattern'] as String, arguments['output'] as String));
            case 'reverse_apk_file_update':
              return _ok(id, result: await _ApkFileOps.updateFile(payload!.apkBytes, arguments['file'] as String, Uint8List.fromList((arguments['data'] as String).codeUnits), arguments['output'] as String));
            case 'reverse_apk_file_add':
              return _ok(id, result: await _ApkFileOps.addFile(payload!.apkBytes, arguments['file'] as String, Uint8List.fromList((arguments['data'] as String).codeUnits), arguments['output'] as String));
            case 'reverse_apk_file_extract':
              return _ok(id, result: await _ApkFileOps.extractFile(payload!.apkBytes, arguments['file'] as String, arguments['output'] as String));
            case 'reverse_apk_file_extract_all':
              return _ok(id, result: await _ApkFileOps.extractAll(payload!.apkBytes, arguments['output_dir'] as String, pattern: arguments['pattern'] as String?));

            // ---- AXML binary tag operations (移植自 manifest_ops.py) ----
            case 'reverse_axml_find_tags':
              return _ok(id, result: {'tags': _ManifestOps.findTags(payload!.axmlBytes, tagName: arguments['tag'] as String?, attrName: arguments['attr'] as String?, attrValue: arguments['value'] as String?)});
            case 'reverse_axml_remove_tag':
              return _ok(id, result: {'result': 'removed', 'output': (await File(arguments['output'] as String).writeAsBytes(_ManifestOps.removeTags(payload!.axmlBytes, arguments['tag'] as String, arguments['attr'] as String, arguments['value'] as String))).path});
            case 'reverse_axml_replace_attr':
              return _ok(id, result: {'result': 'replaced', 'output': (await File(arguments['output'] as String).writeAsBytes(_ManifestOps.replaceAttrValue(payload!.axmlBytes, arguments['tag'] as String, arguments['attr'] as String, arguments['old'] as String, arguments['new'] as String))).path});
            case 'reverse_axml_remove_component':
              return _ok(id, result: {'result': 'removed', 'output': (await File(arguments['output'] as String).writeAsBytes(_ManifestOps.removeComponent(payload!.axmlBytes, arguments['type'] as String, arguments['class'] as String))).path});
            case 'reverse_axml_replace_launcher':
              return _ok(id, result: {'result': 'replaced', 'output': (await File(arguments['output'] as String).writeAsBytes(_ManifestOps.replaceLauncherActivity(payload!.axmlBytes, arguments['old'] as String, arguments['new'] as String))).path});

            // ---- resources.arsc parser (移植自 resource_parser.py) ----
            case 'reverse_arsc_parse':
              final arscParser = _ArscParser(payload!.arscBytes);
              return _ok(id, result: arscParser.parse());
            case 'reverse_arsc_packages':
              final arscParser = _ArscParser(payload!.arscBytes);
              arscParser.parse();
              return _ok(id, result: {'packages': arscParser.getPackageNames()});
            case 'reverse_arsc_resources':
              final arscParser = _ArscParser(payload!.arscBytes);
              arscParser.parse();
              final res = arscParser.getResources();
              return _ok(id, result: {'count': res.length, 'resources': res.take(500).toList()});
            case 'reverse_arsc_find':
              final arscParser = _ArscParser(payload!.arscBytes);
              arscParser.parse();
              final resId = int.parse(arguments['res_id'] as String, radix: 16);
              return _ok(id, result: arscParser.findResource(resId) ?? {'error': 'not found'});

            // ---- Workspace management (移植自 workspace/manager.py) ----
            case 'reverse_workspace_create':
              return _ok(id, result: await _Workspace.create(arguments['name'] as String, description: arguments['description'] as String? ?? '', apkPath: arguments['apk_path'] as String?));
            case 'reverse_workspace_list':
              return _ok(id, result: {'workspaces': await _Workspace.list()});
            case 'reverse_workspace_open':
              return _ok(id, result: await _Workspace.open(arguments['name'] as String) ?? {'error': 'not found'});
            case 'reverse_workspace_delete':
              return _ok(id, result: {'deleted': await _Workspace.delete(arguments['name'] as String)});
            case 'reverse_workspace_info':
              return _ok(id, result: await _Workspace.info(arguments['name'] as String));
            case 'reverse_workspace_save_result':
              return _ok(id, result: {'path': await _Workspace.saveResult(arguments['name'] as String, arguments['key'] as String, arguments['data'] as Map<String, dynamic>)});
            case 'reverse_workspace_load_result':
              return _ok(id, result: await _Workspace.loadResult(arguments['name'] as String, arguments['key'] as String) ?? {'error': 'not found'});

            // ---- ADB device operations (移植自 device/adb.py) ----
            case 'reverse_adb_devices':
              final adb = _Adb(arguments['device_id'] as String?);
              return _ok(id, result: {'devices': await adb.devices()});
            case 'reverse_adb_info':
              final adb = _Adb(arguments['device_id'] as String?);
              return _ok(id, result: await adb.info());
            case 'reverse_adb_install':
              final adb = _Adb(arguments['device_id'] as String?);
              return _ok(id, result: {'result': await adb.install(arguments['apk_path'] as String, reinstall: arguments['reinstall'] as bool? ?? false)});
            case 'reverse_adb_uninstall':
              final adb = _Adb(arguments['device_id'] as String?);
              return _ok(id, result: {'result': await adb.uninstall(arguments['package'] as String)});
            case 'reverse_adb_launch':
              final adb = _Adb(arguments['device_id'] as String?);
              return _ok(id, result: {'result': await adb.launch(arguments['package'] as String, activity: arguments['activity'] as String?)});
            case 'reverse_adb_force_stop':
              final adb = _Adb(arguments['device_id'] as String?);
              return _ok(id, result: {'result': await adb.forceStop(arguments['package'] as String)});
            case 'reverse_adb_pull':
              final adb = _Adb(arguments['device_id'] as String?);
              return _ok(id, result: {'result': await adb.pull(arguments['remote'] as String, arguments['local'] as String)});
            case 'reverse_adb_push':
              final adb = _Adb(arguments['device_id'] as String?);
              return _ok(id, result: {'result': await adb.push(arguments['local'] as String, arguments['remote'] as String)});
            case 'reverse_adb_screenshot':
              final adb = _Adb(arguments['device_id'] as String?);
              return _ok(id, result: {'path': await adb.screenshot(arguments['output'] as String)});
            case 'reverse_adb_logcat':
              final adb = _Adb(arguments['device_id'] as String?);
              return _ok(id, result: {'log': await adb.logcat(filterSpec: arguments['filter'] as String?, lines: arguments['lines'] as int? ?? 50)});
            case 'reverse_adb_list_packages':
              final adb = _Adb(arguments['device_id'] as String?);
              return _ok(id, result: {'packages': await adb.listPackages(filter: arguments['filter'] as String?)});

            // ---- Native SO advanced patching (移植自 patching/native_patcher.py) ----
            case 'reverse_native_detect_arch':
              return _ok(id, result: {'arch': _NativePatcher.detectArch(payload!.soBytes, arguments['offset'] as int? ?? 0)});
            case 'reverse_native_patch_hex':
              return _ok(id, result: {'result': _NativePatcher.patchHex(payload!.soBytes, arguments['old'] as String, arguments['new'] as String)});
            case 'reverse_native_patch_hex_at':
              return _ok(id, result: {'result': _NativePatcher.patchHexAt(payload!.soBytes, arguments['offset'] as int, arguments['hex'] as String)});
            case 'reverse_native_patch_string':
              return _ok(id, result: {'result': _NativePatcher.patchString(payload!.soBytes, arguments['old'] as String, arguments['new'] as String, maxReplace: arguments['max_replace'] as int? ?? 1)});
            case 'reverse_native_nop_out':
              return _ok(id, result: {'result': _NativePatcher.nopOut(payload!.soBytes, arguments['offset'] as int, arguments['count'] as int, arch: arguments['arch'] as String? ?? 'aarch64')});
            case 'reverse_native_branch_to_ret':
              return _ok(id, result: {'result': _NativePatcher.patchBranchToRet(payload!.soBytes, arguments['offset'] as int, arch: arguments['arch'] as String? ?? 'aarch64')});
            case 'reverse_native_branch_to_mov':
              return _ok(id, result: {'result': _NativePatcher.patchBranchToMovR0(payload!.soBytes, arguments['offset'] as int, arguments['value'] as int? ?? 0, arch: arguments['arch'] as String? ?? 'aarch64')});
            case 'reverse_native_patch_jni':
              return _ok(id, result: {'result': _NativePatcher.patchJniFunction(payload!.soBytes, arguments['old'] as String, arguments['new'] as String)});
            case 'reverse_native_patch_elf_entry':
              return _ok(id, result: {'result': _NativePatcher.patchElfEntrypoint(payload!.soBytes, arguments['entry'] as int)});
            case 'reverse_native_patch_branch':
              return _ok(id, result: {'result': _NativePatcher.patchArmBranch(payload!.soBytes, arguments['offset'] as int, arguments['target'] as int, bl: arguments['bl'] as bool? ?? false, arch: arguments['arch'] as String? ?? 'aarch64')});
            case 'reverse_native_find_pattern':
              return _ok(id, result: {'offsets': _NativePatcher.findPattern(payload!.soBytes, arguments['hex'] as String)});
            case 'reverse_native_find_string':
              return _ok(id, result: {'offsets': _NativePatcher.findStringOffsets(payload!.soBytes, arguments['string'] as String)});

            // ---- Smali advanced patching (移植自 patching/smali_patcher.py) ----
            case 'reverse_smali_insert_method':
              return _ok(id, result: {'result': _SmaliPatcher.insertMethod(arguments['smali'] as String, arguments['method'] as String, beforeLine: arguments['before'] as String?)});
            case 'reverse_smali_remove_method':
              return _ok(id, result: {'result': _SmaliPatcher.removeMethod(arguments['smali'] as String, arguments['name'] as String)});
            case 'reverse_smali_add_log':
              return _ok(id, result: {'result': _SmaliPatcher.addLogInject(arguments['smali'] as String, arguments['name'] as String, tag: arguments['tag'] as String? ?? 'DEBUG', msg: arguments['msg'] as String? ?? 'injected')});
            case 'reverse_smali_add_return':
              return _ok(id, result: {'result': _SmaliPatcher.addReturnInject(arguments['smali'] as String, arguments['name'] as String, returnValue: arguments['value'] as String? ?? '0')});
            case 'reverse_smali_bypass_sig':
              return _ok(id, result: {'result': _SmaliPatcher.bypassSignatureCheck(arguments['smali'] as String)});
            case 'reverse_smali_nop_method':
              return _ok(id, result: {'result': _SmaliPatcher.nopOutMethod(arguments['smali'] as String, arguments['name'] as String)});
            case 'reverse_smali_replace_const':
              return _ok(id, result: {'result': _SmaliPatcher.replaceConstValue(arguments['smali'] as String, arguments['old'] as String, arguments['new'] as String)});
            case 'reverse_smali_nop_invoke':
              return _ok(id, result: {'result': _SmaliPatcher.nopOutInvoke(arguments['smali'] as String, targetClass: arguments['class'] as String?, targetMethod: arguments['method'] as String?)});
            case 'reverse_smali_gen_stub':
              return _ok(id, result: {'result': _SmaliPatcher.generateMethodStub(arguments['return_type'] as String, arguments['name'] as String, (arguments['params'] as String? ?? '').split(','), access: arguments['access'] as String? ?? 'public')});
            case 'reverse_smali_find_methods_by_string':
              return _ok(id, result: {'results': _SmaliPatcher.findMethodsByString(arguments['smali'] as String, arguments['search'] as String)});
            case 'reverse_smali_patch_goto':
              return _ok(id, result: {'result': _SmaliPatcher.patchGotoDirection(arguments['smali'] as String, arguments['old'] as String, arguments['new'] as String)});

            // ---- @kelivo/so tools (delegated) ----
            case 'so_parse_header':
              return _ok(id, result: KelivoSoAnalyzer.header(payload as KelivoSoRequestPayload));
            case 'so_list_sections':
              return _ok(id, result: KelivoSoAnalyzer.sections(payload as KelivoSoRequestPayload));
            case 'so_list_symbols':
              return _ok(id, result: KelivoSoAnalyzer.symbols(payload as KelivoSoRequestPayload));
            case 'so_list_imports':
              return _ok(id, result: KelivoSoAnalyzer.imports(payload as KelivoSoRequestPayload));
            case 'so_list_exports':
              return _ok(id, result: KelivoSoAnalyzer.exports(payload as KelivoSoRequestPayload));
            case 'so_list_dependencies':
              return _ok(id, result: KelivoSoAnalyzer.dependencies(payload as KelivoSoRequestPayload));
            case 'so_list_strings':
              return _ok(id, result: KelivoSoAnalyzer.strings(payload as KelivoSoRequestPayload));
            case 'so_read_hexdump':
              return _ok(id, result: KelivoSoAnalyzer.hexdump(payload as KelivoSoRequestPayload, arguments));
            case 'so_analyze_segments':
              return _ok(id, result: KelivoSoAnalyzer.segments(payload as KelivoSoRequestPayload));
            case 'so_analyze_dynamic':
              return _ok(id, result: KelivoSoAnalyzer.dynamicSection(payload as KelivoSoRequestPayload));
            case 'so_analyze_relocations':
              return _ok(id, result: KelivoSoAnalyzer.relocations(payload as KelivoSoRequestPayload));
            case 'so_search_bytes':
              return _ok(id, result: KelivoSoAnalyzer.searchBytes(payload as KelivoSoRequestPayload, arguments));
            case 'so_section_details':
              return _ok(id, result: KelivoSoAnalyzer.sectionDetails(payload as KelivoSoRequestPayload, arguments));
            case 'so_search_strings':
              return _ok(id, result: KelivoSoAnalyzer.searchStrings(payload as KelivoSoRequestPayload, arguments));
            case 'so_symbol_lookup':
              return _ok(id, result: KelivoSoAnalyzer.symbolLookup(payload as KelivoSoRequestPayload, arguments));
            case 'so_section_search':
              return _ok(id, result: KelivoSoAnalyzer.sectionSearch(payload as KelivoSoRequestPayload, arguments));
            case 'so_addr_to_offset':
              return _ok(id, result: KelivoSoAnalyzer.addrToOffset(payload as KelivoSoRequestPayload, arguments));
            case 'so_offset_to_addr':
              return _ok(id, result: KelivoSoAnalyzer.offsetToAddr(payload as KelivoSoRequestPayload, arguments));
            case 'so_compare_headers':
              return _ok(id, result: await KelivoSoAnalyzer.compareHeaders(arguments));
            case 'so_list_notes':
              return _ok(id, result: KelivoSoAnalyzer.listNotes(payload as KelivoSoRequestPayload));
            case 'so_list_init_array':
              return _ok(id, result: KelivoSoAnalyzer.listInitArray(payload as KelivoSoRequestPayload));
            case 'so_xref_symbol':
              return _ok(id, result: KelivoSoAnalyzer.xrefSymbol(payload as KelivoSoRequestPayload, arguments));
            case 'so_detect_packer':
              return _ok(id, result: KelivoSoAnalyzer.detectPacker(payload as KelivoSoRequestPayload));
            case 'so_disassemble':
              return _ok(id, result: KelivoSoAnalyzer.disassemble(payload as KelivoSoRequestPayload, arguments));
            case 'so_got_plt_analysis':
              return _ok(id, result: KelivoSoAnalyzer.gotPltAnalysis(payload as KelivoSoRequestPayload));
            case 'so_find_anti_debug':
              return _ok(id, result: KelivoSoAnalyzer.findAntiDebug(payload as KelivoSoRequestPayload));

            // ---- @kelivo/dex tools (delegated) ----
            case 'dex_parse_header':
              return _ok(id, result: KelivoDexAnalyzer.header(payload as KelivoDexRequestPayload));
            case 'dex_list_strings':
              return _ok(id, result: KelivoDexAnalyzer.strings(payload as KelivoDexRequestPayload));
            case 'dex_list_types':
              return _ok(id, result: KelivoDexAnalyzer.types(payload as KelivoDexRequestPayload));
            case 'dex_list_classes':
              return _ok(id, result: KelivoDexAnalyzer.classes(payload as KelivoDexRequestPayload));
            case 'dex_list_methods':
              return _ok(id, result: KelivoDexAnalyzer.methods(payload as KelivoDexRequestPayload));
            case 'dex_list_fields':
              return _ok(id, result: KelivoDexAnalyzer.fields(payload as KelivoDexRequestPayload));
            case 'dex_list_annotations':
              return _ok(id, result: KelivoDexAnalyzer.annotations(payload as KelivoDexRequestPayload));
            case 'dex_disassemble_method': {
              final method = (arguments['method'] ?? '').toString();
              return _ok(id, result: KelivoDexAnalyzer.disassembleMethod(payload as KelivoDexRequestPayload, method));
            }
            case 'dex_xref_method': {
              final method = (arguments['method'] ?? '').toString();
              return _ok(id, result: KelivoDexAnalyzer.xrefMethod(payload as KelivoDexRequestPayload, method));
            }
            case 'dex_search_strings': {
              final pattern = (arguments['pattern'] ?? '').toString();
              return _ok(id, result: KelivoDexAnalyzer.searchStrings(payload as KelivoDexRequestPayload, pattern));
            }
            case 'dex_complexity':
              return _ok(id, result: KelivoDexAnalyzer.dexComplexity(payload as KelivoDexRequestPayload));
            case 'dex_inherit_tree':
              return _ok(id, result: KelivoDexAnalyzer.dexInheritTree(payload as KelivoDexRequestPayload));
            case 'dex_annotation_stats':
              return _ok(id, result: KelivoDexAnalyzer.dexAnnotationStats(payload as KelivoDexRequestPayload));
            case 'dex_string_pool':
              return _ok(id, result: KelivoDexAnalyzer.dexStringPool(payload as KelivoDexRequestPayload));
            case 'dex_call_graph':
              return _ok(id, result: KelivoDexAnalyzer.dexCallGraph(payload as KelivoDexRequestPayload));
            case 'dex_field_stats':
              return _ok(id, result: KelivoDexAnalyzer.dexFieldStats(payload as KelivoDexRequestPayload));
            case 'dex_type_ref':
              return _ok(id, result: KelivoDexAnalyzer.dexTypeRef(payload as KelivoDexRequestPayload));
            case 'dex_method_signatures':
              return _ok(id, result: KelivoDexAnalyzer.dexMethodSignatures(payload as KelivoDexRequestPayload));
            case 'dex_const_scan':
              return _ok(id, result: KelivoDexAnalyzer.dexConstScan(payload as KelivoDexRequestPayload));
            case 'dex_reg_pressure':
              return _ok(id, result: KelivoDexAnalyzer.dexRegPressure(payload as KelivoDexRequestPayload));
            case 'dex_exception_flow':
              return _ok(id, result: KelivoDexAnalyzer.dexExceptionFlow(payload as KelivoDexRequestPayload));
            case 'dex_insn_density':
              return _ok(id, result: KelivoDexAnalyzer.dexInsnDensity(payload as KelivoDexRequestPayload));
            case 'dex_debug_info':
              return _ok(id, result: KelivoDexAnalyzer.dexDebugInfo(payload as KelivoDexRequestPayload));
            case 'dex_obfuscation_scan':
              return _ok(id, result: KelivoDexAnalyzer.dexObfuscationScan(payload as KelivoDexRequestPayload));
            case 'dex_ctrl_flow':
              return _ok(id, result: KelivoDexAnalyzer.dexCtrlFlow(payload as KelivoDexRequestPayload));
            case 'dex_native_analysis':
              return _ok(id, result: KelivoDexAnalyzer.dexNativeAnalysis(payload as KelivoDexRequestPayload));
            case 'dex_reflection_scan':
              return _ok(id, result: KelivoDexAnalyzer.dexReflectionScan(payload as KelivoDexRequestPayload));
            case 'dex_serialization_scan':
              return _ok(id, result: KelivoDexAnalyzer.dexSerializationScan(payload as KelivoDexRequestPayload));
            case 'dex_crypto_scan':
              return _ok(id, result: KelivoDexAnalyzer.dexCryptoScan(payload as KelivoDexRequestPayload));
            case 'dex_inner_class':
              return _ok(id, result: KelivoDexAnalyzer.dexInnerClass(payload as KelivoDexRequestPayload));
            case 'dex_proto_analysis':
              return _ok(id, result: KelivoDexAnalyzer.dexProtoAnalysis(payload as KelivoDexRequestPayload));
            case 'dex_resource_ref':
              return _ok(id, result: KelivoDexAnalyzer.dexResourceRef(payload as KelivoDexRequestPayload));
            case 'dex_perm_audit':
              return _ok(id, result: KelivoDexAnalyzer.dexPermAudit(payload as KelivoDexRequestPayload));
            case 'dex_lib_analysis':
              return _ok(id, result: KelivoDexAnalyzer.dexLibAnalysis(payload as KelivoDexRequestPayload));
            case 'dex_access_flow':
              return _ok(id, result: KelivoDexAnalyzer.dexAccessFlow(payload as KelivoDexRequestPayload));
            case 'dex_access_pattern':
              return _ok(id, result: KelivoDexAnalyzer.dexAccessPattern(payload as KelivoDexRequestPayload));
            case 'dex_class_density':
              return _ok(id, result: KelivoDexAnalyzer.dexClassDensity(payload as KelivoDexRequestPayload));
            case 'dex_insn_stats':
              return _ok(id, result: KelivoDexAnalyzer.dexInsnStats(payload as KelivoDexRequestPayload));
            case 'dex_proto_matrix':
              return _ok(id, result: KelivoDexAnalyzer.dexProtoMatrix(payload as KelivoDexRequestPayload));

            // ---- @kelivo/jadx tools (delegated) ----
            case 'jadx_meta_info':
              return _ok(id, result: KelivoJadxAnalyzer.metaInfo(arguments));
            case 'jadx_search_classes':
              return _ok(id, result: KelivoJadxAnalyzer.searchClasses(payload as KelivoJadxRequestPayload, arguments));
            case 'jadx_search_methods':
              return _ok(id, result: KelivoJadxAnalyzer.searchMethods(payload as KelivoJadxRequestPayload, arguments));
            case 'jadx_method_source':
              return _ok(id, result: KelivoJadxAnalyzer.methodSource(payload as KelivoJadxRequestPayload, arguments));
            case 'jadx_class_xrefs':
              return _ok(id, result: KelivoJadxAnalyzer.classXrefs(payload as KelivoJadxRequestPayload, arguments));
            case 'jadx_field_xrefs':
              return _ok(id, result: KelivoJadxAnalyzer.fieldXrefs(payload as KelivoJadxRequestPayload, arguments));
            case 'jadx_manifest':
              return _ok(id, result: KelivoJadxAnalyzer.manifest(payload as KelivoJadxRequestPayload));
            case 'jadx_strings':
              return _ok(id, result: KelivoJadxAnalyzer.strings(payload as KelivoJadxRequestPayload, arguments));
            case 'jadx_rename':
              return _ok(id, result: KelivoJadxAnalyzer.rename(payload as KelivoJadxRequestPayload, arguments));
            case 'jadx_extract_endpoints':
              return _ok(id, result: KelivoJadxAnalyzer.extractEndpoints(payload as KelivoJadxRequestPayload, arguments));
            case 'jadx_identify_sdks':
              return _ok(id, result: KelivoJadxAnalyzer.identifySdks(payload as KelivoJadxRequestPayload, arguments));
            case 'jadx_suspicious_strings':
              return _ok(id, result: KelivoJadxAnalyzer.suspiciousStrings(payload as KelivoJadxRequestPayload, arguments));
            case 'jadx_secret_scan':
              return _ok(id, result: KelivoJadxAnalyzer.secretScan(payload as KelivoJadxRequestPayload, arguments));

            default:
              return _error(id, code: -32101, message: 'Tool not found: $name');
          }

        default:
          if (id == null) return _noop();
          return _error(id, code: -32601, message: 'Method not found: $method');
      }
    } catch (e) {
      return _error(null, code: -32603, message: 'Internal error: $e');
    }
  }

  @override
  void close() {
    _closed = true;
  }

  Map<String, dynamic> _ok(dynamic id, {required Map<String, dynamic> result}) {
    return {'jsonrpc': '2.0', if (id != null) 'id': id, 'result': result};
  }

  Map<String, dynamic> _error(dynamic id, {required int code, required String message}) {
    return {
      'jsonrpc': '2.0',
      if (id != null) 'id': id,
      'error': {'code': code, 'message': message},
    };
  }

  Map<String, dynamic> _noop() => {'jsonrpc': '2.0'};

  List<Map<String, dynamic>> _toolDefinitions() {
    Map<String, dynamic> baseSchema({bool withPath = true, bool withLimit = false, bool withMinLen = false}) {
      final props = <String, dynamic>{};
      if (withPath) {
        props['path'] = {'type': 'string', 'description': '本地 APK 文件的绝对路径。'};
        props['base64'] = {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'};
      }
      if (withLimit) {
        props['limit'] = {'type': 'integer', 'description': '返回条目上限，默认 1000。'};
      }
      if (withMinLen) {
        props['min_length'] = {'type': 'integer', 'description': '最小字符串长度，默认 4。'};
      }
      return {
        'type': 'object',
        'properties': props,
      };
    }

    return [
      {
        'name': 'reverse_meta_info',
        'description': '返回工具说明、推荐工作流和帮助信息。传 action=tools|workflows|describe 获取特定部分，不传则返回全部。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'action': {
              'type': 'string',
              'description': '可选：tools（列出工具）、workflows（推荐工作流）、describe（简介）。',
            },
          },
        },
      },
      {
        'name': 'reverse_open_apk',
        'description': '打开 APK 文件，返回 Manifest 摘要、Native 库和 DEX 文件总览。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_list_targets',
        'description': '枚举 APK 内所有可分析目标（.so 和 .dex 文件）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_manifest_summary',
        'description': '解析 AndroidManifest.xml，提取包名、组件、权限等信息。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_list_native_libs',
        'description': '列出 APK 内所有 .so 本地库文件（含对应 ABI）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_list_dex_files',
        'description': '列出 APK 内所有 DEX 文件。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_analyze_so',
        'description': '对指定 .so 文件做聚合分析（header/import/export/dependency/strings/segments），需指定 so_path（如 lib/arm64-v8a/libnative.so）。内部调用 @kelivo/so。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK 文件。'},
            'so_path': {'type': 'string', 'description': 'APK 内目标 .so 路径，如 lib/arm64-v8a/libnative.so。'},
          },
          'required': ['so_path'],
        },
      },
      {
        'name': 'reverse_analyze_dex',
        'description': '对指定 DEX 文件做聚合分析（header/classes/methods/strings），需指定 dex_path（如 classes.dex）。内部调用 @kelivo/dex。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK 文件。'},
            'dex_path': {'type': 'string', 'description': 'APK 内目标 DEX 路径，如 classes.dex。'},
          },
          'required': ['dex_path'],
        },
      },
      {
        'name': 'reverse_find_jni_bridges',
        'description': '在整个 APK 范围内搜索 JNI 注册线索（JNI_OnLoad、Java_* 导出符号、native 方法声明）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_search_strings',
        'description': '跨目标搜索字符串（Manifest + SO 字符串 + DEX 字符串中的匹配项）。需要 query 参数。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK 文件。'},
            'query': {'type': 'string', 'description': '要搜索的字符串（不区分大小写）。'},
          },
          'required': ['query'],
        },
      },
      {
        'name': 'reverse_report',
        'description': '基于当前 APK 数据生成结构化逆向分析报告（目标概览/Manifest/Native/DEX/JNI/可疑关键词/下一步建议）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_quick_triage',
        'description': '一键快速初筛：返回入口信息、ABI、Native 库、DEX、JNI 线索、可疑关键词和推荐操作。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_signature_audit',
        'description': 'APK 签名审计：检测签名方案（v1/v2/v3），提取 META-INF 证书文件，解析证书 DN 字段（CN/O/OU），列出 .SF 摘要条目。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_packer_detect',
        'description': '加固/加壳检测：基于已知 Packer 指纹（360/Baidu/Tencent/Ali/Bangcle/NetEase/Legu/Ijiami/UPX）和可疑特征（Stub DEX、异常 ELF 结构、反调试库、自定义Section名）进行检测。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_secret_scan',
        'description': '硬编码秘钥扫描：扫描 DEX/SO/Manifest 中的 API Key、Secret、Token、Password、JWT、AWS Key、Firebase Key、Stripe Key、数据库连接串等 16 种模式。支持 limit 参数控制返回上限。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK 文件。'},
            'limit': {'type': 'integer', 'description': '每种文件类型返回的匹配条目上限，默认 50。'},
          },
        },
      },
      {
        'name': 'reverse_component_audit',
        'description': '导出组件安全审计：分析 AndroidManifest 中所有 activity/service/receiver/provider 的 exported 状态、intent-filter、permission 保护情况，标记潜在风险组件。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_diff_apk',
        'description': 'APK 深度对比分析（版本演进审计）：对比两个 APK 之间的 Activities/Services/Receivers/Providers/Permissions 变化差异（ADDED/REMOVED/UNCHANGED）、文件级增量/删减、签名方案变更、ABI 差异、DEX 文件变化。支持 compare_path 或 compare_base64 参数指定对比目标。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 APK 文件路径（当前版本）。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的当前版本 APK。'},
            'compare_path': {'type': 'string', 'description': '对比目标 APK 的本地文件路径（如上一版本）。'},
            'compare_base64': {'type': 'string', 'description': '可选：Base64 编码的对比目标 APK。'},
          },
        },
      },
      {
        'name': 'reverse_kill_signature',
        'description': '过签工具：提取 APK 原始签名证书 → 删除 META-INF 签名文件（去除 v1 签名校验）→ 将原始签名以 Base64 注入 assets/kelivo_original_sign → 生成 PmsHook smali 模板代码（Application 子类，通过反射 hook PackageManager 返回原始签名）。输出处理后的 APK + hook smali 文件。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '输入 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK。'},
            'output': {'type': 'string', 'description': '输出处理后 APK 的保存路径（必填）。'},
          },
          'required': ['output'],
        },
      },
      {
        'name': 'reverse_resign_apk',
        'description': '清除旧签名并重新生成 MANIFEST.MF（SHA-256 摘要）。输出 APK 需配合 apksigner 或 jarsigner 完成最终签名。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '输入 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK。'},
            'output': {'type': 'string', 'description': '输出 APK 的保存路径（必填）。'},
          },
          'required': ['output'],
        },
      },
      {
        'name': 'reverse_inject_dex',
        'description': '将外部 DEX 文件注入 APK 作为 classesN.dex（自动确定 N 编号）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '输入 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK。'},
            'dex_path': {'type': 'string', 'description': '要注入的 DEX 文件路径（必填）。'},
            'output': {'type': 'string', 'description': '输出 APK 的保存路径（必填）。'},
          },
          'required': ['dex_path', 'output'],
        },
      },
      {
        'name': 'reverse_smali_decompile',
        'description': '反编译指定DEX为Smali代码，支持类名过滤。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK路径'},
            'base64': {'type': 'string', 'description': 'APK Base64'},
            'dex_path': {'type': 'string', 'description': '目标DEX路径'},
            'class_filter': {'type': 'string', 'description': '类名正则过滤'},
          },
          'required': ['dex_path'],
        },
      },
      {
        'name': 'reverse_obfuscator_detect',
        'description': '检测混淆/加固方案，支持主流360/梆梆/爱加密等。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_resource_extract',
        'description': '提取APK内匹配的资源文件到指定目录，支持文件名正则。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK路径'},
            'base64': {'type': 'string', 'description': 'APK Base64'},
            'pattern': {'type': 'string', 'description': '文件名匹配正则'},
            'output_dir': {'type': 'string', 'description': '输出目录'},
          },
          'required': ['output_dir'],
        },
      },
      {
        'name': 'reverse_string_decrypt',
        'description': '自动解密DEX/SO中常见加密方案的字符串常量。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK路径'},
            'base64': {'type': 'string', 'description': 'APK Base64'},
            'target': {'type': 'string', 'description': 'dex|so|all，默认all'},
          },
        },
      },
      {
        'name': 'reverse_jni_method_map',
        'description': '构建JNI方法映射表，匹配Java native方法与Native函数。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_string_replace',
        'description': 'DEX字符串批量替换：在指定DEX文件中查找匹配的字符串并替换为新值（要求等长替换以保持偏移），输出修改后的APK。常用于修改URL、API端点、包名等硬编码字符串。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
            'dex_path': {'type': 'string', 'description': '目标DEX路径，默认classes.dex。'},
            'find': {'type': 'string', 'description': '要查找的字符串（必填）。'},
            'replace': {'type': 'string', 'description': '替换为的字符串，必须与find等长（必填）。'},
            'output': {'type': 'string', 'description': '输出APK保存路径（必填）。'},
          },
          'required': ['find', 'replace', 'output'],
        },
      },
      {
        'name': 'reverse_batch_resign',
        'description': 'APK批量重签名：清除旧签名文件 → 生成新MANIFEST.MF（SHA-256摘要）→ 可选自动调用apksigner签名。支持自定义keystore路径、密码、别名和签名方案（v1/v2）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
            'output': {'type': 'string', 'description': '输出APK保存路径（必填）。'},
            'keystore_path': {'type': 'string', 'description': '可选：keystore文件路径。提供则自动签名，否则仅生成未签名APK。'},
            'keystore_pass': {'type': 'string', 'description': 'keystore密码，默认android。'},
            'key_alias': {'type': 'string', 'description': '密钥别名，默认androiddebugkey。'},
            'key_pass': {'type': 'string', 'description': '密钥密码，默认android。'},
            'sign_v2': {'type': 'boolean', 'description': '是否启用v2签名，默认true。'},
          },
          'required': ['output'],
        },
      },
      {
        'name': 'reverse_unpack_guide',
        'description': '一键脱壳向导：自动检测APK加固方案（360/腾讯乐固/梆梆/爱加密/阿里/百度/网易/UPX等）→ 推荐最适合的脱壳方法（FRIDA-DEXDump/BlackDex/Xposed Hook）→ 输出详细操作步骤和加固方案特定绕过技巧。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_apk_rebuild',
        'description': 'APK 解码/回编/合并/去混淆工作流：action=decode 将 APK 拆分为 AI 可读写的工作目录（manifest.json + resources.json + smali/classes.txt + assets/）；action=build 将解码目录回编为 APK（zip 打包，跳过辅助文件）；action=merge 合并多个解码目录/APK 条目到单一 APK；action=refactor 基于 @kelivo/dex 输出混淆重命名建议（只读）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
            'action': {'type': 'string', 'description': 'decode|build|merge|refactor，默认build。'},
            'output_dir': {'type': 'string', 'description': 'action=decode 时的输出目录。'},
            'input_dir': {'type': 'string', 'description': 'action=build 时的解码目录（缺省用最近一次 decode 目录）。'},
            'inputs': {'type': 'array', 'items': {'type': 'string'}, 'description': 'action=merge 时的输入目录/APK列表。'},
            'output': {'type': 'string', 'description': 'build/merge 时的输出APK路径。'},
          },
        },
      },
      {
        'name': 'reverse_apk_sign',
        'description': '纯 Dart APK 签名：生成 RSA-2048 自签证书（会话内缓存），写入 v1（JAR：MANIFEST.MF/CERT.SF/CERT.RSA，SHA-256）与 v2（APK Signing Block）签名。输出后可配合 zipalign 对齐。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
            'output': {'type': 'string', 'description': '输出APK保存路径（必填）。'},
          },
          'required': ['output'],
        },
      },
      {
        'name': 'reverse_axml_edit',
        'description': 'AXML 编码/替换：action=encode 将文本 XML 编译为二进制 AXML（纯 Dart，无需 aapt2）；action=replace 替换 APK 内的 AndroidManifest.xml 并重新打包。实现修改 Manifest 后回写闭环。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径（action=replace时需要）。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
            'action': {'type': 'string', 'description': 'encode|replace，默认encode。'},
            'xml': {'type': 'string', 'description': '文本 XML 内容（必填）。'},
            'output': {'type': 'string', 'description': '输出路径（encode=AXML文件路径，replace=输出APK路径）。'},
          },
          'required': ['xml'],
        },
      },
      {
        'name': 'reverse_manifest_edit',
        'description': 'Manifest 属性编辑：解码 APK 中的 AndroidManifest.xml → 修改属性（debuggable/allowBackup/testOnly/extractNativeLibs/usesCleartextTraffic等）→ 设置组件 exported → 重新编码为二进制 AXML → 替换回 APK。支持 preview 模式（不传 output 则返回修改后的文本 XML）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
            'debuggable': {'type': 'string', 'description': 'true|false。'},
            'allowBackup': {'type': 'string', 'description': 'true|false。'},
            'testOnly': {'type': 'string', 'description': 'true|false。'},
            'extractNativeLibs': {'type': 'string', 'description': 'true|false。'},
            'hasCode': {'type': 'string', 'description': 'true|false。'},
            'usesCleartextTraffic': {'type': 'string', 'description': 'true|false。'},
            'networkSecurityConfig': {'type': 'string', 'description': '网络安全配置引用路径。'},
            'set_exported_component': {'type': 'string', 'description': '组件名（如 .MainActivity）。'},
            'set_exported_value': {'type': 'string', 'description': 'true|false。'},
            'output': {'type': 'string', 'description': '输出APK路径。不传则返回预览文本。'},
          },
        },
      },
      {
        'name': 'reverse_smali_patch',
        'description': 'Smali 指令级修补：action=find_replace 搜索匹配并预览替换；action=bypass_signature 签名校验绕过模式；action=inject_log 方法注入 Log.d；action=nop_out 方法体 NOP 填充；action=method_stub 生成方法存根代码。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
            'action': {'type': 'string', 'description': 'find_replace|bypass_signature|inject_log|nop_out|method_stub，默认find_replace。'},
            'dex_path': {'type': 'string', 'description': '目标DEX路径，默认classes.dex。'},
            'find': {'type': 'string', 'description': 'action=find_replace时的查找字符串。'},
            'replace': {'type': 'string', 'description': 'action=find_replace时的替换字符串。'},
            'method': {'type': 'string', 'description': '目标方法名（inject_log/nop_out/method_stub时必填）。'},
            'tag': {'type': 'string', 'description': 'Log tag，默认DEBUG。'},
            'msg': {'type': 'string', 'description': 'Log 消息，默认injected。'},
            'return_type': {'type': 'string', 'description': '返回类型（V/Z/I/J/D/L...），默认V。'},
            'return_value': {'type': 'string', 'description': '返回值，默认0x0。'},
            'patch_type': {'type': 'string', 'description': 'smali补丁类型：bypass_return|log_only|nop。'},
          },
        },
      },
      {
        'name': 'reverse_zipalign',
        'description': 'APK 4 字节对齐：重新打包 APK 使未压缩条目 4 字节对齐（内存映射优化）。⚠️ Dart archive 库不原生支持显式 zipalign，建议生产环境配合 Android SDK zipalign 使用。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
            'output': {'type': 'string', 'description': '输出APK保存路径（必填）。'},
            'alignment': {'type': 'integer', 'description': '对齐字节数，默认4。'},
          },
          'required': ['output'],
        },
      },
      {
        'name': 'reverse_hook_gen',
        'description': 'Hook 脚本生成器：format=frida 生成 Frida JS hook 脚本（支持 root/debug/ssl/signature/emulator 绕过选项）；format=xposed 生成 Xposed/LSPosed Java 模块代码；format=smali 生成 Smali 补丁片段（bypass_return/log_only/nop）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'target_class': {'type': 'string', 'description': '目标类名（Lcom/example/Class; 或 com.example.Class 格式，必填）。'},
            'target_method': {'type': 'string', 'description': '目标方法名。不传则 hook 所有方法。'},
            'format': {'type': 'string', 'description': 'frida|xposed|smali，默认frida。'},
            'verbose': {'type': 'boolean', 'description': '输出详细日志。'},
            'trace_args': {'type': 'boolean', 'description': '追踪参数（仅frida）。'},
            'trace_return': {'type': 'boolean', 'description': '追踪返回值（仅frida）。'},
            'bypass': {'type': 'object', 'description': '绕过选项 {root:true, debug:true, ssl:true, signature:true, emulator:true}。'},
            'patch_type': {'type': 'string', 'description': 'smali补丁类型：bypass_return|log_only|nop。'},
            'return_value': {'type': 'string', 'description': '返回值，默认0x0。'},
          },
          'required': ['target_class'],
        },
      },
      {
        'name': 'reverse_dex_merge',
        'description': '多 DEX 合并：将 APK 内的多个 classes*.dex 合并为单一 classes.dex（简单字节拼接），保留非 DEX 条目，输出合并后的 APK。⚠️ 简单拼接不等同于正确的 dex-merger，生产环境建议使用专业工具。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
            'output': {'type': 'string', 'description': '输出APK保存路径（必填）。'},
          },
          'required': ['output'],
        },
      },
      {
        'name': 'reverse_anti_analysis',
        'description': '反分析检测：扫描 APK 中 DEX/SO 文本，检测反调试、反Root、反模拟器、完整性校验、反Hook（Xposed/Frida/Substrate）、反VPN/代理、反虚拟化/多开等 7 大类反分析措施，输出风险等级评估。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
          },
        },
      },
      {
        'name': 'reverse_callgraph',
        'description': 'DEX 调用图构建：从 DEX 类列表构建方法间引用邻接图，支持正向(callees)/反向(callers)可达性查询、热点方法排名（被引用最多的类）、节点/边统计。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
            'dex_path': {'type': 'string', 'description': '目标DEX路径，默认classes.dex。'},
            'target_class': {'type': 'string', 'description': '目标类名（查 callers/callees 时必填）。'},
            'target_method': {'type': 'string', 'description': '目标方法名。'},
            'direction': {'type': 'string', 'description': 'callers|callees，默认callers。'},
          },
        },
      },
      {
        'name': 'reverse_crypto_analyzer',
        'description': '加密深度分析：扫描 DEX/SO 文本检测加密算法（AES/DES/RSA/ECC/ChaCha20/RC4/Blowfish）、加密模式（ECB/CBC/CTR/GCM）、哈希算法（MD5/SHA1/SHA256/SHA512/HMAC/PBKDF2）、弱加密检测、密钥管理评估，输出风险等级。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
          },
        },
      },
      {
        'name': 'reverse_dataflow',
        'description': 'DEX 数据流分析：action=taint 扫描污点来源（Intent/网络/电话/WebView/文件）与危险汇点（exec/网络输出/文件写入/SQL/反射/动态加载），评估 source→sink 潜在流；action=constants 扫描 URL/Base64/API密钥等常量。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
            'dex_path': {'type': 'string', 'description': '目标DEX路径，默认classes.dex。'},
            'target_class': {'type': 'string', 'description': '目标类名。'},
            'action': {'type': 'string', 'description': 'taint|constants，默认taint。'},
          },
        },
      },
      {
        'name': 'reverse_dex_metadata',
        'description': 'DEX 元数据分析：检测 Hidden API 使用（internal/dalvik/sun.misc/静默安装/强制停止）、反射模式（Class.forName/getDeclaredMethod/DexClassLoader）、注解处理器框架（ButterKnife/Dagger/Room/Realm/EventBus）、序列化框架（Parcelable/Serializable/Gson/Moshi/Jackson/FastJson/Kotlinx）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
            'dex_path': {'type': 'string', 'description': '目标DEX路径，默认classes.dex。'},
          },
        },
      },
      {
        'name': 'reverse_multidex',
        'description': '多 DEX 关联分析：统计各 DEX 类分布、检测重复类（同包名出现在多个 DEX）、分析跨 DEX 引用关系（DEX A 引用 DEX B 中的类）、识别主 DEX。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
          },
        },
      },
      {
        'name': 'reverse_native_xref',
        'description': 'Native-Java 交叉引用：从 DEX 提取 native 方法声明并推测 JNI 函数名，从 SO 提取 JNI 导出符号，交叉匹配 DEX native 方法与 SO 符号，检测 JNI_OnLoad 动态注册。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64编码的APK。'},
          },
        },
      },
      {
        'name': 'reverse_vuln_scan',
        'description': '安全漏洞扫描：11 类漏洞模式静态扫描（组件暴露/Intent注入/SSL/TLS绕过/WebView安全/SQLite注入/文件模式/隐式Intent/动态代码加载/不安全随机数/硬编码凭据/敏感API调用），扫描 DEX 字符串池 + Manifest + 方法体 invoke 指令。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_privacy_audit',
        'description': '隐私风险评估：13 类数据收集行为检测（位置/联系人/短信/通话/相机/麦克风/存储/设备标识/账户/日历/传感器/蓝牙/网络标识）+ 数据外传行为检测 + 风险评分与建议。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_sdk_detect',
        'description': '第三方 SDK/Tracker 检测：从 DEX 类名识别 80+ 常见 SDK（广告/追踪/分析/推送/支付/社交/地图/加固/网络框架），评估隐私风险等级，统计追踪器数量。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_endpoint_extract',
        'description': '网络端点深度提取：从 DEX/SO 字符串中提取所有 URL/域名/IP/端口/API路径/云服务域名/CDN域名，分类公网/内网IP，检测不安全 HTTP URL。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_social_login',
        'description': '社交登录检测：9 平台第三方登录集成检测（微信/QQ/GitHub/支付宝/微博/Google/Facebook/Apple/Twitter），基于 SDK 特征/代码模式/字符串特征/URL 模式多维检测，输出置信度评分。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_apk_size',
        'description': 'APK 体积分析：按类别拆解大小组成（DEX/Native Lib/Resources/Assets/META-INF等），统计压缩比，Top 20 大文件，Native Lib 按 ABI 分组，优化建议。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_security_score',
        'description': '综合安全评分：多维安全风险评估（debuggable/allowBackup/cleartextTraffic/导出组件/SSL绕过/WebView风险/命令执行/硬编码凭据/动态加载/反射），输出风险等级与 CWE 映射。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_api_usage',
        'description': 'API 调用统计分析：13 类 API 使用频率统计（网络通信/数据存储/设备标识/位置服务/加密安全/UI视图/日志调试/反射/序列化/线程异步/JNI Native/多媒体/服务组件），反射模式检测。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_permission_trace',
        'description': '权限使用追溯：将 Manifest 声明权限与 DEX 中实际 API 调用交叉匹配，输出已使用/未使用/缺失权限三类列表，检测危险权限使用模式，评估风险评分。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_clone_detect',
        'description': 'DEX 方法克隆检测：基于指令指纹检测重复/相似方法，精确克隆组 + 相似方法组，计算克隆率与冗余字节数，支持跨 DEX 检测。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_network_analysis',
        'description': '网络行为深度分析：协议检测（不安全 HTTP/FTP）+ SSL/TLS 配置（Pinning/不安全证书）+ WebSocket 检测 + 自定义协议/深层链接 + 网络安全配置评估 + 云平台分类 + 端口分析 + 综合风险评估。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_string_analyze',
        'description': 'DEX 字符串深度分析：13 类分类统计（URL/IP/Email/UUID/Base64/Hex/Java类名/包名等）+ 敏感信息检测（API密钥/Token/密码/私钥）+ 内网IP检测 + URL提取与域名统计。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_key_scan',
        'description': '密钥/凭证深度扫描：21 种密钥模式检测（Google/AWS/Stripe/GitHub/OpenAI/PEM私钥/SSH/JWT/数据库连接串/云服务密钥/加密密钥等）+ 弱加密算法检测（MD5/SHA1/DES/RC4/ECB）+ 风险评分。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_cert_deep',
        'description': '证书深度分析：调试证书检测（Android Debug）+ CA 签发者验证 + 自签名/未知 CA 检测 + 签名算法识别（RSA/DSA/ECDSA）+ V1/V2/V3 签名方案检测 + 安全等级评估 + 建议。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_sig_scheme',
        'description': 'APK 签名方案全面检测：V1 (JAR/META-INF) + V2 (APK Signing Block) + V3 (密钥轮换) + V4 (.idsig) + 签名算法识别 + 安全等级评估 + 兼容性建议。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_deobfuscate',
        'description': '自动化去混淆引擎：XOR 密钥提取 + byte 数组提取与解密 + Base64/Hex 字符串还原 + 控制流平坦化检测（OLLVM）+ 算术混淆检测 + 混淆类名识别与统计。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_code_analyze',
        'description': '深度代码分析：URL/IP/Email/域名提取 + 类引用统计 + 10 类敏感 API 检测（位置/相机/联系人/短信/电话/网络/加密/WebView/反射/动态代码）+ 危险 API 检测（命令执行/弱加密/SQL/日志）+ API 密钥扫描。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_resource_analyze',
        'description': 'APK 资源分析：按类别拆解大小组成（DEX/Native/Resources/Assets/META-INF/Fonts/Audio/Video等）+ 压缩率统计 + Top 20 大文件 + 潜在重复文件检测 + 图片资源分析。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_resource_obfuscation',
        'description': '资源混淆检测：资源文件命名混淆分析（单字符/混淆模式/有意义命名）+ 按资源类型分组统计 + 混淆率计算 + 综合评分与等级。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_apk_clean',
        'description': 'APK 清理分析：调试/测试文件检测 + 备份文件检测 + META-INF 签名文件 + 大文件排名(>1MB) + 重复文件检测 + 清理建议 + 浪费比例与优化等级评估。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_component_explore',
        'description': 'APK 组件浏览器：四大组件（Activity/Service/Receiver/Provider）提取与导出状态分析 + Intent Filter 解析 + Deep Link 提取 + 权限门控检测 + 安全问题（未授权导出/ContentProvider暴露）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_core_class_locate',
        'description': '核心类定位器：多维度启发式评分（命名模式/包名深度/类名特征）自动定位 DEX 中的核心入口类（Application/MainActivity/Core/Manager 等），过滤 SDK 类，输出 Top 20 候选类。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_ad_detect',
        'description': '广告检测：23 个广告 SDK 识别（AdMob/Facebook/AppLovin/Unity/Vungle/ironSource/Chartboost/Pangle/Mintegral 等）+ 代码模式检测（AdView/Interstitial/Rewarded/Native/Banner）+ 广告域名检测 + 综合评分与等级。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_clue_chain',
        'description': '跨模块线索串联分析：8 个子分析器交叉关联 Manifest/DEX/SO/Assets/权限（WebView套壳/JS Bridge/BeanShell/SO功能/权限滥用/动态加载/可疑资源/网络地址/潜在密钥），输出综合风险评分与结论。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_lib_analysis',
        'description': 'DEX 第三方库分析：从 DEX 类名识别 40+ 常见第三方库（广告/网络/图片/数据库/事件总线/推送/社交/地图/加密等），统计库类占比，计算膨胀评分与等级。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_reflection',
        'description': 'DEX 反射/动态加载分析：检测反射模式（Class.forName/getMethod/invoke/setAccessible 等）和动态加载（DexClassLoader/PathClassLoader/MultiDex），评估风险等级。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_resource_ref',
        'description': 'DEX 资源引用分析：统计 R$layout/R$id/R$drawable 等 11 类资源引用计数，检测硬编码 Resource ID（0x7f*），评估资源混淆程度。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_serialization',
        'description': 'DEX 序列化/持久化分析：检测 Serializable/Parcelable 使用，统计持久化模式（SharedPreferences/SQLite/文件IO/ObjectOutputStream），评估数据持久化风险。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_string_pool',
        'description': 'DEX 字符串常量池深度分析：字符串总数/字节数/平均长度统计 + 长度分布 + 10 类敏感模式检测（URL/IP/Email/JWT/Base64/Hex/Java类名/SQL/权限/ContentProvider）+ 重复字符串 Top 15。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_obfuscation_scan',
        'description': 'DEX 混淆特征扫描：类名混淆模式检测（短名/单字符路径）+ 加固指纹匹配（360/腾讯/梆梆/爱加密等 14 种）+ 混淆率计算与综合评分。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_crypto',
        'description': 'DEX 加密特征分析：检测加密算法（AES/RSA/DES/ChaCha20/SM2/SM4）、哈希算法（MD5/SHA/HMAC/PBKDF2）、编码方式（Base64/Hex）、弱加密算法告警，输出安全评分。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_class_density',
        'description': 'DEX 类结构密度分析：统计类/包总数，估算接口/抽象类数量，按包分组 Top 20 类分布，评估代码结构复杂度。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_inner_class',
        'description': 'DEX 内部类/匿名类分析：统计顶层类/内部类/匿名类/Lambda，\$ 嵌套层级分布，计算代码复杂度评分。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_native',
        'description': 'DEX Native 方法分析：检测库加载（System.loadLibrary/load）、JNI 模式（RegisterNatives/JNI_OnLoad/JNIEnv）、native 关键字计数、SO 文件数，评估 Native 混合程度。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_const_scan',
        'description': 'DEX 常量池扫描：5 类数值常量（IPv4/版本号/手机号/Hex/LargeNum）+ 4 类关键词常量（API密钥/加密密钥/设备标识/服务器地址），唯一值去重统计。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_inheritance',
        'description': 'DEX 继承图分析：估算接口/抽象类/终态类数量，统计根类（非内部类），评估类层次结构。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_method_stats',
        'description': 'DEX 方法签名统计：11 类方法模式检测（getter/setter/构造函数/回调/异步/网络/IO/加密/反射/数据库），方法文本长度统计。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_access_flow',
        'description': 'DEX 访问权限流分析：6 类敏感方法模式（加密/反射/命令执行/文件IO/网络/数据库）+ 访问修饰符统计（public/private/protected/native）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_permission_audit',
        'description': 'DEX 权限审计：12 类权限-API 映射检测（相机/录音/位置/联系人/短信/电话/存储/网络等）+ 4 种危险权限组合告警（监控/短信拦截/位置追踪/隐私窃取）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_access_pattern',
        'description': 'DEX 访问控制模式分析：类/方法/字段可见性分布（public/private/protected/package）+ 修饰符统计（static/final/abstract/synchronized/native/volatile/transient）+ 组合模式 Top 15 + 公开 API 方法列表 + 暴露字段检测 + 封装质量评分与等级。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_annotation',
        'description': 'DEX 注解深度分析：16 类已知注解识别（AndroidX/Android/Kotlin/Retrofit/Dagger/ButterKnife/Gson/Glide/RxJava 等）+ 7 种 Dalvik 内部注解（EnclosingClass/InnerClass/Signature 等）+ 4 类空安全注解（Nullable/NonNull/NotNull/Nonnull）+ 注解覆盖率统计。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_complexity',
        'description': 'DEX 代码复杂度分析：分支指令统计（if-eqz/if-eq/goto/switch/throw 等 10 类）+ try-catch 块计数 + synchronized 计数 + 圈复杂度评分与等级（高/中/低/简单）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_control_flow',
        'description': 'DEX 控制流分析：方法数估算 + invoke/return/goto/if/switch 指令统计 + 控制流复杂度评分与等级。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_debug_info',
        'description': 'DEX 调试信息分析：源文件提取（.java 文件名）+ 调试信息保留检测 + 行号信息检测 + 可读性评分（高/中/低）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_exception_flow',
        'description': 'DEX 异常处理流分析：20 类已知异常类型检测（NullPointerException/IOException/JSONException 等）+ try/catch/throw 统计 + 防御性编程评分与等级。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_field_analyzer',
        'description': 'DEX 字段分析：7 类敏感字段名检测（credential/financial/personal/crypto/network/device/config）+ 字段修饰符统计（static/final/volatile/transient）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_field_usage',
        'description': 'DEX 字段使用分析：iget/iput/sget/sput 指令计数 + 读/写总量 + 读写比（R/W ratio）计算。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_insn_density',
        'description': 'DEX 指令密度分析：多 DEX 文件逐个统计方法数/文件大小 + 整体方法密度（methods/KB）计算。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_instruction_stats',
        'description': 'DEX 指令统计：14 类指令分类计数（const/move/invoke/return/if/goto/new/iget/iput/sget/sput/arith/throw/monitor）+ 总指令数。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_proto_analyzer',
        'description': 'DEX 方法原型分析：8 类返回值分布（void/boolean/int/long/String/Object/array/other）+ 参数统计（有参/无参/单参）+ 方法重载 Top 15 + 复杂度评分。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_proto_matrix',
        'description': 'DEX 原型矩阵分析：7 类短签名模式（V()/Z()/I()/V(I)/V(L)/I(L)/V(LL)）+ 12 类参数类型频率（String/Context/Bundle/Intent/View/Activity/Handler/Callback/Listener/List/Map/Throwable）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_register_pressure',
        'description': 'DEX 寄存器压力分析：7 档寄存器大小分布（0-4/5-8/9-12/13-16/17-24/25-32/33+）+ 高压力方法检测（≥16/≥32）+ 平均寄存器/outs 大小 + 压力评分与等级。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_type_ref',
        'description': 'DEX 类型引用分析：全量类名提取 + 应用类/系统类分类（18 种系统前缀过滤）+ 应用类引用计数 Top 20（Hub 类）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_dex_optimizer_patterns',
        'description': 'DEX 优化模式检测：常量折叠检测 + 死代码检测（NOP/Goto）+ 寄存器分配分析 + 内联模式检测（尾调用）+ 代码膨胀检测（switch 密度）+ 窥孔优化模式（冗余 move/常量比较）+ 循环不变量检测 + 综合优化评分与等级。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_permission_analyze',
        'description': '权限综合分析：权限分类（危险/正常/签名/自定义）+ 11 种风险组合检测（位置追踪/隐私窃取/恶意扣费/监控/短信拦截等）+ 广告权限关联 + GDPR/COPPA/CCPA 合规检查 + 过度申请检测 + 隐私评分与等级。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_ad_remove',
        'description': '广告移除引擎：检测 31 种广告 SDK（腾讯/快手/穿山甲/百度/头条/Sigmob/谷歌/米盟/Unity/Mintegral/Vungle/Chartboost/AppLovin/IronSource/InMobi/AdColony/Facebook/华为/OPPO/vivo/StartApp/InMobi/Smaato/Amazon/Yandex/myTarget/AnyThink/TopOn/Fyber/MBridge/BidMachine/PubNative/Pollfish）+ 广告方法统计（loadAd/showAd/requestAd 等 15 种）+ 广告 URL 统计（17 种域名）+ AdMob ID 检测 + VIP/Pro 方法检测（13 种）+ 广告 assets 文件检测。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_smali_patch_advanced',
        'description': 'Smali 高级修补器：签名校验检测（checkSignatures/getPackageInfo/getInstallerPackageName）+ Root/模拟器检测 + Debug 检测 + 广告方法 NOP/return-void 候选 + const 值替换候选（0x1↔0x0）+ goto 跳转统计 + invoke 统计 + 补丁操作能力列表。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_native_patch',
        'description': '原生 SO 补丁工具：SO 文件枚举 + 指令集架构检测（arm64-v8a/armeabi-v7a/x86/x86_64）+ ELF 分析（32/64位/大小端/类型/入口点）+ 补丁能力（Hex 搜索替换/NOP 填充/Branch→RET/Branch→MOV R0+RET/JNI 函数名/ELF 入口点/条件分支/断点插入）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_integrity_patch',
        'description': '完整性校验绕过：签名校验检测（checkSignatures/getPackageInfo/getInstallerPackageName/signatures.equals/verifySignature/PackageManager）+ Root 检测（isRooted/checkRoot//su/Superuser/magisk/busybox）+ 模拟器检测（isEmulator/qemu/goldfish/genymotion）+ 反调试（isDebuggerConnected/waitForDebugger/ptrace）+ 完整性校验（checksum/MD5/SHA/CRC/hashcode/tamper/verify）+ 综合保护等级评估。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_resource_patch',
        'description': '资源文件补丁：ARSC 文件分析 + XML 文件枚举 + 图片资源统计（PNG/JPG/GIF/WEBP/BMP，数量与大小）+ Assets 文件分析 + 包名检测（从 ARSC UTF-16LE 解码）+ 补丁操作（ARSC 字符串替换/包名修改/XML 替换/图片二进制补丁/Asset 字符串替换）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_popup_remove',
        'description': '弹窗去除器：腾讯分享弹窗 SDK 检测（SETUP_LAUNCHER_ACTIVITY/SdkInitProvider/tauth/connect/setup_sdk/TaskActivity，6 项评分）+ 通用弹窗检测（showDialog/AlertDialog/PopupWindow/DialogFragment/rate_app/update_dialog）+ 弹窗 assets 文件检测 + Manifest 组件统计 + 去除操作（删除 manifest 组件/删除 assets/替换启动 Activity/删除 DEX）。',
        'inputSchema': baseSchema(),
      },
      // ---- APK file-level operations (移植自 apk_file_ops.py) ----
      {
        'name': 'reverse_apk_file_list',
        'description': '列出 APK 内所有文件路径，可选正则过滤。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_apk_file_delete',
        'description': '从 APK 中删除指定文件列表，输出新 APK。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_apk_file_delete_pattern',
        'description': '从 APK 中按正则匹配删除文件。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_apk_file_update',
        'description': '更新 APK 中指定文件的内容。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_apk_file_add',
        'description': '向 APK 中添加新文件（若已存在则覆盖）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_apk_file_extract',
        'description': '提取 APK 内指定文件到磁盘。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_apk_file_extract_all',
        'description': '提取 APK 内所有文件到指定目录，支持正则过滤和增量提取。',
        'inputSchema': baseSchema(),
      },
      // ---- AXML binary tag operations (移植自 manifest_ops.py) ----
      {
        'name': 'reverse_axml_find_tags',
        'description': '在 AXML 二进制数据中查找匹配的标签，支持标签名/属性名/属性值过滤。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_axml_remove_tag',
        'description': '从 AXML 二进制中删除匹配的标签及其子标签，直接二进制操作不经文本转换。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_axml_replace_attr',
        'description': '在 AXML 字符串池中原地替换指定标签的属性值，不改变标签结构。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_axml_remove_component',
        'description': '从 AXML 中删除指定组件声明（activity/service/receiver/provider/meta-data）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_axml_replace_launcher',
        'description': '替换启动 Activity 类名。',
        'inputSchema': baseSchema(),
      },
      // ---- resources.arsc parser (移植自 resource_parser.py) ----
      {
        'name': 'reverse_arsc_parse',
        'description': '完整解析 resources.arsc 二进制结构：全局字符串池/包表/类型表/类型规格/配置/条目。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_arsc_packages',
        'description': '获取 resources.arsc 中的所有包名。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_arsc_resources',
        'description': '获取扁平化资源列表（类型/名称/ID/配置/值），最多返回 500 条。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_arsc_find',
        'description': '按资源 ID（十六进制）查找资源详情。',
        'inputSchema': baseSchema(),
      },
      // ---- Workspace management (移植自 workspace/manager.py) ----
      {
        'name': 'reverse_workspace_create',
        'description': '创建分析工作区：元信息/结果目录/artifacts 目录，可选 APK 指纹。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_workspace_list',
        'description': '列出所有工作区。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_workspace_open',
        'description': '打开指定工作区，返回元信息。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_workspace_delete',
        'description': '删除指定工作区。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_workspace_info',
        'description': '获取工作区详情：结果列表/配置/元信息。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_workspace_save_result',
        'description': '保存分析结果快照到工作区。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_workspace_load_result',
        'description': '从工作区加载分析结果快照。',
        'inputSchema': baseSchema(),
      },
      // ---- ADB device operations (移植自 device/adb.py) ----
      {
        'name': 'reverse_adb_devices',
        'description': '列出已连接的 Android 设备。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_adb_info',
        'description': '获取设备信息：型号/Android 版本/SDK/制造商/ABI。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_adb_install',
        'description': '安装 APK 到设备，支持重装。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_adb_uninstall',
        'description': '卸载应用。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_adb_launch',
        'description': '启动应用，可指定 Activity 或自动获取 launcher。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_adb_force_stop',
        'description': '强制停止应用。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_adb_pull',
        'description': '从设备拉取文件。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_adb_push',
        'description': '推送文件到设备。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_adb_screenshot',
        'description': '设备截图并保存到本地。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_adb_logcat',
        'description': '获取 logcat 日志，支持过滤和行数限制。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_adb_list_packages',
        'description': '列出设备上的应用包名，支持过滤和第三方过滤。',
        'inputSchema': baseSchema(),
      },
      // ---- Native SO advanced patching (移植自 native_patcher.py) ----
      {
        'name': 'reverse_native_detect_arch',
        'description': '检测指定偏移处的指令集架构（arm/thumb/aarch64/x86/x86_64）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_native_patch_hex',
        'description': '十六进制模式搜索替换。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_native_patch_hex_at',
        'description': '在指定偏移处写入十六进制字节。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_native_patch_string',
        'description': 'SO 文件字符串替换（保留空终止符），支持最大替换次数。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_native_nop_out',
        'description': '用 NOP 指令填充指定区域，支持多架构自动检测。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_native_branch_to_ret',
        'description': '将分支/调用指令替换为返回指令（RET/BX LR）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_native_branch_to_mov',
        'description': '将分支替换为 mov r0, #value + ret。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_native_patch_jni',
        'description': '修改 JNI 函数名。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_native_patch_elf_entry',
        'description': '修改 ELF 入口点。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_native_patch_branch',
        'description': '在指定偏移处写入跳转指令（B/BL），支持 AArch64 和 ARM。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_native_find_pattern',
        'description': '搜索十六进制模式，返回所有匹配偏移。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_native_find_string',
        'description': '搜索字符串偏移，返回所有匹配位置。',
        'inputSchema': baseSchema(),
      },
      // ---- Smali advanced patching (移植自 smali_patcher.py) ----
      {
        'name': 'reverse_smali_insert_method',
        'description': '在 Smali 代码中插入方法，可指定插入位置。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_smali_remove_method',
        'description': '从 Smali 代码中删除指定方法。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_smali_add_log',
        'description': '在方法头部注入 Log.d 调用。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_smali_add_return',
        'description': '在方法头部注入立即返回指令。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_smali_bypass_sig',
        'description': '签名校验绕过：替换 checkSignatures/getPackageInfo 调用为常量返回。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_smali_nop_method',
        'description': '将方法体全部替换为 NOP 指令。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_smali_replace_const',
        'description': '替换 Smali 常量值（const/4/const/16/const/const-string）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_smali_nop_invoke',
        'description': '将特定方法调用替换为 NOP，支持类名/方法名过滤。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_smali_gen_stub',
        'description': '生成方法存根代码，支持所有返回类型。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_smali_find_methods_by_string',
        'description': '查找包含特定字符串引用的方法。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_smali_patch_goto',
        'description': '修改 goto 跳转目标。',
        'inputSchema': baseSchema(),
      },
    ];
  }
}
