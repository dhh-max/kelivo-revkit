package com.shinegirls.apkadremovereditor.core

import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.Opcode
import org.jf.dexlib2.iface.DexFile
import org.jf.dexlib2.iface.ClassDef
import org.jf.dexlib2.iface.Method
import org.jf.dexlib2.iface.MethodImplementation
import org.jf.dexlib2.iface.instruction.formats.Instruction21c
import org.jf.dexlib2.iface.instruction.formats.Instruction31c
import org.jf.dexlib2.iface.reference.StringReference
import org.jf.dexlib2.immutable.ImmutableDexFile
import org.jf.dexlib2.immutable.ImmutableClassDef
import org.jf.dexlib2.immutable.ImmutableMethod
import org.jf.dexlib2.immutable.ImmutableMethodImplementation
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction10x
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction11n
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction11x
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction12x
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction21c
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction31c
import org.jf.dexlib2.immutable.reference.ImmutableStringReference
import java.io.File

/** 日志回调类型 */
typealias Logger = (String) -> Unit

/**
 * 直接编辑DEX文件（无需smali反编译/回编译）。
 * 使用dexlib2的Immutable API读取-修改-写入DEX，速度比smali流程快几十倍。
 *
 * 功能（仅保留置空方法）：
 * - 匹配到广告类后，仅将方法名包含广告关键词的方法体替换为返回默认值（置空），
 *   跳过构造方法、<clinit> 等关键方法，避免闪退。
 * 已移除功能：NOP广告调用指令、替换广告URL字符串。
 *
 * 性能优化：
 * - 广告模式预编译为HashSet + 小写索引，匹配从O(n*m)降为O(n)
 * - 广告方法名预编译为HashSet，单次lookup O(1)
 * - 未修改的类使用ImmutableClassDef.of零拷贝转换
 */
object DexPatcher {

    /**
     * 预编译的广告模式索引，避免每次匹配都遍历整个列表。
     */
    private data class CompiledPatterns(
        /** SDK包名/类关键词的小写集合，用于精确匹配 */
        val adPatternLowercase: Set<String>,
        /**
         * 配置中声明的广告方法名（小写）。
         * 用于精确匹配：方法名与配置项完全一致时判定为广告方法。
         * 例如配置 `loadAd` 时，方法名 `loadAd` 精确命中。
         */
        val exactMethodNamesLowercase: Set<String>,
        /**
         * 广告类方法置空关键词（小写），用于边界感知的子串匹配。
         * 当匹配到广告SDK类时，只置空方法名"命中"这些关键词的方法，
         * 避免过度置空导致软件崩溃（如置空构造方法、生命周期方法等）。
         * 包含：_ad_, _ads_, _banner_, AdShow, ShowAd, loadAd, showAd 等。
         */
        val neutralizeMethodKeywords: Set<String>,
        /**
         * 广告URL/域名模式（小写）。
         * 用于置空 DEX 中以 const-string 形式存在的广告链接字符串。
         * 参考开源项目 DTL-X 的域名黑名单整理。
         */
        val urlPatternLowercase: Set<String>,
        /**
         * 强制返回 true 的方法名（小写）。
         * 当方法名精确命中该集合且返回类型为 boolean(Z) 或 int(I) 时，方法体被替换为
         * `const/4 v0, 0x1; return v0`（boolean 返回 true，int 返回 1）。
         * 用于"解锁 VIP / 会员 / 专业版"等判定方法，不受广告类限制，作用于全部类。
         */
        val forceTrueMethodNamesLowercase: Set<String>
    )

    /**
     * 预编译广告模式，将列表转为HashSet加速查找。
     */
    private fun compilePatterns(
        adPatterns: List<String>,
        adMethodNames: List<String>,
        urlPatterns: List<String>,
        forceTrueMethodNames: List<String> = emptyList()
    ): CompiledPatterns {
        // 合并配置中的方法名 + 内置广告方法关键词，用于广告类方法置空筛选
        // 避免过度置空非广告方法（如构造方法、生命周期方法等）导致崩溃
        // 关键词参考开源项目 DTL-X 的 adloader / t4adremover 模式扩充。
        val builtinMethodKeywords = listOf(
            "_ad_", "_ads_", "_banner_", "_adview_", "_adsdk_",
            "adshow", "showad", "showads", "loadad", "loadads",
            "bannerad", "bannerads", "nativead", "splashad",
            "interstitialad", "rewardedad", "rewardedvideo",
            "adload", "adclose", "adclick", "adfail",
            "adimpression", "adrequest", "adresponse",
            "adcallback", "adlistener", "adobserver",
            "adcontroller", "admanager", "adhelper",
            "adprovider", "adnetwork", "adsource",
            "initad", "initads", "initsdk",
            "setad", "getad", "onad", "onads",
            "preloadad", "cachead", "fetchad", "requestad",
            "destroyad", "resumead", "pausead",
            "displayad", "hidead", "removead",
            "adview", "adloader", "adbanner", "adsplash",
            "adwidget", "adcontainer", "adlayout",
            "ttad", "panglead", "gdtad", "baiduad",
            "ad_config", "ad_settings", "ad_unit_",
            "advertising", "adidclient", "adid",
            "admob", "adviewbinder",
            // 常见广告方法名变体
            "loadinterstitial", "showinterstitial",
            "loadrewarded", "showrewarded",
            "loadbanner", "showbanner",
            "loadnative", "shownative",
            "loadsplash", "showsplash",
            "loadexpress", "showexpress",
            // ===== 从开源项目 DTL-X 移植的广告方法关键词 =====
            // adloader 加载器方法
            "loadadfrombid", "requestbannerad", "requestinterstitialad",
            "loadbannerad", "loadinterstitialad", "loadnativead", "loadrewardedad",
            "loadrewardedinterstitialad", "loadappopenad", "loadinterscrollerad",
            "loadnativeadforbidding", "loadnextad", "createinterstitialad",
            "setnativead", "loadadviewad", "loadadfromnetwork", "loadadfromub",
            "loadadinternal", "loadadvertisement", "loadsmartbanner",
            "loadnextadforadtoken", "loadnextadforzoneid", "loadrewardedvideo",
            "loadrewardedvideofordemandonly",
            // 展示方法
            "showbannerandnative", "shownativeinterstitial", "showofferwall",
            "showrewardedvideo", "showrewardedvideoad", "showinterstitialad",
            "shownativead", "showbannerad", "showvideoad", "displayadeventloaded",
            "resumebanner", "startadsession", "unsetnativead", "setadlistener",
            "setrewardedvideoadlistener", "reportadclicked", "reportadimpression",
            // 广告回调方法
            "onadloaded", "onaddisplayed", "onaddisplayfailed",
            "onaddismissedfullscreencontent", "onadfailedtoshowsfullscreencontent",
            "onadhidden", "onadleftapplication", "onadopen", "onadopened",
            "onadrevenuepaid", "onadrequeststarted", "onadshowedfullscreencontent",
            "onappopenadloadfailed", "oninterstitialadloaded", "oninterstitialadloadfailed",
            "oninterstitialadrewarded", "onnativeadclicked", "onnativeadloaded",
            "onnativeadloadfailed", "onnativeadshown", "onrewardedadclosed",
            "onrewardedaddisplayfailed", "onrewardedadfailedtoload",
            "onrewardedadfailedtoshow", "onrewardedadloaded", "onrewardedadopened",
            "onrewardedvideoadclicked", "onrewardedvideoadclosed",
            "onrewardedvideoadfailedtoload", "onrewardedvideoadloaded",
            "onrewardedvideoadopened", "onrewardedvideoadrewarded",
            "onrewardedvideoadshowfailed", "onrewardedvideoadstarted",
            "onunifiednativeadloaded", "onuserearnedreward",
            "failedtoreceivead", "failedtoreceiveadv2", "fetchadwithlocation",
            "vpaidadimpression", "vpaidadinteraction", "vpaidadloaded",
            // 第三方广告SDK特有方法
            "renderad", "hasvideocontent"
        )
        // 合并配置中的方法名 + 内置广告方法关键词，去重后小写化
        val configMethodLowercase = adMethodNames.map { it.lowercase() }.toHashSet()
        val allKeywords = (configMethodLowercase + builtinMethodKeywords.map { it.lowercase() }).toHashSet()

        return CompiledPatterns(
            adPatternLowercase = adPatterns.map { it.lowercase() }.toHashSet(),
            exactMethodNamesLowercase = configMethodLowercase,
            neutralizeMethodKeywords = allKeywords,
            urlPatternLowercase = urlPatterns.map { it.lowercase() }.toHashSet(),
            forceTrueMethodNamesLowercase = forceTrueMethodNames.map { it.lowercase() }.toHashSet()
        )
    }

    /**
     * 快速检查类名是否匹配广告模式。
     * 先做小写转换，再用 HashSet 精确匹配，最后才做子串匹配。
     * 单次遍历返回第一个命中项，避免重复扫描。
     */
    private fun fastMatchAdClass(className: String, patterns: CompiledPatterns): String? {
        val lowerName = className.lowercase()
        // 快速路径：精确匹配（HashSet O(1) 查找 + 精确命中优先）
        if (lowerName in patterns.adPatternLowercase) return lowerName
        // 慢路径：子串匹配，单次遍历即可
        for (pattern in patterns.adPatternLowercase) {
            if (lowerName.contains(pattern)) return pattern
        }
        return null
    }

    /**
     * 直接修补DEX文件中的广告内容（置空广告类方法 + 置空广告链接字符串）。
     *
     * 大文件优化（处理速度 + 内存友好）：
     * - 单遍扫描：广告方法置空 与 广告URL字符串置空 在同一个循环内完成，
     *   避免旧实现"先构建全量类列表、再二次遍历置空URL"导致的双倍内存峰值。
     * - 每处理一类即用零拷贝 [ImmutableClassDef.of] 复用未修改类，减少对象创建。
     * - 移除显式 System.gc()：ART 的并发 GC 会自动回收，显式全量 GC 会触发
     *   stop-the-world 停顿，导致大文件处理明显变卡。
     *   这是本版本修复"越优化越卡"问题的关键（旧实现每 ~500KB 全量 GC 一次）。
     *
     * @param logger 实时日志回调，用于报告处理进度
     */
    fun patchDex(
        dexFile: File,
        adPatterns: List<String>,
        adMethodNames: List<String>,
        urlPatterns: List<String> = emptyList(),
        forceTrueMethodNames: List<String> = emptyList(),
        logger: Logger? = null
    ): PatchResult {

        val log = logger ?: {}
        val startTime = System.currentTimeMillis()

        log("  加载 DEX: ${dexFile.name} (${formatSize(dexFile.length())})")

        val dex: DexFile = try {
            DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())
        } catch (e: Exception) {
            log("  [错误] 无法加载 ${dexFile.name}: ${e.message}")
            return PatchResult(0, 0)
        }

        // 预编译广告模式
        val patterns = compilePatterns(adPatterns, adMethodNames, urlPatterns, forceTrueMethodNames)

        val totalClasses = dex.classes.size
        log("  共 $totalClasses 个类待扫描")

        var patchedClasses = 0
        var neutralizedMethods = 0
        var neutralizedUrlStrings = 0
        var forcedTrueMethods = 0
        var failedClasses = 0
        var processedCount = 0

        val newClasses = mutableListOf<ImmutableClassDef>()

        for (classDef in dex.classes) {
            processedCount++
            val className = classDef.type

            // 每 2000 个类输出一次进度（日志由 UI 端缓冲合并渲染，不拖慢处理）
            if (processedCount % 2000 == 0) {
                log("  进度: $processedCount / $totalClasses ...")
            }

            try {
                val matchedPattern = fastMatchAdClass(className, patterns)
                // 该类的任何方法名命中"强制返回true"清单时，也需重建该类
                val hasForceTrue = patterns.forceTrueMethodNamesLowercase.isNotEmpty() &&
                    classDef.methods.any { it.name.lowercase() in patterns.forceTrueMethodNamesLowercase }
                if (matchedPattern != null || hasForceTrue) {
                    log("  [广告类] $className (匹配: ${matchedPattern ?: "强制返回true"})")
                    val result = patchSingleClass(classDef, className, patterns, log)
                    newClasses.add(result.classDef)
                    patchedClasses++
                    neutralizedMethods += result.neutralized
                    neutralizedUrlStrings += result.urls
                    forcedTrueMethods += result.forcedTrue
                } else {
                    // 非广告类且无强制返回true方法：零拷贝复用，避免额外对象
                    newClasses.add(ImmutableClassDef.of(classDef))
                }
            } catch (_: Exception) {
                // 单类处理失败不影响整体：回退为原类，累计失败数
                newClasses.add(ImmutableClassDef.of(classDef))
                failedClasses++
            }
        }

        log("  扫描完成，开始写入 DEX ...")

        // 构建新的DEX文件并写回（依赖 ART 并发 GC，不再手动触发全量 GC）
        try {
            val newDex = ImmutableDexFile(Opcodes.getDefault(), newClasses)

            // 【原子写入】修复"安装包不完整"问题：
            // 旧实现直接 writeDexFile 到原 dex 路径，若在写入过程中发生 OOM/进程被杀，
            // 原 dex 会被截断成损坏的半成品；随后被重新打包进 APK，导致安装包残缺。
            // 改为先写入同目录临时文件，写成功后原子重命名替换原文件，
            // 任何失败都不会破坏原 dex，且可安全跳过该文件继续处理。
            val tmpDex = File(dexFile.parentFile, "${dexFile.name}.tmp")
            if (tmpDex.exists()) tmpDex.delete()
            DexFileFactory.writeDexFile(tmpDex.absolutePath, newDex)

            if (!tmpDex.renameTo(dexFile)) {
                // 重命名失败（极少见，如文件被占用）：回退为删除+复制
                dexFile.delete()
                if (!tmpDex.renameTo(dexFile)) {
                    tmpDex.copyTo(dexFile, overwrite = true)
                    tmpDex.delete()
                }
            }

            val elapsed = System.currentTimeMillis() - startTime
            log("  DEX 写入成功: ${dexFile.name} (${elapsed}ms, ${formatSize(dexFile.length())})")
        } catch (e: OutOfMemoryError) {
            newClasses.clear()
            throw RuntimeException("DEX写入内存不足: ${dexFile.name}", e)
        }

        if (failedClasses > 0) {
            log("  [注意] $failedClasses 个类处理失败已跳过")
        }
        if (forcedTrueMethods > 0) {
            log("  ✓ 强制返回 true 方法: $forcedTrueMethods 个")
        }

        return PatchResult(
            patchedClasses = patchedClasses,
            neutralizedMethods = neutralizedMethods,
            neutralizedUrlStrings = neutralizedUrlStrings,
            forcedTrueMethods = forcedTrueMethods
        )
    }

    /**
     * 单类修补结果。
     */
    private data class SingleClassPatch(
        val classDef: ImmutableClassDef,
        val neutralized: Int,
        val urls: Int,
        val forcedTrue: Int
    )

    /**
     * 单遍修补单个类：同时完成广告方法置空、广告URL字符串置空、强制返回true。
     *
     * 相比旧实现（先置空方法、二次遍历全量类列表置空URL），
     * 本方法在遍历一个类的方法时同步处理三类修改，避免二次构建方法对象，
     * 显著降低大 DEX 处理时的内存峰值。
     *
     * @return [SingleClassPatch] 修改后的类及各修改计数
     */
    private fun patchSingleClass(
        classDef: ClassDef,
        className: String,
        patterns: CompiledPatterns,
        log: Logger
    ): SingleClassPatch {
        val needUrl = patterns.urlPatternLowercase.isNotEmpty()
        var neutralizedCount = 0
        var urlCount = 0
        var forcedTrueCount = 0
        var skippedCount = 0

        val newMethods = ArrayList<ImmutableMethod>(classDef.methods.count())
        for (method in classDef.methods) {
            try {
                val methodName = method.name
                val impl = method.implementation
                if (impl == null) {
                    newMethods.add(ImmutableMethod.of(method))
                    continue
                }

                // 始终跳过构造方法和静态构造器，避免类初始化失败
                if (methodName == "<init>" || methodName == "<clinit>") {
                    newMethods.add(ImmutableMethod.of(method))
                    skippedCount++
                    continue
                }

                // 0) 强制返回 true：方法名精确命中"强制返回true"清单且返回类型为 boolean(Z) 或 int(I)。
                //    方法体替换为 const/4 v0, 0x1 + return v0，用于解锁 VIP/会员/专业版判定。
                //    - Z (boolean)：返回 1，即逻辑 true
                //    - I (int)：返回 1，通常表示"是会员/已解锁/已购买"等非0真值
                //    该判定独立于广告类，作用于所有类、所有方法。
                if (patterns.forceTrueMethodNamesLowercase.isNotEmpty() &&
                    methodName.lowercase() in patterns.forceTrueMethodNamesLowercase
                ) {
                    if (method.returnType == "Z" || method.returnType == "I") {
                        val newImpl = ImmutableMethodImplementation(
                            impl.registerCount.coerceAtLeast(1),
                            createReturnTrueInstructions(),
                            emptyList(),
                            emptyList()
                        )
                        newMethods.add(
                            ImmutableMethod(
                                method.definingClass, method.name, method.parameters.toList(),
                                method.returnType, method.accessFlags,
                                method.annotations.toSet(), method.hiddenApiRestrictions.toSet(), newImpl
                            )
                        )
                        forcedTrueCount++
                        continue
                    }
                    // 非 boolean/int 返回类型：跳过，不强制，避免生成非法指令
                }

                // 1) 置空广告方法（方法名命中广告关键词）
                val isAdMethod = fastMatchNeutralizeMethod(methodName, patterns)
                // 2) 置空广告URL字符串：惰性处理，仅当方法体内确实命中广告URL时才构建新指令，
                //    绝大多数方法无命中，返回 null 直接复用原始方法，零对象创建。
                var urlInstructions: List<ImmutableInstruction>? = null
                var urlCountInMethod = 0
                if (needUrl && !isAdMethod) {
                    val result = neutralizeUrlInMethod(impl, patterns)
                    urlInstructions = result.first
                    urlCountInMethod = result.second
                }

                if (isAdMethod) {
                    // 广告方法：方法体替换为返回默认值
                    val returnType = method.returnType
                    val newInstructions = createReturnInstructions(returnType)
                    val newImpl = ImmutableMethodImplementation(
                        impl.registerCount.coerceAtLeast(1),
                        newInstructions,
                        emptyList(),
                        emptyList()
                    )
                    newMethods.add(
                        ImmutableMethod(
                            method.definingClass, method.name, method.parameters.toList(),
                            method.returnType, method.accessFlags,
                            method.annotations.toSet(), method.hiddenApiRestrictions.toSet(), newImpl
                        )
                    )
                    neutralizedCount++
                } else if (needUrl && urlCountInMethod > 0 && urlInstructions != null) {
                    // 非广告方法但含广告URL字符串：重建方法体，其余不变
                    urlCount += urlCountInMethod
                    val newImpl = ImmutableMethodImplementation(
                        impl.registerCount.coerceAtLeast(1),
                        urlInstructions,
                        emptyList(),
                        emptyList()
                    )
                    newMethods.add(
                        ImmutableMethod(
                            method.definingClass, method.name, method.parameters.toList(),
                            method.returnType, method.accessFlags,
                            method.annotations.toSet(), method.hiddenApiRestrictions.toSet(), newImpl
                        )
                    )
                } else {
                    newMethods.add(ImmutableMethod.of(method))
                    if (!isAdMethod) skippedCount++
                }
            } catch (_: Exception) {
                try {
                    newMethods.add(ImmutableMethod.of(method))
                } catch (_: Exception) {
                }
            }
        }

        if (forcedTrueCount > 0) {
            log("    -> $className: 强制返回 true $forcedTrueCount 个方法")
        }
        if (neutralizedCount > 0) {
            log("    -> $className: 置空 $neutralizedCount 个广告方法, 跳过 $skippedCount 个非广告方法${if (urlCount > 0) ", 置空 $urlCount 处广告链接" else ""}")
        } else if (urlCount > 0) {
            log("    -> $className: 置空 $urlCount 处广告链接")
        }

        val newClass = ImmutableClassDef(
            classDef.type, classDef.accessFlags, classDef.superclass,
            classDef.interfaces.toList(), classDef.sourceFile,
            classDef.annotations.toSet(), classDef.fields.toList(), newMethods
        )
        return SingleClassPatch(newClass, neutralizedCount, urlCount, forcedTrueCount)
    }

    /**
     * 置空单个方法体内引用广告URL/域名的 const-string / const-string/jumbo 指令。
     *
     * 惰性两遍策略（性能关键）：
     * - 第一遍只读扫描：仅遍历指令，检查 opcode 与字符串值，不创建任何对象。
     *   绝大多数方法体内没有广告URL，此时直接返回 (null, 0)，零开销。
     * - 第二遍仅在第一遍命中时执行：才真正构建新的指令列表并替换命中项。
     *   这样避免旧实现"无条件为每个方法复制全部指令"导致的 CPU/内存峰值。
     *
     * @return Pair(新指令列表，被置空的字符串数量)；无命中时 first 为 null。
     */
    private fun neutralizeUrlInMethod(
        impl: MethodImplementation,
        patterns: CompiledPatterns
    ): Pair<List<ImmutableInstruction>?, Int> {
        // 第一遍：只读检测是否有命中的广告URL字符串
        var hit = false
        var changed = 0
        for (ins in impl.instructions) {
            val opcode = ins.opcode
            if (opcode == Opcode.CONST_STRING || opcode == Opcode.CONST_STRING_JUMBO) {
                val str = extractConstString(ins)
                if (str != null && isAdUrlString(str, patterns)) {
                    hit = true
                    changed++
                }
            }
        }
        // 无命中：零对象创建，直接返回 null
        if (!hit) return Pair(null, 0)

        // 第二遍：命中才构建新指令列表
        val newInstructions = mutableListOf<ImmutableInstruction>()
        for (ins in impl.instructions) {
            val opcode = ins.opcode
            if (opcode == Opcode.CONST_STRING || opcode == Opcode.CONST_STRING_JUMBO) {
                val str = extractConstString(ins)
                if (str != null && isAdUrlString(str, patterns)) {
                    newInstructions.add(
                        ImmutableInstruction21c(
                            Opcode.CONST_STRING, extractRegister(ins), ImmutableStringReference("")
                        )
                    )
                    continue
                }
            }
            newInstructions.add(ImmutableInstruction.of(ins))
        }
        return Pair(newInstructions, changed)
    }

    /** 从 const-string / const-string/jumbo 指令提取字符串值（非字符串指令返回 null）。 */
    private fun extractConstString(ins: org.jf.dexlib2.iface.instruction.Instruction): String? {
        return when (ins) {
            is Instruction21c -> (ins.reference as? StringReference)?.string
            is Instruction31c -> (ins.reference as? StringReference)?.string
            else -> null
        }
    }

    /** 从 const-string / const-string/jumbo 指令提取目标寄存器（非字符串指令返回 0）。 */
    private fun extractRegister(ins: org.jf.dexlib2.iface.instruction.Instruction): Int {
        return when (ins) {
            is Instruction21c -> ins.registerA
            is Instruction31c -> ins.registerA
            else -> 0
        }
    }

    /**
     * 判断方法名是否为广告方法，决定是否置空该方法。
     *
     * 匹配策略（提升准确率）：
     * 1. 精确匹配：方法名与配置中的某个广告方法名完全一致（如 `loadAd`），
     *    避免过长或拼接方法名的误判。
     * 2. 边界感知子串匹配：广告关键词必须作为方法名中的"单词边界"出现。
     *    边界基于原始大小写识别驼峰边界（如 `Ad`），
     *    避免把 `showAndroid`、`loadAdapter`、`getAddress` 等误判为广告方法，
     *    同时保留 `showRewardedVideo`、`showInterstitialAd` 等驼峰复合广告方法的命中。
     *
     * 使用预编译的 HashSet 加速查找。
     */
    private fun fastMatchNeutralizeMethod(methodName: String, patterns: CompiledPatterns): Boolean {
        val lower = methodName.lowercase()

        // 1) 精确匹配配置中的广告方法名
        if (lower in patterns.exactMethodNamesLowercase) return true

        // 2) 边界感知的子串匹配：小写串只分配一次，供所有关键词复用
        for (keyword in patterns.neutralizeMethodKeywords) {
            if (isKeywordAtBoundary(methodName, lower, keyword)) return true
        }
        return false
    }

    /**
     * 判断 keyword 是否在 name 中以"单词边界"形式出现。
     * 使用原始大小写识别驼峰边界（如 `loadAd` 中的 `Ad` 前是 `load` 的小写 `d`）。
     *
     * @param nameLower 已小写化的 name，避免每个关键词重复分配低开销字符串
     */
    private fun isKeywordAtBoundary(name: String, nameLower: String, keyword: String): Boolean {
        if (keyword.isEmpty()) return false
        var fromIndex = 0
        while (true) {
            val idx = nameLower.indexOf(keyword, fromIndex)
            if (idx < 0) return false
            // 前方边界：位于开头，或前一个字符不是字母，或为驼峰边界（前小写后大写）
            val prevOk = idx == 0 ||
                !name[idx - 1].isLetter() ||
                (name[idx].isUpperCase() && name[idx - 1].isLowerCase())
            // 后方边界：位于末尾，或后一个字符不是字母，或后一字符为新单词开头（大写）
            val nextIdx = idx + keyword.length
            val nextOk = nextIdx >= name.length ||
                !name[nextIdx].isLetter() ||
                name[nextIdx].isUpperCase()
            if (prevOk && nextOk) return true
            fromIndex = idx + 1
        }
    }

    /**
     * 判断字符串是否为广告URL链接。
     * 匹配广告URL模式中的域名/关键词，避免误伤普通字符串。
     */
    private fun isAdUrlString(value: String, patterns: CompiledPatterns): Boolean {
        // 仅处理形如链接的字符串，降低误判
        if (!value.contains("://") && !value.contains("www.") && !value.contains(".com") &&
            !value.contains(".net") && !value.contains(".cn") && !value.contains(".mobi") &&
            !value.contains(".ru") && !value.contains("/ads") && !value.contains("ca-app-pub")
        ) {
            return false
        }
        val lower = value.lowercase()
        for (pattern in patterns.urlPatternLowercase) {
            if (lower.contains(pattern)) return true
        }
        return false
    }

    /**
     * 生成返回 true 的指令序列（适用于 boolean(Z) 和 int(I) 返回类型）。
     *
     * const/4 v0, 0x1
     * return v0
     *
     * 对 boolean 返回 1（true），对 int 返回 1（非0真值）。
     */
    private fun createReturnTrueInstructions(): List<ImmutableInstruction> {
        return listOf(
            ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
            ImmutableInstruction11x(Opcode.RETURN, 0)
        )
    }

    /**
     * 根据返回类型生成return指令。
     */
    private fun createReturnInstructions(returnType: String): List<ImmutableInstruction> {
        if (returnType.isEmpty()) {
            return listOf(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }

        val firstChar = returnType.first()

        return when (firstChar) {
            'V' -> listOf(ImmutableInstruction10x(Opcode.RETURN_VOID))
            'Z', 'B', 'S', 'C', 'I' -> listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.RETURN, 0)
            )
            'J' -> listOf(
                ImmutableInstruction11n(Opcode.CONST_WIDE_16, 0, 0),
                ImmutableInstruction12x(Opcode.RETURN_WIDE, 0, 0)
            )
            'F' -> listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.RETURN, 0)
            )
            'D' -> listOf(
                ImmutableInstruction11n(Opcode.CONST_WIDE_16, 0, 0),
                ImmutableInstruction12x(Opcode.RETURN_WIDE, 0, 0)
            )
            else -> listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0)
            )
        }
    }

    private fun formatSize(bytes: Long): String {
        return when {
            bytes < 1024 -> "${bytes}B"
            bytes < 1024 * 1024 -> "${bytes / 1024}KB"
            else -> String.format("%.1fMB", bytes / (1024.0 * 1024.0))
        }
    }
}

/**
 * DEX修补结果。
 */
data class PatchResult(
    val patchedClasses: Int,
    val neutralizedMethods: Int,
    val neutralizedUrlStrings: Int = 0,
    val forcedTrueMethods: Int = 0
)