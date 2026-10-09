package zhou.solab.tools

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.luckypray.dexkit.DexKitBridge
import org.luckypray.dexkit.query.FindClass
import org.luckypray.dexkit.query.FindMethod
import org.luckypray.dexkit.query.enums.OpCodeMatchType
import org.luckypray.dexkit.query.enums.StringMatchType
import org.luckypray.dexkit.query.matchers.ClassMatcher
import org.luckypray.dexkit.query.matchers.FieldMatcher
import org.luckypray.dexkit.query.matchers.AnnotationMatcher
import org.luckypray.dexkit.query.matchers.AnnotationsMatcher
import org.luckypray.dexkit.query.matchers.InterfacesMatcher
import org.luckypray.dexkit.query.matchers.MethodMatcher
import java.io.File

/**
 * A8: DexKit 反混淆查找（移植自玄星逆核 DexKitTool.kt，C++ 高性能 dex 解析）。
 *
 * 混淆 App 里靠特征反查真实类/方法：method_by_string（最常用，如搜 sign/pay/vip）、
 * class_by_string、method_by_name、class_by_name。
 * DexKitBridge 用完即 close 释放 native 资源。
 */
object SolabDexKitTool {

    /**
     * 当前调用是否针对 Flutter 包（D17）。用 ThreadLocal 而不是可变字段：
     * 本 object 是单例，字段会被并发调用串味；而 handle → resultJson 是
     * 同线程同步调用，ThreadLocal 恰好只覆盖一次调用的作用域。（同款做法
     * 见 AsmFastIndex 的线程本地 Matcher。）
     */
    private val flutterApkFlag = ThreadLocal.withInitial { false }

    private val flutterApkProbeCache =
        java.util.concurrent.ConcurrentHashMap<String, Pair<Long, Boolean>>()

    /** 在 zip 中央目录里找 Flutter 引擎库（lib/<abi>/libflutter.so）；按 (path, length, mtime) 缓存，避免每次查询重扫。 */
    private fun isFlutterApk(file: File): Boolean {
        if (!file.isFile) return false
        val key = "${file.absolutePath}|${file.length()}|${file.lastModified()}"
        flutterApkProbeCache.entries.removeAll { it.key.substringBefore('|') == file.absolutePath && it.key != key }
        flutterApkProbeCache[key]?.let { return it.second }
        val detected = runCatching {
            java.util.zip.ZipFile(file).use { zip ->
                zip.entries().asSequence().any { entry ->
                    val name = entry.name
                    name.startsWith("lib/") && name.endsWith("/libflutter.so")
                }
            }
        }.getOrDefault(false)
        flutterApkProbeCache[key] = file.length() to detected
        return detected
    }

    private data class MethodFeatures(
        val strings: List<String>,
        val numbers: List<Number>,
        val className: String,
        val methodName: String,
        val fieldNames: List<String>,
        val invokedMethodNames: List<String>,
        val opNames: List<String>,
    ) {
        fun isEmpty(): Boolean = strings.isEmpty() && numbers.isEmpty() && className.isBlank() &&
            methodName.isBlank() && fieldNames.isEmpty() && invokedMethodNames.isEmpty() && opNames.isEmpty()
    }

    private data class AutoCandidate(
        val className: String,
        val methodName: String,
        val descriptor: String,
        val returnType: String,
        val params: List<String>,
        val dimensions: MutableSet<String> = linkedSetOf(),
        val evidence: MutableSet<String> = linkedSetOf(),
    )

    // 依赖用的是 org.luckypray:dexkit 纯 JAR（非 dexkit-android AAR），
    // JAR 版没有自动 loadLibrary 的伴生初始化，libdexkit.so 由 jniLibs
    // 手工打包；不显式加载会抛 "No implementation found for nativeInitDexKit"。
    @Volatile
    private var nativeLibReady = false
    private fun ensureNativeLib() {
        if (nativeLibReady) return
        synchronized(this) {
            if (nativeLibReady) return
            System.loadLibrary("dexkit")
            nativeLibReady = true
        }
    }

    fun handle(context: Context, args: JSONObject): JSONObject {
        val (input, inputErr) = resolveInputFile(args)
        if (inputErr != null) return inputErr
        val inputPath = input!!.absolutePath
        // D17（2026-09-21 自检）：Flutter 包的 DEX 里没有业务代码，0 命中时给的
        // 五六条"换关键词/换 action/浏览器结构"建议对它是纯噪声——唯一正确的
        // 动作是切到 Dart 层。这里判定一次（zip 中央目录找 libflutter.so，按
        // path+length+mtime 缓存），供 resultJson 的空结果分支收窄提示。
        flutterApkFlag.set(isFlutterApk(input))

        val action = args.str("action", "auto").ifBlank { "auto" }
        val keywords = parseKeywords(args.str("keyword"))
        val numbers = parseNumbers(args)
        val features = MethodFeatures(
            keywords,
            numbers,
            args.str("className").trim(),
            args.str("methodName").trim(),
            parseFeatureTerms(args, "fieldNames", "fieldName"),
            parseFeatureTerms(args, "invokedMethodNames", "invokedMethodName"),
            parseFeatureTerms(args, "opNames"),
        )
        if (action == "method_by_numbers" && numbers.isEmpty()) {
            return err("INVALID_ARGUMENT", "method_by_numbers 缺少 numbers", "numbers", "")
        }
        if (action in setOf("auto", "method_by_features") && features.isEmpty()) {
            // auto 的 className/methodName 是合法独立维度（declaredClass/name
            // 匹配），不是 keyword 的附属；缺特征时列出全部可补维度，避免把
            // 锅只甩给 keyword——冒烟实测 className-only 报「缺 keyword」误导。
            return err(
                "INVALID_ARGUMENT",
                "$action 至少需要一种代码特征：keyword / numbers / className / " +
                    "methodName / fieldNames / invokedMethodNames / opNames 之一",
                "features",
                "",
            )
        }
        if (action !in setOf("auto", "method_by_numbers", "method_by_features") && keywords.isEmpty()) {
            // method_by_name/class_by_name 的名称维度（methodName/className）是
            // 合法独立查询键——存在时免 keyword，与工具描述"结构线索可单独作为
            // 主查询"对齐，不再误报「缺少参数 keyword」。
            val nameDim = when (action) {
                "method_by_name" -> features.methodName
                "class_by_name" -> features.className
                // D2：class_by_superclass/interface 的父类/接口名同样可以走 className
                // 别名（dispatch 里做的转换），守卫这一层必须认得，否则上面那条
                // 别名永远到不了。
                "class_by_superclass", "class_by_interface", "class_by_interfaces" ->
                    features.className
                else -> ""
            }
            if (nameDim.isBlank()) {
                return err("INVALID_ARGUMENT", "缺少参数 keyword(要查的字符串/名字)", "keyword", "")
            }
        }
        val matchType = when (args.str("matchType", "Contains")) {
            "Equals" -> StringMatchType.Equals
            "StartsWith" -> StringMatchType.StartsWith
            "EndsWith" -> StringMatchType.EndsWith
            else -> StringMatchType.Contains
        }
        val ignoreCase = args.optBoolean("ignoreCase", false)
        val pkgPrefix = args.str("packagePrefix")
        val limit = args.intValue("limit", 100).coerceIn(1, 2000)

        return runCatching {
            // DexKit 加载 APK 是耗时操作，用完即 close 释放 native 资源
            // 裸 dex（外部重组或 dump 产物）DexKitBridge.create 只认
            // APK/zip（直接喂会抛 "Open zip file failed"），先包成临时 zip。
            val bareDexWrap = if (DexIo.isBareDex(input)) {
                runCatching { DexIo.wrapBareDexAsApk(context, input) }.getOrElse { e ->
                    return err("DEXKIT_FAILED", "裸 dex 临时包装失败: ${e.message ?: e.javaClass.simpleName}", "path", inputPath)
                }
            } else null
            // 自检：libdexkit.so 缺失/ABI 不匹配时给出可诊断的结构化错误，而非笼统失败
            val bridge = runCatching {
                ensureNativeLib()
                DexKitBridge.create(bareDexWrap?.absolutePath ?: input.absolutePath)
            }.getOrElse { e ->
                // 早退路径同样要回收临时包装 zip，否则每次失败漏一个 dex 体积文件。
                bareDexWrap?.let { runCatching { it.delete() } }
                if (e is UnsatisfiedLinkError || e.cause is UnsatisfiedLinkError) {
                    return err(
                        "DEXKIT_UNAVAILABLE",
                        "DexKit native 库不可用（libdexkit.so 未随当前设备 ABI 打包或加载失败）：" +
                            "${e.message}。请确认 APK 安装包包含设备 ABI（如 arm64-v8a）的 libdexkit.so，或改用 class_outline + smali_read 链路定位",
                        "path", inputPath,
                    )
                }
                throw e
            }
            try {
                bridge.use { b -> dispatch(b, action, features, matchType, ignoreCase, pkgPrefix, limit) }
            } finally {
                bareDexWrap?.let { runCatching { it.delete() } }
            }
        }.getOrElse { e ->
            err("DEXKIT_FAILED", "DexKit 查找失败: ${e.message ?: e.javaClass.simpleName}", "path", inputPath)
        }
    }

    private fun dispatch(
        bridge: DexKitBridge,
        action: String,
        features: MethodFeatures,
        matchType: StringMatchType,
        ignoreCase: Boolean,
        pkgPrefix: String,
        limit: Int,
    ): JSONObject {
        val keywords = features.strings
        val numbers = features.numbers
        return when (action) {
            "auto" -> autoSearch(bridge, features, matchType, ignoreCase, pkgPrefix, limit)

            "method_by_string", "method_by_strings" -> {
                val find = FindMethod.create().apply {
                    if (pkgPrefix.isNotBlank()) searchPackages(pkgPrefix)
                    matcher(
                        MethodMatcher.create()
                            .usingStrings(keywords, matchType, ignoreCase),
                    )
                }
                val results = bridge.findMethod(find)
                val arr = JSONArray()
                results.take(limit).forEach { m ->
                    arr.put(JSONObject()
                        .put("class", m.className)
                        .put("method", m.methodName)
                        .put("descriptor", m.descriptor)
                        .put("qualifiedId", canonicalMethodQid(m.className, m.methodName, m.descriptor))
                        .put("returnType", m.returnTypeName)
                        .put("params", JSONArray(m.paramTypeNames)))
                }
                resultJson(action, features, results.size, arr,
                    matchTypeName = matchTypeName(matchType))
            }

            "class_by_string", "class_by_strings" -> {
                val find = FindClass.create().apply {
                    if (pkgPrefix.isNotBlank()) searchPackages(pkgPrefix)
                    matcher(
                        ClassMatcher.create()
                            .usingStrings(keywords, matchType, ignoreCase),
                    )
                }
                val results = bridge.findClass(find)
                val arr = JSONArray()
                results.take(limit).forEach { c ->
                    arr.put(JSONObject()
                        .put("class", c.name)
                        .put("simpleName", c.simpleName)
                        .put("sourceFile", c.sourceFile ?: ""))
                }
                resultJson(action, features, results.size, arr)
            }

            "method_by_numbers", "method_by_features" -> {
                val find = FindMethod.create().apply {
                    if (pkgPrefix.isNotBlank()) searchPackages(pkgPrefix)
                    matcher(methodFeatureMatcher(features, matchType, ignoreCase))
                }
                val results = bridge.findMethod(find)
                val arr = JSONArray(results.take(limit).map { m -> methodJson(
                    m.className, m.methodName, m.descriptor, m.returnTypeName, m.paramTypeNames,
                ) })
                resultJson(action, features, results.size, arr)
            }

            "method_by_name" -> {
                val name = keywords.firstOrNull() ?: features.methodName
                val find = FindMethod.create().apply {
                    if (pkgPrefix.isNotBlank()) searchPackages(pkgPrefix)
                    matcher(
                        MethodMatcher.create()
                            .name(name, matchType, ignoreCase),
                    )
                }
                val results = bridge.findMethod(find)
                val arr = JSONArray()
                results.take(limit).forEach { m ->
                    arr.put(JSONObject()
                        .put("class", m.className)
                        .put("method", m.methodName)
                        .put("descriptor", m.descriptor)
                        .put("qualifiedId", canonicalMethodQid(m.className, m.methodName, m.descriptor)))
                }
                resultJson(action, features, results.size, arr)
            }

            "class_by_name" -> {
                val name = keywords.firstOrNull() ?: features.className
                val find = FindClass.create().apply {
                    if (pkgPrefix.isNotBlank()) searchPackages(pkgPrefix)
                    matcher(
                        ClassMatcher.create()
                            .className(name, matchType, ignoreCase),
                    )
                }
                val results = bridge.findClass(find)
                val arr = JSONArray()
                results.take(limit).forEach { c ->
                    arr.put(JSONObject()
                        .put("class", c.name)
                        .put("simpleName", c.simpleName)
                        .put("sourceFile", c.sourceFile ?: ""))
                }
                resultJson(action, features, results.size, arr)
            }

            // 类级结构查询（2026-09-14 接入，此前 DexKit 的类层级/注解能力全部
            // 吃灰）：广告 SDK 分析的高频查询——按基类找全部子类、按接口找实现、
            // 按注解找挂点（@JavascriptInterface/@Keep/@OnClick 等）。
            "class_by_superclass" -> {
                // D2（2026-09-21）：调用方按其他工具的习惯传 `className` 找子类是很自然的
                // （"找这个类的子类"），而这里只认 keyword，于是回"缺少 keyword"像是参数
                // 写错了。className 在本动作里没有别的语义（不是查询维度），直接当别名。
                val name = keywords.firstOrNull()
                    ?: features.className.takeIf(String::isNotBlank)
                    ?: return err(
                        "INVALID_ARGUMENT",
                        "class_by_superclass 需要父类名：传 keyword（或 className，二者等价），" +
                            "如 com.bytedance.sdk.ads.base.BaseAdActivity",
                        "keyword",
                    )
                val find = FindClass.create().apply {
                    if (pkgPrefix.isNotBlank()) searchPackages(pkgPrefix)
                    matcher(
                        ClassMatcher.create()
                            .superClass(name, matchType, ignoreCase),
                    )
                }
                val results = bridge.findClass(find)
                val arr = JSONArray()
                results.take(limit).forEach { c ->
                    arr.put(JSONObject()
                        .put("class", c.name)
                        .put("simpleName", c.simpleName)
                        .put("sourceFile", c.sourceFile ?: ""))
                }
                resultJson(action, features, results.size, arr)
            }

            "class_by_interface", "class_by_interfaces" -> {
                // D2 同款别名：单个接口名也可以传 className。
                val interfaceNames = keywords.ifEmpty {
                    listOfNotNull(features.className.takeIf(String::isNotBlank))
                }
                if (interfaceNames.isEmpty()) return err(
                    "INVALID_ARGUMENT",
                    "class_by_interface 需要接口名：传 keyword（或 className，二者等价；" +
                        "多接口用 keywords 数组）",
                    "keyword",
                )
                val find = FindClass.create().apply {
                    if (pkgPrefix.isNotBlank()) searchPackages(pkgPrefix)
                    matcher(
                        ClassMatcher.create().interfaces(
                            InterfacesMatcher().interfaces(
                                interfaceNames.map {
                                    ClassMatcher.create().className(it, matchType, ignoreCase)
                                },
                            ),
                        ),
                    )
                }
                val results = bridge.findClass(find)
                val arr = JSONArray()
                results.take(limit).forEach { c ->
                    arr.put(JSONObject()
                        .put("class", c.name)
                        .put("simpleName", c.simpleName)
                        .put("sourceFile", c.sourceFile ?: ""))
                }
                resultJson(action, features, results.size, arr)
            }

            "class_by_annotation" -> {
                if (keywords.isEmpty()) return err(
                    "INVALID_ARGUMENT",
                    "class_by_annotation 需要 keyword=注解类型名（如 Landroid/webkit/JavascriptInterface; 或 Contains 风格 JavascriptInterface）",
                    "keyword",
                )
                val find = FindClass.create().apply {
                    if (pkgPrefix.isNotBlank()) searchPackages(pkgPrefix)
                    matcher(
                        ClassMatcher.create().annotations(
                            AnnotationsMatcher().annotations(
                                keywords.map {
                                    AnnotationMatcher.create().type(it, matchType, ignoreCase)
                                },
                            ),
                        ),
                    )
                }
                val results = bridge.findClass(find)
                val arr = JSONArray()
                results.take(limit).forEach { c ->
                    arr.put(JSONObject()
                        .put("class", c.name)
                        .put("simpleName", c.simpleName)
                        .put("sourceFile", c.sourceFile ?: ""))
                }
                resultJson(action, features, results.size, arr)
            }

            "method_by_annotation" -> {
                if (keywords.isEmpty()) return err(
                    "INVALID_ARGUMENT",
                    "method_by_annotation 需要 keyword=注解类型名（如 JavascriptInterface）",
                    "keyword",
                )
                val find = FindMethod.create().apply {
                    if (pkgPrefix.isNotBlank()) searchPackages(pkgPrefix)
                    matcher(
                        MethodMatcher.create().annotations(
                            AnnotationsMatcher().annotations(
                                keywords.map {
                                    AnnotationMatcher.create().type(it, matchType, ignoreCase)
                                },
                            ),
                        ),
                    )
                }
                val results = bridge.findMethod(find)
                val arr = JSONArray()
                results.take(limit).forEach { m ->
                    arr.put(JSONObject()
                        .put("class", m.className)
                        .put("method", m.methodName)
                        .put("descriptor", m.descriptor)
                        .put("qualifiedId", canonicalMethodQid(m.className, m.methodName, m.descriptor))
                        .put("returnType", m.returnTypeName)
                        .put("params", JSONArray(m.paramTypeNames)))
                }
                resultJson(action, features, results.size, arr,
                    matchTypeName = matchTypeName(matchType))
            }

            else -> err("UNKNOWN_ACTION", "未知 action: $action", "action", action)
        }
    }

    private fun autoSearch(
        bridge: DexKitBridge,
        features: MethodFeatures,
        matchType: StringMatchType,
        ignoreCase: Boolean,
        pkgPrefix: String,
        limit: Int,
    ): JSONObject {
        val strictFind = FindMethod.create().apply {
            if (pkgPrefix.isNotBlank()) searchPackages(pkgPrefix)
            matcher(methodFeatureMatcher(features, matchType, ignoreCase))
        }
        val strict = bridge.findMethod(strictFind)
        if (strict.isNotEmpty()) {
            val rows = JSONArray(strict.take(limit).map { method -> methodJson(
                method.className,
                method.methodName,
                method.descriptor,
                method.returnTypeName,
                method.paramTypeNames,
            ).put("matchedDimensions", JSONArray(featureDimensions(features)))
                .put("candidateStatus", "strict_match")
            })
            return resultJson(
                "auto", features, strict.size, rows,
                resolution = "strict_intersection", strictMatch = true,
            )
        }

        // 真机实测（2026-09-15）：auto 原先只做 method 维度探测，`keyword=WXManager`
        // 返回 0 命中而 `action=class_by_name` 能命中 4 个类——类名线索在 auto 下
        // 完全丢失，属能力缺口而非使用问题。这里补 class 侧独立探测（类名/父类/
        // 接口/注解/用串），命中后并入 candidates 名列前茅。
        val typeCandidates = linkedMapOf<String, AutoTypeCandidate>()
        typeProbes(features, matchType, ignoreCase).forEach { (dimension, evidence, finder) ->
            val find = FindClass.create().apply {
                if (pkgPrefix.isNotBlank()) searchPackages(pkgPrefix)
                matcher(finder)
            }
            bridge.findClass(find).take(AUTO_RESULTS_PER_PROBE).forEach { cls ->
                val candidate = typeCandidates.getOrPut(cls.name) {
                    AutoTypeCandidate(cls.name, cls.simpleName, cls.sourceFile ?: "")
                }
                candidate.dimensions += dimension
                candidate.evidence += "$dimension:$evidence"
            }
        }

        val probes = mutableListOf<Triple<String, String, MethodMatcher>>()
        fun addProbe(dimension: String, evidence: String, matcher: MethodMatcher) {
            if (probes.size < AUTO_PROBE_BUDGET) probes += Triple(dimension, evidence, matcher)
        }
        if (features.className.isNotBlank()) addProbe(
            "class_name", features.className,
            MethodMatcher.create().declaredClass(features.className, matchType, ignoreCase),
        )
        if (features.methodName.isNotBlank()) addProbe(
            "method_name", features.methodName,
            MethodMatcher.create().name(features.methodName, matchType, ignoreCase),
        )
        features.fieldNames.take(1).forEach { value -> addProbe(
            "used_fields", value,
            MethodMatcher.create().addUsingField(FieldMatcher.create().name(value, matchType, ignoreCase)),
        ) }
        features.invokedMethodNames.take(1).forEach { value -> addProbe(
            "invoked_methods", value,
            MethodMatcher.create().addInvoke(MethodMatcher.create().name(value, matchType, ignoreCase)),
        ) }
        features.strings.take(1).forEach { value -> addProbe(
            "used_strings", value,
            MethodMatcher.create().usingStrings(listOf(value), matchType, ignoreCase),
        ) }
        features.numbers.take(1).forEach { value -> addProbe(
            "used_numbers", value.toString(),
            MethodMatcher.create().usingNumbers(listOf(value)),
        ) }
        if (features.opNames.isNotEmpty()) addProbe(
            "opcode_sequence", features.opNames.joinToString("|"),
            MethodMatcher.create().opNames(features.opNames, OpCodeMatchType.Contains),
        )
        features.fieldNames.drop(1).forEach { value -> addProbe(
            "used_fields", value,
            MethodMatcher.create().addUsingField(FieldMatcher.create().name(value, matchType, ignoreCase)),
        ) }
        features.invokedMethodNames.drop(1).forEach { value -> addProbe(
            "invoked_methods", value,
            MethodMatcher.create().addInvoke(MethodMatcher.create().name(value, matchType, ignoreCase)),
        ) }
        features.strings.drop(1).forEach { value -> addProbe(
            "used_strings", value,
            MethodMatcher.create().usingStrings(listOf(value), matchType, ignoreCase),
        ) }
        features.numbers.drop(1).forEach { value -> addProbe(
            "used_numbers", value.toString(),
            MethodMatcher.create().usingNumbers(listOf(value)),
        ) }

        val candidates = linkedMapOf<String, AutoCandidate>()
        probes.forEach { (dimension, evidence, matcher) ->
            val find = FindMethod.create().apply {
                if (pkgPrefix.isNotBlank()) searchPackages(pkgPrefix)
                matcher(matcher)
            }
            bridge.findMethod(find).take(AUTO_RESULTS_PER_PROBE).forEach { method ->
                val qid = canonicalMethodQid(method.className, method.methodName, method.descriptor)
                val candidate = candidates.getOrPut(qid) {
                    AutoCandidate(
                        method.className,
                        method.methodName,
                        method.descriptor,
                        method.returnTypeName,
                        method.paramTypeNames,
                    )
                }
                candidate.dimensions += dimension
                candidate.evidence += "$dimension:$evidence"
            }
        }
        val ranked = candidates.values.sortedWith(
            compareByDescending<AutoCandidate> { it.dimensions.size }
                .thenByDescending { it.evidence.size }
                .thenBy { canonicalMethodQid(it.className, it.methodName, it.descriptor) },
        )
        val rows = JSONArray(ranked.take(limit).map { candidate ->
            val crossEvidence = candidate.dimensions.size >= 2
            methodJson(
                candidate.className,
                candidate.methodName,
                candidate.descriptor,
                candidate.returnType,
                candidate.params,
            ).put("matchedDimensions", JSONArray(candidate.dimensions.toList()))
                .put("matchedEvidence", JSONArray(candidate.evidence.toList()))
                .put("evidenceScore", autoCandidateScore(candidate.dimensions.size, candidate.evidence.size))
                .put("candidateStatus", if (crossEvidence) "cross_evidence_candidate" else "single_evidence_clue")
        })
        // 类侧命中：与 method 结果同信封（rows 是异构数组，调用方按
        // `method` 字段是否存在即可判别条目类型），避免再开一个结果通道。
        val typeRows = JSONArray(
            typeCandidates.values
                .sortedWith(
                    compareByDescending<AutoTypeCandidate> { it.dimensions.size }
                        .thenByDescending { it.evidence.size }
                        .thenBy { it.className },
                )
                .take(limit)
                .map { candidate ->
                    JSONObject()
                        .put("class", candidate.className)
                        .put("simpleName", candidate.simpleName)
                        .put("sourceFile", candidate.sourceFile)
                        .put("matchedDimensions", JSONArray(candidate.dimensions.toList()))
                        .put("matchedEvidence", JSONArray(candidate.evidence.toList()))
                        .put("evidenceScore", autoCandidateScore(candidate.dimensions.size, candidate.evidence.size))
                        .put("candidateStatus", if (candidate.dimensions.size >= 2) {
                            "cross_evidence_candidate"
                        } else {
                            "single_evidence_clue"
                        })
                },
        )
        val payload = resultJson(
            "auto", features, ranked.size, rows,
            resolution = when {
                ranked.isEmpty() && typeRows.length() == 0 -> "not_found"
                ranked.isEmpty() -> "ranked_partial_evidence"
                else -> "ranked_partial_evidence"
            },
            strictMatch = false,
        )
        payload.put("classTotal", typeCandidates.size)
        payload.put("classReturned", typeRows.length())
        payload.put("classes", typeRows)
        payload.put("searchedDimensions", JSONArray(
            (typeCandidates.values.flatMap { it.dimensions } + candidates.values.flatMap { it.dimensions })
                .distinct(),
        ))
        return payload
    }

    private data class AutoTypeCandidate(
        val className: String,
        val simpleName: String,
        val sourceFile: String,
        val dimensions: MutableSet<String> = linkedSetOf(),
        val evidence: MutableSet<String> = linkedSetOf(),
    )

    /**
     * auto 的 class 侧探测清单：同一份 keyword 在「类名 / 父类 / 接口 / 注解 /
     * 用串」五个维度各自独立试探。DexKit 单个 ClassMatcher 内多条件是 AND，
     * 所以必须拆成独立探测再合并（与 method 侧 probes 同思路）。
     */
    private fun typeProbes(
        features: MethodFeatures,
        matchType: StringMatchType,
        ignoreCase: Boolean,
    ): List<Triple<String, String, ClassMatcher>> {
        val probes = mutableListOf<Triple<String, String, ClassMatcher>>()
        fun add(dimension: String, evidence: String, matcher: ClassMatcher) {
            if (probes.size < AUTO_PROBE_BUDGET) probes += Triple(dimension, evidence, matcher)
        }
        if (features.className.isNotBlank()) add(
            "class_name", features.className,
            ClassMatcher.create().className(features.className, matchType, ignoreCase),
        )
        // keyword 同时是「类名的常见写法」——auto 不缺 keyword 时把它当类名探一次，
        // 这是 WXManager 类问题不再漏命的根因。
        features.strings.forEach { value ->
            add("class_name", value, ClassMatcher.create().className(value, matchType, ignoreCase))
            add("super_class", value, ClassMatcher.create().superClass(value, matchType, ignoreCase))
            add("interface", value, classMatcherWithInterfaces(value, matchType, ignoreCase))
            add(
                "annotation", value,
                ClassMatcher.create().annotations(
                    AnnotationsMatcher().annotations(
                        listOf(AnnotationMatcher.create().type(value, matchType, ignoreCase)),
                    ),
                ),
            )
            add("used_strings", value, ClassMatcher.create().usingStrings(listOf(value), matchType, ignoreCase))
        }
        features.fieldNames.forEach { value ->
            add(
                "declared_field", value,
                ClassMatcher.create().addFieldForName(value, matchType, ignoreCase),
            )
        }
        return probes
    }

    private fun classMatcherWithInterfaces(
        name: String,
        matchType: StringMatchType,
        ignoreCase: Boolean,
    ): ClassMatcher = ClassMatcher.create().interfaces(
        InterfacesMatcher().interfaces(
            listOf(ClassMatcher.create().className(name, matchType, ignoreCase)),
        ),
    )

    private fun methodFeatureMatcher(
        features: MethodFeatures,
        matchType: StringMatchType,
        ignoreCase: Boolean,
    ): MethodMatcher = MethodMatcher.create().apply {
        if (features.strings.isNotEmpty()) usingStrings(features.strings, matchType, ignoreCase)
        if (features.numbers.isNotEmpty()) usingNumbers(features.numbers)
        if (features.className.isNotBlank()) declaredClass(features.className, matchType, ignoreCase)
        if (features.methodName.isNotBlank()) name(features.methodName, matchType, ignoreCase)
        features.fieldNames.forEach { fieldName ->
            addUsingField(FieldMatcher.create().name(fieldName, matchType, ignoreCase))
        }
        features.invokedMethodNames.forEach { invokedName ->
            addInvoke(MethodMatcher.create().name(invokedName, matchType, ignoreCase))
        }
        if (features.opNames.isNotEmpty()) opNames(features.opNames, OpCodeMatchType.Contains)
    }

    private fun methodJson(
        className: String,
        methodName: String,
        descriptor: String,
        returnType: String,
        params: List<String>,
    ): JSONObject = JSONObject()
        .put("class", className)
        .put("method", methodName)
        .put("descriptor", descriptor)
        .put("qualifiedId", canonicalMethodQid(className, methodName, descriptor))
        .put("returnType", returnType)
        .put("params", JSONArray(params))

    private fun featureDimensions(features: MethodFeatures): List<String> = buildList {
        if (features.className.isNotBlank()) add("class_name")
        if (features.methodName.isNotBlank()) add("method_name")
        if (features.fieldNames.isNotEmpty()) add("used_fields")
        if (features.strings.isNotEmpty()) add("used_strings")
        if (features.numbers.isNotEmpty()) add("used_numbers")
        if (features.opNames.isNotEmpty()) add("opcode_sequence")
        if (features.invokedMethodNames.isNotEmpty()) add("invoked_methods")
    }

    internal fun autoCandidateScore(dimensionCount: Int, evidenceCount: Int): Int =
        dimensionCount.coerceAtLeast(0) * 100 + evidenceCount.coerceAtLeast(0)

    /** 点分类名 + 方法描述符 → 权威 qualifiedId（Lpkg/Class;->name(params)ret），
     *  下游 dex_xref/smali_read/patch 均可直接原样消费，消除模型手工拼签名。 */
    internal fun canonicalMethodQid(className: String, methodName: String, descriptor: String): String {
        val normalized = descriptor.trim()
        if (normalized.startsWith("L") && normalized.contains(";->")) return normalized
        return "L${className.replace('.', '/')};->$methodName$normalized"
    }

    internal fun parseKeywords(raw: String): List<String> = splitTerms(raw, '|', '\n')

    /**
     * 词条切分：`|`/换行 等是分隔符，但**前面带反斜杠的按字面收**（2026-09-21 D24）。
     *
     * 独立复验发现：目标串本身含 `|`（如正则片段 `(?i:http|https|rtsp)://`）时，
     * 过去无条件按 `|` 拆成多段 —— `matchType=Equals` 于是退化成"三个片段各自精确
     * 匹配"，回 0 命中；而当时刚加的 `stringMatchNote` 正好教人"要用 Equals 复核"，
     * 两者叠加会得出**错误的"无引用"结论**。现在写成 `\|` 即可让竖线作为字面字符
     * 参与匹配（`\\` 保持字面反斜杠，Windows 路径不受影响）。
     */
    private fun splitTerms(raw: String, vararg separators: Char): List<String> {
        val terms = mutableListOf<String>()
        val current = StringBuilder()
        var i = 0
        while (i < raw.length) {
            val ch = raw[i]
            if (ch == '\\' && i + 1 < raw.length && separators.contains(raw[i + 1])) {
                current.append(raw[i + 1])
                i += 2
                continue
            }
            if (separators.contains(ch)) {
                terms.add(current.toString())
                current.clear()
            } else {
                current.append(ch)
            }
            i++
        }
        terms.add(current.toString())
        return terms.map(String::trim).filter(String::isNotBlank).distinct().take(16)
    }

    /** 匹配语义的名字（回显给调用方：Contains 与 Equals 的结论含义不同）。 */
    private fun matchTypeName(matchType: StringMatchType): String = when (matchType) {
        StringMatchType.Equals -> "Equals"
        StringMatchType.StartsWith -> "StartsWith"
        StringMatchType.EndsWith -> "EndsWith"
        else -> "Contains"
    }

    internal fun parseFeatureTerms(raw: String): List<String> = splitTerms(raw, '|', ',', '\n')

    private fun parseFeatureTerms(args: JSONObject, vararg keys: String): List<String> {
        val values = mutableListOf<String>()
        keys.forEach { key ->
            args.optJSONArray(key)?.let { array ->
                (0 until array.length()).forEach { index -> values += array.optString(index) }
            }
            if (args.opt(key) is String) values += args.optString(key)
        }
        return parseFeatureTerms(values.joinToString("|"))
    }

    internal fun parseNumbers(args: JSONObject): List<Number> {
        val values = mutableListOf<Any?>()
        val array = args.optJSONArray("numbers") ?: args.optJSONArray("values")
        if (array != null) (0 until array.length()).forEach { values += array.opt(it) }
        val raw = args.optString("numbers").ifBlank { args.optString("values") }
        if (raw.isNotBlank()) values.addAll(raw.split('|', ',', ';', '\n'))
        return values.mapNotNull { value -> when (value) {
            is Number -> value
            else -> parseNumber(value?.toString().orEmpty())
        } }.distinctBy(Number::toString).take(16)
    }

    private fun parseNumber(raw: String): Number? {
        val value = raw.trim().lowercase()
        return when {
            value.startsWith("-0x") -> value.removePrefix("-0x").toLongOrNull(16)?.let { -it }
            value.startsWith("0x") -> value.removePrefix("0x").toLongOrNull(16)
            value.contains('.') || value.contains('e') -> value.toDoubleOrNull()
            else -> value.toLongOrNull()
        }
    }

    private fun resultJson(
        action: String,
        features: MethodFeatures,
        total: Int,
        arr: JSONArray,
        resolution: String = "direct_query",
        strictMatch: Boolean = true,
        matchTypeName: String = "",
    ): JSONObject {        val keywords = features.strings
        val numbers = features.numbers
        val dimensions = featureDimensions(features)
        // 空结果给结构化引导：0 命中 ≠ 方法不存在（混淆/Flutter 场景常态），
        // 原先返回的固定 hint 与命中场景绑定，对空结果零指引。
        val flutterApk = flutterApkFlag.get()
        val hint = if (total > 0) {
            "method 结果的 qualifiedId 可原样传给 dex_xref / class_outline / smali_read / patch_apk_dex_methods，不要手工改写或重拼签名"
        } else if (flutterApk) {
            // D17：Flutter 包只给一条正确路径。此前一律罗列 5~6 条 DEX 侧重试
            // 建议（换关键词/换 action/类名浏览/池诊断），对"业务逻辑根本不在
            // DEX 里"的包全是噪声，实测把调用方留在 DEX 层反复试探。
            "0 命中是**预期结果**：本包是 Flutter 包（lib/*/libflutter.so 存在），业务代码在 Dart AOT 里，DEX 层搜不到会员/试用/广告闸门是正常现象。" +
                "唯一正确路径：切到 Dart 层 —— so_analyze(action=blutter, blutterAction=search, scope=pp, query=<业务词>) 找对象池偏移 → " +
                "blutterAction=pool 读对象原文与引用 VA → so_analyze(action=disasm, addr=<引用VA>) 读原始反汇编判读写方向。" +
                "不要继续在 DEX 层换关键词或换 action 重试，也不要据此断定目标不存在。" +
                "（DEX 层仍有意义的情形只有：加固壳/签名校验/Manifest 组件等与 Dart 业务无关的旁路目标。）"
        } else {
            "0 命中不等于目标不存在。按序换路径：1) 用更短/更通用的关键词重试 dex_search" +
                "（matchType=Contains + ignoreCase=true，并去掉 packagePrefix 限制）；" +
                "2) 换 action（method_by_string ↔ class_by_string ↔ method_by_name/class_by_name）；" +
                "3) 界面文案类线索先 string_scan 拿真实字节串；" +
                "4) 报告 flutterApp.detected=true 时改走 so_analyze(action=blutter)——" +
                "Flutter 业务在 dex 搜不到是正常现象；5) 已知类名时用 class_outline 浏览结构；" +
                "6) 怀疑「串存在但没被方法引用」时，用 patch_apk_dex_strings(dryRun=true) 做池内诊断：" +
                "它区分 ABSENT（池里根本没有）与 PRESENT_NO_CONST_REF（池里有但无 const-string 引用，" +
                "常见于拼接串/死条目——这类串 DexKit 也关联不到方法，两处结论不矛盾）。" +
                "本动作只回答「哪个方法引用了这个串」，不回答「串在不在池里」。"
        }
        val firstQualifiedId = arr.optJSONObject(0)?.optString("qualifiedId").orEmpty()
        val nextActions = JSONArray()
        if (firstQualifiedId.isNotBlank()) {
            nextActions.put(JSONObject().put("tool", "dex_xref").put("purpose", "调用处与流程图")
                .put("arguments", JSONObject().put("target", firstQualifiedId)
                    .put("direction", "both").put("includeGraph", true)))
            nextActions.put(JSONObject().put("tool", "dex_xref").put("purpose", "重写实现")
                .put("arguments", JSONObject().put("target", firstQualifiedId)
                    .put("direction", "overrides").put("includeGraph", true)))
            nextActions.put(JSONObject().put("tool", "smali_read").put("purpose", "真实代码验证")
                .put("arguments", JSONObject().put("qualifiedId", firstQualifiedId)))
        }
        return ok(JSONObject()
            .put("tool", "dex_search")
            .put("action", action)
            .put("keyword", keywords.firstOrNull() ?: JSONObject.NULL)
            .put("keywords", JSONArray(keywords))
            .put("numbers", JSONArray(numbers))
            .put("className", features.className.takeIf(String::isNotBlank) ?: JSONObject.NULL)
            .put("methodName", features.methodName.takeIf(String::isNotBlank) ?: JSONObject.NULL)
            .put("fieldNames", JSONArray(features.fieldNames))
            .put("invokedMethodNames", JSONArray(features.invokedMethodNames))
            .put("opNames", JSONArray(features.opNames))
            .put("featureDimensions", JSONArray(dimensions))
            .put("featureDimensionCount", dimensions.size)
            .put("resolution", resolution)
            .put("strictMatch", strictMatch)
            .put("querySpecificity", when {
                dimensions.size >= 4 -> "high"
                dimensions.size >= 2 -> "medium"
                else -> "low"
            })
            .put("needsCodeAndXrefVerification", true)
            .put("matchLogic", when {
                action == "auto" && strictMatch -> "all_supplied_features_in_same_method"
                action == "auto" -> "ranked_by_independent_evidence_dimensions"
                action == "method_by_features" -> "all_supplied_features_in_same_method"
                keywords.size > 1 -> "all_strings_in_same_candidate"
                numbers.isNotEmpty() -> "all_numbers_in_same_method"
                else -> "single_string"
            })
            .put("total", total)
            .put("returned", arr.length())
            .put("results", arr)
            .put("nextActions", nextActions)
            .put("hint", hint)
            .also { body ->
                // 匹配语义必须显式回显（2026-09-21 独立复验 D16 改判）：
                // `matchType` 默认 **Contains**，于是"某方法的池条目**包含**该串"
                // 会被读成"该串被引用"——而 patch_apk_dex_strings 按池条目**精确**
                // 比对，同一事实两工具给出相反结论（真机：`(?i:http|https|rtsp)://`
                // 在 dex_search 命中、在 patch 工具回 PRESENT_NO_CONST_REF。
                // 实际那串只是超长正则常量的子串，patch 工具是对的）。
                if (matchTypeName.isNotEmpty()) {
                    body.put("stringMatchType", matchTypeName)
                    body.put(
                        "stringMatchNote",
                        if (matchTypeName == "Contains") {
                            "Contains 语义：命中 = 该方法使用的某个字符串池条目**包含**该关键词，" +
                                "不代表该串本身是独立的 const-string 条目。要交给 patch_apk_dex_strings " +
                                "必须先用 matchType=Equals 复核（否则会得到 PRESENT_NO_CONST_REF，" +
                                "那不是工具的假阴性）。关键词本身含竖线时写成 \\| （否则会被当多词分隔符拆开，" +
                                "Equals 会退化成逐片段匹配而误报 0 命中）。"
                        } else {
                            "匹配语义：$matchTypeName（精确/前后缀）。关键词含竖线请写 \\|，" +
                                "否则会被拆成多段、按多段匹配（Equals 下会误报 0 命中）。"
                        },
                    )
                }
            })
    }

    private const val AUTO_PROBE_BUDGET = 24
    private const val AUTO_RESULTS_PER_PROBE = 200
}
