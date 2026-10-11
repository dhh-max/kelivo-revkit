package com.shinegirls.apkadremovereditor.core

import android.content.Context
import java.io.File

/**
 * 一键去广告引擎（仅 DEX 模式）。
 *
 * 仅通过直接修补 DEX 字节码移除广告调用，不再扫描或修改布局文件、
 * AndroidManifest 或 assets/lib 资源。
 *
 * 崩溃防护：
 * - 每个 DEX 文件独立 try-catch
 * - OOM 时自动 GC 并跳过当前文件
 *
 * 广告特征从外部 JSON 配置文件加载（AdPatternConfig），不再硬编码在 DEX 中。
 * DEX编辑模式：直接使用 DexPatcher 操作 DEX 字节码，无需 smali 反编译/回编译。
 */
object AdRemover {

    /**
     * 大 DEX 预检阈值（单位：字节）。超过该阈值时提示用户，避免误以为卡死。
     */
    private const val LARGE_DEX_THRESHOLD: Long = 10L * 1024 * 1024

    /**
     * 主入口：仅通过 DEX 修补去广告，返回处理报告。
     *
     * @param extractDir 解包后的APK目录
     * @param context    用于加载 assets 内置默认配置
     * @param logger     实时日志回调，用于UI实时显示处理进度
     * @return 处理报告文本
     */
    fun removeAds(extractDir: File, context: Context, logger: Logger? = null): String {
        val log = logger ?: {}
        val report = StringBuilder()
        val totalStartTime = System.currentTimeMillis()

        // ========== 从配置文件加载广告特征 ==========
        log("━━━ 加载广告特征配置 ━━━")
        val config = AdPatternConfig.loadConfig(context)
        val configFile = AdPatternConfig.getConfigFile()

        log("  配置文件: ${configFile.absolutePath}")
        log("  广告SDK包名: ${config.sdkPackages.size} 条")
        log("  广告类名关键词: ${config.classKeywords.size} 条")
        log("  广告方法名: ${config.methodPatterns.size} 条")
        log("  特征总计: ${config.totalCount()} 条")

        if (config.totalCount() == 0) {
            log("  [警告] 广告特征配置为空，跳过去广告处理")
            return "广告特征配置为空，请在设置中添加广告特征。"
        }

        val allAdPatterns = config.allAdPatterns()
        val adMethodPatterns = config.methodPatterns
        val adUrlPatterns = config.urlPatterns
        // 强制返回 true 的方法名（解锁 VIP/会员/专业版判定方法）
        val forceTrueMethods = config.forceTrueMethodNames

        if (forceTrueMethods.isNotEmpty()) {
            log("  强制返回true方法名: ${forceTrueMethods.size} 条")
        }

        var totalPatchedClasses = 0
        var totalNeutralizedMethods = 0
        var totalNeutralizedUrls = 0
        var totalForcedTrue = 0

        // ---------- 阶段1: 直接修补DEX文件 ----------
        val phase1Start = System.currentTimeMillis()
        log("━━━ 阶段 1/1: DEX 直接修补 ━━━")
        report.appendLine("=== DEX 直接修补 ===")

        val dexFiles = extractDir.listFiles { f ->
            f.isFile && f.name.endsWith(".dex")
        } ?: emptyArray()

        if (dexFiles.isNotEmpty()) {
            log("找到 ${dexFiles.size} 个 DEX 文件: ${dexFiles.joinToString { it.name }}")

            for (dexFile in dexFiles.sortedBy { it.name }) {
                log("▶ 正在处理: ${dexFile.name} (${formatSize(dexFile.length())})")
                report.appendLine("  ${dexFile.name}:")

                // 大 DEX 预检：体积超过阈值时提示，避免用户误以为卡死
                if (dexFile.length() > LARGE_DEX_THRESHOLD) {
                    log("  [提示] 该 DEX 较大，处理耗时可能较长，请耐心等待...")
                }

                try {
                    val result = DexPatcher.patchDex(
                        dexFile,
                        allAdPatterns,
                        adMethodPatterns,
                        urlPatterns = adUrlPatterns,
                        forceTrueMethodNames = forceTrueMethods,
                        logger = { msg ->
                            log(msg)
                            report.appendLine(msg)
                        }
                    )

                    totalPatchedClasses += result.patchedClasses
                    totalNeutralizedMethods += result.neutralizedMethods
                    totalNeutralizedUrls += result.neutralizedUrlStrings
                    totalForcedTrue += result.forcedTrueMethods

                    report.appendLine("    广告类置空: ${result.patchedClasses}")
                    report.appendLine("    广告方法置空: ${result.neutralizedMethods}")
                    if (result.neutralizedUrlStrings > 0) {
                        report.appendLine("    广告链接置空: ${result.neutralizedUrlStrings}")
                    }
                    if (result.forcedTrueMethods > 0) {
                        report.appendLine("    强制返回true: ${result.forcedTrueMethods}")
                    }

                    log("  ✓ ${dexFile.name} 完成: 类置空=${result.patchedClasses}, 方法置空=${result.neutralizedMethods}, 链接置空=${result.neutralizedUrlStrings}")
                } catch (e: OutOfMemoryError) {
                    log("  ✗ ${dexFile.name} 内存不足: ${e.message}")
                    report.appendLine("  ${dexFile.name} 内存不足: ${e.message}")
                } catch (e: Exception) {
                    log("  ✗ ${dexFile.name} 修补失败: ${e.message}")
                    report.appendLine("  ${dexFile.name} 修补失败: ${e.message}")
                } finally {
                    // 每个 DEX 处理完主动 GC，释放上一个 DEX 的分析对象，
                    // 避免多 DEX 顺序处理时内存逐步累积
                    System.gc()
                }
            }
        } else {
            log("未找到 DEX 文件")
        }

        logPhaseTime("DEX修补", phase1Start, log)

        // ---------- 阶段2: 清理广告SDK原生库文件 ----------
        val totalCleanedSdkFiles = cleanAdSdkLibs(extractDir, config.sdkPackages, log, report)

        // ---------- 汇总报告 ----------
        val totalTime = System.currentTimeMillis() - totalStartTime

        log("━━━ 处理汇总 ━━━")
        report.appendLine("=== 处理汇总 ===")
        report.appendLine("  配置特征总数: ${config.totalCount()} 条")
        report.appendLine("  广告SDK类置空: $totalPatchedClasses 个")
        report.appendLine("  广告方法置空: $totalNeutralizedMethods 个")
        report.appendLine("  广告链接置空: $totalNeutralizedUrls 处")
        report.appendLine("  强制返回true: $totalForcedTrue 个")
        report.appendLine("  广告SDK库文件清理: $totalCleanedSdkFiles 个")
        report.appendLine("  总耗时: ${totalTime}ms")

        log("  广告SDK类置空: $totalPatchedClasses")
        log("  广告方法置空: $totalNeutralizedMethods")
        log("  广告链接置空: $totalNeutralizedUrls")
        log("  强制返回true: $totalForcedTrue")
        log("  广告SDK库文件清理: $totalCleanedSdkFiles")
        log("  总耗时: ${totalTime}ms")
        log("━━━ 去广告处理完成 ━━━")

        return report.toString()
    }

    // ========== 阶段耗时日志 ==========
    private fun logPhaseTime(phaseName: String, startTime: Long, log: Logger) {
        val elapsed = System.currentTimeMillis() - startTime
        log("  ⏱ $phaseName 耗时: ${elapsed}ms")
    }

    private fun formatSize(bytes: Long): String {
        return when {
            bytes < 1024 -> "${bytes}B"
            bytes < 1024 * 1024 -> "${bytes / 1024}KB"
            else -> String.format("%.1fMB", bytes / (1024.0 * 1024.0))
        }
    }

    /**
     * 清理广告SDK对应的原生库文件（lib 目录下的 libXXX.so）。
     *
     * 通过广告SDK包名推导常见的 .so 库名关键词（如 adsdk、ttad、gdt、pangle、admob 等），
     * 遍历 APK 解压根目录下的 lib 目录，删除匹配的 .so 文件，从而"移除广告SDK文件"。
     *
     * @return 清理的文件数量
     */
    private fun cleanAdSdkLibs(
        extractDir: File,
        sdkPackages: List<String>,
        log: Logger,
        report: StringBuilder
    ): Int {
        log("━━━ 阶段2: 清理广告SDK原生库文件 ━━━")
        report.appendLine("=== 广告SDK原生库清理 ===")

        val libDir = File(extractDir, "lib")
        if (!libDir.exists() || !libDir.isDirectory) {
            log("  未找到 lib 目录，跳过原生库清理")
            return 0
        }

        // 从广告SDK包名提取库名关键词
        val libKeywords = buildSdkLibKeywords(sdkPackages)
        if (libKeywords.isEmpty()) {
            log("  无广告SDK库名关键词，跳过")
            return 0
        }

        var cleaned = 0
        val abiDirs = libDir.listFiles { f -> f.isDirectory } ?: emptyArray()
        for (abiDir in abiDirs) {
            val soFiles = abiDir.listFiles { f -> f.isFile && f.name.endsWith(".so") } ?: emptyArray()
            for (soFile in soFiles) {
                val libName = soFile.name.lowercase()
                if (libKeywords.any { libName.contains(it) }) {
                    log("  [广告SDK库] 删除 ${abiDir.name}/${soFile.name}")
                    report.appendLine("  删除 lib/${abiDir.name}/${soFile.name}")
                    if (soFile.delete()) {
                        cleaned++
                    } else {
                        log("  [警告] 删除失败: ${soFile.name}")
                    }
                }
            }
        }

        log("  广告SDK原生库清理完成: $cleaned 个文件")
        return cleaned
    }

    /**
     * 从广告SDK包名集合推导原生库 .so 文件名关键词。
     * 例如 com.bytedance.sdk.openadsdk -> pangle/ttad, com.qq.e.ads -> gdt 等。
     */
    private fun buildSdkLibKeywords(sdkPackages: List<String>): Set<String> {
        val keywords = mutableSetOf<String>()
        val joined = sdkPackages.joinToString(" ").lowercase()

        // 常见广告SDK的原生库命名关键词
        val knownMappings = mapOf(
            "bytedance" to listOf("ttad", "pangle", "openadsdk", "bytedance"),
            "pangle" to listOf("pangle", "ttad"),
            "qq.e" to listOf("gdt", "qqad", "gdtad"),
            "gdt" to listOf("gdt"),
            "baidu" to listOf("baidu", "mobads", "mobad"),
            "kuaishou" to listOf("kuaishou", "gdfp"),
            "unity3d" to listOf("unityads", "unity_ad"),
            "mintegral" to listOf("mintegral", "mbridge", "mtg"),
            "mobvista" to listOf("mobvista", "mtg"),
            "vungle" to listOf("vungle"),
            "chartboost" to listOf("chartboost"),
            "appnext" to listOf("appnext"),
            "inmobi" to listOf("inmobi"),
            "flurry" to listOf("flurry"),
            "adcolony" to listOf("adcolony"),
            "applovin" to listOf("applovin", "applvn"),
            "ironsource" to listOf("ironsource", "is_adapt"),
            "startapp" to listOf("startapp"),
            "smaato" to listOf("smaato"),
            "pubmatic" to listOf("pubmatic"),
            "amazon" to listOf("amazon", "amoad"),
            "yandex" to listOf("yandex"),
            "mytarget" to listOf("mytarget"),
            "huawei" to listOf("huawei_hms", "hms_ads"),
            "sigmob" to listOf("sigmob"),
            "anythink" to listOf("anythink", "topon"),
            "topon" to listOf("topon"),
            "facebook" to listOf("facebook", "fb_ads", "audience"),
            "admob" to listOf("admob", "gms"),
            "googleadb" to listOf("gms"),
            "appodeal" to listOf("appodeal"),
            "pollfish" to listOf("pollfish"),
            "tapjoy" to listOf("tapjoy"),
            "mopub" to listOf("mopub"),
            "pubnative" to listOf("pubnative"),
            "fyber" to listOf("fyber", "inneractive"),
            "oneway" to listOf("oneway")
        )

        for ((pkgFragment, libNames) in knownMappings) {
            if (joined.contains(pkgFragment)) {
                keywords.addAll(libNames)
            }
        }

        // 通用穷举：任何包含 "ad" 的 .so 库名关键词（保守，需与包名关联）
        // 仅当包名里明确含 adsdk/ad 时加入
        if (joined.contains("adsdk") || joined.contains("_ads")) {
            keywords.add("adsdk")
        }
        return keywords
    }
}