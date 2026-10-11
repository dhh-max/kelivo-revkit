package com.shinegirls.apkadremovereditor.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * 广告特征配置管理器（仅 DEX 相关分类）。
 *
 * 将广告特征以 JSON 配置文件形式存储在外部存储，而非硬编码在 DEX 中。
 * 用户可在设置界面中读取、显示、编辑、删除、添加和保存自定义广告特征。
 *
 * 配置文件路径: /storage/emulated/0/APKEditor/ad_patterns.json
 *
 * 配置结构（仅保留 DEX 修补所需的分类，布局/资源/权限相关分类已移除）:
 * {
 *   "sdk_packages": ["com.google.android.gms.ads", ...],
 *   "class_keywords": ["AdView", "AdActivity", ...],
 *   "method_patterns": ["loadAd", "showAd", ...],
 *   "url_patterns": ["googleads.g.doubleclick.net", ...],
 *   "ad_view_names": ["AdView", "BannerAd", ...],
 *   "ad_activities": ["AdActivity", "InterstitialAdActivity", ...],
 *   "ad_services": ["AdService", "DownloadService", ...],
 *   "ad_receivers": ["AdReceiver", "BootReceiver", ...],
 *   "force_true_methods": ["isVip", "isPro", "isPremium", ...]
 * }
 */
object AdPatternConfig {

    private const val CONFIG_DIR = "/storage/emulated/0/APKEditor"
    private const val CONFIG_FILE = "ad_patterns.json"

    // JSON 字段名
    private const val KEY_SDK_PACKAGES = "sdk_packages"
    private const val KEY_CLASS_KEYWORDS = "class_keywords"
    private const val KEY_METHOD_PATTERNS = "method_patterns"
    private const val KEY_URL_PATTERNS = "url_patterns"
    private const val KEY_AD_VIEW_NAMES = "ad_view_names"
    private const val KEY_AD_ACTIVITIES = "ad_activities"
    private const val KEY_AD_SERVICES = "ad_services"
    private const val KEY_AD_RECEIVERS = "ad_receivers"
    private const val KEY_FORCE_TRUE_METHODS = "force_true_methods"

    /**
     * 广告特征配置数据类。
     */
    data class AdPatterns(
        val sdkPackages: MutableList<String> = mutableListOf(),
        val classKeywords: MutableList<String> = mutableListOf(),
        val methodPatterns: MutableList<String> = mutableListOf(),
        val urlPatterns: MutableList<String> = mutableListOf(),
        val adViewNames: MutableList<String> = mutableListOf(),
        val adActivities: MutableList<String> = mutableListOf(),
        val adServices: MutableList<String> = mutableListOf(),
        val adReceivers: MutableList<String> = mutableListOf(),
        val forceTrueMethodNames: MutableList<String> = mutableListOf()
    ) {
        /**
         * 合并所有广告模式供 DexPatcher 匹配。
         * SDK包名(转换为斜杠格式) + 类名关键词 + Activity/Service/Receiver名称 + View名称
         */
        fun allAdPatterns(): List<String> {
            val result = mutableListOf<String>()
            // SDK包名：点号转换为斜杠（DEX类名格式为 Lcom/google/...;）
            result.addAll(sdkPackages.map { it.replace('.', '/') })
            result.addAll(classKeywords)
            result.addAll(adActivities)
            result.addAll(adServices)
            result.addAll(adReceivers)
            result.addAll(adViewNames)
            return result
        }

        /**
         * 统计总数。
         */
        fun totalCount(): Int =
            sdkPackages.size + classKeywords.size +
            methodPatterns.size + urlPatterns.size + adViewNames.size +
            adActivities.size + adServices.size + adReceivers.size +
            forceTrueMethodNames.size
    }

    /**
     * 配置分类信息（用于 UI 显示）。
     */
    enum class Category(val key: String, val displayName: String) {
        SDK_PACKAGES(KEY_SDK_PACKAGES, "广告SDK包名"),
        CLASS_KEYWORDS(KEY_CLASS_KEYWORDS, "广告类名关键词"),
        METHOD_PATTERNS(KEY_METHOD_PATTERNS, "广告方法名"),
        URL_PATTERNS(KEY_URL_PATTERNS, "广告URL/域名"),
        AD_VIEW_NAMES(KEY_AD_VIEW_NAMES, "广告View类名"),
        AD_ACTIVITIES(KEY_AD_ACTIVITIES, "广告Activity"),
        AD_SERVICES(KEY_AD_SERVICES, "广告Service"),
        AD_RECEIVERS(KEY_AD_RECEIVERS, "广告Receiver"),
        FORCE_TRUE_METHODS(KEY_FORCE_TRUE_METHODS, "强制返回true的方法名")
    }

    /**
     * 获取配置文件路径。
     */
    fun getConfigFile(): File {
        return File(CONFIG_DIR, CONFIG_FILE)
    }

    /**
     * 确保配置目录存在。
     */
    private fun ensureConfigDir(): File {
        val dir = File(CONFIG_DIR)
        if (!dir.exists()) {
            dir.mkdirs()
        }
        return dir
    }

    /**
     * 从 JSON 文件加载广告特征配置。
     * 如果文件不存在，则从 assets 读取默认配置并保存到外部存储。
     */
    fun loadConfig(context: Context): AdPatterns {
        val configFile = getConfigFile()
        if (!configFile.exists()) {
            val defaults = getDefaultConfig(context)
            saveConfig(defaults)
            return defaults
        }

        return try {
            val jsonStr = configFile.readText(Charsets.UTF_8)
            val json = JSONObject(jsonStr)

            AdPatterns(
                sdkPackages = jsonToStringList(json, KEY_SDK_PACKAGES),
                classKeywords = jsonToStringList(json, KEY_CLASS_KEYWORDS),
                methodPatterns = jsonToStringList(json, KEY_METHOD_PATTERNS),
                urlPatterns = jsonToStringList(json, KEY_URL_PATTERNS),
                adViewNames = jsonToStringList(json, KEY_AD_VIEW_NAMES),
                adActivities = jsonToStringList(json, KEY_AD_ACTIVITIES),
                adServices = jsonToStringList(json, KEY_AD_SERVICES),
                adReceivers = jsonToStringList(json, KEY_AD_RECEIVERS),
                forceTrueMethodNames = jsonToStringList(json, KEY_FORCE_TRUE_METHODS)
            )
        } catch (_: Exception) {
            // 配置文件损坏，恢复默认
            val defaults = getDefaultConfig(context)
            saveConfig(defaults)
            defaults
        }
    }

    /**
     * 保存广告特征配置到 JSON 文件。
     */
    fun saveConfig(config: AdPatterns): Boolean {
        return try {
            ensureConfigDir()
            val json = JSONObject()

            json.put(KEY_SDK_PACKAGES, listToJsonArray(config.sdkPackages))
            json.put(KEY_CLASS_KEYWORDS, listToJsonArray(config.classKeywords))
            json.put(KEY_METHOD_PATTERNS, listToJsonArray(config.methodPatterns))
            json.put(KEY_URL_PATTERNS, listToJsonArray(config.urlPatterns))
            json.put(KEY_AD_VIEW_NAMES, listToJsonArray(config.adViewNames))
            json.put(KEY_AD_ACTIVITIES, listToJsonArray(config.adActivities))
            json.put(KEY_AD_SERVICES, listToJsonArray(config.adServices))
            json.put(KEY_AD_RECEIVERS, listToJsonArray(config.adReceivers))
            json.put(KEY_FORCE_TRUE_METHODS, listToJsonArray(config.forceTrueMethodNames))

            getConfigFile().writeText(json.toString(2), Charsets.UTF_8)
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * 重置为默认配置。
     */
    fun resetToDefault(context: Context): AdPatterns {
        val defaults = getDefaultConfig(context)
        saveConfig(defaults)
        return defaults
    }

    /**
     * 从配置中获取指定分类的列表。
     */
    fun getCategoryList(config: AdPatterns, category: Category): MutableList<String> {
        return when (category) {
            Category.SDK_PACKAGES -> config.sdkPackages
            Category.CLASS_KEYWORDS -> config.classKeywords
            Category.METHOD_PATTERNS -> config.methodPatterns
            Category.URL_PATTERNS -> config.urlPatterns
            Category.AD_VIEW_NAMES -> config.adViewNames
            Category.AD_ACTIVITIES -> config.adActivities
            Category.AD_SERVICES -> config.adServices
            Category.AD_RECEIVERS -> config.adReceivers
            Category.FORCE_TRUE_METHODS -> config.forceTrueMethodNames
        }
    }

    // ========== JSON 辅助方法 ==========

    private fun jsonToStringList(json: JSONObject, key: String): MutableList<String> {
        val result = mutableListOf<String>()
        if (!json.has(key)) return result
        val arr = json.getJSONArray(key)
        for (i in 0 until arr.length()) {
            result.add(arr.getString(i))
        }
        return result
    }

    private fun listToJsonArray(list: List<String>): JSONArray {
        val arr = JSONArray()
        for (item in list) {
            arr.put(item)
        }
        return arr
    }

    // ========== 默认配置 ==========

    /**
     * 从 assets 内置 JSON 文件读取默认广告特征配置。
     * 文件路径: assets/ad_patterns_default.json
     * SDK包名以点号格式存储（com.google.android.gms.ads），
     * 在 DEX 匹配时会自动转换为斜杠格式（com/google/android/gms/ads）。
     */
    fun getDefaultConfig(context: Context): AdPatterns {
        return try {
            context.assets.open("ad_patterns_default.json").use { inputStream ->
                val jsonStr = inputStream.bufferedReader().readText()
                val json = JSONObject(jsonStr)
                AdPatterns(
                    sdkPackages = jsonToStringList(json, KEY_SDK_PACKAGES),
                    classKeywords = jsonToStringList(json, KEY_CLASS_KEYWORDS),
                    methodPatterns = jsonToStringList(json, KEY_METHOD_PATTERNS),
                    urlPatterns = jsonToStringList(json, KEY_URL_PATTERNS),
                    adViewNames = jsonToStringList(json, KEY_AD_VIEW_NAMES),
                    adActivities = jsonToStringList(json, KEY_AD_ACTIVITIES),
                    adServices = jsonToStringList(json, KEY_AD_SERVICES),
                    adReceivers = jsonToStringList(json, KEY_AD_RECEIVERS),
                    forceTrueMethodNames = jsonToStringList(json, KEY_FORCE_TRUE_METHODS)
                )
            }
        } catch (e: Exception) {
            // assets 文件缺失或损坏时的最小化兜底
            AdPatterns(
                sdkPackages = mutableListOf("com.google.android.gms.ads"),
                classKeywords = mutableListOf("AdView", "AdActivity")
            )
        }
    }
}