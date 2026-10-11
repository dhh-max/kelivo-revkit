package zhou.solab

/**
 * 业务敏感字段词表（唯一真相源）。
 *
 * 为什么单独抽出来：词表覆盖度直接决定 `analyzeModule(fields)` 的 recall，
 * 而不同项目关注的业务域不同（会员/试用/广告/风控）。此前硬编码在
 * `ApkModuleAnalyzer.fieldsSection` 里，换领域就得改 Kotlin 重编译。
 *
 * 匹配约定（与 `ApkModuleAnalyzer.matchFieldName` 一致，**必须遵守**）：
 * 词表项按**段边界**对齐，即字段名按驼峰/下划线/数字边界拆段后，
 * 关键词必须**整段全等**、或等于**多段连续拼接**。绝不做任意位置子串匹配。
 *
 * 反例（真实缺陷）：词表含 `ispro` 时，若用裸 `contains`，
 * `isProxy` / `isProtected` / `isProduct` / `isPromise` 全部命中，
 * 腾讯网络栈字段会被误当成会员字段（真机实测被下游以 0.95 高置信呈现）。
 *
 * 词表项一律**小写**、**去掉分隔符**：`vip_level` 写成 `viplevel`，
 * 因为它要匹配的是拆段后的拼接结果。
 */
object BusinessFieldKeywords {

    /**
     * 内置默认词表：会员/付费/试用/授权这一组最常见业务态。
     *
     * 覆盖三类命名习惯：
     * - `is*` 布尔判定（isvip / ispro / ismember）
     * - `vip*` / `member*` 前缀属性（viplevel / vipexpire / memberexpire）
     * - `*expire` / `*deadline` / `*endtime` 后缀到期时间
     */
    val default: List<String> = listOf(
        "isvip", "ispro", "isforever", "vipexpire", "vipmember", "viptype",
        "viplevel", "ispremium", "isvipmember", "vipendtime", "viptime",
        "memberexpire", "expiretime", "expireat", "expireend",
        "deadline", "ispaid", "ismember", "ispermanent", "authlevel",
        "usertype", "vipperiod", "vipstatus", "vipflag",
    )

    /** 外部覆写词表；null 表示使用 [default]。 */
    @Volatile
    private var override: List<String>? = null

    /**
     * 设置领域词表（覆盖默认）。传入 null 或空列表即恢复默认。
     *
     * 词表项会被规范化为小写并剥掉 `_`/`$`/空格，防止调用方写成
     * `vip_level` 这种带分隔符的形式导致永不命中（段拼接结果里没有下划线）。
     */
    @Synchronized
    fun overrideWith(keywords: List<String>?) {
        if (keywords.isNullOrEmpty()) {
            override = null
            return
        }
        override = keywords
            .map { it.trim().lowercase().replace("_", "").replace("$", "").replace(" ", "") }
            .filter { it.isNotEmpty() }
            .distinct()
            .ifEmpty { null }
    }

    /** 当前生效词表：有覆写用覆写，否则用内置默认。 */
    fun effective(): List<String> = override ?: default
}
