package zhou.solab.tools

import android.content.Context
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Field
import com.android.tools.smali.dexlib2.iface.Method
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * M2: 类大纲引擎（自研，替代 MT 的 outline_class）。
 *
 * 按类名列出方法/字段签名。用途：混淆类（短名 b/c/d 无规则关键字）
 * 浏览兜底通道——规则匹配不到时用本工具看类里有什么。
 */
object ClassOutlineEngine {

    // D1（修订）：类大纲结果级 LRU——key=apk指纹|className → 未分页的
    // 全量方法/字段 JSONArray。同 APK 翻页/重复 outline 避免重复全扫定位
    // （dex 遍历是主要成本，此前每次 offset 变体都全扫）。指纹含 mtime/size，
    // dex 变更自动失效；max 32 条防内存膨胀。
    private val outlineCache =
        LinkedHashMap<String, OutlineSnapshot>()
    private const val OUTLINE_CACHE_MAX = 32

    private class OutlineSnapshot(
        val sourceFile: String,
        val methods: JSONArray,
        val fields: JSONArray,
        val totalMethods: Int,
        val totalFields: Int,
    )

    private const val MAX_APK_BYTES = 512L * 1024 * 1024

    private fun qidOf(m: Method): String =
        "${m.definingClass}->${m.name}(${m.parameterTypes.joinToString("")})${m.returnType}"

    fun outline(
        context: Context,
        apkPath: String,
        className: String,
        offset: Int = 0,
        limit: Int = 200,
        fieldsOffset: Int = 0,
    ): JSONObject {
        val apk = File(apkPath)
        if (!apk.isFile) return err("FILE_NOT_FOUND", "APK 不存在: $apkPath", "apkPath", apkPath)
        if (apk.length() > MAX_APK_BYTES) return err("APK_LIMIT_EXCEEDED", "APK 超过 512MiB 上限", "apkPath", apkPath)
        val target = className.trim()
            .substringBefore("->") // 兼容 qualifiedId（Lpkg/C;->method）直接喂入
            .let { if (!it.contains('/') && it.contains('.')) it.replace('.', '/') else it } // 点分 → 斜杠
            .trim()
        if (target.isBlank()) return err("INVALID_ARGUMENT", "缺少 className", "className", "")

        val wantExact = target.startsWith("L") && target.endsWith(";")

        // D1（修订）：结果级缓存——同 APK 同类的翻页/重复查询直接命中
        // 全量结构，避免重复全扫定位（dex 遍历是主要成本）。
        val cacheKey = "${apk.canonicalPath}|${apk.length()}|${apk.lastModified()}|$target"
        val snapshot = try {
            synchronized(outlineCache) {
                val hit = outlineCache.remove(cacheKey)
                if (hit != null) {
                    outlineCache[cacheKey] = hit
                    hit
                } else {
                    val scanned = _scanFull(context, apk, target, wantExact)
                    if (scanned != null) {
                        outlineCache[cacheKey] = scanned
                        while (outlineCache.size > OUTLINE_CACHE_MAX) {
                            outlineCache.remove(outlineCache.keys.first())
                        }
                    }
                    scanned
                }
            }
        } catch (e: ScanFailed) {
            // C5：扫描失败（dex 损坏/IO）与「类不存在」区分开。
            return err(
                "CLASS_SCAN_FAILED",
                "类大纲扫描失败（可能是 dex 解析错误而非类不存在）: ${e.message}。可先试 dex_search 或换更短类名；若确定 dex 损坏则报告该 APK。",
                "className", className,
                "cause" to (e.cause?.javaClass?.simpleName ?: ""),
            )
        }
        if (snapshot == null) {
            return err(
                "CLASS_NOT_FOUND", "未在 DEX 中找到类: $target（可尝试短名/子串，或先用 dex_search 反查真实类名）",
                "className", className,
            )
        }

        // 分页切片。字段**独立游标**（2026-09-21 独立复验：过去"字段不参与分页、
        // 始终从头取 limit 条"使字段尾部**永久不可达**——28 字段的类在 limit=3
        // 时第 21~28 个永远不会出现，且没有任何字段游标可以前进）。
        // 默认 fieldsOffset=0 与旧行为一致（首屏不变），需要下一页时用
        // 响应里的 nextFieldsOffset。
        val pageMethods = JSONArray()
        var methodIndex = 0
        for (i in 0 until snapshot.methods.length()) {
            methodIndex++
            if (methodIndex <= offset) continue
            if (pageMethods.length() >= limit) break
            pageMethods.put(snapshot.methods.get(i))
        }
        val fields = JSONArray()
        var fieldIndex = 0
        for (i in 0 until snapshot.fields.length()) {
            fieldIndex++
            if (fieldIndex <= fieldsOffset) continue
            if (fields.length() >= limit) break
            fields.put(snapshot.fields.get(i))
        }
        val hasMoreMethods = offset + pageMethods.length() < snapshot.totalMethods
        val hasMoreFields = fieldsOffset + fields.length() < snapshot.totalFields
        // offset 越界要显式说（2026-09-21 复测 D4）：真机实测 methodCount=2 的类
        // 传 offset=30 时回 methods=[]、hasMore=false、nextOffset=null，且**没有
        // 任何越界提示**——调用方容易读成「该类没有方法」。契约上「空数组」已经
        // 被 B3 用来表达「类存在但为空」，两种语义必须能区分。
        //
        // 边界口径（独立复验修正）：`offset == methodCount` 是**合法的空尾页**
        // （读完最后一页后 nextOffset 正好等于总数），只有 `>` 才是越界。
        val offsetBeyondMethods = offset > snapshot.totalMethods
        return ok(JSONObject()
            .put("tool", "class_outline")
            .put("className", target)
            // B3：命中即显式声明 exists，空类也返回空数组——
            // 杜绝「静默空成功」被误读为类不存在。
            .put("exists", true)
            .put("methodCount", snapshot.totalMethods)
            .put("fieldCount", snapshot.totalFields)
            .put("sourceFile", snapshot.sourceFile)
            .put("methods", pageMethods)
            .put("fields", fields)
            .put("totalMethods", snapshot.totalMethods)
            .put("totalFields", snapshot.totalFields)
            .put("offsetOutOfRange", offsetBeyondMethods)
            .put(
                "offsetNote",
                if (offsetBeyondMethods) {
                    "offset=$offset 超出该类的方法数（${snapshot.totalMethods}）：" +
                        "methods 为空是**越界**，不是「该类没有方法」。用 offset=0 重读，或按 " +
                        "nextOffset 翻页。"
                } else {
                    "offset $offset 在范围内（该类共 ${snapshot.totalMethods} 个方法）。"
                },
            )
            .put("offset", offset)
            .put("returnedMethods", pageMethods.length())
            .put("hasMore", hasMoreMethods)
            .put("nextOffset", if (hasMoreMethods) offset + pageMethods.length() else JSONObject.NULL)
            .put("fieldsOffset", fieldsOffset)
            .put("returnedFields", fields.length())
            .put("hasMoreFields", hasMoreFields)
            .put(
                "nextFieldsOffset",
                if (hasMoreFields) fieldsOffset + fields.length() else JSONObject.NULL,
            )
            .put("truncated", hasMoreMethods || hasMoreFields)
            .put(
                "hint",
                "混淆类定位: 拿到方法 qualifiedId 后可喂给 dex_xref 查调用者,或 patch_apk_dex_methods.classMethods 精确补丁; " +
                    "方法与字段各有独立游标——方法用 offset/nextOffset，字段用 fieldsOffset/nextFieldsOffset（字段多时 limit 不够要接着翻，否则尾部读不到）",
            ))
    }

    /** 全量扫描定位类并序列化全部方法/字段（结果级缓存的数据源）。 */
    private fun _scanFull(
        context: Context,
        apk: File,
        target: String,
        wantExact: Boolean,
    ): OutlineSnapshot? {
        return runCatching {
            var found = false
            var sourceFile = ""
            var totalMethods = 0
            var totalFields = 0
            val methods = JSONArray()
            val fields = JSONArray()
            DexIo.eachDex(context, apk) { dexName, dexFile ->
                for (cls: ClassDef in dexFile.classes) {
                    val matches = if (wantExact) cls.type == target
                    else cls.type.contains(target, ignoreCase = true) ||
                        cls.type.removePrefix("L").removeSuffix(";").substringAfterLast('/').contains(target, ignoreCase = true)
                    if (!matches) continue
                    found = true
                    if (sourceFile.isEmpty()) sourceFile = cls.sourceFile ?: ""
                    totalMethods += cls.methods.count()
                    totalFields += cls.fields.count()
                    cls.methods.forEach { m ->
                        val flags = m.accessFlags
                        methods.put(JSONObject()
                            .put("name", m.name)
                            .put("signature", "(${m.parameterTypes.joinToString("")})${m.returnType}")
                            .put("qualifiedId", qidOf(m))
                            .put("returnType", m.returnType)
                            .put("isStatic", flags and 0x8 != 0)
                            .put("isPrivate", flags and 0x2 != 0)
                            .put("isConstructor", m.name == "<init>" || m.name == "<clinit>")
                            .put("dexFile", dexName))
                    }
                    cls.fields.forEach { f ->
                        fields.put(JSONObject()
                            .put("name", f.name)
                            .put("type", f.type)
                            .put("isStatic", f.accessFlags and 0x8 != 0)
                            .put("isPrivate", f.accessFlags and 0x2 != 0)
                            .put("dexFile", dexName))
                    }
                    // 命中后继续扫描其余 dex（同名类可能多 dex 分布），不 break
                }
            }
            if (!found) return@runCatching null
            OutlineSnapshot(
                sourceFile = sourceFile,
                methods = methods,
                fields = fields,
                totalMethods = totalMethods,
                totalFields = totalFields,
            )
        // C5（阶段 0）：异常与「真未找到」区分——解析失败（dex 损坏/IO/OOM）
        // 抛 ScanFailed 交由 outline 转 CLASS_SCAN_FAILED，不再折叠成 CLASS_NOT_FOUND
        // （此前 AI 会把 dex 损坏误判成"类不存在"而放弃错误方向）。
        }.getOrElse { e ->
            throw ScanFailed("class outline scan failed for $target: ${e.message ?: e.javaClass.simpleName}", e)
        }
    }

    /** C5：类大纲扫描失败的专用异常（区别于"未找到类"）。 */
    internal class ScanFailed(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
}
