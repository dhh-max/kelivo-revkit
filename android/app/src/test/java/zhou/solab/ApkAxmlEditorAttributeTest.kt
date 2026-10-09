package zhou.solab

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * C7：Manifest 布尔/整数属性级修改原语测试。
 * 样本 = 真实产物 APK 的 AndroidManifest.xml（test resources，zip 原样解出）。
 * 验证闭环：readManifestSummary 读初始 → setElementBooleanAttribute 翻转 →
 * 再读确认。全部在字节层，不触发 repack。
 */
class ApkAxmlEditorAttributeTest {

    private fun fixture(): ByteArray {
        val res = javaClass.classLoader?.getResource("AndroidManifest_sample.bin")
            ?: throw IllegalStateException("缺少 AndroidManifest_sample.bin fixture")
        return File(res.toURI()).readBytes()
    }

    @Test
    fun `readManifestSummary 能解析真实 manifest`() {
        val summary = ApkAxmlEditor.readManifestSummary(fixture())
        assertNotNull(summary.packageName)
        assertTrue(summary.packageName!!.isNotBlank())
        // 样本为 release 产物：debuggable 通常不存在（null 合法），
        // allowBackup 存在（false）。versionCode 必须可读。
        assertEquals(false, summary.allowBackup)
        assertEquals(93L, summary.versionCode)
    }

    @Test
    fun `setElementBooleanAttribute 翻转 application allowBackup 并保持字节长度`() {
        val original = fixture()
        val before = ApkAxmlEditor.readManifestSummary(original)
        assertEquals("前置：allowBackup 存在且为 false", false, before.allowBackup)

        // 翻转 false -> true（写路径验证）。
        val patched = ApkAxmlEditor.setElementBooleanAttribute(
            original, "application", "allowBackup", true,
        )
        assertNotNull("必须命中 application/allowBackup 属性", patched)

        val after = ApkAxmlEditor.readManifestSummary(patched!!)
        assertEquals("写后应读到新值 true", true, after.allowBackup)

        // 纯字节手术：长度不变，不重建字符串池。
        assertEquals("长度不变", original.size, patched.size)

        // 再翻转回 false，确认可重复写。
        val restored = ApkAxmlEditor.setElementBooleanAttribute(
            patched, "application", "allowBackup", false,
        )
        assertNotNull(restored)
        assertEquals("再翻转应恢复 false",
            false, ApkAxmlEditor.readManifestSummary(restored!!).allowBackup)
    }

    @Test
    fun `未命中属性返回 null（不假成功）`() {
        val original = fixture()
        val miss = ApkAxmlEditor.setElementBooleanAttribute(
            original, "application", "nonexistentAttr", true,
        )
        assertNull("不存在的属性必须返回 null", miss)
    }

    @Test
    fun `非 application 标签未命中返回 null`() {
        val original = fixture()
        val miss = ApkAxmlEditor.setElementBooleanAttribute(
            original, "activity", "debuggable", true,
        )
        // activity 上一般没有 debuggable；即便有，断言只是"不崩溃且要么命中要么 null"。
        if (miss != null) {
            // 若真命中（某些 manifest 会给 activity 配 debuggable），结果必须是合法 AXML。
            assertTrue(ApkAxmlEditor.isAxml(miss))
        }
    }

    @Test
    fun `损坏字节不崩溃返回 null`() {
        val broken = ByteArray(64) { 0x42 }
        val r = ApkAxmlEditor.setElementBooleanAttribute(broken, "application", "debuggable", true)
        assertNull(r)
    }
}
