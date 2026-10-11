package zhou.solab

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import zhou.solab.tools.ArscResourceReader
import java.io.File
import java.util.zip.ZipFile

/**
 * 资源表读取器真数据回归（2026-09-19 复测缺口能力）。
 *
 * 用 dist/ 下的真实成品 APK 里的 resources.arsc 解析：断言能量出资源、
 * 名字/类型/值形状合理（不追求具体资源名，避免随成品变化而脆）。
 */
class ArscResourceReaderTest {

    private fun arscBytes(): ByteArray? {
        val distDir = File("../../dist")
        val apk = distDir.listFiles()?.filter { it.name.endsWith(".apk") }
            ?.maxByOrNull { it.lastModified() }
            ?: return null
        ZipFile(apk).use { zip ->
            val entry = zip.getEntry("resources.arsc") ?: return null
            return zip.getInputStream(entry).use { it.readBytes() }
        }
    }

    @Test
    fun `真实 resources arsc 能解析出资源条目`() {
        val bytes = arscBytes()
        assumeTrue("dist 下没有成品 APK，跳过真数据用例", bytes != null)
        val parsed = ArscResourceReader.read(bytes!!)
        assertTrue("应解析出资源条目", parsed.entries.size > 50)
        assertTrue("应识别出类型名", parsed.typeNames.isNotEmpty())
        assertTrue("typeNames 应含 string", parsed.typeNames.any { it == "string" })

        val strings = parsed.entries.filter { it.dataType == 0x03 }
        assertTrue("应有字符串型资源", strings.isNotEmpty())
        assertTrue(
            "字符串型资源应解出非空值（前 20 条里至少一条）",
            strings.take(20).any { it.value.isNotEmpty() },
        )
        assertTrue(
            "资源 id 应为 0xPPTTEEEE 形状（包 id 非 0）",
            parsed.entries.all { (it.id ushr 24) != 0 },
        )
        assertTrue(
            "应能按名字定位（名字非空且各不相同）",
            parsed.entries.map { it.name }.filter { it.isNotEmpty() }.distinct().size > 50,
        )
    }

    @Test
    fun `空字节与非法输入不崩`() {
        assertTrue(ArscResourceReader.read(ByteArray(0)).entries.isEmpty())
        assertFalse(ArscResourceReader.read(ByteArray(64)).entries.isNotEmpty())
    }
}
