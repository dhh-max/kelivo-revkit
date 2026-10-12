package zhou.solab.tools

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import zhou.solab.tools.ApkArchiveTool

/**
 * 已处理产物身份检测（C 修复轮）：内置签名指纹常量 + 签名代理痕迹字节检测。
 */
class ApkArtifactIdentityTest {

    @Test
    fun builtinCertSha256MatchesDistFingerprint() {
        // 从 dist 成品提取的内置证书指纹（key.properties keystore）。
        assertEquals(
            "5A6917AB87D84A81FB838EC61F737CA39AD70B85358201D13966A93A7721A549",
            ApkArchiveTool.BUILTIN_CERT_SHA256.replace(":", "").uppercase(),
        )
        // 规范化比对：去冒号、大小写不敏感、要求完整指纹。
        assertTrue(
            ApkArchiveTool.isBuiltinCert(
                "5a:69:17:ab:87:d8:4a:81:fb:83:8e:c6:1f:73:7c:a3:9a:d7:0b:85:35:82:01:d1:39:66:a9:3a:77:21:a5:49",
            ),
        )
        assertFalse(ApkArchiveTool.isBuiltinCert("5a:69:17:ab"))
        assertFalse(ApkArchiveTool.isBuiltinCert("AA:BB:CC:DD"))
    }

    @Test
    fun manifestProxyDetectionMatchesUtf8AndUtf16() {
        // manifest android:name 属性值是点分类名（非 dex 的 L/ 形式）。
        val dotted = "zhou.solab.signature.SignatureProxyApplication"
        val utf8 = dotted.toByteArray(Charsets.UTF_8)
        val utf16 = dotted.toByteArray(Charsets.UTF_16LE)
        val clean = "com.example.App".toByteArray(Charsets.UTF_16LE)
        assertTrue(ApkArchiveTool.manifestContainsProxy(utf8))
        assertTrue(ApkArchiveTool.manifestContainsProxy(utf16))
        assertFalse(ApkArchiveTool.manifestContainsProxy(clean))
        assertFalse(ApkArchiveTool.manifestContainsProxy(ByteArray(0)))
    }
}
