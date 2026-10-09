package zhou.solab.engine

import java.net.InetAddress
import java.net.URL
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * open_url 下载目标守卫（SSRF 防护）的回归锁。
 *
 * 全部用例只用**字面量**地 址/主机名，不做 DNS 解析——守卫的主机名层判定在
 * 解析之前，测试不依赖网络。
 */
class UrlTargetGuardTest {
    private fun address(ip: String) = InetAddress.getByName(ip)

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    @Test
    fun `blocks loopback and private hosts by name`() {
        assertNotNull(UrlTargetGuard.rejectReason("localhost"))
        assertNotNull(UrlTargetGuard.rejectReason("LOCALHOST."))
        assertNotNull(UrlTargetGuard.rejectReason("ip6-localhost"))
        assertNotNull(UrlTargetGuard.rejectReason("metadata.google.internal"))
        assertNotNull(UrlTargetGuard.rejectReason("anything.internal"))
        assertNotNull(UrlTargetGuard.rejectReason("printer.local"))
        assertNotNull(UrlTargetGuard.rejectReason(""))
        assertNotNull(UrlTargetGuard.rejectReason(null))
    }

    @Test
    fun `blocks literal private and reserved addresses`() {
        for (ip in listOf(
            "127.0.0.1",
            "127.1.2.3",
            "0.0.0.0",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "169.254.169.254", // 云元数据
            "100.64.0.1", // CGNAT
            "192.0.2.10", // TEST-NET
            "198.18.0.1",
            "203.0.113.7",
            "240.0.0.1",
            "255.255.255.255",
        )) {
            assertNotNull("应拒绝 $ip", UrlTargetGuard.rejectReason(ip))
        }
    }

    @Test
    fun `blocks ipv6 loopback unique-local and mapped ipv4`() {
        assertNotNull(UrlTargetGuard.rejectReason("::1"))
        assertNotNull(UrlTargetGuard.rejectReason("[::1]"))
        assertNotNull(UrlTargetGuard.rejectReason("fd00::1"))
        assertNotNull(UrlTargetGuard.rejectReason("fe80::1"))
        // IPv4-mapped 必须走同一条内网判定（否则是绕回 127.0.0.1 的口子）。
        // 注意 InetAddress.getByName("::ffff:127.0.0.1") 会被 Java 折成 Inet4，
        // 所以要手搓 16 字节地址才能真正打到 IPv6 分支。
        val mappedLoopback = InetAddress.getByAddress(
            bytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1),
        )
        val mappedPrivate = InetAddress.getByAddress(
            bytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1),
        )
        assertFalse(UrlTargetGuard.isPublicAddress(mappedLoopback))
        assertFalse(UrlTargetGuard.isPublicAddress(mappedPrivate))
        assertTrue(
            UrlTargetGuard.isPublicAddress(
                InetAddress.getByAddress(
                    bytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8),
                ),
            ),
        )
    }

    @Test
    fun `allows public addresses`() {
        assertTrue(UrlTargetGuard.isPublicAddress(address("8.8.8.8")))
        assertTrue(UrlTargetGuard.isPublicAddress(address("93.184.216.34")))
        assertTrue(UrlTargetGuard.isPublicAddress(address("2606:4700:4700::1111")))
        assertNull(UrlTargetGuard.rejectReason(address("8.8.8.8").hostAddress))
    }

    @Test
    fun `rejects reserved ranges at byte level`() {
        assertFalse(UrlTargetGuard.isPublicAddress(address("192.168.0.1")))
        assertFalse(UrlTargetGuard.isPublicAddress(address("172.16.5.5")))
        assertTrue(UrlTargetGuard.isPublicAddress(address("172.32.0.1")))
        assertFalse(UrlTargetGuard.isPublicAddress(InetAddress.getByAddress(bytes(224, 0, 0, 1))))
        assertFalse(UrlTargetGuard.isPublicAddress(InetAddress.getByAddress(bytes(0, 0, 0, 0))))
    }

    @Test
    fun `rejects urls whose host is internal`() {
        assertNotNull(UrlTargetGuard.rejectReason(URL("http://127.0.0.1:8080/lib.so")))
        assertNotNull(UrlTargetGuard.rejectReason(URL("http://169.254.169.254/latest/meta-data/")))
        assertNotNull(UrlTargetGuard.rejectReason(URL("https://localhost/lib.so")))
        assertNotNull(UrlTargetGuard.rejectReason(URL("http://[::1]/lib.so")))
    }

    @Test
    fun `public literal url passes and scheme check stays in openUrl`() {
        // 守卫只判目标；scheme 白名单（http/https）仍由 openUrl 负责。
        assertNull(UrlTargetGuard.rejectReason(URL("https://8.8.8.8/lib.so")))
    }

    @Test
    fun `message names the offending host for diagnostics`() {
        val reason = UrlTargetGuard.rejectReason("127.0.0.1")
        assertNotNull(reason)
        assertTrue("拒绝原因应包含命中地址: $reason", reason!!.contains("127.0.0.1"))
    }
}
