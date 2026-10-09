package zhou.solab.engine

import java.net.InetAddress
import java.net.URL

/**
 * 下载目标守卫（SSRF 防护）。
 *
 * `so_analyze` 的 `open_url` 会把远端文件抓到设备上再解析。这类由设备发起的
 * 请求如果不校验目标，就能被指向只在网络内部可达的地址：127.0.0.1（本机上
 * 其他服务）、10.x/192.168.x/172.16-31（局域网设备）、169.254.169.254（云元
 * 数据）、以及 ::1 / fc00::/7 等 IPv6 内网段。
 *
 * 守卫分两层：
 * 1. **主机名层**（无需 DNS）：本机名、元数据服务名、内网后缀直接拒；
 * 2. **地址层**：解析出的每个地址都必须是公网地址——既防 DNS 把公网域名解析
 *    到内网，也防 `::ffff:127.0.0.1` 这类 IPv4-mapped IPv6 绕过。
 *
 * 重定向必须逐跳复用本守卫：302 跳到内网是这类接口最常见的绕过手法。
 */
internal object UrlTargetGuard {
    private val blockedHosts = setOf(
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "instance-data",
    )
    private val blockedSuffixes = listOf(".localhost", ".local", ".internal", ".home.arpa")

    /** 返回 null 表示放行；否则返回拒绝原因（中文，直接进工具错误消息）。 */
    fun rejectReason(url: URL): String? = rejectReason(url.host)

    fun rejectReason(rawHost: String?): String? {
        var host = rawHost?.trim()?.removeSuffix(".")?.lowercase().orEmpty()
        // IPv6 字面量在 URL.host 里带方括号（`[::1]`），先剥掉再判定/解析。
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length - 1)
        if (host.isEmpty()) return "URL 缺少主机名"
        if (host in blockedHosts || blockedSuffixes.any { host.endsWith(it) }) {
            return "禁止访问本机/内网主机：$host"
        }
        val addresses = runCatching { InetAddress.getAllByName(host) }.getOrNull()
        if (addresses.isNullOrEmpty()) return "无法解析主机：$host"
        addresses.firstOrNull { !isPublicAddress(it) }?.let {
            return "禁止访问非公网地址：${it.hostAddress}（本机/环回/私有/保留网段）"
        }
        return null
    }

    /** 公网可达判定：排除环回、私有、链路本地、组播与保留网段。 */
    fun isPublicAddress(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress ||
            address.isLoopbackAddress ||
            address.isLinkLocalAddress ||
            address.isSiteLocalAddress ||
            address.isMulticastAddress
        ) {
            return false
        }
        return when (address.address.size) {
            4 -> isPublicIpv4(address.address)
            16 -> isPublicIpv6(address.address)
            else -> false
        }
    }

    private fun isPublicIpv4(bytes: ByteArray): Boolean {
        val a = bytes[0].toInt() and 0xff
        val b = bytes[1].toInt() and 0xff
        val c = bytes[2].toInt() and 0xff
        return !(a == 0 || // 0.0.0.0/8 本网络
            (a == 100 && b in 64..127) || // 100.64/10 CGNAT
            (a == 192 && b == 0 && c == 0) || // 192.0.0/24 保留
            (a == 192 && b == 0 && c == 2) || // TEST-NET-1
            (a == 192 && b == 88 && c == 99) || // 6to4 relay anycast
            (a == 198 && (b == 18 || b == 19)) || // 198.18/15 基准测试
            (a == 198 && b == 51 && c == 100) || // TEST-NET-2
            (a == 203 && b == 0 && c == 113) || // TEST-NET-3
            a >= 240) // 240/4 保留（含 255.255.255.255）
    }

    private fun isPublicIpv6(bytes: ByteArray): Boolean {
        val first = bytes[0].toInt() and 0xff
        if (first and 0xfe == 0xfc) return false // fc00::/7 唯一本地地址
        val second = bytes[1].toInt() and 0xff
        if (first == 0xfe && (second and 0xc0) == 0x80) return false // fe80::/10
        // IPv4-mapped ::ffff:a.b.c.d 交回 v4 判定，否则可借它绕过内网检查。
        val v4Mapped = bytes[10] == 0xff.toByte() && bytes[11] == 0xff.toByte() &&
            (0 until 10).all { bytes[it] == 0.toByte() }
        if (v4Mapped) return isPublicIpv4(bytes.copyOfRange(12, 16))
        return true
    }
}
