package zhou.solab.tools

import android.content.pm.PackageInstaller
import org.junit.Assert.assertEquals
import org.junit.Test

/** R9 自动验收：安装状态码 → 结构化标签/失败原因映射（纯函数）。 */
class ApkInstallToolTest {

    @Test
    fun `statusLabel maps every PackageInstaller status`() {
        assertEquals(
            "PENDING_USER_ACTION",
            ApkInstallTool.statusLabel(PackageInstaller.STATUS_PENDING_USER_ACTION),
        )
        assertEquals("SUCCESS", ApkInstallTool.statusLabel(PackageInstaller.STATUS_SUCCESS))
        assertEquals("FAILURE", ApkInstallTool.statusLabel(PackageInstaller.STATUS_FAILURE))
        assertEquals("BLOCKED", ApkInstallTool.statusLabel(PackageInstaller.STATUS_FAILURE_BLOCKED))
        assertEquals("ABORTED", ApkInstallTool.statusLabel(PackageInstaller.STATUS_FAILURE_ABORTED))
        assertEquals("INVALID", ApkInstallTool.statusLabel(PackageInstaller.STATUS_FAILURE_INVALID))
        assertEquals("CONFLICT", ApkInstallTool.statusLabel(PackageInstaller.STATUS_FAILURE_CONFLICT))
        assertEquals("STORAGE", ApkInstallTool.statusLabel(PackageInstaller.STATUS_FAILURE_STORAGE))
        assertEquals(
            "INCOMPATIBLE",
            ApkInstallTool.statusLabel(PackageInstaller.STATUS_FAILURE_INCOMPATIBLE),
        )
        assertEquals("UNKNOWN", ApkInstallTool.statusLabel(9999))
    }

    @Test
    fun `failureReason is machine-readable and structured`() {
        assertEquals(
            "INSTALL_BLOCKED_BY_SOURCE",
            ApkInstallTool.failureReason("BLOCKED"),
        )
        assertEquals(
            "INSTALL_CONFLICT_SIGNATURE_OR_VERSION",
            ApkInstallTool.failureReason("CONFLICT"),
        )
        assertEquals(
            "INSTALL_INCOMPATIBLE_ABI_OR_SDK",
            ApkInstallTool.failureReason("INCOMPATIBLE"),
        )
        assertEquals(
            "INSTALL_USER_CONFIRMATION_TIMEOUT",
            ApkInstallTool.failureReason("TIMEOUT"),
        )
        assertEquals("INSTALL_SESSION_ERROR", ApkInstallTool.failureReason("SESSION_ERROR"))
        // 成功与挂起态没有失败原因（空串约定）。
        assertEquals("", ApkInstallTool.failureReason("SUCCESS"))
        assertEquals("", ApkInstallTool.failureReason("PENDING_USER_ACTION"))
        // 未知标签兜底。
        assertEquals("INSTALL_FAILED", ApkInstallTool.failureReason("WHATEVER"))
    }
}
