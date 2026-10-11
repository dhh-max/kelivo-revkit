package zhou.solab.engine

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 用真实的 runners.json 校验 Dart 3.13 runner 已正确注册：
 * 条目存在、哈希是 64 位十六进制、Dart 3.13 快照能被选中。
 *
 * 该文件随 assets 打包，本测试直接读工程内的源文件，
 * 保证“加了 runner 却没进 manifest”这类漏配能被拦住。
 */
class BlutterRunnerManifestTest {
    private fun loadManifest(): JSONObject {
        val path = "src/main/assets/blutter/runners.json"
        return JSONObject(java.io.File(path).readText())
    }

    @Test
    fun dart313RunnerIsRegisteredWithHashes() {
        val runners = loadManifest().getJSONArray("runners")
        var found: JSONObject? = null
        for (i in 0 until runners.length()) {
            val item = runners.getJSONObject(i)
            if (item.optString("dartVersion") == "3.13") {
                found = item
                break
            }
        }
        assertNotNull("Dart 3.13 runner must be present in runners.json", found)
        val entry = found!!
        assertEquals("blutter_3_13", entry.getString("libraryName"))
        assertEquals("exec", entry.getString("backend"))
        assertEquals("blutter-termux", entry.getString("source"))
        assertTrue(
            "sha256 must be a 64-char hex digest",
            entry.getString("sha256").matches(Regex("[a-f0-9]{64}")),
        )
        assertTrue(
            "packagedSha256 must be a 64-char hex digest",
            entry.getString("packagedSha256").matches(Regex("[a-f0-9]{64}")),
        )
    }

    @Test
    fun dart313SnapshotSelectsTheRegisteredRunner() {
        val runners = loadManifest().getJSONArray("runners")
        val descriptors = (0 until runners.length()).map { i ->
            val item = runners.getJSONObject(i)
            BlutterRunnerDescriptor(
                runnerId = item.getString("runnerId"),
                dartVersion = item.optString("dartVersion"),
                engineRevision = null,
                abi = item.optString("abi", "arm64-v8a"),
                compressedPointers = item.optBoolean("compressedPointers", true),
                analysis = item.optBoolean("analysis", true),
                sha256 = item.getString("sha256"),
                source = item.optString("source"),
                libraryName = item.getString("libraryName"),
                backend = item.optString("backend", "exec"),
            )
        }
        val selected = BlutterRunnerMatcher.selectWithEvidence(
            BlutterRunnerRequirement(null, "3.13.0", "unknown-snapshot", "arm64-v8a", true, true),
            descriptors,
        )
        assertNotNull("Dart 3.13 requirement must resolve to a runner", selected)
        assertEquals("blutter_3_13", selected!!.runner.libraryName)
    }
}
