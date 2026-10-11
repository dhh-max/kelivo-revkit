package zhou.solab.engine

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class BlutterResultStoreTest {

    @Test
    fun objectInventoryPagesDirectlyFromRawObjsWithoutDuplicateJsonl() {
        val root = Files.createTempDirectory("blutter-objects-").toFile()
        try {
            val store = BlutterResultStore(root, true)
            val key = "a".repeat(64)
            val job = "blutter-object-page"
            val jobDir = File(root, "jobs/$job").apply { mkdirs() }
            File(jobDir, "state.json").writeText(JSONObject()
                .put("jobId", job)
                .put("status", "succeeded")
                .put("resultKey", key)
                .toString())
            val resultDir = File(root, "results/$key").apply { mkdirs() }
            File(resultDir, "result.json").writeText(JSONObject()
                .put("status", "succeeded")
                .put("summary", JSONObject().put("counts", JSONObject().put("objects", 3)))
                .toString())
            File(resultDir, "objs.txt").writeText("first\nsecond\nthird\n")

            val page = store.result(job, "objects", null, 2)!!
                .getJSONObject("objects")

            assertEquals(3, page.getInt("total"))
            assertTrue(page.getBoolean("hasMore"))
            assertEquals("first", page.getJSONArray("items").getJSONObject(0).getString("name"))
            assertFalse(File(resultDir, "objects.jsonl").exists())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun analysisCacheOptionsIgnoreSchedulingAndQueryArguments() {
        val first = JSONObject()
            .put("action", "analyze")
            .put("path", "/storage/emulated/0/Ai/first.apk")
            .put("wait", true)
            .put("timeoutMs", 90000)
            .put("goal", "定位会员")
        val second = JSONObject()
            .put("action", "analyze")
            .put("path", "/storage/emulated/0/Ai/renamed.apk")
            .put("wait", false)
            .put("timeoutMs", 5000)
            .put("goal", "定位广告")

        assertEquals(
            BlutterResultStore.analysisCacheOptions(first),
            BlutterResultStore.analysisCacheOptions(second),
        )
        assertFalse(
            BlutterResultStore.analysisCacheOptions(first) ==
                BlutterResultStore.analysisCacheOptions(JSONObject(second.toString()).put("abi", "armeabi-v7a")),
        )
    }

    @Test
    fun reapOrphanJobsInterruptsOnlyStaleJobsAndDeletesTheirInputs() {
        val noBackupDir = Files.createTempDirectory("blutter-store-").toFile()
        try {
            val root = File(noBackupDir, "blutter/v1")
            val store = BlutterResultStore(root, true)
            val jobsDir = File(root, "jobs")
            val stale = File(jobsDir, "blutter-stale-job").apply { mkdirs() }
            val fresh = File(jobsDir, "blutter-fresh-job").apply { mkdirs() }
            writeState(stale, "running", System.currentTimeMillis() - 10 * 60 * 1000L)
            writeState(fresh, "queued", System.currentTimeMillis())
            File(stale, "input/libapp.so").apply { parentFile!!.mkdirs(); writeText("old") }
            File(fresh, "input/libapp.so").apply { parentFile!!.mkdirs(); writeText("new") }

            store.reapOrphanJobs()

            assertEquals("interrupted", JSONObject(File(stale, "state.json").readText()).getString("status"))
            assertFalse(File(stale, "input").exists())
            assertEquals("queued", JSONObject(File(fresh, "state.json").readText()).getString("status"))
            assertTrue(File(fresh, "input/libapp.so").isFile)
        } finally {
            noBackupDir.deleteRecursively()
        }
    }

    @Test
    fun prunePreviewReportsBytesWithoutDeletingThenPruneReclaimsThem() {
        val root = Files.createTempDirectory("blutter-prune-").toFile()
        try {
            val store = BlutterResultStore(root, true)
            val key = "b".repeat(64)
            val job = File(root, "jobs/blutter-old-result-job").apply { mkdirs() }
            val old = System.currentTimeMillis() - 10_000
            File(job, "state.json").writeText(JSONObject()
                .put("jobId", job.name)
                .put("status", "succeeded")
                .put("updatedAt", old)
                .put("resultKey", key)
                .toString())
            File(job, "input.bin").writeBytes(ByteArray(11))
            val result = File(root, "results/$key").apply { mkdirs() }
            File(result, "result.json").writeBytes(ByteArray(17))
            result.setLastModified(old)

            val preview = store.prunePreview(1_000)
            assertTrue(preview.getBoolean("dryRun"))
            assertEquals(1, preview.getInt("candidateJobs"))
            assertEquals(1, preview.getInt("candidateResults"))
            assertTrue(preview.getLong("freedBytes") >= 28)
            assertTrue(job.exists())
            assertTrue(result.exists())

            val pruned = store.prune(1_000)
            assertFalse(pruned.getBoolean("dryRun"))
            assertEquals(1, pruned.getInt("removedJobs"))
            assertEquals(1, pruned.getInt("removedResults"))
            assertFalse(job.exists())
            assertFalse(result.exists())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun runningStatusIncludesHeartbeatStageAndArtifactGrowth() {
        val root = Files.createTempDirectory("blutter-progress-").toFile()
        try {
            val store = BlutterResultStore(root, true)
            val jobId = store.create(JSONObject().put("action", "analyze"))

            store.progress(jobId, "writing_indexes", "正在生成反汇编", 4096, 12)
            val state = store.get(jobId)!!

            assertEquals("running", state.getString("status"))
            assertEquals("生成对象池与反汇编", state.getString("stageLabel"))
            assertEquals("正在生成反汇编", state.getString("progressMessage"))
            assertEquals(4096, state.getLong("outputBytes"))
            assertEquals(12, state.getInt("outputFiles"))
            assertTrue(state.getLong("elapsedMillis") >= 0)
            assertTrue(state.getLong("heartbeatAgeMillis") >= 0)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun identicalRunningAnalysisReusesExistingJob() {
        val root = Files.createTempDirectory("blutter-dedupe-").toFile()
        try {
            val store = BlutterResultStore(root, true)
            val first = store.create(JSONObject().put("path", "same.apk"))
            val second = store.create(JSONObject().put("path", "same.apk"))

            assertEquals(null, store.claimAnalysisKey(first, "same-key"))
            assertEquals(first, store.claimAnalysisKey(second, "same-key"))
        } finally {
            root.deleteRecursively()
        }
    }

    /**
     * D5（2026-09-21）跨语言契约锁：Blutter 产物落在 `<工作目录>/SoLab/blutter/v1`，
     * 而 Dart 侧的验证后清理必须把这一段列为"可复用层"保留（见
     * `ApkWorkspaceBindingService._reusableCacheRoots`）。改这里的路径就得同步改
     * Dart 的保留清单，否则清理会把产物删掉、同一 APK 的追问要从零重算。
     *
     * 同时验证：产物位于该路径下时，`reuse` 命中（analyze 走缓存、不重建索引）。
     */
    @Test
    fun workRootPathIsStableContractAndReuseHitsThere() {
        assertEquals("SoLab/blutter/v1", BlutterResultStore.WORK_SUBPATH)
        val workDir = Files.createTempDirectory("blutter-workdir-").toFile()
        try {
            val root = BlutterResultStore.blutterWorkRoot(workDir.path)
            assertTrue(
                "产物根必须落在工作目录内的 SoLab/blutter/v1：${root.path}",
                root.path.endsWith("SoLab${File.separator}blutter${File.separator}v1") ||
                    root.path.endsWith("SoLab/blutter/v1"),
            )
            // 模拟"验证后清理只动一次性中间包、产物层存活"之后的状态
            val store = BlutterResultStore(root, true)
            val jobId = store.create(JSONObject().put("path", "same.apk"))
            val key = "d".repeat(64)
            val resultDir = File(root, "results/$key").apply { mkdirs() }
            File(resultDir, "result.json").writeText(JSONObject()
                .put("status", "succeeded")
                .put("backend", "exec")
                .put("summary", JSONObject().put("counts", JSONObject().put("functions", 42)))
                .toString())

            val reused = store.reuse(jobId, key)
            assertTrue("产物存活时 reuse 必须命中（不重建索引）", reused != null)
            assertTrue(reused!!.getBoolean("cacheHit"))
            assertEquals(42, reused.getJSONObject("summary").getJSONObject("counts").getInt("functions"))
        } finally {
            workDir.deleteRecursively()
        }
    }

    @Test
    fun cacheHitReturnsCompactSummaryInsteadOfFullInventories() {
        val root = Files.createTempDirectory("blutter-cache-").toFile()
        try {
            val store = BlutterResultStore(root, true)
            val jobId = store.create(JSONObject().put("path", "same.apk"))
            val key = "c".repeat(64)
            val resultDir = File(root, "results/$key").apply { mkdirs() }
            File(resultDir, "result.json").writeText(JSONObject()
                .put("status", "succeeded")
                .put("backend", "exec")
                .put("summary", JSONObject().put("counts", JSONObject().put("functions", 100)))
                .put("functions", JSONObject().put("items", org.json.JSONArray().put("large inventory")))
                .toString())

            val reused = store.reuse(jobId, key)!!

            assertTrue(reused.getBoolean("cacheHit"))
            assertEquals(100, reused.getJSONObject("summary").getJSONObject("counts").getInt("functions"))
            assertFalse(reused.has("functions"))
            assertEquals("cache_hit", store.get(jobId)!!.getString("stage"))
        } finally {
            root.deleteRecursively()
        }
    }

    private fun writeState(dir: File, status: String, updatedAt: Long) {
        File(dir, "state.json").writeText(
            JSONObject()
                .put("jobId", dir.name)
                .put("status", status)
                .put("updatedAt", updatedAt)
                .toString(),
        )
    }

    /**
     * 用户报告 #2：jobs/ 丢了（进程崩溃/清理/换工作目录）而 results/ 还在时，
     * `listJobs()` 过去回空表 → 调用方以为"从没分析过"，重新 analyze 走全量重算
     * （实测 29.7s），而产物其实完好（内容寻址的 resultKey 目录就是证据）。
     * 现在从 results/<key>/result.json 反重建 job 表。
     */
    @Test
    fun listJobsRebuildsFromResultDirsWhenJobStateIsLost() {
        val root = Files.createTempDirectory("blutter-rebuild-").toFile()
        try {
            val store = BlutterResultStore(root, true)
            val key = "e".repeat(64)
            val jobId = "blutter-rebuilt-from-result"
            val resultDir = File(root, "results/$key").apply { mkdirs() }
            File(resultDir, "result.json").writeText(JSONObject()
                .put("jobId", jobId)
                .put("status", "succeeded")
                .put("backend", "exec")
                .put("input", JSONObject()
                    .put("displayName", "极简记物_3.3.1.apk")
                    .put("abi", "arm64-v8a")
                    .put("libapp", JSONObject()
                        .put("sha256", "a".repeat(64))
                        .put("sourcePath", "/storage/emulated/0/Ai/极简记物_3.3.1.apk")))
                .toString())

            // 故意不建 jobs/ —— 模拟 job 状态丢失
            val items = store.listJobs()
            assertEquals(1, items.length())
            val entry = items.getJSONObject(0)
            assertEquals(jobId, entry.getString("jobId"))
            assertEquals("rebuilt_from_result", entry.getString("stage"))
            assertEquals(key, entry.getString("resultKey"))
            assertTrue(entry.getBoolean("hasResult"))
            assertEquals("result_dir", entry.getString("source"))
        } finally {
            root.deleteRecursively()
        }
    }

    /** jobs/ 与 results/ 都在时不得重复列出同一个 job。 */
    @Test
    fun listJobsDeduplicatesJobStateAndResultEntries() {
        val root = Files.createTempDirectory("blutter-dedupe-").toFile()
        try {
            val store = BlutterResultStore(root, true)
            val key = "f".repeat(64)
            val jobId = "blutter-dedupe-me"
            val jobDir = File(root, "jobs/$jobId").apply { mkdirs() }
            File(jobDir, "state.json").writeText(JSONObject()
                .put("jobId", jobId).put("status", "succeeded")
                .put("stage", "committed").put("resultKey", key)
                .put("request", JSONObject().put("path", "/x.apk"))
                .toString())
            val resultDir = File(root, "results/$key").apply { mkdirs() }
            File(resultDir, "result.json").writeText(JSONObject()
                .put("jobId", jobId).put("status", "succeeded")
                .put("input", JSONObject().put("libapp", JSONObject().put("sha256", "a".repeat(64))))
                .toString())

            val items = store.listJobs()
            assertEquals(1, items.length())
            assertEquals("job_state", items.getJSONObject(0).getString("source"))
        } finally {
            root.deleteRecursively()
        }
    }

    /** 未命中缓存的解释：有同输入旧产物 vs 完全没有产物，两种原因要分得清。 */
    @Test
    fun explainCacheMissDistinguishesMissingResultFromChangedKey() {
        val root = Files.createTempDirectory("blutter-miss-").toFile()
        try {
            val store = BlutterResultStore(root, true)
            val libapp = File(root, "libapp.so").apply { writeBytes(ByteArray(1024) { 7 }) }
            val libflutter = File(root, "libflutter.so").apply { writeBytes(ByteArray(64) { 3 }) }

            // 还没有任何产物
            val empty = store.explainCacheMiss(libapp, libflutter)
            assertEquals("no_result_for_this_input", empty.getString("reason"))

            // 造一条同输入的旧产物（sha256 用真实值算，才能命中"同输入"判据）
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            val sha = digest.digest(libapp.readBytes()).joinToString("") { "%02x".format(it) }
            val resultDir = File(root, "results/${"c".repeat(64)}").apply { mkdirs() }
            File(resultDir, "result.json").writeText(JSONObject()
                .put("jobId", "blutter-old").put("status", "succeeded")
                .put("input", JSONObject().put("libapp", JSONObject().put("sha256", sha)))
                .toString())

            val explained = store.explainCacheMiss(libapp, libflutter)
            assertEquals("result_exists_but_key_differs", explained.getString("reason"))
            assertTrue(explained.getJSONArray("existingResultKeys").length() == 1)
        } finally {
            root.deleteRecursively()
        }
    }
}
