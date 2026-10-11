package zhou.solab.engine

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * D20（2026-09-21 自检）回归锁：句柄映射按**输入路径**对齐，两侧配不上的都如实
 * 列出。此前 jobId 与 workspaceId 互不可推，调用方只能人工比对 VA/fileOffset
 * 判断"是不是同一个产物"（实测多花 3~4 次调用）。
 */
class ArtifactHandleLinkTest {

    private fun workspace(
        id: String,
        apkPath: String = "",
        path: String = "",
    ): JSONObject = JSONObject()
        .put("workspaceId", id)
        .put("apkPath", apkPath)
        .put("path", path)
        .put("soFileName", "libapp.so")

    private fun job(id: String, requestPath: String, hasResult: Boolean = true): JSONObject =
        JSONObject()
            .put("jobId", id)
            .put("requestPath", requestPath)
            .put("status", "succeeded")
            .put("hasResult", hasResult)
            .put("resultKey", "a".repeat(64))

    @Test
    fun linksWorkspaceToJobByApkPathAndToleratesSeparatorsAndCase() {
        val result = linkArtifactHandles(
            JSONArray().put(workspace("ws-1", apkPath = "D:\\Work\\Target.apk")),
            JSONArray().put(job("blutter-aaaaaaaa", "d:/work/target.apk")),
        )
        assertEquals(1, result.getInt("linkCount"))
        val link = result.getJSONArray("links").getJSONObject(0)
        assertEquals("ws-1", link.getString("workspaceId"))
        assertEquals("blutter-aaaaaaaa", link.getString("jobId"))
        assertEquals("input_path", link.getString("matchBasis"))
        assertTrue(link.getBoolean("jobHasResult"))
        // 地址口径说明必须在链接里给出——这正是"不必人工比对 VA/fileOffset"的关键
        assertTrue(link.getString("addressNote").contains("fileOffset"))
    }

    @Test
    fun linksStandaloneSoBySoPath() {
        val result = linkArtifactHandles(
            JSONArray().put(workspace("ws-2", path = "/w/libapp.so")),
            JSONArray().put(job("blutter-bbbbbbbb", "/w/libapp.so")),
        )
        assertEquals(1, result.getInt("linkCount"))
        assertEquals(
            "/w/libapp.so",
            result.getJSONArray("links").getJSONObject(0).getString("soPath"),
        )
    }

    @Test
    fun unmatchedWorkspaceAndOrphanJobAreBothReportedWithReasons() {
        val result = linkArtifactHandles(
            JSONArray()
                .put(workspace("ws-1", apkPath = "/w/a.apk"))
                .put(workspace("ws-2", apkPath = "/w/other.apk")),
            JSONArray()
                .put(job("blutter-aaaaaaaa", "/w/a.apk"))
                .put(job("blutter-cccccccc", "/w/never-opened.apk")),
        )
        assertEquals(1, result.getInt("linkCount"))
        // 配不上的工作区：列出并说明原因，不静默丢弃
        val unmatched = result.getJSONArray("unmatchedWorkspaces")
        assertEquals(1, unmatched.length())
        assertEquals("ws-2", unmatched.getJSONObject(0).getString("workspaceId"))
        assertTrue(unmatched.getJSONObject(0).getString("note").isNotBlank())
        // 没有对应工作区的 job：同样列出，并说明可以直接用 jobId
        val orphans = result.getJSONArray("orphanBlutterJobs")
        assertEquals(1, orphans.length())
        assertEquals("blutter-cccccccc", orphans.getJSONObject(0).getString("jobId"))
        assertTrue(orphans.getJSONObject(0).getString("note").contains("jobId"))
        // 已配对的不该出现在 orphan 里
        assertFalse(orphans.toString().contains("blutter-aaaaaaaa"))
    }

    @Test
    fun noInputPathOnEitherSideYieldsNoLinksAndNoCrash() {
        val result = linkArtifactHandles(
            JSONArray().put(JSONObject().put("workspaceId", "ws-empty")),
            JSONArray().put(JSONObject().put("jobId", "blutter-empty")),
        )
        assertEquals(0, result.getInt("linkCount"))
        assertEquals(1, result.getJSONArray("unmatchedWorkspaces").length())
        assertEquals(1, result.getJSONArray("orphanBlutterJobs").length())
    }
}
