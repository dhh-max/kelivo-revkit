package com.shinegirls.apkadremovereditor

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.SystemClock
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.provider.Settings
import android.text.method.ScrollingMovementMethod
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.shinegirls.apkadremovereditor.core.ApkProcessor
import com.shinegirls.apkadremovereditor.core.Signer
import com.shinegirls.apkadremovereditor.core.UpdateChecker
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.progressindicator.LinearProgressIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : AppCompatActivity() {

    companion object {
        private const val REQUEST_CODE_PICK_APK = 1001
        private const val REQUEST_CODE_PERMISSIONS = 1002
        private const val EXPORT_DIR = "/storage/emulated/0/APKEditor"
        /** 日志滚动最小间隔（毫秒） */
        private const val SCROLL_INTERVAL_MS = 200L
        /** 日志缓冲最大字符数，超出后丢弃最旧部分，防止 TextView 无限增长导致渲染变慢 */
        private const val MAX_LOG_CHARS = 200_000
    }

    private lateinit var progressBar: LinearProgressIndicator
    private lateinit var logView: TextView
    private lateinit var scrollView: ScrollView
    private lateinit var fabOpen: FloatingActionButton

    private val apkProcessor = ApkProcessor()

    /** 日志缓冲：工作线程先写入，再由 UI 线程批量渲染，避免高频日志刷爆主线程 */
    private val logBuffer = StringBuilder()
    private var logFlushPending = false
    /** 日志滚动节流：SCROLL_INTERVAL_MS 内的多次日志只滚动一次，避免 UI 卡顿 */
    private var lastScrollTime = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)

        progressBar = findViewById(R.id.progressBar)
        logView = findViewById(R.id.logView)
        scrollView = findViewById(R.id.scrollView)
        fabOpen = findViewById(R.id.fabOpen)

        logView.movementMethod = ScrollingMovementMethod.getInstance()

        fabOpen.setOnClickListener {
            checkPermissionsAndPick()
        }

        checkPermissions()
    }

    /**
     * 实时日志输出（工作线程安全）。
     * 先写入缓冲，再投递一次 UI 线程渲染，把高频日志批量合并成一次 append。
     * 避免旧实现"每条日志都 runOnUiThread + fullScroll"导致主线程卡顿。
     */
    private fun log(message: String) {
        synchronized(logBuffer) {
            logBuffer.append(message).append('\n')
            // 字符数上限：超过后丢弃最旧的一半（从换行处切断），防止 TextView 无限增长
            if (logBuffer.length > MAX_LOG_CHARS) {
                val cut = logBuffer.indexOf("\n", logBuffer.length / 2)
                if (cut >= 0) logBuffer.delete(0, cut + 1)
            }
            // 同一批日志只投递一次渲染，后续日志合并进同一个缓冲
            if (!logFlushPending) {
                logFlushPending = true
                runOnUiThread { flushLog() }
            }
        }
    }

    /** 在 UI 线程执行一次批量渲染 + 滚动节流。 */
    private fun flushLog() {
        val chunk: String
        synchronized(logBuffer) {
            chunk = logBuffer.toString()
            logBuffer.setLength(0)
            logFlushPending = false
        }
        logView.append(chunk)
        val now = SystemClock.uptimeMillis()
        if (now - lastScrollTime >= SCROLL_INTERVAL_MS) {
            lastScrollTime = now
            scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
        }
    }

    private fun showProgress(show: Boolean) {
        runOnUiThread {
            progressBar.visibility = if (show) View.VISIBLE else View.GONE
        }
    }

    private fun checkPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                try {
                    startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                } catch (_: Exception) {
                }
            }
        } else {
            val permissions = arrayOf(
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
            )
            if (permissions.any {
                ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
            }) {
                ActivityCompat.requestPermissions(this, permissions, REQUEST_CODE_PERMISSIONS)
            }
        }
    }

    private fun checkPermissionsAndPick() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
            Toast.makeText(this, "请先授予\"所有文件访问\"权限", Toast.LENGTH_LONG).show()
            try {
                startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
            } catch (_: Exception) {
            }
            return
        }
        pickApkFile()
    }

    private fun pickApkFile() {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "application/vnd.android.package-archive"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        startActivityForResult(Intent.createChooser(intent, "选择APK文件"), REQUEST_CODE_PICK_APK)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == Activity.RESULT_OK && data?.data != null) {
            val uri = data.data!!
            when (requestCode) {
                REQUEST_CODE_PICK_APK -> processApk(uri)
            }
        }
    }

    /**
     * 一键处理流程：解包 -> 直接修补DEX去广告 -> 打包 -> 签名 -> 导出。
     *
     * 优化功能：
     * - 全流程计时，各阶段耗时统计
     * - 原始APK体积与处理后体积对比
     * - 智能文件命名（包含包名和时间戳）
     * - 工作目录自动清理，避免缓存膨胀
     * - 处理完成后自动清理临时文件
     */
    private fun processApk(uri: Uri) {
        logView.text = ""
        showProgress(true)
        fabOpen.isEnabled = false
        log("━━━ 开始处理 APK ━━━")

        // 处理期间保持屏幕常亮，防止处理中突然黑屏锁屏导致处理失败
        com.shinegirls.apkadremovereditor.core.ScreenKeeper.keepOn(this)

        val totalStartTime = System.currentTimeMillis()

        lifecycleScope.launch(Dispatchers.IO) {
            var workDir: File? = null
            try {
                workDir = File(cacheDir, "apk_work_${System.currentTimeMillis()}")
                workDir.mkdirs()

                // 1. 读取 APK
                val step1Start = System.currentTimeMillis()
                log("步骤 1/4: 读取 APK 文件 ...")
                val sourceApk = File(workDir, "source.apk")
                contentResolver.openInputStream(uri)?.use { input ->
                    sourceApk.outputStream().use { output -> input.copyTo(output) }
                } ?: throw IllegalStateException("无法读取所选文件")

                val originalApkSize = sourceApk.length()
                log("  ✓ APK 已读取: ${sourceApk.name} (${formatSize(originalApkSize)})")
                logStepTime("读取APK", step1Start)

                // 获取APK基本信息
                val apkInfo = apkProcessor.getApkInfo(sourceApk)
                log("  APK 信息: DEX=${apkInfo["dex_count"]}, 资源=${apkInfo["res_count"]}, 库=${apkInfo["lib_count"]}")

                // 2. 解包
                val step2Start = System.currentTimeMillis()
                log("步骤 2/4: 解包 APK ...")
                val extractDir = File(workDir, "extracted")
                extractDir.mkdirs()
                apkProcessor.extractApk(sourceApk, extractDir)

                val dexCount = extractDir.listFiles { f -> f.name.endsWith(".dex") }?.size ?: 0
                val totalFiles = extractDir.walkTopDown().filter { it.isFile }.count()
                log("  ✓ 解包完成: $totalFiles 个文件, $dexCount 个DEX")
                logStepTime("解包", step2Start)

                // 3. 直接修补DEX去广告
                val step3Start = System.currentTimeMillis()
                log("步骤 3/4: 直接修补 DEX 去广告 ...")
                try {
                    val result = com.shinegirls.apkadremovereditor.core.AdRemover.removeAds(extractDir, this@MainActivity) { msg ->
                        log(msg)
                    }
                    log(result)
                } catch (e: OutOfMemoryError) {
                    log("  [严重] 内存不足: ${e.message}")
                    log("  建议: 减少同时处理的DEX大小或关闭其他应用后重试")
                    System.gc()
                } catch (e: Exception) {
                    log("  去广告处理异常: ${e.message}")
                    log("  堆栈: ${e.stackTraceToString().take(200)}")
                }
                logStepTime("去广告处理", step3Start)

                // 4. 打包并签名
                val step4Start = System.currentTimeMillis()
                log("步骤 4/4: 打包并签名 APK ...")
                val unsignedApk = File(workDir, "unsigned.apk")
                log("  正在打包 ...")
                apkProcessor.buildApk(extractDir, unsignedApk) { msg ->
                    log(msg)
                }
                val unsignedSize = unsignedApk.length()
                log("  ✓ 打包完成: ${formatSize(unsignedSize)}")

                log("  正在签名 (v1+v2 兼容全部Android版本) ...")
                val tempSigned = File(workDir, "temp_signed.apk")
                Signer.signApk(this@MainActivity, unsignedApk, tempSigned)
                val signedSize = tempSigned.length()
                log("  ✓ 签名完成: ${formatSize(signedSize)}")
                logStepTime("打包签名", step4Start)

                // 导出：优先保存到所选 APK 所在目录，失败时回退到默认导出目录
                log("  正在导出 ...")

                // 生成输出文件名：原文件名_noads.apk
                val displayName = queryDisplayName(uri) ?: "output"
                val baseName = displayName.substringBeforeLast('.').ifBlank { "output" }
                val fileName = "${baseName}_noads.apk"

                var finalSize: Long
                val exportDesc: String
                val exportedViaSaf = try {
                    // 尝试通过 SAF 在所选 APK 的同目录创建输出文件
                    val resultUri = createOutputInSelectedDir(uri, fileName)
                    if (resultUri != null) {
                        contentResolver.openOutputStream(resultUri)?.use { out ->
                            tempSigned.inputStream().use { it.copyTo(out) }
                        }
                        true
                    } else {
                        false
                    }
                } catch (_: Exception) {
                    false
                }

                if (exportedViaSaf) {
                    // 已通过 SAF 写入所选 APK 同目录
                    finalSize = tempSigned.length()
                    exportDesc = docUriToReadablePath(uri, fileName)
                } else {
                    // 回退到默认导出目录
                    val exportDir = File(EXPORT_DIR)
                    if (!exportDir.exists()) exportDir.mkdirs()
                    val exportFile = File(exportDir, fileName)
                    tempSigned.copyTo(exportFile, overwrite = true)
                    finalSize = exportFile.length()
                    exportDesc = exportFile.absolutePath
                }

                val savedBytes = originalApkSize - finalSize
                val totalTime = System.currentTimeMillis() - totalStartTime

                log("  ✓ 已导出: $exportDesc")
                log("━━━ 处理完成! ━━━")
                log("导出路径: $exportDesc")
                log("原始大小: ${formatSize(originalApkSize)}")
                log("处理后大小: ${formatSize(finalSize)}")
                if (savedBytes > 0) {
                    log("节省空间: ${formatSize(savedBytes)}")
                }
                log("总耗时: ${totalTime}ms (${String.format("%.1f", totalTime / 1000.0)}秒)")

                withContext(Dispatchers.Main) {
                    showProgress(false)
                    fabOpen.isEnabled = true
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle("处理完成")
                        .setMessage(
                            "已导出到:\n$exportDesc\n\n" +
                            "原始: ${formatSize(originalApkSize)}\n" +
                            "处理后: ${formatSize(finalSize)}\n" +
                            (if (savedBytes > 0) "节省: ${formatSize(savedBytes)}\n" else "") +
                            "耗时: ${String.format("%.1f", totalTime / 1000.0)}秒"
                        )
                        .setPositiveButton("确定", null)
                        .show()
                }
            } catch (e: OutOfMemoryError) {
                log("━━━ 处理失败: 内存不足 ━━━")
                log("错误: ${e.message}")
                log("建议: 该APK可能过大，请尝试关闭其他应用后重试")
                System.gc()
                withContext(Dispatchers.Main) {
                    showProgress(false)
                    fabOpen.isEnabled = true
                    Toast.makeText(this@MainActivity, "内存不足，处理失败", Toast.LENGTH_LONG).show()
                }
            } catch (e: StackOverflowError) {
                log("━━━ 处理失败: 嵌套过深(StackOverflow) ━━━")
                log("错误: ${e.message}")
                withContext(Dispatchers.Main) {
                    showProgress(false)
                    fabOpen.isEnabled = true
                    Toast.makeText(this@MainActivity, "处理失败: 文件结构异常", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                log("━━━ 处理失败 ━━━")
                log("错误: ${e.message}")
                log("堆栈: ${e.stackTraceToString().take(300)}")
                withContext(Dispatchers.Main) {
                    showProgress(false)
                    fabOpen.isEnabled = true
                    Toast.makeText(this@MainActivity, "处理失败: ${e.message}", Toast.LENGTH_LONG).show()
                }
            } finally {
                // 处理结束（无论成功或失败），恢复屏幕常亮 flag，允许正常锁屏
                com.shinegirls.apkadremovereditor.core.ScreenKeeper.release(this@MainActivity)

                // 清理工作目录，释放存储空间
                workDir?.let { dir ->
                    try {
                        dir.deleteRecursively()
                    } catch (_: Exception) {
                    }
                }
            }
        }
    }

    /**
     * 选择 APK 文件进行体积分析（已移除）。
     */

    /**
     * 查询所选文件的显示名称（含扩展名）。
     */
    private fun queryDisplayName(uri: Uri): String? {
        return try {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(c.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME)) else null
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * 通过 SAF 在所选 APK 的父目录创建输出文件，返回写入用的 document uri。
     * 仅当所选 uri 是 document uri 且能解析出父目录时才有意义，否则返回 null。
     */
    private fun createOutputInSelectedDir(uri: Uri, fileName: String): Uri? {
        return try {
            if (!DocumentsContract.isDocumentUri(this, uri)) return null
            val docId = DocumentsContract.getDocumentId(uri)
            val slash = docId.lastIndexOf('/')
            if (slash <= 0) return null
            val parentDocId = docId.substring(0, slash)
            val parentUri = DocumentsContract.buildDocumentUri(uri.authority, parentDocId)
            if (parentUri == null) return null
            DocumentsContract.createDocument(
                contentResolver,
                parentUri,
                "application/vnd.android.package-archive",
                fileName
            )
        } catch (_: Exception) {
            null
        }
    }

    /**
     * 将所选 APK 的 document uri 解析为可读的文件系统路径（仅用于日志展示）。
     * 内部存储（primary）映射为 /storage/emulated/0，其余存储挂载点保守回退为 uri 字符串。
     */
    private fun docUriToReadablePath(uri: Uri, fileName: String): String {
        return try {
            if (DocumentsContract.isDocumentUri(this, uri)) {
                val docId = DocumentsContract.getDocumentId(uri)
                val slash = docId.lastIndexOf('/')
                if (slash > 0) {
                    val parentDocId = docId.substring(0, slash)
                    if (parentDocId.startsWith("primary:")) {
                        val dir = parentDocId.substringAfter(':')
                        val base = if (dir.isEmpty()) "/storage/emulated/0" else "/storage/emulated/0/$dir"
                        return "$base/$fileName"
                    }
                }
            }
            uri.toString()
        } catch (_: Exception) {
            uri.toString()
        }
    }

    private fun logStepTime(stepName: String, startTime: Long) {
        val elapsed = System.currentTimeMillis() - startTime
        log("  ⏱ $stepName 耗时: ${elapsed}ms")
    }

    private fun formatSize(bytes: Long): String {
        return when {
            bytes < 1024 -> "${bytes}B"
            bytes < 1024 * 1024 -> "${bytes / 1024}KB"
            else -> String.format("%.1fMB", bytes / (1024.0 * 1024.0))
        }
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_check_update -> {
                checkForUpdate()
                true
            }
            R.id.action_settings -> {
                startActivity(Intent(this, SettingsActivity::class.java))
                true
            }
            R.id.action_about -> {
                startActivity(Intent(this, AboutActivity::class.java))
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    /**
     * 检测更新：在后台线程拉取版本信息，然后在 UI 线程展示结果。
     * 若有强制更新，UpdateChecker 会弹出不可取消的对话框。
     */
    private fun checkForUpdate() {
        Toast.makeText(this, "正在检查更新 ...", Toast.LENGTH_SHORT).show()
        lifecycleScope.launch(Dispatchers.IO) {
            val info = UpdateChecker
                .fetchLatestUpdate(UpdateChecker.getCheckUrl(this@MainActivity))
            withContext(Dispatchers.Main) {
                UpdateChecker.showResult(this@MainActivity, info)
            }
        }
    }
}
