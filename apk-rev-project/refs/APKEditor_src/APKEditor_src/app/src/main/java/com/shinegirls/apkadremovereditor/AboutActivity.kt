package com.shinegirls.apkadremovereditor

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.shinegirls.apkadremovereditor.core.UpdateChecker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 关于页面。
 *
 * 展示应用信息、作者信息、开源项目、隐私声明与免责声明。
 */
class AboutActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_about)

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.setNavigationOnClickListener { finish() }

        // 版本号
        findViewById<TextView>(R.id.tvVersion).text = "版本 ${getVersionName()}"

        // 检查更新
        findViewById<MaterialButton>(R.id.btnCheckUpdate)
            .setOnClickListener { checkForUpdate() }

        // 开源项目信息
        findViewById<TextView>(R.id.tvOpenSource).text = OPEN_SOURCE_TEXT

        // 隐私声明
        findViewById<TextView>(R.id.tvPrivacy).text = PRIVACY_TEXT

        // 免责声明
        findViewById<TextView>(R.id.tvDisclaimer).text = DISCLAIMER_TEXT

        // 版权信息
        findViewById<TextView>(R.id.tvCopyright).text = COPYRIGHT_TEXT

        // 点击作者信息可复制或发送邮件
        bindAuthorClick()
    }

    private fun bindAuthorClick() {
        val tvQq = findViewById<TextView>(R.id.tvAuthorQq)
        val tvEmail = findViewById<TextView>(R.id.tvAuthorEmail)

        // 点击 QQ 复制
        tvQq.setOnClickListener {
            val clip = android.content.ClipData.newPlainText("作者QQ", "3679265780")
            (getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager).setPrimaryClip(clip)
            Toast.makeText(this, "QQ已复制到剪贴板", Toast.LENGTH_SHORT).show()
        }

        // 点击邮箱发邮件
        tvEmail.setOnClickListener {
            try {
                val intent = Intent(Intent.ACTION_SENDTO).apply {
                    data = Uri.parse("mailto:3679265780@qq.com")
                    putExtra(Intent.EXTRA_SUBJECT, "APK去广告编辑器反馈")
                }
                startActivity(Intent.createChooser(intent, "发送邮件"))
            } catch (_: Exception) {
                Toast.makeText(this, "未找到邮件客户端", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun getVersionName(): String {
        return try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "1.0"
        } catch (_: PackageManager.NameNotFoundException) {
            "1.0"
        }
    }

    /**
     * 检测更新：后台拉取版本信息，UI 线程展示结果。
     * 若有强制更新，UpdateChecker 会弹出不可取消的对话框。
     */
    private fun checkForUpdate() {
        Toast.makeText(this, "正在检查更新 ...", Toast.LENGTH_SHORT).show()
        lifecycleScope.launch(Dispatchers.IO) {
            val info = UpdateChecker
                .fetchLatestUpdate(UpdateChecker.getCheckUrl(this@AboutActivity))
            withContext(Dispatchers.Main) {
                UpdateChecker.showResult(this@AboutActivity, info)
            }
        }
    }

    companion object {
        private const val OPEN_SOURCE_TEXT = "本应用基于以下开源项目构建，感谢各位作者的奉献：\n\n" +
            "1. dexlib2 (The Android Open Source Project)\n" +
            "   DEX 文件读写与字节码修补核心库\n" +
            "   - 开源协议: Apache License 2.0\n\n" +
            "2. smali / baksmali (JesusFreke)\n" +
            "   smali 语言反汇编 / 汇编工具链\n" +
            "   - 开源协议: BSD 3-Clause\n\n" +
            "3. apksig (Android Open Source Project)\n" +
            "   APK v1/v2/v3 签名实现\n" +
            "   - 开源协议: Apache License 2.0\n\n" +
            "4. BouncyCastle (BC)\n" +
            "   Java 加解密与证书生成库\n" +
            "   - 开源协议: MIT License\n\n" +
            "5. Guava (Google)\n" +
            "   Java 集合与工具库\n" +
            "   - 开源协议: Apache License 2.0\n\n" +
            "6. AndroidX / Material Components\n" +
            "   Android 官方支持库与 Material 设计组件\n" +
            "   - 开源协议: Apache License 2.0\n\n" +
            "7. DTL-X（广告特征规则参考）\n" +
            "   参考其广告类名 / 方法名 / URL 特征整理\n" +
            "   - 仅供特征参考与学习"

        private const val PRIVACY_TEXT = "本应用注重并保护您的个人隐私：\n\n" +
            "1. 本应用为本地离线工具，所有 APK 的解包、去广告、打包、签名均在您的设备本地完成，不会上传任何 APK 文件或内部数据。\n\n" +
            "2. 本应用仅在您主动点击\"检查更新\"时联网请求版本信息，其余时间不会在后台联网、收集或上传任何个人信息。\n\n" +
            "3. 本应用不读取、不存储您的通讯录、相册、定位、短信等敏感信息。\n\n" +
            "4. 若您在使用过程中有任何隐私疑问，欢迎通过作者联系方式与我们沟通。"

        private const val DISCLAIMER_TEXT = "请在使用本应用前仔细阅读以下免责声明：\n\n" +
            "1. 本应用仅供学习、研究与合法用途使用。请勿对您不拥有权限或未授权的 APK 文件进行修改。\n\n" +
            "2. 使用本应用处理 APK 所产生的任何后果（包括但不限于：应用无法安装、闪退、功能异常、数据丢失等）由使用者自行承担。\n\n" +
            "3. 修改后的 APK 若用于商业用途或分发，请确保遵守相关应用的所有权、版权及法律法规。\n\n" +
            "4. 本应用不提供任何形式的担保，作者不对因使用本应用而造成的任何直接或间接损失承担责任。\n\n" +
            "5. 使用本应用即视为您已阅读并同意以上条款。"

        private const val COPYRIGHT_TEXT = "© 2024 小奶瓶 · 保留所有权利\nPowered by dexlib2 / apksig"
    }
}