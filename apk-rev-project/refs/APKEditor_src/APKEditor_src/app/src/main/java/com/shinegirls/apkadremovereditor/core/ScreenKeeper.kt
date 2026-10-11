package com.shinegirls.apkadremovereditor.core

import android.app.Activity
import android.view.WindowManager

/**
 * 屏幕常亮控制器。
 *
 * 用于在处理 APK 过程中保持屏幕常亮，防止处理到一半时突然黑屏锁屏导致处理失败；
 * 处理完毕后调用 [release] 清除常亮 flag，恢复正常锁屏。
 *
 * 使用 FLAG_KEEP_SCREEN_ON（无需任何权限）：
 * 该 flag 在 Activity 可见期间持续生效，且不会阻止系统睡眠，
 * 仅阻止屏幕自动关闭，是最轻量、最安全的保屏方案。
 */
object ScreenKeeper {

    /**
     * 开启屏幕常亮。
     *
     * @param activity 当前 Activity，需运行在 UI 线程
     */
    fun keepOn(activity: Activity) {
        activity.runOnUiThread {
            try {
                activity.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            } catch (_: Exception) {
                // 忽略异常，不影响处理流程
            }
        }
    }

    /**
     * 关闭屏幕常亮，恢复正常锁屏。
     *
     * @param activity 当前 Activity，需运行在 UI 线程
     */
    fun release(activity: Activity) {
        activity.runOnUiThread {
            try {
                activity.window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            } catch (_: Exception) {
                // 忽略异常，不影响处理流程
            }
        }
    }
}