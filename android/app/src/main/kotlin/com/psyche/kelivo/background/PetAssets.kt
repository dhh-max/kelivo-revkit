package com.psyche.kelivo.background

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.LruCache
import org.json.JSONObject
import java.util.concurrent.Executors

/** 一组动作：帧序列 + 每帧时长 + 是否循环。 */
internal class PetClip(
    val name: String,
    val frames: List<String>,
    val frameMs: Int,
    val loop: Boolean,
)

/**
 * 大肥鱼动画素材（源：QCYTSN/dsh-dafeiyu，MIT）。
 *
 * 帧是逐张 webp，全部放在 `assets/pet/<动作>/`，清单在 `assets/pet/manifest.json`。
 * 解码按需进行并进 LRU 缓存——整套 1600+ 帧不可能常驻内存，播放器一次也只
 * 需要相邻几帧。
 */
internal object PetAssets {
    private const val ROOT = "flutter_assets/assets/pet/"
    private const val CACHE_KB = 6 * 1024

    private var clips: Map<String, PetClip>? = null
    private var cache: LruCache<String, Bitmap>? = null
    private val decodeQueue = Executors.newSingleThreadExecutor()

    fun clip(context: Context, name: String): PetClip? {
        val table = clips ?: load(context).also { clips = it }
        return table[name]
    }

    fun frameCount(context: Context, name: String): Int = clip(context, name)?.frames?.size ?: 0

    /** 清单里的全部动作名（悬浮窗待机随机动作要从中抽签）。 */
    fun names(context: Context): List<String> {
        val table = clips ?: load(context).also { clips = it }
        return table.keys.toList()
    }

    /** 只播一次的动作（非循环）：随机的待机小动作只能从这些里抽，
     * 循环的（idle/thinking）插播进去会回不到基础状态。 */
    fun oneShotNames(context: Context): List<String> {
        val table = clips ?: load(context).also { clips = it }
        return table.filterValues { !it.loop }.keys.toList()
    }

    /** 第一帧：给图标工厂做静态兜底，也用于抖动前的占位。 */
    fun firstFrame(context: Context, name: String): Bitmap? {
        val target = clip(context, name) ?: return null
        return bitmap(context, target, 0)
    }

    fun bitmap(context: Context, clip: PetClip, index: Int): Bitmap? {
        if (clip.frames.isEmpty()) return null
        val safeIndex = index.mod(clip.frames.size)
        val key = "${clip.name}#$safeIndex"
        val store = cache ?: LruCache<String, Bitmap>(CACHE_KB).also { cache = it }
        store.get(key)?.let { return it }
        val decoded = runCatching {
            context.assets.open(ROOT + clip.frames[safeIndex]).use { BitmapFactory.decodeStream(it) }
        }.getOrNull() ?: return null
        store.put(key, decoded)
        return decoded
    }

    /** 预取下一帧：24fps 下每帧都在 UI 线程现解会有掉帧风险，提前在后台
     * 线程解好塞进缓存，播放时基本只做一次查表。 */
    fun prefetch(context: Context, clip: PetClip, index: Int) {
        if (clip.frames.isEmpty()) return
        val safeIndex = index.mod(clip.frames.size)
        if (cache?.get("${clip.name}#$safeIndex") != null) return
        decodeQueue.execute {
            runCatching { bitmap(context, clip, safeIndex) }
        }
    }

    private fun load(context: Context): Map<String, PetClip> = runCatching {
        val text = context.assets.open(ROOT + "manifest.json").use { it.readBytes().decodeToString() }
        val root = JSONObject(text).getJSONObject("clips")
        buildMap {
            root.keys().forEach { name ->
                val clip = root.getJSONObject(name)
                val frames = clip.getJSONArray("frames")
                put(
                    name,
                    PetClip(
                        name = name,
                        frames = List(frames.length()) { frames.getString(it) },
                        frameMs = clip.optInt("frameMs", 42).coerceIn(16, 200),
                        loop = clip.optBoolean("loop", true),
                    ),
                )
            }
        }
    }.getOrDefault(emptyMap())
}
