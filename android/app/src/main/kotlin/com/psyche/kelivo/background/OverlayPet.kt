package com.psyche.kelivo.background

import android.content.Context
import android.graphics.Bitmap
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.TransitionDrawable
import android.os.Handler
import android.os.Looper
import android.widget.ImageView
import kotlin.random.Random

/**
 * 待机小动作的兜底名（抽签失败时才用）。历史实现把待机小动作**写死**成
 * eat_token，于是八套动作里用户只看得到一两套；现在改成抽签（见下）。
 */
private const val PET_IDLE_FIDGET_FALLBACK_CLIP = "eat_token"

/**
 * 待机小动作频率（用户 2026-09-21 问"频率啥配置、有的动作几乎看不见"）。
 *
 * 原来的 22–55 秒 + **每次独立随机**：六个候选动作里任意一个平均要等
 * 2–5 分钟才轮到一次，再被任务状态切换打断，自然"几乎看不见"。
 *
 * 现在两条改动一起解决：
 * 1. 间隔缩到 [PET_FIDGET_MIN_MS, PET_FIDGET_MAX_MS]；
 * 2. 抽签改成**洗牌袋**（见 fidget）：一轮里每个动作各出一次再洗牌，
 *    所以任何动作都不会被随机饿死。
 */
private const val PET_FIDGET_MIN_MS = 10_000L
private const val PET_FIDGET_MAX_MS = 26_000L

/** 循环动作（idle/thinking）作为小动作露脸时的固定时长。 */
private const val PET_LOOPING_FIDGET_MS = 4_000L

/** 换动作的交叉淡化时长：约 4 帧，够顺但不拖沓。 */
private const val FADE_MS = 180

/**
 * 大肥鱼动画播放器。
 *
 * 素材是逐帧 webp（`PetAssets`），播法是原项目那套：
 * - 基础状态由外部驱动：idle / thinking / working / success / error
 * - 一次性动作（poke / dragging_release）插播完自动回基础状态
 * - 待机久了随机插一个 eat_token，别让它只是原地重复同一个循环
 *
 * 逐帧解码交给 PetAssets 的 LRU，播放器自己只持有当前帧号。
 */
internal class OverlayPet(
    private val context: Context,
    private val image: ImageView,
) {
    private val main = Handler(Looper.getMainLooper())
    private var state = STATE_IDLE
    private var playing: PetClip? = null
    private var oneShot: String? = null
    private var index = 0
    private var shown: Bitmap? = null
    private var running = false

    private val tick = Runnable { advance() }
    /**
     * 洗牌袋：一轮内每个动作各出一次，出完再洗牌。
     *
     * 纯随机（旧实现）会让某个动作连续几次抽不到，观感就是"有的几乎看不见"；
     * 洗牌袋保证 6 个动作在 6 次内全部露面，顺序仍随机。
     */
    private val fidgetBag = ArrayDeque<String>()

    private val fidget = Runnable {
        if (oneShot != null) return@Runnable
        // 八个动作全部接入（用户要求，2026-09-21）：抽签池就是清单里的**全部**
        // 动作（含 idle/thinking 这两个循环态——它们本是常驻状态，现在也会作为
        // 小动作露脸，播固定时长后回基准状态，见下）。抽签走洗牌袋。
        val pool = PetAssets.names(context).filter { it != state }
        if (pool.isEmpty()) {
            react(PET_IDLE_FIDGET_FALLBACK_CLIP)
            return@Runnable
        }
        if (fidgetBag.isEmpty() || fidgetBag.any { it !in pool }) {
            fidgetBag.clear()
            fidgetBag.addAll(pool.shuffled())
        }
        val pick = fidgetBag.removeFirst()
        react(pick)
        // 循环动作（idle/thinking）插播后不会自己结束，播固定时长就收回来。
        if (PetAssets.clip(context, pick)?.loop == true) {
            main.postDelayed(
                { if (oneShot == pick) endReact() },
                PET_LOOPING_FIDGET_MS,
            )
        }
    }

    /** 外部状态：任务在跑换 thinking，收尾换 success/error，其余 idle。 */
    fun setState(name: String) {
        if (state == name) return
        state = name
        if (oneShot == null) play(name)
    }

    /** 插播一次性动作（摸了头、拖拽、点一下），播完回基础状态。 */
    fun react(name: String) {
        val clip = PetAssets.clip(context, name) ?: return
        oneShot = name
        play(clip)
        // 非循环动作播完就回状态；循环动作（拖拽中）靠 endReact 收尾。
        if (!clip.loop) {
            main.removeCallbacks(fidget)
            main.postDelayed(fidget, Random.nextLong(PET_FIDGET_MIN_MS, PET_FIDGET_MAX_MS))
        }
    }

    /** 拖拽结束：切回基础状态并重新安排待机小动作。 */
    fun endReact() {
        oneShot = null
        play(state)
        main.removeCallbacks(fidget)
        main.postDelayed(fidget, Random.nextLong(PET_FIDGET_MIN_MS, PET_FIDGET_MAX_MS))
    }

    fun start() {
        if (running) return
        running = true
        play(state)
        main.postDelayed(fidget, Random.nextLong(PET_FIDGET_MIN_MS, PET_FIDGET_MAX_MS))
    }

    fun stop() {
        running = false
        main.removeCallbacks(tick)
        main.removeCallbacks(fidget)
        playing = null
        oneShot = null
        index = 0
        shown = null
    }

    private fun play(name: String) = play(PetAssets.clip(context, name))

    private fun play(clip: PetClip?) {
        val next = clip ?: return
        playing = next
        index = 0
        main.removeCallbacks(tick)
        // 换动作不能硬切：从当前姿态交叉淡化到新动作首帧（和原项目转向
        // 用同一种过渡），淡化期间先不推帧，避免淡到一半又跳一下。
        val from = shown
        val to = PetAssets.bitmap(context, next, 0)
        if (from != null && to != null && from !== to) {
            image.setImageDrawable(
                TransitionDrawable(
                    arrayOf(BitmapDrawable(context.resources, from), BitmapDrawable(context.resources, to)),
                ).apply {
                    isCrossFadeEnabled = true
                    startTransition(FADE_MS)
                },
            )
            shown = to
            if (running) {
                index = 1
                main.postDelayed(tick, FADE_MS.toLong())
            }
            return
        }
        draw()
        if (running) main.postDelayed(tick, next.frameMs.toLong())
    }

    private fun advance() {
        val clip = playing ?: return
        index++
        if (index >= clip.frames.size) {
            if (clip.loop) {
                index = 0
            } else {
                // 一次性动作放完：回基础状态。
                index = 0
                val back = state
                playing = null
                oneShot = null
                play(back)
                return
            }
        }
        draw()
        if (running) main.postDelayed(tick, clip.frameMs.toLong())
    }

    private fun draw() {
        val clip = playing ?: return
        val frame = PetAssets.bitmap(context, clip, index) ?: return
        shown = frame
        image.setImageBitmap(frame)
        PetAssets.prefetch(context, clip, index + 1)
    }

    private companion object {
        const val STATE_IDLE = "idle"
    }
}
