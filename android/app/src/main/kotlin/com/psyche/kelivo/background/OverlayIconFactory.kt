package com.psyche.kelivo.background

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewOutlineProvider
import android.widget.ImageView
import android.widget.TextView
import zhou.solab.R
import java.io.File

/**
 * 悬浮窗图标的唯一出处：`overlayIconKind` / `overlayIconValue` 现在有两个
 * 消费者（上游任务胶囊、自研保活小标记），取值与校验规则必须只有一份，
 * 否则大肥鱼、自定义图这类改动会在其中一边漏掉。
 */
internal object OverlayIconFactory {

    /** 兜底用的待机首帧；与 Dart 侧 OverlayPetClips.idle 同名。 */
    private const val PET_IDLE_CLIP = "idle"

    fun create(context: Context, kind: String, value: String, sizePx: Int): View =
        when (kind) {
            "emoji" -> TextView(context).apply {
                text = value
                setTextSize(TypedValue.COMPLEX_UNIT_PX, sizePx * .85f)
                includeFontPadding = false
                gravity = Gravity.CENTER
            }

            // 大肥鱼：透明 PNG 按原比例放进徽标框，不裁圆也不铺底。这里只放
            // 待机首帧当兜底，动起来由 OverlayPet 接管（assets/pet 逐帧素材）。
            "fish" -> ImageView(context).apply {
                scaleType = ImageView.ScaleType.FIT_CENTER
                setImageResource(R.mipmap.ic_launcher)
                val clip = value.ifEmpty { PET_IDLE_CLIP }
                (PetAssets.firstFrame(context, clip) ?: PetAssets.firstFrame(context, PET_IDLE_CLIP))
                    ?.let(::setImageBitmap)
            }

            else -> ImageView(context).apply {
                scaleType = ImageView.ScaleType.CENTER_CROP
                background = GradientDrawable().apply {
                    shape = GradientDrawable.OVAL
                    setColor(Color.TRANSPARENT)
                }
                outlineProvider = ViewOutlineProvider.BACKGROUND
                clipToOutline = true
                setImageResource(R.mipmap.ic_launcher)
                if (kind == "image") ownedIcon(context, value)?.let(::setImageBitmap)
            }
        }

    /** 相册导入的图标只认应用私有目录下的原件，尺寸与体积同样设上限，
     * 避免一个被篡改的路径变成解码大图的内存入口。 */
    private fun ownedIcon(context: Context, value: String): Bitmap? = runCatching {
        val file = File(value)
        val root = File(context.filesDir, "background-icons").canonicalFile
        if (!file.isFile || file.canonicalFile.parentFile != root) return@runCatching null
        if (file.length() > 1024 * 1024) return@runCatching null
        val dimensions = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(value, dimensions)
        if (dimensions.outWidth !in 1..512 || dimensions.outHeight !in 1..512) return@runCatching null
        BitmapFactory.decodeFile(value)
    }.getOrNull()
}
