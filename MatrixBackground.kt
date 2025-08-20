package com.wimlee115.leecrypt

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.util.AttributeSet
import android.view.View
import java.util.Random

class MatrixBackground @JvmOverloads constructor(
    context: Context, attrs: AttributeSet? = null, defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private val paint = Paint().apply {
        color = Color.parseColor("#00FF00")
        textSize = 20f
        isAntiAlias = true
    }
    private val chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private val columns = mutableListOf<Pair<Float, Float>>()
    private val random = Random()

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        canvas.drawColor(Color.BLACK)
        if (columns.isEmpty()) {
            for (i in 0 until width / 20) {
                columns.add(Pair(i * 20f, random.nextFloat() * height))
            }
        }
        columns.forEachIndexed { index, (x, y) ->
            val char = chars[random.nextInt(chars.length)]
            canvas.drawText(char.toString(), x, y, paint)
            columns[index] = Pair(x, (y + 20f) % height)
        }
        invalidate()
    }
}
