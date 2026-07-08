package com.wimlee115.leecrypt.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Matrix / cyberpunk-palet — donker met neon-groen.
val MatrixGreen = Color(0xFF00FF9C)
val MatrixCyan = Color(0xFF00E5FF)
val Amber = Color(0xFFF59E0B)
val VoidBlack = Color(0xFF0D1117)
val Surface = Color(0xFF161B22)
val OnSurface = Color(0xFFC9D1D9)
val ErrorRed = Color(0xFFEF4444)

private val LeeCryptColors = darkColorScheme(
    primary = MatrixGreen,
    onPrimary = VoidBlack,
    secondary = MatrixCyan,
    onSecondary = VoidBlack,
    tertiary = Amber,
    background = VoidBlack,
    onBackground = OnSurface,
    surface = Surface,
    onSurface = OnSurface,
    surfaceVariant = Surface,
    error = ErrorRed,
)

@Composable
fun LeeCryptTheme(content: @Composable () -> Unit) {
    // Altijd het donkere Matrix-thema; [isSystemInDarkTheme] hier bewust genegeerd.
    MaterialTheme(
        colorScheme = LeeCryptColors,
        typography = Typography(),
        content = content
    )
}
