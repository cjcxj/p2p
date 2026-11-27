package com.example.p2pdemo

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val LightScheme = lightColorScheme(
    primary = Color(0xFF0F6D4F),
    onPrimary = Color(0xFFFFFFFF),
    secondary = Color(0xFF1F5B8A),
    tertiary = Color(0xFF6A4E1B),
)

private val DarkScheme = darkColorScheme(
    primary = Color(0xFF6FD3A8),
    secondary = Color(0xFF8FC7F0),
    tertiary = Color(0xFFE3C177),
)

/**
 * 界面主题。Material3 的配色跟随深浅色，状态语义（直连绿 / 连接中黄 / 错误红）
 * 由组件自己给，保证在两种主题下含义一致。
 */
@Composable
fun MeshTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkScheme else LightScheme,
        content = content,
    )
}
