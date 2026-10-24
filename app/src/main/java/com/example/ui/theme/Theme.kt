package com.example.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColorScheme = darkColorScheme(
    primary = SentinelCyan,
    onPrimary = CyberSlate950,
    primaryContainer = SentinelCyanDark,
    onPrimaryContainer = Color.White,
    secondary = SentinelTeal,
    onSecondary = CyberSlate950,
    secondaryContainer = SentinelTealDark,
    onSecondaryContainer = Color.White,
    background = CyberSlate950,
    onBackground = CyberSlate100,
    surface = CyberSlate900,
    onSurface = CyberSlate100,
    surfaceVariant = CyberSlate800,
    onSurfaceVariant = CyberSlate200,
    outline = CyberSlate600,
    outlineVariant = CyberSlate700,
    error = SeverityCritical,
    onError = Color.White
)

private val LightColorScheme = lightColorScheme(
    primary = SentinelCyanDark,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFBAE6FD),
    onPrimaryContainer = CyberSlate950,
    secondary = SentinelTealDark,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFF99F6E4),
    onSecondaryContainer = CyberSlate950,
    background = Color(0xFFF8FAFC),
    onBackground = CyberSlate950,
    surface = Color.White,
    onSurface = CyberSlate950,
    surfaceVariant = Color(0xFFF1F5F9),
    onSurfaceVariant = CyberSlate700,
    outline = CyberSlate400,
    outlineVariant = Color(0xFFCBD5E1),
    error = SeverityCritical,
    onError = Color.White
)

@Composable
fun SentinelTheme(
    darkTheme: Boolean = true, // Default to sleek cybersecurity dark mode
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}

// Backward compatibility alias
@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    SentinelTheme(darkTheme = darkTheme, content = content)
}
