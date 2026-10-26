package org.selfhosted.securemessenger

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

// Fallback palette (Android < 12): deep teal, matching the app icon.
private val Light = lightColorScheme(
    primary = Color(0xFF006A66),
    onPrimary = Color.White,
    primaryContainer = Color(0xFF9EF2EC),
    onPrimaryContainer = Color(0xFF00201E),
    secondary = Color(0xFF4A6361),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFCCE8E5),
    onSecondaryContainer = Color(0xFF051F1E),
    tertiary = Color(0xFF48607B),
    tertiaryContainer = Color(0xFFD0E4FF),
    background = Color(0xFFF4FBF9),
    surface = Color(0xFFF4FBF9),
    surfaceVariant = Color(0xFFDAE5E2),
    surfaceContainer = Color(0xFFE9EFED),
    surfaceContainerHigh = Color(0xFFE3EAE8),
    surfaceContainerHighest = Color(0xFFDDE4E2),
)

private val Dark = darkColorScheme(
    primary = Color(0xFF82D5D0),
    onPrimary = Color(0xFF003735),
    primaryContainer = Color(0xFF00504D),
    onPrimaryContainer = Color(0xFF9EF2EC),
    secondary = Color(0xFFB0CCC9),
    onSecondary = Color(0xFF1C3533),
    secondaryContainer = Color(0xFF324B49),
    onSecondaryContainer = Color(0xFFCCE8E5),
    tertiary = Color(0xFFB0C9E8),
    tertiaryContainer = Color(0xFF304862),
    background = Color(0xFF0E1514),
    surface = Color(0xFF0E1514),
    surfaceVariant = Color(0xFF3F4948),
    surfaceContainer = Color(0xFF1A2120),
    surfaceContainerHigh = Color(0xFF252B2A),
    surfaceContainerHighest = Color(0xFF2F3635),
)

/** Follows the system light/dark mode; Android 12+ uses the wallpaper colours. */
@Composable
fun AppTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> Dark
        else -> Light
    }
    MaterialTheme(colorScheme = colors, content = content)
}

private val avatarColors = listOf(
    Color(0xFF00897B), Color(0xFF5E35B1), Color(0xFFD81B60), Color(0xFF3949AB),
    Color(0xFFF4511E), Color(0xFF7CB342), Color(0xFF8E24AA), Color(0xFF00ACC1),
)

/** A stable colour per name (avatars, sender names in groups). */
fun colorFor(name: String): Color = avatarColors[Math.floorMod(name.hashCode(), avatarColors.size)]
