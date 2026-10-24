package com.example.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.model.Severity
import com.example.ui.theme.CyberSlate700
import com.example.ui.theme.CyberSlate800
import com.example.ui.theme.CyberSlate900
import com.example.ui.theme.SentinelCyan
import com.example.ui.theme.SeverityClean
import com.example.ui.theme.SeverityCleanBg
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityCriticalBg
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityHighBg
import com.example.ui.theme.SeverityInfo
import com.example.ui.theme.SeverityInfoBg
import com.example.ui.theme.SeverityLow
import com.example.ui.theme.SeverityLowBg
import com.example.ui.theme.SeverityMedium
import com.example.ui.theme.SeverityMediumBg

@Composable
fun SeverityBadge(severity: Severity, modifier: Modifier = Modifier) {
    val (bgColor, fgColor) = when (severity) {
        Severity.CRITICAL -> SeverityCriticalBg to SeverityCritical
        Severity.HIGH -> SeverityHighBg to SeverityHigh
        Severity.MEDIUM -> SeverityMediumBg to SeverityMedium
        Severity.LOW -> SeverityLowBg to SeverityLow
        Severity.INFORMATIONAL -> SeverityInfoBg to SeverityInfo
    }

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(4.dp))
            .background(bgColor)
            .border(1.dp, fgColor.copy(alpha = 0.4f), RoundedCornerShape(4.dp))
            .padding(horizontal = 8.dp, vertical = 2.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = severity.label,
            color = fgColor,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
fun PostureGradeBadge(
    grade: String,
    score: Int,
    modifier: Modifier = Modifier
) {
    val color = when (grade) {
        "A+", "A" -> SeverityClean
        "B" -> SentinelCyan
        "C" -> SeverityMedium
        else -> SeverityCritical
    }

    Row(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(CyberSlate900)
            .border(1.5.dp, color.copy(alpha = 0.6f), RoundedCornerShape(12.dp))
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(46.dp)
                .clip(CircleShape)
                .background(color.copy(alpha = 0.2f))
                .border(1.5.dp, color, CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = grade,
                color = color,
                fontSize = 20.sp,
                fontWeight = FontWeight.Black
            )
        }

        Spacer(modifier = Modifier.width(12.dp))

        Column {
            Text(
                text = "DEFENSIVE POSTURE",
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                letterSpacing = 1.sp
            )
            Text(
                text = "$score / 100",
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}

@Composable
fun ScopeStatusChip(
    isInScope: Boolean,
    modifier: Modifier = Modifier
) {
    val bgColor = if (isInScope) SeverityCleanBg else SeverityCriticalBg
    val fgColor = if (isInScope) SeverityClean else SeverityCritical
    val label = if (isInScope) "AUTHORIZED & IN-SCOPE" else "SCOPE VIOLATION / BLOCKED"

    Row(
        modifier = modifier
            .clip(RoundedCornerShape(6.dp))
            .background(bgColor)
            .border(1.dp, fgColor.copy(alpha = 0.5f), RoundedCornerShape(6.dp))
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(6.dp)
                .clip(CircleShape)
                .background(fgColor)
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = label,
            color = fgColor,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace
        )
    }
}
