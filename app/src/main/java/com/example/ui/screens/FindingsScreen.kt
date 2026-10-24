package com.example.ui.screens

import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.model.FindingStatus
import com.example.data.model.SecurityFindingEntity
import com.example.data.model.Severity
import com.example.ui.SentinelViewModel
import com.example.ui.components.SeverityBadge
import com.example.ui.theme.CyberSlate700
import com.example.ui.theme.CyberSlate800
import com.example.ui.theme.CyberSlate900
import com.example.ui.theme.SentinelCyan
import com.example.ui.theme.SeverityClean
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityLow
import com.example.ui.theme.SeverityMedium

@Composable
fun FindingsScreen(
    viewModel: SentinelViewModel,
    modifier: Modifier = Modifier
) {
    val findings by viewModel.selectedJobFindings.collectAsState()
    val selectedJob by viewModel.selectedJob.collectAsState()

    var selectedSeverityFilter by remember { mutableStateOf<Severity?>(null) }

    val filteredFindings = remember(findings, selectedSeverityFilter) {
        if (selectedSeverityFilter == null) findings else findings.filter { it.severity == selectedSeverityFilter }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag("findings_screen_list"),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Summary Header Card
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = CyberSlate900),
                border = androidx.compose.foundation.BorderStroke(1.dp, CyberSlate700),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().testTag("findings_header_card")
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "SECURITY FINDINGS REPOSITORY",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = SentinelCyan,
                            letterSpacing = 1.sp
                        )

                        Text(
                            text = "${findings.size} Total Items",
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "Target: ${selectedJob?.resolvedHost ?: "None Selected"}",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        text = "Every finding below is backed by captured technical evidence and CWE classification.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        // Severity Filter Chips Row
        item {
            LazyRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth().testTag("filter_chips_row")
            ) {
                item {
                    FilterChip(
                        label = "All (${findings.size})",
                        isSelected = selectedSeverityFilter == null,
                        onClick = { selectedSeverityFilter = null }
                    )
                }
                item {
                    val count = findings.count { it.severity == Severity.CRITICAL }
                    FilterChip(
                        label = "Critical ($count)",
                        isSelected = selectedSeverityFilter == Severity.CRITICAL,
                        badgeColor = SeverityCritical,
                        onClick = { selectedSeverityFilter = Severity.CRITICAL }
                    )
                }
                item {
                    val count = findings.count { it.severity == Severity.HIGH }
                    FilterChip(
                        label = "High ($count)",
                        isSelected = selectedSeverityFilter == Severity.HIGH,
                        badgeColor = SeverityHigh,
                        onClick = { selectedSeverityFilter = Severity.HIGH }
                    )
                }
                item {
                    val count = findings.count { it.severity == Severity.MEDIUM }
                    FilterChip(
                        label = "Medium ($count)",
                        isSelected = selectedSeverityFilter == Severity.MEDIUM,
                        badgeColor = SeverityMedium,
                        onClick = { selectedSeverityFilter = Severity.MEDIUM }
                    )
                }
                item {
                    val count = findings.count { it.severity == Severity.LOW }
                    FilterChip(
                        label = "Low ($count)",
                        isSelected = selectedSeverityFilter == Severity.LOW,
                        badgeColor = SeverityLow,
                        onClick = { selectedSeverityFilter = Severity.LOW }
                    )
                }
            }
        }

        // Findings List
        if (filteredFindings.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 40.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (findings.isEmpty()) "No assessment findings available. Run an assessment on an approved target." else "No findings match the selected filter.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 13.sp
                    )
                }
            }
        } else {
            items(filteredFindings) { finding ->
                FindingDetailCard(
                    finding = finding,
                    onStatusChange = { newStatus ->
                        viewModel.updateFindingStatus(finding, newStatus)
                    }
                )
            }
        }
    }
}

@Composable
fun FilterChip(
    label: String,
    isSelected: Boolean,
    badgeColor: Color? = null,
    onClick: () -> Unit
) {
    val borderColor = if (isSelected) (badgeColor ?: SentinelCyan) else CyberSlate700
    val bgColor = if (isSelected) (badgeColor ?: SentinelCyan).copy(alpha = 0.18f) else CyberSlate900

    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(bgColor)
            .border(1.dp, borderColor, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 6.dp)
            .testTag("filter_chip_$label")
    ) {
        Text(
            text = label,
            fontSize = 12.sp,
            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
            color = if (isSelected) (badgeColor ?: SentinelCyan) else MaterialTheme.colorScheme.onSurface
        )
    }
}

@Composable
fun FindingDetailCard(
    finding: SecurityFindingEntity,
    onStatusChange: (FindingStatus) -> Unit,
    modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(false) }
    var showStatusMenu by remember { mutableStateOf(false) }
    val clipboardManager = LocalClipboardManager.current
    val context = LocalContext.current

    Card(
        colors = CardDefaults.cardColors(containerColor = CyberSlate900),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberSlate700),
        shape = RoundedCornerShape(12.dp),
        modifier = modifier.fillMaxWidth().testTag("finding_card_${finding.id.take(8)}")
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Header Row: Severity + Status dropdown
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SeverityBadge(severity = finding.severity)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = finding.category.label,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Box {
                    OutlinedButton(
                        onClick = { showStatusMenu = true },
                        modifier = Modifier.testTag("btn_change_status_${finding.id.take(8)}")
                    ) {
                        Text(finding.status.label, fontSize = 11.sp)
                    }

                    DropdownMenu(
                        expanded = showStatusMenu,
                        onDismissRequest = { showStatusMenu = false }
                    ) {
                        FindingStatus.entries.forEach { status ->
                            DropdownMenuItem(
                                text = { Text(status.label, fontSize = 12.sp) },
                                onClick = {
                                    onStatusChange(status)
                                    showStatusMenu = false
                                }
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Title
            Text(
                text = finding.title,
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(4.dp))

            // CWE & OWASP Tags
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "${finding.cweId}  •  ${finding.owaspCategory}",
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = SentinelCyan
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Summary
            Text(
                text = finding.summary,
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                lineHeight = 18.sp
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Expand / Collapse Details Button
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded }
                    .padding(vertical = 4.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = if (expanded) "Hide Technical Evidence & Remediation" else "Show Evidence & Remediation Guidance",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = SentinelCyan
                )
                Icon(
                    imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = "Expand",
                    tint = SentinelCyan
                )
            }

            AnimatedVisibility(visible = expanded) {
                Column(modifier = Modifier.padding(top = 10.dp)) {
                    // Technical Evidence
                    Text(
                        text = "CAPTURED TECHNICAL EVIDENCE",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        letterSpacing = 1.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(6.dp))
                            .background(CyberSlate800)
                            .padding(10.dp)
                    ) {
                        Text(
                            text = finding.technicalEvidence,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Color(0xFFE2E8F0)
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    // Impact
                    Text(
                        text = "SECURITY IMPACT",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        letterSpacing = 1.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = finding.impact,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurface,
                        lineHeight = 17.sp
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    // Remediation Guidance
                    Text(
                        text = "REMEDIATION GUIDANCE",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = SeverityClean,
                        letterSpacing = 1.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = finding.remediationGuidance,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurface,
                        lineHeight = 17.sp
                    )

                    // Reproduction command if available
                    if (finding.verificationCurl.isNotBlank()) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "VERIFICATION COMMAND",
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                letterSpacing = 1.sp
                            )
                            IconButton(
                                onClick = {
                                    clipboardManager.setText(AnnotatedString(finding.verificationCurl))
                                    Toast.makeText(context, "Command copied to clipboard", Toast.LENGTH_SHORT).show()
                                },
                                modifier = Modifier.size(24.dp)
                            ) {
                                Icon(Icons.Default.ContentCopy, contentDescription = "Copy", tint = SentinelCyan, modifier = Modifier.size(16.dp))
                            }
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(6.dp))
                                .background(CyberSlate800)
                                .padding(8.dp)
                        ) {
                            Text(
                                text = finding.verificationCurl,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                color = SentinelCyan
                            )
                        }
                    }
                }
            }
        }
    }
}
