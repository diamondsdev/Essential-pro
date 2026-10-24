package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.engine.ScanStepStatus
import com.example.ui.SentinelViewModel
import com.example.ui.components.PostureGradeBadge
import com.example.ui.components.ScopeStatusChip
import com.example.ui.theme.CyberSlate700
import com.example.ui.theme.CyberSlate800
import com.example.ui.theme.CyberSlate900
import com.example.ui.theme.SentinelCyan
import com.example.ui.theme.SeverityClean
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityCriticalBg
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityLow
import com.example.ui.theme.SeverityMedium

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ScannerScreen(
    viewModel: SentinelViewModel,
    onNavigateToFindings: () -> Unit,
    modifier: Modifier = Modifier
) {
    val scopes by viewModel.currentScopes.collectAsState()
    val auth by viewModel.currentAuthorization.collectAsState()
    val isScanning by viewModel.isScanning.collectAsState()
    val scanStatus by viewModel.scanStatus.collectAsState()
    val selectedJob by viewModel.selectedJob.collectAsState()

    var targetUrlInput by remember {
        mutableStateOf(if (scopes.isNotEmpty()) "https://${scopes.first().hostname}" else "https://scanme.nmap.org")
    }

    // Derived scope check
    val isTargetInScope by remember(targetUrlInput, scopes, auth) {
        derivedStateOf {
            if (auth == null || !auth!!.explicitTestingPermitted) return@derivedStateOf false
            val cleanHost = targetUrlInput.trim().lowercase().removePrefix("https://").removePrefix("http://").substringBefore("/")
            scopes.any { s ->
                s.active && (if (s.wildcardAllowed) cleanHost == s.hostname || cleanHost.endsWith(".${s.hostname}") else cleanHost == s.hostname)
            }
        }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag("scanner_screen_list"),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Target Input Card
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = CyberSlate900),
                border = androidx.compose.foundation.BorderStroke(1.dp, CyberSlate700),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().testTag("scanner_input_card")
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "TARGET ASSET IDENTIFICATION",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = SentinelCyan,
                        letterSpacing = 1.sp
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedTextField(
                        value = targetUrlInput,
                        onValueChange = { targetUrlInput = it },
                        label = { Text("Target Website URL") },
                        placeholder = { Text("https://scanme.nmap.org") },
                        singleLine = true,
                        enabled = !isScanning,
                        modifier = Modifier.fillMaxWidth().testTag("input_target_url")
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    // Quick-select in-scope targets
                    Text(
                        text = "Authorized Scope Targets:",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        scopes.forEach { scope ->
                            val isSelected = targetUrlInput.contains(scope.hostname)
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(if (isSelected) SentinelCyan.copy(alpha = 0.2f) else CyberSlate800)
                                    .border(1.dp, if (isSelected) SentinelCyan else CyberSlate700, RoundedCornerShape(6.dp))
                                    .clickable(enabled = !isScanning) {
                                        targetUrlInput = "https://${scope.hostname}"
                                    }
                                    .padding(horizontal = 10.dp, vertical = 5.dp)
                                    .testTag("chip_target_${scope.hostname}")
                            ) {
                                Text(
                                    text = scope.hostname,
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = if (isSelected) SentinelCyan else MaterialTheme.colorScheme.onSurface,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    // Scope Gate Status Pill
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        ScopeStatusChip(isInScope = isTargetInScope)

                        if (!isScanning) {
                            Button(
                                onClick = {
                                    viewModel.startAssessment(targetUrlInput)
                                },
                                enabled = targetUrlInput.isNotBlank(),
                                colors = ButtonDefaults.buttonColors(containerColor = SentinelCyan),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.testTag("btn_run_assessment")
                            ) {
                                Icon(Icons.Default.PlayArrow, contentDescription = "Run", tint = CyberSlate900, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Execute Audit", color = CyberSlate900, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            }
                        } else {
                            OutlinedButton(
                                onClick = { viewModel.cancelAssessment() },
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = SeverityCritical),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.testTag("btn_cancel_assessment")
                            ) {
                                Icon(Icons.Default.Cancel, contentDescription = "Abort", tint = SeverityCritical, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Abort Test", color = SeverityCritical, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            }
                        }
                    }
                }
            }
        }

        // Live Scanning Progress Card
        if (isScanning || scanStatus is ScanStepStatus.Progress) {
            item {
                val progressData = scanStatus as? ScanStepStatus.Progress
                Card(
                    colors = CardDefaults.cardColors(containerColor = CyberSlate900),
                    border = androidx.compose.foundation.BorderStroke(1.dp, SentinelCyan),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth().testTag("scanning_progress_card")
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(
                                strokeWidth = 2.5.dp,
                                color = SentinelCyan,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = progressData?.step ?: "DEFENSIVE TESTING IN PROGRESS",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = SentinelCyan
                            )
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        val frac = progressData?.progressFraction ?: 0.1f
                        LinearProgressIndicator(
                            progress = { frac },
                            color = SentinelCyan,
                            trackColor = CyberSlate800,
                            modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp))
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = progressData?.detail ?: "Evaluating security boundaries...",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        // Scan Failed Error Banner
        if (scanStatus is ScanStepStatus.ScanFailed) {
            item {
                val error = (scanStatus as ScanStepStatus.ScanFailed).error
                Card(
                    colors = CardDefaults.cardColors(containerColor = SeverityCriticalBg),
                    border = androidx.compose.foundation.BorderStroke(1.dp, SeverityCritical),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth().testTag("scan_error_card")
                ) {
                    Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Error, contentDescription = "Error", tint = SeverityCritical)
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(
                            text = error,
                            color = SeverityCritical,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            }
        }

        // Scan Completed Summary Card
        if (selectedJob != null && selectedJob?.status == "COMPLETED") {
            item {
                val job = selectedJob!!
                Card(
                    colors = CardDefaults.cardColors(containerColor = CyberSlate900),
                    border = androidx.compose.foundation.BorderStroke(1.dp, SeverityClean.copy(alpha = 0.6f)),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth().testTag("scan_results_summary_card")
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.CheckCircle, contentDescription = "Done", tint = SeverityClean, modifier = Modifier.size(20.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "ASSESSMENT COMPLETED",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = SeverityClean,
                                    letterSpacing = 1.sp
                                )
                            }

                            Text(
                                text = job.resolvedHost,
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        // Score & Grade badge
                        PostureGradeBadge(
                            grade = job.postureGrade,
                            score = job.postureScore,
                            modifier = Modifier.fillMaxWidth()
                        )

                        Spacer(modifier = Modifier.height(14.dp))

                        // Severity Breakdown Bar
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            MetricPill(label = "Critical", count = job.criticalCount, color = SeverityCritical)
                            MetricPill(label = "High", count = job.highCount, color = SeverityHigh)
                            MetricPill(label = "Medium", count = job.mediumCount, color = SeverityMedium)
                            MetricPill(label = "Low", count = job.lowCount, color = SeverityLow)
                        }

                        Spacer(modifier = Modifier.height(16.dp))

                        Button(
                            onClick = onNavigateToFindings,
                            colors = ButtonDefaults.buttonColors(containerColor = SentinelCyan),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth().testTag("btn_inspect_findings")
                        ) {
                            Text(
                                text = "Inspect Verified Findings (${job.totalFindingsCount})",
                                color = CyberSlate900,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun MetricPill(label: String, count: Int, color: Color) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(color.copy(alpha = 0.12f))
            .border(1.dp, color.copy(alpha = 0.3f), RoundedCornerShape(6.dp))
            .padding(horizontal = 14.dp, vertical = 6.dp)
    ) {
        Text(
            text = count.toString(),
            fontSize = 16.sp,
            fontWeight = FontWeight.Bold,
            color = color
        )
        Text(
            text = label,
            fontSize = 10.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
