package com.example.ui.screens

import android.content.Intent
import android.widget.Toast
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.PictureAsPdf
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.runtime.rememberCoroutineScope
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
import androidx.core.content.FileProvider
import com.example.data.model.AssessmentJobEntity
import com.example.data.model.AuditAction
import com.example.data.model.AuditLogEntity
import com.example.ui.SentinelViewModel
import com.example.ui.components.PostureGradeBadge
import com.example.ui.theme.CyberSlate700
import com.example.ui.theme.CyberSlate800
import com.example.ui.theme.CyberSlate900
import com.example.ui.theme.SentinelCyan
import com.example.ui.theme.SeverityClean
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityMedium
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ReportsScreen(
    viewModel: SentinelViewModel,
    modifier: Modifier = Modifier
) {
    val recentJobs by viewModel.recentJobs.collectAsState()
    val selectedJob by viewModel.selectedJob.collectAsState()
    val auditLogs by viewModel.auditLogs.collectAsState()

    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val coroutineScope = rememberCoroutineScope()

    var isGeneratingPdf by remember { mutableStateOf(false) }

    val auditChainStatus by viewModel.auditChainStatus.collectAsState()

    val activeJob = selectedJob ?: recentJobs.firstOrNull()
    val dateFormat = remember { SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US) }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag("reports_screen_list"),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // PDF Report Generation Card
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = CyberSlate900),
                border = androidx.compose.foundation.BorderStroke(1.dp, SentinelCyan),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().testTag("export_report_card")
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.PictureAsPdf,
                            contentDescription = "PDF Report",
                            tint = SentinelCyan,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "SECURITY AUDIT REPORT EXPORT",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = SentinelCyan,
                            letterSpacing = 1.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    if (activeJob != null) {
                        Text(
                            text = "Target: ${activeJob.resolvedHost}",
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "Grade: ${activeJob.postureGrade} (${activeJob.postureScore}/100) • Checks: ${activeJob.checksPassedCount} passed / ${activeJob.checksFailedCount} failed • Findings: ${activeJob.totalFindingsCount}",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        Spacer(modifier = Modifier.height(14.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Button(
                                onClick = {
                                    coroutineScope.launch {
                                        isGeneratingPdf = true
                                        val file = viewModel.generatePdfReport(activeJob)
                                        isGeneratingPdf = false
                                        if (file != null) {
                                            try {
                                                val uri = FileProvider.getUriForFile(
                                                    context,
                                                    "${context.packageName}.provider",
                                                    file
                                                )
                                                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                                    type = "application/pdf"
                                                    putExtra(Intent.EXTRA_STREAM, uri)
                                                    putExtra(Intent.EXTRA_SUBJECT, "Sentinel Pro Security Report - ${activeJob.resolvedHost}")
                                                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                                }
                                                context.startActivity(Intent.createChooser(shareIntent, "Share Security PDF Report"))
                                            } catch (e: Exception) {
                                                Toast.makeText(context, "PDF saved to: ${file.name}", Toast.LENGTH_LONG).show()
                                            }
                                        } else {
                                            Toast.makeText(context, "Failed to compile PDF report", Toast.LENGTH_SHORT).show()
                                        }
                                    }
                                },
                                enabled = !isGeneratingPdf,
                                colors = ButtonDefaults.buttonColors(containerColor = SentinelCyan),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.weight(1f).testTag("btn_export_pdf")
                            ) {
                                if (isGeneratingPdf) {
                                    CircularProgressIndicator(strokeWidth = 2.dp, color = CyberSlate900, modifier = Modifier.size(16.dp))
                                } else {
                                    Icon(Icons.Default.Share, contentDescription = "Share", tint = CyberSlate900, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Export PDF", color = CyberSlate900, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                }
                            }

                            OutlinedButton(
                                onClick = {
                                    coroutineScope.launch {
                                        val md = viewModel.generateMarkdownReport(activeJob)
                                        clipboardManager.setText(AnnotatedString(md))
                                        Toast.makeText(context, "Markdown report copied to clipboard", Toast.LENGTH_SHORT).show()
                                    }
                                },
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.weight(1f).testTag("btn_copy_markdown")
                            ) {
                                Icon(Icons.Default.ContentCopy, contentDescription = "Copy", modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Copy Markdown", fontSize = 12.sp)
                            }
                        }
                    } else {
                        Text(
                            text = "No assessment runs completed yet. Run an audit first to generate reports.",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        // Recent Scans History Section
        if (recentJobs.isNotEmpty()) {
            item {
                Text(
                    text = "ASSESSMENT HISTORY (${recentJobs.size})",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = SentinelCyan,
                    letterSpacing = 1.sp
                )
            }

            items(recentJobs.take(5)) { job ->
                val isSelected = activeJob?.id == job.id
                Card(
                    colors = CardDefaults.cardColors(containerColor = if (isSelected) CyberSlate800 else CyberSlate900),
                    border = androidx.compose.foundation.BorderStroke(1.dp, if (isSelected) SentinelCyan else CyberSlate700),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { viewModel.selectJob(job) }
                        .testTag("job_history_item_${job.id.take(8)}")
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = job.resolvedHost,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "${dateFormat.format(Date(job.startedAt))} • Status: ${job.status}",
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(SentinelCyan.copy(alpha = 0.15f))
                                .padding(horizontal = 10.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = "Grade ${job.postureGrade} (${job.postureScore})",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = SentinelCyan
                            )
                        }
                    }
                }
            }
        }

        // Audit Chain Integrity Verification Card
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = CyberSlate900),
                border = androidx.compose.foundation.BorderStroke(
                    1.dp,
                    if (auditChainStatus?.isValid == true) SeverityClean else if (auditChainStatus?.isValid == false) SeverityCritical else CyberSlate700
                ),
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.fillMaxWidth().testTag("audit_chain_verification_card")
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Shield,
                                contentDescription = "Chain Integrity",
                                tint = if (auditChainStatus?.isValid == true) SeverityClean else SentinelCyan,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "AUDIT CHAIN CRYPTOGRAPHIC INTEGRITY",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (auditChainStatus?.isValid == true) SeverityClean else SentinelCyan,
                                letterSpacing = 1.sp
                            )
                        }

                        OutlinedButton(
                            onClick = { viewModel.verifyAuditChain() },
                            modifier = Modifier.testTag("btn_verify_audit_chain")
                        ) {
                            Text("Verify Chain", fontSize = 11.sp)
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    if (auditChainStatus != null) {
                        val status = auditChainStatus!!
                        if (status.isValid) {
                            Text(
                                text = "CHAIN INTACT: ${status.totalEntries} entries verified. Previous-hash linkages and SHA-256 signatures are cryptographically valid.",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = SeverityClean
                            )
                        } else {
                            Text(
                                text = "TAMPERING DETECTED: Chain integrity check failed! Entry index: ${status.brokenAtIndex ?: "N/A"}. Reason: ${status.failureReason}",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = SeverityCritical
                            )
                        }
                    } else {
                        Text(
                            text = "Each audit log entry contains a cryptographic hash signature linked to the previous entry's SHA-256 hash. Run verification to confirm the log chain is unmodified.",
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        // Immutable Audit Trail Header
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.History, contentDescription = "Audit", tint = SeverityClean, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "AUDIT TRAIL RECORDS (${auditLogs.size})",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = SeverityClean,
                        letterSpacing = 1.sp
                    )
                }

                Text(
                    text = "Chained SHA-256",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // Audit Log Items
        items(auditLogs) { log ->
            AuditLogCard(log = log, dateFormat = dateFormat)
        }
    }
}

@Composable
fun AuditLogCard(
    log: AuditLogEntity,
    dateFormat: SimpleDateFormat,
    modifier: Modifier = Modifier
) {
    val actionColor = when (log.action) {
        AuditAction.SCOPE_VIOLATION_BLOCKED -> SeverityCritical
        AuditAction.AUTHORIZATION_SIGNED, AuditAction.SCAN_COMPLETED, AuditAction.INTEGRITY_CHECK_PASSED -> SeverityClean
        AuditAction.SCAN_CANCELLED, AuditAction.INTEGRITY_CHECK_FAILED -> SeverityCritical
        else -> SentinelCyan
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = CyberSlate900),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberSlate700),
        shape = RoundedCornerShape(8.dp),
        modifier = modifier.fillMaxWidth().testTag("audit_item_${log.id.take(8)}")
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(6.dp)
                            .clip(CircleShape)
                            .background(actionColor)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = log.action.label,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = actionColor
                    )
                }

                Text(
                    text = dateFormat.format(Date(log.timestamp)),
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "Actor: ${log.actor}  •  Target: ${log.target}",
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = log.details,
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(6.dp))

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(CyberSlate800.copy(alpha = 0.5f), RoundedCornerShape(4.dp))
                    .padding(horizontal = 6.dp, vertical = 4.dp)
            ) {
                Text(
                    text = "prev: ${log.previousHash.take(24)}...",
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "hash: ${log.hashSignature.take(24)}...",
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    color = SentinelCyan.copy(alpha = 0.8f)
                )
            }
        }
    }
}
