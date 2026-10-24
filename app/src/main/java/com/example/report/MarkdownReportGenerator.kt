package com.example.report

import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AssessmentJobEntity
import com.example.data.model.AuthorizationRecordEntity
import com.example.data.model.ClientEntity
import com.example.data.model.EngagementEntity
import com.example.data.model.SecurityFindingEntity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object MarkdownReportGenerator {

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US)

    fun generateMarkdown(
        job: AssessmentJobEntity,
        engagement: EngagementEntity?,
        client: ClientEntity?,
        authorization: AuthorizationRecordEntity?,
        scopes: List<ApprovedScopeEntity>,
        findings: List<SecurityFindingEntity>
    ): String {
        val completedDate = dateFormat.format(Date(job.completedAt ?: System.currentTimeMillis()))
        val sb = StringBuilder()

        sb.append("# Sentinel Pro — Defensive Security Assessment Report\n\n")
        sb.append("**Target Host:** `${job.resolvedHost}` (${job.resolvedIps})  \n")
        sb.append("**Assessment Date:** $completedDate  \n")
        sb.append("**Lead Assessor:** ${job.triggeredBy}  \n")
        sb.append("**Overall Posture Grade:** **${job.postureGrade}** (${job.postureScore}/100)  \n\n")

        sb.append("## 1. Engagement & Written Authorization\n\n")
        sb.append("- **Client:** ${client?.organization ?: "Authorized Client"} (${client?.name ?: "N/A"})\n")
        sb.append("- **Engagement Title:** ${engagement?.title ?: "N/A"}\n")
        sb.append("- **Document Reference:** `${authorization?.documentReference ?: "ROA-SIGNED"}`\n")
        sb.append("- **Authorized Officer:** ${authorization?.authorizedByName ?: "N/A"} (${authorization?.authorizedByRole ?: "N/A"})\n")
        sb.append("- **Emergency Contact:** ${authorization?.emergencyContactPhone ?: "N/A"}\n")
        sb.append("- **Scope Boundaries:** Strict non-destructive testing on `${scopes.joinToString(", ") { it.hostname }}`\n\n")

        sb.append("## 2. Executive Metrics\n\n")
        sb.append("| Metric | Count |\n")
        sb.append("|---|---|\n")
        sb.append("| **Critical Findings** | ${job.criticalCount} |\n")
        sb.append("| **High Severity** | ${job.highCount} |\n")
        sb.append("| **Medium Severity** | ${job.mediumCount} |\n")
        sb.append("| **Low Severity** | ${job.lowCount} |\n")
        sb.append("| **Informational** | ${job.infoCount} |\n")
        sb.append("| **Total Verified Issues** | **${findings.size}** |\n\n")

        sb.append("## 3. Verified Defensive Findings & Remediation Guidance\n\n")
        if (findings.isEmpty()) {
            sb.append("*No security misconfigurations or unencrypted endpoints detected in audited scope.*\n\n")
        } else {
            findings.forEachIndexed { index, finding ->
                sb.append("### 3.${index + 1} [${finding.severity.label}] ${finding.title}\n\n")
                sb.append("- **Category:** ${finding.category.label}\n")
                sb.append("- **Standard Classification:** ${finding.cweId} | ${finding.owaspCategory}\n")
                sb.append("- **Verification Status:** ${finding.status.label} (${finding.confidence.label})\n\n")
                sb.append("**Summary:**  \n${finding.summary}\n\n")
                sb.append("**Technical Evidence:**  \n```\n${finding.technicalEvidence}\n```\n\n")
                sb.append("**Business & Technical Impact:**  \n${finding.impact}\n\n")
                sb.append("**Remediation Guidance:**  \n${finding.remediationGuidance}\n\n")
                if (finding.verificationCurl.isNotBlank()) {
                    sb.append("**Reproduction / Verification Command:**  \n```bash\n${finding.verificationCurl}\n```\n\n")
                }
                sb.append("---\n\n")
            }
        }

        sb.append("## 4. Methodology & Safety Statement\n\n")
        sb.append("All security evaluations were conducted defensively against explicitly approved and authorized client assets. Tests were executed using standard protocol inspections, TLS handshake validation, passive DNS-over-HTTPS queries, and HTTP header auditing. No denial-of-service, destructive exploits, or credential attacks were executed.\n")

        return sb.toString()
    }
}
