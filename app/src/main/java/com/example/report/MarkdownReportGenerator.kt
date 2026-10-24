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
        if (job.isDemo || (authorization?.isDemo == true)) {
            sb.append("> **NOTICE: DEMO / SYNTHETIC ENVIRONMENT**  \n")
            sb.append("> This report was produced in an isolated demonstration environment using simulated or seeded fixtures.\n\n")
        }

        sb.append("**Target Host:** `${job.resolvedHost}` (${job.resolvedIps})  \n")
        sb.append("**Assessment Date:** $completedDate  \n")
        sb.append("**Lead Assessor:** ${job.triggeredBy}  \n")
        sb.append("**Overall Posture Grade:** **${job.postureGrade}** (${job.postureScore}/100)  \n")
        sb.append("**Defensive Checks Run:** ${job.checksPassedCount} Passed | ${job.checksFailedCount} Failed / Flagged  \n\n")

        sb.append("## 1. Engagement & Written Authorization\n\n")
        sb.append("- **Client Organization:** ${client?.organization ?: "Authorized Client"} (${client?.name ?: "N/A"})\n")
        sb.append("- **Engagement Title:** ${engagement?.title ?: "N/A"}\n")
        sb.append("- **Document Reference:** `${authorization?.documentReference ?: "Awaiting Signed ROA"}`\n")
        val roaStatusStr = authorization?.verificationStatus?.label ?: "PENDING_VERIFICATION"
        val permittedStr = if (authorization?.explicitTestingPermitted == true) "Testing Permitted" else "Testing Blocked"
        sb.append("- **ROA Verification Status:** **$roaStatusStr** ($permittedStr)\n")
        if (!authorization?.verifiedBy.isNullOrBlank()) {
            sb.append("- **Verified By Auditor:** ${authorization?.verifiedBy}\n")
        }
        if (!authorization?.evidenceHash.isNullOrBlank()) {
            sb.append("- **Document SHA-256 Hash:** `${authorization?.evidenceHash}`\n")
        }
        sb.append("- **Authorized Officer:** ${authorization?.authorizedByName ?: "N/A"} (${authorization?.authorizedByRole ?: "N/A"})\n")
        sb.append("- **Emergency Contact:** ${authorization?.emergencyContactPhone ?: "N/A"}\n")
        sb.append("- **Scope Boundaries:** Strict non-destructive defensive checks on `${scopes.joinToString(", ") { it.hostname }}`\n\n")

        sb.append("## 2. Executive Metrics & Check Results\n\n")
        sb.append("| Metric | Count |\n")
        sb.append("|---|---|\n")
        sb.append("| **Checks Passed** | ${job.checksPassedCount} |\n")
        sb.append("| **Checks Failed / Penalized** | ${job.checksFailedCount} |\n")
        sb.append("| **Critical Findings** | ${job.criticalCount} |\n")
        sb.append("| **High Severity** | ${job.highCount} |\n")
        sb.append("| **Medium Severity** | ${job.mediumCount} |\n")
        sb.append("| **Low Severity** | ${job.lowCount} |\n")
        sb.append("| **Informational** | ${job.infoCount} |\n")
        sb.append("| **Total Findings / Observations** | **${findings.size}** |\n\n")

        sb.append("## 3. Defensive Findings & Observations\n\n")
        if (findings.isEmpty()) {
            sb.append("*No security misconfigurations or unencrypted endpoints detected in audited scope.*\n\n")
        } else {
            findings.forEachIndexed { index, finding ->
                sb.append("### 3.${index + 1} [${finding.severity.label}] ${finding.title}\n\n")
                sb.append("- **Category:** ${finding.category.label}\n")
                sb.append("- **Standard Classification:** ${finding.cweId} | ${finding.owaspCategory}\n")
                sb.append("- **Verification Status:** **${finding.status.label}** (${finding.confidence.label})\n")
                if (!finding.verifiedBy.isNullOrBlank()) {
                    sb.append("- **Auditor Sign-off:** ${finding.verifiedBy}\n")
                }
                sb.append("\n**Summary:**  \n${finding.summary}\n\n")
                sb.append("**Technical Evidence:**  \n```\n${finding.technicalEvidence}\n```\n\n")
                sb.append("**Business & Technical Impact:**  \n${finding.impact}\n\n")
                sb.append("**Remediation Guidance:**  \n${finding.remediationGuidance}\n\n")
                if (finding.verificationCurl.isNotBlank()) {
                    sb.append("**Reproduction / Verification Command:**  \n```bash\n${finding.verificationCurl}\n```\n\n")
                }
                sb.append("---\n\n")
            }
        }

        sb.append("## 4. Methodology & Scope Limitations\n\n")
        sb.append("1. **Defensive-Only Inspection:** All evaluations were conducted defensively against explicitly approved client assets via DNS, TLS handshake parameter negotiation, and HTTP security header inspection.\n")
        sb.append("2. **Strict Exclusions:** No denial-of-service, vulnerability fuzzing, authentication credential attacks, data interception, or destructive testing were conducted.\n")
        sb.append("3. **Scope Restrictions:** Out-of-scope hostnames and redirect targets were blocked by the Sentinel Pro fail-closed scope validator.\n")
        sb.append("4. **Findings Verification:** Automated observations reflect observable runtime configurations. Assessor review is recommended prior to architectural modifications.\n")

        return sb.toString()
    }
}
