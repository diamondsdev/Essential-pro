package com.example.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey
import java.util.UUID

@Entity(tableName = "clients")
data class ClientEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val name: String,
    val organization: String,
    val contactEmail: String,
    val isDemo: Boolean = false,
    val createdAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "engagements")
data class EngagementEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val clientId: String,
    val title: String,
    val engagementType: String = "Defensive Website Security Assessment",
    val leadAssessor: String = "Lead SecOps Assessor",
    val status: EngagementStatus = EngagementStatus.ACTIVE,
    val targetEnvironment: String = "Production (Passive / Non-Destructive)",
    val startDate: Long = System.currentTimeMillis() - 86400000L * 7,
    val endDate: Long = System.currentTimeMillis() + 86400000L * 30,
    val isDemo: Boolean = false,
    val createdAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "authorizations")
data class AuthorizationRecordEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val engagementId: String,
    val authorizedByName: String,
    val authorizedByRole: String,
    val authorizedByEmail: String,
    val documentReference: String, // e.g. "SOW-2026-0492 / ROA-SIGNED-PDF"
    val evidenceHash: String = "", // SHA-256 of verified written document
    val verificationStatus: AuthorizationStatus = AuthorizationStatus.PENDING_VERIFICATION,
    val verifiedBy: String? = null,
    val verifiedAtTimestamp: Long? = null,
    val authorizationScopeSummary: String,
    val validFromTimestamp: Long,
    val validToTimestamp: Long,
    val explicitTestingPermitted: Boolean = false, // MUST remain false until verified by auditor
    val emergencyContactPhone: String,
    val signedAtTimestamp: Long = System.currentTimeMillis(),
    val rulesOfEngagementNotes: String = "Strictly non-destructive defensive checks only. No DoS, no credential stuffing.",
    val isDemo: Boolean = false,
    val revokedAtTimestamp: Long? = null,
    val revocationReason: String? = null
)

@Entity(tableName = "approved_scopes")
data class ApprovedScopeEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val engagementId: String,
    val hostname: String, // e.g. "scanme.nmap.org", "example.com"
    val wildcardAllowed: Boolean = false,
    val allowedPorts: String = "80,443",
    val pathPrefix: String = "/",
    val active: Boolean = true,
    val isDemo: Boolean = false,
    val addedAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "assessment_jobs")
data class AssessmentJobEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val engagementId: String,
    val targetUrl: String,
    val resolvedHost: String,
    val resolvedIps: String,
    val status: String, // "QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", "INCOMPLETE"
    val triggeredBy: String = "Lead Assessor",
    val startedAt: Long = System.currentTimeMillis(),
    val completedAt: Long? = null,
    val totalFindingsCount: Int = 0,
    val criticalCount: Int = 0,
    val highCount: Int = 0,
    val mediumCount: Int = 0,
    val lowCount: Int = 0,
    val infoCount: Int = 0,
    val checksPassedCount: Int = 0,
    val checksFailedCount: Int = 0,
    val postureScore: Int = 100, // 0 - 100
    val postureGrade: String = "A",
    val summaryNotes: String = "",
    val errorMessage: String? = null,
    val isDemo: Boolean = false
)

@Entity(tableName = "security_findings")
data class SecurityFindingEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val jobId: String,
    val engagementId: String,
    val category: FindingCategory,
    val title: String,
    val severity: Severity,
    val confidence: Confidence = Confidence.HIGH,
    val status: FindingStatus = FindingStatus.AUTOMATED_OBSERVATION,
    val cweId: String, // e.g. "CWE-693", "CWE-319"
    val owaspCategory: String, // e.g. "A05:2021-Security Misconfiguration"
    val summary: String,
    val technicalEvidence: String, // Headers, Cert values, DNS TXT answers
    val impact: String,
    val remediationGuidance: String,
    val verificationCurl: String = "",
    val verifiedBy: String? = null,
    val verifiedAtTimestamp: Long? = null,
    val createdAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "audit_logs")
data class AuditLogEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val timestamp: Long,
    val actor: String,
    val action: AuditAction,
    val target: String,
    val details: String,
    val previousHash: String, // Link to previous log's hash in blockchain-style chain
    val hashSignature: String // SHA-256(previousHash + "|" + timestamp + "|" + actor + "|" + action + "|" + target + "|" + details)
)
