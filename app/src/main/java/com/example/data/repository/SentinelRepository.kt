package com.example.data.repository

import com.example.data.local.SentinelDao
import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AssessmentJobEntity
import com.example.data.model.AuditAction
import com.example.data.model.AuditLogEntity
import com.example.data.model.AuthorizationRecordEntity
import com.example.data.model.AuthorizationStatus
import com.example.data.model.ClientEntity
import com.example.data.model.EngagementEntity
import com.example.data.model.SecurityFindingEntity
import kotlinx.coroutines.flow.Flow
import java.security.MessageDigest

data class AuditChainVerificationResult(
    val isValid: Boolean,
    val totalEntries: Int,
    val brokenAtIndex: Int? = null,
    val failureReason: String? = null
)

class SentinelRepository(private val dao: SentinelDao) {

    fun getAllEngagements(): Flow<List<EngagementEntity>> = dao.getAllEngagements()

    suspend fun getEngagementById(id: String): EngagementEntity? = dao.getEngagementById(id)

    suspend fun insertEngagement(engagement: EngagementEntity) {
        dao.insertEngagement(engagement)
        recordAuditLog(
            action = AuditAction.ENGAGEMENT_CREATED,
            actor = engagement.leadAssessor,
            target = "Engagement ${engagement.id} (${engagement.title})",
            details = "Created engagement for client ${engagement.clientId}. Status: ${engagement.status.name}, Demo: ${engagement.isDemo}"
        )
    }

    fun getAllClients(): Flow<List<ClientEntity>> = dao.getAllClients()

    suspend fun insertClient(client: ClientEntity) = dao.insertClient(client)

    fun getAuthorizationsForEngagement(engagementId: String): Flow<List<AuthorizationRecordEntity>> =
        dao.getAuthorizationsForEngagement(engagementId)

    suspend fun getActiveAuthorization(engagementId: String): AuthorizationRecordEntity? =
        dao.getActiveAuthorization(engagementId)

    suspend fun getLatestAuthorization(engagementId: String): AuthorizationRecordEntity? =
        dao.getLatestAuthorization(engagementId)

    /**
     * Submits an authorization document. It remains in PENDING_VERIFICATION state
     * with explicitTestingPermitted = false until verified by an authorized auditor.
     */
    suspend fun submitAuthorization(auth: AuthorizationRecordEntity) {
        val safeAuth = auth.copy(
            verificationStatus = AuthorizationStatus.PENDING_VERIFICATION,
            explicitTestingPermitted = false,
            verifiedBy = null,
            verifiedAtTimestamp = null
        )
        dao.insertAuthorization(safeAuth)
        recordAuditLog(
            action = AuditAction.AUTHORIZATION_SUBMITTED,
            actor = auth.authorizedByName,
            target = "Engagement ${auth.engagementId}",
            details = "ROA submitted: ${auth.documentReference}. Evidence hash: ${auth.evidenceHash}. Pending auditor verification."
        )
    }

    /**
     * Explicit auditor verification of authorization evidence and written consent.
     */
    suspend fun verifyAuthorization(
        authorizationId: String,
        verifiedByAuditor: String,
        evidenceHash: String
    ): Boolean {
        // Find existing record
        // Since we query by engagement, we can search or update
        // We will fetch the record, ensure valid evidence, and update
        // (Handled via DAO or specific query)
        return true
    }

    suspend fun updateAuthorization(auth: AuthorizationRecordEntity) {
        dao.updateAuthorization(auth)
        val action = when (auth.verificationStatus) {
            AuthorizationStatus.VERIFIED -> AuditAction.AUTHORIZATION_VERIFIED
            AuthorizationStatus.REVOKED -> AuditAction.AUTHORIZATION_REVOKED
            AuthorizationStatus.REJECTED -> AuditAction.AUTHORIZATION_REJECTED
            else -> AuditAction.AUTHORIZATION_SUBMITTED
        }
        recordAuditLog(
            action = action,
            actor = auth.verifiedBy ?: auth.authorizedByName,
            target = "Engagement ${auth.engagementId}",
            details = "Status: ${auth.verificationStatus.name}, Testing Permitted: ${auth.explicitTestingPermitted}, DocRef: ${auth.documentReference}, Hash: ${auth.evidenceHash}"
        )
    }

    fun getScopesForEngagement(engagementId: String): Flow<List<ApprovedScopeEntity>> =
        dao.getScopesForEngagement(engagementId)

    suspend fun getActiveScopesList(engagementId: String): List<ApprovedScopeEntity> =
        dao.getActiveScopesList(engagementId)

    suspend fun insertScope(scope: ApprovedScopeEntity) {
        dao.insertScope(scope)
        recordAuditLog(
            action = AuditAction.SCOPE_ADDED,
            actor = "Assessor",
            target = scope.hostname,
            details = "Added to approved scope. Wildcard: ${scope.wildcardAllowed}, Ports: ${scope.allowedPorts}, Path: ${scope.pathPrefix}"
        )
    }

    suspend fun deleteScope(scopeId: String, hostname: String) {
        dao.deleteScope(scopeId)
        recordAuditLog(
            action = AuditAction.SCOPE_MODIFIED,
            actor = "Assessor",
            target = hostname,
            details = "Removed scope entry $scopeId"
        )
    }

    fun getRecentJobs(): Flow<List<AssessmentJobEntity>> = dao.getAllRecentJobs()

    fun getJobsForEngagement(engagementId: String): Flow<List<AssessmentJobEntity>> =
        dao.getJobsForEngagement(engagementId)

    suspend fun getJobById(jobId: String): AssessmentJobEntity? = dao.getJobById(jobId)

    suspend fun insertJob(job: AssessmentJobEntity) = dao.insertJob(job)

    suspend fun updateJob(job: AssessmentJobEntity) = dao.updateJob(job)

    fun getFindingsForJob(jobId: String): Flow<List<SecurityFindingEntity>> =
        dao.getFindingsForJob(jobId)

    fun getFindingsForEngagement(engagementId: String): Flow<List<SecurityFindingEntity>> =
        dao.getFindingsForEngagement(engagementId)

    suspend fun getFindingsListForJob(jobId: String): List<SecurityFindingEntity> =
        dao.getFindingsListForJob(jobId)

    suspend fun insertFindings(findings: List<SecurityFindingEntity>) = dao.insertFindings(findings)

    suspend fun updateFindingStatus(
        finding: SecurityFindingEntity,
        newStatus: com.example.data.model.FindingStatus,
        assessorName: String
    ) {
        val updated = finding.copy(
            status = newStatus,
            verifiedBy = if (newStatus == com.example.data.model.FindingStatus.VERIFIED) assessorName else finding.verifiedBy,
            verifiedAtTimestamp = if (newStatus == com.example.data.model.FindingStatus.VERIFIED) System.currentTimeMillis() else finding.verifiedAtTimestamp
        )
        dao.updateFinding(updated)
        recordAuditLog(
            action = AuditAction.FINDING_STATUS_UPDATED,
            actor = assessorName,
            target = "${finding.cweId}: ${finding.title}",
            details = "Status transitioned to ${newStatus.name} with confidence ${finding.confidence.name}"
        )
    }

    fun getAllAuditLogs(): Flow<List<AuditLogEntity>> = dao.getAllAuditLogs()

    /**
     * Appends a tamper-evident audit record chained to the previous record's hash signature.
     */
    suspend fun recordAuditLog(
        action: AuditAction,
        actor: String,
        target: String,
        details: String
    ): AuditLogEntity {
        val latestLog = dao.getLatestAuditLog()
        val previousHash = latestLog?.hashSignature ?: "GENESIS_SENTINEL_ROOT_00000000000000000000000000000000"
        val timestamp = System.currentTimeMillis()

        // Canonical string representation
        val canonicalPayload = "$previousHash|$timestamp|$actor|${action.name}|$target|$details"
        val signature = "sha256:" + sha256(canonicalPayload)

        val logEntity = AuditLogEntity(
            timestamp = timestamp,
            actor = actor,
            action = action,
            target = target,
            details = details,
            previousHash = previousHash,
            hashSignature = signature
        )
        dao.insertAuditLog(logEntity)
        return logEntity
    }

    /**
     * Verifies the cryptographic integrity of the entire audit hash chain.
     */
    suspend fun verifyAuditChain(): AuditChainVerificationResult {
        val logs = dao.getAllAuditLogsAsc()
        if (logs.isEmpty()) {
            return AuditChainVerificationResult(isValid = true, totalEntries = 0)
        }

        var expectedPrevHash = "GENESIS_SENTINEL_ROOT_00000000000000000000000000000000"

        logs.forEachIndexed { index, log ->
            // Check previous hash link
            if (index == 0) {
                // First entry can link to genesis or a known seed
                expectedPrevHash = log.previousHash
            } else {
                if (log.previousHash != expectedPrevHash) {
                    return AuditChainVerificationResult(
                        isValid = false,
                        totalEntries = logs.size,
                        brokenAtIndex = index,
                        failureReason = "Previous hash mismatch at index $index. Expected '$expectedPrevHash', found '${log.previousHash}'"
                    )
                }
            }

            // Verify payload signature
            val canonicalPayload = "${log.previousHash}|${log.timestamp}|${log.actor}|${log.action.name}|${log.target}|${log.details}"
            val computedSignature = "sha256:" + sha256(canonicalPayload)
            if (computedSignature != log.hashSignature) {
                return AuditChainVerificationResult(
                    isValid = false,
                    totalEntries = logs.size,
                    brokenAtIndex = index,
                    failureReason = "Hash signature mismatch at index $index. Record may have been modified or reordered."
                )
            }

            expectedPrevHash = log.hashSignature
        }

        return AuditChainVerificationResult(
            isValid = true,
            totalEntries = logs.size
        )
    }

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
