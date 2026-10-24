package com.example.data.repository

import com.example.data.local.SentinelDao
import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AssessmentJobEntity
import com.example.data.model.AuditAction
import com.example.data.model.AuditLogEntity
import com.example.data.model.AuthorizationRecordEntity
import com.example.data.model.ClientEntity
import com.example.data.model.EngagementEntity
import com.example.data.model.SecurityFindingEntity
import kotlinx.coroutines.flow.Flow
import java.security.MessageDigest

class SentinelRepository(private val dao: SentinelDao) {

    fun getAllEngagements(): Flow<List<EngagementEntity>> = dao.getAllEngagements()

    suspend fun getEngagementById(id: String): EngagementEntity? = dao.getEngagementById(id)

    suspend fun insertEngagement(engagement: EngagementEntity) = dao.insertEngagement(engagement)

    fun getAllClients(): Flow<List<ClientEntity>> = dao.getAllClients()

    suspend fun insertClient(client: ClientEntity) = dao.insertClient(client)

    fun getAuthorizationsForEngagement(engagementId: String): Flow<List<AuthorizationRecordEntity>> =
        dao.getAuthorizationsForEngagement(engagementId)

    suspend fun getActiveAuthorization(engagementId: String): AuthorizationRecordEntity? =
        dao.getActiveAuthorization(engagementId)

    suspend fun insertAuthorization(auth: AuthorizationRecordEntity) {
        dao.insertAuthorization(auth)
        recordAuditLog(
            action = AuditAction.AUTHORIZATION_SIGNED,
            actor = auth.authorizedByName,
            target = "Engagement ${auth.engagementId}",
            details = "ROA reference: ${auth.documentReference}. Valid until: ${auth.validToTimestamp}"
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
            details = "Added to approved scope. Wildcard: ${scope.wildcardAllowed}, Ports: ${scope.allowedPorts}"
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

    suspend fun updateFindingStatus(finding: SecurityFindingEntity) {
        dao.updateFinding(finding)
        recordAuditLog(
            action = AuditAction.FINDING_STATUS_UPDATED,
            actor = "Lead Assessor",
            target = finding.title,
            details = "Status changed to ${finding.status.name} with confidence ${finding.confidence.name}"
        )
    }

    fun getAllAuditLogs(): Flow<List<AuditLogEntity>> = dao.getAllAuditLogs()

    suspend fun recordAuditLog(
        action: AuditAction,
        actor: String,
        target: String,
        details: String
    ) {
        val payload = "${System.currentTimeMillis()}|$actor|${action.name}|$target|$details"
        val hash = sha256(payload)
        dao.insertAuditLog(
            AuditLogEntity(
                timestamp = System.currentTimeMillis(),
                actor = actor,
                action = action,
                target = target,
                details = details,
                hashSignature = "sha256:$hash"
            )
        )
    }

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
