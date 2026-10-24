package com.example.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AssessmentJobEntity
import com.example.data.model.AuditLogEntity
import com.example.data.model.AuthorizationRecordEntity
import com.example.data.model.ClientEntity
import com.example.data.model.EngagementEntity
import com.example.data.model.SecurityFindingEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface SentinelDao {
    // Clients
    @Query("SELECT * FROM clients ORDER BY createdAt DESC")
    fun getAllClients(): Flow<List<ClientEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertClient(client: ClientEntity)

    // Engagements
    @Query("SELECT * FROM engagements ORDER BY createdAt DESC")
    fun getAllEngagements(): Flow<List<EngagementEntity>>

    @Query("SELECT * FROM engagements WHERE id = :id LIMIT 1")
    suspend fun getEngagementById(id: String): EngagementEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertEngagement(engagement: EngagementEntity)

    @Update
    suspend fun updateEngagement(engagement: EngagementEntity)

    // Authorizations
    @Query("SELECT * FROM authorizations WHERE engagementId = :engagementId ORDER BY signedAtTimestamp DESC")
    fun getAuthorizationsForEngagement(engagementId: String): Flow<List<AuthorizationRecordEntity>>

    @Query("SELECT * FROM authorizations WHERE engagementId = :engagementId AND explicitTestingPermitted = 1 AND verificationStatus = 'VERIFIED' ORDER BY signedAtTimestamp DESC LIMIT 1")
    suspend fun getActiveAuthorization(engagementId: String): AuthorizationRecordEntity?

    @Query("SELECT * FROM authorizations WHERE engagementId = :engagementId ORDER BY signedAtTimestamp DESC LIMIT 1")
    suspend fun getLatestAuthorization(engagementId: String): AuthorizationRecordEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAuthorization(auth: AuthorizationRecordEntity)

    @Update
    suspend fun updateAuthorization(auth: AuthorizationRecordEntity)

    // Approved Scopes
    @Query("SELECT * FROM approved_scopes WHERE engagementId = :engagementId ORDER BY addedAt DESC")
    fun getScopesForEngagement(engagementId: String): Flow<List<ApprovedScopeEntity>>

    @Query("SELECT * FROM approved_scopes WHERE engagementId = :engagementId AND active = 1")
    suspend fun getActiveScopesList(engagementId: String): List<ApprovedScopeEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScope(scope: ApprovedScopeEntity)

    @Update
    suspend fun updateScope(scope: ApprovedScopeEntity)

    @Query("DELETE FROM approved_scopes WHERE id = :scopeId")
    suspend fun deleteScope(scopeId: String)

    // Assessment Jobs
    @Query("SELECT * FROM assessment_jobs WHERE engagementId = :engagementId ORDER BY startedAt DESC")
    fun getJobsForEngagement(engagementId: String): Flow<List<AssessmentJobEntity>>

    @Query("SELECT * FROM assessment_jobs ORDER BY startedAt DESC LIMIT 20")
    fun getAllRecentJobs(): Flow<List<AssessmentJobEntity>>

    @Query("SELECT * FROM assessment_jobs WHERE id = :jobId LIMIT 1")
    suspend fun getJobById(jobId: String): AssessmentJobEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertJob(job: AssessmentJobEntity)

    @Update
    suspend fun updateJob(job: AssessmentJobEntity)

    // Security Findings
    @Query("SELECT * FROM security_findings WHERE engagementId = :engagementId ORDER BY createdAt DESC")
    fun getFindingsForEngagement(engagementId: String): Flow<List<SecurityFindingEntity>>

    @Query("SELECT * FROM security_findings WHERE jobId = :jobId ORDER BY severity ASC")
    fun getFindingsForJob(jobId: String): Flow<List<SecurityFindingEntity>>

    @Query("SELECT * FROM security_findings WHERE jobId = :jobId")
    suspend fun getFindingsListForJob(jobId: String): List<SecurityFindingEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertFinding(finding: SecurityFindingEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertFindings(findings: List<SecurityFindingEntity>)

    @Update
    suspend fun updateFinding(finding: SecurityFindingEntity)

    // Audit Logs
    @Query("SELECT * FROM audit_logs ORDER BY timestamp DESC")
    fun getAllAuditLogs(): Flow<List<AuditLogEntity>>

    @Query("SELECT * FROM audit_logs ORDER BY timestamp ASC")
    suspend fun getAllAuditLogsAsc(): List<AuditLogEntity>

    @Query("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLatestAuditLog(): AuditLogEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAuditLog(log: AuditLogEntity)
}
