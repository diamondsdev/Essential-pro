package com.example.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.local.SentinelDatabase
import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AssessmentJobEntity
import com.example.data.model.AuthorizationRecordEntity
import com.example.data.model.AuthorizationStatus
import com.example.data.model.ClientEntity
import com.example.data.model.EngagementEntity
import com.example.data.model.EngagementStatus
import com.example.data.model.FindingStatus
import com.example.data.model.SecurityFindingEntity
import com.example.data.repository.AuditChainVerificationResult
import com.example.data.repository.SentinelRepository
import com.example.engine.RealSecurityScanner
import com.example.engine.ScanStepStatus
import com.example.report.MarkdownReportGenerator
import com.example.report.PdfSecurityReportGenerator
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.io.File
import java.util.UUID

class SentinelViewModel(application: Application) : AndroidViewModel(application) {

    private val repository: SentinelRepository
    private val scanner: RealSecurityScanner
    private val pdfGenerator: PdfSecurityReportGenerator

    val allEngagements: StateFlow<List<EngagementEntity>>
    val allClients: StateFlow<List<ClientEntity>>
    val recentJobs: StateFlow<List<AssessmentJobEntity>>
    val auditLogs = MutableStateFlow<List<com.example.data.model.AuditLogEntity>>(emptyList())

    private val _selectedEngagementId = MutableStateFlow<String?>(null)
    val selectedEngagementId = _selectedEngagementId.asStateFlow()

    private val _currentAuthorization = MutableStateFlow<AuthorizationRecordEntity?>(null)
    val currentAuthorization = _currentAuthorization.asStateFlow()

    private val _currentScopes = MutableStateFlow<List<ApprovedScopeEntity>>(emptyList())
    val currentScopes = _currentScopes.asStateFlow()

    private val _selectedJob = MutableStateFlow<AssessmentJobEntity?>(null)
    val selectedJob = _selectedJob.asStateFlow()

    private val _selectedJobFindings = MutableStateFlow<List<SecurityFindingEntity>>(emptyList())
    val selectedJobFindings = _selectedJobFindings.asStateFlow()

    private val _scanStatus = MutableStateFlow<ScanStepStatus?>(null)
    val scanStatus = _scanStatus.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    val isScanning = _isScanning.asStateFlow()

    private val _auditChainStatus = MutableStateFlow<AuditChainVerificationResult?>(null)
    val auditChainStatus = _auditChainStatus.asStateFlow()

    private var activeScanJob: Job? = null

    init {
        val database = SentinelDatabase.getDatabase(application)
        repository = SentinelRepository(database.sentinelDao())
        scanner = RealSecurityScanner(repository)
        pdfGenerator = PdfSecurityReportGenerator(application)

        allEngagements = repository.getAllEngagements()
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

        allClients = repository.getAllClients()
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

        recentJobs = repository.getRecentJobs()
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

        viewModelScope.launch {
            repository.getAllAuditLogs().collectLatest { logs ->
                auditLogs.value = logs
            }
        }

        // Auto-select first engagement once loaded
        viewModelScope.launch {
            allEngagements.collectLatest { list ->
                if (_selectedEngagementId.value == null && list.isNotEmpty()) {
                    selectEngagement(list.first().id)
                }
            }
        }
    }

    fun selectEngagement(engagementId: String) {
        _selectedEngagementId.value = engagementId
        viewModelScope.launch {
            repository.getAuthorizationsForEngagement(engagementId).collectLatest { auths ->
                _currentAuthorization.value = auths.firstOrNull()
            }
        }
        viewModelScope.launch {
            repository.getScopesForEngagement(engagementId).collectLatest { scopes ->
                _currentScopes.value = scopes
            }
        }
    }

    fun selectJob(job: AssessmentJobEntity) {
        _selectedJob.value = job
        viewModelScope.launch {
            repository.getFindingsForJob(job.id).collectLatest { findings ->
                _selectedJobFindings.value = findings
            }
        }
    }

    fun addApprovedScope(hostname: String, wildcard: Boolean, ports: String = "80,443", pathPrefix: String = "/") {
        val engagementId = _selectedEngagementId.value ?: return
        val cleanHost = hostname.trim().lowercase().removePrefix("https://").removePrefix("http://").substringBefore("/")
        if (cleanHost.isBlank()) return

        val isDemoEng = allEngagements.value.firstOrNull { it.id == engagementId }?.isDemo ?: false

        viewModelScope.launch {
            val scope = ApprovedScopeEntity(
                engagementId = engagementId,
                hostname = cleanHost,
                wildcardAllowed = wildcard,
                allowedPorts = ports.ifBlank { "80,443" },
                pathPrefix = if (pathPrefix.isBlank()) "/" else pathPrefix.trim(),
                active = true,
                isDemo = isDemoEng
            )
            repository.insertScope(scope)
        }
    }

    fun removeScope(scope: ApprovedScopeEntity) {
        viewModelScope.launch {
            repository.deleteScope(scope.id, scope.hostname)
        }
    }

    /**
     * Submits authorization documentation. Does NOT grant permission immediately;
     * enters PENDING_VERIFICATION state until auditor sign-off.
     */
    fun submitAuthorization(
        authorizedByName: String,
        authorizedByRole: String,
        authorizedByEmail: String,
        documentRef: String,
        emergencyPhone: String,
        evidenceHash: String = ""
    ) {
        val engagementId = _selectedEngagementId.value ?: return
        val isDemoEng = allEngagements.value.firstOrNull { it.id == engagementId }?.isDemo ?: false

        viewModelScope.launch {
            val auth = AuthorizationRecordEntity(
                engagementId = engagementId,
                authorizedByName = authorizedByName.trim(),
                authorizedByRole = authorizedByRole.trim(),
                authorizedByEmail = authorizedByEmail.trim(),
                documentReference = documentRef.trim(),
                evidenceHash = evidenceHash.ifBlank { "sha256:pending_document_verification" },
                verificationStatus = AuthorizationStatus.PENDING_VERIFICATION,
                authorizationScopeSummary = "Defensive website assessment for approved engagement targets.",
                validFromTimestamp = System.currentTimeMillis() - 60000L,
                validToTimestamp = System.currentTimeMillis() + 86400000L * 60,
                explicitTestingPermitted = false, // Remains false until auditor verification!
                emergencyContactPhone = emergencyPhone.trim(),
                isDemo = isDemoEng
            )
            repository.submitAuthorization(auth)
            _currentAuthorization.value = auth
        }
    }

    fun confirmAuthorization(
        authorizedByName: String,
        authorizedByRole: String,
        authorizedByEmail: String,
        documentRef: String,
        emergencyPhone: String,
        evidenceHash: String = ""
    ) {
        submitAuthorization(authorizedByName, authorizedByRole, authorizedByEmail, documentRef, emergencyPhone, evidenceHash)
    }

    /**
     * Explicit auditor verification workflow.
     */
    fun verifyAuthorization(auth: AuthorizationRecordEntity, auditorName: String, verifiedHash: String) {
        viewModelScope.launch {
            val verified = auth.copy(
                verificationStatus = AuthorizationStatus.VERIFIED,
                explicitTestingPermitted = true,
                verifiedBy = auditorName.trim(),
                verifiedAtTimestamp = System.currentTimeMillis(),
                evidenceHash = verifiedHash.trim().ifBlank { auth.evidenceHash }
            )
            repository.updateAuthorization(verified)
            _currentAuthorization.value = verified
        }
    }

    /**
     * Explicit authorization revocation.
     */
    fun revokeAuthorization(auth: AuthorizationRecordEntity, reason: String) {
        viewModelScope.launch {
            val revoked = auth.copy(
                verificationStatus = AuthorizationStatus.REVOKED,
                explicitTestingPermitted = false,
                revokedAtTimestamp = System.currentTimeMillis(),
                revocationReason = reason.trim().ifBlank { "Revoked by assessor or client demand" }
            )
            repository.updateAuthorization(revoked)
            _currentAuthorization.value = revoked
        }
    }

    /**
     * Creates a new engagement in DRAFT / UNVERIFIED state.
     * No automatic permission is granted.
     */
    fun createEngagement(
        clientOrg: String,
        clientName: String,
        clientEmail: String,
        engagementTitle: String,
        primaryScopeHost: String
    ) {
        viewModelScope.launch {
            val clientId = UUID.randomUUID().toString()
            val engagementId = UUID.randomUUID().toString()

            repository.insertClient(
                ClientEntity(
                    id = clientId,
                    name = clientName.trim(),
                    organization = clientOrg.trim(),
                    contactEmail = clientEmail.trim(),
                    isDemo = false
                )
            )

            val engagement = EngagementEntity(
                id = engagementId,
                clientId = clientId,
                title = engagementTitle.trim(),
                status = EngagementStatus.DRAFT, // Begins in DRAFT
                isDemo = false
            )
            repository.insertEngagement(engagement)

            // Submit an UNVERIFIED authorization record (explicitTestingPermitted = false)
            val auth = AuthorizationRecordEntity(
                engagementId = engagementId,
                authorizedByName = clientName.trim(),
                authorizedByRole = "Client Representative",
                authorizedByEmail = clientEmail.trim(),
                documentReference = "Awaiting signed ROA / SOW document",
                evidenceHash = "",
                verificationStatus = AuthorizationStatus.PENDING_VERIFICATION,
                authorizationScopeSummary = "Target scope: $primaryScopeHost. Requires signed written ROA before assessment.",
                validFromTimestamp = System.currentTimeMillis(),
                validToTimestamp = System.currentTimeMillis() + 86400000L * 30,
                explicitTestingPermitted = false, // Strictly unapproved until verified!
                emergencyContactPhone = "+1-555-0100",
                isDemo = false
            )
            repository.submitAuthorization(auth)

            val cleanHost = primaryScopeHost.trim().lowercase().removePrefix("https://").removePrefix("http://").substringBefore("/")
            if (cleanHost.isNotBlank()) {
                repository.insertScope(
                    ApprovedScopeEntity(
                        engagementId = engagementId,
                        hostname = cleanHost,
                        wildcardAllowed = false,
                        isDemo = false
                    )
                )
            }

            selectEngagement(engagementId)
        }
    }

    fun startAssessment(targetUrl: String) {
        val engagementId = _selectedEngagementId.value ?: return
        val auth = _currentAuthorization.value
        val scopes = _currentScopes.value

        _isScanning.value = true
        _scanStatus.value = ScanStepStatus.Progress("Initializing", 0.02f, "Preparing scope validator and PinnedDns...")

        activeScanJob?.cancel()
        activeScanJob = viewModelScope.launch {
            scanner.executeAssessment(
                targetUrl = targetUrl,
                engagementId = engagementId,
                authorization = auth,
                activeScopes = scopes
            ).collect { status ->
                _scanStatus.value = status
                if (status is ScanStepStatus.ScanFinished) {
                    _isScanning.value = false
                    _selectedJob.value = status.job
                    _selectedJobFindings.value = status.findings
                } else if (status is ScanStepStatus.ScanFailed) {
                    _isScanning.value = false
                }
            }
        }
    }

    fun cancelAssessment() {
        activeScanJob?.cancel()
        activeScanJob = null
        _isScanning.value = false
        _scanStatus.value = ScanStepStatus.ScanFailed("Assessment aborted by user.")
    }

    fun updateFindingStatus(finding: SecurityFindingEntity, newStatus: FindingStatus, assessorName: String = "Lead SecOps Assessor") {
        viewModelScope.launch {
            repository.updateFindingStatus(finding, newStatus, assessorName)
            _selectedJobFindings.value = _selectedJobFindings.value.map {
                if (it.id == finding.id) it.copy(status = newStatus, verifiedBy = assessorName, verifiedAtTimestamp = System.currentTimeMillis()) else it
            }
        }
    }

    fun verifyAuditChain() {
        viewModelScope.launch {
            val result = repository.verifyAuditChain()
            _auditChainStatus.value = result
            repository.recordAuditLog(
                action = if (result.isValid) com.example.data.model.AuditAction.INTEGRITY_CHECK_PASSED else com.example.data.model.AuditAction.INTEGRITY_CHECK_FAILED,
                actor = "Audit Verifier",
                target = "Audit Trail (${result.totalEntries} entries)",
                details = if (result.isValid) "Cryptographic hash chain validated successfully." else "INTEGRITY ERROR: ${result.failureReason}"
            )
        }
    }

    suspend fun generatePdfReport(job: AssessmentJobEntity): File? {
        val engagement = repository.getEngagementById(job.engagementId)
        val auth = repository.getLatestAuthorization(job.engagementId)
        val scopes = repository.getActiveScopesList(job.engagementId)
        val findings = repository.getFindingsListForJob(job.id)

        return try {
            pdfGenerator.generatePdf(
                job = job,
                engagement = engagement,
                client = null,
                authorization = auth,
                scopes = scopes,
                findings = findings
            )
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    suspend fun generateMarkdownReport(job: AssessmentJobEntity): String {
        val engagement = repository.getEngagementById(job.engagementId)
        val auth = repository.getLatestAuthorization(job.engagementId)
        val scopes = repository.getActiveScopesList(job.engagementId)
        val findings = repository.getFindingsListForJob(job.id)

        return MarkdownReportGenerator.generateMarkdown(
            job = job,
            engagement = engagement,
            client = null,
            authorization = auth,
            scopes = scopes,
            findings = findings
        )
    }
}
