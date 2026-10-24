package com.example.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.local.SentinelDatabase
import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AssessmentJobEntity
import com.example.data.model.AuthorizationRecordEntity
import com.example.data.model.ClientEntity
import com.example.data.model.EngagementEntity
import com.example.data.model.EngagementStatus
import com.example.data.model.FindingStatus
import com.example.data.model.SecurityFindingEntity
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
                _currentAuthorization.value = auths.firstOrNull { it.explicitTestingPermitted }
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

    fun addApprovedScope(hostname: String, wildcard: Boolean, ports: String = "80,443") {
        val engagementId = _selectedEngagementId.value ?: return
        val cleanHost = hostname.trim().lowercase().removePrefix("https://").removePrefix("http://").substringBefore("/")
        if (cleanHost.isBlank()) return

        viewModelScope.launch {
            val scope = ApprovedScopeEntity(
                engagementId = engagementId,
                hostname = cleanHost,
                wildcardAllowed = wildcard,
                allowedPorts = ports.ifBlank { "80,443" },
                pathPrefix = "/",
                active = true
            )
            repository.insertScope(scope)
        }
    }

    fun removeScope(scope: ApprovedScopeEntity) {
        viewModelScope.launch {
            repository.deleteScope(scope.id, scope.hostname)
        }
    }

    fun confirmAuthorization(
        authorizedByName: String,
        authorizedByRole: String,
        authorizedByEmail: String,
        documentRef: String,
        emergencyPhone: String
    ) {
        val engagementId = _selectedEngagementId.value ?: return
        viewModelScope.launch {
            val auth = AuthorizationRecordEntity(
                engagementId = engagementId,
                authorizedByName = authorizedByName.trim(),
                authorizedByRole = authorizedByRole.trim(),
                authorizedByEmail = authorizedByEmail.trim(),
                documentReference = documentRef.trim(),
                authorizationScopeSummary = "Defensive website assessment for approved engagement targets.",
                validFromTimestamp = System.currentTimeMillis() - 60000L,
                validToTimestamp = System.currentTimeMillis() + 86400000L * 60,
                explicitTestingPermitted = true,
                emergencyContactPhone = emergencyPhone.trim()
            )
            repository.insertAuthorization(auth)
            _currentAuthorization.value = auth
        }
    }

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
                    contactEmail = clientEmail.trim()
                )
            )

            val engagement = EngagementEntity(
                id = engagementId,
                clientId = clientId,
                title = engagementTitle.trim(),
                status = EngagementStatus.ACTIVE
            )
            repository.insertEngagement(engagement)

            // Auto-create initial ROA authorization
            val auth = AuthorizationRecordEntity(
                engagementId = engagementId,
                authorizedByName = clientName.trim(),
                authorizedByRole = "Authorized Security Lead",
                authorizedByEmail = clientEmail.trim(),
                documentReference = "ROA-AUTO-${UUID.randomUUID().toString().take(6).uppercase()}",
                authorizationScopeSummary = "Authorized defensive website testing on $primaryScopeHost",
                validFromTimestamp = System.currentTimeMillis() - 60000L,
                validToTimestamp = System.currentTimeMillis() + 86400000L * 30,
                explicitTestingPermitted = true,
                emergencyContactPhone = "+1-555-0100"
            )
            repository.insertAuthorization(auth)

            val cleanHost = primaryScopeHost.trim().lowercase().removePrefix("https://").removePrefix("http://").substringBefore("/")
            if (cleanHost.isNotBlank()) {
                repository.insertScope(
                    ApprovedScopeEntity(
                        engagementId = engagementId,
                        hostname = cleanHost,
                        wildcardAllowed = false
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
        _scanStatus.value = ScanStepStatus.Progress("Initializing", 0.02f, "Preparing scope validator...")

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

    fun updateFindingStatus(finding: SecurityFindingEntity, newStatus: FindingStatus) {
        viewModelScope.launch {
            val updated = finding.copy(status = newStatus)
            repository.updateFindingStatus(updated)
            _selectedJobFindings.value = _selectedJobFindings.value.map {
                if (it.id == finding.id) updated else it
            }
        }
    }

    suspend fun generatePdfReport(job: AssessmentJobEntity): File? {
        val engagement = repository.getEngagementById(job.engagementId)
        val auth = repository.getActiveAuthorization(job.engagementId)
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
        val auth = repository.getActiveAuthorization(job.engagementId)
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
