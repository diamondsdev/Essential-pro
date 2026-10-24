package com.example.engine

import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AssessmentJobEntity
import com.example.data.model.AuditAction
import com.example.data.model.AuthorizationRecordEntity
import com.example.data.model.Confidence
import com.example.data.model.FindingCategory
import com.example.data.model.FindingStatus
import com.example.data.model.SecurityFindingEntity
import com.example.data.model.Severity
import com.example.data.repository.SentinelRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.EventListener
import okhttp3.Handshake
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.net.InetAddress
import java.net.URI
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.TimeUnit

sealed class ScanStepStatus {
    data class Progress(val step: String, val progressFraction: Float, val detail: String) : ScanStepStatus()
    data class StepComplete(val step: String, val findingsFoundSoFar: Int) : ScanStepStatus()
    data class ScanFinished(val job: AssessmentJobEntity, val findings: List<SecurityFindingEntity>) : ScanStepStatus()
    data class ScanFailed(val error: String) : ScanStepStatus()
}

class RealSecurityScanner(
    private val repository: SentinelRepository,
    private val scopeValidator: ScopeValidator = ScopeValidator()
) {

    fun executeAssessment(
        targetUrl: String,
        engagementId: String,
        authorization: AuthorizationRecordEntity?,
        activeScopes: List<ApprovedScopeEntity>,
        assessorName: String = "Lead SecOps Assessor"
    ): Flow<ScanStepStatus> = flow {
        emit(ScanStepStatus.Progress("1. Scope Validation", 0.05f, "Auditing written ROA and host boundary rules..."))

        // Phase 1: Enforce Authorization & Scope Boundaries
        val scopeResult = scopeValidator.validateTarget(targetUrl, authorization, activeScopes)
        if (scopeResult is ScopeEnforcementResult.Denied) {
            repository.recordAuditLog(
                action = AuditAction.SCOPE_VIOLATION_BLOCKED,
                actor = assessorName,
                target = targetUrl,
                details = "Access Denied: ${scopeResult.reason}"
            )
            emit(ScanStepStatus.ScanFailed("Scope Violation: ${scopeResult.reason}"))
            return@flow
        }

        val allowed = scopeResult as ScopeEnforcementResult.Allowed
        val hostname = allowed.normalizedHost
        val resolvedIps = allowed.resolvedIps.joinToString(", ")
        val jobId = UUID.randomUUID().toString()

        val initialJob = AssessmentJobEntity(
            id = jobId,
            engagementId = engagementId,
            targetUrl = targetUrl,
            resolvedHost = hostname,
            resolvedIps = resolvedIps,
            status = "RUNNING",
            triggeredBy = assessorName,
            startedAt = System.currentTimeMillis()
        )
        repository.insertJob(initialJob)
        repository.recordAuditLog(
            action = AuditAction.SCAN_INITIATED,
            actor = assessorName,
            target = hostname,
            details = "Defensive assessment started on in-scope host $hostname ($resolvedIps). Job ID: $jobId"
        )

        val collectedFindings = mutableListOf<SecurityFindingEntity>()

        try {
            currentCoroutineContext().ensureActive()

            // Phase 2: DNS Resolution & Passive SPF/DMARC Email Security Audit
            emit(ScanStepStatus.Progress("2. DNS & Domain Checks", 0.20f, "Querying A, AAAA, SPF, and DMARC records for $hostname..."))
            val dnsFindings = auditDns(hostname, jobId, engagementId)
            collectedFindings.addAll(dnsFindings)
            emit(ScanStepStatus.StepComplete("DNS Checks", collectedFindings.size))

            currentCoroutineContext().ensureActive()
            delay(300) // Rate limit pause

            // Phase 3: TLS Handshake & Certificate Verification
            emit(ScanStepStatus.Progress("3. TLS & Cryptography", 0.40f, "Inspecting TLS handshake, cipher suites, and X.509 cert chain..."))
            val tlsFindings = auditTls(hostname, jobId, engagementId)
            collectedFindings.addAll(tlsFindings)
            emit(ScanStepStatus.StepComplete("TLS Cryptography Checks", collectedFindings.size))

            currentCoroutineContext().ensureActive()
            delay(300)

            // Phase 4: HTTP Security Headers & Cookie Flags
            emit(ScanStepStatus.Progress("4. HTTP Headers & Cookies", 0.60f, "Auditing HSTS, CSP, X-Frame-Options, and Set-Cookie flags..."))
            val headerFindings = auditHttpHeadersAndCookies(hostname, jobId, engagementId)
            collectedFindings.addAll(headerFindings)
            emit(ScanStepStatus.StepComplete("Header & Cookie Audits", collectedFindings.size))

            currentCoroutineContext().ensureActive()
            delay(300)

            // Phase 5: HTTPS Redirection & Downgrade Resistance
            emit(ScanStepStatus.Progress("5. Redirect Checks", 0.75f, "Testing plain HTTP to HTTPS auto-redirection on port 80..."))
            val redirectFindings = auditHttpsRedirect(hostname, jobId, engagementId)
            collectedFindings.addAll(redirectFindings)
            emit(ScanStepStatus.StepComplete("Redirect Checks", collectedFindings.size))

            currentCoroutineContext().ensureActive()
            delay(300)

            // Phase 6: Public Security Metadata (RFC 9116 security.txt & robots.txt)
            emit(ScanStepStatus.Progress("6. Public Metadata", 0.88f, "Auditing RFC 9116 security.txt and robots.txt disclosures..."))
            val metadataFindings = auditPublicFiles(hostname, jobId, engagementId)
            collectedFindings.addAll(metadataFindings)
            emit(ScanStepStatus.StepComplete("Public Metadata Checks", collectedFindings.size))

            // Calculate Scoring & Grade
            var score = 100
            var critical = 0
            var high = 0
            var medium = 0
            var low = 0
            var info = 0

            for (f in collectedFindings) {
                when (f.severity) {
                    Severity.CRITICAL -> { critical++; score -= 25 }
                    Severity.HIGH -> { high++; score -= 15 }
                    Severity.MEDIUM -> { medium++; score -= 8 }
                    Severity.LOW -> { low++; score -= 3 }
                    Severity.INFORMATIONAL -> { info++ }
                }
            }
            score = score.coerceIn(0, 100)
            val grade = when {
                score >= 95 -> "A+"
                score >= 90 -> "A"
                score >= 80 -> "B"
                score >= 70 -> "C"
                score >= 60 -> "D"
                else -> "F"
            }

            val finalJob = initialJob.copy(
                status = "COMPLETED",
                completedAt = System.currentTimeMillis(),
                totalFindingsCount = collectedFindings.size,
                criticalCount = critical,
                highCount = high,
                mediumCount = medium,
                lowCount = low,
                infoCount = info,
                postureScore = score,
                postureGrade = grade,
                summaryNotes = "Passive defensive assessment executed against authorized host $hostname. Identified ${collectedFindings.size} verified findings."
            )

            // Persist job and findings to Room database
            repository.updateJob(finalJob)
            if (collectedFindings.isNotEmpty()) {
                repository.insertFindings(collectedFindings)
            }
            repository.recordAuditLog(
                action = AuditAction.SCAN_COMPLETED,
                actor = assessorName,
                target = hostname,
                details = "Assessment completed. Score: $score ($grade). Total Findings: ${collectedFindings.size}"
            )

            emit(ScanStepStatus.Progress("Finalizing Report", 1.0f, "Completed successfully."))
            emit(ScanStepStatus.ScanFinished(finalJob, collectedFindings))

        } catch (e: Exception) {
            val failedJob = initialJob.copy(
                status = "FAILED",
                completedAt = System.currentTimeMillis(),
                errorMessage = e.message ?: "Unknown assessment failure"
            )
            repository.updateJob(failedJob)
            repository.recordAuditLog(
                action = AuditAction.SCAN_CANCELLED,
                actor = assessorName,
                target = hostname,
                details = "Assessment aborted or interrupted: ${e.message}"
            )
            emit(ScanStepStatus.ScanFailed("Assessment interrupted: ${e.message}"))
        }
    }.flowOn(Dispatchers.IO)

    // Sub-engine 1: DNS Auditing (Local resolution + DoH for TXT / DMARC)
    private suspend fun auditDns(hostname: String, jobId: String, engagementId: String): List<SecurityFindingEntity> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<SecurityFindingEntity>()
        val baseDomain = extractBaseDomain(hostname)

        val txtRecords = mutableListOf<String>()
        val dmarcRecords = mutableListOf<String>()

        val client = OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build()

        // Query Cloudflare / Google DoH for TXT records passively
        try {
            val txtReq = Request.Builder()
                .url("https://cloudflare-dns.com/dns-query?name=$baseDomain&type=TXT")
                .header("Accept", "application/dns-json")
                .build()
            client.newCall(txtReq).execute().use { resp ->
                if (resp.isSuccessful) {
                    val body = resp.body?.string() ?: ""
                    val json = JSONObject(body)
                    val answers = json.optJSONArray("Answer")
                    if (answers != null) {
                        for (i in 0 until answers.length()) {
                            val data = answers.getJSONObject(i).optString("data").replace("\"", "")
                            txtRecords.add(data)
                        }
                    }
                }
            }
        } catch (_: Exception) {}

        // Query _dmarc.<baseDomain> for DMARC record
        try {
            val dmarcReq = Request.Builder()
                .url("https://cloudflare-dns.com/dns-query?name=_dmarc.$baseDomain&type=TXT")
                .header("Accept", "application/dns-json")
                .build()
            client.newCall(dmarcReq).execute().use { resp ->
                if (resp.isSuccessful) {
                    val body = resp.body?.string() ?: ""
                    val json = JSONObject(body)
                    val answers = json.optJSONArray("Answer")
                    if (answers != null) {
                        for (i in 0 until answers.length()) {
                            val data = answers.getJSONObject(i).optString("data").replace("\"", "")
                            dmarcRecords.add(data)
                        }
                    }
                }
            }
        } catch (_: Exception) {}

        findings.addAll(DefensiveChecks.checkDnsSpfAndDmarc(txtRecords, dmarcRecords, jobId, engagementId))
        findings
    }

    // Sub-engine 2: TLS & Cryptography Handshake
    private suspend fun auditTls(hostname: String, jobId: String, engagementId: String): List<SecurityFindingEntity> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<SecurityFindingEntity>()
        var capturedHandshake: Handshake? = null

        val client = OkHttpClient.Builder()
            .connectTimeout(7, TimeUnit.SECONDS)
            .readTimeout(7, TimeUnit.SECONDS)
            .eventListener(object : EventListener() {
                override fun secureConnectEnd(call: okhttp3.Call, handshake: Handshake?) {
                    capturedHandshake = handshake
                }
            })
            .build()

        try {
            val request = Request.Builder()
                .url("https://$hostname")
                .header("User-Agent", "Sentinel-Pro-Defensive-Auditor/1.0 (+https://sentinel.internal/audit)")
                .build()

            client.newCall(request).execute().use { resp ->
                val handshake = capturedHandshake ?: resp.handshake
                if (handshake != null) {
                    val tlsVersion = handshake.tlsVersion.javaName
                    val cipherSuite = handshake.cipherSuite.javaName
                    val peerCerts = handshake.peerCertificates

                    val primaryCert = peerCerts.firstOrNull() as? X509Certificate
                    if (primaryCert != null) {
                        findings.addAll(
                            DefensiveChecks.checkCertificate(
                                cert = primaryCert,
                                tlsVersion = tlsVersion,
                                cipherSuite = cipherSuite,
                                jobId = jobId,
                                engagementId = engagementId
                            )
                        )
                    }
                }
            }
        } catch (e: Exception) {
            // If SSL handshake completely fails, record critical finding
            if (e.message?.contains("CertPathValidatorException") == true || e.message?.contains("SSLHandshakeException") == true) {
                findings.add(
                    SecurityFindingEntity(
                        id = UUID.randomUUID().toString(),
                        jobId = jobId,
                        engagementId = engagementId,
                        category = FindingCategory.TLS,
                        title = "Untrusted or Invalid SSL/TLS Certificate",
                        severity = Severity.CRITICAL,
                        confidence = Confidence.CONFIRMED,
                        status = FindingStatus.VERIFIED,
                        cweId = "CWE-295",
                        owaspCategory = "A02:2021-Cryptographic Failures",
                        summary = "The TLS connection failed certificate validation: ${e.message}",
                        technicalEvidence = "Handshake Error: ${e.message}",
                        impact = "Users receive untrusted certificate warnings and traffic can be intercepted.",
                        remediationGuidance = "Deploy a valid certificate issued by a recognized public CA (e.g., Let's Encrypt, DigiCert)."
                    )
                )
            }
        }

        findings
    }

    // Sub-engine 3: HTTP Headers & Cookie Security Flags
    private suspend fun auditHttpHeadersAndCookies(hostname: String, jobId: String, engagementId: String): List<SecurityFindingEntity> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<SecurityFindingEntity>()
        val client = OkHttpClient.Builder()
            .connectTimeout(7, TimeUnit.SECONDS)
            .readTimeout(7, TimeUnit.SECONDS)
            .followRedirects(true)
            .build()

        try {
            val request = Request.Builder()
                .url("https://$hostname")
                .header("User-Agent", "Sentinel-Pro-Defensive-Auditor/1.0")
                .build()

            client.newCall(request).execute().use { resp ->
                val headersMap = mutableMapOf<String, String>()
                for (name in resp.headers.names()) {
                    headersMap[name] = resp.header(name) ?: ""
                }

                // Header checks
                DefensiveChecks.checkHsts(headersMap, true, jobId, engagementId)?.let { findings.add(it) }
                DefensiveChecks.checkCsp(headersMap, jobId, engagementId)?.let { findings.add(it) }
                DefensiveChecks.checkXFrameOptions(headersMap, jobId, engagementId)?.let { findings.add(it) }
                DefensiveChecks.checkXContentTypeOptions(headersMap, jobId, engagementId)?.let { findings.add(it) }
                DefensiveChecks.checkReferrerPolicy(headersMap, jobId, engagementId)?.let { findings.add(it) }
                DefensiveChecks.checkServerInformationDisclosure(headersMap, jobId, engagementId)?.let { findings.add(it) }

                // Cookie checks
                val cookies = resp.headers("Set-Cookie")
                findings.addAll(DefensiveChecks.checkCookies(cookies, true, jobId, engagementId))
            }
        } catch (_: Exception) {}

        findings
    }

    // Sub-engine 4: HTTPS Redirection Check
    private suspend fun auditHttpsRedirect(hostname: String, jobId: String, engagementId: String): List<SecurityFindingEntity> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<SecurityFindingEntity>()
        val client = OkHttpClient.Builder()
            .connectTimeout(6, TimeUnit.SECONDS)
            .readTimeout(6, TimeUnit.SECONDS)
            .followRedirects(false) // Do NOT follow automatically, inspect status
            .build()

        try {
            val request = Request.Builder()
                .url("http://$hostname")
                .header("User-Agent", "Sentinel-Pro-Defensive-Auditor/1.0")
                .build()

            client.newCall(request).execute().use { resp ->
                val statusCode = resp.code
                val location = resp.header("Location") ?: ""

                if (statusCode in 300..399 && location.startsWith("https://", ignoreCase = true)) {
                    // Valid HTTPS redirect established!
                } else if (statusCode == 200) {
                    findings.add(
                        SecurityFindingEntity(
                            id = UUID.randomUUID().toString(),
                            jobId = jobId,
                            engagementId = engagementId,
                            category = FindingCategory.REDIRECT,
                            title = "Plain HTTP Service Accessible Without HTTPS Redirect",
                            severity = Severity.HIGH,
                            confidence = Confidence.CONFIRMED,
                            status = FindingStatus.VERIFIED,
                            cweId = "CWE-319",
                            owaspCategory = "A02:2021-Cryptographic Failures",
                            summary = "Connecting to http://$hostname returns HTTP $statusCode without redirecting to https://.",
                            technicalEvidence = "HTTP/1.1 $statusCode OK\nLocation: [NONE - Served in Cleartext]",
                            impact = "Allows passive wiretapping and eavesdropping of user credentials and session cookies in transit.",
                            remediationGuidance = "Configure web server or reverse proxy to issue an immediate 301 Permanent Redirect from http:// to https://.",
                            verificationCurl = "curl -sI http://$hostname"
                        )
                    )
                }
            }
        } catch (_: Exception) {
            // Port 80 closed is also secure against unencrypted traffic
        }

        findings
    }

    // Sub-engine 5: Rate-Limited Public Metadata Inspection
    private suspend fun auditPublicFiles(hostname: String, jobId: String, engagementId: String): List<SecurityFindingEntity> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<SecurityFindingEntity>()
        val client = OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build()

        // 1. Check RFC 9116 security.txt
        var hasSecurityTxt = false
        for (path in listOf("/.well-known/security.txt", "/security.txt")) {
            try {
                val req = Request.Builder()
                    .url("https://$hostname$path")
                    .header("User-Agent", "Sentinel-Pro-Defensive-Auditor/1.0")
                    .build()
                client.newCall(req).execute().use { resp ->
                    if (resp.isSuccessful) {
                        val body = resp.body?.string() ?: ""
                        if (body.contains("Contact:", ignoreCase = true)) {
                            hasSecurityTxt = true
                        }
                    }
                }
                if (hasSecurityTxt) break
            } catch (_: Exception) {}
        }

        if (!hasSecurityTxt) {
            findings.add(
                SecurityFindingEntity(
                    id = UUID.randomUUID().toString(),
                    jobId = jobId,
                    engagementId = engagementId,
                    category = FindingCategory.PUBLIC_FILES,
                    title = "Missing RFC 9116 Vulnerability Disclosure Policy (security.txt)",
                    severity = Severity.INFORMATIONAL,
                    confidence = Confidence.CONFIRMED,
                    status = FindingStatus.VERIFIED,
                    cweId = "CWE-16",
                    owaspCategory = "A05:2021-Security Misconfiguration",
                    summary = "No RFC 9116 security.txt file located at /.well-known/security.txt. Security researchers have no standardized protocol to report discovered vulnerabilities.",
                    technicalEvidence = "Checked /.well-known/security.txt and /security.txt -> 404 Not Found",
                    impact = "Critical vulnerability discoveries may be reported via public or chaotic channels rather than responsible coordinated disclosure.",
                    remediationGuidance = "Create /.well-known/security.txt with 'Contact: mailto:security@<domain>' and 'Expires: <timestamp>' conforming to RFC 9116.",
                    verificationCurl = "curl -sI https://$hostname/.well-known/security.txt"
                )
            )
        }

        findings
    }

    private fun extractBaseDomain(host: String): String {
        val parts = host.split(".")
        return if (parts.size >= 2) {
            "${parts[parts.size - 2]}.${parts[parts.size - 1]}"
        } else {
            host
        }
    }
}
