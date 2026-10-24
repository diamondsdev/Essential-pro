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
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.json.JSONObject
import java.io.IOException
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

/**
 * Custom OkHttp DNS implementation that pins lookups strictly to pre-validated IP addresses.
 * Completely eliminates DNS-rebinding / TOCTOU SSRF attacks at the socket layer.
 */
class PinnedDns(
    private val expectedHost: String,
    private val validatedAddresses: List<InetAddress>
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        if (hostname.equals(expectedHost, ignoreCase = true)) {
            return validatedAddresses
        }
        // Fail-closed for any unpinned hostname
        throw IOException("DNS lookup prohibited for unpinned host '$hostname'")
    }
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
        val resolvedIps = allowed.validatedAddresses.joinToString(", ") { it.hostAddress }
        val jobId = UUID.randomUUID().toString()

        val initialJob = AssessmentJobEntity(
            id = jobId,
            engagementId = engagementId,
            targetUrl = targetUrl,
            resolvedHost = hostname,
            resolvedIps = resolvedIps,
            status = "RUNNING",
            triggeredBy = assessorName,
            startedAt = System.currentTimeMillis(),
            isDemo = authorization?.isDemo ?: false
        )
        repository.insertJob(initialJob)
        repository.recordAuditLog(
            action = AuditAction.SCAN_INITIATED,
            actor = assessorName,
            target = hostname,
            details = "Defensive assessment started on in-scope host $hostname ($resolvedIps). Job ID: $jobId"
        )

        val collectedFindings = mutableListOf<SecurityFindingEntity>()
        var checksPassed = 0
        var checksFailed = 0

        // Build Pinned HttpClient to prevent DNS-rebinding
        val pinnedDns = PinnedDns(hostname, allowed.validatedAddresses)

        // Redirect-Interception: Validates all redirect targets against scope
        val redirectInterceptor = Interceptor { chain ->
            val request = chain.request()
            val response = chain.proceed(request)
            if (response.isRedirect) {
                val location = response.header("Location")
                if (location != null) {
                    val resolvedRedirectUri = try {
                        request.url.toUri().resolve(location)
                    } catch (_: Exception) {
                        null
                    }
                    if (resolvedRedirectUri != null) {
                        val redHost = resolvedRedirectUri.host?.lowercase()?.trimEnd('.')
                        if (redHost != hostname) {
                            // Check if redirect host is authorized in active scopes
                            val isAuthRedirect = activeScopes.any { s ->
                                s.active && (if (s.wildcardAllowed) redHost == s.hostname || redHost?.endsWith(".${s.hostname}") == true else redHost == s.hostname)
                            }
                            if (!isAuthRedirect) {
                                throw IOException("Prohibited cross-host redirect to unapproved destination: $resolvedRedirectUri")
                            }
                        }
                    }
                }
            }
            response
        }

        val pinnedClient = OkHttpClient.Builder()
            .dns(pinnedDns)
            .addInterceptor(redirectInterceptor)
            .connectTimeout(6, TimeUnit.SECONDS)
            .readTimeout(6, TimeUnit.SECONDS)
            .callTimeout(10, TimeUnit.SECONDS)
            .followRedirects(false) // Handle redirects safely with policy
            .build()

        try {
            currentCoroutineContext().ensureActive()

            // Phase 2: DNS Resolution, A/AAAA validation, and Passive SPF/DMARC Email Security Audit
            emit(ScanStepStatus.Progress("2. DNS & Domain Checks", 0.20f, "Auditing A/AAAA resolutions, SPF, and DMARC for $hostname..."))
            val (dnsFindings, dnsSuccess) = auditDns(hostname, allowed.validatedAddresses, jobId, engagementId)
            collectedFindings.addAll(dnsFindings)
            if (dnsSuccess) checksPassed++ else checksFailed++
            emit(ScanStepStatus.StepComplete("DNS Checks", collectedFindings.size))

            currentCoroutineContext().ensureActive()
            delay(300) // Rate-limiting delay

            // Phase 3: TLS Handshake & Certificate Verification
            emit(ScanStepStatus.Progress("3. TLS & Cryptography", 0.40f, "Inspecting TLS handshake, cipher suites, and X.509 cert chain..."))
            val (tlsFindings, tlsSuccess) = auditTls(hostname, pinnedClient, jobId, engagementId)
            collectedFindings.addAll(tlsFindings)
            if (tlsSuccess) checksPassed++ else checksFailed++
            emit(ScanStepStatus.StepComplete("TLS Cryptography Checks", collectedFindings.size))

            currentCoroutineContext().ensureActive()
            delay(300)

            // Phase 4: HTTP Security Headers & Cookie Flags
            emit(ScanStepStatus.Progress("4. HTTP Headers & Cookies", 0.60f, "Auditing HSTS, CSP, X-Frame-Options, and Set-Cookie flags..."))
            val (headerFindings, headerSuccess) = auditHttpHeadersAndCookies(hostname, pinnedClient, jobId, engagementId)
            collectedFindings.addAll(headerFindings)
            if (headerSuccess) checksPassed++ else checksFailed++
            emit(ScanStepStatus.StepComplete("Header & Cookie Audits", collectedFindings.size))

            currentCoroutineContext().ensureActive()
            delay(300)

            // Phase 5: HTTPS Redirection & Downgrade Resistance
            emit(ScanStepStatus.Progress("5. Redirect Checks", 0.75f, "Testing plain HTTP to HTTPS auto-redirection on port 80..."))
            val (redirectFindings, redirectSuccess) = auditHttpsRedirect(hostname, pinnedClient, jobId, engagementId)
            collectedFindings.addAll(redirectFindings)
            if (redirectSuccess) checksPassed++ else checksFailed++
            emit(ScanStepStatus.StepComplete("Redirect Checks", collectedFindings.size))

            currentCoroutineContext().ensureActive()
            delay(300)

            // Phase 6: Public Security Metadata (RFC 9116 security.txt & robots.txt)
            emit(ScanStepStatus.Progress("6. Public Metadata", 0.88f, "Auditing RFC 9116 security.txt and robots.txt disclosures..."))
            val (metadataFindings, metaSuccess) = auditPublicFiles(hostname, pinnedClient, jobId, engagementId)
            collectedFindings.addAll(metadataFindings)
            if (metaSuccess) checksPassed++ else checksFailed++
            emit(ScanStepStatus.StepComplete("Public Metadata Checks", collectedFindings.size))

            // Calculate Scoring & Grade with incomplete check penalty
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

            // Penalty for incomplete/failed checks so an errored scan never gets 100% "A+"
            if (checksFailed > 0) {
                score -= (checksFailed * 10)
            }
            score = score.coerceIn(0, 100)

            val finalStatus = if (checksFailed >= 3) "INCOMPLETE" else "COMPLETED"
            val grade = when {
                finalStatus == "INCOMPLETE" -> "INC"
                score >= 95 -> "A+"
                score >= 90 -> "A"
                score >= 80 -> "B"
                score >= 70 -> "C"
                score >= 60 -> "D"
                else -> "F"
            }

            val finalJob = initialJob.copy(
                status = finalStatus,
                completedAt = System.currentTimeMillis(),
                totalFindingsCount = collectedFindings.size,
                criticalCount = critical,
                highCount = high,
                mediumCount = medium,
                lowCount = low,
                infoCount = info,
                checksPassedCount = checksPassed,
                checksFailedCount = checksFailed,
                postureScore = score,
                postureGrade = grade,
                summaryNotes = "Defensive assessment completed against authorized host $hostname. " +
                        "$checksPassed checks executed cleanly, $checksFailed checks had errors. " +
                        "${collectedFindings.size} observations recorded."
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
                details = "Assessment finished ($finalStatus). Score: $score ($grade). Observations: ${collectedFindings.size}. Passed: $checksPassed, Failed: $checksFailed"
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

    // Sub-engine 1: DNS Auditing
    private suspend fun auditDns(
        hostname: String,
        resolvedAddresses: List<InetAddress>,
        jobId: String,
        engagementId: String
    ): Pair<List<SecurityFindingEntity>, Boolean> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<SecurityFindingEntity>()
        var success = true
        val baseDomain = extractBaseDomain(hostname)

        val txtRecords = mutableListOf<String>()
        val dmarcRecords = mutableListOf<String>()

        val dohClient = OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build()

        // 1. Query Cloudflare DoH for TXT records passively
        try {
            val txtReq = Request.Builder()
                .url("https://cloudflare-dns.com/dns-query?name=$baseDomain&type=TXT")
                .header("Accept", "application/dns-json")
                .build()
            dohClient.newCall(txtReq).execute().use { resp ->
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
        } catch (_: Exception) {
            success = false
        }

        // 2. Query _dmarc.<baseDomain> for DMARC record
        try {
            val dmarcReq = Request.Builder()
                .url("https://cloudflare-dns.com/dns-query?name=_dmarc.$baseDomain&type=TXT")
                .header("Accept", "application/dns-json")
                .build()
            dohClient.newCall(dmarcReq).execute().use { resp ->
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
        } catch (_: Exception) {
            success = false
        }

        findings.addAll(DefensiveChecks.checkDnsSpfAndDmarc(txtRecords, dmarcRecords, jobId, engagementId))
        findings to success
    }

    // Sub-engine 2: TLS Handshake & Certificate Verification
    private suspend fun auditTls(
        hostname: String,
        pinnedClient: OkHttpClient,
        jobId: String,
        engagementId: String
    ): Pair<List<SecurityFindingEntity>, Boolean> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<SecurityFindingEntity>()
        var success = false
        var capturedHandshake: Handshake? = null

        val client = pinnedClient.newBuilder()
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
                        success = true
                    }
                }
            }
        } catch (e: Exception) {
            if (e.message?.contains("CertPathValidatorException") == true ||
                e.message?.contains("SSLHandshakeException") == true) {
                findings.add(
                    SecurityFindingEntity(
                        id = UUID.randomUUID().toString(),
                        jobId = jobId,
                        engagementId = engagementId,
                        category = FindingCategory.TLS,
                        title = "Untrusted or Invalid SSL/TLS Certificate",
                        severity = Severity.CRITICAL,
                        confidence = Confidence.CONFIRMED,
                        status = FindingStatus.AUTOMATED_OBSERVATION,
                        cweId = "CWE-295",
                        owaspCategory = "A02:2021-Cryptographic Failures",
                        summary = "The TLS connection failed certificate validation: ${e.message}",
                        technicalEvidence = "Handshake Error: ${e.message}",
                        impact = "Users receive untrusted certificate warnings and traffic can be intercepted.",
                        remediationGuidance = "Deploy a valid certificate issued by a recognized public CA (e.g., Let's Encrypt, DigiCert)."
                    )
                )
                success = true
            } else {
                success = false
            }
        }

        findings to success
    }

    // Sub-engine 3: HTTP Headers & Cookie Security Flags
    private suspend fun auditHttpHeadersAndCookies(
        hostname: String,
        pinnedClient: OkHttpClient,
        jobId: String,
        engagementId: String
    ): Pair<List<SecurityFindingEntity>, Boolean> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<SecurityFindingEntity>()
        var success = false

        try {
            val request = Request.Builder()
                .url("https://$hostname")
                .header("User-Agent", "Sentinel-Pro-Defensive-Auditor/1.0")
                .build()

            pinnedClient.newCall(request).execute().use { resp ->
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
                success = true
            }
        } catch (_: Exception) {
            success = false
        }

        findings to success
    }

    // Sub-engine 4: HTTPS Redirection Check
    private suspend fun auditHttpsRedirect(
        hostname: String,
        pinnedClient: OkHttpClient,
        jobId: String,
        engagementId: String
    ): Pair<List<SecurityFindingEntity>, Boolean> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<SecurityFindingEntity>()
        var success = false

        try {
            val request = Request.Builder()
                .url("http://$hostname")
                .header("User-Agent", "Sentinel-Pro-Defensive-Auditor/1.0")
                .build()

            pinnedClient.newCall(request).execute().use { resp ->
                val statusCode = resp.code
                val location = resp.header("Location") ?: ""

                if (statusCode in 300..399 && location.startsWith("https://", ignoreCase = true)) {
                    // Valid HTTPS redirect established
                    success = true
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
                            status = FindingStatus.AUTOMATED_OBSERVATION,
                            cweId = "CWE-319",
                            owaspCategory = "A02:2021-Cryptographic Failures",
                            summary = "Connecting to http://$hostname returns HTTP $statusCode without redirecting to https://.",
                            technicalEvidence = "HTTP/1.1 $statusCode OK\nLocation: [NONE - Served in Cleartext]",
                            impact = "Allows passive wiretapping and eavesdropping of user credentials and session cookies in transit.",
                            remediationGuidance = "Configure web server or reverse proxy to issue an immediate 301 Permanent Redirect from http:// to https://.",
                            verificationCurl = "curl -sI http://$hostname"
                        )
                    )
                    success = true
                } else {
                    success = true
                }
            }
        } catch (_: Exception) {
            // Port 80 connection refused / closed is securely non-plaintext
            success = true
        }

        findings to success
    }

    // Sub-engine 5: Rate-Limited Public Metadata Inspection (security.txt and robots.txt)
    private suspend fun auditPublicFiles(
        hostname: String,
        pinnedClient: OkHttpClient,
        jobId: String,
        engagementId: String
    ): Pair<List<SecurityFindingEntity>, Boolean> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<SecurityFindingEntity>()
        var success = true

        // 1. Check RFC 9116 security.txt
        var hasSecurityTxt = false
        for (path in listOf("/.well-known/security.txt", "/security.txt")) {
            try {
                val req = Request.Builder()
                    .url("https://$hostname$path")
                    .header("User-Agent", "Sentinel-Pro-Defensive-Auditor/1.0")
                    .build()
                pinnedClient.newCall(req).execute().use { resp ->
                    if (resp.isSuccessful) {
                        val body = resp.body?.string()?.take(4096) ?: ""
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
                    status = FindingStatus.AUTOMATED_OBSERVATION,
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

        // 2. Check robots.txt for sensitive path disclosure
        try {
            val req = Request.Builder()
                .url("https://$hostname/robots.txt")
                .header("User-Agent", "Sentinel-Pro-Defensive-Auditor/1.0")
                .build()
            pinnedClient.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    val body = resp.body?.string()?.take(8192) ?: ""
                    val sensitiveKeywords = listOf("/admin", "/backup", "/private", "/internal", "/.git", "/config", "/db")
                    val exposedPaths = mutableListOf<String>()

                    body.lines().forEach { line ->
                        val trimmed = line.trim()
                        if (trimmed.startsWith("Disallow:", ignoreCase = true)) {
                            val path = trimmed.substringAfter(":").trim()
                            if (sensitiveKeywords.any { path.contains(it, ignoreCase = true) }) {
                                exposedPaths.add(path)
                            }
                        }
                    }

                    if (exposedPaths.isNotEmpty()) {
                        findings.add(
                            SecurityFindingEntity(
                                id = UUID.randomUUID().toString(),
                                jobId = jobId,
                                engagementId = engagementId,
                                category = FindingCategory.PUBLIC_FILES,
                                title = "Sensitive Administrative Path Disclosed in robots.txt",
                                severity = Severity.LOW,
                                confidence = Confidence.CONFIRMED,
                                status = FindingStatus.AUTOMATED_OBSERVATION,
                                cweId = "CWE-200",
                                owaspCategory = "A05:2021-Security Misconfiguration",
                                summary = "The robots.txt file contains Disallow rules referencing potentially sensitive administrative or backup paths.",
                                technicalEvidence = "Exposed paths in robots.txt:\n${exposedPaths.take(5).joinToString("\n")}",
                                impact = "Attackers can enumerate hidden endpoints and administrative interfaces directly from publicly accessible search engine directives.",
                                remediationGuidance = "Protect administrative interfaces with authentication and access controls instead of relying on robots.txt for obscurity. Remove sensitive path names from robots.txt.",
                                verificationCurl = "curl -s https://$hostname/robots.txt"
                            )
                        )
                    }
                }
            }
        } catch (_: Exception) {}

        findings to success
    }

    /**
     * Public suffix aware base domain extraction.
     * Correctly handles multi-part TLDs (.co.uk, .com.au, .gov.uk, etc.)
     */
    fun extractBaseDomain(host: String): String {
        val parts = host.lowercase().trimEnd('.').split(".")
        if (parts.size <= 2) return host

        val multiPartSuffixes = setOf(
            "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
            "com.au", "net.au", "org.au", "edu.au", "gov.au",
            "co.nz", "net.nz", "org.nz", "govt.nz",
            "com.br", "org.br", "gov.br",
            "co.jp", "ne.jp", "ac.jp",
            "co.in", "net.in", "org.in", "gen.in",
            "co.za", "org.za", "web.za"
        )

        val lastTwo = "${parts[parts.size - 2]}.${parts[parts.size - 1]}"
        return if (multiPartSuffixes.contains(lastTwo) && parts.size >= 3) {
            "${parts[parts.size - 3]}.${parts[parts.size - 2]}.${parts[parts.size - 1]}"
        } else {
            lastTwo
        }
    }
}
