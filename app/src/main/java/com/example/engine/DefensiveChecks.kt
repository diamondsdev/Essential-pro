package com.example.engine

import com.example.data.model.Confidence
import com.example.data.model.FindingCategory
import com.example.data.model.FindingStatus
import com.example.data.model.SecurityFindingEntity
import com.example.data.model.Severity
import java.security.cert.X509Certificate
import java.util.Date
import java.util.UUID

object DefensiveChecks {

    fun checkHsts(headers: Map<String, String>, isHttps: Boolean, jobId: String, engagementId: String): SecurityFindingEntity? {
        if (!isHttps) return null
        val hsts = headers.entries.firstOrNull { it.key.equals("Strict-Transport-Security", ignoreCase = true) }?.value
        if (hsts == null) {
            return SecurityFindingEntity(
                id = UUID.randomUUID().toString(),
                jobId = jobId,
                engagementId = engagementId,
                category = FindingCategory.HTTP_HEADERS,
                title = "Missing HTTP Strict Transport Security (HSTS) Header",
                severity = Severity.HIGH,
                confidence = Confidence.CONFIRMED,
                status = FindingStatus.VERIFIED,
                cweId = "CWE-319",
                owaspCategory = "A05:2021-Security Misconfiguration",
                summary = "The web application does not enforce HTTPS via the Strict-Transport-Security header, allowing potential SSL-stripping and man-in-the-middle downgrade attacks.",
                technicalEvidence = "HTTP Response Headers:\nStrict-Transport-Security: [NOT PRESENT]",
                impact = "An attacker in the network path can intercept plain HTTP traffic and strip HTTPS redirects before encryption is established.",
                remediationGuidance = "Configure web server to return: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
                verificationCurl = "curl -sI https://TARGET | grep -i strict-transport-security"
            )
        } else {
            val maxAge = Regex("max-age=(\\d+)", RegexOption.IGNORE_CASE).find(hsts)?.groupValues?.get(1)?.toLongOrNull() ?: 0L
            val hasSubdomains = hsts.contains("includeSubDomains", ignoreCase = true)
            if (maxAge < 15552000L || !hasSubdomains) {
                return SecurityFindingEntity(
                    id = UUID.randomUUID().toString(),
                    jobId = jobId,
                    engagementId = engagementId,
                    category = FindingCategory.HTTP_HEADERS,
                    title = "Sub-optimal HSTS Configuration (Short max-age or Missing SubDomains)",
                    severity = Severity.LOW,
                    confidence = Confidence.CONFIRMED,
                    status = FindingStatus.VERIFIED,
                    cweId = "CWE-319",
                    owaspCategory = "A05:2021-Security Misconfiguration",
                    summary = "The HSTS header duration is less than 6 months (15552000s) or does not include subdomains, reducing protection across perimeter subdomains.",
                    technicalEvidence = "Strict-Transport-Security: $hsts",
                    impact = "Subdomains might remain vulnerable to cleartext interception if users traverse unencrypted links.",
                    remediationGuidance = "Update HSTS policy: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
                    verificationCurl = "curl -sI https://TARGET | grep -i strict-transport-security"
                )
            }
        }
        return null
    }

    fun checkCsp(headers: Map<String, String>, jobId: String, engagementId: String): SecurityFindingEntity? {
        val csp = headers.entries.firstOrNull { it.key.equals("Content-Security-Policy", ignoreCase = true) }?.value
        if (csp == null) {
            return SecurityFindingEntity(
                id = UUID.randomUUID().toString(),
                jobId = jobId,
                engagementId = engagementId,
                category = FindingCategory.HTTP_HEADERS,
                title = "Missing Content Security Policy (CSP)",
                severity = Severity.MEDIUM,
                confidence = Confidence.CONFIRMED,
                status = FindingStatus.VERIFIED,
                cweId = "CWE-1021",
                owaspCategory = "A03:2021-Injection",
                summary = "Content-Security-Policy header is absent. Browsers will execute any script sources without restriction, increasing the severity of cross-site scripting (XSS) vectors.",
                technicalEvidence = "HTTP Response Headers:\nContent-Security-Policy: [NOT PRESENT]",
                impact = "Malicious inline scripts or injected external scripts can execute in the context of the user's session without restriction.",
                remediationGuidance = "Implement a strict Content-Security-Policy. Example: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-RANDOM'; style-src 'self' 'unsafe-inline'; object-src 'none';",
                verificationCurl = "curl -sI https://TARGET | grep -i content-security-policy"
            )
        } else if (csp.contains("'unsafe-inline'", ignoreCase = true) || csp.contains("'unsafe-eval'", ignoreCase = true)) {
            return SecurityFindingEntity(
                id = UUID.randomUUID().toString(),
                jobId = jobId,
                engagementId = engagementId,
                category = FindingCategory.HTTP_HEADERS,
                title = "Insecure CSP Directives ('unsafe-inline' / 'unsafe-eval')",
                severity = Severity.LOW,
                confidence = Confidence.CONFIRMED,
                status = FindingStatus.VERIFIED,
                cweId = "CWE-1021",
                owaspCategory = "A05:2021-Security Misconfiguration",
                summary = "The Content Security Policy allows unsafe inline execution or eval(), weakening resistance against XSS.",
                technicalEvidence = "Content-Security-Policy: $csp",
                impact = "Enables attackers with HTML injection access to execute arbitrary JavaScript payloads.",
                remediationGuidance = "Remove 'unsafe-inline' and 'unsafe-eval'. Use cryptographic nonces (nonce-*) or SHA-256 hashes for trusted scripts.",
                verificationCurl = "curl -sI https://TARGET | grep -i content-security-policy"
            )
        }
        return null
    }

    fun checkXFrameOptions(headers: Map<String, String>, jobId: String, engagementId: String): SecurityFindingEntity? {
        val xfo = headers.entries.firstOrNull { it.key.equals("X-Frame-Options", ignoreCase = true) }?.value
        val csp = headers.entries.firstOrNull { it.key.equals("Content-Security-Policy", ignoreCase = true) }?.value
        val hasCspFrameAncestors = csp != null && csp.contains("frame-ancestors", ignoreCase = true)

        if (xfo == null && !hasCspFrameAncestors) {
            return SecurityFindingEntity(
                id = UUID.randomUUID().toString(),
                jobId = jobId,
                engagementId = engagementId,
                category = FindingCategory.HTTP_HEADERS,
                title = "Missing Anti-Clickjacking Protection (X-Frame-Options)",
                severity = Severity.MEDIUM,
                confidence = Confidence.CONFIRMED,
                status = FindingStatus.VERIFIED,
                cweId = "CWE-1021",
                owaspCategory = "A05:2021-Security Misconfiguration",
                summary = "The site does not restrict framing via X-Frame-Options or CSP frame-ancestors, exposing users to UI-redirection / Clickjacking attacks.",
                technicalEvidence = "X-Frame-Options: [NOT PRESENT]\nCSP frame-ancestors: [NOT PRESENT]",
                impact = "Malicious web pages can load the target inside an invisible <iframe> and trick users into authorizing unintended actions.",
                remediationGuidance = "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', and include 'frame-ancestors 'none'' in Content-Security-Policy.",
                verificationCurl = "curl -sI https://TARGET | grep -i x-frame-options"
            )
        }
        return null
    }

    fun checkXContentTypeOptions(headers: Map<String, String>, jobId: String, engagementId: String): SecurityFindingEntity? {
        val xcto = headers.entries.firstOrNull { it.key.equals("X-Content-Type-Options", ignoreCase = true) }?.value
        if (xcto == null || !xcto.contains("nosniff", ignoreCase = true)) {
            return SecurityFindingEntity(
                id = UUID.randomUUID().toString(),
                jobId = jobId,
                engagementId = engagementId,
                category = FindingCategory.HTTP_HEADERS,
                title = "Missing MIME-Sniffing Defense (X-Content-Type-Options)",
                severity = Severity.LOW,
                confidence = Confidence.CONFIRMED,
                status = FindingStatus.VERIFIED,
                cweId = "CWE-16",
                owaspCategory = "A05:2021-Security Misconfiguration",
                summary = "Missing 'X-Content-Type-Options: nosniff'. Legacy browsers may interpret non-executable MIME types (e.g. images, text) as HTML or JavaScript.",
                technicalEvidence = "X-Content-Type-Options: ${xcto ?: "[NOT PRESENT]"}",
                impact = "Can facilitate cross-site script execution if file uploads or user-controlled content are served without strict MIME boundaries.",
                remediationGuidance = "Send the response header 'X-Content-Type-Options: nosniff' across all HTTP endpoints.",
                verificationCurl = "curl -sI https://TARGET | grep -i x-content-type-options"
            )
        }
        return null
    }

    fun checkReferrerPolicy(headers: Map<String, String>, jobId: String, engagementId: String): SecurityFindingEntity? {
        val rp = headers.entries.firstOrNull { it.key.equals("Referrer-Policy", ignoreCase = true) }?.value
        if (rp == null || rp.equals("unsafe-url", ignoreCase = true) || rp.equals("no-referrer-when-downgrade", ignoreCase = true)) {
            return SecurityFindingEntity(
                id = UUID.randomUUID().toString(),
                jobId = jobId,
                engagementId = engagementId,
                category = FindingCategory.HTTP_HEADERS,
                title = "Sub-optimal or Missing Referrer-Policy",
                severity = Severity.LOW,
                confidence = Confidence.CONFIRMED,
                status = FindingStatus.VERIFIED,
                cweId = "CWE-200",
                owaspCategory = "A01:2021-Broken Access Control",
                summary = "The Referrer-Policy header is absent or insecure, which may leak query parameters or sensitive URLs to third-party domains.",
                technicalEvidence = "Referrer-Policy: ${rp ?: "[NOT PRESENT]"}",
                impact = "URLs containing reset tokens, search keywords, or sensitive account identifiers may leak in HTTP Referer headers.",
                remediationGuidance = "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                verificationCurl = "curl -sI https://TARGET | grep -i referrer-policy"
            )
        }
        return null
    }

    fun checkServerInformationDisclosure(headers: Map<String, String>, jobId: String, engagementId: String): SecurityFindingEntity? {
        val server = headers.entries.firstOrNull { it.key.equals("Server", ignoreCase = true) }?.value
        val poweredBy = headers.entries.firstOrNull { it.key.equals("X-Powered-By", ignoreCase = true) }?.value
        val aspNet = headers.entries.firstOrNull { it.key.equals("X-AspNet-Version", ignoreCase = true) }?.value

        val leaks = mutableListOf<String>()
        if (server != null && Regex("[0-9]+\\.[0-9]+").containsMatchIn(server)) {
            leaks.add("Server: $server")
        }
        if (poweredBy != null) leaks.add("X-Powered-By: $poweredBy")
        if (aspNet != null) leaks.add("X-AspNet-Version: $aspNet")

        if (leaks.isNotEmpty()) {
            return SecurityFindingEntity(
                id = UUID.randomUUID().toString(),
                jobId = jobId,
                engagementId = engagementId,
                category = FindingCategory.HTTP_HEADERS,
                title = "Technology Stack & Detailed Version Banner Disclosure",
                severity = Severity.LOW,
                confidence = Confidence.CONFIRMED,
                status = FindingStatus.VERIFIED,
                cweId = "CWE-200",
                owaspCategory = "A05:2021-Security Misconfiguration",
                summary = "Server banners expose internal web server, framework, or runtime versions in HTTP response headers.",
                technicalEvidence = leaks.joinToString("\n"),
                impact = "Assists threat actors in fingerprinting specific software vulnerabilities and targeting known CVE exploits.",
                remediationGuidance = "Disable server signature tokens in Apache/Nginx/IIS. Remove X-Powered-By and server version numbers from HTTP headers.",
                verificationCurl = "curl -sI https://TARGET | grep -Ei 'server|x-powered-by'"
            )
        }
        return null
    }

    fun checkCookies(cookieHeaders: List<String>, isHttps: Boolean, jobId: String, engagementId: String): List<SecurityFindingEntity> {
        val findings = mutableListOf<SecurityFindingEntity>()
        for (cookie in cookieHeaders) {
            val cookieName = cookie.substringBefore("=").trim()
            val hasSecure = cookie.contains("Secure", ignoreCase = true)
            val hasHttpOnly = cookie.contains("HttpOnly", ignoreCase = true)
            val hasSameSite = cookie.contains("SameSite", ignoreCase = true)

            if (isHttps && !hasSecure) {
                findings.add(
                    SecurityFindingEntity(
                        id = UUID.randomUUID().toString(),
                        jobId = jobId,
                        engagementId = engagementId,
                        category = FindingCategory.COOKIES,
                        title = "Cookie Missing 'Secure' Flag: $cookieName",
                        severity = Severity.MEDIUM,
                        confidence = Confidence.CONFIRMED,
                        status = FindingStatus.VERIFIED,
                        cweId = "CWE-614",
                        owaspCategory = "A05:2021-Security Misconfiguration",
                        summary = "The cookie '$cookieName' was set without the 'Secure' attribute over an HTTPS channel.",
                        technicalEvidence = "Set-Cookie: $cookie",
                        impact = "Browsers may transmit this cookie in unencrypted HTTP requests, exposing session identifiers to wiretapping.",
                        remediationGuidance = "Append '; Secure' to all Set-Cookie directives.",
                        verificationCurl = "curl -sI https://TARGET | grep -i set-cookie"
                    )
                )
            }

            if (!hasHttpOnly && (cookieName.contains("sess", ignoreCase = true) || cookieName.contains("auth", ignoreCase = true) || cookieName.contains("token", ignoreCase = true))) {
                findings.add(
                    SecurityFindingEntity(
                        id = UUID.randomUUID().toString(),
                        jobId = jobId,
                        engagementId = engagementId,
                        category = FindingCategory.COOKIES,
                        title = "Session Cookie Missing 'HttpOnly' Attribute: $cookieName",
                        severity = Severity.HIGH,
                        confidence = Confidence.CONFIRMED,
                        status = FindingStatus.VERIFIED,
                        cweId = "CWE-1004",
                        owaspCategory = "A07:2021-Identification and Authentication Failures",
                        summary = "Authentication or session token '$cookieName' lacks the HttpOnly flag, permitting access from client-side JavaScript.",
                        technicalEvidence = "Set-Cookie: $cookie",
                        impact = "If the application suffers an XSS vulnerability, attackers can steal session tokens directly via document.cookie.",
                        remediationGuidance = "Append '; HttpOnly' to all sensitive session and authentication cookies.",
                        verificationCurl = "curl -sI https://TARGET | grep -i set-cookie"
                    )
                )
            }

            if (!hasSameSite) {
                findings.add(
                    SecurityFindingEntity(
                        id = UUID.randomUUID().toString(),
                        jobId = jobId,
                        engagementId = engagementId,
                        category = FindingCategory.COOKIES,
                        title = "Cookie Missing 'SameSite' Attribute: $cookieName",
                        severity = Severity.LOW,
                        confidence = Confidence.CONFIRMED,
                        status = FindingStatus.VERIFIED,
                        cweId = "CWE-352",
                        owaspCategory = "A01:2021-Broken Access Control",
                        summary = "The cookie '$cookieName' does not specify a SameSite attribute (Strict or Lax).",
                        technicalEvidence = "Set-Cookie: $cookie",
                        impact = "Increases attack surface for Cross-Site Request Forgery (CSRF).",
                        remediationGuidance = "Append '; SameSite=Lax' or '; SameSite=Strict' to the cookie definition.",
                        verificationCurl = "curl -sI https://TARGET | grep -i set-cookie"
                    )
                )
            }
        }
        return findings
    }

    fun checkCertificate(cert: X509Certificate, tlsVersion: String?, cipherSuite: String?, jobId: String, engagementId: String): List<SecurityFindingEntity> {
        val findings = mutableListOf<SecurityFindingEntity>()
        val now = Date()

        // 1. Expiration check
        val notAfter = cert.notAfter
        val daysUntilExpiry = ((notAfter.time - now.time) / (1000 * 60 * 60 * 24)).toInt()

        if (now.after(notAfter)) {
            findings.add(
                SecurityFindingEntity(
                    id = UUID.randomUUID().toString(),
                    jobId = jobId,
                    engagementId = engagementId,
                    category = FindingCategory.TLS,
                    title = "TLS Certificate is Expired",
                    severity = Severity.CRITICAL,
                    confidence = Confidence.CONFIRMED,
                    status = FindingStatus.VERIFIED,
                    cweId = "CWE-298",
                    owaspCategory = "A02:2021-Cryptographic Failures",
                    summary = "The server certificate expired on $notAfter. Connecting clients receive severe browser security warnings.",
                    technicalEvidence = "Certificate Expiry: $notAfter (Expired $daysUntilExpiry days ago)\nSubject: ${cert.subjectDN.name}\nIssuer: ${cert.issuerDN.name}",
                    impact = "Loss of customer trust, broken API clients, and browser blockage.",
                    remediationGuidance = "Renew the SSL/TLS certificate immediately with an authorized Certificate Authority.",
                    verificationCurl = "echo | openssl s_client -connect TARGET:443 2>/dev/null | openssl x509 -noout -dates"
                )
            )
        } else if (daysUntilExpiry <= 14) {
            findings.add(
                SecurityFindingEntity(
                    id = UUID.randomUUID().toString(),
                    jobId = jobId,
                    engagementId = engagementId,
                    category = FindingCategory.TLS,
                    title = "TLS Certificate Expiring Soon (< $daysUntilExpiry Days)",
                    severity = Severity.HIGH,
                    confidence = Confidence.CONFIRMED,
                    status = FindingStatus.VERIFIED,
                    cweId = "CWE-298",
                    owaspCategory = "A02:2021-Cryptographic Failures",
                    summary = "The SSL/TLS certificate expires in $daysUntilExpiry days on $notAfter.",
                    technicalEvidence = "Expires: $notAfter\nIssuer: ${cert.issuerDN.name}",
                    impact = "Imminent outage and service interruption if automated renewal fails.",
                    remediationGuidance = "Verify ACME / cert-manager automated renewal pipelines and reissue certificate.",
                    verificationCurl = "echo | openssl s_client -connect TARGET:443 2>/dev/null | openssl x509 -noout -dates"
                )
            )
        }

        // 2. TLS Version check
        if (tlsVersion != null && (tlsVersion.contains("1.0") || tlsVersion.contains("1.1"))) {
            findings.add(
                SecurityFindingEntity(
                    id = UUID.randomUUID().toString(),
                    jobId = jobId,
                    engagementId = engagementId,
                    category = FindingCategory.TLS,
                    title = "Deprecated TLS Protocol Negotiated ($tlsVersion)",
                    severity = Severity.HIGH,
                    confidence = Confidence.CONFIRMED,
                    status = FindingStatus.VERIFIED,
                    cweId = "CWE-326",
                    owaspCategory = "A02:2021-Cryptographic Failures",
                    summary = "The server negotiated deprecated protocol $tlsVersion. TLS 1.0 and 1.1 have been deprecated by RFC 8996 and NIST guidelines.",
                    technicalEvidence = "Negotiated TLS Version: $tlsVersion\nCipherSuite: ${cipherSuite ?: "Unknown"}",
                    impact = "Susceptible to historical cryptographic attacks (BEAST, POODLE) and fails PCI-DSS compliance.",
                    remediationGuidance = "Disable TLS 1.0 and 1.1 on load balancers. Enforce TLS 1.2 and TLS 1.3 only.",
                    verificationCurl = "openssl s_client -connect TARGET:443 -tls1_1"
                )
            )
        }

        return findings
    }

    fun checkDnsSpfAndDmarc(
        txtRecords: List<String>,
        dmarcRecords: List<String>,
        jobId: String,
        engagementId: String
    ): List<SecurityFindingEntity> {
        val findings = mutableListOf<SecurityFindingEntity>()

        // SPF Check
        val spfRecord = txtRecords.firstOrNull { it.startsWith("v=spf1", ignoreCase = true) }
        if (spfRecord == null) {
            findings.add(
                SecurityFindingEntity(
                    id = UUID.randomUUID().toString(),
                    jobId = jobId,
                    engagementId = engagementId,
                    category = FindingCategory.DNS,
                    title = "Missing Sender Policy Framework (SPF) DNS Record",
                    severity = Severity.MEDIUM,
                    confidence = Confidence.CONFIRMED,
                    status = FindingStatus.VERIFIED,
                    cweId = "CWE-290",
                    owaspCategory = "A07:2021-Identification and Authentication Failures",
                    summary = "No SPF record was located in DNS TXT records. Mail servers cannot authenticate authorized sending MTAs.",
                    technicalEvidence = "DNS TXT records checked: ${txtRecords.ifEmpty { listOf("None") }.joinToString(", ")}",
                    impact = "Allows spoofed phishing emails to be sent impersonating the domain.",
                    remediationGuidance = "Publish a valid SPF record in DNS: 'v=spf1 include:_spf.example.com -all'",
                    verificationCurl = "dig TXT TARGET +short"
                )
            )
        } else if (spfRecord.contains("+all")) {
            findings.add(
                SecurityFindingEntity(
                    id = UUID.randomUUID().toString(),
                    jobId = jobId,
                    engagementId = engagementId,
                    category = FindingCategory.DNS,
                    title = "Permissive SPF Record (+all)",
                    severity = Severity.HIGH,
                    confidence = Confidence.CONFIRMED,
                    status = FindingStatus.VERIFIED,
                    cweId = "CWE-290",
                    owaspCategory = "A07:2021-Identification and Authentication Failures",
                    summary = "SPF record specifies '+all', permitting any internet host to send email on behalf of the domain.",
                    technicalEvidence = "SPF Record: $spfRecord",
                    impact = "Completely disables email origin validation, facilitating widespread email spoofing.",
                    remediationGuidance = "Change '+all' to strict fail '-all' or soft fail '~all'.",
                    verificationCurl = "dig TXT TARGET +short"
                )
            )
        }

        // DMARC Check
        val dmarcRecord = dmarcRecords.firstOrNull { it.startsWith("v=DMARC1", ignoreCase = true) }
        if (dmarcRecord == null) {
            findings.add(
                SecurityFindingEntity(
                    id = UUID.randomUUID().toString(),
                    jobId = jobId,
                    engagementId = engagementId,
                    category = FindingCategory.DNS,
                    title = "Missing DMARC Email Protection Policy",
                    severity = Severity.MEDIUM,
                    confidence = Confidence.CONFIRMED,
                    status = FindingStatus.VERIFIED,
                    cweId = "CWE-290",
                    owaspCategory = "A07:2021-Identification and Authentication Failures",
                    summary = "No DMARC record exists at _dmarc.<target>. Recipient MTAs cannot enforce quarantine or rejection policies on spoofed messages.",
                    technicalEvidence = "Query: _dmarc.TARGET TXT -> [RECORD NOT FOUND]",
                    impact = "Adversaries can forge executive emails and domain identity with negligible deliverability friction.",
                    remediationGuidance = "Add TXT record at _dmarc.<domain>: 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@<domain>'",
                    verificationCurl = "dig TXT _dmarc.TARGET +short"
                )
            )
        } else if (dmarcRecord.contains("p=none", ignoreCase = true)) {
            findings.add(
                SecurityFindingEntity(
                    id = UUID.randomUUID().toString(),
                    jobId = jobId,
                    engagementId = engagementId,
                    category = FindingCategory.DNS,
                    title = "DMARC Policy Set to Monitoring Only (p=none)",
                    severity = Severity.LOW,
                    confidence = Confidence.CONFIRMED,
                    status = FindingStatus.VERIFIED,
                    cweId = "CWE-290",
                    owaspCategory = "A07:2021-Identification and Authentication Failures",
                    summary = "The DMARC policy is set to 'p=none', which logs reports but does not block spoofed emails from reaching inboxes.",
                    technicalEvidence = "DMARC Record: $dmarcRecord",
                    impact = "Fails to protect brand reputation against active phishing campaigns.",
                    remediationGuidance = "Transition policy from 'p=none' to 'p=quarantine' and ultimately 'p=reject'.",
                    verificationCurl = "dig TXT _dmarc.TARGET +short"
                )
            )
        }

        return findings
    }
}
