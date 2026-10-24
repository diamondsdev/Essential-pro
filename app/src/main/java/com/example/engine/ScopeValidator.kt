package com.example.engine

import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AuthorizationRecordEntity
import com.example.data.model.AuthorizationStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.IDN
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI

sealed class ScopeEnforcementResult {
    data class Allowed(
        val normalizedHost: String,
        val targetUri: URI,
        val validatedAddresses: List<InetAddress>,
        val matchedScope: ApprovedScopeEntity
    ) : ScopeEnforcementResult()

    data class Denied(
        val reason: String,
        val host: String? = null,
        val isSecurityViolation: Boolean = false
    ) : ScopeEnforcementResult()
}

class ScopeValidator {

    /**
     * Centralized, fail-closed target validation and scope boundary enforcement.
     */
    suspend fun validateTarget(
        inputUrl: String,
        authorization: AuthorizationRecordEntity?,
        activeScopes: List<ApprovedScopeEntity>,
        allowDemoTesting: Boolean = false
    ): ScopeEnforcementResult = withContext(Dispatchers.IO) {
        // 1. Authorization Gate Check
        if (authorization == null) {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "Assessment aborted: No written Rules of Engagement (ROA) record on file.",
                isSecurityViolation = false
            )
        }

        if (authorization.isDemo && !allowDemoTesting) {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "Assessment blocked: Demo records cannot authorize live network testing. Create a verified production engagement.",
                isSecurityViolation = false
            )
        }

        if (authorization.revokedAtTimestamp != null || authorization.verificationStatus == AuthorizationStatus.REVOKED) {
            val note = authorization.revocationReason?.let { ": $it" } ?: ""
            return@withContext ScopeEnforcementResult.Denied(
                reason = "Assessment aborted: Written authorization was explicitly REVOKED$note.",
                isSecurityViolation = true
            )
        }

        if (authorization.verificationStatus != AuthorizationStatus.VERIFIED) {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "Assessment aborted: Authorization status is '${authorization.verificationStatus.label}'. Written evidence must be verified by an authorized auditor before scanning.",
                isSecurityViolation = false
            )
        }

        if (!authorization.explicitTestingPermitted) {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "Assessment aborted: ROA explicitly disallows active/passive testing.",
                isSecurityViolation = true
            )
        }

        val now = System.currentTimeMillis()
        if (now < authorization.validFromTimestamp) {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "Assessment aborted: Authorization window is future-dated (not yet active).",
                isSecurityViolation = false
            )
        }
        if (now > authorization.validToTimestamp) {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "Assessment aborted: Authorization window has expired.",
                isSecurityViolation = false
            )
        }

        // 2. Parse URL and Scheme
        val sanitized = inputUrl.trim()
        val uri: URI = try {
            val temp = URI.create(sanitized)
            if (temp.scheme == null) {
                URI.create("https://$sanitized")
            } else {
                temp
            }
        } catch (e: Exception) {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "Invalid URL syntax: ${e.message}",
                isSecurityViolation = false
            )
        }

        val scheme = uri.scheme?.lowercase()
        if (scheme != "http" && scheme != "https") {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "Unsupported URL scheme '$scheme'. Only HTTP and HTTPS are permitted for defensive website assessments.",
                isSecurityViolation = true
            )
        }

        val rawHost = uri.host
        if (rawHost.isNullOrBlank()) {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "Target URL must contain a valid, non-empty hostname.",
                isSecurityViolation = false
            )
        }

        // 3. Normalize Hostname (IDN, lowercasing, trailing dots)
        val normalizedHost = try {
            IDN.toASCII(rawHost).lowercase().trimEnd('.')
        } catch (e: Exception) {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "Malformed internationalized hostname '$rawHost': ${e.message}",
                isSecurityViolation = true
            )
        }

        // 4. DNS Resolution & Multi-destination IP Validation (Anti-SSRF & DNS Rebinding)
        val resolvedAddresses: Array<InetAddress> = try {
            InetAddress.getAllByName(normalizedHost)
        } catch (e: Exception) {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "DNS lookup failed for '$normalizedHost'. Target host does not exist or network is offline.",
                host = normalizedHost,
                isSecurityViolation = false
            )
        }

        if (resolvedAddresses.isEmpty()) {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "DNS returned no routable IP addresses for '$normalizedHost'.",
                host = normalizedHost,
                isSecurityViolation = false
            )
        }

        // Check EVERY returned address against comprehensive prohibited lists
        for (addr in resolvedAddresses) {
            val (isBlocked, reason) = checkProhibitedAddress(addr)
            if (isBlocked) {
                return@withContext ScopeEnforcementResult.Denied(
                    reason = "Security boundary violation: Host '$normalizedHost' resolved to prohibited destination ($reason: ${addr.hostAddress}).",
                    host = normalizedHost,
                    isSecurityViolation = true
                )
            }
        }

        // 5. Approved Scope Matching (Host, Ports, Path Prefix)
        val targetPort = if (uri.port != -1) uri.port else (if (scheme == "http") 80 else 443)
        val targetPath = if (uri.path.isNullOrBlank()) "/" else uri.path

        val matchedScope = activeScopes.firstOrNull { scope ->
            if (!scope.active) return@firstOrNull false
            val scopeHost = try {
                IDN.toASCII(scope.hostname).lowercase().trimEnd('.')
            } catch (_: Exception) {
                scope.hostname.lowercase().trimEnd('.')
            }

            // Strict Host Matching
            val hostMatches = if (scope.wildcardAllowed) {
                normalizedHost == scopeHost || normalizedHost.endsWith(".$scopeHost")
            } else {
                normalizedHost == scopeHost
            }

            if (!hostMatches) return@firstOrNull false

            // Port Restriction Check
            val allowedPortsList = scope.allowedPorts
                .split(",")
                .mapNotNull { it.trim().toIntOrNull() }
            if (allowedPortsList.isNotEmpty() && targetPort !in allowedPortsList) {
                return@firstOrNull false
            }

            // Path Restriction Check
            val requiredPrefix = scope.pathPrefix.trim()
            if (requiredPrefix.isNotBlank() && requiredPrefix != "/") {
                if (!targetPath.startsWith(requiredPrefix)) {
                    return@firstOrNull false
                }
            }

            true
        }

        if (matchedScope == null) {
            return@withContext ScopeEnforcementResult.Denied(
                reason = "Out-of-Scope: Target '$normalizedHost' (port $targetPort, path '$targetPath') is not authorized in approved engagement scopes.",
                host = normalizedHost,
                isSecurityViolation = true
            )
        }

        return@withContext ScopeEnforcementResult.Allowed(
            normalizedHost = normalizedHost,
            targetUri = uri,
            validatedAddresses = resolvedAddresses.toList(),
            matchedScope = matchedScope
        )
    }

    /**
     * Comprehensive IP Blacklist for Anti-SSRF / Internal Infrastructure Protection
     */
    fun checkProhibitedAddress(addr: InetAddress): Pair<Boolean, String?> {
        // Loopback (127.0.0.0/8, ::1)
        if (addr.isLoopbackAddress) return true to "Loopback Address"
        // Any local / wildcard (0.0.0.0, ::)
        if (addr.isAnyLocalAddress) return true to "Unspecified / Wildcard Address"
        // Link-local (169.254.0.0/16, fe80::/10)
        if (addr.isLinkLocalAddress) return true to "Link-Local / Cloud Metadata Address"
        // Site-local / RFC 1918 Private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        if (addr.isSiteLocalAddress) return true to "RFC 1918 Private Network"
        // Multicast
        if (addr.isMulticastAddress) return true to "Multicast Address"

        val bytes = addr.address

        if (addr is Inet4Address) {
            val b0 = bytes[0].toInt() and 0xFF
            val b1 = bytes[1].toInt() and 0xFF

            // 0.0.0.0/8
            if (b0 == 0) return true to "Current Network (0.0.0.0/8)"
            // 100.64.0.0/10 (Carrier-Grade NAT, RFC 6598)
            if (b0 == 100 && (b1 and 0xC0) == 64) return true to "Shared / CGNAT Address (100.64.0.0/10)"
            // 192.0.0.0/24 (IETF Protocol Assignments)
            if (b0 == 192 && b1 == 0 && (bytes[2].toInt() and 0xFF) == 0) return true to "IETF Protocol Assignment (192.0.0.0/24)"
            // 192.0.2.0/24 (TEST-NET-1)
            if (b0 == 192 && b1 == 0 && (bytes[2].toInt() and 0xFF) == 2) return true to "Documentation Address (192.0.2.0/24)"
            // 198.18.0.0/15 (Benchmarking)
            if (b0 == 198 && (b1 in 18..19)) return true to "Benchmark Address (198.18.0.0/15)"
            // 198.51.100.0/24 (TEST-NET-2)
            if (b0 == 198 && b1 == 51 && (bytes[2].toInt() and 0xFF) == 100) return true to "Documentation Address (198.51.100.0/24)"
            // 203.0.113.0/24 (TEST-NET-3)
            if (b0 == 203 && b1 == 0 && (bytes[2].toInt() and 0xFF) == 113) return true to "Documentation Address (203.0.113.0/24)"
            // 240.0.0.0/4 (Reserved / Future Use)
            if ((b0 and 0xF0) == 240) return true to "Reserved Address (240.0.0.0/4)"
        }

        if (addr is Inet6Address) {
            val b0 = bytes[0].toInt() and 0xFF
            val b1 = bytes[1].toInt() and 0xFF

            // Unique Local Address (fc00::/7)
            if ((b0 and 0xFE) == 0xFC) return true to "IPv6 Unique Local Address (fc00::/7)"
            // IPv4-mapped IPv6 (::ffff:0:0/96)
            var isIPv4Mapped = true
            for (i in 0..9) {
                if (bytes[i] != 0.toByte()) { isIPv4Mapped = false; break }
            }
            if (isIPv4Mapped && bytes[10] == 0xFF.toByte() && bytes[11] == 0xFF.toByte()) {
                val mappedIpv4Bytes = byteArrayOf(bytes[12], bytes[13], bytes[14], bytes[15])
                val mappedIpv4 = InetAddress.getByAddress(mappedIpv4Bytes)
                return checkProhibitedAddress(mappedIpv4)
            }
            // Documentation prefix (2001:db8::/32)
            if (b0 == 0x20 && b1 == 0x01 && (bytes[2].toInt() and 0xFF) == 0x0D && (bytes[3].toInt() and 0xFF) == 0xB8) {
                return true to "IPv6 Documentation Prefix (2001:db8::/32)"
            }
        }

        return false to null
    }
}
