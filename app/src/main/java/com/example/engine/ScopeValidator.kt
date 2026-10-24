package com.example.engine

import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AuthorizationRecordEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.URI

sealed class ScopeEnforcementResult {
    data class Allowed(
        val normalizedHost: String,
        val targetUri: URI,
        val resolvedIps: List<String>,
        val matchedScope: ApprovedScopeEntity
    ) : ScopeEnforcementResult()

    data class Denied(
        val reason: String,
        val host: String? = null
    ) : ScopeEnforcementResult()
}

class ScopeValidator {

    suspend fun validateTarget(
        inputUrl: String,
        authorization: AuthorizationRecordEntity?,
        activeScopes: List<ApprovedScopeEntity>
    ): ScopeEnforcementResult = withContext(Dispatchers.IO) {
        // 1. Authorization Gate Check
        if (authorization == null) {
            return@withContext ScopeEnforcementResult.Denied(
                "Assessment aborted: No written Rules of Engagement (ROA) authorization record on file."
            )
        }
        if (!authorization.explicitTestingPermitted) {
            return@withContext ScopeEnforcementResult.Denied(
                "Assessment aborted: ROA explicitly disallows active/passive testing."
            )
        }
        val now = System.currentTimeMillis()
        if (now < authorization.validFromTimestamp || now > authorization.validToTimestamp) {
            return@withContext ScopeEnforcementResult.Denied(
                "Assessment aborted: Authorization window has expired or is not yet active."
            )
        }

        // 2. Parse URL and Scheme
        val sanitized = inputUrl.trim()
        val urlWithScheme = if (!sanitized.startsWith("http://") && !sanitized.startsWith("https://")) {
            "https://$sanitized"
        } else {
            sanitized
        }

        val uri: URI = try {
            URI.create(urlWithScheme)
        } catch (e: Exception) {
            return@withContext ScopeEnforcementResult.Denied("Invalid URL syntax: ${e.message}")
        }

        val rawHost = uri.host
        if (rawHost.isNullOrBlank()) {
            return@withContext ScopeEnforcementResult.Denied("Target URL must contain a valid hostname.")
        }
        val normalizedHost = rawHost.lowercase().trimEnd('.')

        // 3. Prohibited & Private IP protection (Prevent internal abuse / SSRF)
        if (normalizedHost == "localhost" ||
            normalizedHost == "127.0.0.1" ||
            normalizedHost == "::1" ||
            normalizedHost == "169.254.169.254"
        ) {
            return@withContext ScopeEnforcementResult.Denied(
                "Safety violation: Localhost and cloud metadata endpoints are strictly prohibited."
            )
        }

        // 4. DNS Resolution & Private Network Check
        val resolvedIps: List<String> = try {
            InetAddress.getAllByName(normalizedHost).map { it.hostAddress }
        } catch (e: Exception) {
            // Host does not resolve
            return@withContext ScopeEnforcementResult.Denied(
                "DNS lookup failed for '$normalizedHost'. Host does not exist or network is offline."
            )
        }

        for (ip in resolvedIps) {
            if (isPrivateOrLoopbackIp(ip)) {
                return@withContext ScopeEnforcementResult.Denied(
                    "Safety violation: Host '$normalizedHost' resolves to private/internal IP ($ip)."
                )
            }
        }

        // 5. Approved Scope Matching
        val targetPort = if (uri.port != -1) uri.port else (if (uri.scheme == "http") 80 else 443)

        val matchedScope = activeScopes.firstOrNull { scope ->
            if (!scope.active) return@firstOrNull false
            val scopeHost = scope.hostname.lowercase().trimEnd('.')

            val hostMatches = if (scope.wildcardAllowed) {
                normalizedHost == scopeHost || normalizedHost.endsWith(".$scopeHost")
            } else {
                normalizedHost == scopeHost
            }

            if (!hostMatches) return@firstOrNull false

            // Port restriction check
            val allowedPortsList = scope.allowedPorts
                .split(",")
                .mapNotNull { it.trim().toIntOrNull() }
            if (allowedPortsList.isNotEmpty() && targetPort !in allowedPortsList) {
                return@firstOrNull false
            }

            true
        }

        if (matchedScope == null) {
            return@withContext ScopeEnforcementResult.Denied(
                "Out-of-Scope: '$normalizedHost' (port $targetPort) is NOT listed in approved engagement scopes.",
                host = normalizedHost
            )
        }

        return@withContext ScopeEnforcementResult.Allowed(
            normalizedHost = normalizedHost,
            targetUri = uri,
            resolvedIps = resolvedIps,
            matchedScope = matchedScope
        )
    }

    private fun isPrivateOrLoopbackIp(ip: String): Boolean {
        if (ip.startsWith("127.") || ip == "::1" || ip == "0.0.0.0") return true
        if (ip.startsWith("10.")) return true
        if (ip.startsWith("192.168.")) return true
        if (ip.startsWith("169.254.")) return true // Link-local
        // Check 172.16.0.0 - 172.31.255.255
        if (ip.startsWith("172.")) {
            val parts = ip.split(".")
            if (parts.size >= 2) {
                val second = parts[1].toIntOrNull()
                if (second != null && second in 16..31) return true
            }
        }
        return false
    }
}
