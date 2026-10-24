package com.example

import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AuthorizationRecordEntity
import com.example.engine.ScopeEnforcementResult
import com.example.engine.ScopeValidator
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScopeValidatorTest {

    private val validator = ScopeValidator()

    private val validAuth = AuthorizationRecordEntity(
        id = "auth-1",
        engagementId = "eng-1",
        authorizedByName = "CISO",
        authorizedByRole = "Chief Information Security Officer",
        authorizedByEmail = "ciso@example.com",
        documentReference = "SOW-2026-001",
        authorizationScopeSummary = "Defensive tests",
        validFromTimestamp = System.currentTimeMillis() - 86400000L,
        validToTimestamp = System.currentTimeMillis() + 86400000L * 10,
        explicitTestingPermitted = true,
        emergencyContactPhone = "+1-555-0100"
    )

    private val approvedScopes = listOf(
        ApprovedScopeEntity(
            id = "scope-1",
            engagementId = "eng-1",
            hostname = "scanme.nmap.org",
            wildcardAllowed = false,
            allowedPorts = "80,443"
        ),
        ApprovedScopeEntity(
            id = "scope-2",
            engagementId = "eng-1",
            hostname = "example.com",
            wildcardAllowed = true,
            allowedPorts = "80,443"
        )
    )

    @Test
    fun testBlocksScanWithoutAuthorization() = runBlocking {
        val result = validator.validateTarget(
            inputUrl = "https://scanme.nmap.org",
            authorization = null,
            activeScopes = approvedScopes
        )
        assertTrue(result is ScopeEnforcementResult.Denied)
        val denied = result as ScopeEnforcementResult.Denied
        assertTrue(denied.reason.contains("No written Rules of Engagement", ignoreCase = true))
    }

    @Test
    fun testBlocksScanWhenTestingDisallowedInRoa() = runBlocking {
        val disallowedAuth = validAuth.copy(explicitTestingPermitted = false)
        val result = validator.validateTarget(
            inputUrl = "https://scanme.nmap.org",
            authorization = disallowedAuth,
            activeScopes = approvedScopes
        )
        assertTrue(result is ScopeEnforcementResult.Denied)
        val denied = result as ScopeEnforcementResult.Denied
        assertTrue(denied.reason.contains("ROA explicitly disallows", ignoreCase = true))
    }

    @Test
    fun testBlocksScanWhenAuthorizationExpired() = runBlocking {
        val expiredAuth = validAuth.copy(validToTimestamp = System.currentTimeMillis() - 1000L)
        val result = validator.validateTarget(
            inputUrl = "https://scanme.nmap.org",
            authorization = expiredAuth,
            activeScopes = approvedScopes
        )
        assertTrue(result is ScopeEnforcementResult.Denied)
        val denied = result as ScopeEnforcementResult.Denied
        assertTrue(denied.reason.contains("expired", ignoreCase = true))
    }

    @Test
    fun testBlocksOutOfScopeHost() = runBlocking {
        val result = validator.validateTarget(
            inputUrl = "https://unauthorized-victim.org",
            authorization = validAuth,
            activeScopes = approvedScopes
        )
        assertTrue(result is ScopeEnforcementResult.Denied)
    }

    @Test
    fun testBlocksLocalhostAndLoopbackSsrf() = runBlocking {
        val result = validator.validateTarget(
            inputUrl = "http://127.0.0.1:8080",
            authorization = validAuth,
            activeScopes = approvedScopes
        )
        assertTrue(result is ScopeEnforcementResult.Denied)
        val denied = result as ScopeEnforcementResult.Denied
        assertTrue(denied.reason.contains("prohibited", ignoreCase = true))
    }
}
