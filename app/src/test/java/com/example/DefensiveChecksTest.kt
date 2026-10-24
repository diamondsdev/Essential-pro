package com.example

import com.example.data.model.Severity
import com.example.engine.DefensiveChecks
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DefensiveChecksTest {

    private val testJobId = "job-test-123"
    private val testEngId = "eng-test-456"

    @Test
    fun testMissingHstsFlagsHighSeverity() {
        val emptyHeaders = emptyMap<String, String>()
        val finding = DefensiveChecks.checkHsts(emptyHeaders, isHttps = true, jobId = testJobId, engagementId = testEngId)
        assertNotNull(finding)
        assertEquals(Severity.HIGH, finding!!.severity)
        assertEquals("CWE-319", finding.cweId)
        assertTrue(finding.title.contains("Missing HTTP Strict Transport Security"))
    }

    @Test
    fun testValidHstsPassesClean() {
        val headers = mapOf("Strict-Transport-Security" to "max-age=31536000; includeSubDomains; preload")
        val finding = DefensiveChecks.checkHsts(headers, isHttps = true, jobId = testJobId, engagementId = testEngId)
        assertNull(finding)
    }

    @Test
    fun testMissingCspFlagsMediumSeverity() {
        val headers = emptyMap<String, String>()
        val finding = DefensiveChecks.checkCsp(headers, jobId = testJobId, engagementId = testEngId)
        assertNotNull(finding)
        assertEquals(Severity.MEDIUM, finding!!.severity)
        assertEquals("CWE-1021", finding.cweId)
    }

    @Test
    fun testMissingXFrameOptionsFlagsClickjacking() {
        val headers = emptyMap<String, String>()
        val finding = DefensiveChecks.checkXFrameOptions(headers, jobId = testJobId, engagementId = testEngId)
        assertNotNull(finding)
        assertEquals(Severity.MEDIUM, finding!!.severity)
        assertTrue(finding.title.contains("Clickjacking"))
    }

    @Test
    fun testMissingXContentTypeOptionsFlagsNosniff() {
        val headers = emptyMap<String, String>()
        val finding = DefensiveChecks.checkXContentTypeOptions(headers, jobId = testJobId, engagementId = testEngId)
        assertNotNull(finding)
        assertEquals(Severity.LOW, finding!!.severity)
        assertTrue(finding.title.contains("MIME-Sniffing"))
    }

    @Test
    fun testCookieSecurityFlags() {
        val insecureCookies = listOf("session_id=abc123456; Path=/")
        val findings = DefensiveChecks.checkCookies(insecureCookies, isHttps = true, jobId = testJobId, engagementId = testEngId)
        // Should flag missing Secure flag, missing HttpOnly flag, and missing SameSite
        assertEquals(3, findings.size)
        assertTrue(findings.any { it.title.contains("Missing 'Secure' Flag") })
        assertTrue(findings.any { it.title.contains("Missing 'HttpOnly'") })
        assertTrue(findings.any { it.title.contains("Missing 'SameSite'") })
    }

    @Test
    fun testDnsMissingSpfAndDmarc() {
        val findings = DefensiveChecks.checkDnsSpfAndDmarc(
            txtRecords = emptyList(),
            dmarcRecords = emptyList(),
            jobId = testJobId,
            engagementId = testEngId
        )
        assertEquals(2, findings.size)
        assertTrue(findings.any { it.title.contains("Missing Sender Policy Framework (SPF)") })
        assertTrue(findings.any { it.title.contains("Missing DMARC") })
    }
}
