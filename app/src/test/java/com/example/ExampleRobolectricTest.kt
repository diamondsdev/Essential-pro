package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.data.model.AssessmentJobEntity
import com.example.report.MarkdownReportGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

    @Test
    fun `read string from context`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val appName = context.getString(R.string.app_name)
        assertEquals("Sentinel Pro", appName)
    }

    @Test
    fun `generate markdown report with executive summary and scope`() {
        val dummyJob = AssessmentJobEntity(
            id = "test-job-001",
            engagementId = "eng-001",
            targetUrl = "https://scanme.nmap.org",
            resolvedHost = "scanme.nmap.org",
            resolvedIps = "45.33.32.156",
            status = "COMPLETED",
            postureScore = 92,
            postureGrade = "A"
        )
        val markdown = MarkdownReportGenerator.generateMarkdown(
            job = dummyJob,
            engagement = null,
            client = null,
            authorization = null,
            scopes = emptyList(),
            findings = emptyList()
        )
        assertNotNull(markdown)
        assertTrue(markdown.contains("Sentinel Pro"))
        assertTrue(markdown.contains("scanme.nmap.org"))
        assertTrue(markdown.contains("Overall Posture Grade"))
        assertTrue(markdown.contains("(92/100)"))
    }
}
