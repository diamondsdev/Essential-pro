package com.example.report

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AssessmentJobEntity
import com.example.data.model.AuthorizationRecordEntity
import com.example.data.model.ClientEntity
import com.example.data.model.EngagementEntity
import com.example.data.model.SecurityFindingEntity
import com.example.data.model.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class PdfSecurityReportGenerator(private val context: Context) {

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US)

    suspend fun generatePdf(
        job: AssessmentJobEntity,
        engagement: EngagementEntity?,
        client: ClientEntity?,
        authorization: AuthorizationRecordEntity?,
        scopes: List<ApprovedScopeEntity>,
        findings: List<SecurityFindingEntity>
    ): File = withContext(Dispatchers.IO) {
        val pdfDocument = PdfDocument()
        val pageWidth = 595 // Standard A4 width in PostScript points
        val pageHeight = 842 // Standard A4 height in PostScript points

        val pageInfo = PdfDocument.PageInfo.Builder(pageWidth, pageHeight, 1).create()
        val page = pdfDocument.startPage(pageInfo)
        val canvas = page.canvas

        val paint = Paint().apply { isAntiAlias = true }
        var y = 40f

        // 1. Header Banner
        paint.color = Color.parseColor("#0F172A") // Deep cyber slate
        canvas.drawRect(0f, 0f, pageWidth.toFloat(), 90f, paint)

        // Title
        paint.color = Color.parseColor("#38BDF8") // Cyan
        paint.textSize = 18f
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        canvas.drawText("SENTINEL PRO // DEFENSIVE SECURITY ASSESSMENT", 30f, 40f, paint)

        paint.color = Color.parseColor("#94A3B8")
        paint.textSize = 10f
        paint.typeface = Typeface.DEFAULT
        canvas.drawText("CONFIDENTIAL SECURITY REPORT — AUTHORIZED CLIENT REVIEW ONLY", 30f, 60f, paint)

        val reportDateStr = dateFormat.format(Date(job.completedAt ?: System.currentTimeMillis()))
        canvas.drawText("Generated: $reportDateStr", 30f, 75f, paint)

        y = 115f

        // 2. Engagement & Authorization Metadata Card
        paint.color = Color.parseColor("#F1F5F9")
        val metaCardRect = RectF(25f, y, pageWidth - 25f, y + 105f)
        canvas.drawRoundRect(metaCardRect, 8f, 8f, paint)

        paint.color = Color.parseColor("#0F172A")
        paint.textSize = 11f
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        canvas.drawText("ENGAGEMENT & RULES OF ENGAGEMENT (ROA)", 35f, y + 20f, paint)

        paint.textSize = 9.5f
        paint.typeface = Typeface.DEFAULT
        paint.color = Color.parseColor("#334155")

        val clientName = client?.organization ?: "Authorized Client Organization"
        val engTitle = engagement?.title ?: "Web Perimeter Security Assessment"
        val roaRef = authorization?.documentReference ?: "Awaiting Signed ROA"
        val roaStatus = authorization?.verificationStatus?.label ?: "PENDING_VERIFICATION"
        val authorizedBy = authorization?.authorizedByName ?: "Chief Information Security Officer"

        canvas.drawText("Client Organization: $clientName", 35f, y + 40f, paint)
        canvas.drawText("Engagement: $engTitle", 35f, y + 55f, paint)
        canvas.drawText("Written ROA Reference: $roaRef (Status: $roaStatus)", 35f, y + 70f, paint)
        canvas.drawText("Authorized Officer: $authorizedBy | Assessor: ${job.triggeredBy}", 35f, y + 85f, paint)
        canvas.drawText("Target Host: ${job.resolvedHost} (${job.resolvedIps})", 35f, y + 100f, paint)

        y += 125f

        // 3. Posture Score & Metrics Badge
        paint.color = when (job.postureGrade) {
            "A+", "A" -> Color.parseColor("#10B981") // Green
            "B" -> Color.parseColor("#0284C7") // Blue
            "C" -> Color.parseColor("#D97706") // Amber
            else -> Color.parseColor("#DC2626") // Red
        }
        val scoreCardRect = RectF(25f, y, 160f, y + 65f)
        canvas.drawRoundRect(scoreCardRect, 8f, 8f, paint)

        paint.color = Color.WHITE
        paint.textSize = 11f
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        canvas.drawText("POSTURE GRADE", 40f, y + 22f, paint)

        paint.textSize = 28f
        canvas.drawText("${job.postureGrade} (${job.postureScore}/100)", 40f, y + 52f, paint)

        // Metrics breakdown box
        paint.color = Color.parseColor("#F8FAFC")
        val metricsRect = RectF(175f, y, pageWidth - 25f, y + 65f)
        canvas.drawRoundRect(metricsRect, 8f, 8f, paint)

        paint.color = Color.parseColor("#0F172A")
        paint.textSize = 10f
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        canvas.drawText("CHECKS & FINDINGS SUMMARY", 185f, y + 20f, paint)

        paint.textSize = 9f
        paint.typeface = Typeface.DEFAULT
        paint.color = Color.parseColor("#475569")
        val metricsText = "Checks: ${job.checksPassedCount} Passed, ${job.checksFailedCount} Flagged | Critical: ${job.criticalCount} High: ${job.highCount} Med: ${job.mediumCount}"
        canvas.drawText(metricsText, 185f, y + 42f, paint)
        canvas.drawText("Scope: ${scopes.map { it.hostname }.joinToString(", ")}", 185f, y + 56f, paint)

        y += 85f

        // 4. Findings Header
        paint.color = Color.parseColor("#0F172A")
        paint.textSize = 13f
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        canvas.drawText("DEFENSIVE FINDINGS & OBSERVATIONS (${findings.size})", 25f, y, paint)
        y += 18f

        // Loop findings (fit page 1 or create subsequent pages if needed)
        var currentPage = page
        var currentCanvas = canvas
        var pageIndex = 1

        for (finding in findings) {
            // Check page overflow
            if (y > pageHeight - 120f) {
                pdfDocument.finishPage(currentPage)
                pageIndex++
                val nextInfo = PdfDocument.PageInfo.Builder(pageWidth, pageHeight, pageIndex).create()
                currentPage = pdfDocument.startPage(nextInfo)
                currentCanvas = currentPage.canvas
                y = 40f

                // Header on subsequent page
                paint.color = Color.parseColor("#0F172A")
                paint.textSize = 10f
                paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
                currentCanvas.drawText("SENTINEL PRO // DEFENSIVE ASSESSMENT REPORT (CONT.) — PAGE $pageIndex", 25f, y, paint)
                y += 25f
            }

            // Severity Badge Color
            val badgeColor = when (finding.severity) {
                Severity.CRITICAL -> Color.parseColor("#DC2626")
                Severity.HIGH -> Color.parseColor("#EA580C")
                Severity.MEDIUM -> Color.parseColor("#D97706")
                Severity.LOW -> Color.parseColor("#0284C7")
                Severity.INFORMATIONAL -> Color.parseColor("#64748B")
            }

            val findingCardHeight = 85f
            paint.color = Color.parseColor("#F8FAFC")
            val cardRect = RectF(25f, y, pageWidth - 25f, y + findingCardHeight)
            currentCanvas.drawRoundRect(cardRect, 6f, 6f, paint)

            // Severity indicator bar on left
            paint.color = badgeColor
            val barRect = RectF(25f, y, 30f, y + findingCardHeight)
            currentCanvas.drawRoundRect(barRect, 2f, 2f, paint)

            // Finding Title & Severity Pill
            paint.color = badgeColor
            paint.textSize = 9f
            paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            currentCanvas.drawText("[${finding.severity.label}]", 40f, y + 16f, paint)

            paint.color = Color.parseColor("#0F172A")
            paint.textSize = 10f
            val cleanTitle = if (finding.title.length > 60) finding.title.take(57) + "..." else finding.title
            currentCanvas.drawText(cleanTitle, 105f, y + 16f, paint)

            paint.color = Color.parseColor("#64748B")
            paint.textSize = 8f
            paint.typeface = Typeface.DEFAULT
            currentCanvas.drawText("${finding.category.label} | ${finding.cweId} | ${finding.owaspCategory}", 40f, y + 28f, paint)

            // Summary
            paint.color = Color.parseColor("#334155")
            paint.textSize = 8.5f
            val truncatedSummary = if (finding.summary.length > 115) finding.summary.take(112) + "..." else finding.summary
            currentCanvas.drawText(truncatedSummary, 40f, y + 43f, paint)

            // Evidence Snippet
            paint.color = Color.parseColor("#0F172A")
            paint.textSize = 8f
            paint.typeface = Typeface.MONOSPACE
            val cleanEvidence = finding.technicalEvidence.lines().firstOrNull()?.take(80) ?: "Observed configuration"
            currentCanvas.drawText("Evidence: $cleanEvidence", 40f, y + 58f, paint)

            // Remediation
            paint.color = Color.parseColor("#047857")
            paint.typeface = Typeface.DEFAULT
            val cleanRemediation = if (finding.remediationGuidance.length > 105) finding.remediationGuidance.take(102) + "..." else finding.remediationGuidance
            currentCanvas.drawText("Remediation: $cleanRemediation", 40f, y + 73f, paint)

            y += findingCardHeight + 10f
        }

        // Footer Statement
        if (y < pageHeight - 50f) {
            paint.color = Color.parseColor("#94A3B8")
            paint.textSize = 7.5f
            paint.typeface = Typeface.DEFAULT
            currentCanvas.drawText(
                "Methodology Statement: Assessment performed in strict accordance with written authorization rules. Non-destructive testing only.",
                25f,
                pageHeight - 25f,
                paint
            )
        }

        pdfDocument.finishPage(currentPage)

        // Write to application cache
        val reportsDir = File(context.cacheDir, "reports").apply { mkdirs() }
        val outputFile = File(reportsDir, "Sentinel_Report_${job.resolvedHost}_${job.id.take(8)}.pdf")
        FileOutputStream(outputFile).use { out ->
            pdfDocument.writeTo(out)
        }
        pdfDocument.close()

        outputFile
    }
}
