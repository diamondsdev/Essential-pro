package com.example.data.model

enum class Severity(val label: String, val weight: Int) {
    CRITICAL("CRITICAL", 25),
    HIGH("HIGH", 15),
    MEDIUM("MEDIUM", 8),
    LOW("LOW", 3),
    INFORMATIONAL("INFO", 0)
}

enum class Confidence(val label: String) {
    CONFIRMED("Confirmed Observation"),
    HIGH("High Confidence"),
    MEDIUM("Medium Confidence"),
    LOW("Tentative / Unverified")
}

enum class FindingStatus(val label: String) {
    AUTOMATED_OBSERVATION("Automated Observation"),
    VERIFIED("Human Verified"),
    MITIGATED("Mitigated"),
    FALSE_POSITIVE("False Positive"),
    ACCEPTED_RISK("Risk Accepted")
}

enum class FindingCategory(val label: String) {
    DNS("DNS & Domain Security"),
    TLS("TLS / SSL & Encryption"),
    HTTP_HEADERS("HTTP Security Headers"),
    COOKIES("Cookie Security & Session"),
    REDIRECT("HTTPS & Downgrade Defense"),
    PUBLIC_FILES("Public Metadata & Disclosure")
}

enum class CheckResultStatus(val label: String) {
    PASS("Pass"),
    FINDING("Finding Detected"),
    ERROR("Check Failed / Incomplete"),
    NOT_APPLICABLE("Not Applicable")
}

enum class AuthorizationStatus(val label: String) {
    PENDING_VERIFICATION("Pending Auditor Verification"),
    VERIFIED("Verified by Auditor"),
    EXPIRED("Authorization Window Expired"),
    REVOKED("Authorization Explicitly Revoked"),
    REJECTED("Authorization Documentation Rejected")
}

enum class EngagementStatus(val label: String) {
    DRAFT("Draft / Scoping"),
    ACTIVE("Active Engagement"),
    COMPLETED("Completed"),
    ARCHIVED("Archived")
}

enum class AuditAction(val label: String) {
    ENGAGEMENT_CREATED("Engagement Created"),
    AUTHORIZATION_SUBMITTED("Authorization Documentation Submitted"),
    AUTHORIZATION_VERIFIED("Authorization Verified by Auditor"),
    AUTHORIZATION_REVOKED("Authorization Revoked"),
    AUTHORIZATION_REJECTED("Authorization Rejected"),
    SCOPE_ADDED("Target Scope Added"),
    SCOPE_MODIFIED("Target Scope Modified"),
    SCAN_INITIATED("Defensive Assessment Initiated"),
    SCAN_COMPLETED("Defensive Assessment Completed"),
    SCAN_CANCELLED("Assessment Cancelled by User"),
    SCOPE_VIOLATION_BLOCKED("UNAUTHORIZED TARGET BLOCKED"),
    FINDING_STATUS_UPDATED("Finding Verification Status Updated"),
    REPORT_GENERATED("Security PDF Report Generated"),
    INTEGRITY_CHECK_PASSED("Audit Trail Integrity Verified"),
    INTEGRITY_CHECK_FAILED("AUDIT TRAIL TAMPERING DETECTED")
}
