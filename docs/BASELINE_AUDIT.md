# Sentinel Pro — Baseline Security & Architecture Audit Report

**Date:** 2026-10-23  
**Auditor:** Sentinel Engineering & Application Security Team  
**Scope:** Sentinel Pro Android Application, Local Database, Network Engine, Report Generators, Backend Worker, and Supabase Migrations.

---

## Executive Summary

Sentinel Pro was conceived as a defensive website security assessment platform. A comprehensive baseline audit of the existing codebase revealed critical defects across authorization verification, network scope enforcement, scan accuracy, audit trail integrity, data protection, and backend worker completeness. 

Immediate remediation is required to ensure that:
1. Authorization is genuine and verifiable before any testing is permitted.
2. Network boundaries are enforced fail-closed at socket level (preventing SSRF and DNS rebinding).
3. Scan results, findings, and scores accurately represent technical observations without false claims.
4. The audit trail uses an authentic cryptographic hash chain.
5. Android storage, backup rules, and network security policies are hardened.
6. Database migrations are safe and non-destructive.
7. Backend worker code builds and operates deterministically.

---

## Verified Baseline Vulnerabilities & Deficiencies

| ID | Category | Severity | File(s) Affected | Finding Summary |
|---|---|---|---|---|
| **VULN-01** | Authorization | **CRITICAL** | `SentinelViewModel.kt`, `Entities.kt`, `SentinelDatabase.kt` | **Fictitious / Automatic Authorization Approval**: `createEngagement()` automatically created an active `AuthorizationRecordEntity` with `explicitTestingPermitted = true`. Database pre-population seeded a fictional signed ROA. Users could run scans without verifiable written consent. |
| **VULN-02** | Scope & Network | **CRITICAL** | `ScopeValidator.kt`, `RealSecurityScanner.kt` | **DNS Rebinding & TOCTOU Scope Bypass**: `ScopeValidator` validated DNS at check time, but subsequent checks (`auditTls`, `auditHttpHeaders`, `auditHttpsRedirect`) initiated new network connections using hostname resolution. A target could resolve to a public IP initially and then switch to internal IP (SSRF). |
| **VULN-03** | Scope & Network | **HIGH** | `RealSecurityScanner.kt` | **Unrestricted Redirect Following**: `auditHttpHeadersAndCookies()` enabled `followRedirects(true)` on `OkHttpClient` without scope re-validation, allowing redirect chains to escape authorized hostnames to private/prohibited destinations. |
| **VULN-04** | Scope & Network | **HIGH** | `ScopeValidator.kt`, `Entities.kt` | **Unenforced Path Restrictions & Incomplete IP Blacklisting**: `pathPrefix` defined in `ApprovedScopeEntity` was never evaluated. IPv4-mapped IPv6, CGNAT, and link-local ranges were not comprehensively blocked. |
| **VULN-05** | Finding Accuracy | **HIGH** | `RealSecurityScanner.kt`, `DefensiveChecks.kt` | **Silent Failure Masking & Misleading Posture Grades**: Network timeouts and socket exceptions were caught and swallowed (`catch (_: Exception) {}`), leaving findings empty and incorrectly awarding an "A+" (100/100) posture grade to unreachable services. |
| **VULN-06** | Finding Accuracy | **MEDIUM** | `DefensiveChecks.kt` | **Cookie Attribute Substring False Positives**: Cookie flag detection used naive substring matching (`contains("Secure")`), falsely flagging or passing cookies whose values or names merely contained attribute substrings. |
| **VULN-07** | Finding Accuracy | **MEDIUM** | `RealSecurityScanner.kt` | **Flawed Multi-part Public Suffix Parsing**: Base domain extraction used `split(".").takeLast(2)`, failing for domains like `.co.uk`, `.com.au`, or `.ac.in`. |
| **VULN-08** | Audit Trail | **HIGH** | `SentinelRepository.kt`, `Entities.kt` | **Broken Audit Hash Integrity & Missing Chain Link**: Log timestamp in hash payload differed from persisted entity timestamp. Entries were hashed individually without previous-hash chaining, failing to provide tamper-evident history. |
| **VULN-09** | Android Security | **HIGH** | `AndroidManifest.xml`, `backup_rules.xml` | **Global Cleartext Permitted & Unrestricted Backups**: `android:usesCleartextTraffic="true"` allowed unencrypted traffic globally. Android backup rules did not explicitly exclude security assessment databases and findings. |
| **VULN-10** | Data Persistence | **HIGH** | `SentinelDatabase.kt` | **Destructive Database Fallback**: Database initialization configured `fallbackToDestructiveMigration()`, which silently drops all user tables and history upon any schema version increment. |
| **VULN-11** | Backend & Worker | **HIGH** | `backend/worker/`, `20261022000000_sentinel_schema.sql` | **Missing TypeScript Toolchain & Incomplete Worker**: `backend/worker` had no `tsconfig.json` and no executable runner or health check. Supabase RLS had potential `search_path` and self-escalation issues. |

---

## Detailed Analysis & Evidence

### 1. Authorization Flaws
In `app/src/main/java/com/example/ui/SentinelViewModel.kt`:
```kotlin
// Lines 198-209:
val auth = AuthorizationRecordEntity(
    engagementId = engagementId,
    authorizedByName = clientName.trim(),
    authorizedByRole = "Authorized Security Lead",
    authorizedByEmail = clientEmail.trim(),
    documentReference = "ROA-AUTO-${UUID.randomUUID().toString().take(6).uppercase()}",
    authorizationScopeSummary = "Authorized defensive website testing on $primaryScopeHost",
    validFromTimestamp = System.currentTimeMillis() - 60000L,
    validToTimestamp = System.currentTimeMillis() + 86400000L * 30,
    explicitTestingPermitted = true, // <-- Automatically approved without verification
    emergencyContactPhone = "+1-555-0100"
)
repository.insertAuthorization(auth)
```
*Remediation Plan:* 
- Remove auto-approval from `createEngagement()`.
- Add an explicit `AuthorizationStatus` (`PENDING_VERIFICATION`, `VERIFIED`, `EXPIRED`, `REVOKED`).
- Require an auditor verification step before `explicitTestingPermitted` can become `true`.
- Tag demo data explicitly (`isDemo = true`) and prevent demo authorizations from enabling live external scans.

### 2. Network Boundary & SSRF/Rebinding
In `app/src/main/java/com/example/engine/RealSecurityScanner.kt`:
```kotlin
// Line 344:
val client = OkHttpClient.Builder()
    .connectTimeout(7, TimeUnit.SECONDS)
    .readTimeout(7, TimeUnit.SECONDS)
    .followRedirects(true) // <-- Unchecked redirect following
    .build()
```
*Remediation Plan:*
- Introduce a centralized `PinnedDns` resolver that validates IPs against the strict blacklists on every lookup and locks connections to the validated IP.
- Enforce custom OkHttp interceptor that validates every HTTP 3xx redirect destination against authorized scope before following.
- Expand IP blocklists to cover IPv4-mapped IPv6, CGNAT, 0.0.0.0/8, documentation nets, loopback, and cloud metadata.

### 3. Finding Accuracy & Cookie Parsing
In `app/src/main/java/com/example/engine/DefensiveChecks.kt`:
```kotlin
val hasSecure = cookie.contains("Secure", ignoreCase = true)
```
*Remediation Plan:*
- Parse `Set-Cookie` directives by splitting on `;` and trimming attributes. Check `Secure` and `HttpOnly` only as standalone attribute names, and `SameSite` as key-value pairs.
- Handle exceptions properly in `RealSecurityScanner.kt`: if network requests fail, mark checks as `ScanCheckStatus.FAILED` or `ERROR`, deduct points or mark the assessment as `INCOMPLETE`, and never present an empty findings list as an "A+" grade.
- Replace naive base-domain extraction with an RFC-compliant public suffix lookup table or robust multi-part TLD parsing.

### 4. Audit Trail Integrity
In `app/src/main/java/com/example/data/repository/SentinelRepository.kt`:
```kotlin
val payload = "${System.currentTimeMillis()}|$actor|${action.name}|$target|$details"
val hash = sha256(payload)
dao.insertAuditLog(
    AuditLogEntity(
        timestamp = System.currentTimeMillis(), // <-- DIFFERENT timestamp than payload!
        actor = actor,
        ...
```
*Remediation Plan:*
- Implement canonical serialization using the exact persisted timestamp, actor, action, target, details, and the `previousHash` from the immediately preceding audit record.
- Add an `AuditIntegrityVerifier` to validate the blockchain-like audit trail.

### 5. Android Manifest & Data Protection
- Remove `android:usesCleartextTraffic="true"` from `AndroidManifest.xml`.
- Provide an `exclude` rule in `res/xml/backup_rules.xml` and `res/xml/data_extraction_rules.xml` for `sentinel_security_db`.
- Remove `fallbackToDestructiveMigration()` in `SentinelDatabase.kt` and write explicit migrations.

### 6. Supabase & Backend Worker
- Create `backend/worker/tsconfig.json`.
- Implement a worker server entry point with health check and job processor.
- Secure Supabase PostgreSQL functions with `SET search_path = public` and prevent self-role elevation.

---

## Verification Strategy

1. Automated unit tests for ScopeValidator (wildcard edge cases, private IPs, ports, paths, schemes).
2. Automated unit tests for DefensiveChecks (cookies, headers, DNS, TLS).
3. Automated unit tests for AuditTrail hash chain verification.
4. Robolectric tests for Room migrations and UI state transitions.
5. Compilation and execution of `gradle :app:testDebugUnitTest`.
6. TypeScript compilation (`tsc`) and execution of backend worker tests.
