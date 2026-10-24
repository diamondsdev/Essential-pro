# Sentinel Pro — Defensive Security Assessment Platform Setup Guide

## Overview
Sentinel Pro is an application-security assessment platform tailored for defensive security consultancies and enterprise security operations teams. It conducts real, non-destructive, passive and configuration audits against explicitly authorized target assets and generates accurate, evidence-backed security reports.

---

## 1. Safety & Rules of Engagement (ROA) Enforcement
Sentinel Pro strictly enforces defensive security boundaries before initiating any network connections:
1. **Written Authorization Required:** Testing is completely blocked unless an active, unexpired Rules of Engagement (ROA) record is on file with `explicitTestingPermitted = true`.
2. **Strict Host Scope Boundary:** Target URLs are checked against the pre-approved scope registry (`ApprovedScopeEntity`). Any destination outside approved boundaries is rejected with an immutable audit log violation (`SCOPE_VIOLATION_BLOCKED`).
3. **SSRF & Loopback Prevention:** Scans targeting `localhost`, `127.0.0.1`, `::1`, link-local (`169.254.169.254`), or private RFC 1918 subnets are intercepted and prevented.
4. **Non-Destructive Defensive Checks:** Only passive protocol inspections, DNS-over-HTTPS queries, TLS certificate handshakes, HTTP security headers, and cookie flags are evaluated. Denial-of-service, brute force, and credential stuffing are excluded by design.

---

## 2. Using the Android Application

### Step 1: Manage Scope & ROA
1. Navigate to the **Scope & ROA** tab.
2. Review the active client engagement and the written authorization card.
3. Tap **Add Target** to register authorized hostnames (e.g., `scanme.nmap.org`, `example.com`).
4. Tap the **Edit** icon on the ROA card to update the authorizing officer (CISO/SecOps Lead), document reference (e.g., `SOW-2026-ROA.pdf`), and validity dates.

### Step 2: Run a Defensive Assessment
1. Navigate to the **Assessment** tab.
2. Choose an in-scope hostname using the quick-select chips or type a target URL.
3. Verify that the **Scope Enforcement** badge displays `AUTHORIZED & IN-SCOPE`.
4. Tap **Execute Audit**.
5. Observe the live multi-phase assessment:
   - Phase 1: Written ROA & Scope Enforcement
   - Phase 2: DNS Resolution, SPF (`v=spf1`), and DMARC (`_dmarc`) queries
   - Phase 3: TLS handshake, Cipher Suite, and X.509 Certificate validity
   - Phase 4: HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Server disclosure)
   - Phase 5: Cookie attributes (`Secure`, `HttpOnly`, `SameSite`)
   - Phase 6: Plain HTTP port 80 to HTTPS redirection check
   - Phase 7: RFC 9116 `security.txt` and `robots.txt` disclosure check

### Step 3: Inspect Verified Findings
1. Navigate to the **Findings** tab.
2. Filter findings by severity (Critical, High, Medium, Low, Informational).
3. Tap any finding to expand the **Captured Technical Evidence**, **Security Impact**, and **Remediation Guidance**.
4. Use the **Copy** button to copy the reproduction `curl` command.
5. Update verification status (Verified, Mitigated, False Positive, Risk Accepted) as remediation progresses.

### Step 4: Export Evidence-Backed PDF Reports & Audit Logs
1. Navigate to the **Reports & Audit** tab.
2. Tap **Export PDF** to generate an executive-ready multi-page PDF security report. The report is compiled on-device with posture scores, breakdown metrics, and verified findings.
3. Tap **Copy Markdown** for instant integration into Slack, Jira, or client portals.
4. Review the tamper-evident **Security Audit Trail** with SHA-256 integrity signatures for regulatory compliance.

---

## 3. Supabase & Backend Worker Deployment

### Database Setup (Supabase / PostgreSQL)
1. In your Supabase project dashboard, navigate to the **SQL Editor**.
2. Open `backend/supabase/migrations/20261022000000_sentinel_schema.sql`.
3. Run the migration to provision:
   - Tables (`clients`, `engagements`, `authorizations`, `approved_scopes`, `assessment_jobs`, `security_findings`, `audit_logs`).
   - Row-Level Security (RLS) policies enforcing organization multi-tenancy and immutable audit trails.

### Backend Worker Setup
For executing deeper asynchronous or scheduled perimeter scans:
```bash
cd backend/worker
npm install
npm run build
npm start
```
Configure environment variables in `.env` based on `.env.example`:
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `WORKER_CONCURRENCY_LIMIT`

---

## 4. Test Scenarios Included
The application is pre-seeded with test assets:
- `scanme.nmap.org`: Standard authorized public security test target.
- `example.com`: RFC 2606 reserved documentation domain.
- Attempting to audit unauthorized targets (e.g. `google.com` or `internal-bank.com` without adding them to authorized scope) will trigger the active scope enforcement gate, immediately aborting execution and recording a security audit violation.
