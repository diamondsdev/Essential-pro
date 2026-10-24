# Sentinel Pro Security Architecture & Threat Model

## 1. Executive Summary & Principles

Sentinel Pro is an Android-based defensive security assessment platform designed for cybersecurity consultancies and authorized enterprise SecOps teams. The tool is strictly defensive: it audits observable configurations (DNS, TLS/SSL certificates, HTTP security response headers, cookie flags, robots.txt, security.txt) against assets for which the assessor has verified written authorization.

The system is engineered around four core security guarantees:
1. **Never Test Without Verifiable Authorization:** No active packet is sent without a signed, unexpired, unrevoked Rules of Engagement (ROA) record verified by a named assessor.
2. **Fail-Closed Network Boundary:** Requests to unauthorized hostnames, unapproved ports, prohibited paths, internal/loopback IP addresses, or cloud metadata services are blocked before socket allocation.
3. **DNS Rebinding (TOCTOU) Elimination:** Network connections pin the exact IP addresses validated during pre-flight checks (`PinnedDns`).
4. **Cryptographic Tamper-Evident Audit Trail:** Every action, check, and scope violation is recorded into a SHA-256 hash-chained log.

---

## 2. Threat Model

| Threat Agent | Vector / Objective | Sentinel Pro Defensive Mitigation |
|---|---|---|
| **Malicious Assessor / Rogue User** | Attempting to scan unauthorized third-party infrastructure (e.g. competitor, government). | `ScopeValidator` fails closed; requires engagement-specific approved hostnames and active ROA. |
| **Server-Side Request Forgery (SSRF)** | Specifying localhost (`127.0.0.1`), LAN subnets (`192.168.x.x`), or cloud metadata (`169.254.169.254`). | Multi-layer IP blocking: rejects loopback, RFC 1918, CGNAT, link-local, documentation blocks, IPv4-mapped IPv6, and cloud metadata IPs. |
| **DNS Rebinding (TOCTOU)** | Attacker-controlled DNS server returns an authorized public IP on validation, then returns `127.0.0.1` upon HTTP connection. | `PinnedDns` OkHttp resolver pins socket connection exclusively to validated pre-flight IP addresses. |
| **Redirect Hijacking** | Target server returns HTTP 301/302 redirecting assessor to internal microservices or unauthorized domains. | Custom `Interceptor` re-validates redirect URL and port against active scopes and IP blocklists prior to following. |
| **Audit Log Tampering** | Assessor or attacker alters SQLite database records to conceal unauthorized testing. | Blockchain-style SHA-256 hash chaining: every block signs `previousHash + payload`. `verifyAuditChain()` detects any modification or deletion. |
| **Unencrypted Cloud Backup Leakage** | Android OS uploads database containing findings and client records to unencrypted Google Drive backup. | `backup_rules.xml` and `data_extraction_rules.xml` explicitly exclude `sentinel_security_db`. |
| **Supabase Privilege Escalation** | Multi-tenant organization user attempts to alter their own role to `admin` or access foreign tenant records. | Hardened RLS policies with `SECURITY DEFINER SET search_path = public` and update restrictions on `user_profiles.role`. |

---

## 3. Authorization & Rules of Engagement (ROA) Lifecycle

```
[Create Engagement]
         │
         ▼
[DRAFT / UNVERIFIED] ──(Explicit Testing Permitted = false)
         │
         │  Assessor attaches signed ROA document reference & SHA-256 hash
         ▼
[PENDING_VERIFICATION]
         │
         │  Named Lead Auditor validates document & signs off in UI
         ▼
[VERIFIED] ────────────(Explicit Testing Permitted = true)
    │        │
    │        └── Assessor / Client demands halt
    ▼                     │
[EXPIRED]                 ▼
 (Window elapsed)     [REVOKED] ──(Explicit Testing Permitted = false)
```

- **Demo Isolation:** Sample/fixture engagements are tagged with `isDemo = true`. In demo mode, `explicitTestingPermitted` remains `false` and prominent UI banners warn assessors that live testing is disabled until an authentic engagement is configured.

---

## 4. Network Enforcement Architecture

### 4.1 Address Validation Pipeline
1. **URI & Protocol Check:** Accepts only `http://` or `https://`.
2. **IDN Normalization:** Punycode-normalizes internationalized domain names (e.g., `xn--...`).
3. **Approved Scope Matching:**
   - Exact hostname match, or
   - Suffix match if `wildcardAllowed = true` (e.g. `*.example.com`).
   - Port validation (defaulting to 80 and 443).
   - Path prefix validation (defaulting to `/`).
4. **IP Resolution & SSRF Filtering:**
   Resolves all DNS `A` and `AAAA` records and verifies that *none* fall within:
   - Loopback (`127.0.0.0/8`, `::1`)
   - Private RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - Link-local (`169.254.0.0/16`, `fe80::/10`)
   - Carrier-Grade NAT / CGNAT (`100.64.0.0/10`)
   - Documentation & Benchmark (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15`)
   - IPv4-mapped IPv6 (`::ffff:0:0/96`)
   - IPv6 Unique Local (`fc00::/7`)
   - Cloud Metadata (`169.254.169.254`, `metadata.google.internal`)

### 4.2 Pinned DNS Engine
OkHttp is configured with a dynamic `PinnedDns` instance:
```kotlin
class PinnedDns(private val pinnedIps: List<InetAddress>) : Dns {
    override fun lookup(hostname: String): List<InetAddress> = pinnedIps
}
```
This guarantees that the exact IP address validated during scope checks is used for the TCP handshake, thwarting DNS rebinding attacks.

---

## 5. Audit Trail & Cryptographic Verification

Audit log entries follow strict sequential hash linking:
- **Genesis Block:** `previousHash = "0000000000000000000000000000000000000000000000000000000000000000"`
- **Subsequent Blocks:** `hashSignature = SHA256(previousHash + ":" + timestamp + ":" + actor + ":" + action + ":" + target + ":" + details)`
- **Chain Verification:** `SentinelRepository.verifyAuditChain()` walks all audit entries sequentially, recomputing each block's expected hash and verifying link continuity.
