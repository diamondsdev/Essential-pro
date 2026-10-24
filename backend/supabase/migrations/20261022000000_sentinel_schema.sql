-- ====================================================================
-- Sentinel Pro: Defensive Security Assessment Platform Database Schema
-- Supabase / PostgreSQL with Row-Level Security (RLS) & Audit Policies
-- ====================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Organizations & Assessor Profiles
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('lead_assessor', 'peer_reviewer', 'client_auditor', 'admin')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Clients
CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    organization TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Engagements
CREATE TABLE IF NOT EXISTS engagements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    engagement_type TEXT NOT NULL DEFAULT 'Defensive Web Security Assessment',
    lead_assessor TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('DRAFT', 'ACTIVE', 'COMPLETED', 'ARCHIVED')) DEFAULT 'ACTIVE',
    target_environment TEXT NOT NULL DEFAULT 'Production (Passive / Non-Destructive)',
    start_date TIMESTAMPTZ NOT NULL,
    end_date TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Written Rules of Engagement (ROA) Authorization Records
CREATE TABLE IF NOT EXISTS authorizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    engagement_id UUID REFERENCES engagements(id) ON DELETE CASCADE,
    authorized_by_name TEXT NOT NULL,
    authorized_by_role TEXT NOT NULL,
    authorized_by_email TEXT NOT NULL,
    document_reference TEXT NOT NULL,
    authorization_scope_summary TEXT NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_to TIMESTAMPTZ NOT NULL,
    explicit_testing_permitted BOOLEAN NOT NULL DEFAULT true,
    emergency_contact_phone TEXT NOT NULL,
    signed_at TIMESTAMPTZ DEFAULT NOW(),
    rules_notes TEXT DEFAULT 'Strictly non-destructive defensive checks only.'
);

-- 5. Approved Scope Hostnames (Strict Boundaries)
CREATE TABLE IF NOT EXISTS approved_scopes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    engagement_id UUID REFERENCES engagements(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    wildcard_allowed BOOLEAN NOT NULL DEFAULT false,
    allowed_ports TEXT NOT NULL DEFAULT '80,443',
    path_prefix TEXT NOT NULL DEFAULT '/',
    active BOOLEAN NOT NULL DEFAULT true,
    added_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. Assessment Jobs
CREATE TABLE IF NOT EXISTS assessment_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    engagement_id UUID REFERENCES engagements(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    resolved_host TEXT NOT NULL,
    resolved_ips TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    triggered_by TEXT NOT NULL,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    total_findings_count INT DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    info_count INT DEFAULT 0,
    posture_score INT DEFAULT 100,
    posture_grade TEXT DEFAULT 'A',
    summary_notes TEXT DEFAULT '',
    error_message TEXT
);

-- 7. Verified Security Findings & Evidence
CREATE TABLE IF NOT EXISTS security_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID REFERENCES assessment_jobs(id) ON DELETE CASCADE,
    engagement_id UUID REFERENCES engagements(id) ON DELETE CASCADE,
    category TEXT NOT NULL CHECK (category IN ('DNS', 'TLS', 'HTTP_HEADERS', 'COOKIES', 'REDIRECT', 'PUBLIC_FILES')),
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')),
    confidence TEXT NOT NULL DEFAULT 'CONFIRMED',
    status TEXT NOT NULL CHECK (status IN ('VERIFIED', 'MITIGATED', 'FALSE_POSITIVE', 'ACCEPTED_RISK')) DEFAULT 'VERIFIED',
    cwe_id TEXT NOT NULL,
    owasp_category TEXT NOT NULL,
    summary TEXT NOT NULL,
    technical_evidence TEXT NOT NULL,
    impact TEXT NOT NULL,
    remediation_guidance TEXT NOT NULL,
    verification_curl TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 8. Immutable Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL,
    hash_signature TEXT NOT NULL
);

-- ====================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ====================================================================

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE engagements ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE approved_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE assessment_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Helper function to get current user's organization
CREATE OR REPLACE FUNCTION get_user_org_id()
RETURNS UUID AS $$
  SELECT org_id FROM user_profiles WHERE id = auth.uid() LIMIT 1;
$$ LANGUAGE sql STABLE SECURITY DEFINER;

-- 1. Engagements Policy (Organization Isolation)
CREATE POLICY "Engagements are viewable by org members" ON engagements
    FOR SELECT USING (org_id = get_user_org_id());

CREATE POLICY "Engagements can be created by lead assessors" ON engagements
    FOR INSERT WITH CHECK (
        org_id = get_user_org_id() AND
        EXISTS (SELECT 1 FROM user_profiles WHERE id = auth.uid() AND role IN ('lead_assessor', 'admin'))
    );

-- 2. Authorizations Policy
CREATE POLICY "Authorizations are viewable by org members" ON authorizations
    FOR SELECT USING (
        EXISTS (SELECT 1 FROM engagements WHERE id = authorizations.engagement_id AND org_id = get_user_org_id())
    );

CREATE POLICY "Authorizations insertable by lead assessors" ON authorizations
    FOR INSERT WITH CHECK (
        EXISTS (SELECT 1 FROM user_profiles WHERE id = auth.uid() AND role IN ('lead_assessor', 'admin'))
    );

-- 3. Scopes Policy
CREATE POLICY "Scopes viewable by org members" ON approved_scopes
    FOR SELECT USING (
        EXISTS (SELECT 1 FROM engagements WHERE id = approved_scopes.engagement_id AND org_id = get_user_org_id())
    );

CREATE POLICY "Scopes manageable by lead assessors" ON approved_scopes
    FOR ALL USING (
        EXISTS (SELECT 1 FROM user_profiles WHERE id = auth.uid() AND role IN ('lead_assessor', 'admin'))
    );

-- 4. Jobs & Findings Policy
CREATE POLICY "Assessment jobs viewable by org members" ON assessment_jobs
    FOR SELECT USING (
        EXISTS (SELECT 1 FROM engagements WHERE id = assessment_jobs.engagement_id AND org_id = get_user_org_id())
    );

CREATE POLICY "Security findings viewable by org members" ON security_findings
    FOR SELECT USING (
        EXISTS (SELECT 1 FROM engagements WHERE id = security_findings.engagement_id AND org_id = get_user_org_id())
    );

-- 5. Audit Log Immutability Policy (Insert allowed, No Update, No Delete)
CREATE POLICY "Audit logs viewable by org members" ON audit_logs
    FOR SELECT USING (org_id = get_user_org_id());

CREATE POLICY "Audit logs can be appended" ON audit_logs
    FOR INSERT WITH CHECK (org_id = get_user_org_id());

-- Disallow updates or deletes to maintain tamper evidence
CREATE POLICY "Audit logs cannot be updated" ON audit_logs FOR UPDATE USING (false);
CREATE POLICY "Audit logs cannot be deleted" ON audit_logs FOR DELETE USING (false);
