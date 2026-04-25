-- Migration 001: Assessment persistence tables (AIDA-inspired)
-- Apply: psql -h localhost -p 5433 -U shadowhunter -d terminator -f tools/migrations/001_assessment_tables.sql

CREATE TABLE IF NOT EXISTS assessments (
    id SERIAL PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    pipeline VARCHAR(50) NOT NULL,
    session_id VARCHAR(100),
    status VARCHAR(30) DEFAULT 'active',
    phase VARCHAR(30) DEFAULT 'recon',
    template VARCHAR(50),
    scope_contract JSONB,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_assessments_target ON assessments(target);
CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);

CREATE TABLE IF NOT EXISTS assessment_sections (
    id SERIAL PRIMARY KEY,
    assessment_id INTEGER REFERENCES assessments(id) ON DELETE CASCADE,
    section_type VARCHAR(50) NOT NULL,
    title VARCHAR(200),
    content TEXT,
    agent_role VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sections_assessment ON assessment_sections(assessment_id);

CREATE TABLE IF NOT EXISTS command_log (
    id SERIAL PRIMARY KEY,
    assessment_id INTEGER REFERENCES assessments(id) ON DELETE CASCADE,
    agent_role VARCHAR(50),
    command TEXT NOT NULL,
    command_type VARCHAR(30),
    source_code TEXT,
    stdout TEXT,
    stderr TEXT,
    exit_code INTEGER,
    duration_ms INTEGER,
    approval_mode VARCHAR(20) DEFAULT 'open',
    approval_status VARCHAR(20) DEFAULT 'auto_approved',
    phase VARCHAR(30),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cmdlog_assessment ON command_log(assessment_id);
CREATE INDEX IF NOT EXISTS idx_cmdlog_approval ON command_log(approval_status);

CREATE TABLE IF NOT EXISTS timeline_events (
    id SERIAL PRIMARY KEY,
    assessment_id INTEGER REFERENCES assessments(id) ON DELETE CASCADE,
    phase VARCHAR(30) NOT NULL,
    event_type VARCHAR(30),
    severity VARCHAR(20),
    title VARCHAR(200),
    details TEXT,
    agent_role VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_timeline_assessment ON timeline_events(assessment_id);

CREATE TABLE IF NOT EXISTS assessment_credentials (
    id SERIAL PRIMARY KEY,
    assessment_id INTEGER REFERENCES assessments(id) ON DELETE CASCADE,
    cred_type VARCHAR(30),
    name VARCHAR(100),
    placeholder VARCHAR(100),
    value TEXT,
    service VARCHAR(100),
    target VARCHAR(255),
    discovered_by VARCHAR(50) DEFAULT 'manual',
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_creds_assessment ON assessment_credentials(assessment_id);
CREATE INDEX IF NOT EXISTS idx_creds_placeholder ON assessment_credentials(placeholder);

-- Extend findings with assessment linkage + CVSS 4.0
ALTER TABLE findings ADD COLUMN IF NOT EXISTS assessment_id INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_vector VARCHAR(200);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack_phase VARCHAR(30);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cwe_id VARCHAR(20);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_tier VARCHAR(5);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS proof TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS commands_used INTEGER[];
