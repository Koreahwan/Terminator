-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Exploit knowledge vectors
CREATE TABLE IF NOT EXISTS exploit_vectors (
    id SERIAL PRIMARY KEY,
    category VARCHAR(100),
    technique VARCHAR(200),
    description TEXT,
    content TEXT,
    source_url TEXT,
    embedding vector(768),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Failure memory for learning
CREATE TABLE IF NOT EXISTS failure_memory (
    id SERIAL PRIMARY KEY,
    technique VARCHAR(255),
    error_description TEXT,
    solution TEXT,
    embedding vector(768),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes using HNSW (works on empty tables, unlike ivfflat)
CREATE INDEX IF NOT EXISTS idx_exploit_embedding ON exploit_vectors USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS idx_failure_embedding ON failure_memory USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS idx_exploit_category ON exploit_vectors (category);

-- ──────────────────────────────────────────────
-- Session-persistent tables (Sprint 2026-02-17)
-- ──────────────────────────────────────────────

-- Bug bounty / CTF finding tracking across sessions
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    title VARCHAR(500) NOT NULL,
    severity VARCHAR(20),
    status VARCHAR(50) DEFAULT 'ACTIVE',
    poc_tier INTEGER,
    cvss_score DECIMAL(3,1),
    description TEXT,
    poc_summary TEXT,
    platform VARCHAR(50),
    submitted_at TIMESTAMP,
    triager_outcome VARCHAR(50),
    bounty_amount DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- Binary analysis cache (avoid re-analysis of identical binaries)
CREATE TABLE IF NOT EXISTS binary_cache (
    id SERIAL PRIMARY KEY,
    md5 VARCHAR(32) UNIQUE NOT NULL,
    sha256 VARCHAR(64),
    filename VARCHAR(255),
    arch VARCHAR(50),
    bits INTEGER,
    protections JSONB,
    imports TEXT[],
    interesting_strings TEXT[],
    analysis_summary TEXT,
    embedding vector(768),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_binary_md5 ON binary_cache(md5);
CREATE INDEX IF NOT EXISTS idx_binary_embedding ON binary_cache USING hnsw (embedding vector_cosine_ops);

-- Agent execution history for monitoring and cost tracking
CREATE TABLE IF NOT EXISTS agent_runs (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(100),
    agent_role VARCHAR(50),
    target VARCHAR(255),
    model VARCHAR(50),
    status VARCHAR(20) DEFAULT 'RUNNING',
    duration_seconds INTEGER,
    tokens_used INTEGER,
    output_summary TEXT,
    artifacts TEXT[],
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_agent_runs_session ON agent_runs(session_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_target ON agent_runs(target);
CREATE INDEX IF NOT EXISTS idx_agent_runs_status ON agent_runs(status);
