-- Migration: Add detection_rules table
-- Date: 2026-04-04
-- Description: Persistent storage for AI-generated detection rules (Sigma, SPL, KQL)

CREATE TABLE IF NOT EXISTS detection_rules (
    id SERIAL PRIMARY KEY,
    technique_id VARCHAR(50) NOT NULL,
    sigma_rule JSONB NOT NULL,
    spl_query TEXT NOT NULL,
    kql_query TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    confidence INTEGER NOT NULL DEFAULT 70,
    rule_hash VARCHAR(64) NOT NULL UNIQUE,
    source VARCHAR(100) DEFAULT 'auto-generated',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexing for performance
CREATE INDEX IF NOT EXISTS idx_detection_rules_technique ON detection_rules(technique_id);
CREATE INDEX IF NOT EXISTS idx_detection_rules_hash ON detection_rules(rule_hash);
CREATE INDEX IF NOT EXISTS idx_detection_rules_created_at ON detection_rules(created_at);

-- Unique constraint for idempotency
ALTER TABLE detection_rules ADD CONSTRAINT uq_rule_hash UNIQUE (rule_hash);
