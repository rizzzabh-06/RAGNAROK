-- Supabase Schema for AI Triage System
-- Run this in Supabase SQL Editor

-- Alerts table
create table if not exists alerts (
  id uuid primary key default gen_random_uuid(),
  rule_id text,
  description text,
  severity int,
  agent_name text,
  srcip text,
  cmd text,
  mitre_techniques text[],
  dedup_key text unique,
  timestamp timestamptz default now(),
  full_log text,
  recent_similar_count int default 0,
  ti_hit boolean default false,
  created_at timestamptz default now()
);

-- Scores table
create table if not exists scores (
  id uuid primary key default gen_random_uuid(),
  alert_id uuid references alerts(id),
  score numeric not null,
  dedup_key text,
  recommended_playbook text,
  reasons jsonb,
  timestamp timestamptz,
  created_at timestamptz default now()
);

-- Audit logs table
create table if not exists audit_logs (
  id uuid primary key default gen_random_uuid(),
  dedup_key text,
  score numeric,
  reasons jsonb,
  suggested_playbook text,
  mitre_techniques text[],
  ts bigint,
  raw jsonb,
  explanation jsonb,
  created_at timestamptz default now()
);

-- Indexes for performance
create index if not exists idx_alerts_dedup_key on alerts(dedup_key);
create index if not exists idx_scores_dedup_key on scores(dedup_key);
create index if not exists idx_audit_dedup_key on audit_logs(dedup_key);
create index if not exists idx_alerts_timestamp on alerts(timestamp);
create index if not exists idx_scores_score on scores(score);

-- Row Level Security (optional)
-- alter table alerts enable row level security;
-- alter table scores enable row level security;
-- alter table audit_logs enable row level security;