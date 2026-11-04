create table if not exists policy_versions (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  version text not null,
  policy jsonb not null,
  created_by text not null,
  created_at timestamptz not null default now(),
  constraint policy_versions_org_version_key unique (org_id, version)
);

create index if not exists policy_versions_org_created_idx
  on policy_versions (org_id, created_at desc);

create unique index if not exists policy_versions_one_active_idx
  on policy_versions (org_id)
  where (policy ->> 'active') = 'true';

create table if not exists rate_limit_buckets (
  bucket_key text primary key,
  window_start bigint not null,
  request_count integer not null,
  updated_at timestamptz not null default now()
);

create index if not exists rate_limit_buckets_updated_idx
  on rate_limit_buckets (updated_at);
