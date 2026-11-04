alter table audits
  add column if not exists policy_version text not null default 'm1-static';

create table if not exists audit_cache (
  scope_key text not null,
  tarball_digest text not null,
  engine_version text not null,
  artifact jsonb not null,
  created_at timestamptz not null default now(),
  primary key (scope_key, tarball_digest, engine_version)
);

create index if not exists audit_cache_created_idx
  on audit_cache (scope_key, created_at desc);
