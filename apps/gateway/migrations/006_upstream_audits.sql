create table if not exists upstream_audits (
  tarball_digest text not null,
  package_name text not null,
  version text not null,
  engine_version text not null,
  policy_version text not null,
  status text not null check (status in ('audited', 'blocked')),
  safety_verdict text not null,
  intent_verdict text not null,
  risk_tier text not null,
  policy_result text not null,
  signals jsonb not null default '[]'::jsonb,
  change_set jsonb not null default '{}'::jsonb,
  summary text not null,
  created_at timestamptz not null default now(),
  primary key (tarball_digest, engine_version, policy_version)
);

create index if not exists upstream_audits_package_idx
  on upstream_audits (package_name, version, created_at desc);
