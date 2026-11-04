-- V2: package name claims and the advisory agent panel.

create table if not exists package_claims (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  package_name text not null,
  claimant text not null,
  reason text not null,
  status text not null default 'pending' check (
    status in ('pending', 'approved', 'rejected')
  ),
  decided_by text,
  decided_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists package_claims_pending_name_idx
  on package_claims (org_id, package_name)
  where status = 'pending';

create unique index if not exists package_claims_approved_name_idx
  on package_claims (org_id, package_name)
  where status = 'approved';

create index if not exists package_claims_org_idx
  on package_claims (org_id, created_at desc);

-- Advisory agent reviews. Agents never write approvals; humans decide.
create table if not exists agent_reviews (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  release_id uuid not null references releases(id) on delete cascade,
  audit_id uuid references audits(id),
  agent_id text not null,
  recommendation text not null check (
    recommendation in ('approve', 'reject', 'needs_info')
  ),
  confidence numeric(4, 3),
  rationale text not null,
  created_at timestamptz not null default now()
);

create index if not exists agent_reviews_release_idx
  on agent_reviews (release_id, created_at desc);

drop trigger if exists agent_reviews_reject_mutation on agent_reviews;
create trigger agent_reviews_reject_mutation
  before update or delete on agent_reviews
  for each row execute function reject_evidence_mutation();
