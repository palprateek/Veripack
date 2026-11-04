-- Asymmetric policy control. Tightening activates immediately; loosening
-- creates a request that needs a second admin or the cooling-off window.

create table if not exists policy_change_requests (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  requested_by text not null,
  base_policy_id uuid references policy_versions(id),
  candidate_policy jsonb not null,
  diff jsonb not null default '[]'::jsonb,
  direction text not null check (direction in ('tighten', 'loosen')),
  reason text not null,
  status text not null default 'pending' check (
    status in ('pending', 'approved', 'rejected', 'expired')
  ),
  cooling_off_deadline timestamptz not null,
  second_approver text,
  decided_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists policy_change_requests_pending_idx
  on policy_change_requests (org_id, created_at)
  where status = 'pending';

create index if not exists policy_change_requests_deadline_idx
  on policy_change_requests (cooling_off_deadline)
  where status = 'pending';

-- One open request per candidate version per organization.
create unique index if not exists policy_change_requests_pending_version_idx
  on policy_change_requests (org_id, (candidate_policy ->> 'version'))
  where status = 'pending';
