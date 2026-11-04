-- Durable replay jobs. Approval commits the decision and enqueues a job in one
-- transaction; a worker claims jobs with a lease and takes over expired ones,
-- so no release can remain wedged in an in-progress replay.

create table if not exists replay_jobs (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  release_id uuid not null references releases(id) on delete cascade,
  state text not null default 'queued' check (
    state in ('queued', 'running', 'succeeded', 'failed')
  ),
  attempts integer not null default 0,
  lease_owner text,
  lease_expires_at timestamptz,
  available_at timestamptz not null default now(),
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- At most one active job per release.
create unique index if not exists replay_jobs_active_release_idx
  on replay_jobs (release_id)
  where state in ('queued', 'running');

create index if not exists replay_jobs_claim_idx
  on replay_jobs (available_at, created_at)
  where state = 'queued';

create index if not exists replay_jobs_expired_lease_idx
  on replay_jobs (lease_expires_at)
  where state = 'running';

create index if not exists replay_jobs_failed_idx
  on replay_jobs (updated_at desc)
  where state = 'failed';

alter table releases
  add column if not exists replay_job_id uuid;

do $$
begin
  if not exists (
    select 1
      from pg_constraint
     where conname = 'releases_replay_job_id_fkey'
       and conrelid = 'releases'::regclass
  ) then
    alter table releases
      add constraint releases_replay_job_id_fkey
      foreign key (replay_job_id) references replay_jobs(id)
      on delete set null not valid;
  end if;
end $$;

alter table releases validate constraint releases_replay_job_id_fkey;

-- Recover releases wedged by the pre-P3 synchronous replay: queue a durable
-- job for each one and reset the compatibility projection.
insert into replay_jobs (org_id, release_id, state, last_error)
select org_id, id, 'queued', 'Recovered from a pre-P3 in-progress replay.'
  from releases
 where status in ('approved', 'overridden')
   and replay_state = 'in_progress'
on conflict (release_id) where state in ('queued', 'running') do nothing;

update releases r
   set replay_job_id = j.id,
       replay_state = 'not_started',
       replay_started_at = null,
       updated_at = now()
  from replay_jobs j
 where j.release_id = r.id
   and j.state = 'queued'
   and r.replay_state = 'in_progress';
