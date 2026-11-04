alter table releases
  add column if not exists replay_state text not null default 'not_started',
  add column if not exists replay_started_at timestamptz;

do $$
begin
  if not exists (
    select 1
      from pg_constraint
     where conname = 'releases_replay_state_check'
  ) then
    alter table releases
      add constraint releases_replay_state_check check (
        replay_state in ('not_started', 'in_progress', 'succeeded', 'failed')
      );
  end if;
end $$;

update releases
   set replay_state = 'succeeded'
 where status in ('approved', 'overridden', 'yanked');

create table if not exists audit_outbox (
  release_id uuid primary key references releases(id) on delete cascade,
  attempts integer not null default 0,
  next_attempt_at timestamptz not null default now(),
  last_error text,
  created_at timestamptz not null default now(),
  sent_at timestamptz
);

create index if not exists audit_outbox_pending_idx
  on audit_outbox (next_attempt_at, created_at)
  where sent_at is null;

insert into audit_outbox (release_id)
select id
  from releases
 where status = 'pending'
on conflict (release_id) do nothing;

create table if not exists audit_worker_heartbeats (
  worker_id text primary key,
  process_role text not null,
  last_seen_at timestamptz not null,
  updated_at timestamptz not null default now()
);

create index if not exists audit_worker_heartbeats_seen_idx
  on audit_worker_heartbeats (last_seen_at desc);

create table if not exists active_policy_versions (
  org_id text primary key,
  policy_id uuid not null references policy_versions(id),
  activated_at timestamptz not null default now()
);

insert into active_policy_versions (org_id, policy_id)
select distinct on (org_id) org_id, id
  from policy_versions
 where coalesce((policy ->> 'active')::boolean, false) = true
 order by org_id, created_at desc
on conflict (org_id) do nothing;
