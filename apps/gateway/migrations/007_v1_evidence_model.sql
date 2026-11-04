-- V1 evidence model: multiple immutable audits, a current-audit pointer, and
-- approvals bound to the audit that produced them.
--
-- This migration is additive. It never rewrites audit or event evidence. If
-- pre-V1 rows use reviewer_type = 'agent', it fails and asks an operator to
-- resolve them; it does not silently turn agent evidence into human evidence.

-- Multiple audits per release. The pre-V1 constraint allowed exactly one.
alter table audits drop constraint if exists audits_release_key;

do $$
begin
  if not exists (
    select 1
      from pg_constraint
     where conname = 'audits_release_version_key'
       and conrelid = 'audits'::regclass
  ) then
    alter table audits
      add constraint audits_release_version_key
      unique (release_id, engine_version, policy_version);
  end if;
end $$;

create index if not exists audits_release_created_idx
  on audits (release_id, created_at desc);

-- The pointer is the only mutable row in the evidence model: it names the
-- audit that current decisions must reference.
create table if not exists release_current_audits (
  release_id uuid primary key,
  audit_id uuid not null,
  updated_at timestamptz not null default now()
);

-- Backfill the latest existing audit per release, then validate the foreign
-- keys so an existing database can be migrated without a long lock.
insert into release_current_audits (release_id, audit_id)
select distinct on (release_id) release_id, id
  from audits
 order by release_id, created_at desc, id desc
on conflict (release_id) do nothing;

do $$
begin
  if not exists (
    select 1
      from pg_constraint
     where conname = 'release_current_audits_release_id_fkey'
       and conrelid = 'release_current_audits'::regclass
  ) then
    alter table release_current_audits
      add constraint release_current_audits_release_id_fkey
      foreign key (release_id) references releases(id) not valid;
  end if;
  if not exists (
    select 1
      from pg_constraint
     where conname = 'release_current_audits_audit_id_fkey'
       and conrelid = 'release_current_audits'::regclass
  ) then
    alter table release_current_audits
      add constraint release_current_audits_audit_id_fkey
      foreign key (audit_id) references audits(id) not valid;
  end if;
  if not exists (
    select 1
      from pg_constraint
     where conname = 'release_current_audits_audit_id_key'
       and conrelid = 'release_current_audits'::regclass
  ) then
    alter table release_current_audits
      add constraint release_current_audits_audit_id_key unique (audit_id);
  end if;
end $$;

alter table release_current_audits
  validate constraint release_current_audits_release_id_fkey;
alter table release_current_audits
  validate constraint release_current_audits_audit_id_fkey;

-- Bind approvals to an audit and record the reviewer's role next to the
-- reviewer type.
alter table approvals
  add column if not exists audit_id uuid,
  add column if not exists reviewer_role text;

update approvals a
   set audit_id = c.audit_id,
       policy_version = au.policy_version
  from release_current_audits c
  join audits au on au.id = c.audit_id
 where a.release_id = c.release_id
   and a.audit_id is null;

-- Fail rather than rewriting agent evidence. An operator must decide whether
-- those rows are reclassified or archived before P1 can exit.
do $$
begin
  if exists (select 1 from approvals where reviewer_type = 'agent') then
    raise exception using
      errcode = 'check_violation',
      message = 'Migration 007 cannot continue: approvals contains reviewer_type = ''agent'' rows.',
      detail = 'V1 permits only human and system reviewers. Resolve the agent rows manually and rerun the migration; evidence is not rewritten automatically.',
      hint = 'Inspect approvals where reviewer_type = ''agent'' and reclassify them as human or system.';
  end if;
end $$;

alter table approvals drop constraint if exists approvals_reviewer_type_check;
alter table approvals
  add constraint approvals_reviewer_type_check
  check (reviewer_type in ('human', 'system')) not valid;
alter table approvals validate constraint approvals_reviewer_type_check;

do $$
begin
  if not exists (
    select 1
      from pg_constraint
     where conname = 'approvals_audit_id_fkey'
       and conrelid = 'approvals'::regclass
  ) then
    alter table approvals
      add constraint approvals_audit_id_fkey
      foreign key (audit_id) references audits(id) not valid;
  end if;
  if not exists (
    select 1
      from pg_constraint
     where conname = 'approvals_audit_link_check'
       and conrelid = 'approvals'::regclass
  ) then
    alter table approvals
      add constraint approvals_audit_link_check
      check (
        decision not in ('approved', 'overridden')
        or (audit_id is not null and policy_version is not null)
      ) not valid;
  end if;
end $$;

alter table approvals validate constraint approvals_audit_id_fkey;
alter table approvals validate constraint approvals_audit_link_check;

create index if not exists approvals_audit_idx
  on approvals (audit_id, created_at);

-- Approvals must name the audit they were decided against. Approval and
-- override decisions must reference the audit that is current at insert time;
-- the other decisions carry the current audit when one exists, and may be null
-- only when the release has no audit at all.
create or replace function validate_approval_evidence()
returns trigger
language plpgsql
as $$
declare
  current_audit uuid;
  audit_release uuid;
begin
  select c.audit_id
    into current_audit
    from release_current_audits c
   where c.release_id = new.release_id;

  if new.audit_id is null then
    if new.decision in ('approved', 'overridden') then
      raise exception using
        errcode = 'not_null_violation',
        message = format(
          'Approval decision %s for release %s requires an audit id',
          new.decision,
          new.release_id
        );
    end if;
    if current_audit is not null then
      raise exception using
        errcode = 'check_violation',
        message = format(
          'Approval decision %s for release %s must reference the current audit %s',
          new.decision,
          new.release_id,
          current_audit
        );
    end if;
    return new;
  end if;

  select a.release_id into audit_release from audits a where a.id = new.audit_id;
  if audit_release is null then
    raise exception using
      errcode = 'foreign_key_violation',
      message = format('Approval references missing audit %s', new.audit_id);
  end if;
  if audit_release <> new.release_id then
    raise exception using
      errcode = 'check_violation',
      message = format(
        'Approval audit %s belongs to release %s, not %s',
        new.audit_id,
        audit_release,
        new.release_id
      );
  end if;

  if new.decision in ('approved', 'overridden')
     and current_audit is distinct from new.audit_id then
    raise exception using
      errcode = 'check_violation',
      message = format(
        'Approval decision %s for release %s must reference the current audit %s',
        new.decision,
        new.release_id,
        current_audit
      );
  end if;

  return new;
end;
$$;

drop trigger if exists approvals_validate_evidence on approvals;
create trigger approvals_validate_evidence
  before insert on approvals
  for each row execute function validate_approval_evidence();

-- Database-layer append-only enforcement. Application bugs or a compromised
-- gateway cannot rewrite evidence.
create or replace function reject_evidence_mutation()
returns trigger
language plpgsql
as $$
begin
  raise exception using
    errcode = 'restrict_violation',
    message = format(
      '%s rows are append-only; %s is not permitted',
      tg_table_name,
      tg_op
    );
end;
$$;

drop trigger if exists audits_reject_mutation on audits;
create trigger audits_reject_mutation
  before update or delete on audits
  for each row execute function reject_evidence_mutation();

drop trigger if exists approvals_reject_mutation on approvals;
create trigger approvals_reject_mutation
  before update or delete on approvals
  for each row execute function reject_evidence_mutation();

drop trigger if exists audit_events_reject_mutation on audit_events;
create trigger audit_events_reject_mutation
  before update or delete on audit_events
  for each row execute function reject_evidence_mutation();

-- The application role is provisioned outside migrations (see the production
-- runbook). When it is supplied, it gets read/append access to evidence and
-- loses UPDATE/DELETE. Without EVIDENCE_APP_ROLE the grants are skipped.
do $$
declare
  app_role text := nullif(current_setting('veripack.app_role', true), '');
begin
  if app_role is null then
    return;
  end if;

  if not exists (select 1 from pg_roles where rolname = app_role) then
    raise exception using
      errcode = 'undefined_object',
      message = format(
        'veripack.app_role "%s" does not exist',
        app_role
      ),
      hint = 'Create the restricted application role before running migrations.';
  end if;

  execute format('grant usage on schema %I to %I', current_schema(), app_role);
  execute format(
    'grant select, insert on audits, approvals, audit_events to %I',
    app_role
  );
  execute format(
    'grant select, insert, update on release_current_audits to %I',
    app_role
  );
  execute format(
    'revoke update, delete on audits, approvals, audit_events from %I',
    app_role
  );
  execute format(
    'revoke delete on release_current_audits from %I',
    app_role
  );
end $$;
