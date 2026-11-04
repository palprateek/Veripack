-- Full upstream cache key and TTL. The cache identity is the tarball digest,
-- package/version, engine, ruleset and intel versions, and the policy version.

alter table upstream_audits
  add column if not exists ruleset_version text not null default 'v1',
  add column if not exists intel_version text not null default 'v1',
  add column if not exists expires_at timestamptz;

-- Conservative backfill: rows expire seven days after they were created, so
-- anything older is re-audited under the current key on next access.
update upstream_audits
   set expires_at = created_at + interval '7 days'
 where expires_at is null;

alter table upstream_audits
  alter column expires_at set not null;

alter table upstream_audits
  drop constraint if exists upstream_audits_pkey;

do $$
begin
  if not exists (
    select 1
      from pg_constraint
     where conname = 'upstream_audits_pkey'
       and conrelid = 'upstream_audits'::regclass
  ) then
    alter table upstream_audits
      add constraint upstream_audits_pkey
      primary key (
        tarball_digest, package_name, version, engine_version,
        ruleset_version, intel_version, policy_version
      );
  end if;
end $$;

create index if not exists upstream_audits_expiry_idx
  on upstream_audits (expires_at);
