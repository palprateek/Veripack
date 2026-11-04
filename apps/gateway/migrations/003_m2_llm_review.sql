alter table audits
  add column if not exists llm_review jsonb;
