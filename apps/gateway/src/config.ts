import { config as loadEnv } from "dotenv";
import { resolve } from "node:path";
import { z } from "zod";

// Load the repo-root .env first, then a local .env if one exists. Both are
// optional; the defaults below make a clean local checkout work.
loadEnv({ path: resolve(process.cwd(), "../../.env"), quiet: true });
loadEnv({ quiet: true });

const boolFromEnv = (defaultValue: boolean) =>
  z
    .string()
    .optional()
    .transform((value) => {
      if (value === undefined) return defaultValue;
      return ["1", "true", "yes", "on"].includes(value.toLowerCase());
    });

const csvFromEnv = (defaultValue: string) =>
  z
    .string()
    .default(defaultValue)
    .transform((value) =>
      value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    );

const envSchema = z.object({
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
  LOG_LEVEL: z.string().default("info"),
  PROCESS_ROLE: z.enum(["all", "gateway", "worker"]).default("all"),

  DATABASE_URL: z
    .string()
    .default("postgres://veripack:veripack@localhost:5432/veripack"),
  DATABASE_SSL: boolFromEnv(false),
  DATABASE_SSL_REJECT_UNAUTHORIZED: boolFromEnv(true),
  // Restricted role that receives evidence grants from migration 007. Empty
  // means the grants are skipped (the application role is not separated).
  EVIDENCE_APP_ROLE: z.string().default(""),

  S3_ENDPOINT: z.string().default("http://localhost:9090"),
  S3_REGION: z.string().default("us-east-1"),
  S3_BUCKET: z.string().default("veripack-tarballs"),
  S3_ACCESS_KEY_ID: z.string().default("dev"),
  S3_SECRET_ACCESS_KEY: z.string().default("dev"),
  S3_FORCE_PATH_STYLE: boolFromEnv(true),
  S3_AUTO_CREATE_BUCKET: boolFromEnv(true),

  VERDACCIO_URL: z.string().default("http://localhost:4873"),
  VERDACCIO_USER: z.string().default("gateway"),
  VERDACCIO_PASSWORD: z.string().default("dev-service-token"),
  VERDACCIO_IDENTITIES: z.string().default(""),
  VERDACCIO_ACTIVE_IDENTITY: z.string().default("a"),

  PUBLIC_REGISTRY_URL: z.string().default("http://localhost:4874"),
  GATEWAY_HOST: z.string().default("0.0.0.0"),
  GATEWAY_PORT: z.coerce.number().int().positive().default(4874),
  ORG_ID: z.string().default("dev-org"),
  CORS_ORIGINS: csvFromEnv("http://localhost:3000"),
  TRUST_PROXY: boolFromEnv(false),
  BODY_LIMIT_BYTES: z.coerce.number().int().positive().default(50 * 1024 * 1024),
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(1_000),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  RATE_LIMIT_BACKEND: z.enum(["memory", "postgres"]).default("memory"),
  PROXY_TIMEOUT_MS: z.coerce.number().int().positive().default(60_000),
  METRICS_ENABLED: boolFromEnv(true),
  METRICS_TOKEN: z.string().default(""),

  AUTH_MODE: z.enum(["static", "oidc", "github", "hybrid"]).default("static"),
  VERIPACK_TOKEN: z.string().default("dev-token"),
  READ_TOKEN: z.string().default(""),
  REVIEWER_TOKEN: z.string().default(""),
  ADMIN_TOKEN: z.string().default("admin-token"),
  DEFAULT_PUBLISHER: z.string().default("dev-publisher"),
  REVIEWER_USER: z.string().default("dev-reviewer"),
  ADMIN_USER: z.string().default("dev-admin"),
  ALLOW_SELF_APPROVAL: boolFromEnv(false),
  ALLOW_UNSCOPED_NAMES: boolFromEnv(false),
  OIDC_ISSUER_URL: z.string().default(""),
  OIDC_AUDIENCE: z.string().default(""),
  OIDC_JWKS_URL: z.string().default(""),
  OIDC_ROLE_CLAIM: z.string().default("roles"),
  OIDC_ORG_CLAIM: z.string().default("org_id"),
  OIDC_PACKAGE_CLAIM: z.string().default("package_scope"),
  OIDC_READ_SCOPE_CLAIM: z.string().default("read_scope"),
  OIDC_PUBLISH_SCOPE_CLAIM: z.string().default("publish_scope"),
  OIDC_PUBLISHER_ROLES: csvFromEnv("publisher"),
  OIDC_REVIEWER_ROLES: csvFromEnv("reviewer"),
  OIDC_ADMIN_ROLES: csvFromEnv("admin"),
  OIDC_REQUIRE_PACKAGE_SCOPE: boolFromEnv(false),
  OIDC_CLOCK_TOLERANCE_SECONDS: z.coerce.number().int().nonnegative().default(5),

  GITHUB_OIDC_ENABLED: boolFromEnv(false),
  GITHUB_OIDC_ISSUER: z
    .string()
    .default("https://token.actions.githubusercontent.com"),
  GITHUB_OIDC_JWKS_URL: z
    .string()
    .default("https://token.actions.githubusercontent.com/.well-known/jwks"),
  GITHUB_OIDC_AUDIENCE: z.string().default("veripack"),
  GITHUB_ALLOWED_REPOSITORIES: csvFromEnv(""),
  GITHUB_ALLOWED_WORKFLOW_REFS: csvFromEnv(""),
  GITHUB_ADMIN_WORKFLOW_REFS: csvFromEnv(""),
  GITHUB_PACKAGE_SCOPE: z.string().default(""),
  GITHUB_PACKAGE_SCOPES: z.string().default(""),
  GITHUB_PROTECTED_BRANCHES: csvFromEnv(""),
  GITHUB_ADMIN_REPOSITORIES: csvFromEnv(""),
  GITHUB_REVIEWER_REPOSITORIES: csvFromEnv(""),
  GITHUB_ADMIN_USERS: csvFromEnv(""),
  GITHUB_PUBLISHER_USERS: csvFromEnv(""),
  GITHUB_REVIEWER_USERS: csvFromEnv(""),
  GITHUB_API_URL: z.string().default("https://api.github.com"),
  GITHUB_TOKEN_EXCHANGE_SECRET: z.string().default(""),
  GITHUB_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(900),
  DASHBOARD_INTERNAL_SECRET: z.string().default(""),
  AGENT_TOKEN: z.string().default(""),
  AGENT_USER: z.string().default("agent-panel"),

  AUDIT_ENGINE_VERSION: z.string().default("0.2.0-static"),
  AUDIT_RULESET_VERSION: z.string().default("v1"),
  AUDIT_INTEL_VERSION: z.string().default("v1"),
  UPSTREAM_AUDIT_TTL_DAYS: z.coerce.number().int().positive().default(7),
  UPSTREAM_SPOOL_DIR: z.string().default(""),
  INGEST_PER_USER_CONCURRENCY: z.coerce.number().int().positive().default(2),
  INGEST_GLOBAL_CONCURRENCY: z.coerce.number().int().positive().default(8),
  INGEST_PER_USER_RATE_PER_HOUR: z.coerce.number().int().positive().default(20),
  INGEST_MAX_TARBALL_BYTES: z.coerce.number().int().positive().default(25 * 1024 * 1024),
  INGEST_QUOTA_BYTES_PER_HOUR: z.coerce.number().int().positive().default(500 * 1024 * 1024),
  INGEST_TIMEOUT_MS: z.coerce.number().int().positive().default(120_000),
  AUDIT_POLICY_VERSION: z.string().default("v1-default-1"),
  AUDIT_POLICY_JSON: z.string().default("{}"),
  AUDIT_LLM_BACKEND: z.string().default("disabled"),
  AUDIT_LLM_URL: z.string().default(""),
  AUDIT_LLM_API_KEY: z.string().default(""),
  AUDIT_LLM_MODEL: z.string().default(""),
  AUDIT_LLM_TIMEOUT_MS: z.coerce.number().int().positive().default(20_000),
  AUDIT_LLM_TEMPERATURE: z.coerce.number().min(0).max(2).default(0),
  AUDIT_LLM_MAX_TOKENS: z.coerce.number().int().positive().max(8_000).default(1_200),
  AUDIT_QUEUE: z.string().default("veripack-audit"),
  AUDIT_JOB_RETRY_LIMIT: z.coerce.number().int().nonnegative().default(3),
  AUDIT_JOB_RETRY_DELAY_SECONDS: z.coerce.number().int().positive().default(2),
  AUDIT_JOB_EXPIRE_SECONDS: z.coerce.number().int().positive().default(300),
  AUDIT_JOB_DELETE_AFTER_SECONDS: z.coerce.number().int().positive().default(86_400),
  QUEUE_MAX_CONNECTIONS: z.coerce.number().int().positive().default(5),
  AUDIT_OUTBOX_BATCH_SIZE: z.coerce.number().int().positive().max(500).default(100),
  AUDIT_OUTBOX_INTERVAL_MS: z.coerce.number().int().positive().default(5_000),
  AUDIT_WORKER_REQUIRED: boolFromEnv(false),
  AUDIT_WORKER_HEARTBEAT_INTERVAL_MS: z.coerce.number().int().positive().default(10_000),
  AUDIT_WORKER_STALE_MS: z.coerce.number().int().positive().default(60_000),
  REPLAY_LEASE_MS: z.coerce.number().int().positive().default(60_000),
  REPLAY_POLL_MS: z.coerce.number().int().positive().default(2_000),
  REPLAY_MAX_ATTEMPTS: z.coerce.number().int().positive().default(3),
  REPLAY_BACKOFF_MS: z.coerce.number().int().nonnegative().default(30_000),

  SANDBOX_MODE: z.enum(["disabled", "docker", "podman"]).default("disabled"),
  SANDBOX_ENABLE_ON_AUDIT: boolFromEnv(false),
  SANDBOX_IMAGE: z.string().default(
    "node@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914",
  ),
  SANDBOX_TIMEOUT_MS: z.coerce.number().int().positive().default(30_000),
  SANDBOX_MEMORY_MB: z.coerce.number().int().positive().default(256),
  SANDBOX_CPUS: z.coerce.number().positive().default(1),
  SANDBOX_MAX_OUTPUT_BYTES: z.coerce.number().int().positive().default(64_000),

  BACKUP_S3_PREFIX: z.string().default("backups"),
});

export type Config = z.infer<typeof envSchema>;

export const config: Config = envSchema.parse(process.env);

if (config.NODE_ENV === "production") {
  if (config.AUTH_MODE === "static") {
    throw new Error(
      "Refusing to start in production with AUTH_MODE=static. Use OIDC, GitHub federation, or hybrid authentication.",
    );
  }
  if (
    (config.AUTH_MODE === "oidc" || config.AUTH_MODE === "hybrid") &&
    (!config.OIDC_ISSUER_URL || !config.OIDC_AUDIENCE || !config.OIDC_JWKS_URL)
  ) {
    throw new Error(
      "Production OIDC requires OIDC_ISSUER_URL, OIDC_AUDIENCE, and OIDC_JWKS_URL.",
    );
  }
  if (!config.PUBLIC_REGISTRY_URL.startsWith("https://")) {
    throw new Error("PUBLIC_REGISTRY_URL must use HTTPS in production.");
  }
  if (!config.DATABASE_SSL) {
    throw new Error("DATABASE_SSL=true is required in production.");
  }
  if (!config.DATABASE_SSL_REJECT_UNAUTHORIZED) {
    throw new Error(
      "DATABASE_SSL_REJECT_UNAUTHORIZED=true is required in production.",
    );
  }
  if (!config.S3_ENDPOINT.startsWith("https://")) {
    throw new Error("S3_ENDPOINT must use HTTPS in production.");
  }
  if (!config.VERDACCIO_URL.startsWith("https://")) {
    throw new Error("VERDACCIO_URL must use HTTPS in production.");
  }
  if (config.VERDACCIO_PASSWORD === "dev-service-token" || config.VERDACCIO_PASSWORD.length < 16) {
    throw new Error("Production Verdaccio credentials must be replaced with a strong secret.");
  }
  if (config.CORS_ORIGINS.includes("*")) {
    throw new Error("CORS_ORIGINS cannot contain '*' in production.");
  }
  if (config.S3_AUTO_CREATE_BUCKET) {
    throw new Error(
      "S3_AUTO_CREATE_BUCKET must be false in production; provision the bucket out of band.",
    );
  }
  if (config.RATE_LIMIT_BACKEND !== "postgres") {
    throw new Error(
      "RATE_LIMIT_BACKEND=postgres is required in production for multi-replica rate limiting.",
    );
  }
  if (config.AUTH_MODE === "oidc" || config.AUTH_MODE === "hybrid") {
    if (!config.OIDC_REQUIRE_PACKAGE_SCOPE) {
      throw new Error("OIDC_REQUIRE_PACKAGE_SCOPE=true is required in production.");
    }
  }
  if (config.GITHUB_OIDC_ENABLED) {
    if (config.GITHUB_ALLOWED_WORKFLOW_REFS.length === 0) {
      throw new Error(
        "GITHUB_ALLOWED_WORKFLOW_REFS is required when GitHub federation is enabled.",
      );
    }
    if (!config.GITHUB_PACKAGE_SCOPES.trim() && !config.GITHUB_PACKAGE_SCOPE.trim()) {
      throw new Error(
        "GITHUB_PACKAGE_SCOPES (or a single-repository GITHUB_PACKAGE_SCOPE) is required for GitHub publisher tokens in production.",
      );
    }
    if (
      !config.GITHUB_PACKAGE_SCOPES.trim() &&
      config.GITHUB_ALLOWED_REPOSITORIES.length > 1
    ) {
      throw new Error(
        "A single GITHUB_PACKAGE_SCOPE cannot cover multiple repositories in production. Configure GITHUB_PACKAGE_SCOPES per repository.",
      );
    }
    if (config.GITHUB_ALLOWED_WORKFLOW_REFS.some((pattern) => pattern.includes("*"))) {
      throw new Error(
        "GitHub publisher workflow refs must be exact in production; wildcard refs are rejected.",
      );
    }
    if (
      config.GITHUB_ADMIN_REPOSITORIES.length > 0 &&
      config.GITHUB_ADMIN_WORKFLOW_REFS.length === 0
    ) {
      throw new Error(
        "GITHUB_ADMIN_WORKFLOW_REFS is required for GitHub admin repositories.",
      );
    }
    if (
      config.GITHUB_ADMIN_REPOSITORIES.some((pattern) => pattern.includes("*")) ||
      config.GITHUB_ADMIN_WORKFLOW_REFS.some((pattern) => pattern.includes("*"))
    ) {
      throw new Error(
        "GitHub administrator repositories and workflow refs must be exact in production.",
      );
    }
  }
  if (config.PROCESS_ROLE !== "worker") {
    // A production gateway must not report ready while no audit worker can
    // consume the durable outbox and queue.
    if (!config.AUDIT_WORKER_REQUIRED) {
      throw new Error("AUDIT_WORKER_REQUIRED=true is required for production gateways.");
    }
  }
  if (config.METRICS_ENABLED && !config.METRICS_TOKEN) {
    throw new Error("METRICS_TOKEN is required when metrics are enabled in production.");
  }
  if (
    config.S3_ACCESS_KEY_ID === "dev" ||
    config.S3_SECRET_ACCESS_KEY === "dev"
  ) {
    throw new Error("Production S3 credentials must not use the development values.");
  }
  if (config.GITHUB_OIDC_ENABLED) {
    if (config.GITHUB_ALLOWED_REPOSITORIES.length === 0) {
      throw new Error(
        "GITHUB_ALLOWED_REPOSITORIES is required when GitHub federation is enabled.",
      );
    }
  }
  if (
    config.AUTH_MODE === "github" ||
    config.GITHUB_OIDC_ENABLED ||
    config.GITHUB_ADMIN_USERS.length > 0 ||
    config.GITHUB_PUBLISHER_USERS.length > 0
  ) {
    if (config.GITHUB_TOKEN_EXCHANGE_SECRET.length < 32) {
      throw new Error(
        "GITHUB_TOKEN_EXCHANGE_SECRET must contain at least 32 characters when GitHub authentication is enabled.",
      );
    }
  }
  if (config.SANDBOX_ENABLE_ON_AUDIT && config.SANDBOX_MODE === "disabled") {
    throw new Error(
      "SANDBOX_MODE must be docker or podman when SANDBOX_ENABLE_ON_AUDIT=true.",
    );
  }
}
