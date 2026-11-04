import type { FastifyInstance, FastifyRequest } from "fastify";
import { issueGithubExchangeToken, verifyGithubActionsToken, verifyGithubOAuthToken } from "../github-auth.js";
import type { AppContext } from "../context.js";

function bearer(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (!header) return null;
  const [scheme, ...parts] = header.split(" ");
  if (scheme?.toLowerCase() !== "bearer") return null;
  const token = parts.join(" ").trim();
  return token || null;
}

export async function registerGithubRoutes(
  app: FastifyInstance,
  context: AppContext,
): Promise<void> {
  app.post("/-/auth/github/actions/exchange", async (request, reply) => {
    const token = bearer(request);
    if (!token) {
      reply.code(401).send({ error: "A GitHub Actions OIDC bearer token is required." });
      return;
    }
    try {
      const principal = await verifyGithubActionsToken(token, context.config);
      const issued = await issueGithubExchangeToken(principal, context.config);
      reply.send({ ...issued, tokenType: "Bearer", subject: principal.username, role: principal.role });
    } catch (error) {
      reply.code(401).send({
        error: error instanceof Error ? error.message : "GitHub Actions token exchange failed.",
      });
    }
  });

  app.post("/-/auth/github/oauth/exchange", async (request, reply) => {
    const token = bearer(request);
    if (!token) {
      reply.code(401).send({ error: "A GitHub OAuth bearer token is required." });
      return;
    }
    try {
      const principal = await verifyGithubOAuthToken(token, context.config);
      const issued = await issueGithubExchangeToken(principal, context.config);
      reply.send({ ...issued, tokenType: "Bearer", subject: principal.username, role: principal.role });
    } catch (error) {
      reply.code(401).send({
        error: error instanceof Error ? error.message : "GitHub OAuth token exchange failed.",
      });
    }
  });
}
