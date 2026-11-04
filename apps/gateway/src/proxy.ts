import type { FastifyReply, FastifyRequest } from "fastify";
import { Readable } from "node:stream";
import type { AppContext } from "./context.js";

const FORWARD_REQUEST_HEADERS = [
  "accept",
  "content-type",
  "npm-command",
  "user-agent",
  "npm-in-ci",
  "npm-scope",
  "npm-session",
];

const FORWARD_RESPONSE_HEADERS = [
  "content-type",
  "cache-control",
  "etag",
  "last-modified",
  "npm-notice",
];

/**
 * Forward an npm protocol request to Verdaccio. The gateway is the only public
 * endpoint; Verdaccio is a private upstream.
 */
export async function proxyToVerdaccio(
  request: FastifyRequest,
  reply: FastifyReply,
  context: AppContext,
): Promise<void> {
  const base = context.config.VERDACCIO_URL.replace(/\/+$/, "");
  const target = `${base}${request.url}`;

  const headers = new Headers();
  for (const name of FORWARD_REQUEST_HEADERS) {
    const value = request.headers[name];
    if (typeof value === "string") headers.set(name, value);
  }

  const method = request.method.toUpperCase();
  const hasBody = !["GET", "HEAD"].includes(method);
  let body: string | undefined;
  if (hasBody && request.body !== undefined && request.body !== null) {
    body = JSON.stringify(request.body);
    headers.set("content-type", "application/json");
  }

  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method,
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(context.config.PROXY_TIMEOUT_MS),
    });
  } catch (error) {
    request.log.error({ err: error, target }, "Verdaccio proxy request failed");
    reply.code(502).send({ error: "Registry upstream is unavailable." });
    return;
  }

  reply.code(upstream.status);
  for (const name of FORWARD_RESPONSE_HEADERS) {
    const value = upstream.headers.get(name);
    if (value) reply.header(name, value);
  }

  if (method === "HEAD") {
    reply.send();
    return;
  }

  if (!upstream.body) {
    reply.send();
    return;
  }

  // Keep tarballs streaming end to end. Buffering a package response in the
  // gateway makes large installs consume memory proportional to the archive.
  reply.send(Readable.fromWeb(upstream.body as never));
}
