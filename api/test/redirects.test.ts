import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/types";
import { WEBSITE_ORIGIN } from "../src/version";

const env = {
  ALLOWED_ORIGINS: "",
  ASSETS: { fetch: async () => new Response("asset", { status: 200 }) },
} as unknown as Env;
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

async function fetchPath(origin: string, path: string, init?: RequestInit): Promise<Response> {
  return worker.fetch(new Request(`${origin}${path}`, init), env, ctx);
}

describe("VulnScope HTTPS edge redirects", () => {
  it("redirects the HTTP homepage while preserving the path and query", async () => {
    const response = await fetchPath(WEBSITE_ORIGIN.replace("https://", "http://"), "/?from=test");
    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(`${WEBSITE_ORIGIN}/?from=test`);
  });

  it("redirects HTTP API paths before API handling", async () => {
    const response = await fetchPath(WEBSITE_ORIGIN.replace("https://", "http://"), "/api/health?check=1");
    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(`${WEBSITE_ORIGIN}/api/health?check=1`);
  });

  it("does not redirect an HTTPS canonical request", async () => {
    const response = await fetchPath(WEBSITE_ORIGIN, "/api/health");
    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();
  });

  it("serves plain HTTP requests in the development environment", async () => {
    // `wrangler dev` emulates a custom-domain host over plain HTTP, so the
    // development environment must skip the HTTPS and alias-host guards.
    const devEnv = { ...env, ENVIRONMENT: "development" } as unknown as Env;
    const response = await worker.fetch(new Request("http://scan.illek.ie/api/health"), devEnv, ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();
    const health = await response.json<{ ok: boolean; environment: string }>();
    expect(health.ok).toBe(true);
    expect(health.environment).toBe("development");

    const canonicalDev = await worker.fetch(new Request("http://vulnscope.illek.ie/api/health"), devEnv, ctx);
    expect(canonicalDev.status).toBe(200);
    expect(canonicalDev.headers.get("location")).toBeNull();
  });
});

describe("VulnScope alias-host redirects", () => {
  it("permanently redirects HTTPS scan.illek.ie to the canonical origin", async () => {
    const response = await fetchPath("https://scan.illek.ie", "/api/health?check=1");
    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(`${WEBSITE_ORIGIN}/api/health?check=1`);
  });

  it("sends HTTP scan.illek.ie to HTTPS vulnscope.illek.ie in one hop", async () => {
    const response = await fetchPath("http://scan.illek.ie", "/?from=legacy");
    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(`${WEBSITE_ORIGIN}/?from=legacy`);
  });

  it("redirects www.scan.illek.ie the same way", async () => {
    const response = await fetchPath("https://www.scan.illek.ie", "/mcp/v2");
    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(`${WEBSITE_ORIGIN}/mcp/v2`);
  });

  it("redirects HEAD on the legacy host before asset or API handling", async () => {
    const response = await fetchPath("https://scan.illek.ie", "/styles.css", { method: "HEAD" });
    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(`${WEBSITE_ORIGIN}/styles.css`);
  });
});
