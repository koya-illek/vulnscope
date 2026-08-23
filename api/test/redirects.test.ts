import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/types";

const env = {
  ALLOWED_ORIGINS: "",
  ASSETS: { fetch: async () => new Response("asset", { status: 200 }) },
} as unknown as Env;
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

async function redirectFor(path: string): Promise<Response> {
  return worker.fetch(new Request(`http://scan.illek.ie${path}`), env, ctx);
}

describe("VulnScope HTTPS edge redirects", () => {
  it("redirects the HTTP homepage while preserving the path and query", async () => {
    const response = await redirectFor("/?from=test");
    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe("https://scan.illek.ie/?from=test");
  });

  it("redirects HTTP API paths before API handling", async () => {
    const response = await redirectFor("/api/health?check=1");
    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe("https://scan.illek.ie/api/health?check=1");
  });

  it("does not redirect an HTTPS canonical request", async () => {
    const response = await worker.fetch(new Request("https://scan.illek.ie/api/health"), env, ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();
  });

  it("serves plain HTTP requests in the development environment", async () => {
    // `wrangler dev` emulates the custom-domain host over plain HTTP, so the
    // development environment must skip the HTTPS entry guard entirely.
    const devEnv = { ...env, ENVIRONMENT: "development" } as unknown as Env;
    const response = await worker.fetch(new Request("http://scan.illek.ie/api/health"), devEnv, ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();
    const health = await response.json<{ ok: boolean; environment: string }>();
    expect(health.ok).toBe(true);
    expect(health.environment).toBe("development");
  });
});
