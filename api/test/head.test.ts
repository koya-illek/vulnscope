import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/types";

const env = {
  ALLOWED_ORIGINS: "",
  ASSETS: {
    fetch: async () => new Response("<html>asset</html>", { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } }),
  },
} as unknown as Env;
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

describe("HEAD request handling", () => {
  it("identifies the release without claiming dependency health", async () => {
    const response = await worker.fetch(new Request("https://vulnscope.illek.ie/api/health"), {
      ...env, SOURCE_REVISION: "abc123456789", VERSION_METADATA: { id: "release-id" },
    }, ctx);
    const body = await response.json<Record<string, unknown>>();
    expect(body.sourceRevision).toBe("abc123456789");
    expect(body.deploymentId).toBe("release-id");
    expect(body.healthScope).toContain("does not check database");
  });

  it("does not invent release provenance in local development", async () => {
    const response = await worker.fetch(new Request("https://vulnscope.illek.ie/api/health"), env, ctx);
    const body = await response.json<Record<string, unknown>>();
    expect(body.sourceRevision).toBe("unknown");
    expect(body.deploymentId).toBe("unknown");
  });

  it("serves static assets for HEAD instead of falling through to the JSON 404 handler", async () => {
    const response = await worker.fetch(new Request("https://vulnscope.illek.ie/", { method: "HEAD" }), env, ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
  });

  it("treats HEAD /api/health like GET so uptime monitors see a healthy endpoint", async () => {
    const response = await worker.fetch(new Request("https://vulnscope.illek.ie/api/health", { method: "HEAD" }), env, ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
  });
});
