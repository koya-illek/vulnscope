import { describe, expect, it, vi } from "vitest";
import worker, { scanQuotaPolicy } from "../src/index";
import type { Env } from "../src/types";

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

function envWithDb(prepare: ReturnType<typeof vi.fn>): Env {
  return {
    DB: { prepare } as unknown as D1Database,
    ASSETS: { fetch: async () => new Response("asset") } as unknown as Env["ASSETS"],
    ALLOWED_ORIGINS: "",
    REPORT_RETENTION_DAYS: "14",
    DAILY_SCAN_LIMIT: "50",
    MCP_DAILY_LIMIT: "200",
    ENVIRONMENT: "test",
  };
}

describe("quota accounting boundaries", () => {
  it("does not charge malformed report IDs", async () => {
    const prepare = vi.fn();
    const response = await worker.fetch(
      new Request("https://scan.illek.ie/api/scans/not-a-report"),
      envWithDb(prepare),
      ctx,
    );
    expect(response.status).toBe(404);
    expect(prepare).not.toHaveBeenCalled();
  });

  it("does not write quota state for MCP discovery or initialization", async () => {
    const prepare = vi.fn(() => { throw new Error("unexpected D1 write"); });
    const request = new Request("https://scan.illek.ie/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } }),
    });
    const response = await worker.fetch(request, envWithDb(prepare), ctx);
    expect(response.status).toBe(200);
    expect(prepare).not.toHaveBeenCalled();
  });

  it("rejects a self-scan before charging quota or creating a false grade", async () => {
    const prepare = vi.fn();
    const response = await worker.fetch(
      new Request("https://scan.illek.ie/api/v2/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: "https://scan.illek.ie" }),
      }),
      envWithDb(prepare),
      ctx,
    );

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({
      error:
        "VulnScope cannot scan its own hostname from inside the same Cloudflare Worker. Use a different public target.",
    });
    expect(prepare).not.toHaveBeenCalled();
  });
});

describe("quota scope selection", () => {
  const env = envWithDb(vi.fn());

  it("charges web scans against the scan scope and its configured limit", () => {
    expect(scanQuotaPolicy(env, "web")).toEqual({ scope: "scan", limit: 50, label: "Daily scan limit" });
  });

  it("charges MCP scans against their own mcp scope so agents do not consume the web bucket", () => {
    expect(scanQuotaPolicy(env, "mcp")).toEqual({ scope: "mcp", limit: 200, label: "Daily MCP scan limit" });
  });

  it("falls back to safe defaults when the variables are missing", () => {
    const bare = { ...env, DAILY_SCAN_LIMIT: undefined, MCP_DAILY_LIMIT: undefined } as unknown as Env;
    expect(scanQuotaPolicy(bare, "web").limit).toBe(10);
    expect(scanQuotaPolicy(bare, "mcp").limit).toBe(50);
  });

  it("clamps nonsensical configured limits into the allowed range", () => {
    const wild = { ...env, DAILY_SCAN_LIMIT: "-5", MCP_DAILY_LIMIT: "99999" } as unknown as Env;
    expect(scanQuotaPolicy(wild, "web").limit).toBe(1);
    expect(scanQuotaPolicy(wild, "mcp").limit).toBe(1000);
  });
});
