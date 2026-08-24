import { describe, expect, it, vi } from "vitest";
import worker, { scanQuotaPolicy } from "../src/index";
import { ResolverUnavailableError } from "../src/security";
import { deriveDailyQuotaKey } from "../src/quota";
import type { Env } from "../src/types";

vi.mock("../src/analyzer", () => ({
  analyzeUrl: vi.fn(),
}));

import { analyzeUrl } from "../src/analyzer";

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

function envWithDb(prepare: ReturnType<typeof vi.fn>): Env {
  return {
    DB: { prepare } as unknown as D1Database,
    ASSETS: { fetch: async () => new Response("asset") } as unknown as Env["ASSETS"],
    ALLOWED_ORIGINS: "",
    REPORT_RETENTION_DAYS: "14",
    DAILY_SCAN_LIMIT: "50",
    MCP_DAILY_LIMIT: "200",
    RATE_LIMIT_HMAC_KEY: "test-only-rate-limit-hmac-key-32-bytes",
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

  it("carries machine-readable quota state in the 429 body alongside the headers", async () => {
    // The daily window always closes at the end of the current UTC day.
    const resetAt = `${new Date().toISOString().slice(0, 10)}T23:59:59.999Z`;
    const prepare = vi.fn(() => ({
      bind: () => ({ first: async () => ({ request_count: 51 }) }),
    }));
    // The quota check runs after the recent-scan cache lookup, which needs a
    // CacheStorage stand-in under the plain-node test runtime.
    vi.stubGlobal("caches", {
      open: async () => ({
        match: async () => undefined,
        put: async () => {},
      }),
    });
    try {
      const response = await worker.fetch(
        new Request("https://scan.illek.ie/api/v2/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: "https://example.com" }),
        }),
        envWithDb(prepare),
        ctx,
      );

      expect(response.status).toBe(429);
      await expect(response.json()).resolves.toEqual({
        error: "Daily scan limit of 50 reached.",
        limit: 50,
        remaining: 0,
        resetAt,
      });
      expect(response.headers.get("RateLimit-Limit")).toBe("50");
      // Both countdown headers agree on the seconds remaining in the window.
      const reset = Number(response.headers.get("RateLimit-Reset"));
      expect(response.headers.get("Retry-After")).toBe(String(reset));
      expect(reset).toBeGreaterThan(0);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("refunds the charged request when a scan dies to a resolver outage", async () => {
    const executed: string[] = [];
    const prepare = vi.fn((sql: string) => {
      executed.push(sql);
      if (sql.includes("INSERT INTO rate_limits")) {
        return { bind: () => ({ first: async () => ({ request_count: 1 }) }) };
      }
      return {
        bind: () => ({ first: async () => undefined, run: async () => undefined }),
      };
    });
    vi.stubGlobal("caches", {
      open: async () => ({
        match: async () => undefined,
        put: async () => {},
      }),
    });
    vi.mocked(analyzeUrl).mockRejectedValue(
      new ResolverUnavailableError("Public DNS resolvers were unavailable while checking example.com. Try the scan again."),
    );
    try {
      const response = await worker.fetch(
        new Request("https://scan.illek.ie/api/v2/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.7" },
          body: JSON.stringify({ url: "https://example.com" }),
        }),
        envWithDb(prepare),
        ctx,
      );

      expect(response.status).toBe(503);
      // The outage message invites a retry; give agents a concrete interval.
      expect(response.headers.get("Retry-After")).toBe("60");
      // The charge was written, then given back on the same scoped key.
      const update = executed.find((sql) => sql.includes("UPDATE rate_limits"));
      expect(update).toBeTruthy();
      expect(update).toContain("MAX(request_count - 1, 0)");
    } finally {
      vi.unstubAllGlobals();
      vi.mocked(analyzeUrl).mockReset();
    }
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

describe("quota client identifiers", () => {
  const base = {
    scope: "scan",
    date: "2026-08-23",
    clientAddress: "203.0.113.7",
    secret: "test-only-rate-limit-hmac-key-32-bytes",
  };

  it("derives a stable versioned HMAC identifier", async () => {
    await expect(deriveDailyQuotaKey(base)).resolves.toBe(
      "scan:v2:b1e29011a38e4d6e33407f9e9b033796",
    );
  });

  it("separates addresses, dates, scopes, and deployment secrets", async () => {
    const original = await deriveDailyQuotaKey(base);
    const variants = await Promise.all([
      deriveDailyQuotaKey({ ...base, clientAddress: "203.0.113.8" }),
      deriveDailyQuotaKey({ ...base, date: "2026-08-24" }),
      deriveDailyQuotaKey({ ...base, scope: "mcp" }),
      deriveDailyQuotaKey({ ...base, secret: "different-test-rate-limit-key-32-bytes" }),
    ]);

    expect(new Set([original, ...variants])).toHaveLength(5);
  });

  it("rejects missing or weak deployment keys", async () => {
    await expect(deriveDailyQuotaKey({ ...base, secret: "too-short" })).rejects.toThrow(
      "RATE_LIMIT_HMAC_KEY must contain at least 32 UTF-8 bytes.",
    );
  });
});
