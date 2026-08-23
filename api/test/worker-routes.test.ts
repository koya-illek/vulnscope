import { describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import type { CoveragePhase, Env, ScanCoverage } from "../src/types";

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

function phase(status: CoveragePhase["status"], detail = `${status} phase`): CoveragePhase {
  return { status, detail };
}

function storedCoverage(): ScanCoverage {
  return {
    mainFetch: phase("measured"),
    headers: phase("measured"),
    tlsProtocolCipher: phase("unavailable"),
    certificateEvidence: phase("measured"),
    dns: phase("measured"),
    cookies: phase("measured"),
    paths: phase("skipped"),
    cors: phase("measured"),
    secrets: phase("skipped"),
    wordpress: phase("skipped"),
    methods: phase("measured"),
    takeover: phase("skipped"),
    criticalGaps: [],
  };
}

function storedReportJson(hostname: string): string {
  return JSON.stringify({
    schemaVersion: 2,
    id: "abcdefghijklmnop",
    requestedUrl: `https://${hostname}/`,
    hostname,
    status: "complete",
    createdAt: "2026-08-23T00:00:00.000Z",
    expiresAt: "2026-09-06T00:00:00.000Z",
    totalDurationMs: 100,
    observation: { vantage: "cloudflare-edge", disclaimer: "d" },
    coverage: storedCoverage(),
    dns: { queries: [], addresses: [], dnssecAuthenticated: false },
    ssl: {},
    fingerprint: {},
    headers: {},
    cookies: [],
    exposedPaths: [],
    cors: {},
    findings: [],
    summary: { grade: "A", critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  });
}

function envWithRow(row: { report_json: string } | null): Env {
  return {
    DB: {
      prepare: vi.fn(() => ({
        bind: () => ({ first: async () => row }),
      })),
    },
    ASSETS: { fetch: async () => new Response("<html>asset</html>", { status: 200 }) },
    ALLOWED_ORIGINS: "",
    ENVIRONMENT: "test",
  } as unknown as Env;
}

describe("report export contract", () => {
  it("slugs hostile stored hostnames into a safe attachment filename", async () => {
    const response = await worker.fetch(
      new Request("https://scan.illek.ie/api/scans/abcdefghijklmnop/export"),
      envWithRow({ report_json: storedReportJson(`evil.example";\r\nX-Injected: yes`) }),
      ctx,
    );
    expect(response.status).toBe(200);
    const disposition = response.headers.get("content-disposition") || "";
    expect(disposition).toMatch(/^attachment; filename="vulnscope-[A-Za-z0-9.-]+\.json"$/);
    expect(disposition).not.toContain("\r");
    expect(disposition).not.toContain("\n");
    // The injection payload survives only as slug text; its structure is gone.
    expect(disposition).not.toContain("X-Injected:");
  });

  it("answers a well-shaped but expired or missing report with an honest 404", async () => {
    const response = await worker.fetch(
      new Request("https://scan.illek.ie/api/scans/abcdefghijklmnop"),
      envWithRow(null),
      ctx,
    );
    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toEqual({ error: "Report not found or expired" });
  });

  it("treats HEAD on a report route like GET instead of a JSON 404 miss", async () => {
    const response = await worker.fetch(
      new Request("https://scan.illek.ie/api/scans/abcdefghijklmnop", { method: "HEAD" }),
      envWithRow(null),
      ctx,
    );
    expect(response.status).toBe(404);
  });
});

describe("stream endpoint contract", () => {
  async function postStream(body: string, contentType = "application/json"): Promise<Response> {
    return worker.fetch(new Request("https://scan.illek.ie/api/scans/stream", {
      method: "POST",
      headers: { "Content-Type": contentType },
      body,
    }), { ALLOWED_ORIGINS: "", ENVIRONMENT: "test" } as unknown as Env, ctx);
  }

  it("emits an accepted progress event before any other stream event", async () => {
    const response = await postStream(JSON.stringify({ url: "https://scan.illek.ie" }));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/x-ndjson");
    const events = (await response.text()).trim().split("\n").map((line) => JSON.parse(line));
    expect(events[0]).toMatchObject({ type: "progress", stage: "accepted" });
    // Self-scans are blocked before quota charging, so the run fails honestly
    // inside the stream instead of producing a result event.
    const last = events[events.length - 1];
    expect(last.type).toBe("error");
    expect(last.status).toBe(403);
  });

  it("answers malformed scan input with a plain JSON error, not a stream", async () => {
    const response = await postStream("{not json");
    expect(response.status).toBe(400);
    expect(response.headers.get("content-type")).toContain("application/json");
    await expect(response.json()).resolves.toEqual({ error: "Invalid JSON request body." });
  });

  it("rejects bodies beyond the 8 KiB input cap", async () => {
    const response = await postStream(JSON.stringify({ url: `https://${"a".repeat(9000)}.com` }));
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "Request body is too large." });
  });

  it("requires the application/json content type", async () => {
    const response = await postStream("{}", "text/plain");
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "Content-Type must be application/json." });
  });
});

describe("static and discovery surfaces", () => {
  it("adds HSTS to asset responses even when the asset server omits it", async () => {
    const response = await worker.fetch(
      new Request("https://scan.illek.ie/styles.css"),
      envWithRow(null),
      ctx,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("strict-transport-security")).toContain("max-age=31536000");
  });

  it("advertises every public interface from the API metadata document", async () => {
    const response = await worker.fetch(
      new Request("https://scan.illek.ie/api/v2"),
      envWithRow(null),
      ctx,
    );
    const body = await response.json<{ endpoints: Record<string, string> }>();
    expect(body.endpoints.v2Scan).toBe("POST /api/v2/scan");
    expect(body.endpoints.streamScan).toBe("POST /api/scans/stream");
    expect(body.endpoints.exportScan).toBe("GET /api/scans/:id/export");
    expect(body.endpoints.mcp).toContain("/mcp");
  });

  it("echoes only allowlisted origins on preflight requests", async () => {
    const env = { ALLOWED_ORIGINS: "https://scan.illek.ie", ENVIRONMENT: "test" } as unknown as Env;
    const allowed = await worker.fetch(new Request("https://scan.illek.ie/api/v2/scan", {
      method: "OPTIONS",
      headers: { Origin: "https://scan.illek.ie" },
    }), env, ctx);
    expect(allowed.status).toBe(204);
    expect(allowed.headers.get("access-control-allow-origin")).toBe("https://scan.illek.ie");

    const rejected = await worker.fetch(new Request("https://scan.illek.ie/api/v2/scan", {
      method: "OPTIONS",
      headers: { Origin: "https://evil.example" },
    }), env, ctx);
    expect(rejected.status).toBe(403);
    expect(rejected.headers.get("access-control-allow-origin")).toBeNull();
  });
});
