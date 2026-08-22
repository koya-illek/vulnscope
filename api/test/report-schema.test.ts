import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env, Finding, ScanCoverage } from "../src/types";

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

function databaseReturning(report: unknown): D1Database {
  return {
    prepare() {
      return {
        bind() {
          return { first: async () => ({ report_json: JSON.stringify(report) }) };
        },
      };
    },
  } as unknown as D1Database;
}

const measured = (detail: string) => ({ status: "measured" as const, detail });
const unavailable = (detail: string) => ({ status: "unavailable" as const, detail });
const skipped = (detail: string) => ({ status: "skipped" as const, detail });

function storedV2Coverage(overrides: Partial<ScanCoverage> = {}): ScanCoverage {
  return {
    mainFetch: measured("GET measured"),
    headers: measured("Headers measured"),
    tlsProtocolCipher: unavailable("Origin TLS protocol/cipher was not assessed."),
    certificateEvidence: unavailable("Certificate-transparency evidence was unavailable."),
    dns: measured("DNS measured"),
    cookies: measured("Cookies measured"),
    paths: skipped("Optional path probing was not enabled."),
    cors: measured("CORS measured"),
    secrets: measured("Secrets measured"),
    wordpress: skipped("Target was not WordPress."),
    methods: measured("Methods measured"),
    takeover: skipped("Optional takeover checks were not enabled."),
    criticalGaps: [
      "tlsProtocolCipher: Origin TLS protocol/cipher was not assessed.",
      "certificateEvidence: Certificate-transparency evidence was unavailable.",
    ],
    ...overrides,
  };
}

function finding(severity: Finding["severity"]): Finding {
  return {
    id: `stored-${severity}`,
    severity,
    category: "missing-header",
    title: `Stored ${severity} finding`,
    detail: "Stored finding detail",
    evidence: "Stored finding evidence",
    recommendation: "Stored finding recommendation",
  };
}

function storedV2Report(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: 2,
    id: "abcdefghijklmnop",
    requestedUrl: "https://example.com/",
    hostname: "example.com",
    status: "partial",
    createdAt: "2026-08-12T00:00:00.000Z",
    expiresAt: "2026-08-26T00:00:00.000Z",
    totalDurationMs: 10,
    observation: { vantage: "cloudflare-edge", disclaimer: "Stored schema-v2 report" },
    coverage: storedV2Coverage(),
    findings: [],
    summary: { grade: "INCOMPLETE", critical: 7, high: 6, medium: 5, low: 4, info: 3 },
    ...overrides,
  };
}

async function loadStoredReport(report: unknown) {
  const env = { DB: databaseReturning(report) } as unknown as Env;
  const response = await worker.fetch(
    new Request("https://scan.illek.ie/api/scans/abcdefghijklmnop"),
    env,
    ctx,
  );
  return { response, report: await response.json<any>() };
}

describe("stored VulnScope report compatibility", () => {
  it("regrades an existing schema 2 HTTP-surface report and removes stale TLS/CT gaps", async () => {
    const { response, report } = await loadStoredReport(storedV2Report());

    expect(response.status).toBe(200);
    expect(report.status).toBe("complete");
    expect(report.summary).toEqual({
      grade: "A",
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    });
    expect(report.coverage.criticalGaps).toEqual([]);
    expect(report.coverage.tlsProtocolCipher.status).toBe("unavailable");
    expect(report.coverage.certificateEvidence.status).toBe("unavailable");
  });

  it("surfaces a stored high finding as D even when required grade coverage is incomplete", async () => {
    const coverage = storedV2Coverage({
      headers: skipped("Header audit did not run."),
      criticalGaps: [
        "headers: Header audit did not run.",
        "tlsProtocolCipher: Origin TLS protocol/cipher was not assessed.",
        "certificateEvidence: Certificate-transparency evidence was unavailable.",
      ],
    });
    const { report } = await loadStoredReport(storedV2Report({
      coverage,
      findings: [finding("high")],
      summary: { grade: "INCOMPLETE", critical: 0, high: 0, medium: 9, low: 9, info: 9 },
    }));

    expect(report.status).toBe("partial");
    expect(report.summary).toEqual({
      grade: "D",
      critical: 0,
      high: 1,
      medium: 0,
      low: 0,
      info: 0,
    });
    expect(report.coverage.criticalGaps).toEqual(["headers: Header audit did not run."]);
  });

  it.each([
    {
      name: "failed main fetch",
      storedStatus: "failed",
      expectedStatus: "failed",
      coverage: storedV2Coverage({
        mainFetch: { status: "failed", detail: "GET timed out." },
        headers: skipped("Header audit skipped because the main fetch failed."),
      }),
    },
    {
      name: "skipped header audit",
      storedStatus: "complete",
      expectedStatus: "partial",
      coverage: storedV2Coverage({ headers: skipped("Header audit did not run.") }),
    },
  ])("keeps an existing schema 2 report incomplete for $name", async ({ storedStatus, expectedStatus, coverage }) => {
    const { report } = await loadStoredReport(storedV2Report({ status: storedStatus, coverage }));

    expect(report.status).toBe(expectedStatus);
    expect(report.summary.grade).toBe("INCOMPLETE");
    expect(report.coverage.criticalGaps.length).toBeGreaterThan(0);
  });

  it("does not erase a partial status attributed to a non-TLS coverage gap", async () => {
    const coverage = storedV2Coverage({
      criticalGaps: ["paths: Sensitive path probing failed."],
    });
    const { report } = await loadStoredReport(storedV2Report({ coverage }));

    expect(report.summary.grade).toBe("A");
    expect(report.coverage.criticalGaps).toEqual([]);
    expect(report.status).toBe("partial");
  });

  it("rejects a malformed schema 2 report instead of assigning it a clean grade", async () => {
    const malformed = storedV2Report({
      findings: [{ severity: "not-a-real-severity" }],
    });
    const { response } = await loadStoredReport(malformed);

    expect(response.status).toBe(404);
  });

  it("migrates schema 1 reports to an explicitly incomplete schema 2 report", async () => {
    const legacy = {
      schemaVersion: 1,
      id: "abcdefghijklmnop",
      url: "https://example.com/",
      hostname: "example.com",
      status: "complete",
      createdAt: "2026-08-01T00:00:00.000Z",
      expiresAt: "2026-08-15T00:00:00.000Z",
      totalDurationMs: 10,
      observation: { vantage: "cloudflare-edge", disclaimer: "Legacy report" },
      summary: { grade: "A", critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    };
    const env = { DB: databaseReturning(legacy) } as unknown as Env;

    const response = await worker.fetch(
      new Request("https://scan.illek.ie/api/scans/abcdefghijklmnop"),
      env,
      ctx,
    );
    const migrated = await response.json<any>();

    expect(response.status).toBe(200);
    expect(migrated.schemaVersion).toBe(2);
    expect(migrated.requestedUrl).toBe("https://example.com/");
    expect(migrated.status).toBe("partial");
    expect(migrated.summary.grade).toBe("INCOMPLETE");
    expect(migrated.coverage.criticalGaps).toEqual([
      "mainFetch: Legacy report has no explicit main-fetch coverage metadata.",
      "headers: Legacy report has no explicit header coverage metadata.",
    ]);
    expect(migrated.coverage.tlsProtocolCipher.status).toBe("unavailable");
    expect(migrated.coverage.certificateEvidence.status).toBe("unavailable");
    expect(migrated.observation.disclaimer).toContain("not graded");
  });
});
