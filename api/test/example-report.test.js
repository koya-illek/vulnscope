import { describe, expect, it } from "vitest";
import "../../web/example-report.js";

const report = globalThis.VulnScopeExample.report();

const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const COVERAGE_STATUSES = new Set(["measured", "unavailable", "skipped", "failed", "partial"]);
const COVERAGE_PHASES = [
  "mainFetch",
  "headers",
  "tlsProtocolCipher",
  "certificateEvidence",
  "dns",
  "cookies",
  "paths",
  "cors",
  "secrets",
  "wordpress",
  "methods",
  "takeover",
];

describe("VulnScope example report fixture", () => {
  it("satisfies the stored-report field shapes the renderer trusts", () => {
    expect(report.schemaVersion).toBe(2);
    expect(report.id).toMatch(/^[A-Za-z0-9_-]{16}$/);
    expect(typeof report.hostname).toBe("string");
    expect(typeof report.requestedUrl).toBe("string");
    expect(["complete", "partial", "failed"]).toContain(report.status);
    expect(Number.isFinite(report.totalDurationMs)).toBe(true);

    for (const phase of COVERAGE_PHASES) {
      const entry = report.coverage[phase];
      expect(entry, `coverage.${phase}`).toBeTruthy();
      expect(COVERAGE_STATUSES.has(entry.status), `coverage.${phase}.status`).toBe(true);
      expect(typeof entry.detail, `coverage.${phase}.detail`).toBe("string");
    }
    expect(Array.isArray(report.coverage.criticalGaps)).toBe(true);

    for (const finding of report.findings) {
      expect(SEVERITIES.has(finding.severity)).toBe(true);
      for (const field of ["id", "category", "title", "detail", "evidence", "recommendation"]) {
        expect(typeof finding[field], `finding ${finding.id} ${field}`).toBe("string");
        expect(finding[field].length, `finding ${finding.id} ${field}`).toBeGreaterThan(0);
      }
    }

    const counters = [
      "maxSubrequests",
      "maxConcurrent",
      "maxDurationMs",
      "requestsAttempted",
      "requestsSucceeded",
      "requestsFailed",
      "requestsSkipped",
      "activePeak",
      "bodyBytes",
      "truncatedBodies",
    ];
    for (const counter of counters) {
      expect(Number.isFinite(report.outbound[counter]), `outbound.${counter}`).toBe(true);
      expect(report.outbound[counter]).toBeGreaterThanOrEqual(0);
    }
    expect(Array.isArray(report.outbound.redirects)).toBe(true);
  });

  it("keeps summary counts and grade consistent with its findings", () => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of report.findings) counts[finding.severity] += 1;
    expect(report.summary).toEqual({ ...counts, grade: "F" });

    // Mirror calculateGrade's ordering so a fixture edit that changes
    // severities without recomputing the grade fails here.
    const expected =
      counts.critical > 0 ? "F"
        : counts.high > 0 ? "D"
          : counts.medium > 3 ? "C"
            : counts.low > 3 ? "B"
              : "A";
    expect(report.summary.grade).toBe(expected);
  });

  it("never claims to be a scan of a real site", () => {
    expect(report.hostname.endsWith(".example")).toBe(true);
    expect(new URL(report.requestedUrl).hostname).toBe(report.hostname);
    // The grade-blocking phases must be measured so the sample presents as a
    // complete report rather than an INCOMPLETE one.
    expect(report.coverage.mainFetch.status).toBe("measured");
    expect(report.coverage.headers.status).toBe("measured");
    expect(report.coverage.criticalGaps).toEqual([]);
  });
});
