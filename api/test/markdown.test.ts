import { describe, expect, it } from "vitest";
import { reportToMarkdown } from "../src/markdown";
import type { ScanReport } from "../src/types";

function reportFixture(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    schemaVersion: 2,
    id: "abcdefghijklmnop",
    requestedUrl: "https://example.com/",
    hostname: "example.com",
    status: "complete",
    createdAt: "2026-08-23T00:00:00.000Z",
    expiresAt: "2026-09-06T00:00:00.000Z",
    totalDurationMs: 12_340,
    observation: {
      vantage: "cloudflare-edge",
      colo: "DUB",
      country: "IE",
      disclaimer: "Observations are from the Cloudflare edge.",
    },
    outbound: {
      maxSubrequests: 46, maxConcurrent: 6, maxDurationMs: 25_000,
      requestsAttempted: 29, requestsSucceeded: 27, requestsFailed: 1, requestsSkipped: 0,
      activePeak: 6, bodyBytes: 483_211, truncatedBodies: 1, redirects: [],
    },
    coverage: {
      mainFetch: { status: "measured", detail: "GET response received with HTTP 200." },
      headers: { status: "measured", detail: "Security headers were audited from the main GET response." },
      tlsProtocolCipher: { status: "unavailable", detail: "Not assessed." },
      certificateEvidence: { status: "measured", detail: "crt.sh evidence observed." },
      dns: { status: "measured", detail: "Confirmed 1 address record(s)." },
      cookies: { status: "measured", detail: "Audited 1 cookie(s)." },
      paths: { status: "skipped", detail: "Not enabled for this scan.", requested: false },
      cors: { status: "measured", detail: "Probes completed." },
      secrets: { status: "skipped", detail: "Not enabled for this scan.", requested: false },
      wordpress: { status: "skipped", detail: "Target is not WordPress.", requested: false },
      methods: { status: "measured", detail: "Reconnaissance completed." },
      takeover: { status: "skipped", detail: "Not enabled for this scan.", requested: false },
      criticalGaps: [],
    },
    findings: [
      {
        id: "missing-header-hsts",
        severity: "high",
        category: "missing-header",
        title: "Strict-Transport-Security missing",
        detail: "Browsers are not told to enforce HTTPS.",
        evidence: "No Strict-Transport-Security header on GET /",
        recommendation: "Send Strict-Transport-Security once HTTPS-only is confirmed.",
      },
      {
        id: "cookie-sid-flags",
        severity: "medium",
        category: "cookie",
        title: "Session cookie lacks Secure, HttpOnly, and SameSite",
        detail: "The sid cookie is readable from scripts.",
        evidence: "Set-Cookie: sid=...; Path=/",
        recommendation: "Set Secure, HttpOnly, and SameSite=Lax on the session cookie.",
      },
    ],
    summary: { grade: "D", critical: 0, high: 1, medium: 1, low: 0, info: 0 },
    ...overrides,
  } as ScanReport;
}

describe("report markdown rendering", () => {
  it("renders grade, meta, coverage, and findings in severity order", () => {
    const markdown = reportToMarkdown(reportFixture());
    expect(markdown).toContain("# VulnScope report: example.com");
    expect(markdown).toContain("- Grade: D");
    expect(markdown).toContain("- Target: https://example.com/");
    expect(markdown).toContain("- Report ID: `abcdefghijklmnop`");
    expect(markdown).toContain(`- Report link: https://vulnscope.illek.ie/#abcdefghijklmnop`);
    expect(markdown).toContain("- Duration: 12.3s");
    expect(markdown).toContain("- Outbound work: 29/46 requests");
    expect(markdown.indexOf("### High:")).toBeGreaterThan(-1);
    expect(markdown.indexOf("### High:")).toBeLessThan(markdown.indexOf("### Medium:"));
    expect(markdown).toContain("| Main Fetch | measured | GET response received with HTTP 200. |");
    expect(markdown).toContain("**Fix:** Send Strict-Transport-Security once HTTPS-only is confirmed.");
    expect(markdown.endsWith("\n")).toBe(true);
  });

  it("keeps evidence containing backticks inside an unbreakable code fence", () => {
    const markdown = reportToMarkdown(reportFixture({
      findings: [{
        id: "evidence-with-fence",
        severity: "low",
        category: "information-disclosure",
        title: "Odd evidence",
        detail: "detail",
        evidence: "```\nalready fenced\n```",
        recommendation: "fix",
      }],
      summary: { grade: "B", critical: 0, high: 0, medium: 0, low: 1, info: 0 },
    }));
    const fence = markdown.split("\n").find((line) => line.startsWith("````"));
    expect(fence).toBe("````");
  });

  it("escapes pipes and newlines inside coverage table cells", () => {
    const markdown = reportToMarkdown(reportFixture({
      coverage: {
        ...(reportFixture().coverage),
        dns: { status: "partial", detail: "Resolver A failed\nwith | separators" },
      },
    }));
    expect(markdown).toContain("Resolver A failed with \\| separators");
  });

  it("lists coverage gaps for INCOMPLETE reports instead of hiding them", () => {
    const fixture = reportFixture({ summary: { grade: "INCOMPLETE", critical: 0, high: 0, medium: 0, low: 0, info: 0 } });
    fixture.coverage.mainFetch = { status: "failed", detail: "GET failed: timeout" };
    fixture.coverage.criticalGaps = ["mainFetch: GET failed: timeout"];
    const markdown = reportToMarkdown(fixture);
    expect(markdown).toContain("- Coverage gap: mainFetch: GET failed: timeout");
  });

  it("states when a report produced no findings", () => {
    const markdown = reportToMarkdown(reportFixture({
      findings: [],
      summary: { grade: "A", critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    }));
    expect(markdown).toContain("## Findings");
    expect(markdown).toContain("No findings were generated.");
  });
});
