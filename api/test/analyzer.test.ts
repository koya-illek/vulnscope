import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { analyzeUrl } from "../src/analyzer";
import { auditCookies } from "../src/cookies";
import { testCors } from "../src/cors";
import { inspectDns } from "../src/dns";
import { fingerprint } from "../src/fingerprint";
import { auditHeaders } from "../src/headers-audit";
import { probeMethods } from "../src/methods";
import { probePaths } from "../src/paths";
import { scanForSecrets } from "../src/secrets";
import { inspectSsl } from "../src/ssl";
import { scanWordPress } from "../src/wordpress";

vi.mock("../src/dns", () => ({
  inspectDns: vi.fn(),
  queryDns: vi.fn(),
}));

vi.mock("../src/ssl", () => ({
  inspectSsl: vi.fn(),
}));

vi.mock("../src/paths", () => ({
  probePaths: vi.fn(),
}));

vi.mock("../src/headers-audit", () => ({
  auditHeaders: vi.fn(),
}));

vi.mock("../src/fingerprint", () => ({
  fingerprint: vi.fn(),
}));

vi.mock("../src/cookies", () => ({
  auditCookies: vi.fn(),
}));

vi.mock("../src/cors", () => ({
  testCors: vi.fn(),
}));

vi.mock("../src/secrets", () => ({
  scanForSecrets: vi.fn(),
}));

vi.mock("../src/wordpress", () => ({
  scanWordPress: vi.fn(),
}));

vi.mock("../src/methods", () => ({
  probeMethods: vi.fn(),
}));

const originalFetch = globalThis.fetch;

describe("analyzeUrl schema-v2 grading coverage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();

    vi.mocked(inspectDns).mockResolvedValue([
      {
        resolver: "mock-resolver",
        name: "example.com",
        type: "A",
        status: 0,
        authenticatedData: false,
        answers: [{ name: "example.com", type: "A", ttl: 60, data: "93.184.216.34" }],
        elapsedMs: 1,
        evidenceKind: "dns_observation",
      },
    ]);
    vi.mocked(inspectSsl).mockResolvedValue({
      protocol: null,
      cipher: null,
      issuer: null,
      subject: null,
      validFrom: null,
      validTo: null,
      daysUntilExpiry: null,
      authorityKeyIdentifier: null,
      certificateEvidence: {
        source: "crt.sh",
        status: "unavailable",
        limitation: "Certificate Transparency entries are historical observations and do not prove the certificate currently presented by the target.",
        observedAt: null,
      },
    });
    vi.mocked(probePaths).mockResolvedValue([]);
    vi.mocked(auditHeaders).mockReturnValue({
      result: {
        hsts: { present: true, raw: "max-age=31536000; includeSubDomains", maxAge: 31536000, includeSubDomains: true, preload: false },
        csp: { present: true, hasUnsafeInline: false, hasUnsafeEval: false, hasWildcard: false, hasDefaultSrc: true, raw: "default-src 'self'" },
        xContentTypeOptions: { present: true, value: "nosniff" },
        xFrameOptions: { present: true, value: "DENY" },
        referrerPolicy: { present: true, value: "strict-origin-when-cross-origin" },
        permissionsPolicy: { present: true, value: "camera=()" },
        xXssProtection: { present: false, value: null },
        serverRevealsVersion: false,
        poweredByRevealsTech: false,
      },
      findings: [],
    });
    vi.mocked(fingerprint).mockReturnValue({
      result: { server: null, poweredBy: null, cms: null, framework: null, languages: [] },
      findings: [],
    });
    vi.mocked(auditCookies).mockReturnValue({ cookies: [], findings: [] });
    vi.mocked(testCors).mockResolvedValue({
      result: {
        testedOrigin: "https://evil.example",
        acaoGet: null,
        acaoOptions: null,
        acacGet: null,
        acacOptions: null,
        reflectsOrigin: false,
        wildcardWithCredentials: false,
        vulnerable: false,
        evidence: "No ACAO reflection observed",
      },
      findings: [],
    });
    vi.mocked(scanForSecrets).mockResolvedValue([]);
    vi.mocked(scanWordPress).mockResolvedValue([]);
    vi.mocked(probeMethods).mockResolvedValue({ methods: [], traceVulnerable: false });

    globalThis.fetch = vi.fn(async () => new Response(
      "<!doctype html><html><head><title>Example</title></head><body>ok</body></html>",
      {
        status: 200,
        headers: {
          "content-type": "text/html; charset=utf-8",
          "strict-transport-security": "max-age=31536000; includeSubDomains",
          "content-security-policy": "default-src 'self'",
          "x-content-type-options": "nosniff",
          "x-frame-options": "DENY",
          "referrer-policy": "strict-origin-when-cross-origin",
          "permissions-policy": "camera=()",
        },
      },
    ));
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("produces a gradeable schema-v2 report when only the HTTP surface is measured", async () => {
    const report = await analyzeUrl("https://example.com", 7);

    expect(report.schemaVersion).toBe(2);
    expect(report.status).toBe("complete");
    expect(report.summary.grade).toBe("A");
    expect(report.coverage.mainFetch).toMatchObject({ status: "measured" });
    expect(report.coverage.headers).toMatchObject({ status: "measured" });
    expect(report.coverage.tlsProtocolCipher).toMatchObject({
      status: "unavailable",
    });
    expect(report.coverage.tlsProtocolCipher.detail).toContain("not assessed");
    expect(report.coverage.certificateEvidence).toMatchObject({
      status: "unavailable",
    });
    expect(report.coverage.certificateEvidence.detail).toContain("historical");
    expect(report.coverage.criticalGaps).toEqual([]);
    expect(report.findings).toEqual([]);
  });

  it("does not grade an HTTP error response as the target page", async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response("upstream unavailable", { status: 522 }),
    );

    const report = await analyzeUrl("https://example.com", 7);

    expect(report.status).toBe("failed");
    expect(report.summary.grade).toBe("INCOMPLETE");
    expect(report.coverage.mainFetch).toMatchObject({
      status: "failed",
    });
    expect(report.coverage.mainFetch.detail).toContain("HTTP 522");
    expect(report.coverage.headers).toMatchObject({ status: "skipped" });
    expect(
      report.findings.some((finding) => finding.category === "missing-header"),
    ).toBe(false);
  });

  it("does not run WordPress deep checks or TRACE unless opted in", async () => {
    vi.mocked(fingerprint).mockReturnValue({
      result: { server: null, poweredBy: null, cms: { name: "WordPress", version: "6.5" }, framework: null, languages: ["PHP"] },
      findings: [],
    });

    const report = await analyzeUrl("https://example.com", 7);

    expect(scanWordPress).not.toHaveBeenCalled();
    expect(report.coverage.wordpress).toMatchObject({
      status: "skipped",
      requested: false,
    });
    expect(report.coverage.wordpress.detail).toContain("not enabled");
    expect(probeMethods).toHaveBeenCalledWith(
      expect.any(String),
      expect.anything(),
      { probeTrace: false },
    );
    expect(report.coverage.methods.detail).toContain("OPTIONS Allow reconnaissance");
    expect(report.coverage.methods.detail).not.toContain("TRACE");
  });

  it("runs WordPress deep checks and TRACE when those options are enabled", async () => {
    vi.mocked(fingerprint).mockReturnValue({
      result: { server: null, poweredBy: null, cms: { name: "WordPress", version: "6.5" }, framework: null, languages: ["PHP"] },
      findings: [],
    });

    await analyzeUrl("https://example.com", 7, {}, () => {}, {
      probePaths: false,
      checkTakeover: false,
      checkWordPress: true,
      probeTrace: true,
    });

    expect(scanWordPress).toHaveBeenCalled();
    expect(probeMethods).toHaveBeenCalledWith(
      expect.any(String),
      expect.anything(),
      { probeTrace: true },
    );
  });
});
