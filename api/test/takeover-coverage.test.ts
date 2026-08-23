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

vi.mock("../src/ssl", () => ({ inspectSsl: vi.fn() }));
vi.mock("../src/paths", () => ({ probePaths: vi.fn() }));
vi.mock("../src/headers-audit", () => ({ auditHeaders: vi.fn() }));
vi.mock("../src/fingerprint", () => ({ fingerprint: vi.fn() }));
vi.mock("../src/cookies", () => ({ auditCookies: vi.fn() }));
vi.mock("../src/cors", () => ({ testCors: vi.fn() }));
vi.mock("../src/secrets", () => ({ scanForSecrets: vi.fn() }));
vi.mock("../src/wordpress", () => ({ scanWordPress: vi.fn() }));
vi.mock("../src/methods", () => ({ probeMethods: vi.fn() }));

const originalFetch = globalThis.fetch;

const PAGE = "<!doctype html><html><head><title>Example</title></head><body>ok</body></html>";

function htmlResponse(): Response {
  return new Response(PAGE, {
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
  });
}

describe("takeover coverage honesty", () => {
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

    globalThis.fetch = vi.fn(async () => htmlResponse());
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("records failed takeover coverage when the CT provider errors instead of reporting measured zero", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).includes("crt.sh")) {
        return new Response("upstream error", { status: 502 });
      }
      return htmlResponse();
    });

    const report = await analyzeUrl(
      "https://example.com",
      7,
      {},
      () => {},
      { probePaths: false, checkTakeover: true },
    );

    expect(report.coverage.takeover.requested).toBe(true);
    expect(report.coverage.takeover.status).toBe("failed");
    expect(report.coverage.takeover.detail).toContain("Certificate Transparency");
  });

  it("keeps measured zero-subdomain coverage when CT answers successfully with no entries", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).includes("crt.sh")) {
        return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
      }
      return htmlResponse();
    });

    const report = await analyzeUrl(
      "https://example.com",
      7,
      {},
      () => {},
      { probePaths: false, checkTakeover: true },
    );

    expect(report.coverage.takeover.status).toBe("measured");
    expect(report.coverage.takeover.detail).toContain("0 subdomain(s)");
  });

  it("records failed takeover coverage when the CT provider is unreachable", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).includes("crt.sh")) {
        throw new TypeError("fetch threw");
      }
      return htmlResponse();
    });

    const report = await analyzeUrl(
      "https://example.com",
      7,
      {},
      () => {},
      { probePaths: false, checkTakeover: true },
    );

    expect(report.coverage.takeover.status).toBe("failed");
  });
});
