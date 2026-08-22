import { describe, it, expect } from "vitest";
import { auditHeaders } from "../src/headers-audit";

function makeHeaders(entries: Record<string, string>): Headers {
  return new Headers(entries);
}

describe("auditHeaders", () => {
  it("returns all findings when no security headers are present", () => {
    const headers = makeHeaders({});
    const { result, findings } = auditHeaders(headers);

    expect(result.hsts.present).toBe(false);
    expect(result.csp.present).toBe(false);
    expect(result.xContentTypeOptions.present).toBe(false);
    expect(result.xFrameOptions.present).toBe(false);
    expect(result.referrerPolicy.present).toBe(false);
    expect(result.permissionsPolicy.present).toBe(false);

    // Should flag missing HSTS (high), missing CSP (high), missing X-Content-Type-Options (medium),
    // missing clickjacking protection (medium), missing Referrer-Policy (low),
    // missing Permissions-Policy (low), missing X-XSS-Protection (info)
    const severities = findings.map((f) => f.severity);
    expect(severities).toContain("high");
    expect(severities).toContain("medium");
    expect(severities).toContain("low");
    expect(severities).toContain("info");
  });

  it("passes with all security headers properly configured", () => {
    const headers = makeHeaders({
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
      "content-security-policy": "default-src 'self'; script-src 'self'",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=(), microphone=(), geolocation=()",
    });
    const { result, findings } = auditHeaders(headers);

    expect(result.hsts.present).toBe(true);
    expect(result.hsts.maxAge).toBe(31536000);
    expect(result.hsts.includeSubDomains).toBe(true);
    expect(result.hsts.preload).toBe(true);
    expect(result.csp.present).toBe(true);
    expect(result.csp.hasUnsafeInline).toBe(false);
    expect(result.csp.hasDefaultSrc).toBe(true);
    expect(result.xContentTypeOptions.present).toBe(true);

    // Should only have the info-level X-XSS-Protection finding
    const nonInfo = findings.filter((f) => f.severity !== "info");
    expect(nonInfo.length).toBe(0);
  });

  it("flags weak HSTS max-age", () => {
    const headers = makeHeaders({
      "strict-transport-security": "max-age=3600",
    });
    const { result, findings } = auditHeaders(headers);

    expect(result.hsts.maxAge).toBe(3600);
    const weakHsts = findings.find((f) => f.title.includes("Weak HSTS"));
    expect(weakHsts).toBeTruthy();
    expect(weakHsts!.severity).toBe("medium");
  });

  it("does not treat the optional preload directive as required", () => {
    const headers = makeHeaders({
      "strict-transport-security": "max-age=31536000; includeSubDomains",
    });
    const { result, findings } = auditHeaders(headers);

    expect(result.hsts.preload).toBe(false);
    expect(findings.some((finding) => finding.title.includes("Weak HSTS"))).toBe(false);
  });

  it("flags CSP with unsafe-inline", () => {
    const headers = makeHeaders({
      "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'",
    });
    const { result, findings } = auditHeaders(headers);

    expect(result.csp.hasUnsafeInline).toBe(true);
    const unsafeFinding = findings.find((f) => f.title.includes("unsafe-inline"));
    expect(unsafeFinding).toBeTruthy();
    expect(unsafeFinding!.severity).toBe("medium");
  });

  it("flags CSP with unsafe-eval", () => {
    const headers = makeHeaders({
      "content-security-policy": "default-src 'self'; script-src 'unsafe-eval'",
    });
    const { result, findings } = auditHeaders(headers);

    expect(result.csp.hasUnsafeEval).toBe(true);
    const evalFinding = findings.find((f) => f.title.includes("unsafe-eval"));
    expect(evalFinding).toBeTruthy();
  });

  it("flags CSP with wildcard", () => {
    const headers = makeHeaders({
      "content-security-policy": "default-src *",
    });
    const { result, findings } = auditHeaders(headers);

    expect(result.csp.hasWildcard).toBe(true);
    const wildcardFinding = findings.find((f) => f.title.includes("Wildcard"));
    expect(wildcardFinding).toBeTruthy();
  });

  it("flags server version disclosure", () => {
    const headers = makeHeaders({
      "server": "nginx/1.24.0",
    });
    const { result, findings } = auditHeaders(headers);

    expect(result.serverRevealsVersion).toBe(true);
    const serverFinding = findings.find((f) => f.title.includes("Server Header"));
    expect(serverFinding).toBeTruthy();
    expect(serverFinding!.severity).toBe("medium");
  });

  it("flags X-Powered-By disclosure", () => {
    const headers = makeHeaders({
      "x-powered-by": "Express",
    });
    const { result, findings } = auditHeaders(headers);

    expect(result.poweredByRevealsTech).toBe(true);
    const poweredFinding = findings.find((f) => f.title.includes("X-Powered-By"));
    expect(poweredFinding).toBeTruthy();
  });

  it("accepts CSP frame-ancestors as clickjacking protection", () => {
    const headers = makeHeaders({
      "content-security-policy": "frame-ancestors 'none'",
    });
    const { findings } = auditHeaders(headers);

    const clickjackFinding = findings.find((f) => f.title.includes("Clickjacking"));
    expect(clickjackFinding).toBeFalsy();
  });

  it("does not flag server version when no version number", () => {
    const headers = makeHeaders({
      "server": "nginx",
    });
    const { result, findings } = auditHeaders(headers);

    expect(result.serverRevealsVersion).toBe(false);
    const serverFinding = findings.find((f) => f.title.includes("Server Header"));
    expect(serverFinding).toBeFalsy();
  });
});
