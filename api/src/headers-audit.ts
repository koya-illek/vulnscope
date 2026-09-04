import type { Finding, HeaderAuditResult } from "./types";
import { redactHeaderValue } from "./security";

/**
 * Deep analysis of security headers from the main page response.
 * Returns the audit result and a list of findings.
 */
export function auditHeaders(headers: Headers): { result: HeaderAuditResult; findings: Finding[] } {
  const findings: Finding[] = [];

  // --- HSTS ---
  const rawHsts = redactHeaderValue("strict-transport-security", headers.get("strict-transport-security") || "");
  const hstsMaxAge = parseMaxAge(rawHsts);
  const hstsPresent = Boolean(rawHsts);
  const hstsResult: HeaderAuditResult["hsts"] = {
    present: hstsPresent,
    raw: hstsPresent ? rawHsts : null,
    maxAge: hstsMaxAge,
    includeSubDomains: /includeSubDomains/i.test(rawHsts),
    preload: /preload/i.test(rawHsts),
  };

  if (!hstsPresent) {
    findings.push(makeFinding("missing-header", "high", "Missing Strict-Transport-Security Header",
      "The HSTS header is not set. Without it, users may be vulnerable to SSL stripping attacks on first visit.",
      "Strict-Transport-Security header is absent from the response.",
      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"));
  } else if (hstsMaxAge === null) {
    findings.push(makeFinding("missing-header", "medium", "Invalid HSTS max-age",
      "The HSTS header is present without a numeric max-age, so browsers cannot enforce a useful policy.",
      `Strict-Transport-Security: ${rawHsts}`,
      "Set Strict-Transport-Security: max-age=31536000; includeSubDomains."));
  } else if (hstsMaxAge < 31536000) {
    findings.push(makeFinding("missing-header", "medium", "Weak HSTS max-age",
      "The HSTS max-age is less than 1 year (31536000 seconds).",
      `max-age=${hstsMaxAge}`,
      "Increase max-age to at least 31536000 (1 year)."));
  }

  // --- CSP ---
  const rawCsp = redactHeaderValue("content-security-policy", headers.get("content-security-policy") || "");
  const cspPresent = Boolean(rawCsp);
  const hasUnsafeInline = /'unsafe-inline'|unsafe-inline/i.test(rawCsp);
  const hasUnsafeEval = /'unsafe-eval'|unsafe-eval/i.test(rawCsp);
  const hasWildcard = /(?:^|[\s;])(?:[a-z][a-z0-9+.-]*:\/\/)?\*(?=$|[\s;])/i.test(rawCsp);
  const hasDefaultSrc = /default-src/i.test(rawCsp);

  const cspResult: HeaderAuditResult["csp"] = {
    present: cspPresent,
    hasUnsafeInline,
    hasUnsafeEval,
    hasWildcard,
    hasDefaultSrc,
    raw: cspPresent ? rawCsp : null,
  };

  if (!cspPresent) {
    findings.push(makeFinding("missing-header", "high", "Missing Content-Security-Policy Header",
      "CSP is the most effective client-side XSS mitigation available. Without it, the page is vulnerable to injected scripts.",
      "Content-Security-Policy header is absent.",
      "Add a Content-Security-Policy header. Start with: default-src 'self'; script-src 'self'; object-src 'none'"));
  } else {
    if (hasUnsafeInline) {
      findings.push(makeFinding("missing-header", "medium", "CSP Contains unsafe-inline",
        "The CSP allows inline scripts/styles, significantly weakening XSS protection.",
        "Content-Security-Policy includes 'unsafe-inline'",
        "Remove 'unsafe-inline' and use nonces or hashes for inline scripts/styles."));
    }
    if (hasUnsafeEval) {
      findings.push(makeFinding("missing-header", "medium", "CSP Contains unsafe-eval",
        "The CSP allows eval(), which can be exploited for code injection.",
        "Content-Security-Policy includes 'unsafe-eval'",
        "Remove 'unsafe-eval' from the CSP."));
    }
    if (hasWildcard) {
      findings.push(makeFinding("missing-header", "medium", "CSP Contains Wildcard Directive",
        "The CSP uses wildcard (*) sources, allowing content from any origin.",
        "Content-Security-Policy includes wildcard (*) source",
        "Replace wildcard sources with explicit allowed origins."));
    }
    if (!hasDefaultSrc) {
      findings.push(makeFinding("missing-header", "low", "CSP Missing default-src Directive",
        "Without a default-src fallback, browsers use permissive defaults for unlisted directive types.",
        "Content-Security-Policy has no default-src directive.",
        "Add default-src 'self' as a fallback directive."));
    }
  }

  // --- X-Content-Type-Options ---
  const rawXcto = redactHeaderValue("x-content-type-options", headers.get("x-content-type-options") || "");
  const xctoPresent = Boolean(rawXcto);
  const xctoResult: HeaderAuditResult["xContentTypeOptions"] = {
    present: xctoPresent,
    value: xctoPresent ? rawXcto : null,
  };

  if (!xctoPresent || !/^nosniff$/i.test(rawXcto.trim())) {
    findings.push(makeFinding("missing-header", "medium", "Missing or Invalid X-Content-Type-Options",
      "Without nosniff, browsers may MIME-sniff content and execute non-executable files.",
      xctoPresent ? `X-Content-Type-Options: ${rawXcto}` : "Header is absent.",
      "Add: X-Content-Type-Options: nosniff"));
  }

  // --- X-Frame-Options (or CSP frame-ancestors) ---
  const rawXfo = redactHeaderValue("x-frame-options", headers.get("x-frame-options") || "");
  const cspFrameAncestors = /frame-ancestors/i.test(rawCsp);
  const xfoPresent = Boolean(rawXfo);
  const xfoResult: HeaderAuditResult["xFrameOptions"] = {
    present: xfoPresent,
    value: xfoPresent ? rawXfo : null,
  };

  const validXfo = /^(?:DENY|SAMEORIGIN)$/i.test(rawXfo.trim());
  if (xfoPresent && !validXfo && !cspFrameAncestors) {
    findings.push(makeFinding("missing-header", "medium", "Invalid X-Frame-Options",
      "The X-Frame-Options value is not DENY or SAMEORIGIN and does not provide a reliable clickjacking boundary.",
      `X-Frame-Options: ${rawXfo}`,
      "Use X-Frame-Options: DENY or SAMEORIGIN, or define CSP frame-ancestors."));
  }
  if (!xfoPresent && !cspFrameAncestors) {
    findings.push(makeFinding("missing-header", "medium", "Missing Clickjacking Protection",
      "Neither X-Frame-Options nor CSP frame-ancestors is set. The page can be embedded in an iframe for clickjacking.",
      "X-Frame-Options and CSP frame-ancestors are both absent.",
      "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."));
  }

  // --- Referrer-Policy ---
  const rawReferrer = redactHeaderValue("referrer-policy", headers.get("referrer-policy") || "");
  const referrerPresent = Boolean(rawReferrer);
  const strictReferrer = /strict-origin-when-cross-origin|no-referrer|same-origin/i.test(rawReferrer);
  const referrerResult: HeaderAuditResult["referrerPolicy"] = {
    present: referrerPresent,
    value: referrerPresent ? rawReferrer : null,
  };

  if (!referrerPresent) {
    findings.push(makeFinding("missing-header", "low", "Missing Referrer-Policy",
      "Without a Referrer-Policy, browsers default to strict-origin-when-cross-origin, but older browsers may leak full URLs.",
      "Referrer-Policy header is absent.",
      "Add: Referrer-Policy: strict-origin-when-cross-origin"));
  } else if (!strictReferrer) {
    findings.push(makeFinding("missing-header", "low", "Weak Referrer-Policy",
      "The Referrer-Policy allows more information disclosure than necessary.",
      `Referrer-Policy: ${rawReferrer}`,
      "Use a stricter policy like strict-origin-when-cross-origin or no-referrer."));
  }

  // --- Permissions-Policy ---
  const rawPerms = redactHeaderValue("permissions-policy", headers.get("permissions-policy") || "");
  const permsPresent = Boolean(rawPerms);
  const permsResult: HeaderAuditResult["permissionsPolicy"] = {
    present: permsPresent,
    value: permsPresent ? rawPerms : null,
  };

  if (!permsPresent) {
    findings.push(makeFinding("missing-header", "low", "Missing Permissions-Policy",
      "Without a Permissions-Policy, browser features (camera, microphone, geolocation) are accessible by default.",
      "Permissions-Policy header is absent.",
      "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"));
  }

  // --- X-XSS-Protection (deprecated, info only) ---
  const rawXss = redactHeaderValue("x-xss-protection", headers.get("x-xss-protection") || "");
  const xssPresent = Boolean(rawXss);
  const xssResult: HeaderAuditResult["xXssProtection"] = {
    present: xssPresent,
    value: xssPresent ? rawXss : null,
  };


  // --- Server header reveals version ---
  const rawServer = redactHeaderValue("server", headers.get("server") || "");
  const serverRevealsVersion = /\d/.test(rawServer);
  const rawPoweredBy = redactHeaderValue("x-powered-by", headers.get("x-powered-by") || "");
  const poweredByRevealsTech = Boolean(rawPoweredBy);

  if (serverRevealsVersion) {
    findings.push(makeFinding("information-disclosure", "medium", "Server Header Reveals Version",
      "The Server header exposes software version information, helping attackers target known vulnerabilities.",
      `Server: ${rawServer}`,
      "Configure the web server to suppress version information."));
  }

  if (poweredByRevealsTech) {
    findings.push(makeFinding("information-disclosure", "medium", "X-Powered-By Reveals Technology",
      "The X-Powered-By header discloses the technology stack, aiding targeted attacks.",
      `X-Powered-By: ${rawPoweredBy}`,
      "Remove the X-Powered-By header in your application server configuration."));
  }

  const result: HeaderAuditResult = {
    hsts: hstsResult,
    csp: cspResult,
    xContentTypeOptions: xctoResult,
    xFrameOptions: xfoResult,
    referrerPolicy: referrerResult,
    permissionsPolicy: permsResult,
    xXssProtection: xssResult,
    serverRevealsVersion,
    poweredByRevealsTech,
  };

  return { result, findings };
}

function parseMaxAge(hsts: string): number | null {
  const match = hsts.match(/max-age\s*=\s*(\d+)/i);
  return match ? Number.parseInt(match[1], 10) : null;
}

function makeFinding(
  category: Finding["category"],
  severity: Finding["severity"],
  title: string,
  detail: string,
  evidence: string,
  recommendation: string,
): Finding {
  return {
    id: `${category}-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`,
    severity,
    category,
    title,
    detail,
    evidence,
    recommendation,
  };
}
