import type { CookieAuditResult, Finding } from "./types";

/**
 * Audit cookies from the Set-Cookie header(s).
 */
export function auditCookies(headers: Headers): { cookies: CookieAuditResult[]; findings: Finding[] } {
  const findings: Finding[] = [];
  const cookies: CookieAuditResult[] = [];

  // Set-Cookie can appear multiple times
  const nativeCookies = headers.getSetCookie?.() ?? [];
  const rawCookies = nativeCookies.length ? nativeCookies : fallbackSetCookies(headers.get("set-cookie"));

  for (const raw of rawCookies) {
    const parsed = parseCookie(raw);
    cookies.push(parsed);

    const issues: string[] = [];
    if (!parsed.secure) {
      issues.push("Missing Secure flag: cookie can be sent over unencrypted HTTP");
      findings.push({
        id: `cookie-insecure-${parsed.name}`,
        severity: "medium",
        category: "cookie",
        title: `Cookie "${parsed.name}" Missing Secure Flag`,
        detail: `The cookie "${parsed.name}" is set without the Secure attribute, allowing transmission over unencrypted connections.`,
        evidence: redactCookieEvidence(raw),
        recommendation: "Add the Secure attribute to the Set-Cookie directive.",
      });
    }
    if (!parsed.httpOnly) {
      issues.push("Missing HttpOnly flag: cookie accessible via JavaScript (XSS risk)");
      findings.push({
        id: `cookie-no-httponly-${parsed.name}`,
        severity: "medium",
        category: "cookie",
        title: `Cookie "${parsed.name}" Missing HttpOnly Flag`,
        detail: `The cookie "${parsed.name}" is set without the HttpOnly attribute, making it accessible to JavaScript and vulnerable to theft via XSS.`,
        evidence: redactCookieEvidence(raw),
        recommendation: "Add the HttpOnly attribute to the Set-Cookie directive.",
      });
    }
    if (!parsed.sameSite || parsed.sameSite === "None") {
      issues.push("Missing or weak SameSite attribute: cookie may be sent in cross-site requests (CSRF risk)");
      findings.push({
        id: `cookie-weak-samesite-${parsed.name}`,
        severity: "low",
        category: "cookie",
        title: `Cookie "${parsed.name}" Has Weak SameSite Setting`,
        detail: `The cookie "${parsed.name}" has SameSite=${parsed.sameSite || "(not set)"}, which allows cross-site transmission.`,
        evidence: redactCookieEvidence(raw),
        recommendation: "Set SameSite=Strict or SameSite=Lax on session cookies.",
      });
    }
  }

  return { cookies, findings };
}

function fallbackSetCookies(value: string | null): string[] {
  if (!value) return [];
  // Cloudflare exposes getSetCookie(). Older runtimes may collapse repeated
  // values into one header; split only at the next cookie name so Expires
  // dates remain intact.
  return value.split(/,\s*(?=[^;,=\s]+\s*=)/).map((item) => item.trim()).filter(Boolean);
}

/** Keep cookie names and policy attributes useful while never storing values. */
export function redactCookieEvidence(raw: string): string {
  const parts = raw.split(";").map((part) => part.trim()).filter(Boolean);
  if (parts.length === 0) return "Set-Cookie: [redacted]";
  const name = parts[0].split("=", 1)[0].trim() || "[unnamed]";
  const attributes = parts.slice(1).map((attribute) => {
    const equal = attribute.indexOf("=");
    if (equal < 0) return attribute;
    const key = attribute.slice(0, equal).trim();
    const lower = key.toLowerCase();
    // These attributes are policy metadata rather than bearer material.
    if (["path", "domain", "expires", "max-age", "samesite", "priority", "partitioned"].includes(lower)) {
      return `${key}=${attribute.slice(equal + 1).trim()}`;
    }
    return `${key}=[redacted]`;
  });
  return `Set-Cookie: ${name}=[redacted]${attributes.length ? `; ${attributes.join("; ")}` : ""}`;
}

function parseCookie(raw: string): CookieAuditResult {
  const parts = raw.split(";").map((p) => p.trim());
  const [nameValue, ...attrs] = parts;
  const eqIndex = nameValue.indexOf("=");
  const name = eqIndex >= 0 ? nameValue.slice(0, eqIndex) : nameValue;
  const issues: string[] = [];

  let secure = false;
  let httpOnly = false;
  let sameSite: string | null = null;
  let domain: string | null = null;
  let path: string | null = null;
  let expires: string | null = null;

  for (const attr of attrs) {
    const lower = attr.toLowerCase();
    if (lower === "secure") secure = true;
    else if (lower === "httponly") httpOnly = true;
    else if (lower.startsWith("samesite=")) sameSite = attr.slice("samesite=".length);
    else if (lower.startsWith("domain=")) domain = attr.slice("domain=".length);
    else if (lower.startsWith("path=")) path = attr.slice("path=".length);
    else if (lower.startsWith("expires=")) expires = attr.slice("expires=".length);
  }

  return {
    name,
    secure,
    httpOnly,
    sameSite,
    domain,
    path,
    expires,
    issues,
  };
}
