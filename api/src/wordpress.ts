import type { WpFinding } from "./types";
import { discardResponseBody, safeFetch, readBoundedBody, USER_AGENT, type OutboundContext } from "./outbound";
import { redactUrlsInText } from "./security";

// ─── Individual checks ─────────────────────────────────────────────────────

const SCAN_TIMEOUT = 5000;
const WP_BODY_LIMIT = 128 * 1024;

async function wpFetch(url: string, context: OutboundContext | undefined, init: RequestInit = {}, followRedirects = true): Promise<Response> {
  return safeFetch(url, {
    ...init,
    baseUrl: context ? new URL(url) : undefined,
    followRedirects,
    phase: "wordpress",
    context,
    timeoutMs: SCAN_TIMEOUT,
  });
}

async function checkWpRestUsers(baseUrl: URL, context?: OutboundContext): Promise<WpFinding[]> {
  const findings: WpFinding[] = [];
  try {
    const url = new URL("/wp-json/wp/v2/users", baseUrl).toString();
    const response = await wpFetch(url, context, {
      headers: { Accept: "application/json", "User-Agent": USER_AGENT },
    });
    if (response.ok) {
      const body = (await readBoundedBody(response, WP_BODY_LIMIT, context, "wordpress")).text;
      const userCount = (body.match(/"slug"\s*:/g) || []).length;
      if (userCount > 0) {
        findings.push({
          check: "wp-rest-users",
          severity: "medium",
          title: "WordPress User Enumeration via REST API",
          detail: `The /wp-json/wp/v2/users endpoint exposed approximately ${userCount} user(s). Usernames aid brute-force and credential stuffing attacks.`,
          evidence: `GET /wp-json/wp/v2/users → ${response.status}, ~${userCount} users`,
          recommendation: "Restrict the WordPress REST API user endpoint or install a plugin that hides user enumeration.",
        });
      }
    } else {
      await discardResponseBody(response);
    }
  } catch { /* non-fatal */ }
  return findings;
}

async function checkWpRestApi(baseUrl: URL, context?: OutboundContext): Promise<WpFinding[]> {
  const findings: WpFinding[] = [];
  try {
    const url = new URL("/wp-json/", baseUrl).toString();
    const response = await wpFetch(url, context, {
      headers: { Accept: "application/json", "User-Agent": USER_AGENT },
    });
    if (response.ok) {
      const body = (await readBoundedBody(response, WP_BODY_LIMIT, context, "wordpress")).text;
      if (body.includes("WordPress") || body.includes("wp-json")) {
        findings.push({
          check: "wp-rest-api",
          severity: "low",
          title: "WordPress REST API Exposed",
          detail: "The WordPress REST API is publicly accessible, exposing site metadata including CMS version and available endpoints.",
          evidence: `GET /wp-json/ → ${response.status}, contains WordPress metadata`,
          recommendation: "If the REST API is not needed, disable it or restrict it to authenticated users.",
        });
      }
    } else {
      await discardResponseBody(response);
    }
  } catch { /* non-fatal */ }
  return findings;
}

async function checkAuthorEnumeration(baseUrl: URL, context?: OutboundContext): Promise<WpFinding[]> {
  const findings: WpFinding[] = [];
  const checks = [1, 2, 3].map(async (authorId) => {
    try {
      const url = new URL(`/?author=${authorId}`, baseUrl).toString();
      const response = await wpFetch(url, context, {
        headers: { "User-Agent": USER_AGENT },
      }, false);
      // WordPress redirects /?author=N to /author/username/
      const location = response.headers.get("location") || "";
      await discardResponseBody(response);
      if (response.status >= 301 && response.status <= 302 && location) {
        const userMatch = location.match(/\/author\/([^/?#]+)/i);
        if (userMatch) {
          return {
            check: "wp-author-enum",
            severity: "medium" as const,
            title: "WordPress Author Enumeration",
            detail: `The WordPress author endpoint redirect exposed username "${userMatch[1]}".`,
            evidence: redactRelativeUrl(`GET /?author=${authorId} -> ${response.status} to ${location}`),
            recommendation: "Disable author enumeration redirects or install a security plugin that blocks this.",
          } as WpFinding;
        }
      }
    } catch { /* non-fatal */ }
    return null;
  });

  const results = await Promise.allSettled(checks);
  for (const result of results) {
    if (result.status === "fulfilled" && result.value) {
      findings.push(result.value);
    }
  }
  // Only report once even if multiple authors found
  return findings.slice(0, 1);
}

async function checkDirectoryListing(baseUrl: URL, path: string, name: string, context?: OutboundContext): Promise<WpFinding | null> {
  try {
    const url = new URL(path, baseUrl).toString();
    const response = await wpFetch(url, context, {
      headers: { Accept: "text/html", "User-Agent": USER_AGENT },
    });
    if (response.ok) {
      const body = (await readBoundedBody(response, WP_BODY_LIMIT, context, "wordpress")).text;
      if (body.includes("Index of") || body.includes("Directory listing")) {
        return {
          check: `wp-dir-listing-${name}`,
          severity: "medium",
          title: `Directory Listing Enabled: ${path}`,
          detail: `The ${name} directory has directory listing enabled, exposing the contents of ${path}.`,
          evidence: `GET ${path} → ${response.status}, contains "Index of"`,
          recommendation: `Disable directory listing for ${path} via .htaccess or server configuration.`,
        };
      }
    } else {
      await discardResponseBody(response);
    }
  } catch { /* non-fatal */ }
  return null;
}

async function checkReadme(baseUrl: URL, context?: OutboundContext): Promise<WpFinding | null> {
  try {
    const url = new URL("/readme.html", baseUrl).toString();
    const response = await wpFetch(url, context, {
      headers: { "User-Agent": USER_AGENT },
    });
    if (response.ok) {
      const body = (await readBoundedBody(response, WP_BODY_LIMIT, context, "wordpress")).text;
      const versionMatch = body.match(/Version\s+([\d.]+)/i);
      if (versionMatch || body.includes("WordPress")) {
        return {
          check: "wp-readme",
          severity: "low",
          title: "WordPress readme.html Exposed",
          detail: `The default WordPress readme.html is accessible${versionMatch ? `, revealing version ${versionMatch[1]}` : ""}.`,
          evidence: `GET /readme.html → ${response.status}${versionMatch ? `, version ${versionMatch[1]}` : ""}`,
          recommendation: "Delete readme.html or restrict access to it.",
        };
      }
    } else {
      await discardResponseBody(response);
    }
  } catch { /* non-fatal */ }
  return null;
}

/**
 * Detect the XML-RPC endpoint without invoking an XML-RPC method.
 *
 * WordPress commonly answers a GET with "XML-RPC server accepts POST
 * requests only" (or a 405). That signature is enough to establish that the
 * endpoint is present; sending an XML-RPC method call would be an active POST
 * to the target and is outside this scanner's non-mutating probe contract.
 */
async function checkXmlRpc(baseUrl: URL, context?: OutboundContext): Promise<WpFinding | null> {
  try {
    const url = new URL("/xmlrpc.php", baseUrl).toString();
    const response = await wpFetch(url, context, {
      method: "GET",
      headers: {
        Accept: "text/plain,text/html,application/xml;q=0.9,*/*;q=0.1",
        "User-Agent": USER_AGENT,
      },
    });
    const body = (await readBoundedBody(response, WP_BODY_LIMIT, context, "wordpress")).text;
    const endpointSignature = /XML-RPC server accepts POST requests only/i.test(body);
    if (response.status === 405 || endpointSignature) {
      return {
        check: "wp-xmlrpc",
        severity: "medium",
        title: "WordPress XML-RPC Endpoint Exposed",
        detail: "The XML-RPC endpoint at /xmlrpc.php was identified from a GET response signature. No XML-RPC method was invoked.",
        evidence: `GET /xmlrpc.php → ${response.status}, XML-RPC endpoint signature observed`,
        recommendation: "Disable XML-RPC if not needed, or restrict access to trusted IPs only.",
      };
    }
  } catch { /* non-fatal */ }
  return null;
}

async function checkWpConfigBackups(baseUrl: URL, context?: OutboundContext): Promise<WpFinding[]> {
  const findings: WpFinding[] = [];
  const backupFiles = [
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/wp-config.php.save",
    "/wp-config.txt",
  ];

  const checks = backupFiles.map(async (path) => {
    try {
      const url = new URL(path, baseUrl).toString();
      const response = await wpFetch(url, context, {
        headers: { "User-Agent": USER_AGENT },
      });
      if (response.ok) {
        const body = (await readBoundedBody(response, WP_BODY_LIMIT, context, "wordpress")).text;
        if (body.includes("DB_PASSWORD") || body.includes("DB_USER") || body.includes("DB_NAME") || body.includes("table_prefix")) {
          return {
            check: `wp-config-backup-${path}`,
            severity: "critical" as const,
            title: `WordPress Config Backup Exposed: ${path}`,
            detail: `A WordPress configuration backup at ${path} is publicly accessible and contains database credentials.`,
            evidence: `GET ${path} → ${response.status}, contains DB_PASSWORD/DB_USER`,
            recommendation: `Delete ${path} immediately and rotate all database credentials.`,
          } as WpFinding;
        }
      } else {
        await discardResponseBody(response);
      }
    } catch { /* non-fatal */ }
    return null;
  });

  const results = await Promise.allSettled(checks);
  for (const result of results) {
    if (result.status === "fulfilled" && result.value) {
      findings.push(result.value);
    }
  }
  return findings;
}

async function checkDebugLog(baseUrl: URL, context?: OutboundContext): Promise<WpFinding | null> {
  try {
    const url = new URL("/wp-content/debug.log", baseUrl).toString();
    const response = await wpFetch(url, context, {
      headers: { "User-Agent": USER_AGENT },
    });
    if (response.ok) {
      const body = (await readBoundedBody(response, WP_BODY_LIMIT, context, "wordpress")).text;
      // Theme and plugin fallback pages routinely return HTTP 200 with words
      // like "Error" in their copy. Only WordPress debug-log-specific
      // evidence may support a public exposure finding: a dated log line in
      // WP_DEBUG_LOG's "[dd-Mon-yyyy hh:mm:ss UTC] PHP …" format, or an
      // explicit PHP severity marker that prose does not use as a bare word.
      const datedLogLine = /\[\d{1,2}-[A-Za-z]{3}-\d{4}[^\]]*\]\s+PHP\s+/;
      const phpSeverityMarker = /PHP (Warning|Notice|Fatal error|Parse error|Deprecated)\s*:/i;
      if (datedLogLine.test(body) || phpSeverityMarker.test(body)) {
        const lineCount = body.split("\n").length;
        return {
          check: "wp-debug-log",
          severity: "medium",
          title: "WordPress Debug Log Exposed",
          detail: `The WordPress debug log at /wp-content/debug.log is publicly accessible (~${lineCount} lines). It may contain sensitive information including file paths, errors, and plugin details.`,
          evidence: `GET /wp-content/debug.log → ${response.status}, dated PHP log entries observed (~${lineCount} lines)`,
          recommendation: "Delete the debug log, disable WP_DEBUG_LOG, or restrict access via .htaccess.",
        };
      }
    } else {
      await discardResponseBody(response);
    }
  } catch { /* non-fatal */ }
  return null;
}

// ─── Main scan function ────────────────────────────────────────────────────

/**
 * Run WordPress-specific security checks against a detected WordPress site.
 */
export async function scanWordPress(
  pageUrl: URL,
  context?: OutboundContext,
): Promise<WpFinding[]> {
  const findings: WpFinding[] = [];

  // --- Run all network checks in parallel ---
  const [restUsers, restApi, authorEnum, readme, xmlrpc, configBackups, debugLog, uploadsListing, pluginsListing, themesListing] = await Promise.allSettled([
    checkWpRestUsers(pageUrl, context),
    checkWpRestApi(pageUrl, context),
    checkAuthorEnumeration(pageUrl, context),
    checkReadme(pageUrl, context),
    checkXmlRpc(pageUrl, context),
    checkWpConfigBackups(pageUrl, context),
    checkDebugLog(pageUrl, context),
    checkDirectoryListing(pageUrl, "/wp-content/uploads/", "uploads", context),
    checkDirectoryListing(pageUrl, "/wp-content/plugins/", "plugins", context),
    checkDirectoryListing(pageUrl, "/wp-content/themes/", "themes", context),
  ]);

  const allResults: WpFinding[][] = [];
  const singles: (WpFinding | null)[] = [];

  // Collect array results
  for (const r of [restUsers, restApi, authorEnum, configBackups]) {
    if (r.status === "fulfilled") allResults.push(r.value);
  }

  // Collect single results
  for (const r of [readme, xmlrpc, debugLog, uploadsListing, pluginsListing, themesListing]) {
    if (r.status === "fulfilled" && r.value) singles.push(r.value);
  }

  for (const arr of allResults) findings.push(...arr);
  for (const single of singles) {
    if (single) findings.push(single);
  }

  return findings;
}

function redactRelativeUrl(value: string): string {
  return redactUrlsInText(value).replace(/[?#][^\s]*/g, (part) => part.startsWith("?") ? "?[redacted]" : "#[redacted]");
}
