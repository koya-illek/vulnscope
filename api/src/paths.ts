import type { ExposedPath, SensitivePathEntry } from "./types";
import { discardResponseBody, safeFetch, readBoundedBody, USER_AGENT, type OutboundContext } from "./outbound";

// ─── Sensitive path database ───────────────────────────────────────────────

export const SENSITIVE_PATHS: SensitivePathEntry[] = [
  // Critical — secrets / source control
  { path: "/.env", method: "GET", severity: "critical", name: "Environment Variables", description: "Exposes environment variables that may contain secrets", signatures: ["DB_PASSWORD", "API_KEY", "SECRET", "DATABASE_URL", "AWS_", "DEBUG=", "APP_KEY"] },
  { path: "/.git/config", method: "GET", severity: "critical", name: "Git Repository Config", description: "Exposes Git repository configuration", signatures: ["[core]", "[remote", "repositoryformatversion"] },
  { path: "/.git/HEAD", method: "GET", severity: "critical", name: "Git HEAD Reference", description: "Exposes Git HEAD reference", signatures: ["ref: refs/heads/"] },
  { path: "/.svn/entries", method: "GET", severity: "critical", name: "SVN Repository Entries", description: "Exposes Subversion repository data", signatures: ["svn:entries", "dir\n", "file\n"] },
  { path: "/.aws/credentials", method: "GET", severity: "critical", name: "AWS Credentials", description: "Exposes AWS access keys", signatures: ["aws_access_key_id", "aws_secret_access_key", "[default]"] },
  { path: "/.ssh/id_rsa", method: "GET", severity: "critical", name: "SSH Private Key", description: "Exposes an SSH private key", signatures: ["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"] },
  { path: "/backup.sql", method: "GET", severity: "critical", name: "Database Backup", description: "Exposes a SQL database backup file", signatures: ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "CREATE DATABASE", "-- MySQL", "PostgreSQL"] },
  { path: "/dump.sql", method: "GET", severity: "critical", name: "Database Dump", description: "Exposes a SQL database dump", signatures: ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "CREATE DATABASE", "-- MySQL", "PostgreSQL"] },
  { path: "/wp-config.php", method: "GET", severity: "critical", name: "WordPress Configuration", description: "Exposes WordPress configuration with database credentials", signatures: ["DB_PASSWORD", "DB_USER", "DB_NAME", "DB_HOST", "table_prefix"] },
  { path: "/wp-config.php.bak", method: "GET", severity: "critical", name: "WordPress Config Backup", description: "Exposes WordPress configuration backup", signatures: ["DB_PASSWORD", "DB_USER", "DB_NAME", "table_prefix"] },
  { path: "/wp-config.php~", method: "GET", severity: "critical", name: "WordPress Config (tilde)", description: "Exposes WordPress configuration editor backup", signatures: ["DB_PASSWORD", "DB_USER", "DB_NAME", "table_prefix"] },
  { path: "/wp-config.php.save", method: "GET", severity: "critical", name: "WordPress Config (save)", description: "Exposes WordPress configuration save file", signatures: ["DB_PASSWORD", "DB_USER", "DB_NAME", "table_prefix"] },
  { path: "/.env.local", method: "GET", severity: "critical", name: "Environment Variables (Local)", description: "Exposes local environment variables that may contain secrets", signatures: ["DB_PASSWORD", "API_KEY", "SECRET", "DATABASE_URL", "AWS_", "DEBUG="] },
  { path: "/.env.production", method: "GET", severity: "critical", name: "Environment Variables (Production)", description: "Exposes production environment variables that may contain secrets", signatures: ["DB_PASSWORD", "API_KEY", "SECRET", "DATABASE_URL", "AWS_", "DEBUG="] },
  { path: "/.env.development", method: "GET", severity: "critical", name: "Environment Variables (Development)", description: "Exposes development environment variables that may contain secrets", signatures: ["DB_PASSWORD", "API_KEY", "SECRET", "DATABASE_URL", "AWS_", "DEBUG="] },
  { path: "/.git/refs/", method: "GET", severity: "critical", name: "Git Refs Directory", description: "Exposes Git refs directory listing", signatures: ["refs/heads/", "refs/tags/", "refs/remotes/"] },
  { path: "/.git/logs/HEAD", method: "GET", severity: "critical", name: "Git Commit Log", description: "Exposes Git commit history", signatures: ["commit", "Author:", "Date:", "refs/heads/"] },
  { path: "/id_rsa", method: "GET", severity: "critical", name: "SSH Private Key (root)", description: "Exposes an SSH private key in the web root", signatures: ["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"] },
  { path: "/id_dsa", method: "GET", severity: "critical", name: "DSA Private Key", description: "Exposes a DSA private key in the web root", signatures: ["-----BEGIN DSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"] },
  { path: "/config.php", method: "GET", severity: "critical", name: "PHP Configuration File", description: "Exposes PHP configuration with credentials", signatures: ["DB_PASSWORD", "DB_USER", "DB_NAME", "password", "mysql_connect", "mysqli"] },
  { path: "/config.json", method: "GET", severity: "critical", name: "JSON Configuration File", description: "Exposes application configuration in JSON", signatures: ["password", "secret", "api_key", "apiKey", "token", "database"] },
  { path: "/config.yml", method: "GET", severity: "critical", name: "YAML Configuration File", description: "Exposes application configuration in YAML", signatures: ["password:", "secret:", "api_key:", "database:", "production:"] },
  { path: "/database.yml", method: "GET", severity: "critical", name: "Database Configuration", description: "Exposes database configuration file", signatures: ["production:", "development:", "adapter:", "database:", "password:", "username:"] },
  { path: "/credentials.json", method: "GET", severity: "critical", name: "Credentials File", description: "Exposes a credentials file", signatures: ["password", "secret", "token", "key", "credential"] },
  { path: "/credentials", method: "GET", severity: "critical", name: "Credentials", description: "Exposes a credentials file", signatures: ["password", "secret", "token", "key", "aws_access_key_id"] },

  { path: "/backup/", method: "GET", severity: "high", name: "Backup Directory", description: "Backup directory is accessible", signatures: ["backup", "Index of", ".sql", ".zip", ".tar", ".gz"] },
  { path: "/backups/", method: "GET", severity: "high", name: "Backups Directory", description: "Backups directory is accessible", signatures: ["backup", "Index of", ".sql", ".zip", ".tar", ".gz"] },
  { path: "/vendor/", method: "GET", severity: "high", name: "PHP Composer Vendor Directory", description: "Exposes PHP Composer vendor directory with application source code", signatures: ["autoload", "composer", "Index of", "vendor"] },
  { path: "/node_modules/", method: "GET", severity: "high", name: "Node Modules Directory", description: "Exposes Node.js dependencies with application source code", signatures: ["package.json", "Index of", "node_modules", ".bin"] },
  { path: "/manager/html", method: "GET", severity: "high", name: "Tomcat Manager", description: "Apache Tomcat Manager interface exposed", signatures: ["Tomcat", "manager", "Deploy", "Undeploy", "WAR file"] },
  { path: "/owa/", method: "GET", severity: "high", name: "Exchange OWA", description: "Microsoft Exchange Outlook Web Access exposed", signatures: ["Outlook", "Exchange", "OWA", "owa"] },
  { path: "/CFIDE/administrator/", method: "GET", severity: "high", name: "ColdFusion Administrator", description: "Adobe ColdFusion Administrator panel exposed", signatures: ["ColdFusion", "CFIDE", "administrator", "Adobe"] },
  { path: "/_vti_bin/", method: "GET", severity: "high", name: "SharePoint RPC Endpoint", description: "Microsoft SharePoint FrontPage RPC endpoint exposed", signatures: ["SharePoint", "vti_bin", "FrontPage", "owssvr"] },

  // High — admin panels
  { path: "/admin", method: "GET", severity: "high", name: "Admin Panel", description: "Admin panel exposed and accessible", signatures: ["admin", "login", "password", "dashboard", "sign in"] },
  { path: "/wp-admin", method: "GET", severity: "high", name: "WordPress Admin", description: "WordPress admin interface exposed", signatures: ["wp-admin", "wp-login", "wordpress"] },
  { path: "/administrator", method: "GET", severity: "high", name: "Joomla Administrator", description: "Joomla admin interface exposed", signatures: ["joomla", "administrator", "login"] },
  { path: "/phpmyadmin", method: "GET", severity: "high", name: "phpMyAdmin", description: "phpMyAdmin database management tool exposed", signatures: ["phpmyadmin", "phpMyAdmin", "pma"] },

  // Medium — configuration and info leakage
  { path: "/.htaccess", method: "GET", severity: "medium", name: "Apache Configuration", description: "Exposes Apache .htaccess configuration", signatures: ["RewriteRule", "RewriteEngine", "Options", "Deny", "Allow"] },
  { path: "/web.config", method: "GET", severity: "medium", name: "IIS Configuration", description: "Exposes IIS web.config configuration", signatures: ["<configuration", "<system.webServer", "<connectionStrings"] },
  { path: "/server-status", method: "GET", severity: "medium", name: "Apache Server Status", description: "Exposes Apache server status page", signatures: ["Apache Status", "Server uptime", "Total accesses", "mod_status"] },
  { path: "/server-info", method: "GET", severity: "medium", name: "Apache Server Info", description: "Exposes Apache server information page", signatures: ["Server Settings", "Module", "Apache Server Information"] },
  { path: "/xmlrpc.php", method: "GET", severity: "medium", name: "WordPress XML-RPC", description: "WordPress XML-RPC interface exposed (brute force / pingback risk)", signatures: ["XML-RPC", "xmlrpc", "pingback"] },
  { path: "/error_log", method: "GET", severity: "medium", name: "PHP Error Log", description: "Exposes PHP error log", signatures: ["PHP ", "Stack trace", "Fatal error", "Warning:", "Notice:"] },
  { path: "/debug.log", method: "GET", severity: "medium", name: "Debug Log", description: "Exposes debug log file", signatures: ["DEBUG", "ERROR", "INFO", "TRACE", "log"] },
  { path: "/access.log", method: "GET", severity: "medium", name: "Access Log", description: "Exposes web server access log", signatures: ['"GET ', '"POST ', 'HTTP/', 'Mozilla'] },
  // A real .dockerenv file is commonly empty. An empty signature would match
  // every 200 response, so this path is retained only for explicit Docker
  // metadata and can never be reported from a generic page body.
  { path: "/.dockerenv", method: "GET", severity: "medium", name: "Docker Environment Marker", description: "May indicate that the application is running inside a Docker container", signatures: ["docker", "container"] },
  { path: "/docker-compose.yml", method: "GET", severity: "medium", name: "Docker Compose Config", description: "Exposes Docker Compose configuration with service details", signatures: ["version:", "services:", "image:", "ports:", "environment:"] },
  { path: "/docker-compose.yaml", method: "GET", severity: "medium", name: "Docker Compose Config (YAML)", description: "Exposes Docker Compose configuration with service details", signatures: ["version:", "services:", "image:", "ports:", "environment:"] },
  { path: "/Dockerfile", method: "GET", severity: "medium", name: "Dockerfile", description: "Exposes Docker build instructions", signatures: ["FROM", "RUN", "COPY", "CMD", "ENTRYPOINT"] },
  { path: "/nginx.conf", method: "GET", severity: "medium", name: "Nginx Configuration", description: "Exposes Nginx server configuration", signatures: ["server {", "location", "proxy_pass", "listen", "root"] },
  { path: "/.bash_history", method: "GET", severity: "medium", name: "Bash History", description: "Exposes command history that may contain credentials or sensitive commands", signatures: ["cd ", "ls ", "ssh ", "git ", "npm ", "mysql"] },
  { path: "/.bashrc", method: "GET", severity: "medium", name: "Bash Configuration", description: "Exposes bash configuration that may contain environment variables and aliases", signatures: ["export", "alias", "PATH=", "source"] },
  { path: "/.svn/props/", method: "GET", severity: "medium", name: "SVN Properties Directory", description: "Exposes Subversion properties directory", signatures: ["svn:entries", "dir\n", "file\n"] },
  { path: "/.svn/wc.db", method: "GET", severity: "medium", name: "SVN Working Copy Database", description: "Exposes Subversion working copy SQLite database", signatures: ["SQLite", "REPO", "NODES", "sqlite"] },
  { path: "/WEB-INF/web.xml", method: "GET", severity: "medium", name: "Java Web Application Descriptor", description: "Exposes Java EE web.xml with servlet mappings and configuration", signatures: ["<servlet>", "<servlet-mapping>", "<web-app", "<filter>"] },

  // Low — minor information disclosure
  { path: "/.DS_Store", method: "GET", severity: "low", name: "macOS DS Store", description: "Exposes macOS directory listing metadata", signatures: ["Bud1", "DSStore"] },
  { path: "/composer.json", method: "GET", severity: "low", name: "Composer Dependencies", description: "Exposes PHP dependency manifest", signatures: ["require", "autoload", "psr-4", "composer"] },
  { path: "/package.json", method: "GET", severity: "low", name: "Node Package Manifest", description: "Exposes Node.js package manifest", signatures: ["\"name\"", "\"dependencies\"", "\"scripts\"", "npm"] },
  { path: "/crossdomain.xml", method: "GET", severity: "low", name: "Flash Cross-Domain Policy", description: "Exposes Flash cross-domain policy (legacy risk)", signatures: ["cross-domain-policy", "allow-access-from"] },

  // Info — informational
  { path: "/robots.txt", method: "GET", severity: "info", name: "Robots.txt", description: "Robots.txt may reveal sensitive paths", signatures: ["User-agent", "Disallow", "Allow", "Sitemap"] },
  { path: "/.well-known/security.txt", method: "GET", severity: "info", name: "Security Contact", description: "Security contact information", signatures: ["Contact:", "security", "Encryption:", "Acknowledgments:"] },
  { path: "/sitemap.xml", method: "GET", severity: "info", name: "Sitemap", description: "XML sitemap exposed", signatures: ["<urlset", "<sitemap", "<loc>", "<?xml"] },
  { path: "/login", method: "GET", severity: "info", name: "Login Page", description: "Login page detected", signatures: ["login", "password", "sign in", "username", "log in"] },
  { path: "/api", method: "GET", severity: "info", name: "API Endpoint", description: "API endpoint exposed", signatures: ["api", "endpoint", "swagger", "openapi", "version"] },
  { path: "/.well-known/openid-configuration", method: "GET", severity: "info", name: "OpenID Configuration", description: "OpenID Connect configuration exposed (information disclosure)", signatures: ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"] },
];

const SOFT_404_MARKERS = [
  "not found",
  "404",
  "page not found",
  "doesn't exist",
  "no such",
  "could not be found",
];

const SIGNATURE_MATCH_THRESHOLD = 2;
const DEFAULT_PROBE_PATH_LIMIT = 18;

interface ProbeOptions {
  baseUrl: URL;
  homepageBody: string;
  context?: OutboundContext;
  maxPaths?: number;
}

/**
 * Choose which catalogue entries a single scan probes.
 *
 * The public beta budget only fits ~18 path probes, and the critical tier
 * alone has more entries than that. A plain severity sort therefore made every
 * high/medium/low/info entry unreachable as deployed. Instead, higher tiers
 * keep priority over lower ones, entries are shuffled within their tier once
 * per scan, and slots are shared across tiers proportionally (with a minimum
 * of one slot per non-empty tier). Consecutive scans rotate through different
 * subsets of the catalogue while critical paths stay dominant.
 */
export function selectProbeEntries(limit: number): SensitivePathEntry[] {
  const capped = Math.max(0, Math.min(limit, SENSITIVE_PATHS.length));
  if (capped === 0) return [];
  if (capped >= SENSITIVE_PATHS.length) return SENSITIVE_PATHS.slice();

  const tiers = [...SEVERITY_ORDER]
    .map((severity) => shuffle(SENSITIVE_PATHS.filter((entry) => entry.severity === severity)))
    .filter((tier) => tier.length > 0);
  if (capped < tiers.length) {
    // Not enough budget to give every tier a slot: keep strict severity
    // priority and fill from the top.
    return tiers.slice(0, capped).flat().slice(0, capped);
  }

  const total = tiers.reduce((sum, tier) => sum + tier.length, 0);
  // Largest-remainder allocation so tier shares track catalogue size without
  // losing whole tiers to rounding.
  const quotas = tiers.map((tier) => Math.floor((tier.length / total) * capped));
  let remaining = capped - quotas.reduce((sum, quota) => sum + quota, 0);
  const remainderOrder = tiers
    .map((tier, index) => ({
      index,
      fraction: (tier.length / total) * capped - quotas[index],
    }))
    .sort((a, b) => b.fraction - a.fraction || a.index - b.index);
  for (const { index } of remainderOrder) {
    if (remaining <= 0) break;
    quotas[index]++;
    remaining--;
  }
  // Every non-empty tier keeps at least one slot; take the extra slots from
  // the largest tiers first so no tier drops out entirely.
  for (let i = 0; i < quotas.length && remaining < 0; i++) {
    while (quotas[i] > 1 && remaining < 0) {
      quotas[i]--;
      remaining++;
    }
  }

  return tiers.flatMap((tier, index) => tier.slice(0, quotas[index]));
}

/** Cryptographically shuffled copy; rotates the probed subset once per scan. */
function shuffle<T>(items: T[]): T[] {
  const result = items.slice();
  if (typeof crypto?.getRandomValues !== "function") return result;
  for (let i = result.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

/**
 * Probe all sensitive paths concurrently.
 * Only returns paths with positive signature matches (not soft-404s).
 */
export async function probePaths(
  options: ProbeOptions,
): Promise<ExposedPath[]> {
  const { baseUrl, homepageBody } = options;
  const homepageLength = homepageBody.length;
  const homepageLower = homepageBody.slice(0, 5000).toLowerCase();

  // Keep the opt-in phase below the Workers Free budget. The full catalogue
  // remains available as an explicit bounded option for a paid or private
  // deployment, but the public beta probes only a small rotated subset.
  const entries = selectProbeEntries(options.maxPaths ?? DEFAULT_PROBE_PATH_LIMIT);
  const results = await Promise.allSettled(
    entries.map((entry) => probeSinglePath(baseUrl, entry, homepageLength, homepageLower, options.context)),
  );

  const exposed: ExposedPath[] = [];
  for (const result of results) {
    if (result.status === "fulfilled" && result.value) {
      exposed.push(result.value);
    }
  }
  return exposed;
}

async function probeSinglePath(
  baseUrl: URL,
  entry: SensitivePathEntry,
  homepageLength: number,
  homepageLower: string,
  context?: OutboundContext,
): Promise<ExposedPath | null> {
  const target = new URL(entry.path, baseUrl).toString();

  try {
    const response = await safeFetch(target, {
      method: entry.method,
      baseUrl,
      followRedirects: false,
      phase: "paths",
      context,
      headers: {
        Accept: "text/html,application/json,text/plain,*/*;q=0.5",
        "User-Agent": USER_AGENT,
      },
      timeoutMs: 5_000,
    });

    // Only consider 200 OK responses
    if (response.status !== 200) {
      await discardResponseBody(response);
      return null;
    }

    // Read first 10KB of body
    const bodyResult = await readBoundedBody(response, 10_240, context, "paths");
    const body = bodyResult.text;
    const bodyLower = body.toLowerCase();

    const contentType = (response.headers.get("content-type") || "").toLowerCase();
    if (contentType && !/(text\/|json|xml|javascript)/i.test(contentType)) return null;

    // Soft-404 detection: identical content is a stronger signal than a
    // loose length comparison, which incorrectly rejects unrelated pages.
    if (homepageLower && bodyLower.slice(0, 5000) === homepageLower) return null;
    if (homepageLength > 0) {
      const ratio = body.length / homepageLength;
      if (ratio > 0.98 && ratio < 1.02 && bodyLower.includes("not found")) return null;
    }

    // Soft-404 detection: contains generic "not found" text
    if (SOFT_404_MARKERS.some((marker) => bodyLower.includes(marker))) {
      // But still check if the signatures are strong enough to override
      const strongMatch = getMatchedSignatures(entry, bodyLower);
      if (!isStructuredMatch(entry, body, strongMatch) && strongMatch.length < SIGNATURE_MATCH_THRESHOLD) return null;
    }

    // Check for signature matches
    const matchedSignatures = getMatchedSignatures(entry, bodyLower);

    if (!isStructuredMatch(entry, body, matchedSignatures) && matchedSignatures.length < minimumMatches(entry)) {
      return null;
    }

    return makeExposed(entry, response.status, matchedSignatures, bodyResult.bytes, bodyResult.truncated);
  } catch {
    return null;
  }
}

function makeExposed(
  entry: SensitivePathEntry,
  status: number,
  matched: string[],
  responseSize: number,
  truncated = false,
): ExposedPath {
  return {
    path: entry.path,
    method: entry.method,
    status,
    severity: entry.severity,
    name: entry.name,
    description: entry.description,
    evidence: `Matched signatures: ${matched.join(", ") || "structured response"}${truncated ? "; body truncated at probe limit" : ""}`,
    responseSize,
    truncated,
  };
}

function minimumMatches(entry: SensitivePathEntry): number {
  if (entry.severity === "info" || entry.severity === "low") return 1;
  return Math.min(SIGNATURE_MATCH_THRESHOLD, Math.max(1, entry.signatures.length));
}

function getMatchedSignatures(entry: SensitivePathEntry, bodyLower: string): string[] {
  return entry.signatures.filter((signature) => signature.length > 0 && bodyLower.includes(signature.toLowerCase()));
}

function isStructuredMatch(entry: SensitivePathEntry, body: string, matched: string[]): boolean {
  if (entry.path === "/.git/HEAD") return /^ref:\s+refs\/heads\/[a-z0-9._/-]+\s*$/im.test(body.trim());
  if (entry.path.includes("id_rsa") || entry.path.includes("id_dsa") || entry.path.includes(".ssh/")) {
    return /-----BEGIN (?:RSA |DSA |OPENSSH )?PRIVATE KEY-----/.test(body);
  }
  if (entry.path === "/.dockerenv") return false;
  return matched.length >= minimumMatches(entry);
}

const SEVERITY_ORDER: Array<SensitivePathEntry["severity"]> = ["critical", "high", "medium", "low", "info"];
