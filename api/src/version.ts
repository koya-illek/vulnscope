/**
 * Single source of truth for the product version surfaced by the API
 * metadata, the MCP serverInfo, and the outbound scanner User-Agent. The
 * OpenAPI and Copilot contracts pin the same value; a release-config test
 * fails when any of them drift.
 *
 * Public hostnames live here too so redirects, CORS comments, report links,
 * and the self-scan boundary cannot drift from the canonical brand host.
 */
export const VERSION = "2.0.0";
export const CANONICAL_HOST = "vulnscope.illek.ie";
export const WEBSITE_ORIGIN = `https://${CANONICAL_HOST}`;

/** Hosts that permanently redirect to the canonical HTTPS origin. */
export const ALIAS_PUBLIC_HOSTS = [
  "scan.illek.ie",
  "www.scan.illek.ie",
  "www.vulnscope.illek.ie",
] as const;

const SERVICE_HOSTS = new Set<string>([CANONICAL_HOST, ...ALIAS_PUBLIC_HOSTS]);

export function normalizeHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/\.$/, "");
}

export function isAliasPublicHost(hostname: string): boolean {
  const host = normalizeHostname(hostname);
  return host !== CANONICAL_HOST && SERVICE_HOSTS.has(host);
}

export function isServiceHost(hostname: string): boolean {
  return SERVICE_HOSTS.has(normalizeHostname(hostname));
}

/** Canonical HTTPS URL preserving path and query, never the inbound host. */
export function canonicalHttpsUrl(url: URL): string {
  return `${WEBSITE_ORIGIN}${url.pathname}${url.search}`;
}
