import type { DnsAnswer, DnsQueryResult } from "./types";
import { getDomain } from "tldts";
import { discardResponseBody, infrastructureFetch, readBoundedBody, type OutboundContext } from "./outbound";

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const GOOGLE_DOH_ENDPOINT = "https://dns.google/resolve";
const TYPE_NAMES: Record<number, string> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  257: "CAA",
};

interface DnsJson {
  Status?: number;
  AD?: boolean;
  Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
}

export async function queryDns(
  name: string,
  type: string,
  provider: "cloudflare" | "google" = "cloudflare",
  context?: OutboundContext,
): Promise<DnsQueryResult> {
  const started = performance.now();
  const endpoint = provider === "google" ? GOOGLE_DOH_ENDPOINT : DOH_ENDPOINT;
  const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&do=true`;

  try {
    const response = await infrastructureFetch(url, context, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(5000),
    }, "dns");
    if (!response.ok) {
      await discardResponseBody(response);
      throw new Error(`Resolver returned HTTP ${response.status}`);
    }
    const payload = JSON.parse((await readBoundedBody(response, 64 * 1024, context, "dns")).text) as DnsJson;
    // do=true is sent to obtain the AD flag, which makes resolvers attach
    // RRSIG (type 46) signature records to every answer on signed zones.
    // Those base64 signatures carry no review value in a report — DNSSEC
    // evidence is preserved by authenticatedData — so they are dropped here
    // instead of stored per query.
    const answers: DnsAnswer[] = (payload.Answer || [])
      .filter((answer) => answer.type !== 46)
      .map((answer) => ({
      name: answer.name.replace(/\.$/, ""),
      type: TYPE_NAMES[answer.type] || String(answer.type),
      ttl: answer.TTL,
      data: answer.data.replace(/\.$/, ""),
    }));
    return {
      resolver: provider === "google" ? "Google Public DNS" : "Cloudflare DNS",
      name,
      type,
      status: payload.Status ?? -1,
      authenticatedData: Boolean(payload.AD),
      answers,
      elapsedMs: Math.round(performance.now() - started),
      evidenceKind: "dns_observation",
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "DNS query failed";
    console.warn(
      "dns_resolver_failed",
      JSON.stringify({
        resolver: provider,
        recordType: type,
        error: message,
      }),
    );
    return {
      resolver: provider === "google" ? "Google Public DNS" : "Cloudflare DNS",
      name,
      type,
      status: -1,
      authenticatedData: false,
      answers: [],
      elapsedMs: Math.round(performance.now() - started),
      error: message,
      evidenceKind: "dns_observation",
    };
  }
}

export async function queryDnsWithFallback(
  name: string,
  type: string,
  context?: OutboundContext,
): Promise<DnsQueryResult> {
  const primary = await queryDns(name, type, "cloudflare", context);
  if (primary.status !== -1) return primary;
  return queryDns(name, type, "google", context);
}

export async function inspectDns(hostname: string, context?: OutboundContext): Promise<DnsQueryResult[]> {
  const apex = registrableApproximation(hostname);
  const targets: Array<[string, string]> = [
    [hostname, "A"],
    [hostname, "AAAA"],
    [hostname, "CNAME"],
    [apex, "NS"],
    [apex, "CAA"],
  ];
  return Promise.all(
    targets.map(([name, type]) => queryDnsWithFallback(name, type, context)),
  );
}

function registrableApproximation(hostname: string): string {
  return getDomain(hostname, { allowPrivateDomains: true }) || hostname;
}
