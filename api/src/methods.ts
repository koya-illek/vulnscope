import type { MethodResult } from "./types";
import { discardResponseBody, safeFetch, readBoundedBody, USER_AGENT, type OutboundContext } from "./outbound";

const SCAN_TIMEOUT = 5000;
const TRACE_CANARY_PREFIX = "VulnScanner-Trace";

/**
 * Probe which HTTP methods are allowed on the target URL.
 *
 * Default scans send OPTIONS and read the Allow header. TRACE probing is
 * opt-in. Methods advertised by Allow are reported as advertisements only;
 * this scanner never sends mutating PUT or DELETE requests to a target.
 */
export interface ProbeMethodsOptions {
  /** Opt in to a TRACE probe. Default scans only read the OPTIONS Allow header. */
  probeTrace?: boolean;
}

export async function probeMethods(
  targetUrl: string,
  context?: OutboundContext,
  options: ProbeMethodsOptions = {},
): Promise<{ methods: MethodResult[]; traceVulnerable: boolean }> {
  const results = new Map<string, MethodResult>();
  let traceVulnerable = false;

  // --- 1. OPTIONS request — check Allow header ---
  const optionsMethods = await checkOptions(targetUrl, context);
  for (const method of optionsMethods) {
    results.set(method, {
      method,
      allowed: true,
      observation: "advertised",
      evidence: `OPTIONS Allow header advertises ${method}; no ${method} request was sent`,
    });
  }

  // --- 2. TRACE — opt-in Cross-Site Tracing (XST) probe ---
  if (options.probeTrace === true) {
    const traceResult = await checkTrace(targetUrl, context);
    if (traceResult) {
      results.set(traceResult.result.method, mergeMethodResult(results.get(traceResult.result.method), traceResult.result));
      traceVulnerable = traceResult.vulnerable;
    }
  }

  return { methods: [...results.values()], traceVulnerable };
}

/**
 * Merge the OPTIONS advertisement and the real TRACE observation into one
 * method record. The observed response is authoritative, while retaining the
 * advertisement as context in the evidence string.
 */
export function mergeMethodResult(existing: MethodResult | undefined, observed: MethodResult): MethodResult {
  if (!existing || existing.observation === "observed") return existing || observed;
  // The advertisement-only record says that no request was sent. Once the
  // real TRACE probe has run, retaining that clause would contradict the
  // observed evidence, so keep only the advertisement context.
  const advertisementEvidence = existing.evidence
    .replace(/;\s*no\s+\S+\s+request\s+was\s+sent\.?/i, "")
    .trim();
  return {
    ...observed,
    evidence: `${advertisementEvidence}; ${observed.evidence}`,
  };
}

// ─── Individual method checks ──────────────────────────────────────────────

async function checkOptions(targetUrl: string, context?: OutboundContext): Promise<string[]> {
  try {
    const response = await safeFetch(targetUrl, {
      method: "OPTIONS",
      baseUrl: new URL(targetUrl),
      followRedirects: false,
      phase: "methods",
      context,
      headers: { "User-Agent": USER_AGENT },
      timeoutMs: SCAN_TIMEOUT,
    });

    const allowHeader = response.headers.get("allow") || "";
    await discardResponseBody(response);
    if (!allowHeader) return [];

    const allowedMethods = allowHeader
      .split(",")
      .map((m) => m.trim().toUpperCase())
      .filter(Boolean);

    // Return notable methods (skip mundane ones like GET, HEAD, POST, OPTIONS)
    const notable = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"];
    return allowedMethods.filter((m) => notable.includes(m));
  } catch {
    return [];
  }
}

async function checkTrace(
  targetUrl: string,
  context?: OutboundContext,
): Promise<{ result: MethodResult; vulnerable: boolean } | null> {
  try {
    const traceCanary = `${TRACE_CANARY_PREFIX}-${crypto.randomUUID()}`;
    const response = await safeFetch(targetUrl, {
      method: "TRACE",
      baseUrl: new URL(targetUrl),
      followRedirects: false,
      phase: "methods",
      context,
      headers: { "User-Agent": USER_AGENT, "X-Test-Header": traceCanary },
      timeoutMs: SCAN_TIMEOUT,
    });

    if (response.status >= 200 && response.status < 400) {
      const body = (await readBoundedBody(response, 16 * 1024, context, "methods")).text;
      // Only the exact canary injected into this request proves that request
      // data was reflected. Generic TRACE/User-Agent text can be a static
      // error or help page and is not evidence of XST.
      if (body.includes(traceCanary)) {
        return {
          result: {
            method: "TRACE",
            allowed: true,
            observation: "observed",
            evidence: `TRACE returned ${response.status} with reflected request data (XST vulnerability)`,
          },
          vulnerable: true,
        };
      }
      return {
        result: {
          method: "TRACE",
          allowed: true,
          observation: "observed",
          evidence: `TRACE returned ${response.status}; no reflected request data observed`,
        },
        vulnerable: false,
      };
    }
    await discardResponseBody(response);
    return null;
  } catch {
    return null;
  }
}
