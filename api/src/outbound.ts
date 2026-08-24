import { getDomain } from "tldts";
import { isIpLiteral, isPublicIp, isValidHostname } from "./security";
import { queryDnsWithFallback } from "./dns";
import type { OutboundRequestSummary } from "./types";
import { VERSION, WEBSITE_ORIGIN } from "./version";

export const USER_AGENT = `VulnScanner/${VERSION} (+${WEBSITE_ORIGIN})`;

export interface BodyReadResult {
  text: string;
  bytes: number;
  truncated: boolean;
}

export interface PhaseStats {
  attempts: number;
  succeeded: number;
  failed: number;
  skipped: number;
  bytes: number;
  truncated: boolean;
  errors: string[];
}

export interface OutboundBudgetOptions {
  maxSubrequests?: number;
  maxConcurrent?: number;
  maxDurationMs?: number;
  maxBodyBytes?: number;
}

export interface OutboundContext {
  readonly budget: OutboundBudget;
  readonly addresses: Map<string, string[]>;
  readonly phaseStats: Map<string, PhaseStats>;
  currentPhase: string;
  resolveHost?: (hostname: string) => Promise<string[]>;
}

export class OutboundPolicyError extends Error {
  readonly code: "budget" | "blocked" | "redirect" | "timeout" | "body";

  constructor(message: string, code: OutboundPolicyError["code"] = "blocked") {
    super(message);
    this.name = "OutboundPolicyError";
    this.code = code;
  }
}

/**
 * One request-wide budget shared by every target-controlled probe. The
 * scanner deliberately stays below the Workers Free subrequest allowance;
 * infrastructure lookups and redirect hops are counted too.
 */
export class OutboundBudget {
  readonly maxSubrequests: number;
  readonly maxConcurrent: number;
  readonly maxDurationMs: number;
  readonly maxBodyBytes: number;
  readonly startedAt = Date.now();
  requestsAttempted = 0;
  requestsSucceeded = 0;
  requestsFailed = 0;
  requestsSkipped = 0;
  active = 0;
  activePeak = 0;
  bodyBytes = 0;
  truncatedBodies = 0;
  private reservedBodyBytes = 0;
  readonly redirects: OutboundRequestSummary["redirects"] = [];
  private waiters: Array<() => void> = [];

  constructor(options: OutboundBudgetOptions = {}) {
    this.maxSubrequests = options.maxSubrequests ?? 46;
    this.maxConcurrent = options.maxConcurrent ?? 6;
    this.maxDurationMs = options.maxDurationMs ?? 25_000;
    this.maxBodyBytes = options.maxBodyBytes ?? 2 * 1024 * 1024;
  }

  get elapsedMs(): number {
    return Date.now() - this.startedAt;
  }

  consume(phase?: PhaseStats): void {
    if (this.elapsedMs >= this.maxDurationMs) {
      this.requestsSkipped++;
      if (phase) phase.skipped++;
      throw new OutboundPolicyError("The scan time budget was exhausted.", "budget");
    }
    if (this.bodyBytes >= this.maxBodyBytes) {
      this.requestsSkipped++;
      if (phase) phase.skipped++;
      throw new OutboundPolicyError("The scan response-body budget was exhausted.", "body");
    }
    if (this.requestsAttempted >= this.maxSubrequests) {
      this.requestsSkipped++;
      if (phase) phase.skipped++;
      throw new OutboundPolicyError("The scan request budget was exhausted.", "budget");
    }
    this.requestsAttempted++;
    if (phase) phase.attempts++;
  }

  async acquire(): Promise<void> {
    // Re-check after waking: release() resolves a waiter before that waiter
    // resumes, so a caller arriving in between can take the freed slot via
    // the fast path. Without the re-check both would increment and exceed
    // maxConcurrent.
    while (this.active >= this.maxConcurrent) {
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    this.active++;
    this.activePeak = Math.max(this.activePeak, this.active);
  }

  release(): void {
    this.active = Math.max(0, this.active - 1);
    this.waiters.shift()?.();
  }

  reserveBody(limit: number): number {
    const available = Math.max(0, this.maxBodyBytes - this.bodyBytes - this.reservedBodyBytes);
    const reservation = Math.min(Math.max(0, limit), available);
    this.reservedBodyBytes += reservation;
    return reservation;
  }

  releaseBodyReservation(reservation: number): void {
    this.reservedBodyBytes = Math.max(0, this.reservedBodyBytes - Math.max(0, reservation));
  }

  recordBody(result: BodyReadResult, phase?: PhaseStats, reservation = 0): void {
    this.releaseBodyReservation(reservation);
    const recordedBytes = Math.min(result.bytes, Math.max(0, this.maxBodyBytes - this.bodyBytes));
    this.bodyBytes += recordedBytes;
    if (result.truncated) this.truncatedBodies++;
    if (phase) {
      phase.bytes += recordedBytes;
      phase.truncated ||= result.truncated;
    }
  }

  snapshot(): OutboundRequestSummary {
    return {
      maxSubrequests: this.maxSubrequests,
      maxConcurrent: this.maxConcurrent,
      maxDurationMs: this.maxDurationMs,
      requestsAttempted: this.requestsAttempted,
      requestsSucceeded: this.requestsSucceeded,
      requestsFailed: this.requestsFailed,
      requestsSkipped: this.requestsSkipped,
      activePeak: this.activePeak,
      bodyBytes: this.bodyBytes,
      truncatedBodies: this.truncatedBodies,
      redirects: [...this.redirects],
    };
  }
}

export function createOutboundContext(
  options: OutboundBudgetOptions = {},
  seedAddresses: Record<string, string[]> = {},
): OutboundContext {
  const addresses = new Map<string, string[]>();
  for (const [hostname, values] of Object.entries(seedAddresses)) {
    addresses.set(hostname.toLowerCase().replace(/\.$/, ""), [...new Set(values)]);
  }
  const context: OutboundContext = {
    budget: new OutboundBudget(options),
    addresses,
    phaseStats: new Map(),
    currentPhase: "outbound",
  };
  context.resolveHost = async (hostname) => resolvePublicHost(context, hostname);
  return context;
}

export function phaseStats(context: OutboundContext, phase = context.currentPhase): PhaseStats {
  let stats = context.phaseStats.get(phase);
  if (!stats) {
    stats = { attempts: 0, succeeded: 0, failed: 0, skipped: 0, bytes: 0, truncated: false, errors: [] };
    context.phaseStats.set(phase, stats);
  }
  return stats;
}

export function setOutboundPhase(context: OutboundContext, phase: string): void {
  context.currentPhase = phase;
  phaseStats(context, phase);
}

export interface SafeFetchOptions extends RequestInit {
  baseUrl?: URL | string;
  /** Explicitly allow another host in the same registrable domain. */
  allowCrossHost?: boolean;
  followRedirects?: boolean;
  maxRedirects?: number;
  timeoutMs?: number;
  phase?: string;
  context?: OutboundContext;
}

/**
 * Fetch a public target through one fail-closed policy. Redirects are manual,
 * every hop is validated and resolved, and same-host is the default boundary.
 * A cross-host request must explicitly opt in and remains limited to the
 * target's registrable domain.
 */
export async function safeFetch(input: RequestInfo | URL, options: SafeFetchOptions = {}): Promise<Response> {
  const context = options.context;
  const phase = options.phase || context?.currentPhase || "outbound";
  const stats = context ? phaseStats(context, phase) : undefined;
  const baseUrl = options.baseUrl ? new URL(options.baseUrl) : undefined;
  let current = input instanceof Request ? new URL(input.url) : new URL(input.toString());
  const originalHost = current.hostname.toLowerCase().replace(/\.$/, "");
  const maxRedirects = Math.min(Math.max(options.maxRedirects ?? 3, 0), 5);
  const allowCrossHost = options.allowCrossHost === true;
  const followRedirects = options.followRedirects !== false;

  validateUrl(current);
  validateHostBoundary(current.hostname, baseUrl, allowCrossHost);

  let redirects = 0;
  while (true) {
    validateUrl(current);
    validateHostBoundary(current.hostname, baseUrl, allowCrossHost);
    if (context) await assertPublicHost(context, current.hostname, stats, redirects > 0);

    if (context) {
      context.budget.consume(stats);
      await context.budget.acquire();
      if (context.budget.elapsedMs >= context.budget.maxDurationMs || context.budget.bodyBytes >= context.budget.maxBodyBytes) {
        context.budget.requestsSkipped++;
        if (stats) stats.skipped++;
        context.budget.release();
        throw new OutboundPolicyError(
          context.budget.bodyBytes >= context.budget.maxBodyBytes
            ? "The scan response-body budget was exhausted."
            : "The scan time budget was exhausted.",
          context.budget.bodyBytes >= context.budget.maxBodyBytes ? "body" : "budget",
        );
      }
    }

    let response: Response;
    try {
      const timeout = requestTimeout(options.timeoutMs ?? 8_000, context?.budget);
      const deadlineSignal = AbortSignal.timeout(timeout);
      const signal = options.signal
        ? AbortSignal.any([options.signal, deadlineSignal])
        : deadlineSignal;
      const init: RequestInit = { ...options, redirect: "manual", signal };
      delete (init as SafeFetchOptions).baseUrl;
      delete (init as SafeFetchOptions).allowCrossHost;
      delete (init as SafeFetchOptions).followRedirects;
      delete (init as SafeFetchOptions).maxRedirects;
      delete (init as SafeFetchOptions).timeoutMs;
      delete (init as SafeFetchOptions).phase;
      delete (init as SafeFetchOptions).context;
      response = await fetch(current.toString(), init);
      if (context) context.budget.requestsSucceeded++;
      if (stats) stats.succeeded++;
    } catch (error) {
      if (context) context.budget.requestsFailed++;
      if (stats) {
        stats.failed++;
        recordPhaseError(stats, error);
      }
      throw new OutboundPolicyError(
        error instanceof Error ? error.message : "Outbound request failed.",
        "timeout",
      );
    } finally {
      context?.budget.release();
    }

    const location = response.headers.get("location");
    const isRedirect = response.status >= 300 && response.status < 400 && Boolean(location);
    if (!isRedirect || !followRedirects) {
      return response;
    }
    if (redirects >= maxRedirects) {
      throw new OutboundPolicyError("The target exceeded the redirect limit.", "redirect");
    }

    let next: URL;
    try {
      next = new URL(location!, current);
    } catch {
      throw new OutboundPolicyError("The target returned an invalid redirect location.", "redirect");
    }
    validateUrl(next);
    // A redirect may not widen the host boundary unless the caller opted in.
    validateHostBoundary(next.hostname, baseUrl || new URL(`https://${originalHost}`), allowCrossHost);
    const hop = { from: redactOutboundUrl(current), to: redactOutboundUrl(next), status: response.status };
    context?.budget.redirects.push(hop);
    await response.body?.cancel();
    redirects++;
    current = next;
  }
}

/** Fetch a fixed service endpoint such as a public DNS or CT provider. */
export async function infrastructureFetch(
  input: string,
  context: OutboundContext | undefined,
  init: RequestInit = {},
  phase = context?.currentPhase || "infrastructure",
): Promise<Response> {
  const stats = context ? phaseStats(context, phase) : undefined;
  if (context) {
    context.budget.consume(stats);
    await context.budget.acquire();
    if (context.budget.elapsedMs >= context.budget.maxDurationMs || context.budget.bodyBytes >= context.budget.maxBodyBytes) {
      context.budget.requestsSkipped++;
      if (stats) stats.skipped++;
      context.budget.release();
      throw new OutboundPolicyError(
        context.budget.bodyBytes >= context.budget.maxBodyBytes
          ? "The scan response-body budget was exhausted."
          : "The scan time budget was exhausted.",
        context.budget.bodyBytes >= context.budget.maxBodyBytes ? "body" : "budget",
      );
    }
  }
  try {
    const timeout = requestTimeout(8_000, context?.budget);
    const deadlineSignal = AbortSignal.timeout(timeout);
    const signal = init.signal
      ? AbortSignal.any([init.signal, deadlineSignal])
      : deadlineSignal;
    const response = await fetch(input, {
      ...init,
      redirect: "manual",
      signal,
    });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new OutboundPolicyError(
        "The fixed infrastructure endpoint returned an unexpected redirect.",
        "redirect",
      );
    }
    if (context) context.budget.requestsSucceeded++;
    if (stats) stats.succeeded++;
    return response;
  } catch (error) {
    if (context) context.budget.requestsFailed++;
    if (stats) {
      stats.failed++;
      recordPhaseError(stats, error);
    }
    throw error;
  } finally {
    context?.budget.release();
  }
}

/** Release an unread response without making cleanup failures affect a scan. */
export async function discardResponseBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // The response may already be consumed or locked by the runtime.
  }
}

export async function readBoundedBody(
  response: Response,
  limit: number,
  context?: OutboundContext,
  phase = context?.currentPhase || "outbound",
): Promise<BodyReadResult> {
  const stats = context ? phaseStats(context, phase) : undefined;
  const reservation = context ? context.budget.reserveBody(limit) : 0;
  const effectiveLimit = context ? reservation : limit;
  const recordResult = (result: BodyReadResult): BodyReadResult => {
    if (context) context.budget.recordBody(result, stats, reservation);
    return result;
  };
  const declared = Number.parseInt(response.headers.get("content-length") || "", 10);
  if (effectiveLimit <= 0 || (Number.isFinite(declared) && declared > effectiveLimit)) {
    await response.body?.cancel();
    return recordResult({ text: "", bytes: 0, truncated: true });
  }
  if (!response.body) return recordResult({ text: "", bytes: 0, truncated: false });

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (total + value.byteLength > effectiveLimit) {
        const remaining = Math.max(0, effectiveLimit - total);
        if (remaining) chunks.push(value.slice(0, remaining));
        total += remaining;
        truncated = true;
        await reader.cancel();
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } catch (error) {
    context?.budget.releaseBodyReservation(reservation);
    throw error;
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return recordResult({ text: new TextDecoder("utf-8", { fatal: false }).decode(merged), bytes: total, truncated });
}

function validateUrl(url: URL): void {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new OutboundPolicyError("Only HTTP and HTTPS outbound targets are permitted.");
  }
  if (url.username || url.password) throw new OutboundPolicyError("Outbound URLs may not contain credentials.");
  if (url.port && url.port !== "80" && url.port !== "443") {
    throw new OutboundPolicyError("Only standard web ports are permitted for outbound targets.");
  }
  if (isIpLiteral(url.hostname) || !isValidHostname(url.hostname) || url.hostname === "localhost" || url.hostname.endsWith(".localhost")) {
    throw new OutboundPolicyError("The outbound hostname is not a valid public hostname.");
  }
}

function validateHostBoundary(hostname: string, baseUrl: URL | undefined, allowCrossHost: boolean): void {
  if (!baseUrl) return;
  const baseHost = baseUrl.hostname.toLowerCase().replace(/\.$/, "");
  const currentHost = hostname.toLowerCase().replace(/\.$/, "");
  if (currentHost === baseHost) return;
  if (!allowCrossHost || registrableDomain(currentHost) !== registrableDomain(baseHost)) {
    throw new OutboundPolicyError(`Outbound host ${currentHost} is outside the approved target boundary.`);
  }
}

async function assertPublicHost(context: OutboundContext, hostname: string, stats?: PhaseStats, revalidate = false): Promise<void> {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  let addresses = revalidate ? undefined : context.addresses.get(normalized);
  if (!addresses) {
    if (!context.resolveHost) throw new OutboundPolicyError("The target hostname could not be resolved safely.");
    addresses = await context.resolveHost(normalized);
    context.addresses.set(normalized, addresses);
  }
  if (addresses.length === 0 || addresses.some((address) => !isPublicIp(address))) {
    if (stats) recordPhaseError(stats, new Error("private or reserved DNS answer"));
    throw new OutboundPolicyError("The outbound hostname resolved to no confirmed public address.");
  }
}

async function resolvePublicHost(context: OutboundContext, hostname: string): Promise<string[]> {
  // DNS resolver calls are infrastructure requests, but they still consume
  // the same request budget and are deliberately kept to A and AAAA.
  const a = await queryDnsWithFallback(hostname, "A", context);
  const aaaa = await queryDnsWithFallback(hostname, "AAAA", context);
  // Resolvers return the CNAME chain inside the same Answer array, so only
  // records of the queried address type are address candidates. A CNAME
  // hostname string would fail isPublicIp and wrongly fail closed every
  // host that resolves through an alias.
  const addresses = [...new Set([
    ...a.answers.filter((answer) => answer.type === "A").map((answer) => answer.data),
    ...aaaa.answers.filter((answer) => answer.type === "AAAA").map((answer) => answer.data),
  ])];
  if (addresses.length === 0 || addresses.some((address) => !isPublicIp(address))) {
    throw new OutboundPolicyError("The outbound hostname resolved to no confirmed public address.");
  }
  return addresses;
}

function recordPhaseError(stats: PhaseStats, error: unknown): void {
  const message = error instanceof Error ? error.message : "request failed";
  if (stats.errors.length < 5 && !stats.errors.includes(message)) stats.errors.push(message);
}

function registrableDomain(hostname: string): string {
  return getDomain(hostname, { allowPrivateDomains: true }) || hostname;
}

function redactOutboundUrl(url: URL): string {
  const copy = new URL(url.toString());
  copy.search = "";
  copy.hash = "";
  return copy.toString();
}

function requestTimeout(configuredMs: number, budget?: OutboundBudget): number {
  if (!budget) return configuredMs;
  return Math.max(1, Math.min(configuredMs, budget.maxDurationMs - budget.elapsedMs));
}
