import type { SslDetail } from "./types";
import { infrastructureFetch, readBoundedBody, type OutboundContext } from "./outbound";

interface CrtShEntry {
  not_before?: string;
  not_after?: string;
}

/**
 * Extract SSL/TLS connection and certificate details for a hostname.
 *
 * Cloudflare Worker fetches do not expose the scanned origin's negotiated TLS
 * protocol or cipher. Those fields therefore remain unavailable. Certificate
 * Transparency data is retained only as historical evidence and is explicitly
 * labelled as not proving the active certificate.
 */
export async function inspectSsl(
  hostname: string,
  _fetchResponse: Response | null,
  context?: OutboundContext,
): Promise<SslDetail> {
  void _fetchResponse;

  // --- 1. Query crt.sh for certificate-transparency evidence ---
  let validFrom: string | null = null;
  let validTo: string | null = null;
  let authorityKeyIdentifier: string | null = null;
  let certificateStatus: SslDetail["certificateEvidence"]["status"] = "unavailable";
  let observedAt: string | null = null;

  try {
    const crtResult = await queryCrtSh(hostname, context);
    if (crtResult) {
      validFrom = crtResult.not_before ?? null;
      validTo = crtResult.not_after ?? null;
      certificateStatus = "observed";
      observedAt = new Date().toISOString();
    }
  } catch {
    // crt.sh is best-effort; failures are non-fatal.
  }

  // --- 2. Calculate days until the CT entry's reported expiry ---
  let daysUntilExpiry: number | null = null;
  if (validTo) {
    const expiry = new Date(validTo);
    if (!Number.isNaN(expiry.getTime())) {
      daysUntilExpiry = Math.ceil(
        (expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24),
      );
    }
  }

  return {
    protocol: null,
    cipher: null,
    issuer: null,
    subject: null,
    validFrom,
    validTo,
    daysUntilExpiry,
    authorityKeyIdentifier,
    certificateEvidence: {
      source: "crt.sh",
      status: certificateStatus,
      limitation: "Certificate Transparency entries are historical observations and do not prove the certificate currently presented by the target.",
      observedAt,
    },
  };
}

/**
 * Query crt.sh certificate transparency log for the most recent cert entry.
 */
async function queryCrtSh(
  hostname: string,
  context?: OutboundContext,
): Promise<CrtShEntry | null> {
  const url = `https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`;
  const response = await infrastructureFetch(url, context, {
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(8_000),
  }, "certificateEvidence");

  if (!response.ok) return null;

  const body = await readBoundedBody(response, 256 * 1024, context, "certificateEvidence");
  const entries = JSON.parse(body.text) as CrtShEntry[];
  if (!Array.isArray(entries) || entries.length === 0) return null;

  const sorted = entries
    .filter((e) => e.not_before && e.not_after)
    .sort((a, b) => {
      const aTime = new Date(a.not_before!).getTime();
      const bTime = new Date(b.not_before!).getTime();
      return bTime - aTime;
    });

  return sorted[0] ?? entries[0] ?? null;
}
