const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

export class InputError extends Error {
  status = 400;
}

export class BlockedTargetError extends Error {
  status = 403;
}

export class ResolverUnavailableError extends Error {
  status = 503;
}

/** Raised once a scoped daily quota counter exceeds its configured limit. */
export class RateLimitError extends Error {
  readonly limit: number;
  readonly count: number;
  readonly resetAt: string;

  constructor(message: string, limit: number, count: number, resetAt: string) {
    super(message);
    this.name = "RateLimitError";
    this.limit = limit;
    this.count = count;
    this.resetAt = resetAt;
  }
}

export function normalizeUrl(input: unknown): URL {
  if (typeof input !== "string" || input.trim().length === 0 || input.length > 2048) {
    throw new InputError("Enter a URL of no more than 2,048 characters.");
  }

  let value = input.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = `https://${value}`;

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new InputError("Enter a valid public URL.");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new InputError("Only HTTP and HTTPS URLs are supported.");
  }
  if (url.username || url.password) throw new InputError("URLs containing credentials are not supported.");
  if (url.port && url.port !== "80" && url.port !== "443") {
    throw new InputError("Only standard web ports 80 and 443 are supported.");
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (isIpLiteral(hostname)) throw new BlockedTargetError("Direct IP address targets are not supported.");
  if (!isValidHostname(hostname)) throw new InputError("Enter a valid public hostname.");

  url.hostname = hostname;
  url.hash = "";
  return url;
}

export function redactUrlForStorage(input: string): string {
  try {
    const url = new URL(input);
    // Query strings and fragments routinely carry bearer tokens, signed
    // links, identifiers and tracking values. A public report keeps the
    // origin and path useful for review but never persists those values.
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return "[invalid URL]";
  }
}

/** Remove query and fragment material from URL-bearing header or evidence text. */
export function redactUrlsInText(input: string): string {
  return input.replace(/https?:\/\/[^\s"'<>;,]+/gi, (value) => {
    try {
      const url = new URL(value);
      return url.search || url.hash ? redactUrlForStorage(value) : value;
    } catch {
      return "[redacted-url]";
    }
  });
}

export function redactHeaderValue(name: string, value: string): string {
  const lower = name.toLowerCase();
  if (["content-security-policy", "content-security-policy-report-only", "nel", "report-to"].includes(lower)) {
    // Reporting endpoints can contain signed query strings. Retain directive
    // names for audit context, but remove endpoint parameters and fragments.
    return redactUrlsInText(value).replace(/(report-uri|report-to)\s+[^;]+/gi, "$1 [redacted]");
  }
  return redactUrlsInText(value);
}

export function isValidHostname(hostname: string): boolean {
  if (hostname.length > 253 || hostname.length < 4 || !hostname.includes(".")) return false;
  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local")) return false;
  const labels = hostname.split(".");
  return labels.every((label) => HOST_LABEL.test(label));
}

export function isIpLiteral(host: string): boolean {
  const value = host.replace(/^\[|\]$/g, "");
  return isIPv4(value) || value.includes(":");
}

export function isIPv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

export function isPublicIp(address: string): boolean {
  const value = address.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (isIPv4(value)) return isPublicIPv4(value);
  if (value.includes(":")) return isPublicIPv6(value);
  return false;
}

function isPublicIPv4(value: string): boolean {
  const [a, b, c] = value.split(".").map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 0 && c === 0) return false;
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 192 && b === 88 && c === 99) return false;
  if (a === 192 && b === 168) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function isPublicIPv6(value: string): boolean {
  if (!/^[0-9a-f:.]+$/i.test(value) || value.includes(".")) return false;
  const normalized = value.toLowerCase();
  if (normalized === "::" || normalized === "::1") return false;
  // Unspecified, IPv4-mapped, unique-local, link-local, multicast and the
  // documentation/special-purpose blocks are not safe outbound targets.
  if (normalized.startsWith("::ffff:") || normalized.startsWith("::ffff:0:")) return false;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return false;
  if (/^fe[89ab]/.test(normalized) || normalized.startsWith("ff")) return false;
  if (normalized.startsWith("2001:db8") || normalized.startsWith("2001:0:")) return false;
  if (normalized.startsWith("2001:2:") || normalized.startsWith("2001:10:") || normalized.startsWith("2001:20:")) return false;
  if (normalized.startsWith("100::") || normalized.startsWith("64:ff9b:1::")) return false;
  const first = Number.parseInt(normalized.split(":")[0] || "0", 16);
  // Global unicast is 2000::/3. This excludes reserved 0/3 and future-use
  // ranges while allowing compressed public addresses such as 2001:4860::.
  return first >= 0x2000 && first <= 0x3fff;
}

export function allowedOrigin(request: Request, configured: string): string | null {
  const origin = request.headers.get("Origin");
  if (!origin) return null;
  const allowlist = configured.split(",").map((item) => item.trim()).filter(Boolean);
  return allowlist.includes(origin) ? origin : null;
}
