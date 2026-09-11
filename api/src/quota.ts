import { ConfigurationError } from "./security";

const MIN_HMAC_KEY_BYTES = 32;

export const HMAC_KEY_CONFIG_ERROR =
  "RATE_LIMIT_HMAC_KEY is missing or shorter than 32 bytes. Set it with `npx wrangler secret put RATE_LIMIT_HMAC_KEY` in production, or copy api/.dev.vars.example to api/.dev.vars for local development.";

interface DailyQuotaKeyInput {
  scope: string;
  date: string;
  clientAddress: string;
  secret: string;
}

/**
 * Derive a daily, scope-specific quota identifier without retaining a value
 * that can be checked against guessed IP addresses after a D1 disclosure.
 */
export async function deriveDailyQuotaKey({
  scope,
  date,
  clientAddress,
  secret,
}: DailyQuotaKeyInput): Promise<string> {
  const encoder = new TextEncoder();
  if (typeof secret !== "string" || secret.length === 0) {
    throw new ConfigurationError(HMAC_KEY_CONFIG_ERROR);
  }
  const secretBytes = encoder.encode(secret);
  if (secretBytes.byteLength < MIN_HMAC_KEY_BYTES) {
    throw new ConfigurationError(HMAC_KEY_CONFIG_ERROR);
  }

  const hmacKey = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const message = encoder.encode(`${scope}\0${date}\0${clientAddress}`);
  const signature = await crypto.subtle.sign("HMAC", hmacKey, message);
  const fingerprint = [...new Uint8Array(signature)]
    .slice(0, 16)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  return `${scope}:v2:${fingerprint}`;
}
