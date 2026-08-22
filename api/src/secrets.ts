import type { SecretFinding } from "./types";
import { redactUrlForStorage } from "./security";

// ─── Secret detection patterns ─────────────────────────────────────────────

interface SecretPattern {
  type: string;
  /**
   * Only structurally unambiguous provider prefixes justify critical/high.
   * Heuristic shapes that also occur in ordinary minified JavaScript are
   * capped at medium so a single false positive cannot force a grade of F
   * on a publicly shareable report.
   */
  severity: "critical" | "high" | "medium";
  regex: RegExp;
  confidence: "high" | "medium";
}

const PATTERNS: SecretPattern[] = [
  { type: "aws-access-key", severity: "critical", confidence: "high", regex: /AKIA[0-9A-Z]{16}/g },
  { type: "aws-secret-key", severity: "critical", confidence: "high", regex: /aws_secret_access_key\s*[=:]\s*['"][A-Za-z0-9/+=]{40}['"]/g },
  { type: "stripe-secret-key", severity: "critical", confidence: "high", regex: /sk_live_[0-9a-zA-Z]{24,}/g },
  { type: "stripe-publishable-key", severity: "high", confidence: "medium", regex: /pk_live_[0-9a-zA-Z]{24,}/g },
  { type: "stripe-restricted-key", severity: "critical", confidence: "high", regex: /rk_live_[0-9a-zA-Z]{24,}/g },
  { type: "google-api-key", severity: "high", confidence: "high", regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { type: "github-token", severity: "critical", confidence: "high", regex: /gh[ps]_[0-9a-zA-Z]{36}/g },
  { type: "github-pat", severity: "critical", confidence: "high", regex: /github_pat_[0-9a-zA-Z_]{82}/g },
  { type: "slack-token", severity: "critical", confidence: "high", regex: /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/g },
  { type: "generic-api-key", severity: "high", confidence: "medium", regex: /api[_-]?key\s*[=:]\s*['"][A-Za-z0-9]{32,}['"]/gi },
  { type: "generic-secret", severity: "high", confidence: "medium", regex: /secret\s*[=:]\s*['"][A-Za-z0-9]{16,}['"]/gi },
  { type: "private-key", severity: "critical", confidence: "high", regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g },
  // JWT-shaped strings appear routinely in client-side bundles (session and
  // anonymous tokens); presence alone does not demonstrate a leaked secret.
  { type: "jwt-token", severity: "medium", confidence: "medium", regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./g },
  { type: "firebase-config", severity: "high", confidence: "high", regex: /apiKey\s*:\s*['"]AIza[0-9A-Za-z\-_]{35}['"]/g },
  // SK + 32 hex chars also matches ordinary identifiers in minified code;
  // boundaries plus a high-severity cap keep false positives from failing grades.
  { type: "twilio-key", severity: "high", confidence: "medium", regex: /\bSK[0-9a-fA-F]{32}\b/g },
  { type: "sendgrid-key", severity: "critical", confidence: "high", regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g },
  { type: "mailgun-key", severity: "high", confidence: "medium", regex: /\bkey-[0-9a-zA-Z]{32}/g },
  { type: "connection-string", severity: "critical", confidence: "high", regex: /(?:mongodb|postgres|redis|amqp):\/\/[^:\s]+:[^@\s]+@/g },
];

// ─── Scanning ──────────────────────────────────────────────────────────────

/**
 * Scan JavaScript bundle contents for hardcoded secrets and API keys.
 * Each finding is redacted — the full secret value is never stored.
 */
export async function scanForSecrets(
  bundles: Array<{ url: string; content: string }>,
): Promise<SecretFinding[]> {
  const findings: SecretFinding[] = [];
  const seen = new Map<string, number>();

  for (const bundle of bundles) {
    for (const pattern of PATTERNS) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(bundle.content)) !== null) {
        const matchedValue = match[0];
        const line = getLineNumber(bundle.content, match.index);
        const source = redactUrlForStorage(bundle.url);
        const valueKey = extractSecretValue(matchedValue);
        const duplicateKey = `${source}|${valueKey}`;
        const existingIndex = seen.get(duplicateKey);
        const nextFinding = {
          type: pattern.type,
          severity: pattern.severity,
          snippet: redactSecret(matchedValue),
          line,
          source,
          confidence: pattern.confidence,
        } satisfies SecretFinding;
        // Firebase config is a more useful classification than the generic
        // Google key pattern, so replace that overlapping observation once.
        if (existingIndex !== undefined) {
          if (pattern.type === "firebase-config" && findings[existingIndex]?.type === "google-api-key") {
            findings[existingIndex] = nextFinding;
          }
          continue;
        }
        seen.set(duplicateKey, findings.length);
        findings.push(nextFinding);
      }
    }
  }

  return findings;
}

function extractSecretValue(value: string): string {
  const token = value.match(/(?:AIza|AKIA|sk_live_|pk_live_|rk_live_|gh[pso]_\w+|github_pat_|xox[baprs]-|SG\.|key-|SK[0-9a-fA-F]{32}|eyJ)[A-Za-z0-9_./+=:-]*/i);
  return (token?.[0] || value).toLowerCase();
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/**
 * Approximate line number of the match in the source content.
 */
function getLineNumber(content: string, matchIndex: number): number {
  const before = content.slice(0, matchIndex);
  return before.split("\n").length;
}

/**
 * Redact a secret value, showing only the first 8 and last 4 characters.
 * Short values are further redacted to avoid exposure.
 */
function redactSecret(value: string): string {
  if (value.length <= 16) {
    return value.slice(0, 4) + "..." + value.slice(-2);
  }
  return value.slice(0, 8) + "..." + value.slice(-4);
}
