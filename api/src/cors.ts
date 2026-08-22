import type { CorsResult, Finding } from "./types";
import { safeFetch, USER_AGENT, type OutboundContext } from "./outbound";
import { redactUrlsInText } from "./security";

const EVIL_ORIGIN = "https://evil.example";

/**
 * Test CORS misconfiguration with minimal subrequests.
 * Sends OPTIONS preflight + GET with a malicious Origin header.
 */
export async function testCors(
  targetUrl: string,
  context?: OutboundContext,
): Promise<{ result: CorsResult; findings: Finding[] }> {
  const findings: Finding[] = [];

  let acaoGet: string | null = null;
  let acaoOptions: string | null = null;
  let acacGet: string | null = null;
  let acacOptions: string | null = null;

  // Run both requests concurrently
  const [getResult, optionsResult] = await Promise.allSettled([
    fetchCors(targetUrl, "GET", context),
    fetchCors(targetUrl, "OPTIONS", context),
  ]);

  if (getResult.status === "fulfilled") {
    acaoGet = getResult.value.acao;
    acacGet = getResult.value.acac;
  }
  if (optionsResult.status === "fulfilled") {
    acaoOptions = optionsResult.value.acao;
    acacOptions = optionsResult.value.acac;
  }

  const reflectsOrigin =
    acaoGet === EVIL_ORIGIN || acaoOptions === EVIL_ORIGIN;
  const isWildcard = acaoGet === "*" || acaoOptions === "*";
  const credentialsAllowed =
    /true/i.test(acacGet || "") || /true/i.test(acacOptions || "");
  const wildcardWithCredentials = isWildcard && credentialsAllowed;

  const vulnerable = reflectsOrigin || wildcardWithCredentials;

  // Severity follows browser-enforced exploitability, not header presence:
  // - Origin reflection plus Access-Control-Allow-Credentials true lets an
  //   attacker's site read credentialed responses — high.
  // - Reflection without credentials only exposes what any visitor can read
  //   publicly — medium.
  // - Wildcard ACAO with ACAC true is refused by browsers for credentialed
  //   requests, so it cannot be exploited as-is; it stays high as evidence of
  //   broken CORS intent but does not claim demonstrated credential theft.
  const reflectedWithCredentials = reflectsOrigin && credentialsAllowed && !isWildcard;

  if (reflectsOrigin) {
    findings.push({
      id: "cors-origin-reflection",
      severity: reflectedWithCredentials ? "high" : "medium",
      category: "cors",
      title: "CORS Reflects Arbitrary Origins",
      detail: reflectedWithCredentials
        ? "The server reflects the request Origin in the Access-Control-Allow-Origin response header and also allows credentials. Other websites may read authenticated responses on behalf of visitors."
        : "The server reflects the request Origin in the Access-Control-Allow-Origin response header. Because credentials are not allowed alongside the reflection, browsers limit the impact to reading responses that are otherwise public; this still widens who can read the endpoint programmatically.",
      evidence: `ACAO reflected ${EVIL_ORIGIN} (GET: ${acaoGet}, OPTIONS: ${acaoOptions})`,
      recommendation: "Configure the server to only allow specific trusted origins in CORS headers, never reflect arbitrary origins.",
    });
  }

  if (wildcardWithCredentials) {
    findings.push({
      id: "cors-wildcard-credentials",
      severity: "high",
      category: "cors",
      title: "CORS Wildcard Origin with Credentials Allowed",
      detail: "The server returns Access-Control-Allow-Origin: * AND allows credentials. Browsers refuse to attach credentials to wildcard-origin responses, so this combination is not exploitable as-is, but it signals a misunderstood CORS policy and should be corrected before credentials are ever honored.",
      evidence: `ACAO: *, ACAC: true`,
      recommendation: "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
    });
  }

  const result: CorsResult = {
    testedOrigin: EVIL_ORIGIN,
    acaoGet,
    acaoOptions,
    acacGet,
    acacOptions,
    reflectsOrigin,
    wildcardWithCredentials,
    vulnerable,
    evidence: buildEvidence(acaoGet, acaoOptions, acacGet, acacOptions),
  };

  return { result, findings };
}

async function fetchCors(
  targetUrl: string,
  method: "GET" | "OPTIONS",
  context?: OutboundContext,
): Promise<{ acao: string | null; acac: string | null }> {
  try {
    const response = await safeFetch(targetUrl, {
      method,
      baseUrl: new URL(targetUrl),
      followRedirects: false,
      phase: "cors",
      context,
      headers: {
        Origin: EVIL_ORIGIN,
        ...(method === "OPTIONS"
          ? {
              "Access-Control-Request-Method": "GET",
              "Access-Control-Request-Headers": "content-type",
            }
          : {}),
        "User-Agent": USER_AGENT,
      },
      timeoutMs: 5_000,
    });

    return {
      acao: redactUrlsInText(response.headers.get("access-control-allow-origin") || "") || null,
      acac: redactUrlsInText(response.headers.get("access-control-allow-credentials") || "") || null,
    };
  } catch {
    return { acao: null, acac: null };
  }
}

function buildEvidence(
  acaoGet: string | null,
  acaoOptions: string | null,
  acacGet: string | null,
  acacOptions: string | null,
): string {
  const parts: string[] = [];
  if (acaoGet) parts.push(`ACAO (GET): ${acaoGet}`);
  if (acaoOptions) parts.push(`ACAO (OPTIONS): ${acaoOptions}`);
  if (acacGet) parts.push(`ACAC (GET): ${acacGet}`);
  if (acacOptions) parts.push(`ACAC (OPTIONS): ${acacOptions}`);
  return parts.length > 0 ? parts.join("; ") : "No CORS headers returned";
}
