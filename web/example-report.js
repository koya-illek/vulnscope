(function (root) {
  "use strict";

  /**
   * Sample data for the "View an example report" path. The target is the
   * RFC 2606 reserved `.example` TLD, so the fixture can never be mistaken
   * for a real scan of a real site, and every timestamp is derived from the
   * current clock so the sample never reads as stale.
   */
  function report() {
    const now = Date.now();
    const createdAt = new Date(now - 5 * 60 * 1000).toISOString();
    const expiresAt = new Date(now + 14 * 86_400_000).toISOString();
    const validTo = new Date(now + 68 * 86_400_000).toISOString();
    const validFrom = new Date(now + 68 * 86_400_000 - 90 * 86_400_000).toISOString();
    const observedAt = new Date(now - 5 * 60 * 1000).toISOString();

    return {
      schemaVersion: 2,
      id: "example000000000",
      requestedUrl: "https://shop.example/",
      hostname: "shop.example",
      status: "complete",
      createdAt,
      expiresAt,
      totalDurationMs: 11_842,
      observation: {
        vantage: "cloudflare-edge",
        colo: "DUB",
        country: "IE",
        disclaimer: "Observations are from the Cloudflare edge. Timings do not represent browser-side performance.",
      },
      outbound: {
        maxSubrequests: 46,
        maxConcurrent: 6,
        maxDurationMs: 25_000,
        requestsAttempted: 29,
        requestsSucceeded: 27,
        requestsFailed: 1,
        requestsSkipped: 0,
        activePeak: 6,
        bodyBytes: 483_211,
        truncatedBodies: 1,
        redirects: [
          { from: "http://shop.example/", to: "https://shop.example/", status: 301 },
        ],
      },
      coverage: {
        mainFetch: {
          status: "measured",
          detail: "GET response received with HTTP 200.",
          requested: true, attempts: 1, succeeded: 1, failed: 0, skipped: 0, bytes: 38_214, truncated: false,
        },
        headers: {
          status: "measured",
          detail: "Security headers were audited from the main GET response.",
          requested: true,
        },
        tlsProtocolCipher: {
          status: "unavailable",
          detail: "Origin TLS protocol/cipher was not assessed because Cloudflare Worker fetches do not expose the scanned origin's negotiated TLS protocol or cipher, and no active TLS probe was run.",
        },
        certificateEvidence: {
          status: "measured",
          detail: "crt.sh returned historical certificate-transparency evidence only. Certificate Transparency logs are historical: they prove a certificate was issued, not that it is currently served.",
        },
        dns: {
          status: "measured",
          detail: "Public DNS resolution confirmed 1 address record(s).",
          requested: true,
        },
        cookies: {
          status: "measured",
          detail: "Audited 1 cookie(s) from the main GET response.",
          requested: true,
        },
        paths: {
          status: "measured",
          detail: "Sensitive path probes completed with 1 response(s).",
          requested: true, attempts: 18, succeeded: 17, failed: 1, skipped: 0, bytes: 12_884, truncated: false,
        },
        cors: {
          status: "measured",
          detail: "GET and OPTIONS CORS probes completed.",
          requested: true,
        },
        secrets: {
          status: "measured",
          detail: "Scanned 2 JavaScript bundle(s) for exposed secrets.",
          requested: true, attempts: 2, succeeded: 2, failed: 0, skipped: 0, bytes: 402_113, truncated: true,
        },
        wordpress: {
          status: "skipped",
          detail: "WordPress deep checks were not enabled for this scan.",
          requested: false,
        },
        methods: {
          status: "measured",
          detail: "OPTIONS Allow reconnaissance completed.",
          requested: true,
        },
        takeover: {
          status: "skipped",
          detail: "Subdomain takeover checks were not enabled for this scan.",
          requested: false,
        },
        criticalGaps: [],
      },
      dns: {
        queries: [],
        addresses: ["203.0.113.10"],
        dnssecAuthenticated: false,
      },
      ssl: {
        protocol: null,
        cipher: null,
        issuer: "Let's Encrypt",
        subject: "shop.example",
        validFrom,
        validTo,
        daysUntilExpiry: 68,
        authorityKeyIdentifier: null,
        certificateEvidence: {
          source: "crt.sh",
          status: "observed",
          limitation: "Certificate Transparency logs are historical: they prove a certificate was issued, not that it is currently served.",
          observedAt,
        },
      },
      fingerprint: {
        server: "nginx/1.24.0",
        poweredBy: null,
        cms: null,
        framework: null,
        languages: ["PHP"],
      },
      headers: {
        hsts: { present: false, raw: null, maxAge: null, includeSubDomains: false, preload: false },
        csp: {
          present: true,
          hasUnsafeInline: false,
          hasUnsafeEval: false,
          hasWildcard: false,
          hasDefaultSrc: true,
          raw: "default-src 'self'; img-src 'self' data:; object-src 'none'",
        },
        xContentTypeOptions: { present: true, value: "nosniff" },
        xFrameOptions: { present: true, value: "SAMEORIGIN" },
        referrerPolicy: { present: false, value: null },
        permissionsPolicy: { present: false, value: null },
        xXssProtection: { present: false, value: null },
        serverRevealsVersion: true,
        poweredByRevealsTech: false,
      },
      cookies: [
        { name: "sid", secure: false, httpOnly: false, sameSite: null, domain: null, path: "/", expires: "Session" },
      ],
      exposedPaths: [
        {
          path: "/.env",
          method: "GET",
          status: 200,
          severity: "critical",
          name: ".env configuration file",
          description: "A Laravel-style environment file is publicly readable. It routinely holds database credentials, mail tokens, and application keys.",
          evidence: "Response body contains APP_KEY= and DB_PASSWORD= markers",
          responseSize: 1_242,
          truncated: false,
        },
      ],
      cors: {
        testedOrigin: "https://evil.example",
        acaoGet: null,
        acaoOptions: null,
        acacGet: null,
        acacOptions: null,
        reflectsOrigin: false,
        wildcardWithCredentials: false,
        vulnerable: false,
        evidence: "No Access-Control headers were returned on GET or OPTIONS.",
      },
      takeover: [],
      methods: {
        methods: [
          { method: "OPTIONS", allowed: true, evidence: 'Allow: GET, POST, OPTIONS', observation: "advertised" },
        ],
        traceVulnerable: false,
      },
      findings: [
        {
          id: "exposed-path--env",
          severity: "critical",
          category: "exposed-path",
          title: "Exposed: .env configuration file",
          detail: "The environment file at /.env is publicly readable. It routinely holds database credentials, mail provider tokens, and application encryption keys.",
          evidence: "GET /.env → 200 (Response body contains APP_KEY= and DB_PASSWORD= markers)",
          recommendation: "Restrict or remove access to /.env. Rotate every credential it contained, because scanners and attackers may already have collected them.",
        },
        {
          id: "missing-header-hsts",
          severity: "high",
          category: "missing-header",
          title: "Strict-Transport-Security missing",
          detail: "The site serves HTTPS but does not tell browsers to enforce it. Downgrade attacks and stray http:// links can pull visitors onto plaintext.",
          evidence: "No Strict-Transport-Security header on GET /",
          recommendation: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS-only is confirmed across every subdomain.",
        },
        {
          id: "cookie-sid-flags",
          severity: "medium",
          category: "cookie",
          title: "Session cookie lacks Secure, HttpOnly, and SameSite",
          detail: "The sid cookie is readable from scripts, travels over plaintext if offered, and is sent with cross-site requests.",
          evidence: "Set-Cookie: sid=…; Path=/ (no Secure, HttpOnly, or SameSite attribute)",
          recommendation: "Set Secure, HttpOnly, and SameSite=Lax on the session cookie.",
        },
        {
          id: "server-version-disclosure",
          severity: "low",
          category: "information-disclosure",
          title: "Server version disclosed",
          detail: "The Server header advertises nginx/1.24.0, letting attackers match known CVEs to the exact release.",
          evidence: "Server: nginx/1.24.0",
          recommendation: "Set server_tokens off so the version is no longer advertised.",
        },
        {
          id: "method-options",
          severity: "info",
          category: "method",
          title: "HTTP OPTIONS Advertised by Allow Header",
          detail: "Allow: GET, POST, OPTIONS. VulnScope did not send an OPTIONS request beyond the CORS preflight probe.",
          evidence: "Allow: GET, POST, OPTIONS",
          recommendation: "Review whether the advertised OPTIONS method is required; VulnScope did not send a standalone OPTIONS request.",
        },
      ],
      summary: {
        grade: "F",
        critical: 1,
        high: 1,
        medium: 1,
        low: 1,
        info: 1,
      },
    };
  }

  root.VulnScopeExample = { report };
})(typeof window === "undefined" ? globalThis : window);
