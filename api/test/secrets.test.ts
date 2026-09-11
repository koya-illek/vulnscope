import { describe, it, expect } from "vitest";
import { scanForSecrets, hashSecretValue, MAX_SECRET_FINDINGS } from "../src/secrets";
import type { SecretFinding } from "../src/types";

describe("scanForSecrets", () => {
  it("returns empty array for empty input", async () => {
    const results = await scanForSecrets([]);
    expect(results).toEqual([]);
  });

  it("returns empty array for clean JavaScript", async () => {
    const bundles = [
      { url: "https://example.com/app.js", content: "const x = 1; console.log('hello');" },
    ];
    const results = await scanForSecrets(bundles);
    expect(results).toEqual([]);
  });

  it("detects AWS Access Keys", async () => {
    const bundles = [
      { url: "https://example.com/app.js", content: 'const key = "AKIAIOSFODNN7EXAMPLE";' },
    ];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("aws-access-key");
    expect(results[0].severity).toBe("critical");
    expect(results[0].source).toBe("https://example.com/app.js");
  });

  it("detects AWS Secret Keys", async () => {
    const content = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("aws-secret-key");
    expect(results[0].severity).toBe("critical");
  });

  it("detects Stripe live secret keys", async () => {
    const content = 'const stripeKey = "sk_live_1234567890abcdefghijklmnopqrstuv";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("stripe-secret-key");
  });

  it("detects Stripe publishable keys", async () => {
    const content = 'const pubKey = "pk_live_1234567890abcdefghijklmnopqrstuv";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("stripe-publishable-key");
    expect(results[0].severity).toBe("high");
  });

  it("detects Google API keys", async () => {
    const content = 'const gKey = "AIzaSyA1234567890abcdefghijklmnopqrstuv";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("google-api-key");
  });

  it("detects GitHub tokens", async () => {
    const content = 'const token = "ghp_1234567890abcdefghijklmnopqrstuv1234";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("github-token");
  });

  it("detects GitHub PAT tokens", async () => {
    const content = 'const pat = "github_pat_" + "0".repeat(82);';
    const bundles = [{ url: "https://example.com/app.js", content: 'const pat = "github_pat_' + "0".repeat(82) + '"'}];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("github-pat");
  });

  it("detects Slack tokens", async () => {
    const content = 'const slackToken = "xoxb-1234567890-abcdefghij";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("slack-token");
  });

  it("detects private keys", async () => {
    const content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...";
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("private-key");
    expect(results[0].severity).toBe("critical");
  });

  it("detects EC private keys", async () => {
    const content = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...";
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("private-key");
  });

  it("detects generic private key without prefix", async () => {
    const content = "-----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQEA...";
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
  });

  it("detects JWT tokens", async () => {
    const content = 'const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("jwt-token");
  });

  it("detects Twilio keys", async () => {
    const content = 'const twilioKey = "SK1234567890abcdef1234567890abcdef";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("twilio-key");
    expect(results[0].severity).toBe("medium");
    expect(results[0].confidence).toBe("medium");
  });

  it("does not report heuristic severities as critical", async () => {
    const content = [
      'const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123";',
      'const twilio = "SK1234567890abcdef1234567890abcdef";',
      'const mg = "key-1234567890abcdefghijklmnop1234567890";',
    ].join("\n");
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.map((r) => r.type).sort()).toEqual(["jwt-token", "mailgun-key", "twilio-key"]);
    for (const finding of results) {
      expect(finding.severity).toBe("medium");
      expect(finding.confidence).toBe("medium");
    }
    const jwt = results.find((r) => r.type === "jwt-token");
    expect(jwt!.severity).toBe("medium");
  });

  it("detects SendGrid keys", async () => {
    const content = 'const sgKey = "SG.1234567890123456789012.123456789012345678901234567890123456789012345";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("sendgrid-key");
  });

  it("detects Mailgun keys", async () => {
    const content = 'const mgKey = "key-1234567890abcdefghijklmnop1234567890";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("mailgun-key");
  });

  it("detects connection strings", async () => {
    const content = 'const dbUrl = "mongodb://user:password123@cluster.mongodb.net/db";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("connection-string");
  });

  it("detects PostgreSQL connection strings", async () => {
    const content = 'const dbUrl = "postgres://admin:secretpass@db.example.com:5432/mydb";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("connection-string");
  });

  it("detects generic API keys at medium so they cannot force grade D or F", async () => {
    const content = 'const config = { api_key: "abcdefghijklmnop1234567890abcdefghij" };';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("generic-api-key");
    expect(results[0].severity).toBe("medium");
  });

  it("detects generic secrets at medium so they cannot force grade D or F", async () => {
    const content = 'const secret = "mySecretValue1234567";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("generic-secret");
    expect(results[0].severity).toBe("medium");
  });

  it("detects Firebase configs", async () => {
    const content = 'const config = { apiKey: "AIzaSyA1234567890abcdefghijklmnopqrstuv" };';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const firebase = results.find((r) => r.type === "firebase-config");
    expect(firebase).toBeTruthy();
  });

  it("detects multiple secrets in a single bundle", async () => {
    const content = `
      const awsKey = "AKIAIOSFODNN7EXAMPLE";
      const stripeKey = "sk_live_1234567890abcdefghijklmnopqrstuv";
      const githubToken = "ghp_1234567890abcdefghijklmnopqrstuv1234";
    `;
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(3);
  });

  it("detects secrets across multiple bundles", async () => {
    const bundles = [
      { url: "https://example.com/app.js", content: 'const key = "AKIAIOSFODNN7EXAMPLE";' },
      { url: "https://example.com/vendor.js", content: 'const token = "ghp_1234567890abcdefghijklmnopqrstuv1234";' },
    ];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(2);
    expect(results[0].source).toBe("https://example.com/app.js");
    expect(results[1].source).toBe("https://example.com/vendor.js");
  });

  it("stores a stable hash instead of prefix or suffix secret material", async () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const content = `const key = "${secret}";`;
    const bundles = [{ url: "https://example.com/app.js?token=abc", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    const finding = results[0];
    expect(finding.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(finding.hash).toBe(await hashSecretValue(secret));
    expect(JSON.stringify(finding)).not.toContain(secret);
    expect(JSON.stringify(finding)).not.toContain("AKIAIOSF");
    expect(JSON.stringify(finding)).not.toContain("MPLE");
    expect(finding).not.toHaveProperty("snippet");
    expect(finding.source).toBe("https://example.com/app.js");
  });

  it("hashes connection-string userinfo instead of storing it", async () => {
    const content = 'const dbUrl = "postgres://admin:secretpass@db.example.com:5432/mydb";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    const serialized = JSON.stringify(results[0]);
    expect(serialized).not.toContain("admin");
    expect(serialized).not.toContain("secretpass");
    expect(results[0].hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("calculates approximate line numbers", async () => {
    const content = "line1\nline2\nline3\nconst key = \"AKIAIOSFODNN7EXAMPLE\";";
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].line).toBe(4);
  });

  it("handles minified single-line JS correctly", async () => {
    const content = '!function(){var t="AKIAIOSFODNN7EXAMPLE";console.log(t)}();';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].line).toBe(1);
  });

  it("all findings have correct shape", async () => {
    const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    const finding: SecretFinding = results[0];
    expect(typeof finding.type).toBe("string");
    expect(["critical", "high"]).toContain(finding.severity);
    expect(finding.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(typeof finding.line).toBe("number");
    expect(typeof finding.source).toBe("string");
    expect(finding).not.toHaveProperty("snippet");
  });

  it("caps the number of secret findings per scan", async () => {
    const keys = Array.from({ length: MAX_SECRET_FINDINGS + 10 }, (_, i) =>
      `api_key: "${"a".repeat(32)}${String(i).padStart(4, "0")}"`,
    );
    const bundles = [{ url: "https://example.com/app.js", content: keys.join("\n") }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(MAX_SECRET_FINDINGS);
  });
});
