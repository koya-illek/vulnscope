import { describe, it, expect } from "vitest";
import { scanForSecrets } from "../src/secrets";
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
    // The loose SK+hex shape also occurs in minified code, so it is capped at
    // high severity with medium confidence instead of forcing a grade of F.
    expect(results[0].severity).toBe("high");
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
      // No heuristic shape may claim critical severity or high confidence.
      expect(["medium", "high"]).toContain(finding.severity);
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

  it("detects generic API keys", async () => {
    const content = 'const config = { api_key: "abcdefghijklmnop1234567890abcdefghij" };';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("generic-api-key");
  });

  it("detects generic secrets", async () => {
    const content = 'const secret = "mySecretValue1234567";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    expect(results[0].type).toBe("generic-secret");
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

  it("redacts secret values in snippets", async () => {
    const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    const bundles = [{ url: "https://example.com/app.js", content }];
    const results = await scanForSecrets(bundles);
    expect(results.length).toBe(1);
    const snippet = results[0].snippet;
    // Snippet should NOT contain the full secret
    expect(snippet).not.toContain("AKIAIOSFODNN7EXAMPLE");
    // Snippet should contain the beginning
    expect(snippet).toContain("AKIA");
    // Snippet should contain "..."
    expect(snippet).toContain("...");
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
    expect(typeof finding.snippet).toBe("string");
    expect(typeof finding.line).toBe("number");
    expect(typeof finding.source).toBe("string");
  });
});
