import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { VERSION } from "../src/version";
import { USER_AGENT } from "../src/outbound";

describe("production Worker routing", () => {
  it("fetches Worker-backed targets through Cloudflare's public front door", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");

    expect(config).toMatch(
      /^compatibility_flags\s*=\s*\[\s*"global_fetch_strictly_public"\s*\]/m,
    );
  });

  it("does not commit the production quota HMAC secret as a plain Worker variable", async () => {
    const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");

    expect(config).not.toMatch(/^RATE_LIMIT_HMAC_KEY\s*=/m);
  });

  it("ships a secret-free local-dev example instead of a committed .dev.vars file", async () => {
    const example = await readFile(new URL("../.dev.vars.example", import.meta.url), "utf8");
    expect(example).toMatch(/^ENVIRONMENT=development$/m);
    expect(example).toMatch(/^ALLOWED_ORIGINS=/m);
    expect(example).toMatch(/^RATE_LIMIT_HMAC_KEY=.+$/m);
    const key = example.match(/^RATE_LIMIT_HMAC_KEY=(.+)$/m)?.[1] || "";
    expect(key.length).toBeGreaterThanOrEqual(32);
    expect(example).not.toMatch(/sk_live_|AKIA|ghp_/);
  });
});

describe("release version alignment", () => {
  // Every published surface names the product version. When one moves without
  // the others, agents and monitoring compare mismatched contracts.
  it("keeps package.json, both API contracts and the scanner UA on one version", async () => {
    const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
    const openapi = await readFile(new URL("../../web/openapi.yaml", import.meta.url), "utf8");
    const copilot = await readFile(new URL("../../web/mcp-copilot.yaml", import.meta.url), "utf8");

    expect(pkg.version).toBe(VERSION);
    expect(openapi).toMatch(new RegExp(`^  version: ["']?${VERSION}["']?$`, "m"));
    expect(copilot).toMatch(new RegExp(`^  version: ["']?${VERSION}["']?$`, "m"));
    expect(USER_AGENT).toContain(`VulnScanner/${VERSION}`);
  });
});
