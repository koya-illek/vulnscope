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
