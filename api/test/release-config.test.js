import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

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
