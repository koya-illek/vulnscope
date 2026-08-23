import { describe, it, expect } from "vitest";
import { fingerprint } from "../src/fingerprint";

function htmlHeaders(headers: Record<string, string> = {}): Headers {
  return new Headers(headers);
}

describe("fingerprint CMS detection", () => {
  it("does not detect WordPress from prose that merely mentions it", () => {
    const html = `
      <article><h1>Our favourite wordpress plugins</h1>
      <p>We migrated away from WordPress last year and wrote about wordpress
      performance in this guide.</p></article>`;
    const { result } = fingerprint(htmlHeaders(), html);
    expect(result.cms).toBeNull();
  });

  it("does not detect Joomla or Ghost from prose that merely mentions them", () => {
    const html = `
      <article><h1>Ghost stories and our Joomla migration</h1>
      <p>We compared Ghost against Joomla before settling on a static site.
      The word ghost alone must not fingerprint a CMS.</p></article>`;
    const { result } = fingerprint(htmlHeaders(), html);
    expect(result.cms).toBeNull();
  });

  it("detects Joomla from its generator meta tag", () => {
    const html = `<meta name="generator" content="Joomla! - Open Source Content Management">`;
    const { result } = fingerprint(htmlHeaders(), html);
    expect(result.cms?.name).toBe("Joomla");
  });

  it("detects Ghost from its generator meta tag", () => {
    const html = `<meta name="generator" content="Ghost 5.87">`;
    const { result } = fingerprint(htmlHeaders(), html);
    expect(result.cms?.name).toBe("Ghost");
  });

  it("detects WordPress from wp-content asset markers", () => {
    const html = `<link rel="stylesheet" href="/wp-content/themes/a/style.css">`;
    const { result } = fingerprint(htmlHeaders(), html);
    expect(result.cms?.name).toBe("WordPress");
  });

  it("detects WordPress from the generator meta tag and extracts the version", () => {
    const html = `<meta name="generator" content="WordPress 6.4.2">`;
    const { result } = fingerprint(htmlHeaders(), html);
    expect(result.cms).toEqual({ name: "WordPress", version: "6.4.2" });
  });

  it("detects WordPress from wp-includes without a version", () => {
    const html = `<script src="/wp-includes/js/jquery.min.js"></script>`;
    const { result } = fingerprint(htmlHeaders(), html);
    expect(result.cms).toEqual({ name: "WordPress", version: null });
  });

  it("still exposes a version finding only when the generator meta carries one", () => {
    const withVersion = fingerprint(
      htmlHeaders(),
      `<meta name="generator" content="WordPress 5.9">`,
    );
    expect(withVersion.findings.some((f) => f.id === "fingerprint-cms-version-exposed")).toBe(true);

    const withoutVersion = fingerprint(
      htmlHeaders(),
      `<link rel="stylesheet" href="/wp-content/style.css">`,
    );
    expect(withoutVersion.findings).toEqual([]);
  });
});
