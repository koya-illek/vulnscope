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
    const versionFinding = withVersion.findings.find((finding) => finding.id === "fingerprint-cms-version-exposed");
    expect(versionFinding?.severity).toBe("info");
    expect(versionFinding?.detail).not.toMatch(/outdated|unsupported|vulnerable/i);

    const withoutVersion = fingerprint(
      htmlHeaders(),
      `<link rel="stylesheet" href="/wp-content/style.css">`,
    );
    expect(withoutVersion.findings).toEqual([]);
  });

  it("records server software without duplicating the header-audit finding", () => {
    const observed = fingerprint(htmlHeaders({ Server: "nginx/1.24.0" }), "");

    expect(observed.result.server).toBe("nginx/1.24.0");
    expect(observed.findings.some((finding) => finding.id === "fingerprint-server-version")).toBe(false);
  });
});

describe("fingerprint framework detection", () => {
  it("does not detect frameworks or CMSes from prose or links that merely mention them", () => {
    const html = `
      <article><h1>The Great Gatsby</h1>
      <p>Fitzgerald published The Great Gatsby in 1925.</p>
      <p>We compared Angular against Squarespace before moving off Wix.com;
      our Angular migration guide explains the rest.</p>
      <a href="https://www.wix.com/">Wix.com</a></article>`;
    const { result } = fingerprint(htmlHeaders(), html);
    expect(result.cms).toBeNull();
    expect(result.framework).toBeNull();
  });

  it("detects Angular from rendered-output markers only", () => {
    const ngVersion = fingerprint(htmlHeaders(), `<app-root ng-version="17.3.0"></app-root>`);
    expect(ngVersion.result.framework?.name).toBe("Angular");
    const ngContent = fingerprint(htmlHeaders(), `<p _ngcontent-ng-c123=""></p>`);
    expect(ngContent.result.framework?.name).toBe("Angular");
  });

  it("detects Gatsby from build-output markers", () => {
    const html = `<div id="___gatsby"><div class="gatsby-image-wrapper"></div></div>`;
    const { result } = fingerprint(htmlHeaders(), html);
    expect(result.framework?.name).toBe("Gatsby");
  });

  it("detects Squarespace and Wix from their asset hostnames", () => {
    const squarespace = fingerprint(
      htmlHeaders(),
      `<script src="https://static1.squarespace.com/static/site-css.css"></script>`,
    );
    expect(squarespace.result.cms?.name).toBe("Squarespace");

    const wix = fingerprint(
      htmlHeaders(),
      `<link rel="icon" href="https://static.wixstatic.com/media/favicon.ico">`,
    );
    expect(wix.result.cms?.name).toBe("Wix");
  });
});
