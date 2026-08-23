import type { Finding, FingerprintResult } from "./types";

/**
 * Detect software, CMS, framework, and languages from response headers + HTML body.
 */
export function fingerprint(
  headers: Headers,
  html: string,
): { result: FingerprintResult; findings: Finding[] } {
  const findings: Finding[] = [];

  // --- Server ---
  const server = headers.get("server") || null;

  // --- X-Powered-By ---
  const poweredBy = headers.get("x-powered-by") || null;

  // --- CMS detection from HTML ---
  // WordPress requires structural markers (asset paths or the generator meta
  // tag). The bare word "wordpress" appears in ordinary blog prose and must
  // not trigger the full WordPress probe phase on non-WordPress sites.
  let cms: FingerprintResult["cms"] = null;
  if (/wp-content|wp-includes|wp-json|name=["']generator["']\s+content=["']WordPress/i.test(html)) {
    const versionMatch = html.match(/name=["']generator["']\s+content=["']WordPress\s+([\d.]+)/i);
    cms = { name: "WordPress", version: versionMatch ? versionMatch[1] : null };
  } else if (/drupal\.settings|drupal\.js|class=["'][^"']*drupal/i.test(html)) {
    const versionMatch = html.match(/name=["']generator["']\s+content=["']Drupal\s+([\d.]+)/i);
    cms = { name: "Drupal", version: versionMatch ? versionMatch[1] : null };
  } else if (
    // Structural markers only: bare "joomla" appears in ordinary tech prose.
    /name=["']generator["']\s+content=["']Joomla|\/media\/(?:jui|system)\/js\/|\/components\/com_[a-z]+\/|\/modules\/mod_[a-z]+\//i.test(html)
  ) {
    cms = { name: "Joomla", version: null };
  } else if (
    // Same rule as Joomla: "ghost" is a common word and proves nothing.
    /name=["']generator["']\s+content=["']Ghost|\/ghost(?:-sdk)?(?:\.min)?\.js|ghost-api=/i.test(html)
  ) {
    cms = { name: "Ghost", version: null };
  } else if (/cdn\.shopify\.com|shopify\.theme/i.test(html)) {
    cms = { name: "Shopify", version: null };
  } else if (
    // Structural asset markers only: bare "squarespace" appears in ordinary
    // comparison articles and reviews.
    /static1\.squarespace\.com|squarespace-cdn\.com|assets\.squarespace\.com/i.test(html)
  ) {
    cms = { name: "Squarespace", version: null };
  } else if (
    // A bare wix.com link proves nothing about the page itself; these are
    // Wix asset hostnames present in pages actually built with Wix.
    /wixstatic|static\.parastorage\.com/i.test(html)
  ) {
    cms = { name: "Wix", version: null };
  }

  // --- Framework detection ---
  let framework: FingerprintResult["framework"] = null;
  if (/__NEXT_DATA__|_next\/static/i.test(html)) {
    framework = { name: "Next.js", version: null };
  } else if (/<div\s+id=["']__nuxt["']/i.test(html) || /_nuxt\//i.test(html)) {
    framework = { name: "Nuxt", version: null };
  } else if (/data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__/i.test(html)) {
    framework = { name: "React", version: null };
  } else if (/data-v-[a-z0-9]{8}|vue\.runtime/i.test(html)) {
    framework = { name: "Vue.js", version: null };
  } else if (/\bng-version=|_ngcontent|\bng-app[\s=>]/i.test(html)) {
    // Rendered-output markers only: bare "angular" appears in ordinary tech
    // prose. ng-version/_ngcontent are emitted by Angular builds; ng-app
    // covers AngularJS 1.x bootstrap attributes.
    framework = { name: "Angular", version: null };
  } else if (/___gatsby|\/page-data\/|gatsby-image-wrapper/i.test(html)) {
    // Gatsby build-output markers; bare "gatsby" also names a famous novel.
    framework = { name: "Gatsby", version: null };
  }

  // --- Language detection ---
  const languages: string[] = [];
  if (poweredBy) {
    if (/php/i.test(poweredBy)) languages.push("PHP");
    if (/asp\.net/i.test(poweredBy)) languages.push("ASP.NET");
    if (/express/i.test(poweredBy)) languages.push("Node.js (Express)");
    if (/servlet/i.test(poweredBy)) languages.push("Java");
  }
  if (server) {
    if (/microsoft-iis/i.test(server) && !languages.includes("ASP.NET")) {
      languages.push("ASP.NET");
    }
  }
  // Cookie-based language detection
  const setCookie = headers.get("set-cookie") || "";
  if (/PHPSESSID/i.test(setCookie) && !languages.includes("PHP")) languages.push("PHP");
  if (/JSESSIONID/i.test(setCookie) && !languages.includes("Java")) languages.push("Java");
  if (/ASP\.NET_SessionId/i.test(setCookie) && !languages.includes("ASP.NET")) languages.push("ASP.NET");
  if (/connect\.sid/i.test(setCookie) && !languages.some((l) => l.includes("Node.js"))) {
    languages.push("Node.js");
  }

  // --- Findings ---
  if (cms && cms.version) {
    findings.push({
      id: "fingerprint-cms-version-exposed",
      severity: "low",
      category: "fingerprint",
      title: `${cms.name} Version Exposed`,
      detail: `The ${cms.name} version (${cms.version}) is publicly visible in the page source. Attackers can use this to find known vulnerabilities.`,
      evidence: `Generator meta tag reveals ${cms.name} ${cms.version}`,
      recommendation: "Remove or obscure the generator meta tag in your CMS configuration.",
    });
  }

  if (server && /\d/.test(server)) {
    findings.push({
      id: "fingerprint-server-version",
      severity: "medium",
      category: "fingerprint",
      title: "Server Software Version Exposed",
      detail: `The Server header reveals specific software version: ${server}.`,
      evidence: `Server: ${server}`,
      recommendation: "Configure the web server to hide version information.",
    });
  }

  const result: FingerprintResult = {
    server,
    poweredBy,
    cms,
    framework,
    languages,
  };

  return { result, findings };
}
