(() => {
  "use strict";

  const API_BASE = (window.VULN_SCANNER_CONFIG?.API_BASE || "").replace(/\/$/, "");
  const reportView = window.VulnScopeReport;
  const streamReader = window.VulnScopeStream;
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const state = { report: null, progressStep: 0, activeFilter: "all" };
  // One scan or report load owns the UI at a time; runToken invalidates
  // completions of runs abandoned via "New scan", Cancel, or Back navigation,
  // and activeAbort tears down their in-flight requests.
  let busy = false;
  let runToken = 0;
  let activeAbort = null;
  const OBSERVATION_NOTE_SUFFIX = "VulnScope performs unauthenticated checks only. It does not attempt exploitation, submit forms, or bypass authentication. Findings reflect what an external observer can discover without credentials.";

  const form = $("#scan-form");
  const input = $("#url-input");
  const scanButton = $("#scan-button");
  const authConfirm = $("#auth-confirm");
  const probePathsCheckbox = $("#probe-paths");
  const checkTakeoverCheckbox = $("#check-takeover");
  const progressPanel = $("#progress-panel");
  const errorPanel = $("#error-panel");
  const reportPanel = $("#report");
  const methodDialog = $("#method-dialog");
  let methodDialogReturnFocus = null;

  // Stage order mirrors the backend pipeline: recon/dns/fetch/ssl, then
  // headers/cookies, fingerprint, paths, then cors/secrets/wordpress/methods/
  // takeover together on the CORS node. Keeping the map monotonic with the
  // emitted stages stops the route nodes from jumping backwards.
  const STAGE_MAP = {
    validated: 0,
    dns: 0,
    fetch: 0,
    ssl: 0,
    headers: 1,
    cookies: 1,
    fingerprint: 2,
    paths: 3,
    cors: 4,
    secrets: 4,
    wordpress: 4,
    methods: 4,
    takeover: 4,
    complete: 5
  };

  function updateScanAvailability() {
    const authorised = Boolean(authConfirm?.checked);
    // A running scan owns the form: checkbox flips mid-run must not
    // re-enable the submit button or imply late option changes applied.
    scanButton.disabled = busy || !authorised;
    probePathsCheckbox.disabled = busy;
    checkTakeoverCheckbox.disabled = busy;
    $("#scan-state").textContent = busy
      ? "Scan in progress."
      : authorised
        ? "Permission confirmed. Ready to scan."
        : "Confirm permission to enable the scan.";
  }

  authConfirm?.addEventListener("change", updateScanAvailability);
  updateScanAvailability();

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (busy) return;
    if (authConfirm && !authConfirm.checked) {
      showError("Please confirm you have permission to scan this target.");
      return;
    }
    runScan(input.value);
  });
  $("#new-scan").addEventListener("click", () => reset());
  $("#cancel-scan").addEventListener("click", () => reset());
  $("#error-close").addEventListener("click", () => {
    errorPanel.classList.add("hidden");
    input.focus();
  });
  $("#copy-link").addEventListener("click", copyShareLink);
  $("#export-json").addEventListener("click", exportJson);
  $("#method-button").addEventListener("click", (event) => openMethodDialog(event.currentTarget));
  $("#footer-method-button").addEventListener("click", (event) => openMethodDialog(event.currentTarget));
  $("#dialog-close").addEventListener("click", () => methodDialog.close());
  methodDialog.addEventListener("click", (event) => {
    if (event.target === methodDialog) methodDialog.close();
  });
  methodDialog.addEventListener("close", () => {
    methodDialogReturnFocus?.focus();
    methodDialogReturnFocus = null;
  });

  function openMethodDialog(trigger) {
    methodDialogReturnFocus = trigger;
    methodDialog.showModal();
  }

  $$(".filter").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.classList.contains("active")));
    button.addEventListener("click", () => {
      $$(".filter").forEach((item) => {
        const active = item === button;
        item.classList.toggle("active", active);
        item.setAttribute("aria-pressed", String(active));
      });
      state.activeFilter = button.dataset.filter;
      renderFindings(state.report?.findings || []);
    });
  });

  // ─── Scan execution ───────────────────────────────────────────────

  // A thrown Error carries a deliberate, human-readable message (from this
  // app or the API). Anything else — typically an offline fetch rejecting
  // with TypeError — gets one friendly line instead of browser internals.
  function friendlyError(error) {
    if (error?.name === "AbortError") return "The scan was cancelled.";
    if (error instanceof Error) return error.message;
    return "Network request failed. Check your connection and try again.";
  }

  // Pre-stream failures (bad content type, oversized body, invalid JSON,
  // disallowed origin) answer with a JSON {error} body instead of an NDJSON
  // stream; prefer that actionable message over a bare HTTP status.
  async function responseError(response) {
    try {
      const payload = await response.json();
      if (payload && typeof payload.error === "string" && payload.error) {
        return new Error(payload.error);
      }
    } catch {
      // Fall through to the generic status message.
    }
    return new Error(`Scan failed with HTTP ${response.status}`);
  }

  async function runScan(url) {
    if (!url.trim() || busy) return;
    busy = true;
    const token = ++runToken;
    // Cancelling the controller (Cancel button, "New scan", Back) aborts the
    // fetch and its stream so an abandoned run stops downloading instead of
    // silently driving the progress UI from the background.
    const abort = new AbortController();
    activeAbort = abort;
    beginProgress();
    errorPanel.classList.add("hidden");
    reportPanel.classList.add("hidden");
    updateScanAvailability();
    try {
      const response = await fetch(`${API_BASE}/api/scans/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: abort.signal,
        body: JSON.stringify({
          url: url.trim(),
          probePaths: probePathsCheckbox.checked,
          checkTakeover: checkTakeoverCheckbox.checked
        })
      });
      if (token !== runToken) {
        // Superseded before the stream started; stop downloading.
        await response.body?.cancel().catch(() => {});
        return;
      }
      if (!response.ok || !response.body) throw await responseError(response);
      const payload = await readScanStream(response, () => token === runToken);
      if (token !== runToken || payload === null) return;
      finishProgress();
      displayReport(payload, true);
    } catch (error) {
      if (token !== runToken) return;
      stopProgress();
      showError(friendlyError(error));
    } finally {
      if (activeAbort === abort) activeAbort = null;
      if (token === runToken) {
        busy = false;
        updateScanAvailability();
      }
    }
  }

  async function loadReport(id, { trackHistory = false } = {}) {
    if (busy) return;
    busy = true;
    const token = ++runToken;
    const abort = new AbortController();
    activeAbort = abort;
    beginProgress("Loading saved report");
    updateScanAvailability();
    try {
      const response = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(id)}`, { signal: abort.signal });
      let payload;
      try {
        payload = await response.json();
      } catch {
        throw new Error("Saved report could not be loaded.");
      }
      if (token !== runToken) return;
      if (!response.ok) throw new Error(payload.error || "Saved report could not be loaded.");
      finishProgress();
      displayReport(payload, trackHistory);
    } catch (error) {
      if (token !== runToken) return;
      stopProgress();
      showError(friendlyError(error), { badge: "LOAD_FAILED" });
    } finally {
      if (activeAbort === abort) activeAbort = null;
      if (token === runToken) {
        busy = false;
        updateScanAvailability();
      }
    }
  }

  // ─── NDJSON stream reading ────────────────────────────────────────

  async function readScanStream(response, isLive) {
    let report = null;
    const alive = await streamReader.consumeNdjson(response.body, (event) => {
      if (event.type === "progress") applyProgress(event);
      else if (event.type === "result") report = event.report;
      else if (event.type === "error") throw new Error(event.error || "Scan failed.");
    }, { isLive });
    if (!alive) return null;
    if (!report) throw new Error("The scan ended without a report.");
    return report;
  }

  function applyProgress(event) {
    const step = STAGE_MAP[event.stage];
    if (step !== undefined) state.progressStep = step;
    $("#progress-title").textContent = event.message || "Scanning target";
    const reportedProgress = Number(event.progress);
    const progress = Number.isFinite(reportedProgress)
      ? Math.max(Number($("#progress-track").value) || 8, reportedProgress)
      : 10 + (state.progressStep / 5) * 85;
    $("#progress-track").value = Math.min(100, progress);
    updateProgressSteps();
  }

  // ─── Motion + scrolling ───────────────────────────────────────────

  const prefersReducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches ?? false;
  const scrollBehavior = () => (prefersReducedMotion ? "auto" : "smooth");
  function scrollToElement(element, block) {
    element?.scrollIntoView({ behavior: scrollBehavior(), block });
  }

  function beginProgress(title = "Scanning target") {
    state.progressStep = 0;
    $("#progress-title").textContent = title;
    progressPanel.classList.remove("hidden");
    $("#progress-track").value = 8;
    updateProgressSteps();
    scrollToElement(progressPanel, "center");
  }

  function updateProgressSteps() {
    $$("#progress-steps li").forEach((item, index) => {
      item.classList.toggle("active", index === state.progressStep);
      item.classList.toggle("done", index < state.progressStep);
    });
    $$("#live-route .route-node").forEach((item, index) => {
      item.classList.toggle("active", index === state.progressStep);
      item.classList.toggle("done", index < state.progressStep);
    });
    $$("#live-route .route-wire").forEach((item, index) => {
      item.classList.toggle("active", index === state.progressStep - 1 || (state.progressStep === 0 && index === 0));
      item.classList.toggle("done", index < state.progressStep - 1);
    });
  }

  function finishProgress() {
    state.progressStep = 5;
    updateProgressSteps();
    $("#progress-track").value = 100;
    setTimeout(() => progressPanel.classList.add("hidden"), 250);
  }

  function stopProgress() {
    progressPanel.classList.add("hidden");
  }

  function showError(message, { badge = "SCAN_FAILED" } = {}) {
    // The badge names the failure class: a scan that ran versus a saved
    // report that could not be loaded are different user situations.
    $("#error-code").textContent = badge;
    $("#error-message").textContent = message;
    errorPanel.classList.remove("hidden");
    scrollToElement(errorPanel, "center");
    // role="alert" announces the failure; moving focus lets keyboard users
    // reach the dismiss control immediately.
    errorPanel.focus({ preventScroll: true });
  }

  // ─── Report rendering ─────────────────────────────────────────────

  function displayReport(report, updateLocation) {
    state.report = report;
    $("#report-host").textContent = report.hostname;
    const requestedUrl = report.requestedUrl || report.url || `https://${report.hostname}`;
    const targetLink = $("#report-url");
    targetLink.textContent = requestedUrl;
    targetLink.title = requestedUrl;
    // Stored URLs are redacted but legacy migrated rows skip per-field
    // validation, so only well-formed http(s) targets become live links.
    if (/^https?:\/\//i.test(requestedUrl)) {
      targetLink.href = requestedUrl;
    } else {
      targetLink.removeAttribute("href");
    }
    const created = report.createdAt ? new Date(report.createdAt).toLocaleString() : "unknown";
    const expires = report.expiresAt ? new Date(report.expiresAt).toLocaleString() : "unknown";
    const outbound = report.outbound;
    const budget = outbound
      ? ` · ${outbound.requestsAttempted}/${outbound.maxSubrequests} outbound requests · ${outbound.bodyBytes || 0} bytes${outbound.truncatedBodies ? ` · ${outbound.truncatedBodies} body limit${outbound.truncatedBodies === 1 ? "" : "s"}` : ""}`
      : "";
    $("#report-meta").textContent = `Report ${report.id || "unknown"} · ${report.status || "unknown"} · created ${created} · expires ${expires}${budget}`;

    renderGrade(report.summary || {});
    renderMetrics(report.summary || {});
    renderFindings(report.findings || []);
    renderDnsSsl(report);
    renderHeadersAudit(report.headers || {});
    renderCoverage(report.coverage || {});
    renderFingerprint(report.fingerprint || {});
    renderCookies(report.cookies || []);
    renderExposedPaths(report.exposedPaths || [], report.coverage || {});
    renderCors(report.cors || {});
    renderTakeover(report.takeover || [], report.coverage || {});

    // Panel visibility follows the report's own coverage record, not the
    // viewer's form checkboxes: skipped phases stay hidden, attempted phases
    // show their truthful empty/partial/failed state.
    const takeoverSection = $("#takeover-section");
    takeoverSection.classList.toggle("hidden", !reportView.takeoverState(report.takeover || [], report.coverage || {}).visible);

    reportPanel.classList.remove("hidden");
    if (updateLocation) history.pushState({ reportId: report.id }, "", `#${report.id}`);
    document.title = `${report.hostname}: VulnScope`;
    setTimeout(() => {
      scrollToElement(reportPanel, "start");
      // The view swap is announced by the live regions, but keyboard and
      // screen-reader focus still needs to land on the new context.
      $("#report-host").focus({ preventScroll: true });
    }, 280);
  }

  function renderGrade(summary) {
    const presentation = reportView.gradePresentation(summary);
    // Ungraded reports get their own muted tone instead of borrowing the
    // accent styling of a real letter grade.
    const badge = $("#grade-badge");
    badge.className = `grade-badge grade-${presentation.tone}`;
    $("#grade-letter").textContent = presentation.letter;
    $("#grade-label").textContent = presentation.label;
    $("#observation-note").textContent = `${presentation.note} ${OBSERVATION_NOTE_SUFFIX}`;
  }

  function renderMetrics(summary) {
    const items = [
      ["Critical", summary.critical || 0, "critical"],
      ["High", summary.high || 0, "high"],
      ["Medium", summary.medium || 0, "warn"],
      ["Low", summary.low || 0, "low"],
      ["Info", summary.info || 0, ""]
    ];
    // A zero count is not a finding: render it muted instead of in the
    // severity hue (a red "Critical 0" reads as an alarm).
    $("#metrics").innerHTML = items.map(([label, value, cls]) => {
      const valueClass = value > 0 ? cls : "zero";
      return `<div class="metric"><small>${escapeHtml(label)}</small><strong class="${valueClass}">${escapeHtml(String(value))}</strong></div>`;
    }).join("");
  }

  function renderFindings(findings) {
    const filtered = state.activeFilter === "all"
      ? findings
      : findings.filter((f) => f.severity === state.activeFilter);

    const statusRegion = $("#findings-status");
    if (statusRegion) {
      statusRegion.textContent = `${filtered.length} ${state.activeFilter === "all" ? "" : `${state.activeFilter}-severity `}finding${filtered.length === 1 ? "" : "s"} shown.`;
    }

    if (!filtered.length) {
      $("#findings-list").innerHTML = `<div class="findings-empty">${state.activeFilter === "all" ? "No findings were generated." : `No ${escapeHtml(state.activeFilter)} severity findings.`}</div>`;
      return;
    }

    $("#findings-list").innerHTML = filtered.map((f) =>
      `<article class="finding-card severity-${escapeHtml(f.severity)}">
        <span class="finding-bar" aria-hidden="true"></span>
        <div class="finding-meta">
          <span class="finding-severity">${escapeHtml(f.severity)}</span>
          <span class="finding-category">${escapeHtml(f.category || "")}</span>
        </div>
        <div class="finding-body">
          <h4>${escapeHtml(f.title)}</h4>
          <p>${escapeHtml(f.detail)}</p>
          ${f.evidence ? `<pre class="finding-evidence">${escapeHtml(f.evidence)}</pre>` : ""}
          ${f.recommendation ? `<div class="finding-recommendation"><strong>Fix</strong><span>${escapeHtml(f.recommendation)}</span></div>` : ""}
        </div>
      </article>`
    ).join("");
  }

  function renderDnsSsl(report) {
    const dns = report.dns || {};
    const ssl = report.ssl || {};
    const tlsMeasured = report.coverage?.tlsProtocolCipher?.status === "measured";
    const rows = [];

    // DNS
    if (dns.addresses?.length) {
      rows.push(["DNS addresses", dns.addresses.join(", "), "good"]);
    } else if (Array.isArray(dns.queries)) {
      const failures = dns.queries
        .filter((query) => query && (query.error || query.status >= 400))
        .map((query) => `${query.name || "DNS query"}: ${query.error || `HTTP ${query.status}`}`);
      if (failures.length) rows.push(["DNS query errors", failures.join("; "), "critical"]);
    }
    if (typeof dns.dnssecAuthenticated === "boolean") {
      rows.push(["DNSSEC authenticated", dns.dnssecAuthenticated ? "Yes" : "No", dns.dnssecAuthenticated ? "good" : ""]);
    }

    // SSL details
    // The Worker cannot observe the origin's negotiated protocol or cipher.
    // Only render these fields if a future trusted measurement explicitly
    // marks that coverage as measured.
    if (tlsMeasured && ssl.protocol) rows.push(["TLS protocol", ssl.protocol, ssl.protocol === "TLSv1.3" ? "good" : "warn"]);
    if (tlsMeasured && ssl.cipher) rows.push(["Cipher suite", ssl.cipher, ""]);
    if (ssl.issuer) rows.push(["Certificate issuer", ssl.issuer, ""]);
    if (ssl.subject) rows.push(["Certificate subject", ssl.subject, ""]);
    // Migrated rows are not per-field validated on read, so stored SSL
    // fields must prove their type before string operations.
    if (typeof ssl.validFrom === "string" && ssl.validFrom) rows.push(["CT entry valid from", ssl.validFrom.slice(0, 10), ""]);
    if (typeof ssl.validTo === "string" && ssl.validTo) rows.push(["CT entry valid to", ssl.validTo.slice(0, 10), ""]);

    if (ssl.daysUntilExpiry !== undefined && ssl.daysUntilExpiry !== null) {
      const days = Number(ssl.daysUntilExpiry);
      if (Number.isFinite(days)) {
        let text = `${days} days`;
        if (days < 0) text = `reported expired ${Math.abs(days)}d ago`;
        rows.push(["CT entry expiry (not active certificate)", text, ""]);
      }
    }

    if (ssl.certificateEvidence && typeof ssl.certificateEvidence === "object") {
      const evidence = ssl.certificateEvidence;
      rows.push(["Certificate transparency evidence", `${evidence.source}: ${evidence.status}`, ""]);
      rows.push(["Certificate transparency limitation", evidence.limitation, ""]);
    }

    if (!rows.length) {
      $("#dns-ssl-details").innerHTML = `<p class="detail-empty">No DNS or SSL data available.</p>`;
      return;
    }

    $("#dns-ssl-details").innerHTML = `<div class="detail-grid">${rows.map(([label, value, cls]) =>
      `<div class="detail-row"><span class="detail-label">${escapeHtml(label)}</span><span class="detail-value ${cls || ""}">${escapeHtml(String(value))}</span></div>`
    ).join("")}</div>`;
  }

  function renderHeadersAudit(headers) {
    const rows = reportView.headerAuditRows(headers);

    $("#headers-audit").innerHTML = rows.map((r) =>
      `<div class="header-audit-row">
        <span class="header-name">${escapeHtml(r.name)}</span>
        <span class="header-value">${escapeHtml(r.value)}</span>
        <span class="header-status ${r.statusClass}">${escapeHtml(r.status)}</span>
      </div>`
    ).join("");
  }

  function renderCoverage(coverage) {
    const rows = reportView.coverageRows(coverage);
    const gaps = Array.isArray(coverage.criticalGaps) ? coverage.criticalGaps : [];
    const gap = gaps.length
      ? `<p class="detail-empty">Grade-blocking coverage gap${gaps.length === 1 ? "" : "s"}: ${escapeHtml(gaps.join("; "))}</p>`
      : "";
    $("#coverage-details").innerHTML = gap + `<div class="detail-grid">${rows.map((row) =>
      `<div class="detail-row"><span class="detail-label">${escapeHtml(row.label)}</span><span class="detail-value ${escapeHtml(row.status)}">${escapeHtml(row.status)}: ${escapeHtml(row.detail)}</span></div>`
    ).join("")}</div>`;
  }

  function renderFingerprint(fp) {
    const items = reportView.fingerprintRows(fp).map(({ label, value }) => [label, value]);

    if (!items.length) {
      $("#fingerprint-details").innerHTML = `<p class="detail-empty">Could not identify server technologies.</p>`;
      return;
    }

    $("#fingerprint-details").innerHTML = `<div class="fp-grid">${items.map(([label, value]) =>
      `<div class="fp-item"><small>${escapeHtml(label)}</small><strong>${escapeHtml(String(value))}</strong></div>`
    ).join("")}</div>`;
  }

  function renderCookies(cookies) {
    const rows = reportView.cookieRows(cookies);
    const countEl = $("#cookie-count");
    countEl.textContent = rows.length || "";
    countEl.classList.toggle("hidden", !rows.length);

    if (!rows.length) {
      $("#cookie-details").innerHTML = `<p class="detail-empty">No cookies set by the target.</p>`;
      return;
    }

    $("#cookie-details").innerHTML = rows.map((c) => {
      return `<div class="cookie-row">
        <span class="cookie-name">${escapeHtml(c.name)}</span>
        <span class="cookie-attrs">${c.attrs.map((attr) => `<span class="cookie-attr ${attr.statusClass}">${escapeHtml(attr.text)}</span>`).join("")}</span>
        ${c.domain ? `<span class="cookie-attr">Domain=${escapeHtml(c.domain)}</span>` : ""}
        ${c.expires ? `<span class="cookie-attr">Expires=${escapeHtml(c.expires)}</span>` : ""}
      </div>`;
    }).join("");
  }

  function renderExposedPaths(paths, coverage) {
    const pathState = reportView.exposedPathsState(paths, coverage);
    const countEl = $("#paths-count");
    const found = paths.filter((p) => p.status && p.status >= 200 && p.status < 400);
    const count = found.length
      ? `${found.length} found`
      : pathState.status === "measured"
        ? "0 found"
        : paths.length
          ? `${paths.length} checked`
          : "";
    countEl.textContent = count;
    countEl.classList.toggle("hidden", !count);
    countEl.classList.toggle("cs-count-alert", found.length > 0);

    if (!paths.length) {
      $("#paths-details").innerHTML = `<p class="detail-empty">${escapeHtml(pathState.message || "No path results were recorded.")}</p>`;
      return;
    }

    const rows = paths.map((p) => {
      const severity = p.severity || "info";
      return `<div class="path-row">
        <span class="path-url">${escapeHtml(p.path)}</span>
        <span class="path-status s-${escapeHtml(severity)}">${escapeHtml(String(p.status || "Unavailable"))}</span>
        <span class="path-severity s-${escapeHtml(severity)}">${escapeHtml(severity)}${p.truncated ? " · truncated" : ""}</span>
        <span class="path-evidence">${escapeHtml(p.evidence || "Evidence unavailable")}</span>
      </div>`;
    }).join("");

    const header = `<div class="path-row path-table-header">
      <span>Path</span><span>Status</span><span class="path-header-severity">Severity</span><span>Evidence</span>
    </div>`;

    $("#paths-details").innerHTML = header + rows;
  }

  function renderCors(cors) {
    const rows = reportView.corsAuditRows(cors);
    $("#cors-details").innerHTML = `<div class="cors-result">${rows.map(({ label, value, statusClass }) =>
      `<div class="cors-row"><span class="cors-label">${escapeHtml(label)}</span><span class="cors-value ${statusClass || ""}">${escapeHtml(String(value))}</span></div>`
    ).join("")}</div>`;
  }

  function renderTakeover(takeover, coverage) {
    const countEl = $("#takeover-count");
    const vulnerable = takeover.filter((t) => t.vulnerable);
    countEl.textContent = vulnerable.length ? `${vulnerable.length} VULNERABLE` : (takeover.length || "");
    countEl.classList.toggle("hidden", !takeover.length);
    countEl.classList.toggle("cs-count-alert", vulnerable.length > 0);

    if (!takeover.length) {
      const state = reportView.takeoverState(takeover, coverage);
      $("#takeover-details").innerHTML = `<p class="detail-empty">${escapeHtml(state.message || "No subdomain takeover results were recorded.")}</p>`;
      return;
    }

    $("#takeover-details").innerHTML = takeover.map((t) =>
      `<div class="takeover-row ${t.vulnerable ? "takeover-vuln" : ""}">
        <span class="takeover-status ${t.vulnerable ? "vuln" : "ok"}">${t.vulnerable ? "⚠ VULNERABLE" : "✓ OK"}</span>
        <div class="takeover-detail">
          <strong>${escapeHtml(t.subdomain)}</strong>
          <code>CNAME → ${escapeHtml(t.cname || "none")}</code>
          <span>${escapeHtml(t.evidence || "")}${t.confidence ? ` · confidence ${escapeHtml(t.confidence)}` : ""}</span>
        </div>
      </div>`
    ).join("");
  }

  // ─── Share + export ───────────────────────────────────────────────

  async function copyShareLink() {
    if (!state.report) return;
    const link = `${location.origin}${location.pathname}#${state.report.id}`;
    try {
      await navigator.clipboard.writeText(link);
      flashButton($("#copy-link"), "Copied");
    } catch {
      prompt("Copy this report link:", link);
    }
  }

  function exportJson() {
    if (!state.report) return;
    const blob = new Blob([JSON.stringify(state.report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    // Same slug rule as the server-side export: stored fields never steer
    // filename syntax on migrated or corrupted rows.
    const slug = (value) => String(value || "").replace(/[^A-Za-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "") || "report";
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `vulnscope-${slug(state.report.hostname)}-${slug(state.report.id)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function reset({ replaceHistory = false } = {}) {
    runToken++;
    // Tear down any in-flight scan or report fetch owned by the abandoned
    // run; its completions are already invalidated by the token bump.
    activeAbort?.abort();
    activeAbort = null;
    busy = false;
    state.report = null;
    state.activeFilter = "all";
    $$(".filter").forEach((item) => {
      const active = item.dataset.filter === "all";
      item.classList.toggle("active", active);
      item.setAttribute("aria-pressed", String(active));
    });
    reportPanel.classList.add("hidden");
    errorPanel.classList.add("hidden");
    stopProgress();
    // Preserve the query string: only the report hash is view state.
    const basePath = `${location.pathname}${location.search}`;
    if (replaceHistory) history.replaceState(null, "", basePath);
    else history.pushState({}, "", basePath);
    document.title = "VulnScope: Find what's exposed";
    input.value = "";
    if (authConfirm) authConfirm.checked = false;
    updateScanAvailability();
    input.focus();
    scrollTo({ top: 0, behavior: scrollBehavior() });
  }

  function flashButton(button, text) {
    // Rapid repeat clicks must not capture the flashed label as the
    // "original"; one stored label plus a resettable timer keeps restores
    // correct no matter how often Copy is hit during the flash window.
    if (!button.dataset.label) button.dataset.label = button.textContent;
    if (button.dataset.flashTimer) clearTimeout(Number(button.dataset.flashTimer));
    button.textContent = text;
    button.dataset.flashTimer = String(setTimeout(() => {
      delete button.dataset.flashTimer;
      button.textContent = button.dataset.label;
      delete button.dataset.label;
    }, 1400));
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  }

  // ─── Hash restoration + history ───────────────────────────────────

  const REPORT_ID_SHAPE = /^[A-Za-z0-9_-]{16}$/;
  const initialId = location.hash.slice(1);
  // Report IDs are exactly 16 URL-safe characters server-side. Requiring the
  // same shape here stops nav anchors like #status from triggering a doomed
  // report fetch and a spurious error panel.
  if (REPORT_ID_SHAPE.test(initialId)) loadReport(initialId);

  window.addEventListener("popstate", () => {
    const id = location.hash.slice(1);
    if (REPORT_ID_SHAPE.test(id)) {
      if (!busy && state.report?.id !== id) loadReport(id);
      return;
    }
    // Back/Forward returned to a hashless entry while a report is on screen:
    // restore the landing view so the page matches the URL. Anchor jumps such
    // as #status intentionally keep the current view.
    if (location.hash === "" && state.report) reset({ replaceHistory: true });
  });
})();
