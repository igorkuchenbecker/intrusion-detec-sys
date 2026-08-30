/*
 * Dashboard client.
 *
 * Security note: every value rendered here comes from observed traffic or from
 * log lines, which means it is attacker-influenceable. Nothing is ever written
 * with innerHTML -- all values go in through textContent, so a source address
 * or description containing markup is displayed, never executed.
 */
"use strict";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const POLL_INTERVAL_MS = 5000;
const MAX_ROWS = 200;

const state = { filters: {}, usingStream: false };

function el(id) {
  return document.getElementById(id);
}

function setPill(node, text, kind) {
  node.textContent = text;
  node.className = "pill pill-" + kind;
}

/** Build a query string from the active filters. */
function queryString(extra) {
  const params = new URLSearchParams(Object.assign({}, state.filters, extra || {}));
  const query = params.toString();
  return query ? "?" + query : "";
}

async function fetchJson(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const message = payload && payload.error ? payload.error.message : "request failed";
    throw new Error(message);
  }
  return payload;
}

/** Render one alert as a table row, escaping by construction. */
function alertRow(alert) {
  const row = document.createElement("tr");

  const time = document.createElement("td");
  time.className = "mono";
  time.textContent = (alert.timestamp || "").replace("T", " ").slice(0, 19);
  row.appendChild(time);

  const severity = document.createElement("td");
  const badge = document.createElement("span");
  badge.className = "badge badge-" + (SEVERITIES.includes(alert.severity) ? alert.severity : "info");
  badge.textContent = (alert.severity || "").toUpperCase();
  severity.appendChild(badge);
  row.appendChild(severity);

  const columns = [
    alert.confidence || "-",
    alert.detection_type || "-",
    alert.source_ip || "-",
    alert.destination_ip || "-",
  ];
  for (const value of columns) {
    const cell = document.createElement("td");
    cell.className = "mono";
    cell.textContent = value;
    row.appendChild(cell);
  }

  const description = document.createElement("td");
  description.className = "desc";
  description.textContent = alert.description || "";
  row.appendChild(description);

  return row;
}

function renderAlerts(alerts) {
  const body = el("alerts-body");
  body.replaceChildren();
  for (const alert of alerts.slice(0, MAX_ROWS)) {
    body.appendChild(alertRow(alert));
  }
  el("empty-state").hidden = alerts.length > 0;
}

function prependAlert(alert) {
  if (!matchesFilters(alert)) {
    return;
  }
  const body = el("alerts-body");
  body.insertBefore(alertRow(alert), body.firstChild);
  while (body.childElementCount > MAX_ROWS) {
    body.removeChild(body.lastChild);
  }
  el("empty-state").hidden = true;
}

/** Keep a streamed alert out of the table if it does not match the filters. */
function matchesFilters(alert) {
  const filters = state.filters;
  if (filters.severity && alert.severity !== filters.severity) return false;
  if (filters.detection_type && alert.detection_type !== filters.detection_type) return false;
  if (filters.source_ip && alert.source_ip !== filters.source_ip) return false;
  return true;
}

async function refreshAlerts() {
  try {
    const payload = await fetchJson("/api/alerts" + queryString({ limit: MAX_ROWS }));
    renderAlerts(payload.data);
    el("filter-error").hidden = true;
  } catch (error) {
    const box = el("filter-error");
    box.textContent = error.message;
    box.hidden = false;
  }
}

async function refreshStats() {
  const payload = await fetchJson("/api/stats");
  const counts = payload.data.severity_counts || {};
  el("stat-total").textContent = payload.data.total_alerts;
  for (const severity of SEVERITIES) {
    el("stat-" + severity).textContent = counts[severity] || 0;
  }
}

async function refreshMetrics() {
  const payload = await fetchJson("/api/metrics");
  const counters = payload.data.counters || {};
  const gauges = payload.data.gauges || {};
  el("m-captured").textContent = counters.packets_captured || 0;
  el("m-parsed").textContent = counters.packets_parsed || 0;
  el("m-dropped").textContent = counters.packets_dropped || 0;
  el("m-queue").textContent = Math.round(gauges.queue_size || 0);
}

async function refreshTraffic() {
  const payload = await fetchJson("/api/traffic?limit=1");
  const latest = payload.data[payload.data.length - 1];
  el("m-pps").textContent = latest ? latest.packets_per_second.toFixed(1) : "0";
  el("m-bps").textContent = latest ? Math.round(latest.bytes_per_second) : "0";
}

async function refreshHealth() {
  try {
    const payload = await fetchJson("/api/health");
    const report = payload.data;
    setPill(el("health-state"), report.status, report.status === "healthy" ? "ok" : "bad");
  } catch (error) {
    setPill(el("health-state"), "indisponivel", "bad");
  }
}

async function refreshAll() {
  await Promise.allSettled([
    refreshAlerts(),
    refreshStats(),
    refreshMetrics(),
    refreshTraffic(),
    refreshHealth(),
  ]);
}

/*
 * Live updates use Server-Sent Events, with polling as the fallback. Polling
 * also runs alongside the stream, at a slower cadence, because the counters and
 * traffic rates are not pushed -- only alerts are.
 */
function connectStream() {
  if (typeof EventSource === "undefined") {
    setPill(el("stream-state"), "polling", "idle");
    return;
  }
  const source = new EventSource("/api/stream");

  source.onopen = () => {
    state.usingStream = true;
    setPill(el("stream-state"), "ao vivo", "ok");
  };
  source.onmessage = (event) => {
    try {
      const message = JSON.parse(event.data);
      if (message.type === "alert") {
        prependAlert(message.alert);
        refreshStats().catch(() => {});
      }
    } catch (error) {
      /* A malformed frame must not break the stream. */
    }
  };
  source.onerror = () => {
    // EventSource reconnects on its own; report the gap meanwhile.
    state.usingStream = false;
    setPill(el("stream-state"), "reconectando", "bad");
  };
}

function readFilters() {
  const filters = {};
  const severity = el("f-severity").value;
  const type = el("f-type").value;
  const source = el("f-source").value.trim();
  if (severity) filters.severity = severity;
  if (type) filters.detection_type = type;
  if (source) filters.source_ip = source;
  return filters;
}

function bindFilters() {
  el("filters").addEventListener("submit", (event) => {
    event.preventDefault();
    state.filters = readFilters();
    refreshAlerts();
  });
  el("f-clear").addEventListener("click", () => {
    el("f-severity").value = "";
    el("f-type").value = "";
    el("f-source").value = "";
    state.filters = {};
    refreshAlerts();
  });
}

function start() {
  bindFilters();
  refreshAll();
  connectStream();
  setInterval(() => {
    refreshMetrics().catch(() => {});
    refreshTraffic().catch(() => {});
    refreshHealth().catch(() => {});
    if (!state.usingStream) {
      refreshAlerts();
      refreshStats().catch(() => {});
    }
  }, POLL_INTERVAL_MS);
}

document.addEventListener("DOMContentLoaded", start);
