/*
 * Cliente do console.
 *
 * Regra de segurança que governa este arquivo: todo valor exibido vem de
 * tráfego observado ou de linha de log, ou seja, é influenciável por quem está
 * sendo monitorado. Nada é escrito com innerHTML — tudo entra por textContent
 * ou por atributos de nós criados programaticamente. Uma descrição contendo
 * marcação é exibida, nunca executada.
 */
"use strict";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const POLL_INTERVAL_MS = 5000;
const MAX_ROWS = 200;
const SVG_NS = "http://www.w3.org/2000/svg";

const state = { filters: {}, usingStream: false, traffic: [] };

function el(id) {
  return document.getElementById(id);
}

function setPill(node, text, kind) {
  node.textContent = text;
  node.className = "pill pill-" + kind;
}

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

/* ------------------------------------------------------------------ tabela */

function cell(row, text, className) {
  const td = document.createElement("td");
  td.className = className || "";
  td.textContent = text;
  row.appendChild(td);
  return td;
}

function alertRow(alert) {
  const row = document.createElement("tr");

  cell(row, (alert.timestamp || "").replace("T", " ").slice(0, 19), "col-time");

  const severityCell = document.createElement("td");
  const badge = document.createElement("span");
  const severity = SEVERITIES.includes(alert.severity) ? alert.severity : "info";
  badge.className = "badge badge-" + severity;
  badge.textContent = alert.severity || "";
  severityCell.appendChild(badge);
  row.appendChild(severityCell);

  cell(row, alert.confidence || "-", "col-mono");
  cell(row, alert.detection_type || "-", "col-type");
  cell(row, alert.source_ip || "-", "col-mono");
  cell(row, alert.destination_ip || "-", "col-mono");
  cell(row, alert.description || "", "desc");
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

function matchesFilters(alert) {
  const filters = state.filters;
  if (filters.severity && alert.severity !== filters.severity) return false;
  if (filters.detection_type && alert.detection_type !== filters.detection_type) return false;
  if (filters.source_ip && alert.source_ip !== filters.source_ip) return false;
  return true;
}

/* ---------------------------------------------------------- nível de ameaça */

/** Highest severity currently present, shown as a level rather than a number. */
function renderThreatLevel(counts) {
  const present = SEVERITIES.filter((severity) => (counts[severity] || 0) > 0);
  const panel = el("threat-panel");
  const value = el("threat-level");
  const fill = el("threat-fill");

  if (present.length === 0) {
    panel.className = "threat";
    value.textContent = "nominal";
    fill.style.width = "0%";
    return;
  }
  const worst = present.reduce((a, b) => (SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b));
  panel.className = "threat lv-" + worst;
  value.textContent = worst;
  fill.style.width = ((SEVERITY_RANK[worst] + 1) / 5) * 100 + "%";
}

/* ---------------------------------------------------------------- gráfico */
/*
 * Série única de pacotes/s. Sem legenda: o título do painel nomeia a série, e
 * rotular todo ponto seria ruído — o valor mais recente aparece uma vez, como
 * número de destaque, e o resto sai no tooltip sob o cursor.
 */

function svgNode(name, attrs) {
  const node = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attrs || {})) {
    node.setAttribute(key, String(value));
  }
  return node;
}

function renderChart(windows) {
  const svg = el("traffic-chart");
  const empty = el("chart-empty");
  svg.replaceChildren();
  state.traffic = windows;

  if (windows.length < 2) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  const width = svg.clientWidth || 640;
  const height = svg.clientHeight || 168;
  const pad = { top: 14, right: 10, bottom: 20, left: 44 };
  const plotW = Math.max(width - pad.left - pad.right, 10);
  const plotH = Math.max(height - pad.top - pad.bottom, 10);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

  const values = windows.map((w) => w.packets_per_second);
  const peak = Math.max(...values, 1);
  const x = (i) => pad.left + (i / (windows.length - 1)) * plotW;
  const y = (v) => pad.top + plotH - (v / peak) * plotH;

  const defs = svgNode("defs");
  const gradient = svgNode("linearGradient", { id: "trafficFill", x1: 0, y1: 0, x2: 0, y2: 1 });
  gradient.appendChild(svgNode("stop", { offset: "0%", "stop-color": "#00f5c8", "stop-opacity": ".38" }));
  gradient.appendChild(svgNode("stop", { offset: "100%", "stop-color": "#00f5c8", "stop-opacity": "0" }));
  defs.appendChild(gradient);
  svg.appendChild(defs);

  // Grade recessiva: três linhas, sem moldura, para não competir com a série.
  for (let step = 0; step <= 2; step += 1) {
    const gy = pad.top + (plotH / 2) * step;
    svg.appendChild(svgNode("line", { class: "chart-grid", x1: pad.left, y1: gy, x2: width - pad.right, y2: gy }));
    const label = svgNode("text", { class: "chart-axis", x: 6, y: gy + 3 });
    label.textContent = formatNumber(peak - (peak / 2) * step);
    svg.appendChild(label);
  }

  const line = windows.map((w, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(w.packets_per_second).toFixed(1)}`);
  const areaPath = `${line.join(" ")} L${x(windows.length - 1).toFixed(1)},${pad.top + plotH} L${x(0).toFixed(1)},${pad.top + plotH} Z`;
  svg.appendChild(svgNode("path", { class: "chart-area", d: areaPath }));
  svg.appendChild(svgNode("path", { class: "chart-line", d: line.join(" ") }));

  const first = svgNode("text", { class: "chart-axis", x: pad.left, y: height - 5 });
  first.textContent = timeLabel(windows[0].window_start);
  svg.appendChild(first);
  const last = svgNode("text", { class: "chart-axis", x: width - pad.right, y: height - 5, "text-anchor": "end" });
  last.textContent = timeLabel(windows[windows.length - 1].window_end);
  svg.appendChild(last);

  state.chart = { windows, x, y, pad, plotH, width };
  attachHover(svg);
  el("chart-latest").textContent = formatNumber(values[values.length - 1]) + " p/s";
}

/*
 * Crosshair e tooltip: um gráfico SVG numa página é interativo por padrão.
 *
 * Os nós são recriados a cada render, mas os listeners são registrados uma vez
 * só — registrá-los junto com o desenho acumularia um handler por atualização,
 * a cada cinco segundos, para sempre.
 */
function attachHover(svg) {
  const wrap = svg.parentElement;
  let tooltip = wrap.querySelector(".tooltip");
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.className = "tooltip";
    wrap.appendChild(tooltip);
  }
  const ctx0 = state.chart;
  const crosshair = svgNode("line", { class: "chart-crosshair", y1: ctx0.pad.top, y2: ctx0.pad.top + ctx0.plotH });
  const marker = svgNode("circle", { class: "chart-marker", r: 4 });
  crosshair.style.display = "none";
  marker.style.display = "none";
  svg.appendChild(crosshair);
  svg.appendChild(marker);
  state.chartNodes = { crosshair, marker, tooltip };

  if (svg.dataset.hoverBound === "1") {
    return;
  }
  svg.dataset.hoverBound = "1";

  function hide() {
    const nodes = state.chartNodes;
    if (!nodes) return;
    nodes.crosshair.style.display = "none";
    nodes.marker.style.display = "none";
    nodes.tooltip.classList.remove("on");
  }

  svg.addEventListener("mousemove", (event) => {
    const ctx = state.chart;
    const nodes = state.chartNodes;
    if (!ctx || !nodes || ctx.windows.length < 2) return;
    const { crosshair, marker, tooltip } = nodes;
    const box = svg.getBoundingClientRect();
    const scale = ctx.width / (box.width || ctx.width);
    const px = (event.clientX - box.left) * scale;
    const ratio = (px - ctx.pad.left) / Math.max(ctx.width - ctx.pad.left - ctx.pad.right, 1);
    const index = Math.min(ctx.windows.length - 1, Math.max(0, Math.round(ratio * (ctx.windows.length - 1))));
    const point = ctx.windows[index];

    const cx = ctx.x(index);
    const cy = ctx.y(point.packets_per_second);
    crosshair.setAttribute("x1", cx);
    crosshair.setAttribute("x2", cx);
    marker.setAttribute("cx", cx);
    marker.setAttribute("cy", cy);
    crosshair.style.display = "";
    marker.style.display = "";

    tooltip.replaceChildren();
    const value = document.createElement("b");
    value.textContent = formatNumber(point.packets_per_second) + " p/s";
    tooltip.appendChild(value);
    const meta = document.createElement("span");
    meta.textContent = `  ${point.packets} pac · ${timeLabel(point.window_end)}`;
    tooltip.appendChild(meta);

    tooltip.style.left = (cx / scale) + "px";
    tooltip.style.top = (cy / scale) + "px";
    tooltip.classList.add("on");
  });
  svg.addEventListener("mouseleave", hide);
}

function formatNumber(value) {
  if (value >= 1000) return (value / 1000).toFixed(1) + "k";
  if (value >= 10 || value === 0) return Math.round(value).toString();
  return value.toFixed(1);
}

function timeLabel(iso) {
  return (iso || "").slice(11, 19);
}

/* ------------------------------------------------------------- atualizações */

async function refreshAlerts() {
  try {
    const payload = await fetchJson("/api/alerts" + queryString({ limit: MAX_ROWS }));
    renderAlerts(payload.data);
    el("filter-error").hidden = true;
  } catch (error) {
    const box = el("filter-error");
    box.textContent = "// " + error.message;
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
  renderThreatLevel(counts);
}

async function refreshMetrics() {
  const payload = await fetchJson("/api/metrics");
  const counters = payload.data.counters || {};
  const gauges = payload.data.gauges || {};
  el("m-captured").textContent = counters.packets_captured || 0;
  el("m-parsed").textContent = counters.packets_parsed || 0;
  el("m-queue").textContent = Math.round(gauges.queue_size || 0);

  // Pacote descartado é pacote não analisado: destaque quando houver perda.
  const dropped = counters.packets_dropped || 0;
  const droppedNode = el("m-dropped");
  droppedNode.textContent = dropped;
  droppedNode.className = dropped > 0 ? "alarm" : "";
}

async function refreshTraffic() {
  const payload = await fetchJson("/api/traffic?limit=60");
  const windows = payload.data;
  renderChart(windows);
  const latest = windows[windows.length - 1];
  el("m-pps").textContent = latest ? formatNumber(latest.packets_per_second) : "0";
  el("m-bps").textContent = latest ? formatNumber(latest.bytes_per_second) : "0";
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
    refreshAlerts(), refreshStats(), refreshMetrics(), refreshTraffic(), refreshHealth(),
  ]);
}

/*
 * Tempo real por Server-Sent Events, com polling como fallback. O polling
 * continua rodando em cadência lenta mesmo com o stream ativo: só alertas são
 * empurrados, contadores e taxas não.
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
      /* Um frame malformado não pode derrubar o stream. */
    }
  };
  source.onerror = () => {
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
  window.addEventListener("resize", () => renderChart(state.traffic));
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
