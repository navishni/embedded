// Minimal dependency-free SVG charts (bar, line, horizontal bar, donut).
// Rendered at the element's real pixel size so text never scales; re-renders on resize.
(function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  const registry = new Map();
  let tip;

  function svgEl(tag, attrs = {}, text) {
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function showTip(evt, text) {
    if (!tip) { tip = document.createElement("div"); tip.className = "chart-tip"; document.body.append(tip); }
    tip.textContent = text; tip.hidden = false;
    tip.style.left = evt.clientX + 12 + "px"; tip.style.top = evt.clientY - 28 + "px";
  }
  function hideTip() { if (tip) tip.hidden = true; }
  function withTip(node, text) {
    node.addEventListener("mousemove", (e) => showTip(e, text));
    node.addEventListener("mouseleave", hideTip);
    return node;
  }
  function niceMax(v) {
    if (v <= 4) return Math.max(1, Math.ceil(v));
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
    return v;
  }
  function empty(el, msg) {
    el.replaceChildren();
    const d = document.createElement("div");
    d.className = "chart-empty"; d.textContent = msg || "No data for this period";
    el.append(d);
  }
  function frame(el) {
    el.replaceChildren();
    const w = Math.max(el.clientWidth, 200), h = Math.max(el.clientHeight, 120);
    const svg = svgEl("svg", { viewBox: `0 0 ${w} ${h}`, role: "img" });
    el.append(svg);
    return { svg, w, h };
  }
  function yAxis(svg, pad, w, h, max) {
    const g = svgEl("g", { class: "grid" }), a = svgEl("g", { class: "axis" });
    // pick a step count that gives whole-number gridlines (counts are integers)
    const steps = max <= 5 ? max : [4, 5, 2, 3].find((s) => Number.isInteger(max / s)) || 4;
    for (let i = 0; i <= steps; i++) {
      const v = (max / steps) * i, y = h - pad.b - (v / max) * (h - pad.t - pad.b);
      g.append(svgEl("line", { x1: pad.l, x2: w - pad.r, y1: y, y2: y }));
      a.append(svgEl("text", { x: pad.l - 6, y: y + 3, "text-anchor": "end" }, Number.isInteger(v) ? v : v.toFixed(1)));
    }
    svg.append(g, a);
  }

  function bar(el, labels, values, opt = {}) {
    if (!values.some((v) => v > 0)) return empty(el, opt.emptyText);
    const { svg, w, h } = frame(el);
    const pad = { t: 14, r: 6, b: 22, l: 28 };
    const max = niceMax(Math.max(...values));
    yAxis(svg, pad, w, h, max);
    const n = values.length, slot = (w - pad.l - pad.r) / n, bw = Math.max(2, Math.min(38, slot * 0.68));
    const every = opt.labelEvery || Math.ceil(n / Math.floor((w - pad.l) / 34));
    const peak = Math.max(...values);
    values.forEach((v, i) => {
      const x = pad.l + slot * i + (slot - bw) / 2;
      const bh = (v / max) * (h - pad.t - pad.b);
      const r = svgEl("rect", { x, y: h - pad.b - bh, width: bw, height: Math.max(bh, v ? 2 : 0), rx: Math.min(4, bw / 3),
        class: "bar" + (opt.highlightMax && v === peak && v > 0 ? " hot" : "") });
      svg.append(withTip(r, `${opt.tipLabels ? opt.tipLabels[i] : labels[i]}: ${v} ${opt.unit || "incident(s)"}`));
      if (i % every === 0) svg.append(svgEl("text", { x: x + bw / 2, y: h - 6, "text-anchor": "middle", class: "lbl" }, labels[i]));
      if (opt.showValues && v > 0 && bw > 14) svg.append(svgEl("text", { x: x + bw / 2, y: h - pad.b - bh - 4, "text-anchor": "middle", class: "val" }, v));
    });
  }

  function line(el, labels, values, opt = {}) {
    if (!values.some((v) => v > 0)) return empty(el, opt.emptyText);
    const { svg, w, h } = frame(el);
    const pad = { t: 14, r: 10, b: 22, l: 28 };
    const max = niceMax(Math.max(...values));
    const defs = svgEl("defs");
    const grad = svgEl("linearGradient", { id: "areaGrad", x1: 0, y1: 0, x2: 0, y2: 1 });
    grad.append(svgEl("stop", { offset: "0%", "stop-color": "#4f8cff", "stop-opacity": ".35" }),
                svgEl("stop", { offset: "100%", "stop-color": "#4f8cff", "stop-opacity": "0" }));
    defs.append(grad); svg.append(defs);
    yAxis(svg, pad, w, h, max);
    const n = values.length;
    const X = (i) => pad.l + (n === 1 ? (w - pad.l - pad.r) / 2 : (i / (n - 1)) * (w - pad.l - pad.r));
    const Y = (v) => h - pad.b - (v / max) * (h - pad.t - pad.b);
    const pts = values.map((v, i) => `${X(i)},${Y(v)}`);
    svg.append(svgEl("path", { class: "area", d: `M${X(0)},${h - pad.b} L${pts.join(" L")} L${X(n - 1)},${h - pad.b} Z` }));
    svg.append(svgEl("path", { class: "line", d: `M${pts.join(" L")}` }));
    const every = Math.ceil(n / Math.floor((w - pad.l) / 56));
    values.forEach((v, i) => {
      svg.append(withTip(svgEl("circle", { cx: X(i), cy: Y(v), r: n > 40 ? 2.5 : 3.5, class: "pt" }), `${labels[i]}: ${v} ${opt.unit || "incident(s)"}`));
      if (i % every === 0 || i === n - 1) svg.append(svgEl("text", { x: X(i), y: h - 6, "text-anchor": "middle", class: "lbl" }, labels[i]));
    });
  }

  function hbar(el, labels, values, opt = {}) {
    if (!values.length || !values.some((v) => v > 0)) return empty(el, opt.emptyText);
    const { svg, w, h } = frame(el);
    const lw = 70, max = Math.max(...values), rowH = Math.min(34, h / values.length);
    values.forEach((v, i) => {
      const y = i * rowH + 4, bw = (v / max) * (w - lw - 40);
      svg.append(svgEl("text", { x: 0, y: y + rowH / 2 + 2, class: "lbl" }, labels[i]));
      svg.append(withTip(svgEl("rect", { x: lw, y: y + 4, width: Math.max(bw, 2), height: rowH - 12, rx: 4, class: "bar" }), `${labels[i]}: ${v}`));
      svg.append(svgEl("text", { x: lw + bw + 6, y: y + rowH / 2 + 2, class: "val" }, v));
    });
  }

  function donut(el, items, opt = {}) {
    const total = items.reduce((s, it) => s + it.value, 0);
    if (!total) return empty(el, opt.emptyText);
    el.replaceChildren();
    const size = 170, r = 64, sw = 22, c = 2 * Math.PI * r;
    const svg = svgEl("svg", { viewBox: `0 0 ${size} ${size}` });
    svg.append(svgEl("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: "#222c3d", "stroke-width": sw }));
    let off = 0;
    items.forEach((it) => {
      if (!it.value) return;
      const len = (it.value / total) * c;
      const seg = svgEl("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: it.color, "stroke-width": sw,
        "stroke-dasharray": `${len} ${c - len}`, "stroke-dashoffset": -off, transform: `rotate(-90 ${size / 2} ${size / 2})` });
      svg.append(withTip(seg, `${it.label}: ${it.value} (${Math.round((it.value / total) * 100)}%)`));
      off += len;
    });
    svg.append(svgEl("text", { x: size / 2, y: size / 2 + 2, "text-anchor": "middle", class: "val", "font-size": "22" }, total));
    svg.append(svgEl("text", { x: size / 2, y: size / 2 + 20, "text-anchor": "middle", class: "lbl" }, opt.centerLabel || "total"));
    const legend = document.createElement("div");
    legend.className = "donut-legend";
    items.forEach((it) => {
      const s = document.createElement("span");
      const sw2 = document.createElement("i");
      sw2.className = "swatch"; sw2.style.background = it.color;
      s.append(sw2, `${it.label} — ${it.value}`);
      legend.append(s);
    });
    el.append(svg, legend);
  }

  // Re-render registered charts when their container resizes
  const ro = new ResizeObserver((entries) => {
    for (const e of entries) { const fn = registry.get(e.target); if (fn) fn(); }
  });
  function render(el, fn) {
    if (!el) return;
    registry.set(el, fn);
    ro.observe(el);
    fn();
  }

  window.Charts = { bar, line, hbar, donut, render };
})();
