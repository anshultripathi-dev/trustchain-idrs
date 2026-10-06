// Dependency-free SVG charts: persistent elements so hover survives live updates.
import { h, svg, fmt } from './core.js';

let tipEl;
export function tip(html, x, y) {
  if (!tipEl) { tipEl = h('div', { class: 'tip', role: 'tooltip' }); document.body.append(tipEl); }
  if (html == null) { tipEl.style.display = 'none'; return; }
  tipEl.replaceChildren(html);
  tipEl.style.display = 'block';
  const r = tipEl.getBoundingClientRect();
  tipEl.style.left = Math.min(x + 14, innerWidth - r.width - 8) + 'px';
  tipEl.style.top = Math.min(y + 14, innerHeight - r.height - 8) + 'px';
}

const nice = (v) => (Math.abs(v) >= 100 ? v.toFixed(0) : Math.abs(v) >= 10 ? v.toFixed(1) : v.toFixed(2));

/**
 * LineChart: series=[{label,color,points:[{x,y}],dash?,area?}], opts={height,yMin,yMax,yFmt,xFmt,refs:[{y,label}],bands:[{from,to,color}],step}
 */
export class LineChart {
  constructor(opts = {}) {
    this.opts = { height: 220, margin: { l: 44, r: 12, t: 10, b: 24 }, ...opts };
    this.series = [];
    this.root = h('div', { style: { position: 'relative' } });
    this.svg = svg('svg', { width: '100%', height: this.opts.height, role: 'img', 'aria-label': opts.label || 'chart' });
    this.root.append(this.svg);
    this.w = 600;
    new ResizeObserver(() => { this.w = this.root.clientWidth || 600; this.draw(); }).observe(this.root);
    this.svg.addEventListener('mousemove', (e) => this.hover(e));
    this.svg.addEventListener('mouseleave', () => { this.hx = null; this.draw(); tip(null); });
  }
  setData(series, opts) { this.series = series; if (opts) Object.assign(this.opts, opts); this.draw(); }
  scales() {
    const { margin: m, height } = this.opts;
    const all = this.series.flatMap((s) => s.points);
    let x0 = this.opts.xMin ?? Math.min(...all.map((p) => p.x)), x1 = this.opts.xMax ?? Math.max(...all.map((p) => p.x));
    if (!isFinite(x0)) { x0 = 0; x1 = 1; } if (x0 === x1) x1 = x0 + 1;
    let y0 = this.opts.yMin ?? Math.min(...all.map((p) => p.y), 0), y1 = this.opts.yMax ?? Math.max(...all.map((p) => p.y), 1);
    if (!isFinite(y0)) { y0 = 0; y1 = 1; } if (y0 === y1) y1 = y0 + 1;
    const pw = this.w - m.l - m.r, ph = height - m.t - m.b;
    return { x: (v) => m.l + ((v - x0) / (x1 - x0)) * pw, y: (v) => m.t + (1 - (v - y0) / (y1 - y0)) * ph, x0, x1, y0, y1, pw, ph };
  }
  draw() {
    const { margin: m, height, yFmt = nice, xFmt = (v) => v, refs = [], bands = [] } = this.opts;
    const S = this.scales(); this.S = S;
    const g = [];
    for (const b of bands) g.push(svg('rect', { x: m.l, width: S.pw, y: S.y(Math.min(b.to, S.y1)), height: Math.max(0, S.y(Math.max(b.from, S.y0)) - S.y(Math.min(b.to, S.y1))), fill: b.color, opacity: 0.07 }));
    const ticks = 4;
    for (let i = 0; i <= ticks; i++) {
      const v = S.y0 + ((S.y1 - S.y0) * i) / ticks, y = S.y(v);
      g.push(svg('line', { x1: m.l, x2: m.l + S.pw, y1: y, y2: y, stroke: i === 0 ? 'var(--axis)' : 'var(--grid)', 'stroke-width': 1 }));
      g.push(svg('text', { x: m.l - 6, y: y + 4, 'text-anchor': 'end', fill: 'var(--ink-3)', 'font-size': 11 }, yFmt(v)));
    }
    const xt = Math.max(2, Math.min(6, Math.floor(S.pw / 90)));
    for (let i = 0; i <= xt; i++) { const v = S.x0 + ((S.x1 - S.x0) * i) / xt; g.push(svg('text', { x: S.x(v), y: height - 6, 'text-anchor': i === 0 ? 'start' : i === xt ? 'end' : 'middle', fill: 'var(--ink-3)', 'font-size': 11 }, xFmt(v))); }
    for (const r of refs) {
      g.push(svg('line', { x1: m.l, x2: m.l + S.pw, y1: S.y(r.y), y2: S.y(r.y), stroke: r.color || 'var(--ink-3)', 'stroke-dasharray': '4 4', 'stroke-width': 1 }));
      if (r.label) g.push(svg('text', { x: m.l + S.pw - 2, y: S.y(r.y) - 4, 'text-anchor': 'end', fill: 'var(--ink-3)', 'font-size': 10.5 }, r.label));
    }
    for (const s of this.series) {
      if (!s.points.length) continue;
      const pts = s.points.map((p) => [S.x(p.x), S.y(p.y)]);
      let d = pts.map((p, i) => (i ? (this.opts.step ? `H${p[0]}V${p[1]}` : `L${p[0]},${p[1]}`) : `M${p[0]},${p[1]}`)).join('');
      if (s.band) {
        const up = s.band.map((b) => [S.x(b.x), S.y(b.hi)]), lo = s.band.map((b) => [S.x(b.x), S.y(b.lo)]).reverse();
        g.push(svg('path', { d: 'M' + up.concat(lo).map((p) => p.join(',')).join('L') + 'Z', fill: s.color, opacity: 0.15 }));
      }
      if (s.area) g.push(svg('path', { d: d + `L${pts.at(-1)[0]},${S.y(S.y0)}L${pts[0][0]},${S.y(S.y0)}Z`, fill: s.color, opacity: 0.12 }));
      if (s.dots) { for (const p of pts) g.push(svg('circle', { cx: p[0], cy: p[1], r: 3, fill: s.color, stroke: 'var(--surface)', 'stroke-width': 1.5 })); }
      else g.push(svg('path', { d, fill: 'none', stroke: s.color, 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round', 'stroke-dasharray': s.dash || null }));
    }
    if (this.hx != null) {
      const px = S.x(this.hx);
      g.push(svg('line', { x1: px, x2: px, y1: m.t, y2: m.t + S.ph, stroke: 'var(--ink-3)', 'stroke-width': 1 }));
      for (const s of this.series) { const p = s.points.find((q) => q.x === this.hx); if (p && !s.dots) g.push(svg('circle', { cx: px, cy: S.y(p.y), r: 4, fill: s.color, stroke: 'var(--surface)', 'stroke-width': 2 })); }
    }
    this.svg.setAttribute('viewBox', `0 0 ${this.w} ${height}`);
    this.svg.replaceChildren(...g);
  }
  hover(e) {
    const S = this.S; if (!S) return;
    const r = this.svg.getBoundingClientRect(); const mx = ((e.clientX - r.left) / r.width) * this.w;
    const xs = [...new Set(this.series.filter((s) => !s.dots).flatMap((s) => s.points.map((p) => p.x)))];
    if (!xs.length) return;
    const xv = S.x0 + ((mx - this.opts.margin.l) / S.pw) * (S.x1 - S.x0);
    this.hx = xs.reduce((a, b) => (Math.abs(b - xv) < Math.abs(a - xv) ? b : a));
    this.draw();
    const rows = this.series.filter((s) => !s.dots).map((s) => { const p = s.points.find((q) => q.x === this.hx); return p ? h('div', null, h('span', { class: 'sw', style: { background: s.color } }), s.label + ': ', h('b', null, (this.opts.yFmt || nice)(p.y))) : null; });
    tip(h('div', null, h('div', { class: 'faint small' }, (this.opts.xFmt || ((v) => v))(this.hx)), rows), e.clientX, e.clientY);
  }
}

export function sparkline(values, { w = 120, h: ht = 28, color = 'var(--accent)', min, max } = {}) {
  const s = svg('svg', { viewBox: `0 0 ${w} ${ht}`, width: w, height: ht, 'aria-hidden': 'true' });
  if (values.length < 2) return s;
  const lo = min ?? Math.min(...values), hi = max ?? Math.max(...values), span = hi - lo || 1;
  const d = values.map((v, i) => `${i ? 'L' : 'M'}${(i / (values.length - 1)) * w},${ht - 2 - ((v - lo) / span) * (ht - 4)}`).join('');
  s.append(svg('path', { d, fill: 'none', stroke: color, 'stroke-width': 2, 'stroke-linejoin': 'round' }));
  return s;
}

export function ring(value, { size = 64, color = 'var(--good)', label } = {}) {
  const r = size / 2 - 6, c = 2 * Math.PI * r, v = Math.max(0, Math.min(100, value));
  const s = svg('svg', { viewBox: `0 0 ${size} ${size}`, width: size, height: size, class: 'ring', role: 'img', 'aria-label': `${label || 'value'} ${v.toFixed(0)}` });
  s.append(svg('circle', { cx: size / 2, cy: size / 2, r, fill: 'none', stroke: 'var(--grid)', 'stroke-width': 6 }),
    svg('circle', { cx: size / 2, cy: size / 2, r, fill: 'none', stroke: color, 'stroke-width': 6, 'stroke-linecap': 'round', 'stroke-dasharray': `${(v / 100) * c} ${c}`, transform: `rotate(-90 ${size / 2} ${size / 2})` }),
    svg('text', { x: size / 2, y: size / 2 + 5, 'text-anchor': 'middle', fill: 'var(--ink)', 'font-size': size / 3.4 }, v.toFixed(0)));
  return s;
}

/** Horizontal bars: rows=[{label,value,color?,note?}] */
export function barList(rows, { max, fmtv = (v) => v.toFixed(2), color = 'var(--accent)' } = {}) {
  const m = max ?? Math.max(...rows.map((r) => r.value), 1e-9);
  return h('div', { class: 'stack', style: { gap: '8px' } }, rows.map((r) => h('div', null,
    h('div', { class: 'row spread small' }, h('span', null, r.label), h('b', { class: 'num' }, r.note ?? fmtv(r.value))),
    h('div', { class: 'bar' }, h('i', { style: { width: `${Math.max(1, (r.value / m) * 100)}%`, background: r.color || color } })))));
}

/** Grouped vertical bars: groups=[{label, values:[v..]}], names=[..] */
export function groupedBars(groups, names, { height = 200, colors, yMax = 1, yFmt = (v) => (v * 100).toFixed(0) + '%' } = {}) {
  const w = 640, m = { l: 40, r: 8, t: 10, b: 38 }, ph = height - m.t - m.b, pw = w - m.l - m.r;
  const s = svg('svg', { viewBox: `0 0 ${w} ${height}`, width: '100%', height, role: 'img', 'aria-label': 'grouped bar chart' });
  for (let i = 0; i <= 4; i++) { const y = m.t + ph - (ph * i) / 4; s.append(svg('line', { x1: m.l, x2: w - m.r, y1: y, y2: y, stroke: i ? 'var(--grid)' : 'var(--axis)' }), svg('text', { x: m.l - 6, y: y + 4, 'text-anchor': 'end', fill: 'var(--ink-3)', 'font-size': 11 }, yFmt((yMax * i) / 4))); }
  const gw = pw / groups.length, bw = Math.min(26, (gw - 14) / names.length);
  groups.forEach((g, gi) => {
    const x0 = m.l + gi * gw + (gw - bw * names.length - 2 * (names.length - 1)) / 2;
    g.values.forEach((v, i) => {
      const bh = Math.max(0, (v / yMax) * ph), x = x0 + i * (bw + 2), y = m.t + ph - bh;
      const r = svg('rect', { x, y, width: bw, height: bh, rx: 3, fill: colors[i] });
      r.addEventListener('mousemove', (e) => tip(h('div', null, h('b', null, g.label), h('div', null, h('span', { class: 'sw', style: { background: colors[i] } }), `${names[i]}: ${yFmt(v)}`)), e.clientX, e.clientY));
      r.addEventListener('mouseleave', () => tip(null));
      s.append(r);
    });
    s.append(svg('text', { x: m.l + gi * gw + gw / 2, y: height - 20, 'text-anchor': 'middle', fill: 'var(--ink-2)', 'font-size': 10.5 }, g.label.length > 14 ? g.label.slice(0, 13) + '…' : g.label));
  });
  return s;
}

/** Histogram of two overlaid distributions. */
export function histogram(edges, a, b, { names = ['Normal', 'Attack'], colors = ['var(--s1)', 'var(--s2)'], threshold, height = 200 } = {}) {
  const w = 640, m = { l: 44, r: 8, t: 10, b: 26 }, ph = height - m.t - m.b, pw = w - m.l - m.r;
  const maxv = Math.max(...a, ...b, 1), x = (v) => m.l + ((v - edges[0]) / (edges.at(-1) - edges[0])) * pw;
  const s = svg('svg', { viewBox: `0 0 ${w} ${height}`, width: '100%', height, role: 'img', 'aria-label': 'anomaly score distribution' });
  s.append(svg('line', { x1: m.l, x2: w - m.r, y1: m.t + ph, y2: m.t + ph, stroke: 'var(--axis)' }));
  [[a, colors[0], names[0]], [b, colors[1], names[1]]].forEach(([arr, col, nm], k) => {
    arr.forEach((v, i) => {
      const bw = (x(edges[i + 1]) - x(edges[i])) / 2 - 1, bh = (v / maxv) * ph;
      const r = svg('rect', { x: x(edges[i]) + k * (bw + 1) + 1, y: m.t + ph - bh, width: Math.max(1, bw), height: bh, rx: 2, fill: col });
      r.addEventListener('mousemove', (e) => tip(h('div', null, h('div', { class: 'faint small' }, `score ${edges[i].toFixed(2)} … ${edges[i + 1].toFixed(2)}`), h('span', { class: 'sw', style: { background: col } }), `${nm}: ${v}`), e.clientX, e.clientY));
      r.addEventListener('mouseleave', () => tip(null));
      s.append(r);
    });
  });
  for (let i = 0; i <= 4; i++) { const v = edges[0] + ((edges.at(-1) - edges[0]) * i) / 4; s.append(svg('text', { x: x(v), y: height - 6, 'text-anchor': 'middle', fill: 'var(--ink-3)', 'font-size': 11 }, v.toFixed(2))); }
  if (threshold != null) s.append(svg('line', { x1: x(threshold), x2: x(threshold), y1: m.t, y2: m.t + ph, stroke: 'var(--crit)', 'stroke-dasharray': '4 3', 'stroke-width': 1.5 }), svg('text', { x: x(threshold) + 4, y: m.t + 10, fill: 'var(--ink-2)', 'font-size': 11 }, 'anomaly threshold'));
  return s;
}
