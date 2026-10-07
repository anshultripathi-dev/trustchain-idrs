import { h, clear, icon, badge, fmt, api, act, toast } from '../js/core.js';
import { LineChart, barList, groupedBars, histogram } from '../js/charts.js';
import { pageHeader, card, empty } from '../js/shared.js';

const ATK = ['BRUTE_FORCE', 'REQUEST_FLOOD', 'SERVICE_PROBING', 'SENSOR_ANOMALY', 'STEALTH_SURGE'];

export default function ml(root) {
  let data = null, devId = null, last = null, timer = 0;
  const cmpEl = h('div'), clsEl = h('div'), histEl = h('div'), baseEl = h('div'), liveEl = h('div'), evalEl = h('div'), jobEl = h('div');
  const baseChart = new LineChart({ height: 240, xMin: 0, xMax: 24, xFmt: (v) => `${String(Math.round(v)).padStart(2, '0')}:00`, yFmt: (v) => v.toFixed(1), label: 'baseline' });
  const devSel = h('select', { onchange: (e) => { devId = e.target.value; loadBaseline(); } });
  root.append(pageHeader('ML lab', 'Isolation Forest (novelty) + Random-Forest attack classifier + adaptive per-hour baseline, fused with rules.',
    h('button', { class: 'btn', onclick: () => act('Retraining started', () => api.post('/api/ml/retrain', {}, { admin: true })).then(poll) }, icon('brain', 14), 'Retrain models')),
    h('div', { class: 'note warn', style: { marginBottom: '14px' } }, h('b', null, 'Honest scope: '), 'all numbers below come from the built-in traffic simulator (synthetic, with benign bursts and a diurnal pattern). They show how the methods compare under the same assumptions, not accuracy on a real household. Collect real telemetry and retrain before drawing real-world conclusions.'), jobEl,
    card('Detector comparison on held-out simulated traffic', cmpEl), h('div', { class: 'grid g2', style: { marginTop: '14px' } }, card('Attack-class classifier', clsEl), card('Isolation-Forest anomaly scores', histEl)),
    h('div', { class: 'grid g-main', style: { marginTop: '14px' } }, card('Adaptive baseline', h('div', null, baseChart.root, h('div', { class: 'legend' }, h('span', null, h('i', { style: { background: 'var(--s1)' } }), 'Learned expectation ±2σ'), h('span', null, h('i', { style: { background: 'var(--s2)' } }), 'Live observations'))), devSel), card('Live model output', liveEl, h('span', { class: 'faint small' }, '10 most anomalous'))),
    h('div', { style: { marginTop: '14px' } }, card('Attack-scenario evaluation (end-to-end, headless)', evalEl, h('button', { class: 'btn sm', onclick: () => act('Evaluation started', () => api.post('/api/evaluation/run', { trials: 3 }, { admin: true })).then(poll) }, icon('play', 12), 'Run evaluation'))));

  async function load() {
    data = await api.get('/api/ml'); render();
    if (!devId) { const ds = (await api.get('/api/devices')).devices; devSel.replaceChildren(...ds.map((d) => h('option', { value: d.id }, d.name))); devId = ds[0].id; }
    loadBaseline();
  }
  function poll() { clearTimeout(timer); load().then(() => { if (data?.job?.running || data?.retrain?.running) timer = setTimeout(poll, 2500); }); }
  async function loadBaseline() {
    if (!devId) return;
    const r = await api.get('/api/ml/baseline?device_id=' + encodeURIComponent(devId));
    baseChart.setData([{ label: 'Expected req/s ±2σ', color: 'var(--s1)', points: r.curve.map((p) => ({ x: p.hour + 0.5, y: p.mean })), band: r.curve.map((p) => ({ x: p.hour + 0.5, lo: Math.max(0, p.mean - 2 * p.sd), hi: p.mean + 2 * p.sd })) },
      { label: 'Observed', color: 'var(--s2)', dots: true, points: r.recent.map((p) => ({ x: p.hour, y: p.value })) }]);
  }
  function render() {
    const m = data.metrics, c = m.comparison;
    const names = { static_rules: 'Static rules (original IDS)', isolation_forest: 'Isolation Forest only', hybrid: 'Hybrid (rules + IF + classifier)' };
    const colors = ['var(--s1)', 'var(--s2)', 'var(--s3)'];
    clear(cmpEl, c ? h('div', { class: 'stack' },
      groupedBars(ATK.map((a) => ({ label: a.replaceAll('_', ' ').toLowerCase(), values: Object.keys(names).map((k) => c[k].per_attack[a].episode_recall) })), Object.values(names), { colors }),
      h('div', { class: 'legend' }, Object.values(names).map((n, i) => h('span', null, h('i', { style: { background: colors[i] } }), n))),
      h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['Detector', 'Macro recall (episodes)', 'False-positive rate (tick)', 'False-positive rate (2-tick confirm)'].map((x) => h('th', null, x)))),
        h('tbody', null, Object.entries(names).map(([k, n]) => h('tr', null, h('td', null, h('b', null, n)), h('td', { class: 'num' }, fmt.pct(c[k].episode_recall_macro, 1)), h('td', { class: 'num' }, fmt.pct(c[k].false_positive_rate_tick, 2)), h('td', { class: 'num' }, fmt.pct(c[k].false_positive_rate_confirmed, 2))))))),
      h('div', { class: 'note' }, 'Static thresholds never fire on sensor drift below 40 °C or on a quiet-hours surge that stays under 10 req/s; the adaptive baseline and ML layers catch both. ML-only detections must persist for 2 consecutive ticks before an event is raised.')) : empty('No metrics yet — train the models.'));
    const k = m.classifier;
    if (k) {
      const mx = Math.max(...k.confusion.flat(), 1);
      clear(clsEl, h('div', { class: 'stack' }, h('div', { class: 'small muted' }, `accuracy ${fmt.pct(k.accuracy, 1)} · ${m.samples.test_normal + m.samples.test_attack} held-out ticks`),
        h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['Class', 'Precision', 'Recall', 'F1'].map((x) => h('th', null, x)))), h('tbody', null, k.labels.map((l) => h('tr', null, h('td', null, fmt.type(l)), h('td', { class: 'num' }, fmt.n(k.report[l].precision, 3)), h('td', { class: 'num' }, fmt.n(k.report[l].recall, 3)), h('td', { class: 'num' }, fmt.n(k.report[l]['f1-score'], 3))))))),
        h('h3', null, 'Confusion matrix (rows = truth)'),
        h('div', { class: 'scroll' }, h('table', { style: { fontSize: '11px' } }, h('thead', null, h('tr', null, h('th'), k.labels.map((l) => h('th', { title: l }, l.slice(0, 6))))), h('tbody', null, k.confusion.map((row, i) => h('tr', null, h('td', null, k.labels[i].slice(0, 9)), row.map((v) => h('td', { class: 'num right', style: { background: `color-mix(in srgb, var(--seq-400) ${Math.round((v / mx) * 70)}%, transparent)`, color: v / mx > 0.55 ? '#fff' : 'inherit' } }, v))))))),
        h('h3', null, 'Feature importance'), barList(Object.entries(k.importances).sort((a, b) => b[1] - a[1]).map(([f, v]) => ({ label: f, value: v })), { fmtv: (v) => v.toFixed(3) })));
      const sh = m.score_hist;
      clear(histEl, h('div', { class: 'stack' }, histogram(sh.edges, sh.normal, sh.attack, { threshold: sh.threshold }), h('div', { class: 'legend' }, h('span', null, h('i', { style: { background: 'var(--s1)' } }), 'Normal traffic'), h('span', null, h('i', { style: { background: 'var(--s2)' } }), 'Attack traffic')),
        h('div', { class: 'note' }, `Lower score = more anomalous. The threshold (${fmt.n(m.if_threshold, 3)}) is the 0.5th percentile of validation-normal scores, so ~0.5% of clean ticks are flagged before confirmation.`)));
    }
    renderEval(); renderJob(); renderLive();
  }
  function renderJob() {
    const j = data.job, r = data.retrain;
    clear(jobEl, (j?.running || r?.running) ? h('div', { class: 'note', style: { marginBottom: '14px' } }, r?.running ? 'Retraining models… (~30 s)' : `Evaluation running… ${j.progress.length} step(s) done`) : (j?.error || r?.error) ? h('div', { class: 'note warn' }, j?.error || r?.error) : null);
  }
  function renderEval() {
    const e = data.evaluation;
    clear(evalEl, e ? h('div', { class: 'stack' },
      h('div', { class: 'row small muted' }, `${e.trials} trial(s) per scenario on the 5 original devices · virtual clock · clean run: ${e.clean.false_events} false event(s) in ${e.clean.device_ticks.toLocaleString()} device-ticks (≈${e.clean.sim_days} simulated days, ${e.clean.false_quarantines} false quarantines)`),
      e.home_clean && h('div', { class: 'note' }, h('b', null, 'Full smart home, clean traffic: '), `${e.home_clean.devices} devices · ${e.home_clean.device_ticks.toLocaleString()} device-ticks (≈${e.home_clean.sim_days} simulated days) → ${e.home_clean.events} low-severity alerts (${e.home_clean.events_per_sim_day} per day for the whole home), ${e.home_clean.false_quarantines} false quarantines.`),
      h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['Scenario', 'Layer', 'Detected', 'Classified', 'Latency (ticks)', 'Quarantined'].map((x) => h('th', null, x)))),
        h('tbody', null, Object.entries(e.scenarios).map(([k, v]) => h('tr', null, h('td', null, v.label), h('td', null, v.layer), h('td', { class: 'num' }, fmt.pct(v.detection_rate)), h('td', { class: 'num' }, fmt.pct(v.classification_rate)), h('td', { class: 'num' }, v.mean_latency_ticks ?? '–'), h('td', { class: 'num' }, fmt.pct(v.quarantine_rate))))))),
      h('div', { class: 'row' }, Object.entries(e.tamper).map(([k, v]) => h('span', { class: 'badge b-OK' }, icon('check'), `${fmt.type(k)}: detected ${fmt.pct(v.detection_rate)}`))),
      h('div', { class: 'note' }, 'Replay and spoofing are rejected at the gateway without quarantining the victim device on purpose: an outsider must not be able to knock a legitimate device offline by forging its traffic. Only rogue (unregistered) devices and persistent/escalating attacks lead to quarantine.')) : empty('Not run yet. Click “Run evaluation” (≈1–2 min).'));
  }
  function renderLive() {
    const rows = Object.entries(data.live).sort((a, b) => a[1].ml.if_score - b[1].ml.if_score).slice(0, 10);
    clear(liveEl, rows.length ? h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['Device', 'IF score', 'Class', 'Conf.', 'req z'].map((x) => h('th', null, x)))),
      h('tbody', null, rows.map(([id, v]) => h('tr', null, h('td', null, v.name), h('td', { class: 'num' }, fmt.n(v.ml.if_score, 3), v.ml.if_anomaly ? ' ⚠' : ''), h('td', null, fmt.type(v.ml.cls)), h('td', { class: 'num' }, fmt.pct(v.ml.cls_conf)), h('td', { class: 'num' }, fmt.n(v.baseline.req_z, 1))))))) : empty('Waiting for telemetry…'));
  }
  load().then(() => { if (data?.job?.running || data?.retrain?.running) poll(); });
  return { update(d) { last = d; if (data && !data.job?.running) { const live = {}; d.devices.forEach((x) => { if (x.ml) live[x.id] = { name: x.name, ml: x.ml, baseline: x.baseline, risk: x.risk }; }); data.live = live; renderLive(); } }, destroy() { clearTimeout(timer); } };
}
