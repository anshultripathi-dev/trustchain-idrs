import { h, clear, icon, badge, fmt, api, act, modal } from '../js/core.js';
import { barList } from '../js/charts.js';
import { pageHeader, card, tx, empty } from '../js/shared.js';

export default function threats(root, { param }) {
  let sev = '', dev = '', events = [], lastN = -1, devices = [];
  const table = h('div'), memory = h('div'), srcs = h('div');
  const sevSel = h('select', { onchange: (e) => { sev = e.target.value; load(); } }, [['', 'All severities'], ['LOW', 'Low'], ['MEDIUM', 'Medium'], ['HIGH', 'High'], ['CRITICAL', 'Critical']].map(([v, l]) => h('option', { value: v }, l)));
  const devSel = h('select', { onchange: (e) => { dev = e.target.value; load(); } }, h('option', { value: '' }, 'All devices'));
  root.append(pageHeader('Threats & attack memory', 'Every detected event is stored locally and anchored on the ledger. Verified status compares the local record with its on-chain hash.'),
    card('Security events', table, h('div', { class: 'row' }, devSel, sevSel)),
    h('div', { class: 'grid g-main', style: { marginTop: '14px' } }, card('Attack fingerprints (attack memory)', memory), card('Repeat sources', srcs)));

  async function load() {
    const q = new URLSearchParams({ limit: 100 }); if (sev) q.set('severity', sev); if (dev) q.set('device_id', dev);
    const r = await api.get('/api/events?' + q); events = r.events; lastN = r.total; renderTable();
    const m = await api.get('/api/memory');
    clear(memory, m.fingerprints.length ? h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['Fingerprint', 'Type', 'Count', 'Sources', 'Last seen'].map((x) => h('th', null, x)))),
      h('tbody', null, m.fingerprints.map((f) => h('tr', null, h('td', { class: 'mono' }, f.fingerprint), h('td', null, fmt.type(f.event_type)), h('td', null, h('b', null, f.count), f.count >= m.policy.escalate_1 ? h('span', { class: 'badge b-MEDIUM', style: { marginLeft: '6px' } }, f.count >= m.policy.escalate_2 ? 'severity +2' : 'severity +1') : null), h('td', { class: 'small' }, f.sources.join(', ') || '–'), h('td', null, fmt.time(f.last_ts))))))) : empty('No attack fingerprints yet.'),
      h('div', { class: 'note', style: { marginTop: '10px' } }, `Fingerprint = SHA-256(type, device, source, port, protocol, rate bucket, failed-attempt bucket). Timestamps are excluded on purpose so a repeat of the same attack matches. ≥${m.policy.escalate_1} prior → severity +1, ≥${m.policy.escalate_2} → +2 (within ${m.policy.window_s / 60} min).`));
    clear(srcs, m.sources.length ? barList(m.sources.slice(0, 8).map((s) => ({ label: s.source, value: s.count, note: `${s.count} × · ${s.types.map(fmt.type).join(', ')}` })), { color: 'var(--s2)' }) : empty('No repeat sources.'));
  }
  function renderTable() {
    clear(table, events.length ? h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['Time', 'Event', 'Device', 'Type', 'Severity', 'Risk', 'Action', 'Trust', 'Ledger check'].map((x) => h('th', null, x)))),
      h('tbody', null, events.map((e) => h('tr', { class: 'click', onclick: () => detail(e.event_id), tabindex: 0, onkeydown: (k) => k.key === 'Enter' && detail(e.event_id) },
        h('td', null, fmt.time(e.ts)), h('td', { class: 'mono' }, e.event_id), h('td', null, e.device_name), h('td', null, fmt.type(e.event_type)), h('td', null, badge(e.severity)), h('td', { class: 'num' }, fmt.n(e.risk_score, 2)), h('td', { class: 'small' }, e.action.replaceAll('_', ' ')), h('td', { class: 'num' }, fmt.n(e.trust_after, 0)), h('td', null, badge(e.verified, e.verified === 'MATCH' ? 'verified' : e.verified)))))))
      : empty('No events yet. Launch a scenario from the Attack Lab, or wait for the monitor to flag something.'));
  }
  async function detail(id) {
    const r = await api.get('/api/events/' + id);
    const l = r.local, c = r.chain, v = r.verification;
    const fields = ['event_type', 'severity', 'risk_score', 'action', 'source', 'trust_after', 'fingerprint'];
    const rowv = (k) => { const a = l?.[k], b = c?.[k]; const same = l && c && a === b; return h('tr', null, h('td', { class: 'faint' }, k), h('td', { class: same ? '' : 'diff' }, l ? String(a) : '— missing —'), h('td', null, c ? String(b) : '—')); };
    const det = l?.details || {};
    const parts = det.detectors?.risk_parts;
    const body = h('div', { class: 'stack' },
      h('div', { class: 'row spread' }, h('h2', null, `${id} · ${fmt.type((l || c).event_type)}`), badge(v.result, v.result === 'MATCH' ? 'ledger verified' : v.result.replaceAll('_', ' '))),
      h('div', { class: 'cmp' },
        h('div', { class: 'col' }, h('h3', null, 'Local record'), h('table', null, h('thead', null, h('tr', null, h('th', null, 'Field'), h('th', null, 'Local'), h('th', null, 'Ledger'))), h('tbody', null, fields.map(rowv))), h('div', { class: 'small faint', style: { marginTop: '8px' } }, 'recomputed hash'), h('code', { style: { wordBreak: 'break-all' } }, v.recomputed_hash || '–')),
        h('div', { class: 'col' }, h('h3', null, 'On-chain reference'), c ? h('div', { class: 'stack' }, h('div', null, h('div', { class: 'faint small' }, 'committed event hash'), h('code', { style: { wordBreak: 'break-all' } }, c.event_hash)), h('div', { class: 'small' }, 'Block ', h('a', { href: `#/ledger/${c.block}`, onclick: () => document.querySelector('.modal-bg')?.remove() }, '#' + c.block), ` · ${fmt.dt(c.committed_at)}`), c.integrity_flagged && h('span', { class: 'badge b-CRITICAL' }, icon('x'), 'tampering flagged on ledger')) : empty('not on chain'))),
      v.result === 'MISMATCH' || v.result === 'LOCAL_RECORD_MISSING' ? h('div', { class: 'note warn' }, 'The local security log no longer matches the hash committed on the ledger. Tampering was detected, the implicated device’s trust was reduced, and an AUDIT_TAMPERING event was raised. ', h('button', { class: 'btn sm', onclick: () => act('Record repaired from ledger', () => api.post('/api/integrity/repair/' + id)).then(() => { document.querySelector('.modal-bg')?.remove(); load(); }) }, 'Repair record from ledger')) : null,
      l && h('div', { class: 'grid g2' },
        h('div', null, h('h3', null, 'Detector evidence'), h('div', { class: 'stack', style: { marginTop: '8px', gap: '6px' } },
          (det.detectors?.rules || []).map((x) => h('div', null, badge('HIGH', 'rule'), ' ', x.why)),
          det.detectors?.ml && h('div', null, badge('MEDIUM', 'ML'), ` IsolationForest score ${fmt.n(det.detectors.ml.if_score, 3)}${det.detectors.ml.if_anomaly ? ' (anomalous)' : ''} · classifier: ${fmt.type(det.detectors.ml.cls)} ${fmt.pct(det.detectors.ml.cls_conf)}`),
          det.detectors?.baseline && h('div', null, badge('LOW', 'baseline'), ` req z=${det.detectors.baseline.req_z}, sensor z=${det.detectors.baseline.primary_z}${det.detectors.baseline.warm ? '' : ' (cold)'}`),
          det.detectors?.gateway_reject && h('div', null, badge('HIGH', 'gateway'), ' rejected: ' + det.detectors.gateway_reject),
          det.gateway_attested && h('div', { class: 'small muted' }, 'gateway-attested telemetry (unsigned firmware)'),
          h('div', { class: 'small muted' }, `repeat count ${det.repeat_count ?? 0} · base severity ${det.base_severity}`))),
        parts && h('div', null, h('h3', null, 'Risk composition'), h('div', { style: { marginTop: '8px' } }, barList(Object.entries(parts).map(([k, val]) => ({ label: k, value: val })), { max: 1 })))),
      l && h('details', null, h('summary', { class: 'small muted' }, 'Raw sample'), h('pre', { class: 'json' }, JSON.stringify(det.sample, null, 2))));
    modal(body);
  }
  api.get('/api/devices').then((r) => { r.devices.forEach((d) => devSel.append(h('option', { value: d.id }, d.name))); });
  load();
  if (param) detail(param);
  return { update(d) { if (d.kpis.events !== lastN) load(); }, destroy() {} };
}
