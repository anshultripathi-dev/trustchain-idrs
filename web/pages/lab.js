import { h, clear, icon, badge, fmt, api, act, toast, store } from '../js/core.js';
import { pageHeader, card, empty } from '../js/shared.js';

const LAYER = { traffic: 'Traffic & behaviour', crypto: 'Identity & cryptography' };

export default function lab(root) {
  let cat = null, devs = [], last = null, target = null;
  const cards = h('div', { class: 'grid g3' }), activeEl = h('div'), logEl = h('div'), clockEl = h('div'), tamperEl = h('div');
  const devSel = h('select', { onchange: (e) => { target = e.target.value; } });
  root.append(pageHeader('Attack lab', 'Safely simulate attacks against the digital twin and watch the whole loop respond. Targets are simulated devices only.',
    h('button', { class: 'btn', onclick: () => act('All attacks stopped', () => api.post('/api/attacks/stop')) }, 'Stop all attacks'),
    h('button', { class: 'btn danger', onclick: async () => { if (confirm('Reset the demo? This wipes the ledger, local log and keys and starts a fresh chain.')) { await act('Demo reset', () => api.post('/api/reset')); store.feed.length = 0; location.reload(); } } }, 'Reset demo')),
    h('div', { class: 'row', style: { marginBottom: '12px' } }, h('span', { class: 'muted' }, 'Target device'), devSel),
    cards, h('div', { class: 'grid g2', style: { marginTop: '14px' } }, card('Active attacks', activeEl), card('Outcomes', logEl)),
    h('div', { class: 'grid g2', style: { marginTop: '14px' } }, card('Tamper with the evidence', tamperEl), card('Simulated household clock', clockEl)));

  async function load() {
    cat = await api.get('/api/attacks'); devs = cat.devices; target = target || devs[0].id;
    const rooms = cat.rooms || [];
    devSel.replaceChildren(...(rooms.length ? rooms.map((r) => h('optgroup', { label: `${r.icon} ${r.name}` }, devs.filter((d) => d.room === r.id).map((d) => h('option', { value: d.id }, `${d.icon} ${d.name}${d.real ? ' (real)' : ''}`)))) : devs.map((d) => h('option', { value: d.id }, d.name))));
    renderCards(); renderTamper(); renderClock(); renderLists(cat.active, cat.log);
  }
  function renderCards() {
    clear(cards);
    for (const layer of ['traffic', 'crypto']) {
      cards.append(h('h3', { style: { gridColumn: '1/-1', marginTop: '6px' } }, LAYER[layer]));
      cat.catalog.filter((a) => a.layer === layer).forEach((a) => cards.append(card(a.label, h('div', { class: 'stack' }, h('p', { class: 'muted', style: { margin: 0 } }, a.desc),
        h('div', null, h('button', { class: 'btn primary sm', onclick: () => act(`${a.label} launched`, () => api.post('/api/attacks', { type: a.type, device_id: a.type === 'ROGUE_DEVICE' ? null : target }, { admin: true })) }, icon('bolt', 13), 'Launch'))))));
    }
  }
  function renderTamper() {
    clear(tamperEl, h('div', { class: 'stack' },
      h('p', { class: 'muted', style: { margin: 0 } }, 'An intruder who owns the monitoring host edits the log to hide an attack. The integrity checker recomputes record hashes against the ledger and feeds the result into the device’s trust score.'),
      h('div', { class: 'row' }, h('button', { class: 'btn', onclick: () => act('Local log edited (severity → LOW)', () => api.post('/api/tamper/local', { mode: 'edit' }, { admin: true })) }, 'Edit latest event in local DB'),
        h('button', { class: 'btn', onclick: () => act('Local log record deleted', () => api.post('/api/tamper/local', { mode: 'delete' }, { admin: true })) }, 'Delete latest event'),
        h('button', { class: 'btn primary', onclick: () => act('Integrity check complete', () => api.post('/api/integrity/run', {}, { admin: true })) }, 'Run integrity check now')),
      h('div', { class: 'row' }, h('button', { class: 'btn', onclick: () => act('Block edited on validator node-2', () => api.post('/api/tamper/ledger', { node: 'node-2' }, { admin: true })) }, 'Modify a block on validator node-2')),
      h('div', { class: 'small muted' }, 'The checker also runs automatically every ~12 s. Look at Threats (ledger-check column), Ledger (node status) and Devices (trust drop).')));
  }
  function renderClock() {
    const set = (hour) => act(`Sim time set to ${hour}:00`, () => api.post('/api/sim/clock', { hour }));
    clear(clockEl, h('div', { class: 'stack' }, h('div', { class: 'row' }, h('span', { class: 'muted' }, 'Now:'), h('b', { id: 'simt' }, last?.sim.label || '–')),
      h('div', { class: 'row' }, [['Night 02:00', 2], ['Morning 08:00', 8], ['Midday 13:00', 13], ['Evening 19:00', 19]].map(([l, v]) => h('button', { class: 'btn sm', onclick: () => set(v) }, l))),
      h('div', { class: 'row' }, h('span', { class: 'muted' }, 'Speed'), h('div', { class: 'seg' }, [['Slow', 1], ['Normal', 5], ['Fast', 20]].map(([l, v]) => h('button', { onclick: () => act(`Speed ${l}`, () => api.post('/api/sim/clock', { minutes_per_tick: v })) }, l)))),
      h('div', { class: 'note' }, 'Try the “Low-and-slow surge” at 02:00: ~6 req/s is far below the static flood threshold of 10, yet a many-σ outlier for the quiet hours — only the adaptive baseline + ML flag it.')));
  }
  function renderLists(active, log) {
    clear(activeEl, active.length ? h('div', { class: 'stack' }, active.map((a) => h('div', null, h('div', { class: 'row spread' }, h('b', null, a.label), h('span', { class: 'small muted' }, a.source)), h('div', { class: 'small muted' }, fmt.name(a.device_id)), h('div', { class: 'bar', style: { marginTop: '4px' } }, h('i', { style: { width: ((1 - a.ticks_left / a.ticks_total) * 100) + '%' } })), h('div', { class: 'small' }, a.first_event_type ? `detected as ${fmt.type(a.first_event_type)} · ${a.events.length} event(s)` : 'not detected yet')))) : empty('No attack running.'));
    clear(logEl, log.length ? h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['Attack', 'Detected', 'Classified', 'Latency'].map((x) => h('th', null, x)))), h('tbody', null, log.slice(0, 8).map((a) => h('tr', null, h('td', null, fmt.type(a.type), h('div', { class: 'small faint' }, fmt.name(a.device_id))), h('td', null, badge(a.detected ? 'OK' : 'CRITICAL', a.detected ? 'yes' : 'NO')), h('td', null, a.detected ? (a.classified_correctly ? badge('OK', fmt.type(a.first_event_type)) : badge('MEDIUM', fmt.type(a.first_event_type))) : '–'), h('td', { class: 'num' }, a.detection_latency_ticks != null ? `${a.detection_latency_ticks} tick` : '–')))))) : empty('Outcomes appear when an attack ends.'));
  }
  load();
  return { update(d) { last = d; renderLists(d.attacks, d.attack_log); const el = document.getElementById('simt'); if (el) el.textContent = d.sim.label; }, destroy() {} };
}
