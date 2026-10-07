import { h, clear, icon, badge, fmt, api, act, bandColor, seriesColor } from '../js/core.js';
import { LineChart } from '../js/charts.js';
import { pageHeader, card, deviceCard, checkRow, empty } from '../js/shared.js';

export default function devices(root, { param, param2 }) {
  let selected = param ? decodeURIComponent(param) : null;
  let room = 'all', tab = ['telemetry', 'trust', 'baseline', 'identity', 'events', 'commands'].includes(param2) ? param2 : 'telemetry', detail = null, lastFetch = 0, last = null;
  const grid = h('div'), panel = h('div', { style: { marginBottom: '6px' } });
  const risk = new LineChart({ height: 180, yMin: 0, yMax: 1, yFmt: (v) => v.toFixed(2), xFmt: fmt.time, label: 'risk' });
  const req = new LineChart({ height: 180, xFmt: fmt.time, yFmt: (v) => v.toFixed(1), label: 'request rate' });
  const prim = new LineChart({ height: 180, xFmt: fmt.time, yFmt: (v) => v.toFixed(1), label: 'primary sensor' });
  const trust = new LineChart({ height: 200, yMin: 0, yMax: 100, step: true, yFmt: (v) => v.toFixed(0), xFmt: fmt.time, label: 'trust history',
    refs: [{ y: 20, label: 'quarantine < 20', color: 'var(--crit)' }] });
  const base = new LineChart({ height: 220, xMin: 0, xMax: 24, xFmt: (v) => `${String(Math.round(v)).padStart(2, '0')}:00`, yFmt: (v) => v.toFixed(1), label: 'baseline' });
  const roomSel = h('select', { 'aria-label': 'Filter by room', onchange: (e) => { room = e.target.value; renderGrid(); } }, h('option', { value: 'all' }, 'All rooms'));
  root.append(pageHeader('Devices & trust', 'Every device has a ledger-registered identity, a dynamic trust score and a time-of-day behavioural baseline.', roomSel), panel, grid);

  async function load() {
    if (!selected) return;
    lastFetch = Date.now();
    try { detail = await api.get('/api/devices/' + encodeURIComponent(selected)); } catch { detail = null; }
    renderPanel();
  }
  function select(id) { selected = id; history.replaceState(null, '', '#/devices/' + encodeURIComponent(id)); detail = null; renderPanel(); load(); renderGrid(); window.scrollTo({ top: 0, behavior: 'smooth' }); }
  function renderGrid() {
    if (!last) return;
    if (roomSel.options.length === 1) (last.rooms || []).forEach((r) => roomSel.append(h('option', { value: r.id }, `${r.icon} ${r.name} (${r.count})`)));
    const parts = [];
    for (const r of last.rooms || []) {
      if (room !== 'all' && room !== r.id) continue;
      const devs = last.devices.filter((x) => x.room === r.id);
      parts.push(h('div', { class: 'group-hd' }, h('span', { 'aria-hidden': 'true' }, r.icon), h('h2', null, r.name), h('small', null, `${devs.length} devices`)),
        h('div', { class: 'grid g3' }, devs.map((d) => deviceCard(d, { selected: d.id === selected, onclick: () => select(d.id) }))));
    }
    const orphans = (last.devices || []).filter((x) => !x.room);
    if (orphans.length) parts.push(h('div', { class: 'grid g3' }, orphans.map((d) => deviceCard(d, { selected: d.id === selected, onclick: () => select(d.id) }))));
    if (room === 'all' && last.unknown_devices.length) parts.push(h('div', { class: 'group-hd' }, h('span', null, '❓'), h('h2', null, 'Unregistered devices'), h('small', null, 'not enrolled on the ledger')),
      h('div', { class: 'grid g3' }, last.unknown_devices.map((u) => deviceCard({ ...u, series: [], sample: {}, band: 'CRITICAL', risk: 0, primary_name: '' }, { selected: u.id === selected, onclick: () => select(u.id) }))));
    clear(grid, parts);
  }
  const tabs = () => h('div', { class: 'tabs', role: 'tablist' }, [['telemetry', 'Telemetry'], ['trust', 'Trust timeline'], ['baseline', 'Adaptive baseline'], ['identity', 'Identity'], ['events', 'Events'], ['commands', 'Gateway commands']].map(([k, l]) =>
    h('button', { class: tab === k ? 'on' : '', role: 'tab', 'aria-selected': tab === k, onclick: () => { tab = k; renderPanel(); } }, l)));

  function renderPanel() {
    if (!selected) { clear(panel); return; }          // nothing selected: the grid below is the page
    if (!detail) { clear(panel, card(null, empty('Loading…'))); return; }
    const d = detail.device; const live = last?.devices.find((x) => x.id === selected);
    const dd = live ? { ...d, ...live, series: d.series } : d;
    const head = h('div', { class: 'row spread', style: { marginBottom: '10px' } },
      h('div', { class: 'row' }, h('h2', null, dd.icon ? `${dd.icon} ${dd.name}` : dd.name), dd.room_name && h('span', { class: 'badge' }, dd.room_name), badge(dd.status), dd.band && badge(dd.band, 'risk ' + dd.band), dd.unregistered && h('span', { class: 'badge b-CRITICAL' }, 'unregistered')),
      h('div', { class: 'row' }, dd.status === 'ACTIVE' && !dd.unregistered && h('button', { class: 'btn danger sm', onclick: () => act('Quarantined', () => api.post(`/api/devices/${encodeURIComponent(dd.id)}/quarantine`)).then(load) }, icon('lock', 13), 'Quarantine'),
        dd.status !== 'ACTIVE' && h('a', { class: 'btn sm', href: '#/response' }, 'Recovery workflow →')));
    const body = h('div');
    if (tab === 'telemetry' && !dd.unregistered) {
      const s = dd.series;
      risk.setData([{ label: 'Risk', color: 'var(--s1)', area: true, points: s.map((p) => ({ x: p.t, y: p.risk })) }]);
      req.setData([{ label: 'Requests/s', color: 'var(--s2)', points: s.map((p) => ({ x: p.t, y: p.req })) }], { refs: [{ y: 10, label: 'static flood threshold (10)' }], yMax: Math.max(12, ...s.map((p) => p.req)) });
      prim.setData([{ label: dd.primary_name, color: 'var(--s3)', points: s.map((p) => ({ x: p.t, y: p.primary })) }], { yMin: undefined, yMax: undefined });
      body.append(h('div', { class: 'grid g3' }, card('Risk', risk.root), card('Requests / second', req.root), card(dd.primary_name?.replaceAll('_', ' ') || 'Primary sensor', prim.root)),
        dd.risk_parts && h('div', { class: 'note', style: { marginTop: '12px' } }, 'Risk composition (noisy-OR of): ', Object.entries(dd.risk_parts).map(([k, v]) => `${k} ${v.toFixed(2)}`).join(' · ')),
        dd.fail_policy && h('div', { class: 'note warn', style: { marginTop: '12px' } }, icon('lock', 13), ' ', h('b', null, dd.critical ? 'Safety-critical · quarantine policy. ' : 'Quarantine policy. '), dd.fail_policy));
    } else if (tab === 'trust') {
      const th = detail.trust_history || [];
      trust.setData([{ label: 'Trust', color: 'var(--s1)', points: th.map((p) => ({ x: p.ts, y: p.trust })) }]);
      const rows = [...th].reverse().slice(0, 25).map((p) => h('tr', null, h('td', null, fmt.time(p.ts)), h('td', { class: 'num' }, fmt.n(p.trust, 1)), h('td', null, p.reason), h('td', null, h('a', { href: `#/ledger/${p.block}` }, '#' + p.block))));
      const tbl = h('table', null, h('thead', null, h('tr', null, ['Time', 'Trust', 'Reason', 'Block'].map((x) => h('th', null, x)))), h('tbody', null, rows));
      body.append(card('Trust score — reconstructed from ledger blocks', trust.root), h('div', { style: { marginTop: '14px' } }, card('Changes', tbl)));
    } else if (tab === 'baseline' && detail.baseline) {
      const c = detail.baseline.req_rate;
      base.setData([{ label: 'Expected req/s (±2σ)', color: 'var(--s1)', points: c.map((p) => ({ x: p.hour + 0.5, y: p.mean })), band: c.map((p) => ({ x: p.hour + 0.5, lo: Math.max(0, p.mean - 2 * p.sd), hi: p.mean + 2 * p.sd })) },
        { label: 'Observed', color: 'var(--s2)', dots: true, points: dd.series.slice(-60).map((p) => ({ x: p.hour, y: p.req })) }]);
      body.append(card('Request rate vs. learned normal for this hour', h('div', null, base.root, h('div', { class: 'legend' }, h('span', null, h('i', { style: { background: 'var(--s1)' } }), 'Learned expectation ±2σ'), h('span', null, h('i', { style: { background: 'var(--s2)' } }), 'Recent observations'))),
        h('span', { class: 'faint small' }, `z(now) = ${fmt.n(dd.baseline?.req_z, 1)} · ${dd.baseline?.warm ? 'baseline warm' : 'cold-start: rules dominate'}`)),
        h('div', { class: 'note', style: { marginTop: '12px' } }, 'The same raw value scores differently at 03:00 and 18:00. Only clean (SAFE) observations update the baseline, so an attacker cannot slowly “teach” it that an attack is normal.'));
    } else if (tab === 'identity') {
      body.append(card('Device-bound identity', h('div', { class: 'stack' },
        h('div', null, h('div', { class: 'faint small' }, 'Decentralised identifier'), h('code', null, dd.id)),
        h('div', null, h('div', { class: 'faint small' }, 'Public key (ECDSA P-256, enrolled on ledger)'), h('code', { style: { wordBreak: 'break-all' } }, dd.pubkey || '— none (unregistered) —')),
        h('div', null, h('div', { class: 'faint small' }, 'Firmware hash at enrolment'), h('code', { style: { wordBreak: 'break-all' } }, dd.firmware_hash || '–')),
        h('div', null, h('div', { class: 'faint small' }, 'Registration block'), dd.registered_block != null ? h('a', { href: `#/ledger/${dd.registered_block}` }, '#' + dd.registered_block) : '–'),
        h('div', { class: 'note' }, 'Every telemetry message is signed with the device key and carries a timestamp and single-use nonce. The gateway rejects unknown devices, bad signatures, stale timestamps and replayed nonces before any detection logic runs.'),
        dd.ml_mode === 'shadow' && h('div', { class: 'note warn' }, h('b', null, 'ML shadow mode. '), 'The Isolation Forest and classifier were trained on simulated traffic, so on this real board they only observe (scores are shown, not acted on). Rule detections — flood, probing, brute force, sensor range — raise events. Set TRUSTCHAIN_REAL_ML=1 to let ML act, ideally after retraining on real telemetry.'),
        dd.real_hardware && h('div', { class: 'note warn' }, 'This ESP32 runs the original unsigned firmware, so the gateway signs on its behalf (“gateway-attested”). Native on-device signing is a firmware extension.'))));
    } else if (tab === 'events') {
      const ev = detail.events || [];
      body.append(card(null, ev.length ? h('table', null, h('thead', null, h('tr', null, ['Time', 'Type', 'Severity', 'Action', 'Trust after'].map((x) => h('th', null, x)))),
        h('tbody', null, ev.map((e) => h('tr', { class: 'click', onclick: () => { location.hash = '#/threats/' + e.event_id; } }, h('td', null, fmt.time(e.ts)), h('td', null, fmt.type(e.event_type)), h('td', null, badge(e.severity)), h('td', null, e.action.replaceAll('_', ' ')), h('td', { class: 'num' }, fmt.n(e.trust_after)))))) : empty('No security events for this device.')));
    } else if (tab === 'commands') {
      body.append(commands(dd));
    }
    clear(panel, h('div', { class: 'card' }, head, tabs(), body));
  }
  function commands(dd) {
    const cmds = detail.commands || [];
    const origin = h('select', null, h('option', { value: '' }, 'Dashboard (admin)'), ...((last?.devices || []).filter((x) => x.id !== dd.id).map((x) => h('option', { value: x.id }, `Device: ${x.name}`))));
    const sel = h('select', null, cmds.map((c) => h('option', { value: c }, c)));
    const out = h('div');
    return h('div', { class: 'stack' }, h('div', { class: 'note' }, 'All device-to-device and dashboard commands pass through the gateway. Quarantined devices cannot send or receive commands; sensitive commands need a minimum origin trust. A quarantined lock is fail-secure: it keeps its state and local keypad/mechanical access still works.'),
      cmds.length ? h('div', { class: 'row' }, h('span', null, 'Send'), sel, h('span', null, 'from'), origin,
        h('button', { class: 'btn primary', onclick: async () => { try { const r = await api.post('/api/commands', { to: dd.id, command: sel.value, from_device: origin.value || null }); clear(out, h('div', { class: 'row' }, badge(r.allowed ? 'OK' : 'CRITICAL', r.allowed ? 'ALLOWED' : 'BLOCKED'), h('span', null, r.reason)), h('div', { class: 'small muted' }, 'Device state: ' + JSON.stringify(r.state))); } catch (e) { clear(out, e.message); } } }, 'Send command')) : empty('This device accepts no commands.'),
      h('div', { class: 'small muted' }, 'Current device state: ', h('code', null, JSON.stringify(dd.state || {}))), out);
  }

  function update(d) {
    last = d;
    if (!grid.childElementCount || Math.round(Date.now() / 1000) % 1 === 0) renderGrid();
    if (selected && (!detail || Date.now() - lastFetch > 4000)) load();
    else if (selected && detail && (tab === 'telemetry')) renderPanel();
  }
  renderPanel();
  return { update, destroy() {} };
}
