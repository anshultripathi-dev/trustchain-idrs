import { h, clear, icon, badge, fmt, api, act } from '../js/core.js';
import { pageHeader, card, nodePanel, checkRow, empty } from '../js/shared.js';

const POLICY = [
  ['SAFE / LOW', 'Record event and continue normal operation', 'LOGGED'],
  ['SUSPICIOUS / MEDIUM', 'Record event and alert the user', 'ALERT_USER'],
  ['HIGH', 'Reduce trust, block the source at the gateway where supported, sound the alarm', 'BLOCK_SOURCE'],
  ['CRITICAL', 'Quarantine the device, block commands to/from it, activate local alarm', 'QUARANTINE_DEVICE'],
];

export default function response(root) {
  let last = null, results = {};
  const flow = h('div'), table = h('div'), nodeEl = h('div'), hw = h('div'), block = h('div');
  root.append(pageHeader('Response & recovery', 'Reversible, administrator-gated quarantine state machine spanning the network layer and the physical alarm.'),
    card('Quarantine state machine', flow),
    h('div', { class: 'grid g-main', style: { marginTop: '14px' } }, card('Recovery workflow', table), h('div', { class: 'stack' }, card('Physical node (ESP-2)', nodeEl), card('Gateway blocklist', block))),
    h('div', { class: 'grid g2', style: { marginTop: '14px' } },
      card('Response policy', h('table', null, h('thead', null, h('tr', null, ['Risk level', 'Response', 'Recorded action'].map((x) => h('th', null, x)))), h('tbody', null, POLICY.map(([a, b, c]) => h('tr', null, h('td', null, h('b', null, a)), h('td', null, b), h('td', { class: 'mono' }, c)))))),
      card('Hardware connection', hw)));
  load();
  async function load() {
    const r = await api.get('/api/hardware');
    clear(hw, h('div', { class: 'stack' }, h('div', { class: 'row' }, 'Mode: ', h('b', null, r.mode.toUpperCase())),
      h('div', { class: 'row' }, 'Response node: ', badge(r.response_node.reachable ? 'OK' : 'CRITICAL', `${r.response_node.kind} · ${r.response_node.reachable ? 'reachable' : 'unreachable'}`)),
      h('div', { class: 'row' }, 'Smart-home ESP32 #1: ', r.smart_home.configured ? badge(r.smart_home.connected ? 'OK' : 'CRITICAL', r.smart_home.connected ? `connected ${r.smart_home.ip}` : 'not responding') : h('span', { class: 'muted' }, 'simulated')),
      h('div', { class: 'note' }, 'Your existing firmware works unchanged: the engine polls ', h('code', null, 'GET /security/status'), ' on ESP32 #1 and drives ESP32 #2 via ', h('code', null, '/alert?type=…'), ', ', h('code', null, '/safe'), ' and ', h('code', null, '/status'), '. Set ', h('code', null, 'TRUSTCHAIN_MODE=hybrid'), ' and the two IPs in ', h('code', null, '.env'), '.'),
      h('div', { class: 'row' }, h('button', { class: 'btn sm', onclick: () => act('Test alert sent', () => api.post('/api/hardware/test', { action: 'alert' })) }, 'Test alarm'), h('button', { class: 'btn sm', onclick: () => act('Safe state sent', () => api.post('/api/hardware/test', { action: 'safe' })) }, 'Test safe'))));
  }
  async function check(id) {
    try { results[id] = await api.post(`/api/devices/${encodeURIComponent(id)}/recovery-check`, {}, { admin: true }); } catch (e) { import('../js/core.js').then((m) => m.toast(e.message, 'err')); return; }
    render();
  }
  async function approve(id) {
    const notes = prompt('Administrator notes for the audit trail (what was verified / remediated?)', 'Verified clean; credentials rotated.');
    if (notes == null) return;
    await act('Device restored — recorded on ledger', () => api.post(`/api/devices/${encodeURIComponent(id)}/approve`, { admin: 'admin', notes }, { admin: true })).catch(() => {});
    delete results[id];
  }
  function render() {
    if (!last) return;
    const all = [...last.devices, ...last.unknown_devices];
    const by = (s) => all.filter((d) => d.status === s);
    const col = (title, cls, list, desc) => h('div', { class: `state ${cls}` }, h('b', null, title), h('div', { class: 'small muted' }, desc), h('div', { style: { marginTop: '6px' } }, list.length ? list.map((d) => h('div', { class: 'small' }, '• ' + d.name)) : h('span', { class: 'faint small' }, '— none —')));
    clear(flow, h('div', { class: 'sm-flow' }, col('ACTIVE', 'act', by('ACTIVE'), 'trusted · normal operation'), h('span', null, '→ trust < 20 or CRITICAL →'),
      col('QUARANTINED', 'q', by('QUARANTINED'), 'commands blocked · alarm on'), h('span', null, '→ checks pass →'), col('RECOVERY PENDING', 'p', by('RECOVERY_PENDING'), 'awaiting admin approval'), h('span', null, '→ admin approves →'), h('span', { class: 'badge b-ACTIVE' }, icon('check'), 'ACTIVE (trust 60)')),
      h('div', { class: 'note', style: { marginTop: '12px' } }, 'No automatic exit: a quarantined device only returns after a security verification and an explicit, separately-logged administrator approval. Both steps are ledger transactions.'));
    const q = all.filter((d) => d.status !== 'ACTIVE');
    clear(table, q.length ? h('div', { class: 'stack' }, q.map((d) => {
      const r = results[d.id];
      return h('div', { class: 'card', style: { background: 'var(--surface-2)' } },
        h('div', { class: 'row spread' }, h('div', null, h('b', null, d.name), h('div', { class: 'small muted' }, d.quarantine ? `${d.quarantine.reason} · block #${d.quarantine.block}` : '')), badge(d.status)),
        d.unregistered ? h('div', { class: 'note warn', style: { margin: '8px 0' } }, 'Unregistered device. It cannot be restored until an administrator enrols its key on the ledger.') : null,
        d.status === 'QUARANTINED' && d.clean_streak != null && h('div', { style: { margin: '10px 0' } }, h('div', { class: 'small muted' }, `Clean observations ${Math.min(d.clean_streak, d.recovery_needed)}/${d.recovery_needed}`), h('div', { class: 'bar' }, h('i', { style: { width: Math.min(100, (d.clean_streak / d.recovery_needed) * 100) + '%' } }))),
        r && h('div', { class: 'stack', style: { gap: '6px', margin: '8px 0' } }, Object.entries(r.checks).map(([k, v]) => checkRow(v.ok, fmt.type(k), v.detail))),
        h('div', { class: 'row' }, !d.unregistered && d.status === 'QUARANTINED' && h('button', { class: 'btn primary sm', onclick: () => check(d.id) }, 'Run security verification'),
          d.status === 'RECOVERY_PENDING' && h('button', { class: 'btn primary sm', onclick: () => approve(d.id) }, icon('check', 13), 'Approve & restore')));
    })) : empty('No quarantined devices. Quarantine happens automatically at trust < 20 or CRITICAL risk, or manually from the Devices page.'));
    clear(nodeEl, nodePanel(last.physical));
    clear(block, last.blocklist.length ? h('table', null, h('thead', null, h('tr', null, h('th', null, 'Source'), h('th', null, 'Expires'))), h('tbody', null, last.blocklist.map((b) => h('tr', null, h('td', { class: 'mono' }, b.source), h('td', null, `${b.expires_in.toFixed(0)}s`))))) : empty('Nothing blocked.'));
  }
  return { update(d) { last = d; if (!root.querySelector('.btn:focus') && !document.querySelector('.modal-bg')) render(); }, destroy() {} };
}
