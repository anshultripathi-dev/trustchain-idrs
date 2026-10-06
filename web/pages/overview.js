import { h, clear, icon, badge, fmt, store, bandColor, seriesColor } from '../js/core.js';
import { LineChart } from '../js/charts.js';
import { pageHeader, card, kpi, feedItem, deviceCard, nodePanel, trustColor } from '../js/shared.js';

export default function overview(root) {
  const kpis = h('div', { class: 'grid kpis' });
  const chart = new LineChart({ height: 250, yMin: 0, yMax: 1, yFmt: (v) => v.toFixed(2), xFmt: (v) => fmt.time(v), label: 'Risk by device',
    bands: [{ from: 0.92, to: 1, color: 'var(--crit)' }, { from: 0.5, to: 0.92, color: 'var(--serious)' }, { from: 0.25, to: 0.5, color: 'var(--warn)' }],
    refs: [{ y: 0.25, label: 'suspicious' }, { y: 0.5, label: 'high' }, { y: 0.92, label: 'critical' }] });
  const legend = h('div', { class: 'legend' });
  const node = h('div'), devs = h('div', { class: 'grid g3' }), feed = h('div', { class: 'feed' }), flow = h('div', { class: 'flow' });
  const banner = h('div');
  root.append(pageHeader('Security overview', 'Live state of the closed loop: signed telemetry → detection → trust → ledger → response.'), banner, kpis,
    h('div', { class: 'grid g-main', style: { marginTop: '14px' } },
      card('Risk by device', h('div', null, chart.root, legend), h('span', { class: 'faint small' }, 'bounded 0–1 · last 90 s')),
      card('Physical response', node)),
    h('div', { style: { margin: '14px 0' } }, card('Closed-loop pipeline', flow)),
    h('div', { class: 'grid g-main' }, card('Devices', devs), card('Activity', feed)));

  function update(d) {
    const k = d.kpis;
    banner.replaceChildren();
    if (d.threat_level !== 'SAFE' || d.attacks.length) {
      banner.append(h('div', { class: 'note warn', style: { marginBottom: '14px' }, role: 'alert' }, icon('alert', 14), ' ', h('b', null, `Threat level ${d.threat_level}. `),
        d.attacks.length ? `${d.attacks.length} simulated attack(s) in progress. ` : '', k.quarantined ? `${k.quarantined} device(s) quarantined — see Response & Recovery.` : ''));
    }
    clear(kpis,
      kpi('Threat level', badge(d.threat_level), `${d.devices.filter((x) => x.status === 'ACTIVE').length} active · ${k.quarantined} quarantined`, 'shield'),
      kpi('Average trust', fmt.n(k.avg_trust, 0), 'across registered devices', 'check'),
      kpi('Security events', k.events, `${k.crypto_rejects} signature/replay rejects`, 'alert'),
      kpi('Ledger', `#${k.chain_height}`, h('span', { class: 'row' }, badge(k.ledger_consistent ? 'OK' : 'TAMPERING_DETECTED', k.ledger_consistent ? 'validators agree' : 'validators disagree')), 'chain'),
      kpi('Log integrity', badge(k.integrity_status === 'TAMPERING_DETECTED' ? 'TAMPERING_DETECTED' : 'OK', k.integrity_status === 'TAMPERING_DETECTED' ? 'tampering' : fmt.type(k.integrity_status || 'pending')), 'local log vs ledger hashes', 'db'));
    // chart
    const series = d.devices.map((dev, i) => ({ label: dev.name, color: seriesColor(i), points: dev.series.slice(-90).map((p) => ({ x: p.t, y: p.risk })) }));
    chart.setData(series);
    clear(legend, d.devices.map((dev, i) => h('span', null, h('i', { style: { background: seriesColor(i) } }), dev.name)));
    clear(node, nodePanel(d.physical),
      d.blocklist.length ? h('div', { class: 'small muted', style: { marginTop: '10px' } }, 'Gateway blocklist: ', d.blocklist.map((b) => b.source).join(', ')) : null);
    clear(devs, [...d.devices, ...d.unknown_devices.map((u) => ({ ...u, series: [], sample: {}, band: 'CRITICAL', risk: 0, primary_name: '' }))].map((dev) => deviceCard(dev, { onclick: () => { location.hash = '#/devices/' + encodeURIComponent(dev.id); } })));
    clear(feed, store.feed.slice(0, 40).map((f) => feedItem(f)), store.feed.length ? null : h('div', { class: 'empty' }, 'Quiet. Launch a scenario from the Attack Lab.'));
    // pipeline
    const hot = new Set(store.feed.filter((f) => d.now - f.ts < 6).map((f) => f.kind));
    const stage = (name, val, sub, on) => h('div', { class: `stage${on ? ' hot' : ''}` }, h('b', null, name), h('div', { class: 'v num' }, val), h('div', { class: 'small muted' }, sub));
    const arrow = () => h('div', { class: 'arrow', 'aria-hidden': 'true' }, '→');
    const nq = d.kpis.quarantined;
    clear(flow,
      stage('Signed devices', d.devices.length, 'ECDSA-P256 · nonce + timestamp', false), arrow(),
      stage('Gateway verify', k.messages, `${k.crypto_rejects} rejected · ${k.dropped_blocked} dropped`, hot.has('BLOCK')), arrow(),
      stage('Detection', 'rules + ML', 'adaptive baseline · IF · classifier', hot.has('EVENT')), arrow(),
      stage('Trust & risk', fmt.n(k.avg_trust, 0), 'avg trust · bounded risk', hot.has('EVENT')), arrow(),
      stage('Ledger', `#${k.chain_height}`, `${d.ledger.nodes.length} validators · quorum ${d.ledger.quorum}`, hot.has('INTEGRITY') || hot.has('EVENT')), arrow(),
      stage('Response', nq, nq ? 'quarantined' : 'none quarantined', hot.has('QUARANTINE') || hot.has('PHYSICAL')));
  }
  return { update, destroy() {} };
}
