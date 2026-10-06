import { h, icon, badge, fmt, bandColor } from './core.js';
import { sparkline, ring } from './charts.js';

export const pageHeader = (title, desc, ...actions) => h('div', { class: 'top' }, h('div', { class: 'grow' }, h('h1', null, title), desc && h('p', null, desc)), ...actions);
export const card = (title, body, right, cls = '') => h('section', { class: `card ${cls}` }, (title || right) && h('div', { class: 'hd' }, title ? h('h2', null, title) : h('span'), right), body);
export const kpi = (label, value, sub, ic) => h('div', { class: 'card kpi' }, h('div', { class: 'label' }, ic && icon(ic, 14), label), h('div', { class: 'value num' }, value), sub && h('div', { class: 'sub' }, sub));
export const empty = (msg) => h('div', { class: 'empty' }, msg);

const KIND_ICON = { EVENT: 'alert', QUARANTINE: 'lock', BLOCK: 'shield', ATTACK: 'bolt', PHYSICAL: 'siren', INTEGRITY: 'chain', TAMPER: 'x', RECOVERY: 'check', RESTORE: 'check', COMMAND: 'chip', SYSTEM: 'info' };
export function feedItem(f, now) {
  const sev = f.data?.severity;
  return h('div', { class: `it k-${f.kind}` }, icon(KIND_ICON[f.kind] || 'info'),
    h('div', null, h('div', null, h('b', null, f.kind.toLowerCase()), ' · ', f.msg), sev && h('div', { class: 'row', style: { marginTop: '3px' } }, badge(sev), f.data.action && h('span', { class: 'badge' }, f.data.action.replaceAll('_', ' ')), f.data.repeat_count > 0 && h('span', { class: 'badge' }, `repeat ×${f.data.repeat_count}`))),
    h('time', null, fmt.time(f.ts)));
}

export function trustColor(t) { return t >= 70 ? 'var(--good)' : t >= 40 ? 'var(--warn)' : 'var(--crit)'; }

export function deviceCard(d, { selected, onclick } = {}) {
  const q = d.status !== 'ACTIVE';
  const risk = d.series.map((p) => p.risk);
  return h('div', { class: `card dev${selected ? ' sel' : ''}${q ? ' q' : ''}`, onclick, tabindex: 0, role: 'button', onkeydown: (e) => { if (e.key === 'Enter') onclick?.(); } },
    h('div', { class: 'row spread' }, h('div', null, h('div', { class: 'nm' }, d.name), h('div', { class: 'id mono' }, fmt.name(d.id))), ring(d.trust, { color: trustColor(d.trust), label: 'trust' })),
    h('div', { class: 'row' }, badge(d.status), badge(d.band, `risk ${d.band}`), d.real_hardware && h('span', { class: 'badge' }, 'real ESP32'), d.ml_mode === 'shadow' && h('span', { class: 'badge', title: 'Models were trained on simulated devices. On real hardware the ML layer only observes; rules raise events.' }, 'ML: shadow'), d.attack && h('span', { class: 'badge b-HIGH' }, icon('bolt'), 'under attack')),
    h('div', { class: 'metrics' },
      h('div', null, h('b', { class: 'num' }, fmt.n(d.sample?.req_rate)), h('span', null, 'req/s')),
      h('div', null, h('b', { class: 'num' }, fmt.n(d.sample?.primary)), h('span', null, d.primary_name)),
      h('div', null, h('b', { class: 'num' }, fmt.n(d.risk, 2)), h('span', null, 'risk'))),
    h('div', { class: 'row spread small faint' }, h('span', null, 'risk · last 60s'), sparkline(risk, { w: 150, min: 0, max: 1, color: bandColor[d.band] })));
}

export function nodePanel(p) {
  const s = p || {};
  return h('div', { class: 'node' },
    h('div', { class: 'row spread small' }, h('b', null, 'ESP-2 · Hardware security node'), h('span', null, `${s.kind || 'simulated'} · ${s.reachable ? 'reachable' : 'UNREACHABLE'}`)),
    h('div', { class: 'lcd', 'aria-label': 'LCD display' }, (s.lcd || ['', '']).map((l) => h('div', null, l || ' '))),
    h('div', { class: 'led-row' },
      h('span', null, h('i', { class: `led green${s.green_led ? ' on' : ''}` }), 'SAFE'),
      h('span', null, h('i', { class: `led red${s.red_led ? ' on' : ''}` }), 'ALERT'),
      h('span', { class: `buzz${s.buzzer ? ' on' : ''}` }, s.buzzer ? '🔔 BUZZER ON' : 'buzzer off')),
    h('div', { class: 'small', style: { color: '#9aa39a' } }, s.mode === 'ALERT' ? `Alarm state: ${s.type || 'ALERT'}` : 'Idle — no active high-risk condition'));
}

export const checkRow = (ok, label, detail) => h('div', { class: 'row', style: { alignItems: 'flex-start' } }, badge(ok ? 'OK' : 'CRITICAL', ok ? 'pass' : 'fail'), h('div', null, h('b', null, label), h('div', { class: 'small muted' }, detail)));
export const tx = (t) => h('span', { class: `tx ${t}` }, t.replaceAll('_', ' '));
