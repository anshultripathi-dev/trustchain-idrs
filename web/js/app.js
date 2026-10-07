import { h, clear, icon, badge, store, subscribe, connect, api, getToken, promptAdmin, toast } from './core.js';
import home from '../pages/home.js';
import overview from '../pages/overview.js';
import devices from '../pages/devices.js';
import ledger from '../pages/ledger.js';
import threats from '../pages/threats.js';
import ml from '../pages/ml.js';
import lab from '../pages/lab.js';
import response from '../pages/response.js';

const PAGES = [
  ['home', 'Smart Home', 'home', home], ['overview', 'Security Overview', 'shield', overview], ['devices', 'Devices & Trust', 'chip', devices], ['threats', 'Threats & Memory', 'alert', threats],
  ['ledger', 'Ledger', 'chain', ledger], ['response', 'Response & Recovery', 'siren', response], ['ml', 'ML Lab', 'brain', ml], ['lab', 'Attack Lab', 'flask', lab],
];
const nav = document.getElementById('nav'), page = document.getElementById('page');
document.getElementById('logo').append(icon('shield', 18));

let current = null, unsub = null;
const links = {};
for (const [id, label, ic] of PAGES) {
  const a = h('a', { href: `#/${id}` }, icon(ic, 18), h('span', null, label));
  links[id] = a; nav.append(a);
}
const quarBadge = h('span', { class: 'count', style: { display: 'none' } });
links.response.append(quarBadge);

function route() {
  const id = (location.hash.match(/^#\/(\w+)/) || [])[1] || 'home';
  const entry = PAGES.find((p) => p[0] === id) || PAGES[0];
  Object.entries(links).forEach(([k, a]) => a.classList.toggle('active', k === entry[0]));
  unsub?.(); current?.destroy?.(); tipHide();
  clear(page);
  const param = location.hash.split('/')[2];
  const root = h('div'); page.append(root);
  current = entry[3](root, { param, param2: location.hash.split('/')[3] });
  document.title = `${entry[1]} · TrustChain IDRS`;
  unsub = subscribe((d) => current.update?.(d));
}
function tipHide() { document.querySelector('.tip')?.style && (document.querySelector('.tip').style.display = 'none'); }
addEventListener('hashchange', route);

// topbar-ish status in the sidebar + quarantine counter
subscribe((d) => {
  const q = d.kpis.quarantined;
  quarBadge.style.display = q ? '' : 'none'; quarBadge.textContent = q;
  document.getElementById('conn').className = 'dot ' + (store.connected ? 'on' : 'off');
  document.getElementById('conn-t').textContent = `${d.mode.toUpperCase()} · sim ${d.sim.label}`;
});

// theme
const themeBtn = document.getElementById('theme');
const applyTheme = (t) => { if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme; themeBtn.replaceChildren(icon('sun', 14), (document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')) === 'dark' ? 'Light' : 'Dark'); };
let saved = new URLSearchParams(location.search).get('theme'); if (!saved) { try { saved = localStorage.getItem('tc_theme'); } catch { /* blocked */ } }
applyTheme(saved);
themeBtn.onclick = () => {
  const cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = cur === 'dark' ? 'light' : 'dark'; try { localStorage.setItem('tc_theme', next); } catch { /* blocked */ }
  applyTheme(next); route();
};
document.getElementById('admin').onclick = async () => { try { await promptAdmin(); toast('Admin session active', 'ok'); } catch { /* cancelled */ } };

connect();
route();
