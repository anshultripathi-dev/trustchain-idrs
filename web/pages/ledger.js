import { h, clear, icon, badge, fmt, api, act } from '../js/core.js';
import { pageHeader, card, tx, empty } from '../js/shared.js';

export default function ledger(root, { param }) {
  let nodeSel = null, sel = param != null && param !== '' ? Number(param) : null, blocks = [], filter = 'ALL', state = null, last = null, lastFetch = 0, height = -1;
  const nodesEl = h('div', { class: 'grid g3' }), chainEl = h('div', { class: 'chain', tabindex: 0 }), listEl = h('div'), detailEl = h('div'), stateEl = h('div');
  const filterSel = h('select', { onchange: (e) => { filter = e.target.value; renderList(); } }, ['ALL', 'ATTACK_EVENT', 'TRUST_UPDATE', 'QUARANTINE', 'RECOVERY_VERIFIED', 'RESTORE', 'INTEGRITY_ALERT', 'REGISTER_DEVICE'].map((t) => h('option', { value: t }, t === 'ALL' ? 'All transactions' : t.replaceAll('_', ' '))));
  root.append(pageHeader('Permissioned ledger', 'A SHA-256 hash-chain of signed blocks, replicated across validator nodes. Only hashes and metadata go on-chain — raw telemetry stays local.',
    h('button', { class: 'btn', onclick: async () => { const a = await api.get('/api/ledger/audit'); toastAudit(a); } }, icon('check', 14), 'Verify all nodes')),
    nodesEl, h('div', { style: { marginTop: '14px' } }, card('Latest blocks (hash-linked)', chainEl, h('span', { class: 'small faint' }, '← older · newer →'))), h('div', { style: { margin: '14px 0' } }, detailEl),
    card('Block log', listEl, filterSel), h('div', { style: { marginTop: '14px' } }, stateEl));

  function toastAudit(a) {
    const bad = a.nodes.filter((n) => n.online && (!n.valid || !n.matches_majority));
    import('../js/core.js').then(({ toast }) => toast(bad.length ? `Audit: ${bad.map((n) => n.node).join(', ')} failed verification` : 'Audit passed: all validators verify and agree', bad.length ? 'err' : 'ok'));
  }
  async function loadBlocks() {
    lastFetch = Date.now();
    const r = await api.get('/api/ledger/blocks?limit=60' + (nodeSel ? '&node=' + nodeSel : ''));
    blocks = r.blocks; height = r.height; renderChain(); renderList();
    if (!state) { state = await api.get('/api/ledger/state'); renderState(); }
    if (sel != null) showBlock(sel);
  }
  function renderChain() {
    const badIdx = new Set((last?.ledger.nodes.find((n) => n.node === (nodeSel || last.ledger.nodes[0].node)) || {}).first_bad_index != null ? [last.ledger.nodes.find((n) => n.node === (nodeSel || last.ledger.nodes[0].node)).first_bad_index] : []);
    const items = blocks.slice(0, 12).reverse();
    clear(chainEl, items.flatMap((b, i) => [i ? h('div', { class: 'link', 'aria-hidden': 'true' }) : null,
      h('div', { class: `blk${sel === b.index ? ' sel' : ''}${badIdx.has(b.index) ? ' bad' : ''}`, onclick: () => showBlock(b.index), tabindex: 0, onkeydown: (e) => e.key === 'Enter' && showBlock(b.index) },
        h('div', { class: 'row spread' }, h('span', { class: 'ix' }, '#' + b.index), tx(b.tx_type)), h('div', { class: 'hs mono' }, 'hash ' + fmt.hash(b.hash, 10)), h('div', { class: 'hs mono' }, 'prev ' + fmt.hash(b.prev_hash, 10)),
        h('div', { class: 'small muted' }, summary(b)), h('div', { class: 'hs' }, `${Object.keys(b.signatures).length} signatures · ${b.proposer}`))]));
    chainEl.scrollLeft = chainEl.scrollWidth;
  }
  function summary(b) {
    const p = b.payload;
    switch (b.tx_type) {
      case 'ATTACK_EVENT': return `${fmt.type(p.event_type)} · ${p.severity}`;
      case 'TRUST_UPDATE': return `${fmt.name(p.device_id)}: ${p.previous}→${p.trust}`;
      case 'REGISTER_DEVICE': return p.name; case 'QUARANTINE': return fmt.name(p.device_id);
      case 'RESTORE': return `${fmt.name(p.device_id)} by ${p.admin}`; case 'INTEGRITY_ALERT': return p.kind;
      case 'GENESIS': return 'validators + policy'; default: return '';
    }
  }
  function renderList() {
    const rows = blocks.filter((b) => filter === 'ALL' || b.tx_type === filter);
    clear(listEl, rows.length ? h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['Block', 'Time', 'Transaction', 'Summary', 'Hash', 'Proposer'].map((x) => h('th', null, x)))),
      h('tbody', null, rows.slice(0, 40).map((b) => h('tr', { class: 'click', onclick: () => showBlock(b.index) }, h('td', { class: 'num' }, '#' + b.index), h('td', null, fmt.time(b.timestamp)), h('td', null, tx(b.tx_type)), h('td', null, summary(b)), h('td', { class: 'mono' }, fmt.hash(b.hash, 12)), h('td', null, b.proposer)))))) : empty('No blocks match.'));
  }
  async function showBlock(i) {
    sel = i; renderChain();
    let r; try { r = await api.get('/api/ledger/blocks/' + i); } catch { return; }
    const b = r.block;
    clear(detailEl, card(`Block #${b.index}`, h('div', { class: 'grid g2' },
      h('div', { class: 'stack' }, h('div', { class: 'row' }, tx(b.tx_type), h('span', { class: 'muted' }, fmt.dt(b.timestamp)), badge(r.nodes_agree ? 'OK' : 'CRITICAL', r.nodes_agree ? 'all nodes agree' : 'NODES DISAGREE')),
        h('div', null, h('div', { class: 'faint small' }, 'Hash (SHA-256 of header)'), h('code', { style: { wordBreak: 'break-all' } }, b.hash)),
        h('div', null, h('div', { class: 'faint small' }, 'Previous hash'), h('code', { style: { wordBreak: 'break-all' } }, b.prev_hash)),
        h('table', null, h('thead', null, h('tr', null, ['Validator', 'Block hash', 'Recomputed', 'Signature'].map((x) => h('th', null, x)))), h('tbody', null, Object.entries(r.per_node).map(([n, hs]) => h('tr', null, h('td', null, n), h('td', { class: 'mono' }, fmt.hash(hs, 10)), h('td', null, badge(r.recomputed_ok[n] ? 'OK' : 'CRITICAL', r.recomputed_ok[n] ? 'match' : 'tampered')), h('td', null, b.signatures[n] ? h('span', { class: 'mono' }, fmt.hash(b.signatures[n], 10)) : '–')))))),
      h('div', null, h('div', { class: 'faint small' }, 'Payload'), h('pre', { class: 'json' }, JSON.stringify(b.payload, null, 2)))), h('button', { class: 'btn sm', onclick: () => { sel = null; clear(detailEl); renderChain(); } }, 'Close')));
    detailEl.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
  function renderNodes() {
    if (!last) return;
    const net = last.ledger;
    clear(nodesEl, net.nodes.map((n) => {
      const ok = n.valid && n.matches_majority;
      return h('div', { class: 'card', style: ok ? {} : { borderColor: 'var(--crit)' } },
        h('div', { class: 'row spread' }, h('h2', null, n.node), badge(!n.online ? 'NOT_ON_CHAIN' : ok ? 'OK' : 'TAMPERING_DETECTED', !n.online ? 'offline' : ok ? 'verified' : 'FAILED AUDIT')),
        h('div', { class: 'small muted', style: { margin: '8px 0' } }, `height ${n.height} · head ${fmt.hash(n.head_hash, 10)}`),
        !ok && n.online && h('div', { class: 'small', style: { color: 'var(--crit)' } }, n.first_bad_index != null ? `First invalid block: #${n.first_bad_index}` : `Diverges from majority${n.diverges_at != null ? ' at #' + n.diverges_at : ''}`),
        h('div', { class: 'row', style: { marginTop: '8px' } },
          h('button', { class: 'btn sm', onclick: () => { nodeSel = n.node; loadBlocks(); } }, 'View copy'),
          !ok && n.online && h('button', { class: 'btn sm primary', onclick: () => act(`${n.node} repaired from majority`, () => api.post(`/api/ledger/heal/${n.node}`)).then(() => { state = null; loadBlocks(); }) }, 'Heal'),
          h('button', { class: 'btn sm', title: 'Simulation: take validator offline/online', onclick: () => api.post(`/api/ledger/node/${n.node}/online`, { online: !n.online }).catch((e) => import('../js/core.js').then((m) => m.toast(e.message, 'err'))) }, n.online ? 'Take offline' : 'Bring online')));
    }), h('div', { class: 'note', style: { gridColumn: '1/-1' } }, `Consensus: round-robin proof-of-authority — the proposer signs, validators endorse, ${net.quorum} of ${net.nodes.length} signatures commit a block. An attacker editing one copy breaks its hashes and signatures and is outvoted by the others.`));
  }
  function renderState() {
    if (!state) return;
    const s = state.stats;
    clear(stateEl, h('div', { class: 'grid g2' },
      card('Smart-contract device registry (derived by replaying the chain)', h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['Device', 'Status', 'Trust', 'Reg. block'].map((x) => h('th', null, x)))), h('tbody', null, state.registry.map((d) => h('tr', null, h('td', null, d.name, h('div', { class: 'small faint mono' }, fmt.name(d.device_id))), h('td', null, badge(d.status)), h('td', { class: 'num' }, fmt.n(d.trust, 0)), h('td', null, d.registered_block != null ? '#' + d.registered_block : 'unregistered'))))))),
      card('Contract policy & statistics', h('div', { class: 'stack' }, h('div', null, h('div', { class: 'faint small' }, 'Policy'), h('pre', { class: 'json' }, JSON.stringify(s.policy, null, 2))), h('div', null, h('div', { class: 'faint small' }, 'Transactions by type'), h('div', { class: 'row' }, Object.entries(s.tx_counts).map(([k, v]) => h('span', { class: 'row', style: { gap: '4px' } }, tx(k), h('b', null, v)))))))));
  }
  function update(d) {
    last = d; renderNodes();
    if (d.kpis.chain_height !== height || Date.now() - lastFetch > 10000) { state = height === d.kpis.chain_height ? state : null; loadBlocks(); }
  }
  loadBlocks();
  return { update, destroy() {} };
}
