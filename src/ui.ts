/**
 * ui.ts — the interactive lab.
 *
 * The one core interaction: pick a protocol, press Run, and watch the *real*
 * bounded search either return an attack trace or exhaust the space. Toggling
 * the one-field fix re-runs the identical search — the learner causes the
 * transition between "attack found" and "secure in bound" against the genuine
 * engine, never a canned animation.
 */

import { runSearch, SearchResult, TraceStep } from './symbolic/search.ts';
import { protocolById, Protocol } from './symbolic/protocol.ts';
import { analyse, RULE_TEXT, Fact } from './symbolic/intruder.ts';
import { explainRepair } from './symbolic/explain.ts';
import { canon, pretty } from './symbolic/terms.ts';

const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

interface LibEntry {
  key: string;
  label: string;
  spec: string;
  base: string; //  protocol id when the fix is OFF
  fixed?: string; //  protocol id when the fix is ON
  fix?: { title: string; sub: string };
  link?: { href: string; note: string };
  blurb: string;
}

const SIBLING = (slug: string) => `https://systemslibrarian.github.io/crypto-lab-${slug}/`;

const LIBRARY: LibEntry[] = [
  {
    key: 'ns',
    label: 'Needham-Schroeder (public key)',
    spec: 'NSPK 1978 · Lowe 1995',
    base: 'ns-pk',
    fixed: 'ns-lowe',
    fix: {
      title: "Message 2 includes the responder's identity B",
      sub: "Lowe's 1995 fix. One field. Tick it and re-run the identical search.",
    },
    blurb:
      'The famous one. A mutual-authentication handshake whose flaw hid in plain sight for seventeen years.',
  },
  {
    key: 'dh',
    label: 'Diffie-Hellman key exchange',
    spec: 'unauthenticated · signed',
    base: 'dh-naive',
    fixed: 'dh-signed',
    fix: {
      title: 'Sign each Diffie-Hellman share',
      sub: 'Bind every public share to its sender with a signature the attacker cannot forge.',
    },
    blurb:
      'You broke this by hand in the diffie-hellman-mitm lab. Here a machine finds the man in the middle by searching.',
  },
  {
    key: 'kerberos',
    label: 'Kerberos (toy exchange)',
    spec: 'ticket handshake',
    base: '',
    link: {
      href: SIBLING('kerberos'),
      note: 'A Lowe-style reflection on a Kerberos-shaped exchange is built by hand as a panel in the Kerberos lab. Rather than rebuild it here, this entry links to the sibling demo.',
    },
    blurb: 'A ticket-granting exchange. The adjacent attack already lives in the Kerberos lab.',
  },
];

// Abstract protocol schema for display (the roles' messages, not the concrete
// attack scenario). `changed` marks the message the fix rewrites.
const SCHEMA: Record<string, { text: string; changed?: boolean }[]> = {
  'ns-pk': [
    { text: 'A → B : {Na, A}_pkB' },
    { text: 'B → A : {Na, Nb}_pkA', changed: true },
    { text: 'A → B : {Nb}_pkB' },
  ],
  'ns-lowe': [
    { text: 'A → B : {Na, A}_pkB' },
    { text: 'B → A : {Na, Nb, B}_pkA', changed: true },
    { text: 'A → B : {Nb}_pkB' },
  ],
  'dh-naive': [
    { text: 'A → B : g^a' },
    { text: 'B → A : g^b' },
    { text: 'A → B : {secret}_K   where K = (g^b)^a', changed: true },
  ],
  'dh-signed': [
    { text: 'A → B : g^a, [g^a]_skA', changed: true },
    { text: 'B → A : g^b, [g^b]_skB', changed: true },
    { text: 'A → B : {secret}_K   where K = (g^b)^a' },
  ],
};

interface State {
  entryKey: string;
  fixOn: boolean;
  result: SearchResult | null;
  step: number; //  -1 = before any message; else index into trace
}

const state: State = { entryKey: 'ns', fixOn: false, result: null, step: -1 };

function currentEntry(): LibEntry {
  return LIBRARY.find((e) => e.key === state.entryKey)!;
}

function currentProtocolId(): string {
  const e = currentEntry();
  return state.fixOn && e.fixed ? e.fixed : e.base;
}

// ---- DOM helpers ----------------------------------------------------------

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, val] of Object.entries(attrs)) {
    if (k === 'class') node.className = val;
    else node.setAttribute(k, val);
  }
  for (const c of children) node.append(typeof c === 'string' ? document.createTextNode(c) : c);
  return node;
}

// ---- top-level mount ------------------------------------------------------

export function mountApp(root: HTMLElement): void {
  root.innerHTML = '';
  const shell = el('div', { class: 'page-shell' });

  shell.append(hero());
  shell.append(honestyPanel());
  shell.append(introCard());
  shell.append(labCard());
  shell.append(libraryCard());
  shell.append(scopeCard());

  root.append(shell);
  render();
}

function hero(): HTMLElement {
  const header = el('header', { class: 'cl-hero' });
  const main = el('div', { class: 'cl-hero-main' }, [
    el('h1', { class: 'cl-hero-title' }, ['Protocol Checker']),
    el('p', { class: 'cl-hero-sub' }, ['Dolev-Yao symbolic analysis · automated attack discovery']),
    el('p', { class: 'cl-hero-desc' }, [
      'Hand a protocol you believe is correct to a symbolic model checker and watch it return the exact message sequence that breaks it — by searching, not by being told.',
    ]),
  ]);
  const why = el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
    el('span', { class: 'cl-hero-why-label' }, ['WHY IT MATTERS']),
    el('p', { class: 'cl-hero-why-text' }, [
      'You can only test a protocol against the attacks you thought of. Symbolic analysis searches the ones you did not — which is how Lowe found the Needham-Schroeder flaw in 1995, seventeen years after everyone had read it.',
    ]),
  ]);
  header.append(main, why);
  return header;
}

function honestyPanel(): HTMLElement {
  const panel = el('aside', { class: 'honesty', 'aria-label': 'Model assumptions and blind spot' });
  panel.append(
    el('h2', {}, ['This checker assumes perfect cryptography']),
    el('p', {}, [
      'Encryption is an opaque black box: no key recovery, no algebraic properties, no side channels, no timing, no implementation bugs. So “no attack found” means only “no attack in this model, within this bound.” Every attack in the fleet below is one this tool structurally cannot see — the tool’s blind spot is the rest of the site.',
    ]),
  );
  const list = el('ul', { class: 'blindspots' });
  for (const [slug, label] of [
    ['timing-oracle', 'timing-oracle'],
    ['power-trace', 'power-trace'],
    ['kem-trap', 'kem-trap'],
    ['padding-oracle', 'padding-oracle'],
  ] as const) {
    list.append(el('li', {}, [el('a', { href: SIBLING(slug) }, [label])]));
  }
  panel.append(list);
  return panel;
}

function introCard(): HTMLElement {
  const card = el('section', { class: 'card' });
  card.append(
    el('p', { class: 'kicker' }, ['What is this']),
    el('h2', {}, ['The attacker owns the network']),
    el('p', { class: 'lede' }, [
      'Model the attacker as someone who controls every wire: they intercept every message, and they can send any message they can assemble from what they have seen. They cannot break cryptography — they cannot guess a nonce or open a ciphertext addressed to someone else — but they can forward, split apart, and re-encrypt.',
    ]),
    el('p', {}, [
      'A protocol is “secure” only if, across every interleaving of sessions and every message the attacker can compose, no secret ever reaches them. That is far too many cases to check by hand. So we let a machine enumerate them. Below, the search is real — it finds the attack by exploring states, and every fact it learns is justified by a named rule you can audit.',
    ]),
  );
  return card;
}

// ---- the lab --------------------------------------------------------------

function labCard(): HTMLElement {
  const card = el('section', { class: 'card', id: 'lab' });
  card.append(el('p', { class: 'kicker' }, ['The checker']), el('h2', {}, ['Run the search']));

  // protocol picker
  const select = el('select', { id: 'proto-select', 'aria-label': 'Choose a protocol' });
  for (const e of LIBRARY) {
    select.append(el('option', { value: e.key }, [`${e.label} — ${e.spec}`]));
  }
  select.value = state.entryKey;
  select.addEventListener('change', () => {
    state.entryKey = (select as HTMLSelectElement).value;
    state.fixOn = false;
    state.result = null;
    state.step = -1;
    render();
  });

  const controls = el('div', { class: 'controls' }, [
    el('div', { class: 'field' }, [el('label', { for: 'proto-select' }, ['Protocol']), select]),
    runButton(),
  ]);
  card.append(controls);

  // dynamic body (schema, fix toggle, verdicts, workbench) rendered by render()
  card.append(el('div', { id: 'lab-body' }));
  return card;
}

function runButton(): HTMLElement {
  const btn = el('button', { class: 'btn', id: 'run-btn', type: 'button' }, ['▶ Run search']);
  btn.addEventListener('click', runCurrent);
  return btn;
}

function scenarioAndGoal(proto: Protocol): HTMLElement {
  return el('p', { class: 'scenario-note' }, [
    el('strong', {}, ['Scenario: ']),
    proto.scenario,
    ' ',
    el('strong', {}, ['Goal: ']),
    `does the attacker learn ${pretty(proto.goal)}? (${proto.goalDesc})`,
  ]);
}

// ---- the run --------------------------------------------------------------

let animHandle = 0;

function runCurrent(): void {
  const entry = currentEntry();
  if (entry.link) return; //  Kerberos: link-only, nothing to run
  const proto = protocolById(currentProtocolId());
  const result = runSearch(proto);
  state.result = result;
  state.step = -1;
  render();
  animateSearch(result);
}

// Visualise the (real) search: tick the explored-state counter up to its true
// value, then reveal the verdict + trace. Motion is tied to the action, not idle.
function animateSearch(result: SearchResult): void {
  const statusEl = document.getElementById('search-status');
  const numEl = statusEl?.querySelector('.stat-num') as HTMLElement | null;
  if (!statusEl || !numEl) return;
  window.clearInterval(animHandle);

  if (prefersReduced) {
    numEl.textContent = result.statesExplored.toLocaleString();
    revealAfterSearch(result);
    return;
  }

  const target = result.statesExplored;
  const start = performance.now();
  const dur = 750;
  animHandle = window.setInterval(() => {
    const t = Math.min(1, (performance.now() - start) / dur);
    numEl.textContent = Math.round(target * t).toLocaleString();
    if (t >= 1) {
      window.clearInterval(animHandle);
      revealAfterSearch(result);
    }
  }, 16);
}

function revealAfterSearch(result: SearchResult): void {
  // Step to the end so the full trace + final knowledge are shown.
  state.step = result.trace.length - 1;
  render();
}

// ---- render ---------------------------------------------------------------

function render(): void {
  const body = document.getElementById('lab-body');
  if (!body) return;
  body.innerHTML = '';
  const entry = currentEntry();

  // sync select + run button
  const select = document.getElementById('proto-select') as HTMLSelectElement | null;
  if (select) select.value = state.entryKey;
  const runBtn = document.getElementById('run-btn') as HTMLButtonElement | null;
  if (runBtn) runBtn.disabled = !!entry.link;

  if (entry.link) {
    body.append(linkOnlyBody(entry));
    refreshLibraryChips();
    return;
  }

  const proto = protocolById(currentProtocolId());

  // schema + fix toggle
  body.append(el('h3', {}, [`Protocol under test: ${proto.title}`]));
  body.append(schemaList(proto.id));
  body.append(scenarioAndGoal(proto));
  if (entry.fix && entry.fixed) body.append(fixToggle(entry));

  // verdicts (two independent indicators) — always present, idle before a run
  body.append(verdictPanel(proto));

  // the man-in-the-middle diagram — the headline "show", synced to the stepper
  if (state.result && state.result.found) body.append(ladderPanel(state.result, proto));

  // for a secure verdict on a repaired protocol: the engine-DERIVED reason
  if (state.result && !state.result.found) {
    const rp = repairPanel(entry);
    if (rp) body.append(rp);
  }

  // search status + workbench (only meaningful after a run)
  body.append(searchStatus());
  if (state.result) body.append(workbench());
  body.append(expertDetails());

  refreshLibraryChips();
}

function schemaList(protoId: string): HTMLElement {
  const ul = el('ul', { class: 'schema', 'aria-label': 'Protocol messages' });
  SCHEMA[protoId].forEach((m, i) => {
    const li = el('li', { class: m.changed ? 'changed' : '' });
    li.append(el('span', { class: 'num' }, [`${i + 1}.`]));
    const line = el('span', {}, [m.text]);
    if (m.changed) line.append(el('span', { class: 'tag' }, ['this message']));
    li.append(line);
    ul.append(li);
  });
  return ul;
}

function fixToggle(entry: LibEntry): HTMLElement {
  const wrap = el('div', { class: 'edit-toggle' });
  const cb = el('input', { type: 'checkbox', id: 'fix-toggle' }) as HTMLInputElement;
  cb.checked = state.fixOn;
  cb.addEventListener('change', () => {
    state.fixOn = cb.checked;
    state.result = null;
    state.step = -1;
    render();
  });
  const label = el('label', { for: 'fix-toggle' }, [
    el('span', { class: 'edit-title' }, [entry.fix!.title]),
    el('span', { class: 'edit-sub' }, [entry.fix!.sub]),
  ]);
  wrap.append(cb, label);
  return wrap;
}

function verdictPanel(proto: Protocol): HTMLElement {
  const wrap = el('div', { class: 'verdicts' });
  const r = state.result;

  // Indicator 1 — the cryptographic primitive. In this model it is ALWAYS
  // perfect: nothing here ever breaks encryption. This is deliberately NOT the
  // security verdict, and its colour never turns green-for-safe or red-for-bad.
  const crypto = el('div', { class: 'indicator indicator--crypto' });
  crypto.append(
    el('span', { class: 'ind-label' }, ['Cryptographic primitive']),
    el('div', { class: 'ind-value' }, [
      el('span', { class: 'ind-icon', 'aria-hidden': 'true' }, ['🔒']),
      el('span', {}, ['Perfect — unbroken']),
    ]),
    el('p', { class: 'ind-note' }, [
      'Encryption stayed opaque the entire run. No key was recovered. Whatever the verdict, the maths held.',
    ]),
  );

  // Indicator 2 — the security verdict. Colour tracks SYSTEM INTEGRITY: an
  // attack found renders as ALARM even though "the crypto never broke" is true.
  let cls = 'indicator indicator--idle';
  let icon = '·';
  let text = 'Not run yet';
  let note = 'Press Run to search this protocol for an attack.';
  if (r) {
    if (r.found) {
      cls = 'indicator indicator--alarm';
      icon = '✗';
      text = 'ATTACK FOUND';
      note = `The attacker reaches the goal: ${proto.goalDesc}. The protocol logic — not the cipher — leaks it.`;
    } else {
      cls = 'indicator indicator--ok';
      icon = '✓';
      const entry = currentEntry();
      const hasDerived = entry.fixed && state.fixOn && !!explainRepair(protocolById(entry.base), protocolById(entry.fixed));
      const reason = hasDerived ? 'The engine derives exactly why below. ' : proto.secureReason ? `${proto.secureReason} ` : '';
      note = `${reason}No attack in this model within ${r.statesExplored.toLocaleString()} states${
        r.boundHit ? ' (state cap reached)' : ' (space fully exhausted)'
      } — not a proof of security.`;
      text = 'No attack in bound';
    }
  }
  const verdict = el('div', { class: cls });
  verdict.append(
    el('span', { class: 'ind-label' }, ['Security verdict']),
    el('div', { class: 'ind-value' }, [
      el('span', { class: 'ind-icon', 'aria-hidden': 'true' }, [icon]),
      el('span', {}, [text]),
    ]),
    el('p', { class: 'ind-note' }, [note]),
  );

  wrap.append(crypto, verdict);
  return wrap;
}

function searchStatus(): HTMLElement {
  const r = state.result;
  const box = el('div', {
    class: 'search-status',
    id: 'search-status',
    role: 'status',
    'aria-live': 'polite',
  });
  if (!r) {
    box.append('Idle. The search explores interleaved sessions and every message the attacker can compose.');
    return box;
  }
  box.append(
    'Explored ',
    el('span', { class: 'stat-num' }, [r.statesExplored.toLocaleString()]),
    ` reachable states — weighing `,
    el('span', { class: 'stat-num' }, [r.injectionsTried.toLocaleString()]),
    ` candidate attacker injections down to depth `,
    el('span', { class: 'stat-num' }, [String(r.searchDepth)]),
    ` (bound: ${r.bound.toLocaleString()} states). `,
    r.found
      ? 'One interleaving reached a state where the attacker knows the goal — nobody described this attack to the search; it was found by enumeration.'
      : r.boundHit
        ? 'Hit the state cap before finding an attack.'
        : 'The frontier emptied with no attack reachable in this bound.',
  );
  return box;
}

// ---- workbench: trace stepper + attacker knowledge ------------------------

function workbench(): HTMLElement {
  const r = state.result!;
  const wrap = el('div', { class: 'workbench' });
  wrap.append(tracePanel(r), knowledgePanel(r));
  return wrap;
}

// ---- the man-in-the-middle diagram ---------------------------------------

// Three lanes: honest initiator (left) · attacker (middle) · honest responder
// (right). Each message is drawn between its two lanes, tinted by which of the
// attacker's TWO sessions it belongs to — making visible that M runs two
// sessions and bridges them. Synced to the trace stepper.
function ladderPanel(r: SearchResult, proto: Protocol): HTMLElement {
  const initiator = proto.instances[0];
  const responder = proto.instances[1];
  const lanes = [initiator.actor, proto.attacker, responder?.actor ?? '·'];
  const laneIdx = (n: string) => Math.max(0, lanes.indexOf(n));
  // Only actors that actually send/receive in this trace get a belief badge.
  const participants = new Set(r.trace.flatMap((s) => [s.from, s.to]));
  const belief = (inst: { actor: string; peer?: string } | undefined) =>
    inst && participants.has(inst.actor) ? beliefFor(inst, proto) : null;

  const panel = el('section', { class: 'card ladder-card' });
  panel.append(
    el('p', { class: 'kicker' }, ['The attack, as two sessions']),
    el('h3', {}, ['One attacker, two conversations']),
    el('p', {}, [
      `Every message crosses ${proto.attacker}. Read the two tinted columns as two separate sessions ${proto.attacker} runs at once — and watch it forward between them. Step the trace to advance.`,
    ]),
  );

  const grid = el('div', { class: 'ladder', role: 'group', 'aria-label': 'Man-in-the-middle message sequence' });

  // lane headers with belief badges
  const head = el('div', { class: 'ladder-head' });
  head.append(
    laneHead(initiator.actor, 'honest initiator', belief(initiator)),
    laneHead(proto.attacker, 'attacker · the man in the middle', null),
    responder
      ? laneHead(responder.actor, participants.has(responder.actor) ? 'honest responder' : 'responder · did not run', belief(responder))
      : el('div', { class: 'lane-head lane-empty' }, ['—']),
  );
  grid.append(head);

  const rows = el('ol', { class: 'ladder-rows' });
  r.trace.forEach((s, i) => {
    const from = laneIdx(s.from);
    const to = laneIdx(s.to);
    const lo = Math.min(from, to);
    const hi = Math.max(from, to);
    const rightSession = lo >= 1; //  message lives in the M↔responder session
    const shown = i <= state.step;
    const rung = el('li', {
      class: ['rung', rightSession ? 'rung-right' : 'rung-left', shown ? 'shown' : '', i === state.step ? 'current' : '']
        .join(' ')
        .trim(),
    });
    const bar = el('div', {
      class: `rung-bar ${to > from ? 'to-right' : 'to-left'}`,
      style: `grid-column:${lo + 1} / ${hi + 2};`,
    });
    bar.append(
      el('span', { class: 'rung-endpoints' }, [`${s.from} → ${s.to}`]),
      el('span', { class: 'rung-msg mono' }, [s.msgText]),
    );
    rung.append(bar);
    rows.append(rung);
  });
  grid.append(rows);
  panel.append(grid);

  // the deception, stated once, in alarm tone
  const deceived = [initiator, responder].filter((inst) => belief(inst)?.deceived);
  if (deceived.length) {
    const d = deceived[0]!;
    panel.append(
      el('p', { class: 'deception' }, [
        el('strong', {}, ['The deception: ']),
        `${d.actor} believes it is talking to ${d.peer}. It is talking to ${proto.attacker} — who never had to break a single cipher.`,
      ]),
    );
  }
  return panel;
}

interface Belief {
  peer: string;
  deceived: boolean;
  attacker: string;
}

function beliefFor(inst: { peer?: string } | undefined, proto: Protocol): Belief | null {
  if (!inst?.peer) return null;
  return { peer: inst.peer, deceived: inst.peer !== proto.attacker, attacker: proto.attacker };
}

function laneHead(actor: string, role: string, belief: Belief | null): HTMLElement {
  const cls = belief?.deceived ? 'lane-head lane-deceived' : 'lane-head';
  const head = el('div', { class: cls });
  head.append(el('span', { class: 'lane-name' }, [actor]), el('span', { class: 'lane-role' }, [role]));
  if (belief) {
    head.append(
      el('span', { class: 'lane-belief' }, [
        belief.deceived ? `believes peer = ${belief.peer}` : `peer = ${belief.peer}`,
      ]),
    );
    if (belief.deceived) head.append(el('span', { class: 'lane-belief lane-belief-real' }, [`actually ${belief.attacker}`]));
  }
  return head;
}

// ---- derived "why the repair holds" -------------------------------------

function repairPanel(entry: LibEntry): HTMLElement | null {
  if (!entry.fixed || !state.fixOn) return null;
  const d = explainRepair(protocolById(entry.base), protocolById(entry.fixed));
  if (!d) return null;

  const panel = el('section', { class: 'card repair-card' });
  panel.append(
    el('p', { class: 'kicker' }, ['Why the repair holds — derived, not asserted']),
    el('h3', {}, ['The engine shows its work']),
    el('p', {}, [
      'The secure verdict is not editorial. The same primitives that find attacks (unification, the attacker’s synthesis rules) locate the exact point the relay breaks:',
    ]),
  );

  const steps = el('ol', { class: 'repair-steps' });
  steps.append(
    el('li', {}, [
      el('span', { class: 'repair-lead' }, [`${d.pivotActor} now checks message 2 against `]),
      el('code', { class: 'mono' }, [d.pivotPattern]),
      '.',
    ]),
    el('li', {}, [
      'The reply the attacker can relay from the responder is ',
      el('code', { class: 'mono' }, [d.honestReply]),
      '.',
    ]),
  );
  if (d.relayConflict) {
    steps.append(
      el('li', { class: 'repair-block' }, [
        'These no longer unify: the pattern requires ',
        el('code', { class: 'mono' }, [d.relayConflict.expected]),
        ' where the reply carries ',
        el('code', { class: 'mono' }, [d.relayConflict.got]),
        ` — so ${d.pivotActor} rejects it.`,
      ]),
    );
  }
  if (d.synthesisObstacle) {
    steps.append(
      el('li', { class: 'repair-block' }, [
        'To substitute its own share the attacker would have to present ',
        el('code', { class: 'mono' }, [d.synthesisObstacle.needed]),
        ` — but ${d.synthesisObstacle.reason}.`,
      ]),
    );
  }
  if (d.goalUnobtainable) {
    steps.append(
      el('li', {}, [
        'And it cannot build the needed message itself: ',
        el('code', { class: 'mono' }, [d.goalText]),
        ' is not in its knowledge (it is sealed where only an honest party can open it). ',
        el('span', { class: 'repair-conclusion' }, ['No path to the goal — verified by the search exhausting the space.']),
      ]),
    );
  }
  panel.append(steps);
  return panel;
}

function expertDetails(): HTMLElement {
  const d = el('details', { class: 'expert' });
  d.append(
    el('summary', {}, ['How the search actually works (for the curious)']),
    el('p', {}, [
      'A state is: how far each role instance has progressed and what its variables are bound to, plus the exact set of terms the attacker holds. From a state, the enabled moves are — an instance whose next step is a send emits its message (the attacker intercepts it), and an instance whose next step is a receive fires once for every message the attacker can compose that matches the expected pattern.',
    ]),
    el('p', {}, [
      'The attacker composes messages with a fixed rule set: it can split pairs and decrypt anything it holds the key for (analysis), and it can pair, encrypt under any public key, sign with a private key it holds, build a DH share or session key, or simply forward a term it already has (synthesis). Forwarding is the subtle one — it lets the attacker relay an opaque ciphertext it cannot read, which is exactly how Lowe’s attack passes B’s reply through A.',
    ]),
    el('p', {}, [
      'The search is breadth-first over that transition relation, deduplicating on the full state, until it reaches a state where the attacker can synthesise the goal — or the frontier empties. Because it is breadth-first, the trace it returns is a shortest attack. Everything is in ',
      el('span', { class: 'mono' }, ['src/symbolic/']),
      ' and covered by unit tests and the four known-answer attack reproductions.',
    ]),
  );
  return d;
}

function tracePanel(r: SearchResult): HTMLElement {
  const panel = el('div', { class: 'panel' });
  panel.append(
    el('h3', {}, [
      r.found ? 'Attack trace' : 'No trace',
      el('span', { class: 'hint' }, [r.found ? 'every message crosses the attacker' : '—']),
    ]),
  );

  if (!r.found) {
    panel.append(
      el('p', {}, [
        'The search terminated without reaching a state where the attacker learns the goal. There is nothing to replay.',
      ]),
    );
    return panel;
  }

  const list = el('ul', {
    class: 'trace',
    role: 'region',
    tabindex: '0',
    'aria-label': 'Attack message trace',
  });
  r.trace.forEach((s, i) => list.append(traceItem(s, i)));
  panel.append(list);
  panel.append(stepper(r));
  return panel;
}

function traceItem(s: TraceStep, i: number): HTMLElement {
  const shown = i <= state.step;
  const cls = ['', shown ? 'shown' : '', i === state.step ? 'current' : ''].join(' ').trim();
  const li = el('li', { class: cls });
  li.append(
    el('div', { class: 'wire' }, [
      `${s.from} `,
      el('span', { class: 'arrow' }, ['→']),
      ` ${s.to} : ${s.msgText}`,
    ]),
    el('div', { class: 'note' }, [s.note]),
  );
  return li;
}

function stepper(r: SearchResult): HTMLElement {
  const bar = el('div', { class: 'stepper' });
  const prev = el('button', { class: 'btn btn--ghost', type: 'button' }, ['◀ Step back']) as HTMLButtonElement;
  const next = el('button', { class: 'btn btn--ghost', type: 'button' }, ['Step ▶']) as HTMLButtonElement;
  prev.disabled = state.step <= -1;
  next.disabled = state.step >= r.trace.length - 1;
  prev.addEventListener('click', () => {
    state.step = Math.max(-1, state.step - 1);
    render();
  });
  next.addEventListener('click', () => {
    state.step = Math.min(r.trace.length - 1, state.step + 1);
    render();
  });
  bar.append(
    prev,
    next,
    el('span', { class: 'step-count' }, [
      state.step < 0 ? 'start' : `message ${state.step + 1} of ${r.trace.length}`,
    ]),
  );
  return bar;
}

function knowledgePanel(r: SearchResult): HTMLElement {
  const panel = el('div', { class: 'panel' });
  panel.append(
    el('h3', {}, [
      "Attacker's knowledge",
      el('span', { class: 'hint' }, ['each term earns its place by a rule']),
    ]),
  );

  // Facts the attacker holds after the currently-shown step (or the initial
  // knowledge before any message).
  const knownRaw: Fact[] = state.step < 0 ? initialKnowledge(r) : analyse(r.trace[state.step].knownAfter);
  const prevKnown =
    state.step <= 0 ? new Set<string>() : new Set(analyse(r.trace[state.step - 1].knownAfter).map((f) => canon(f.term)));

  const goalCanon = canon(r.goal);

  // Surface the interesting terms: the goal first, then freshly-derived and
  // intercepted terms, with the static public baseline (names/keys) sunk to the
  // bottom — otherwise the term that matters (the leaked secret) scrolls away.
  const rank = (f: Fact): number => {
    if (canon(f.term) === goalCanon) return 0;
    if (f.rule === 'PUB') return 5;
    if (f.rule === 'given') return 4;
    if (f.rule === 'intercept') return 3;
    return 2; //  DEC / SPLIT — the deductions
  };
  const known = knownRaw
    .map((f, i) => ({ f, i }))
    .sort((a, b) => rank(a.f) - rank(b.f) || a.i - b.i)
    .map((x) => x.f);
  const list = el('ul', {
    class: 'knowledge',
    role: 'region',
    tabindex: '0',
    'aria-label': 'Attacker knowledge set',
  });
  for (const f of known) {
    const fresh = state.step >= 0 && !prevKnown.has(canon(f.term));
    const isGoal = canon(f.term) === goalCanon;
    const li = el('li', { class: fresh ? 'fresh' : '' });
    li.append(
      el('span', { class: 'term' }, [pretty(f.term)]),
      el(
        'span',
        { class: `rule${isGoal ? ' goal-hit' : ''}`, 'data-rule': f.rule, title: RULE_TEXT[f.rule] },
        [isGoal ? 'GOAL · ' + f.rule : f.rule],
      ),
    );
    list.append(li);
  }
  panel.append(list);
  panel.append(
    el('p', { class: 'ind-note' }, [
      state.step < 0
        ? 'Before any message: names, public keys, and the keys of corrupt parties.'
        : 'Highlighted terms are new at this step. Every non-initial term names the rule that derived it.',
    ]),
  );
  return panel;
}

function initialKnowledge(r: SearchResult): Fact[] {
  // Reconstruct pre-trace knowledge from the first step's snapshot minus the
  // first intercept — simplest is to analyse an empty-history baseline.
  if (r.trace.length === 0) return [];
  // The first step's knownAfter for a recv equals the baseline; for a send it
  // includes one intercept. Analyse the baseline by dropping intercepts.
  const baseFacts = r.trace[0].knownAfter.filter((f) => f.rule !== 'intercept');
  return analyse(baseFacts);
}

// ---- library + scope ------------------------------------------------------

function linkOnlyBody(entry: LibEntry): HTMLElement {
  const box = el('div', {});
  box.append(
    el('h3', {}, [entry.label]),
    el('p', {}, [entry.link!.note]),
    el('p', {}, [el('a', { href: entry.link!.href }, ['Open the Kerberos lab →'])]),
  );
  return box;
}

function libraryCard(): HTMLElement {
  const card = el('section', { class: 'card' });
  card.append(
    el('p', { class: 'kicker' }, ['Protocol library']),
    el('h2', {}, ['Each protocol, its goal, its verdict']),
    el('p', {}, [
      'The verdicts below come from running the same search you drive above. Select any runnable entry in the checker to replay it message by message.',
    ]),
  );
  const grid = el('div', { class: 'library', id: 'library-grid' });
  card.append(grid);
  buildLibraryChips(grid);
  return card;
}

interface ChipDef {
  title: string;
  spec: string;
  protoId?: string;
  link?: string;
  blurb: string;
}

const CHIPS: ChipDef[] = [
  { title: 'Needham-Schroeder Public Key', spec: 'NSPK · 1978', protoId: 'ns-pk', blurb: 'Goal: attacker learns Nb while B believes it is talking to honest A. The headline.' },
  { title: 'Needham-Schroeder-Lowe', spec: 'Lowe fix · 1995', protoId: 'ns-lowe', blurb: 'The same search, one extra identity field in message 2.' },
  { title: 'Naive Diffie-Hellman', spec: 'unauthenticated', protoId: 'dh-naive', blurb: 'Goal: attacker learns the secret sent under the "shared" key.' },
  { title: 'Signed Diffie-Hellman', spec: 'authenticated', protoId: 'dh-signed', blurb: 'Shares are signed; a substituted share fails verification.' },
  { title: 'Kerberos (toy)', spec: 'ticket handshake', link: SIBLING('kerberos'), blurb: 'The adjacent reflection attack is a hand-built panel in the Kerberos lab.' },
];

function buildLibraryChips(grid: HTMLElement): void {
  grid.innerHTML = '';
  for (const c of CHIPS) {
    const card = el('div', { class: 'lib-card' });
    card.append(el('h3', {}, [c.title]), el('p', { class: 'mono' }, [c.spec]));
    if (c.link) {
      card.append(el('a', { href: c.link, class: 'verdict-chip link' }, ['↗ see Kerberos lab']));
    } else {
      const r = runSearch(protocolById(c.protoId!));
      const chip = el('span', { class: `verdict-chip ${r.found ? 'attack' : 'secure'}` }, [
        r.found ? '✗ attack found' : '✓ no attack in bound',
      ]);
      card.append(chip);
    }
    card.append(el('p', {}, [c.blurb]));
    grid.append(card);
  }
}

// Library chips are static (computed once); this hook exists so a future
// interactive selection can re-highlight the active entry. [extension] point
function refreshLibraryChips(): void {
  /* no-op today; the chips are deterministic verdicts computed at build time */
}

function scopeCard(): HTMLElement {
  const card = el('section', { class: 'card' });
  card.append(
    el('p', { class: 'kicker' }, ['Scope & honesty']),
    el('h2', {}, ['What this is not']),
    el('ul', { class: 'notes' }, [
      el('li', {}, [
        el('strong', {}, ['Not a provable-security lab. ']),
        'Symbolic analysis searches for attacks in the Dolev-Yao model. It is a different discipline from computational proofs and game-hopping reductions, which reason about probabilities and running times — CryptoVerif is the tool on that other branch. Neither subsumes the other.',
      ]),
      el('li', {}, [
        el('strong', {}, ['Not a ProVerif/Tamarin clone. ']),
        'This is a hand-rolled, inspectable engine in the ProVerif/Tamarin lineage — not their input language or their unbounded verification.',
      ]),
      el('li', {}, [
        el('strong', {}, ['Bounded, and the bound is shown. ']),
        'The search explores a finite number of sessions and states. “No attack found” is always relative to that bound.',
      ]),
      el('li', {}, [
        el('strong', {}, ['One equation only. ']),
        'The single algebraic property modelled is g^ab = g^ba (a canonical unordered DH key). No XOR, no partial-DH unification, no equational theory beyond what these protocols need.',
      ]),
      el('li', {}, [
        el('strong', {}, ['Not a protocol-design tutorial. ']),
        'It shows how a flaw is discovered and closed, not how to design protocols from scratch.',
      ]),
    ]),
    el('div', { class: 'whatisnt' }, [
      'Not production tooling — a teaching demo. The engine and the attacks are real, but the model is a deliberate abstraction: it proves nothing about implementations, keys, or timing. See the perfect-cryptography note at the top.',
    ]),
  );
  return card;
}
