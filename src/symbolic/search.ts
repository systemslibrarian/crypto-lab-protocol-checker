/**
 * search.ts — bounded reachability search (the primitive).
 *
 * A *state* is: how far each role instance has progressed (and what its pattern
 * variables are bound to), plus everything the attacker currently knows. From a
 * state, the enabled moves are:
 *
 *   - an instance whose next step is a SEND: it emits its (now ground) message,
 *     which the attacker intercepts — one deterministic successor;
 *   - an instance whose next step is a RECV: for every message the attacker can
 *     produce that matches the expected pattern, one successor (this is where
 *     the attacker "chooses" what to inject; see intruder.produce).
 *
 * We breadth-first search from the initial state until a state is reached in
 * which the attacker can synthesise the goal term — then reconstruct the trace.
 * If the frontier empties (or the state cap is hit) with no such state, the
 * verdict is "no attack in this bound". The bound is real and is displayed:
 * "no attack found" is a statement about this model and this scenario, never an
 * unconditional proof.
 */

import { Term, canon, pretty } from './terms.ts';
import { Subst, emptySubst, apply } from './unify.ts';
import { Fact, baseKnowledge, closureSet, canSynth, produce } from './intruder.ts';
import { Protocol } from './protocol.ts';

export interface TraceStep {
  n: number;
  instance: number;
  actor: string;
  role: string;
  dir: 'send' | 'recv';
  /** Rendered "A → M" style, since every message crosses the attacker-network. */
  from: string;
  to: string;
  msg: Term;
  msgText: string;
  note: string;
  /** Attacker's base knowledge immediately after this step (analysis on demand). */
  knownAfter: Fact[];
}

export interface SearchResult {
  found: boolean;
  goal: Term;
  goalText: string;
  trace: TraceStep[];
  statesExplored: number;
  /** Distinct attacker message-injections the search evaluated (the real work). */
  injectionsTried: number;
  /** Total state transitions generated (send + recv successors). */
  transitions: number;
  /** Deepest interleaving reached, in messages. */
  searchDepth: number;
  bound: number;
  boundHit: boolean;
  attacker: string;
}

// Mutable counters threaded through one search run, folded into the result.
interface Stats {
  injectionsTried: number;
  transitions: number;
  searchDepth: number;
}

interface Node {
  progress: number[]; //  next step index per instance
  subst: Subst[]; //  bindings per instance
  known: Fact[]; //  attacker base facts (given + intercepted)
  history: RawStep[];
}

interface RawStep {
  instance: number;
  dir: 'send' | 'recv';
  msg: Term; //  ground message that crossed the wire
}

function stateKey(n: Node): string {
  const prog = n.progress.join(',');
  const binds = n.subst
    .map((s) =>
      [...s.entries()]
        .map(([k, t]) => `${k}=${canon(t)}`)
        .sort()
        .join('&'),
    )
    .join('|');
  const known = n.known
    .map((f) => canon(f.term))
    .sort()
    .join(';');
  return `${prog}#${binds}#${known}`;
}

/** Run the bounded search for one protocol. Deterministic (BFS, stable order). */
export function search(proto: Protocol): SearchResult {
  const base = baseKnowledge(proto.names, proto.corrupt, proto.attackerTerms ?? []);
  const start: Node = {
    progress: proto.instances.map(() => 0),
    subst: proto.instances.map(() => emptySubst()),
    known: base,
    history: [],
  };

  const guardOk = (node: Node): boolean => {
    if (!proto.guard) return true;
    const bound = node.subst[proto.guard.instance]?.get(proto.guard.varName);
    return !!bound && bound.t === 'name' && proto.guard.honest.includes(bound.v);
  };
  const goalReached = (node: Node): boolean =>
    guardOk(node) && canSynth(proto.goal, closureSet(node.known), node.known.map((f) => f.term));

  const queue: Node[] = [start];
  const visited = new Set<string>([stateKey(start)]);
  let explored = 0;
  let boundHit = false;
  const stats: Stats = { injectionsTried: 0, transitions: 0, searchDepth: 0 };

  // The initial state can't already leak the goal (goal is a fresh secret), but
  // guard anyway.
  if (goalReached(start)) return finalize(proto, start, true, explored, stats);

  while (queue.length > 0) {
    if (explored >= proto.bound) {
      boundHit = true;
      break;
    }
    const node = queue.shift()!;
    explored++;

    for (let i = 0; i < proto.instances.length; i++) {
      const inst = proto.instances[i];
      const idx = node.progress[i];
      if (idx >= inst.steps.length) continue;
      const step = inst.steps[idx];

      if (step.dir === 'send') {
        const msg = apply(step.msg, node.subst[i]);
        const next = advance(node, i, node.subst[i], {
          instance: i,
          dir: 'send',
          msg,
        });
        next.known = [...node.known, { term: msg, rule: 'intercept', from: [] }];
        pushNode(next);
      } else {
        const pattern = apply(step.msg, node.subst[i]);
        for (const sub of produce(pattern, node.subst[i], node.known)) {
          stats.injectionsTried++; //  a distinct message the attacker could inject here
          const msg = apply(step.msg, sub);
          const next = advance(node, i, sub, { instance: i, dir: 'recv', msg });
          pushNode(next);
        }
      }
    }
  }

  return { ...emptyResult(proto), statesExplored: explored, boundHit, ...stats };

  function pushNode(next: Node): void {
    stats.transitions++;
    if (next.history.length > stats.searchDepth) stats.searchDepth = next.history.length;
    if (goalReached(next)) {
      // Splice the winning node straight into the queue front so finalize sees it.
      const res = finalize(proto, next, true, explored, stats);
      throw new Found(res);
    }
    const key = stateKey(next);
    if (visited.has(key)) return;
    visited.add(key);
    queue.push(next);
  }
}

// A tiny control-flow escape so we can return from deep inside the BFS loop
// the moment the goal is reached, without threading a flag through everything.
class Found {
  result: SearchResult;
  constructor(result: SearchResult) {
    this.result = result;
  }
}

export function runSearch(proto: Protocol): SearchResult {
  try {
    return search(proto);
  } catch (e) {
    if (e instanceof Found) return e.result;
    throw e;
  }
}

function advance(node: Node, i: number, newSubst: Subst, raw: RawStep): Node {
  const progress = node.progress.slice();
  progress[i] = progress[i] + 1;
  const subst = node.subst.slice();
  subst[i] = newSubst;
  return {
    progress,
    subst,
    known: node.known,
    history: [...node.history, raw],
  };
}

function emptyResult(proto: Protocol): SearchResult {
  return {
    found: false,
    goal: proto.goal,
    goalText: pretty(proto.goal),
    trace: [],
    statesExplored: 0,
    injectionsTried: 0,
    transitions: 0,
    searchDepth: 0,
    bound: proto.bound,
    boundHit: false,
    attacker: proto.attacker,
  };
}

function finalize(proto: Protocol, node: Node, found: boolean, explored: number, stats: Stats): SearchResult {
  const trace: TraceStep[] = [];
  let known: Fact[] = baseKnowledge(proto.names, proto.corrupt, proto.attackerTerms ?? []);
  node.history.forEach((raw, n) => {
    const inst = proto.instances[raw.instance];
    if (raw.dir === 'send') known = [...known, { term: raw.msg, rule: 'intercept', from: [] }];
    const from = raw.dir === 'send' ? inst.actor : proto.attacker;
    const to = raw.dir === 'send' ? proto.attacker : inst.actor;
    trace.push({
      n: n + 1,
      instance: raw.instance,
      actor: inst.actor,
      role: inst.role,
      dir: raw.dir,
      from,
      to,
      msg: raw.msg,
      msgText: pretty(raw.msg),
      note: annotate(proto, raw, inst),
      knownAfter: known,
    });
  });
  return {
    found,
    goal: proto.goal,
    goalText: pretty(proto.goal),
    trace,
    statesExplored: explored,
    injectionsTried: stats.injectionsTried,
    transitions: stats.transitions,
    searchDepth: stats.searchDepth,
    bound: proto.bound,
    boundHit: false,
    attacker: proto.attacker,
  };
}

function annotate(proto: Protocol, raw: RawStep, inst: { actor: string; role: string; peer?: string }): string {
  if (raw.dir === 'send') {
    return `${inst.actor} (${inst.role.toLowerCase()}) sends — intercepted by ${proto.attacker}.`;
  }
  return `${proto.attacker} delivers a message ${inst.actor} accepts as ${inst.role.toLowerCase()}.`;
}
