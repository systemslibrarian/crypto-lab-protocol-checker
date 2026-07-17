/**
 * explain.ts — a machine-DERIVED account of why a repair closes the attack.
 *
 * For an attack, the search hands back a real witness trace. A secure verdict
 * deserves the same treatment: rather than assert "the fix works" in prose, this
 * module reconstructs, with the same engine primitives (unify / produce /
 * canSynth), the exact point where the attacker's relay stops working against
 * the repaired protocol — and the exact reason.
 *
 * The method is a "repair diagnostic": take the vulnerable and repaired variants
 * of one protocol, find the single message the edit changed, and at the
 * initiator's pivotal receive, show either
 *   - a RELAY CONFLICT: the honest responder's repaired reply no longer unifies
 *     with what the initiator now checks (a concrete field disagreement), or
 *   - a SYNTHESIS OBSTACLE: the attacker would have to forge a term it cannot
 *     (e.g. a signature under a key it does not hold),
 * plus the fact that the goal secret is not in the attacker's knowledge, so it
 * cannot construct the needed message itself.
 *
 * Everything returned is computed from the protocol terms; on any shape it does
 * not recognise it returns null and the UI falls back to a plain-language note.
 */

import { Term, canon, pretty, name, pub, enc } from './terms.ts';
import { unify, apply, emptySubst, Subst } from './unify.ts';
import { Protocol } from './protocol.ts';
import { baseKnowledge, canSynth, closureSet, Fact } from './intruder.ts';

export interface RepairDiagnostic {
  /** The initiator's pivotal receive, in the repaired protocol. */
  pivotActor: string;
  pivotPattern: string;
  /** The honest responder's repaired reply, as the attacker would relay it. */
  honestReply: string;
  /** A concrete field disagreement (relay no longer type-checks). */
  relayConflict?: { expected: string; got: string };
  /** A term the attacker would have to forge but cannot. */
  synthesisObstacle?: { needed: string; reason: string };
  /** The goal secret, and confirmation the attacker cannot obtain it. */
  goalText: string;
  goalUnobtainable: boolean;
}

/** Replace the outermost public-key recipient of an encryption (models M re-addressing a relayed ciphertext). */
function readdress(term: Term, toName: string): Term {
  if (term.t === 'enc' && term.k.t === 'pub') return enc(term.m, pub(name(toName)));
  return term;
}

/** The deepest position where a non-variable pattern node disagrees with `actual`. */
function firstConflict(pattern: Term, actual: Term): { expected: Term; got: Term } | null {
  if (pattern.t === 'var') return null; //  a hole matches anything
  if (pattern.t !== actual.t) return { expected: pattern, got: actual };
  switch (pattern.t) {
    case 'name':
      return pattern.v === (actual as typeof pattern).v ? null : { expected: pattern, got: actual };
    case 'nonce':
      return pattern.v === (actual as typeof pattern).v ? null : { expected: pattern, got: actual };
    case 'pub':
    case 'priv':
      return firstConflict(pattern.of, (actual as typeof pattern).of);
    case 'pair': {
      const a = actual as typeof pattern;
      return firstConflict(pattern.l, a.l) ?? firstConflict(pattern.r, a.r);
    }
    case 'enc': {
      const a = actual as typeof pattern;
      return firstConflict(pattern.k, a.k) ?? firstConflict(pattern.m, a.m);
    }
    case 'sig': {
      const a = actual as typeof pattern;
      return firstConflict(pattern.by, a.by) ?? firstConflict(pattern.m, a.m);
    }
    case 'dh':
      return firstConflict(pattern.x, (actual as typeof pattern).x);
    case 'kdf': {
      const a = actual as typeof pattern;
      return firstConflict(pattern.a, a.a) ?? firstConflict(pattern.b, a.b);
    }
    default:
      return null;
  }
}

/** Collect every `sig(_, signer)` subterm of a pattern (the credentials it demands). */
function sigSubterms(term: Term, acc: Term[] = []): Term[] {
  switch (term.t) {
    case 'sig':
      acc.push(term);
      sigSubterms(term.m, acc);
      break;
    case 'pair':
      sigSubterms(term.l, acc);
      sigSubterms(term.r, acc);
      break;
    case 'enc':
      sigSubterms(term.m, acc);
      sigSubterms(term.k, acc);
      break;
    case 'pub':
    case 'priv':
      sigSubterms(term.of, acc);
      break;
    case 'dh':
      sigSubterms(term.x, acc);
      break;
    case 'kdf':
      sigSubterms(term.a, acc);
      sigSubterms(term.b, acc);
      break;
    default:
      break;
  }
  return acc;
}

/**
 * Derive why `fixed` closes the attack that `vuln` admits. Returns null if the
 * shapes are not the initiator/responder form this routine understands.
 */
export function explainRepair(vuln: Protocol, fixed: Protocol): RepairDiagnostic | null {
  try {
    const initiator = fixed.instances[0];
    const responder = fixed.instances[1];
    if (!initiator || !responder) return null;

    // 1. Confirm the edit actually changed a message (else there is nothing to explain).
    if (!hasEdit(vuln, fixed)) return null;

    // 2. The initiator's pivotal receive in the repaired protocol (the step that
    //    binds a value the initiator later reveals). Take its first recv.
    const pivotRecv = initiator.steps.find((s) => s.dir === 'recv');
    if (!pivotRecv) return null;
    const pivotPattern = pivotRecv.msg;

    // 3. The honest responder's repaired reply, as the attacker would relay it:
    //    M re-addresses the initiator's opening message to the responder, the
    //    responder binds its receive, and emits its reply.
    const openMsg = readdress(apply(initiator.steps[0].msg, emptySubst()), responder.actor);
    const respRecv = responder.steps.find((s) => s.dir === 'recv');
    const respSend = responder.steps.find((s) => s.dir === 'send');
    if (!respRecv || !respSend) return null;
    const bindResp = unify(respRecv.msg, openMsg, emptySubst());
    if (!bindResp) return null;
    const honestReply = apply(respSend.msg, bindResp);

    // 4. Does the repaired reply still satisfy the initiator's check?
    const relayConflict = firstConflict(pivotPattern, honestReply) ?? undefined;

    // 5. Attacker knowledge available at the pivot (over-approximate: base plus
    //    every honest output it could have intercepted).
    const base = baseKnowledge(fixed.names, fixed.corrupt, fixed.attackerTerms ?? []);
    const known: Fact[] = [
      ...base,
      { term: apply(initiator.steps[0].msg, emptySubst()), rule: 'intercept', from: [] },
      { term: honestReply, rule: 'intercept', from: [] },
    ];
    const closure = closureSet(known);
    const terms = known.map((f) => f.term);

    // 6. A synthesis obstacle: any credential the repaired pattern demands that
    //    the attacker cannot forge (e.g. a signature under sk it does not hold).
    let synthesisObstacle: RepairDiagnostic['synthesisObstacle'] | undefined;
    for (const sg of sigSubterms(pivotPattern)) {
      if (sg.t !== 'sig') continue;
      // Instantiate the signed body with the attacker's own contribution where
      // the pattern is still open, then ask: can the attacker build this sig?
      const grounded = groundWithAny(sg, terms);
      if (grounded && !canSynth(grounded, closure, terms)) {
        const signer = sg.by.t === 'name' ? sg.by.v : pretty(sg.by);
        synthesisObstacle = {
          needed: pretty(grounded),
          reason: `the attacker holds no sk${signer}, so it cannot sign a share of its own`,
        };
        break;
      }
    }

    if (!relayConflict && !synthesisObstacle) return null; //  nothing crisp to show

    const goalUnobtainable = !canSynth(fixed.goal, closure, terms);

    return {
      pivotActor: initiator.actor,
      pivotPattern: pretty(pivotPattern),
      honestReply: pretty(honestReply),
      relayConflict: relayConflict
        ? { expected: pretty(relayConflict.expected), got: pretty(relayConflict.got) }
        : undefined,
      synthesisObstacle,
      goalText: pretty(fixed.goal),
      goalUnobtainable,
    };
  } catch {
    return null;
  }
}

function hasEdit(vuln: Protocol, fixed: Protocol): boolean {
  for (let i = 0; i < fixed.instances.length; i++) {
    const vi = vuln.instances[i];
    const fi = fixed.instances[i];
    if (!vi || !fi) continue;
    for (let k = 0; k < fi.steps.length; k++) {
      if (vi.steps[k] && fi.steps[k] && canon(vi.steps[k].msg) !== canon(fi.steps[k].msg)) return true;
    }
  }
  return false;
}

/** Fill a pattern's open holes with the attacker's own exponent, to test "could it forge this?". */
function groundWithAny(term: Term, terms: Term[]): Term | null {
  const holes = collectVars(term);
  if (holes.length === 0) return term;
  // A share's exponent hole should become the attacker's own exponent (a nonce
  // it holds), producing the attacker's own share — not another share term.
  const filler = terms.find((t) => t.t === 'nonce') ?? terms.find((t) => t.t === 'dh') ?? terms[0];
  if (!filler) return null;
  let s: Subst = emptySubst();
  for (const h of holes) s = new Map(s).set(h, filler);
  return apply(term, s);
}

function collectVars(term: Term, acc: string[] = []): string[] {
  switch (term.t) {
    case 'var':
      if (!acc.includes(term.v)) acc.push(term.v);
      break;
    case 'pub':
    case 'priv':
      collectVars(term.of, acc);
      break;
    case 'pair':
      collectVars(term.l, acc);
      collectVars(term.r, acc);
      break;
    case 'enc':
      collectVars(term.m, acc);
      collectVars(term.k, acc);
      break;
    case 'sig':
      collectVars(term.m, acc);
      collectVars(term.by, acc);
      break;
    case 'dh':
      collectVars(term.x, acc);
      break;
    case 'kdf':
      collectVars(term.a, acc);
      collectVars(term.b, acc);
      break;
    default:
      break;
  }
  return acc;
}
