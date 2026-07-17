/**
 * intruder.ts — the Dolev-Yao attacker.
 *
 * The attacker controls the network completely: every message an honest agent
 * sends is intercepted (added to its knowledge), and every message an honest
 * agent receives must be one the attacker can *produce* from what it knows. The
 * attacker cannot break cryptography — it can only:
 *
 *   ANALYSE what it holds:
 *     DEC   from {m}_pk(X) and sk(X)         derive m
 *     SPLIT from <m1, m2>                    derive m1 and m2
 *   SYNTHESISE new messages:
 *     PAIR  from m1 and m2                   build <m1, m2>
 *     ENC   from m and a (public) key        build {m}_k
 *     SIGN  from m and sk(X) it holds        build [m]_sk(X)
 *     DH    from an exponent x it knows       build g^x
 *     KDF   from two shares it can build      build the DH session key
 *     FWD   send any term it already holds    (relay, even if opaque)
 *
 * Every derived term records the rule and its inputs, so the UI can show that
 * nothing here is magic: each fact in the attacker's knowledge is auditable.
 */

import { Term, canon, name, pub, priv, dh, isGround } from './terms.ts';
import { Subst, unify, apply } from './unify.ts';

export type Rule =
  | 'given' //  in the attacker's initial knowledge
  | 'intercept' //  pulled off the wire when an honest agent sent it
  | 'DEC' //  decrypted a ciphertext with a key it holds
  | 'SPLIT' //  projected a component out of a pair
  | 'PAIR'
  | 'ENC'
  | 'SIGN'
  | 'DH'
  | 'KDF'
  | 'PUB' //  public axiom: all names and public keys are known to everyone
  | 'FWD'; //  forwarded / used a term already held

export interface Fact {
  term: Term;
  rule: Rule;
  from: Term[]; //  the inputs the rule consumed (for the audit trail)
}

export const RULE_TEXT: Record<Rule, string> = {
  given: 'initial knowledge',
  intercept: 'intercepted on the network',
  DEC: 'decrypt {m}_pk(X) using sk(X)',
  SPLIT: 'split a pair <m1, m2>',
  PAIR: 'pair two known terms',
  ENC: 'encrypt under a public key',
  SIGN: 'sign with a private key it holds',
  DH: 'compute g^x from a known exponent x',
  KDF: 'derive a DH session key from two shares',
  PUB: 'public: all names & public keys are known',
  FWD: 'forward a term already known',
};

/**
 * Close a set of base facts under ANALYSIS (DEC, SPLIT) to a fixpoint. The
 * returned list is ordered by discovery, each fact annotated with the rule that
 * produced it — this is exactly what the knowledge panel renders.
 */
export function analyse(base: Fact[]): Fact[] {
  const facts: Fact[] = [];
  const seen = new Set<string>();
  const push = (f: Fact) => {
    const c = canon(f.term);
    if (seen.has(c)) return;
    seen.add(c);
    facts.push(f);
  };
  base.forEach(push);

  let grew = true;
  while (grew) {
    grew = false;
    const before = facts.length;
    for (let i = 0; i < facts.length; i++) {
      const t = facts[i].term;
      if (t.t === 'pair') {
        push({ term: t.l, rule: 'SPLIT', from: [t] });
        push({ term: t.r, rule: 'SPLIT', from: [t] });
      } else if (t.t === 'enc') {
        if (t.k.t === 'pub') {
          // Asymmetric: decrypt {m}_pk(X) only with the private key sk(X).
          const need = priv(t.k.of);
          if (seen.has(canon(need))) push({ term: t.m, rule: 'DEC', from: [t, need] });
        } else if (canSynth(t.k, seen, facts.map((f) => f.term))) {
          // Symmetric (e.g. a DH-derived key): decrypt if the key is derivable.
          push({ term: t.m, rule: 'DEC', from: [t, t.k] });
        }
      }
    }
    if (facts.length > before) grew = true;
  }
  return facts;
}

/** Convenience: the canon-set of everything the attacker can derive by analysis. */
export function closureSet(base: Fact[]): Set<string> {
  return new Set(analyse(base).map((f) => canon(f.term)));
}

/** All public identities the attacker is assumed to know (for PUB synthesis). */
export function knownNames(base: Fact[]): Term[] {
  const out: Term[] = [];
  const seen = new Set<string>();
  for (const f of analyse(base)) {
    const t = f.term;
    if (t.t === 'name' && !seen.has(t.v)) {
      seen.add(t.v);
      out.push(t);
    }
  }
  return out;
}

/**
 * Can the attacker SYNTHESISE this ground target from `closure`?
 * Used for the goal test ("does the attacker know the secret nonce?").
 */
export function canSynth(target: Term, closure: Set<string>, held: Term[]): boolean {
  if (closure.has(canon(target))) return true;
  switch (target.t) {
    case 'name':
      return true; //  PUB
    case 'pub':
      return true; //  PUB — public keys are public
    case 'pair':
      return canSynth(target.l, closure, held) && canSynth(target.r, closure, held);
    case 'enc':
      return canSynth(target.k, closure, held) && canSynth(target.m, closure, held);
    case 'dh':
      return canSynth(target.x, closure, held);
    case 'kdf': {
      // DH session key over exponents a, b: g^(ab). It can be computed as
      // (g^b)^a — needing exponent a and the *share* g^b — or symmetrically
      // (g^a)^b. It is NOT derivable from the two public shares alone. That gap
      // is exactly the Diffie-Hellman (CDH) assumption the model honours.
      const haveShare = (t: Term) => closure.has(canon(dh(t)));
      const withA = canSynth(target.a, closure, held) && haveShare(target.b);
      const withB = canSynth(target.b, closure, held) && haveShare(target.a);
      return withA || withB;
    }
    case 'sig':
      // Can sign only with a private key the attacker actually holds.
      return closure.has(canon(priv(target.by))) && canSynth(target.m, closure, held);
    default:
      return false; //  nonces, private keys: only if already in closure
  }
}

/**
 * The engine of the search. Enumerate substitutions `s'` (extending `s`) such
 * that `pattern` instantiated by `s'` is a *ground* message the attacker can
 * deliver. This is where the attacker "decides" what to inject into an honest
 * agent's next receive step.
 *
 * Two families of moves, mirroring canSynth:
 *   - FORWARD: unify the pattern against any term the attacker already holds
 *     (this is how an opaque ciphertext gets relayed, binding a hole to a value
 *     the attacker never learned — the crux of Lowe's attack).
 *   - CONSTRUCT: build the pattern up by its head symbol (PAIR / ENC / DH / KDF
 *     / SIGN), recursing into the parts; a bare hole is filled from knowledge.
 */
export function produce(pattern: Term, s: Subst, base: Fact[]): Subst[] {
  const facts = analyse(base);
  const factTerms = facts.map((f) => f.term);
  const closure = new Set(factTerms.map(canon));
  const names = knownNames(base);
  const canHold = (t: Term) => closure.has(canon(priv(t)));

  // ways(pat, sub): every substitution extending `sub` under which `pat`
  // becomes a term the attacker can hand to the network. Recursion strictly
  // decreases term depth (compound heads recurse into proper subterms; a hole
  // is filled directly), so it terminates.
  function ways(pat: Term, sub: Subst): Subst[] {
    const p = apply(pat, sub);
    const acc: Subst[] = [];
    const seen = new Set<string>();
    const record = (s2: Subst) => {
      const g = apply(p, s2);
      if (!canSynth(g, closure, factTerms)) return;
      const key = serialize(s2);
      if (seen.has(key)) return;
      seen.add(key);
      acc.push(s2);
    };

    // FORWARD: relay/reuse any held term that unifies (opaque relay lives here).
    for (const f of facts) {
      const s2 = unify(p, f.term, sub);
      if (s2) record(s2);
    }
    // CONSTRUCT by head symbol.
    switch (p.t) {
      case 'var': {
        const candidates = p.sort === 'name' ? names : factTerms;
        for (const c of candidates) {
          const s2 = unify(p, c, sub);
          if (s2) record(s2);
        }
        break;
      }
      case 'name':
      case 'pub':
        record(sub); //  PUB
        break;
      case 'pair':
        for (const s2 of ways(p.l, sub)) for (const s3 of ways(p.r, s2)) record(s3);
        break;
      case 'enc':
        for (const s2 of ways(p.k, sub)) for (const s3 of ways(p.m, s2)) record(s3);
        break;
      case 'dh':
        for (const s2 of ways(p.x, sub)) record(s2);
        break;
      case 'kdf':
        for (const s2 of ways(p.a, sub)) for (const s3 of ways(p.b, s2)) record(s3);
        break;
      case 'sig':
        if (canHold(p.by)) for (const s2 of ways(p.m, sub)) record(s2);
        break;
      default:
        break; //  nonce / priv: only obtainable via FORWARD above
    }
    return acc;
  }

  // Keep only substitutions that ground the whole pattern (no leftover holes).
  const out: Subst[] = [];
  const seenGround = new Set<string>();
  for (const sub of ways(pattern, s)) {
    const g = apply(pattern, sub);
    if (!isGround(g)) continue;
    const key = canon(g);
    if (seenGround.has(key)) continue;
    seenGround.add(key);
    out.push(sub);
  }
  return out;
}

function serialize(s: Subst): string {
  return [...s.entries()]
    .map(([k, t]) => `${k}=${canon(t)}`)
    .sort()
    .join(';');
}

/** Build the standard baseline attacker knowledge for a scenario. */
export function baseKnowledge(names_: string[], corrupt: string[], extra: Term[] = []): Fact[] {
  const facts: Fact[] = [];
  for (const n of names_) {
    facts.push({ term: name(n), rule: 'PUB', from: [] });
    facts.push({ term: pub(name(n)), rule: 'PUB', from: [] });
  }
  for (const c of corrupt) {
    facts.push({ term: priv(name(c)), rule: 'given', from: [] });
  }
  for (const t of extra) {
    facts.push({ term: t, rule: 'given', from: [] });
  }
  return facts;
}
