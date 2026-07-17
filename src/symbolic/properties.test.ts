import { describe, it, expect } from 'vitest';
import {
  Term,
  name,
  nonce,
  pub,
  priv,
  pair,
  enc,
  sig,
  dh,
  kdf,
  v,
  canon,
  eq,
  isGround,
} from './terms.ts';
import { unify, apply, emptySubst } from './unify.ts';
import { analyse, closureSet, baseKnowledge, Fact } from './intruder.ts';
import { runSearch } from './search.ts';
import { needhamSchroeder, diffieHellman, Protocol } from './protocol.ts';

/**
 * Invariant / property tests. Example-based KATs catch known regressions; these
 * catch the semantic drift that hides *behind* passing examples — by asserting
 * algebraic laws over many randomly-generated terms. Seeded for reproducibility
 * (no Math.random / Date.now, so a failure is always replayable).
 */

// mulberry32 — a tiny deterministic PRNG.
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const NAMES = ['A', 'B', 'M'];
const NONCES = ['Na', 'Nb', 'Ns', 'm'];

function genTerm(r: () => number, depth: number): Term {
  if (depth <= 0 || r() < 0.35) {
    const pick = r();
    if (pick < 0.4) return name(NAMES[(r() * NAMES.length) | 0]);
    if (pick < 0.8) return nonce(NONCES[(r() * NONCES.length) | 0]);
    return r() < 0.5 ? pub(name(NAMES[(r() * NAMES.length) | 0])) : priv(name(NAMES[(r() * NAMES.length) | 0]));
  }
  const k = (r() * 6) | 0;
  switch (k) {
    case 0:
      return pair(genTerm(r, depth - 1), genTerm(r, depth - 1));
    case 1:
      return enc(genTerm(r, depth - 1), pub(name(NAMES[(r() * NAMES.length) | 0])));
    case 2:
      return sig(genTerm(r, depth - 1), name(NAMES[(r() * NAMES.length) | 0]));
    case 3:
      return dh(genTerm(r, depth - 1));
    case 4:
      return kdf(genTerm(r, depth - 1), genTerm(r, depth - 1));
    default:
      return pair(genTerm(r, depth - 1), genTerm(r, depth - 1));
  }
}

// Replace some subterms of a ground term with fresh variables, yielding a
// pattern that must unify back to the original.
function patternize(t: Term, r: () => number, counter: { n: number }): Term {
  if (r() < 0.25) return v(`x${counter.n++}`);
  switch (t.t) {
    case 'pair':
      return pair(patternize(t.l, r, counter), patternize(t.r, r, counter));
    case 'enc':
      return enc(patternize(t.m, r, counter), t.k);
    case 'sig':
      return sig(patternize(t.m, r, counter), t.by);
    case 'dh':
      return dh(patternize(t.x, r, counter));
    case 'kdf':
      return kdf(patternize(t.a, r, counter), patternize(t.b, r, counter));
    default:
      return t;
  }
}

describe('term algebra laws', () => {
  it('canon is reflexive and eq is symmetric over random terms', () => {
    const r = rng(1);
    for (let i = 0; i < 400; i++) {
      const t = genTerm(r, 4);
      expect(eq(t, t)).toBe(true);
      const u = genTerm(r, 4);
      expect(eq(t, u)).toBe(eq(u, t));
    }
  });

  it('the DH key is commutative in its shares (the only modelled equation)', () => {
    const r = rng(2);
    for (let i = 0; i < 200; i++) {
      const a = genTerm(r, 3);
      const b = genTerm(r, 3);
      expect(canon(kdf(a, b))).toBe(canon(kdf(b, a)));
    }
  });
});

describe('unification laws', () => {
  it('is reflexive: unify(t, t) succeeds and fixes t', () => {
    const r = rng(3);
    for (let i = 0; i < 400; i++) {
      const t = genTerm(r, 4);
      const s = unify(t, t, emptySubst());
      expect(s).not.toBeNull();
      expect(canon(apply(t, s!))).toBe(canon(t));
    }
  });

  it('is sound: a successful unifier makes both sides equal (MGU correctness)', () => {
    const r = rng(4);
    for (let i = 0; i < 500; i++) {
      const ground = genTerm(r, 4);
      const pattern = patternize(ground, r, { n: 0 });
      const s = unify(pattern, ground, emptySubst());
      expect(s).not.toBeNull(); //  a variable-abstraction of t always unifies with t
      expect(canon(apply(pattern, s!))).toBe(canon(apply(ground, s!)));
      expect(canon(apply(pattern, s!))).toBe(canon(ground)); //  and recovers the original
    }
  });

  it('leaves ground terms untouched under any substitution', () => {
    const r = rng(5);
    const s = new Map([['x0', name('A')], ['x1', nonce('Nb')]]);
    for (let i = 0; i < 300; i++) {
      const t = genTerm(r, 4);
      if (isGround(t)) expect(canon(apply(t, s))).toBe(canon(t));
    }
  });
});

describe('attacker knowledge is monotone', () => {
  it('adding a fact never removes a derivable term (analysis monotonicity)', () => {
    const r = rng(6);
    for (let i = 0; i < 150; i++) {
      const base: Fact[] = [];
      const count = 1 + ((r() * 4) | 0);
      for (let j = 0; j < count; j++) base.push({ term: genTerm(r, 3), rule: 'given', from: [] });
      const before = closureSet(base);
      const extra: Fact = { term: genTerm(r, 3), rule: 'given', from: [] };
      const after = closureSet([...base, extra]);
      for (const c of before) expect(after.has(c)).toBe(true);
    }
  });

  it('analysis is idempotent: re-analysing its own output adds nothing', () => {
    const r = rng(7);
    for (let i = 0; i < 100; i++) {
      const base: Fact[] = [{ term: genTerm(r, 4), rule: 'given', from: [] }];
      const once = analyse(base);
      const twice = analyse(once);
      expect(twice.length).toBe(once.length);
    }
  });
});

describe('search is deterministic and bound-monotone', () => {
  const withBound = (p: Protocol, bound: number): Protocol => ({ ...p, bound });

  for (const [label, make] of [
    ['NSPK', () => needhamSchroeder(false)],
    ['NSL', () => needhamSchroeder(true)],
    ['DH-naive', () => diffieHellman(false)],
    ['DH-signed', () => diffieHellman(true)],
  ] as const) {
    it(`${label}: identical trace across runs`, () => {
      const a = runSearch(make());
      const b = runSearch(make());
      expect(a.found).toBe(b.found);
      expect(a.trace.map((s) => s.msgText)).toEqual(b.trace.map((s) => s.msgText));
    });
  }

  it('raising the bound never hides a found attack (NSPK)', () => {
    const small = runSearch(withBound(needhamSchroeder(false), 60000));
    const large = runSearch(withBound(needhamSchroeder(false), 200000));
    expect(small.found && large.found).toBe(true);
    expect(large.trace.map((s) => s.msgText)).toEqual(small.trace.map((s) => s.msgText));
  });

  it('raising the bound never invents an attack on a secure protocol (NSL)', () => {
    for (const bound of [10000, 60000, 120000]) {
      expect(runSearch(withBound(needhamSchroeder(true), bound)).found).toBe(false);
    }
  });

  it('too small a bound can only hide the attack, never fabricate one (NSPK)', () => {
    const starved = runSearch(withBound(needhamSchroeder(false), 5));
    // With a tiny cap it may not reach the goal — but it must never claim a
    // *different* verdict than "no attack yet"; if it does find one, it must be
    // the real trace.
    if (starved.found) {
      const full = runSearch(needhamSchroeder(false));
      expect(starved.trace.map((s) => s.msgText)).toEqual(full.trace.map((s) => s.msgText));
    } else {
      expect(starved.boundHit).toBe(true);
    }
  });

  it('the initial attacker baseline never already knows a fresh goal', () => {
    for (const make of [() => needhamSchroeder(false), () => diffieHellman(false)]) {
      const p = make();
      const base = baseKnowledge(p.names, p.corrupt, p.attackerTerms ?? []);
      expect(closureSet(base).has(canon(p.goal))).toBe(false);
    }
  });
});
