/**
 * unify.ts — first-order unification over terms, with occurs-check.
 *
 * A `Subst` maps Var names to terms. Unification is how a protocol role decides
 * whether an incoming message *matches* the pattern it is waiting for, binding
 * the pattern's holes in the process. When B waits for {?Na, ?A}_pkB and the
 * network delivers {Na1, A}_pkB, unification binds ?Na -> Na1, ?A -> A.
 *
 * This is also what makes the Lowe attack a *relay* rather than a forgery: the
 * intruder unifies A's waiting pattern {Na, ?Nb}_pkA against the opaque
 * ciphertext {Na, Nb}_pkA it intercepted from B — binding ?Nb to a value it
 * never learned — and forwards the term unopened.
 */

import { Term, canon } from './terms.ts';

export type Subst = Map<string, Term>;

export const emptySubst = (): Subst => new Map();

/** Apply a substitution to a term, recursively, until no bound var remains. */
export function apply(term: Term, s: Subst): Term {
  switch (term.t) {
    case 'var': {
      const bound = s.get(term.v);
      return bound ? apply(bound, s) : term;
    }
    case 'pub':
      return { t: 'pub', of: apply(term.of, s) };
    case 'priv':
      return { t: 'priv', of: apply(term.of, s) };
    case 'pair':
      return { t: 'pair', l: apply(term.l, s), r: apply(term.r, s) };
    case 'enc':
      return { t: 'enc', m: apply(term.m, s), k: apply(term.k, s) };
    case 'sig':
      return { t: 'sig', m: apply(term.m, s), by: apply(term.by, s) };
    case 'dh':
      return { t: 'dh', x: apply(term.x, s) };
    case 'kdf': {
      const a = apply(term.a, s);
      const b = apply(term.b, s);
      // Preserve the canonical DH-symmetry ordering after substitution.
      return canon(a) <= canon(b) ? { t: 'kdf', a, b } : { t: 'kdf', a: b, b: a };
    }
    default:
      return term;
  }
}

function occurs(name: string, term: Term, s: Subst): boolean {
  const t = term.t === 'var' && s.has(term.v) ? apply(term, s) : term;
  switch (t.t) {
    case 'var':
      return t.v === name;
    case 'pair':
      return occurs(name, t.l, s) || occurs(name, t.r, s);
    case 'enc':
      return occurs(name, t.m, s) || occurs(name, t.k, s);
    case 'sig':
      return occurs(name, t.m, s);
    case 'dh':
      return occurs(name, t.x, s);
    case 'kdf':
      return occurs(name, t.a, s) || occurs(name, t.b, s);
    default:
      return false;
  }
}

function bind(name: string, term: Term, s: Subst): Subst | null {
  if (term.t === 'var' && term.v === name) return s;
  if (occurs(name, term, s)) return null; // would build an infinite term
  const next = new Map(s);
  next.set(name, term);
  return next;
}

/**
 * Unify a and b under an existing substitution, returning the extended
 * substitution or null if they cannot be made equal. Symmetric.
 */
export function unify(a: Term, b: Term, s: Subst = emptySubst()): Subst | null {
  const x = a.t === 'var' ? apply(a, s) : a;
  const y = b.t === 'var' ? apply(b, s) : b;

  if (x.t === 'var') return bind(x.v, y, s);
  if (y.t === 'var') return bind(y.v, x, s);
  if (x.t !== y.t) return null;

  switch (x.t) {
    case 'name':
      return x.v === (y as typeof x).v ? s : null;
    case 'nonce':
      return x.v === (y as typeof x).v ? s : null;
    case 'pub':
      return unify(x.of, (y as typeof x).of, s);
    case 'priv':
      return unify(x.of, (y as typeof x).of, s);
    case 'pair': {
      const yy = y as typeof x;
      const s1 = unify(x.l, yy.l, s);
      return s1 && unify(x.r, yy.r, s1);
    }
    case 'enc': {
      const yy = y as typeof x;
      const s1 = unify(x.m, yy.m, s);
      return s1 && unify(x.k, yy.k, s1);
    }
    case 'sig': {
      const yy = y as typeof x;
      const s1 = unify(x.by, yy.by, s);
      return s1 && unify(x.m, yy.m, s1);
    }
    case 'dh':
      return unify(x.x, (y as typeof x).x, s);
    case 'kdf': {
      const yy = y as typeof x;
      // DH keys are symmetric: try both pairings of the two shares.
      const direct = (() => {
        const s1 = unify(x.a, yy.a, s);
        return s1 && unify(x.b, yy.b, s1);
      })();
      if (direct) return direct;
      const swap = unify(x.a, yy.b, s);
      return swap && unify(x.b, yy.a, swap);
    }
    default:
      return null;
  }
}
