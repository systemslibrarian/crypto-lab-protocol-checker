/**
 * terms.ts — the term algebra of the symbolic model.
 *
 * In the Dolev-Yao model a message is not bytes but a *term*: a tree built from
 * atoms (names, nonces, keys) and constructors (pairing, encryption, signature,
 * Diffie-Hellman). Cryptography is "perfect" — an encryption {m}_k is an opaque
 * node that can only be opened with the matching key; there is no key recovery,
 * no algebraic leakage, no partial information. That abstraction is the whole
 * point of the tool, and its blind spot: every side-channel and implementation
 * lab in the fleet is an attack this representation structurally cannot express.
 *
 * `var` terms are the holes in a protocol's receive-patterns. They get bound by
 * unification (see unify.ts) when a concrete message arrives. A term with no
 * var nodes is *ground*. An identity variable (`sort: 'name'`) may only ever be
 * an agent name — a standard typed-model restriction that keeps the search
 * finite without weakening the attacker where it matters.
 */

export type Term =
  | { t: 'name'; v: string } //  A, B, M — public principal identities
  | { t: 'nonce'; v: string } //  Na, Nb — freshly generated secrets
  | { t: 'pub'; of: Term } //  pk(X) — public key of identity X (public)
  | { t: 'priv'; of: Term } //  sk(X) — private key of X (secret to X)
  | { t: 'pair'; l: Term; r: Term } //  <m1, m2>
  | { t: 'enc'; m: Term; k: Term } //  {m}_k — asymmetric encryption under key k
  | { t: 'sig'; m: Term; by: Term } //  [m]_sk(X) — signature by X, verifiable with pk(X)
  | { t: 'dh'; x: Term } //  g^x — a Diffie-Hellman public share
  | { t: 'kdf'; a: Term; b: Term } //  shared key from two DH shares (stored canonically)
  | { t: 'var'; v: string; sort?: 'name' }; //  a pattern hole, bound during matching

// ---- constructors --------------------------------------------------------

export const name = (v: string): Term => ({ t: 'name', v });
export const nonce = (v: string): Term => ({ t: 'nonce', v });
export const pub = (of: Term): Term => ({ t: 'pub', of });
export const priv = (of: Term): Term => ({ t: 'priv', of });
export const pair = (l: Term, r: Term): Term => ({ t: 'pair', l, r });
export const enc = (m: Term, k: Term): Term => ({ t: 'enc', m, k });
export const sig = (m: Term, by: Term): Term => ({ t: 'sig', m, by });
export const dh = (x: Term): Term => ({ t: 'dh', x });
export const v = (name: string): Term => ({ t: 'var', v: name });
export const vName = (name: string): Term => ({ t: 'var', v: name, sort: 'name' });

/** Left-nested tuple of >=2 terms: tuple(a,b,c) = <a,<b,c>>. */
export function tuple(...xs: Term[]): Term {
  if (xs.length < 2) throw new Error('tuple needs >= 2 terms');
  return xs.reduceRight((acc, x) => (acc === null ? x : pair(x, acc)), null as Term | null)!;
}

/**
 * A DH shared key is symmetric in its two shares: g^(ab) = g^(ba). That single
 * equation is the *only* algebraic property this model builds in (the brief's
 * stated limitation — no XOR, no partial-DH unification). We encode it by
 * storing the two shares in a canonical order, so kdf(x,y) and kdf(y,x) are the
 * *same* term. Everything else is free term algebra with no equations.
 */
export function kdf(a: Term, b: Term): Term {
  return canon(a) <= canon(b) ? { t: 'kdf', a, b } : { t: 'kdf', a: b, b: a };
}

// ---- canonical string form (equality, hashing, ordering) -----------------

/** A stable, injective string encoding. Two terms are equal iff canon-equal. */
export function canon(term: Term): string {
  switch (term.t) {
    case 'name':
      return `n:${term.v}`;
    case 'nonce':
      return `N:${term.v}`;
    case 'pub':
      return `pk(${canon(term.of)})`;
    case 'priv':
      return `sk(${canon(term.of)})`;
    case 'var':
      return `?${term.sort === 'name' ? 'n' : ''}:${term.v}`;
    case 'pair':
      return `<${canon(term.l)},${canon(term.r)}>`;
    case 'enc':
      return `{${canon(term.m)}}[${canon(term.k)}]`;
    case 'sig':
      return `[${canon(term.m)}]sig(${canon(term.by)})`;
    case 'dh':
      return `g^(${canon(term.x)})`;
    case 'kdf':
      return `kdf(${canon(term.a)},${canon(term.b)})`;
  }
}

export const eq = (a: Term, b: Term): boolean => canon(a) === canon(b);

export function isGround(term: Term): boolean {
  switch (term.t) {
    case 'var':
      return false;
    case 'name':
    case 'nonce':
      return true;
    case 'pub':
    case 'priv':
      return isGround(term.of);
    case 'pair':
      return isGround(term.l) && isGround(term.r);
    case 'enc':
      return isGround(term.m) && isGround(term.k);
    case 'sig':
      return isGround(term.m) && isGround(term.by);
    case 'dh':
      return isGround(term.x);
    case 'kdf':
      return isGround(term.a) && isGround(term.b);
  }
}

/** Every var name appearing in a term. */
export function vars(term: Term, acc: Set<string> = new Set()): Set<string> {
  switch (term.t) {
    case 'var':
      acc.add(term.v);
      break;
    case 'pub':
    case 'priv':
      vars(term.of, acc);
      break;
    case 'pair':
      vars(term.l, acc);
      vars(term.r, acc);
      break;
    case 'enc':
      vars(term.m, acc);
      vars(term.k, acc);
      break;
    case 'sig':
      vars(term.m, acc);
      vars(term.by, acc);
      break;
    case 'dh':
      vars(term.x, acc);
      break;
    case 'kdf':
      vars(term.a, acc);
      vars(term.b, acc);
      break;
    default:
      break;
  }
  return acc;
}

// ---- human-readable pretty-printing (for the UI and traces) --------------

/** Compact math-like rendering: {Na, A}_pkB, [g^b]_skB, K(g^a, g^b). */
export function pretty(term: Term): string {
  switch (term.t) {
    case 'name':
      return term.v;
    case 'nonce':
      return term.v;
    case 'pub':
      return `pk${bare(term.of)}`;
    case 'priv':
      return `sk${bare(term.of)}`;
    case 'var':
      return `?${term.v}`;
    case 'pair':
      return flattenTuple(term).map(pretty).join(', ');
    case 'enc':
      return `{${pretty(term.m)}}_${pretty(term.k)}`;
    case 'sig':
      return `[${pretty(term.m)}]_sk${bare(term.by)}`;
    case 'dh':
      return `g^${pretty(term.x)}`;
    case 'kdf':
      return `K(${pretty(term.a)}, ${pretty(term.b)})`;
  }
}

// Render an identity inside a key label without noise: pkA, not pk(A).
function bare(term: Term): string {
  return term.t === 'name' || term.t === 'nonce' ? term.v : term.t === 'var' ? `?${term.v}` : pretty(term);
}

function flattenTuple(term: Term): Term[] {
  const out: Term[] = [];
  let cur: Term = term;
  while (cur.t === 'pair') {
    out.push(cur.l);
    cur = cur.r;
  }
  out.push(cur);
  return out;
}
