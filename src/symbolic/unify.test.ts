import { describe, it, expect } from 'vitest';
import { name, nonce, pub, pair, enc, tuple, v, dh, kdf, canon } from './terms.ts';
import { unify, apply, emptySubst } from './unify.ts';

describe('unification', () => {
  it('binds a variable to a matching subterm', () => {
    const pat = enc(tuple(nonce('Na'), v('nb')), pub(name('A')));
    const msg = enc(tuple(nonce('Na'), nonce('Nb')), pub(name('A')));
    const s = unify(pat, msg);
    expect(s).not.toBeNull();
    expect(canon(apply(v('nb'), s!))).toBe(canon(nonce('Nb')));
  });

  it('fails when a fixed field disagrees (the Lowe fix in miniature)', () => {
    // Initiator expects the peer identity M in field 3; the relayed reply carries B.
    const expects = enc(tuple(nonce('Na'), v('nb'), name('M')), pub(name('A')));
    const relayed = enc(tuple(nonce('Na'), nonce('Nb'), name('B')), pub(name('A')));
    expect(unify(expects, relayed)).toBeNull();
  });

  it('unifies without the identity field (the original NSPK, attack stands)', () => {
    const expects = enc(tuple(nonce('Na'), v('nb')), pub(name('A')));
    const relayed = enc(tuple(nonce('Na'), nonce('Nb')), pub(name('A')));
    expect(unify(expects, relayed)).not.toBeNull();
  });

  it('enforces consistent bindings for a repeated variable', () => {
    const pat = tuple(v('x'), v('x'));
    expect(unify(pat, tuple(name('A'), name('A')))).not.toBeNull();
    expect(unify(pat, tuple(name('A'), name('B')))).toBeNull();
  });

  it('occurs-check rejects an infinite term', () => {
    expect(unify(v('x'), pair(v('x'), name('A')))).toBeNull();
  });

  it('unifies DH keys up to share symmetry', () => {
    const s = unify(kdf(dh(v('p')), dh(nonce('b'))), kdf(dh(nonce('a')), dh(nonce('b'))), emptySubst());
    expect(s).not.toBeNull();
    expect(canon(apply(v('p'), s!))).toBe(canon(nonce('a')));
  });
});
