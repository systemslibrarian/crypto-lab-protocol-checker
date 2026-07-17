import { describe, it, expect } from 'vitest';
import {
  name,
  nonce,
  pub,
  priv,
  pair,
  enc,
  sig,
  dh,
  kdf,
  tuple,
  v,
  canon,
  eq,
  isGround,
  vars,
  pretty,
} from './terms.ts';

describe('term algebra', () => {
  it('distinguishes atoms by kind and value', () => {
    expect(eq(name('A'), name('A'))).toBe(true);
    expect(eq(name('A'), name('B'))).toBe(false);
    // A name and a nonce with the same label are different terms.
    expect(eq(name('X'), nonce('X'))).toBe(false);
  });

  it('canon is structural and injective for constructors', () => {
    const t1 = enc(tuple(nonce('Na'), name('A')), pub(name('B')));
    const t2 = enc(tuple(nonce('Na'), name('A')), pub(name('B')));
    expect(canon(t1)).toBe(canon(t2));
    expect(canon(enc(nonce('Na'), pub(name('B'))))).not.toBe(canon(enc(nonce('Na'), pub(name('A')))));
  });

  it('models the DH symmetry g^(ab)=g^(ba) as a canonical unordered key', () => {
    const k1 = kdf(dh(nonce('a')), dh(nonce('b')));
    const k2 = kdf(dh(nonce('b')), dh(nonce('a')));
    expect(eq(k1, k2)).toBe(true);
  });

  it('tuple is right-nested pairing', () => {
    expect(eq(tuple(name('A'), name('B'), name('C')), pair(name('A'), pair(name('B'), name('C'))))).toBe(true);
  });

  it('tracks groundness and free variables', () => {
    expect(isGround(enc(nonce('Na'), pub(name('B'))))).toBe(true);
    expect(isGround(enc(v('x'), pub(name('B'))))).toBe(false);
    expect([...vars(enc(tuple(v('na'), v('nb')), pub(name('B'))))].sort()).toEqual(['na', 'nb']);
  });

  it('keys reference identity terms so pk(?I) is expressible', () => {
    expect(isGround(pub(v('I')))).toBe(false);
    expect(isGround(pub(name('A')))).toBe(true);
  });

  it('pretty-prints in compact math notation', () => {
    expect(pretty(enc(tuple(nonce('Na'), name('A')), pub(name('B'))))).toBe('{Na, A}_pkB');
    expect(pretty(sig(dh(nonce('a')), name('A')))).toBe('[g^a]_skA');
  });

  it('signatures require a matching signer identity to be equal', () => {
    expect(eq(sig(name('m'), name('A')), sig(name('m'), name('A')))).toBe(true);
    expect(eq(sig(name('m'), name('A')), sig(name('m'), name('B')))).toBe(false);
  });

  it('private keys are ground and distinct from public keys', () => {
    expect(eq(priv(name('A')), priv(name('A')))).toBe(true);
    expect(eq(priv(name('A')), pub(name('A')))).toBe(false);
  });
});
