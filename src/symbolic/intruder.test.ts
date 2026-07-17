import { describe, it, expect } from 'vitest';
import { name, nonce, pub, priv, enc, sig, dh, tuple, v, vName, canon } from './terms.ts';
import { analyse, canSynth, closureSet, produce, baseKnowledge, Fact } from './intruder.ts';
import { emptySubst, apply } from './unify.ts';

const facts = (...ts: ReturnType<typeof nonce>[]): Fact[] => ts.map((term) => ({ term, rule: 'given' as const, from: [] }));

describe('intruder analysis (what the attacker can take apart)', () => {
  it('splits pairs', () => {
    const closure = closureSet(facts(tuple(nonce('X'), nonce('Y'))));
    expect(closure.has(canon(nonce('X')))).toBe(true);
    expect(closure.has(canon(nonce('Y')))).toBe(true);
  });

  it('decrypts only with the matching private key', () => {
    const cipher = enc(nonce('S'), pub(name('M')));
    const withKey = analyse([...facts(), { term: cipher, rule: 'given', from: [] }, { term: priv(name('M')), rule: 'given', from: [] }]);
    expect(withKey.some((f) => canon(f.term) === canon(nonce('S')))).toBe(true);

    const noKey = analyse([{ term: cipher, rule: 'given', from: [] }]);
    expect(noKey.some((f) => canon(f.term) === canon(nonce('S')))).toBe(false);
  });

  it('cannot recover a plaintext from a ciphertext it cannot open (perfect crypto)', () => {
    const cipher = enc(nonce('Nb'), pub(name('A'))); //  no sk(A)
    const closure = closureSet([{ term: cipher, rule: 'given', from: [] }]);
    // Ciphertext is held (can be forwarded) but the plaintext is NOT derivable.
    expect(closure.has(canon(cipher))).toBe(true);
    expect(closure.has(canon(nonce('Nb')))).toBe(false);
  });
});

describe('intruder synthesis (what the attacker can build)', () => {
  it('can encrypt under any public key but cannot invent a secret nonce', () => {
    const base = baseKnowledge(['A', 'B'], []);
    const closure = closureSet(base);
    const terms = base.map((f) => f.term);
    expect(canSynth(enc(name('A'), pub(name('B'))), closure, terms)).toBe(true);
    expect(canSynth(nonce('secret'), closure, terms)).toBe(false);
  });

  it('cannot forge a signature without the signer key, but can sign as a corrupt party', () => {
    const base = baseKnowledge(['A', 'B', 'M'], ['M']);
    const closure = closureSet(base);
    const terms = base.map((f) => f.term);
    // A share signed by honest B: unforgeable (no sk(B)).
    expect(canSynth(sig(dh(nonce('m')), name('B')), closure, terms)).toBe(false);
    // The attacker holds sk(M), so it can sign as itself — but that fools no one
    // who checks for B's signature.
    const withExp = [...base, { term: nonce('m'), rule: 'given' as const, from: [] }];
    const c2 = closureSet(withExp);
    expect(canSynth(sig(dh(nonce('m')), name('M')), c2, withExp.map((f) => f.term))).toBe(true);
  });
});

describe('produce (relay is the crux of Lowe)', () => {
  it('forwards an opaque ciphertext, binding a hole to a value it never learned', () => {
    // Attacker holds {Na, Nb}_pkA but has no sk(A): it cannot read Nb.
    const held = enc(tuple(nonce('Na'), nonce('Nb')), pub(name('A')));
    const base: Fact[] = [{ term: held, rule: 'intercept', from: [] }];
    // The initiator waits for {Na, ?nb}_pkA.
    const pattern = enc(tuple(nonce('Na'), v('nb')), pub(name('A')));
    const subs = produce(pattern, emptySubst(), base);
    expect(subs.length).toBeGreaterThan(0);
    // The bound value is Nb — relayed, not decrypted.
    expect(subs.some((s) => canon(apply(v('nb'), s)) === canon(nonce('Nb')))).toBe(true);
    // And the attacker never actually learned Nb.
    expect(closureSet(base).has(canon(nonce('Nb')))).toBe(false);
  });

  it('constructs a fresh ciphertext for a receiver from parts it knows', () => {
    // Attacker knows Na and identity A, and everyone's public key.
    const base = baseKnowledge(['A', 'B', 'M'], ['M']);
    base.push({ term: nonce('Na'), rule: 'given', from: [] });
    // Responder B waits for {?na, ?I}_pkB.
    const pattern = enc(tuple(v('na'), vName('I')), pub(name('B')));
    const subs = produce(pattern, emptySubst(), base);
    // It can build {Na, A}_pkB (Na it knows, A is a public name).
    const built = subs.some((s) => canon(apply(v('na'), s)) === canon(nonce('Na')) && canon(apply(vName('I'), s)) === canon(name('A')));
    expect(built).toBe(true);
  });
});
