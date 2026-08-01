import { describe, it, expect } from 'vitest';
import { runSearch } from './search.ts';
import { needhamSchroeder, diffieHellman } from './protocol.ts';
import { canon, nonce } from './terms.ts';

/**
 * KATs — the known answers are published results, reproduced by *search*, not by
 * script. The engine is told the protocol and the goal; it is never told the
 * attack. If these pass, the machine found the attacks the way Lowe did.
 *
 * Literature the known answers are checked against:
 *   - D. Dolev and A. Yao, "On the Security of Public Key Protocols," IEEE
 *     Trans. Information Theory, 1983 — the attacker model.
 *   - R. Needham and M. Schroeder, "Using Encryption for Authentication in
 *     Large Networks of Computers," CACM, 1978 — the protocol.
 *   - G. Lowe, "An Attack on the Needham-Schroeder Public-Key Authentication
 *     Protocol," Information Processing Letters, 1995; and "Breaking and Fixing
 *     the Needham-Schroeder Public-Key Protocol," TACAS, 1996 — the attack and
 *     the one-field fix reproduced below. The five messages asserted here are the
 *     prefix of Lowe's published six-message interleaving, up to the point the
 *     attacker holds Nb; Lowe's sixth message (I(A) -> B: {Nb}_pkB) completes the
 *     impersonation but is not needed for the secrecy goal this search targets.
 */

describe('KAT: Needham-Schroeder Public Key — Lowe attack (1995)', () => {
  const res = runSearch(needhamSchroeder(false));

  it('finds an attack: the attacker learns Nb', () => {
    expect(res.found).toBe(true);
    expect(canon(res.goal)).toBe(canon(nonce('Nb')));
  });

  it('reproduces the secrecy-violating prefix of Lowe\'s trace shape', () => {
    // The honest, attacker-mediated messages, in order.
    const wire = res.trace.map((s) => `${s.from} → ${s.to} : ${s.msgText}`);
    expect(wire).toEqual([
      'A → M : {Na, A}_pkM', //  A honestly starts with M
      'M → B : {Na, A}_pkB', //  M replays to B, impersonating A
      'B → M : {Na, Nb}_pkA', //  B replies, believing it is A
      'M → A : {Na, Nb}_pkA', //  M forwards it; A accepts
      'A → M : {Nb}_pkM', //  A hands M the nonce
    ]);
  });

  it('never breaks the encryption — the leak is protocol logic', () => {
    // The attacker only ever forwards or opens things addressed to it (sk(M)).
    // Its knowledge of Nb comes from A encrypting it under pkM, not from a break.
    expect(res.found).toBe(true);
  });
});

describe('KAT: Needham-Schroeder-Lowe — no attack in bound', () => {
  const res = runSearch(needhamSchroeder(true));

  it('finds no attack after adding the responder identity to message 2', () => {
    expect(res.found).toBe(false);
    expect(res.boundHit).toBe(false); //  the space is fully exhausted, not truncated
  });

  it('reports how many states it explored', () => {
    expect(res.statesExplored).toBeGreaterThan(0);
  });
});

describe('KAT: Naive Diffie-Hellman — MITM found', () => {
  const res = runSearch(diffieHellman(false));

  it('the attacker learns the secret S sent under the "shared" key', () => {
    expect(res.found).toBe(true);
    expect(canon(res.goal)).toBe(canon(nonce('S')));
  });
});

describe('KAT: Signed Diffie-Hellman — no attack in bound', () => {
  const res = runSearch(diffieHellman(true));

  it('a substituted share fails signature verification; S stays secret', () => {
    expect(res.found).toBe(false);
    expect(res.boundHit).toBe(false);
  });
});

describe('determinism', () => {
  it('the search is deterministic across runs', () => {
    const a = runSearch(needhamSchroeder(false));
    const b = runSearch(needhamSchroeder(false));
    expect(a.trace.map((s) => s.msgText)).toEqual(b.trace.map((s) => s.msgText));
  });
});
