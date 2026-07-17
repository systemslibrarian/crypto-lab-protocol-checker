import { describe, it, expect } from 'vitest';
import { explainRepair } from './explain.ts';
import { needhamSchroeder, diffieHellman } from './protocol.ts';

/**
 * The secure verdict must be EARNED by the engine, not asserted. These lock the
 * derived repair diagnostic: the conflicting field / unforgeable credential are
 * computed by unify + canSynth over the real protocol terms.
 */

describe('derived repair diagnostic — Needham-Schroeder-Lowe', () => {
  const d = explainRepair(needhamSchroeder(false), needhamSchroeder(true))!;

  it('derives the diagnostic (does not fall back to null)', () => {
    expect(d).not.toBeNull();
  });

  it('identifies the exact field that now disagrees: M expected, B relayed', () => {
    expect(d.relayConflict).toEqual({ expected: 'M', got: 'B' });
  });

  it('confirms the attacker still cannot obtain the goal nonce', () => {
    expect(d.goalUnobtainable).toBe(true);
    expect(d.goalText).toBe('Nb');
  });

  it('the honest reply now names the responder', () => {
    expect(d.honestReply).toContain('B');
  });
});

describe('derived repair diagnostic — Signed Diffie-Hellman', () => {
  const d = explainRepair(diffieHellman(false), diffieHellman(true))!;

  it('derives the diagnostic', () => {
    expect(d).not.toBeNull();
  });

  it('the obstacle is a signature the attacker cannot forge', () => {
    expect(d.synthesisObstacle).toBeTruthy();
    expect(d.synthesisObstacle!.needed).toContain('skB');
    expect(d.synthesisObstacle!.reason).toContain('skB');
  });

  it('confirms the secret stays out of reach', () => {
    expect(d.goalUnobtainable).toBe(true);
    expect(d.goalText).toBe('S');
  });
});
