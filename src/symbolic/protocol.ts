/**
 * protocol.ts — how a protocol is described to the checker.
 *
 * A protocol is a fixed set of role *instances* (a bounded scenario: e.g. "one
 * honest initiator A talking to M, one honest responder B"). Each instance is a
 * straight-line sequence of send / recv steps over terms. Receive steps carry
 * pattern variables that get bound when a message arrives. Fresh values (an
 * agent's own nonce) are written as concrete nonces unique to the instance.
 *
 * The search (search.ts) is generic over this description — it knows nothing
 * about Needham-Schroeder specifically. Swap message 2's shape and the same
 * search that finds Lowe's attack reports "secure in bound"; that one-field
 * edit is the whole point of the lab.
 */

import {
  Term,
  enc,
  pub,
  name,
  nonce,
  tuple,
  v,
  vName,
  dh,
  kdf,
  sig,
} from './terms.ts';

export interface Step {
  dir: 'send' | 'recv';
  msg: Term;
}

export interface InstanceDef {
  actor: string; //  the honest agent playing this role
  role: string; //  'Initiator' / 'Responder' — display label
  peer?: string; //  intended peer, for display only
  steps: Step[];
}

export interface Protocol {
  id: string;
  title: string;
  spec: string; //  short spec label (year / citation)
  blurb: string; //  one plain sentence: what this protocol is
  attacker: string; //  the network attacker's identity
  names: string[]; //  all principal identities in the model
  corrupt: string[]; //  identities whose private key the attacker holds
  attackerTerms?: Term[]; //  extra terms the attacker starts with (e.g. its own DH exponent)
  instances: InstanceDef[];
  goal: Term; //  reachability target: "attacker learns this term"
  goalDesc: string; //  plain description of the goal
  // Secrecy is only meaningful when the secret's owner believes it is talking to
  // an HONEST peer. If a responder knowingly runs a session with the corrupt
  // party, that party learning the nonce is no violation. This guard says: the
  // attack counts only if `instance` bound `varName` to one of `honest`.
  guard?: { instance: number; varName: string; honest: string[] };
  expected: 'attack' | 'secure';
  secureReason?: string; //  concrete mechanism when the verdict is "secure"
  bound: number; //  state-exploration cap (displayed)
  scenario: string; //  one line describing the bounded scenario
  whatItIsnt: string; //  the "what this isn't" note (SCOPE guard)
}

const N = (s: string) => name(s);
const Non = (s: string) => nonce(s);

/**
 * Needham-Schroeder Public Key (1978) and Lowe's fix (1995) differ in exactly
 * one message. `lowe=false` is the original; `lowe=true` adds the responder's
 * identity to message 2 — the field whose absence let Lowe's attack stand for
 * seventeen years.
 */
export function needhamSchroeder(lowe: boolean): Protocol {
  // Message 2, as the responder sends it and as the initiator expects it.
  const respMsg2 = lowe
    ? enc(tuple(v('na'), Non('Nb'), name('B')), pub(vName('I')))
    : enc(tuple(v('na'), Non('Nb')), pub(vName('I')));
  const initMsg2 = lowe
    ? enc(tuple(Non('Na'), v('nb'), N('M')), pub(N('A')))
    : enc(tuple(Non('Na'), v('nb')), pub(N('A')));

  const initiator: InstanceDef = {
    actor: 'A',
    role: 'Initiator',
    peer: 'M',
    steps: [
      // A starts a session with M (a legitimate party she chooses to talk to).
      { dir: 'send', msg: enc(tuple(Non('Na'), N('A')), pub(N('M'))) },
      { dir: 'recv', msg: initMsg2 },
      { dir: 'send', msg: enc(v('nb'), pub(N('M'))) },
    ],
  };
  const responder: InstanceDef = {
    actor: 'B',
    role: 'Responder',
    peer: 'A',
    steps: [
      { dir: 'recv', msg: enc(tuple(v('na'), vName('I')), pub(N('B'))) },
      { dir: 'send', msg: respMsg2 },
      { dir: 'recv', msg: enc(Non('Nb'), pub(N('B'))) },
    ],
  };

  return {
    id: lowe ? 'ns-lowe' : 'ns-pk',
    title: lowe ? 'Needham-Schroeder-Lowe' : 'Needham-Schroeder Public Key',
    spec: lowe ? 'Lowe fix · 1995' : 'NSPK · 1978',
    blurb: lowe
      ? 'The 1995 repair: message 2 now names the responder, so a relayed reply no longer type-checks for the initiator.'
      : 'A two-nonce mutual-authentication handshake using public-key encryption — the protocol everyone had read.',
    attacker: 'M',
    names: ['A', 'B', 'M'],
    corrupt: ['M'],
    instances: [initiator, responder],
    goal: Non('Nb'),
    // The leak only counts when B thinks it is talking to an honest agent (A),
    // not when B knowingly runs a session with M.
    guard: { instance: 1, varName: 'I', honest: ['A', 'B'] },
    goalDesc: "the attacker learns Nb, the responder's secret nonce, while the responder believes it is talking to honest A",
    expected: lowe ? 'secure' : 'attack',
    secureReason: lowe
      ? 'Message 2 now carries B. A checks that field against her actual peer M — the relayed reply names B, not M, so it no longer matches and A halts. The attacker cannot forge {Na, Nb, M}_pkA because it never learns Nb.'
      : undefined,
    bound: 60000,
    scenario: 'Honest A initiates a session with M; honest B runs as responder. One session each.',
    whatItIsnt: lowe
      ? "This isn't a proof the protocol is secure — only that no attack exists in this bounded scenario and model."
      : "This isn't a claim the encryption broke: it never does. The protocol logic leaks the nonce.",
  };
}

/**
 * Unauthenticated Diffie-Hellman and its signed repair. The only algebraic fact
 * the model builds in is g^(ab) = g^(ba) (canonical DH key, see terms.ts). The
 * naive version has nothing binding a share to its sender, so the attacker sits
 * in the middle; the signed version binds each share with a signature the
 * attacker cannot forge.
 */
export function diffieHellman(signed: boolean): Protocol {
  // A's outgoing share g^Na (+ signature, if signed); B's, similarly. The peer
  // share A accepts is written g^?q so its exponent q is captured — the key A
  // derives is then K(Na, q) = (g^q)^Na, never a function of the two public
  // shares alone (that would violate the CDH assumption; see canSynth in
  // intruder.ts).
  const aShare = signed ? tuple(dh(Non('Na')), sig(dh(Non('Na')), N('A'))) : dh(Non('Na'));
  const bShare = signed ? tuple(dh(Non('Nb')), sig(dh(Non('Nb')), N('B'))) : dh(Non('Nb'));
  const aExpects = signed ? tuple(dh(v('q')), sig(dh(v('q')), N('B'))) : dh(v('q'));
  const bExpects = signed ? tuple(dh(v('p')), sig(dh(v('p')), N('A'))) : dh(v('p'));

  const initiator: InstanceDef = {
    actor: 'A',
    role: 'Initiator',
    peer: 'B',
    steps: [
      { dir: 'send', msg: aShare },
      { dir: 'recv', msg: aExpects },
      // A sends a secret under the key she derives from her exponent + the
      // received share's exponent.
      { dir: 'send', msg: enc(Non('S'), kdf(Non('Na'), v('q'))) },
    ],
  };
  const responder: InstanceDef = {
    actor: 'B',
    role: 'Responder',
    peer: 'A',
    steps: [
      { dir: 'recv', msg: bExpects },
      { dir: 'send', msg: bShare },
    ],
  };

  return {
    id: signed ? 'dh-signed' : 'dh-naive',
    title: signed ? 'Signed Diffie-Hellman' : 'Naive Diffie-Hellman',
    spec: signed ? 'authenticated DH' : 'unauthenticated DH',
    blurb: signed
      ? 'Each DH share is signed by its sender, so a substituted share fails signature verification.'
      : 'A raw DH exchange with no authentication on the public shares.',
    attacker: 'M',
    names: ['A', 'B', 'M'],
    corrupt: ['M'],
    // The attacker owns a DH exponent m and its public share g^m — a legitimate
    // participant's material, not a break of anyone's secret.
    attackerTerms: [Non('m'), dh(Non('m'))],
    instances: [initiator, responder],
    goal: Non('S'),
    goalDesc: 'the attacker learns S, the secret A sends under the "shared" key',
    expected: signed ? 'secure' : 'attack',
    secureReason: signed
      ? "A now accepts a share only with a valid signature by B over that exact share. The attacker holds no sk(B), so it cannot swap in its own share — it can only forward B's genuine one, and then it cannot compute the resulting key."
      : undefined,
    bound: 60000,
    scenario: 'Honest A and B attempt a key exchange; A then sends secret S under the derived key.',
    whatItIsnt: signed
      ? "This isn't a guarantee against every DH attack — only this bounded scenario, and only the g^ab=g^ba equation is modelled."
      : "This isn't the discrete-log break: the exponents stay secret. Authentication is what's missing.",
  };
}

export const PROTOCOLS: Protocol[] = [
  needhamSchroeder(false),
  needhamSchroeder(true),
  diffieHellman(false),
  diffieHellman(true),
];

export function protocolById(id: string): Protocol {
  const p = PROTOCOLS.find((x) => x.id === id);
  if (!p) throw new Error(`unknown protocol ${id}`);
  return p;
}
