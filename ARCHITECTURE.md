# Architecture

A single-page definition of the symbolic model this lab implements, so the engine can be read against one reference rather than reverse-engineered from four files. Everything lives in `src/symbolic/`; the UI in `src/ui.ts` only renders results.

## The model in one paragraph

A protocol is a fixed set of honest role **instances** (a bounded scenario). The **attacker owns the network**: every message an honest instance sends is added to the attacker's knowledge, and every message an honest instance receives must be one the attacker can **produce**. Cryptography is **perfect** — an encryption is an opaque term that opens only with the matching key. The checker searches the reachable states for one in which the attacker can synthesise a designated **goal** term. If it finds one, the path to it is an attack; if the frontier empties within the bound, the verdict is "no attack in bound."

## Terms (`terms.ts`)

```
Term ::= name(x) | nonce(x) | pub(T) | priv(T)
       | pair(T, T) | enc(T, T) | sig(T, by:T)
       | dh(T) | kdf(T, T) | var(x, sort?)
```

- `pub`/`priv` take a **term** (not a string) so `pk(?I)` — the public key of a *variable* identity — is expressible; the responder replies under the initiator identity it just bound.
- `kdf(a, b)` is stored in canonical share order, encoding the one modelled equation **g^ab = g^ba**. No other equational theory (no XOR, no partial-DH unification).
- `canon(t)` is an injective string encoding; term equality is canon-equality. `var` with `sort: 'name'` is an identity hole that may only bind to an agent name (a standard typed-model restriction that keeps the search finite).

## Unification (`unify.ts`)

Standard first-order unification with occurs-check, over a substitution `Subst = Map<varName, Term>`. `unify(pattern, message)` is how a role decides whether an incoming message matches the pattern it awaits, binding the pattern's holes. `kdf` unifies up to share symmetry. This is also what makes relaying possible: the attacker unifies an initiator's waiting pattern against an opaque ciphertext it intercepted, binding a hole to a value it never learned.

## The attacker (`intruder.ts`)

Knowledge is a set of **facts** (`{term, rule, from}`), closed under **analysis** to a fixpoint and queried under **synthesis** on demand.

| Phase | Rule | Meaning |
|-------|------|---------|
| Analysis | `SPLIT` | from `⟨m1, m2⟩` derive `m1`, `m2` |
| Analysis | `DEC` | from `{m}_pk(X)` and `sk(X)` derive `m`; from `{m}_k` and a derivable symmetric key `k` derive `m` |
| Synthesis | `PAIR` | pair two known terms |
| Synthesis | `ENC` | encrypt a known term under any (public) key |
| Synthesis | `SIGN` | sign, only with a private key the attacker holds |
| Synthesis | `DH` | `g^x` from a known exponent `x` |
| Synthesis | `KDF` | a DH key `g^ab` from **one exponent and the other's share** — never from the two public shares alone (the CDH assumption) |
| Synthesis | `FWD` | forward any term already held (the opaque relay) |
| Axiom | `PUB` | all names and public keys are public |

`produce(pattern, subst, knowledge)` enumerates the substitutions under which `pattern` becomes a ground message the attacker can deliver — by forwarding a held term that unifies, or constructing the pattern by its head symbol. This is the attacker's move set at a receive step.

## The search (`search.ts`)

A **state** is `(progress per instance, bindings per instance, attacker knowledge)`. From a state:

- an instance whose next step is a **send** emits its (now ground) message; the attacker intercepts it — one deterministic successor;
- an instance whose next step is a **receive** fires once per `produce` result — one successor per deliverable message.

The search is **breadth-first**, deduplicating on the full canonical state, until the attacker can synthesise the goal (with an optional honesty **guard**: the leak only counts if the victim believed it was talking to an honest peer) or the frontier empties or the state **bound** is hit. Because it is breadth-first, a returned trace is a *shortest* attack. The bound is displayed; "no attack found" is always relative to it.

## The repair diagnostic (`explain.ts`)

For a secure verdict, the reason is **derived, not asserted**: given the vulnerable and repaired variants, it locates the initiator's pivotal receive and shows — via `unify` and `canSynth` on the real terms — either the field where the relayed reply no longer matches (`M` vs `B`), or the credential the attacker cannot forge (`[g^m]_skB`), plus confirmation the goal term is not in the attacker's knowledge.

## What is deliberately out of scope

Unbounded verification; a ProVerif/Tamarin input language; equational theories beyond `g^ab = g^ba`; protocol authoring; and computational (game-hopping) proofs, which are a different discipline (CryptoVerif's branch). See the in-page "What this is not" panel and the README.

## Test surface

- `*.test.ts` colocated in `src/symbolic/`: unit tests per module, 4 published-result KATs (`search.test.ts`), the derived-diagnostic checks (`explain.test.ts`), and randomized invariant/property tests (`properties.test.ts`: unification soundness, analysis monotonicity/idempotence, DH-key commutativity, search determinism, and bound-monotonicity).
- `e2e/a11y.spec.ts`: axe WCAG 2.1 AA gate over the driven production build, both themes.
