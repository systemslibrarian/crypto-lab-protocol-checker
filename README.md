# Protocol Checker

**Dolev-Yao symbolic analysis · automated attack discovery**

A protocol you believe is correct, handed to a symbolic model checker that returns the exact message sequence that breaks it — found by searching, not by being told.

> Not production crypto — a teaching demo. The symbolic engine and the attacks it finds are real, but the model is a deliberate abstraction. See **What Can Go Wrong** for exactly what it does and does not prove.

## What It Is

The **Dolev-Yao model** (1983) treats every message as a *term* — a tree of names, nonces, keys, pairs, and encryptions — and cryptography as *perfect*: an encryption `{m}_k` is an opaque box that opens only with the matching key. The attacker owns the network. It intercepts every message and can send anything it can assemble from what it has seen (forward, split apart, re-encrypt with keys it holds) — but it cannot guess a nonce or open a ciphertext addressed to someone else.

Under that model, a protocol is secure only if — across every interleaving of sessions and every message the attacker can compose — no secret ever reaches it. That is a reachability question over an unbounded state space, so we bound it and let a machine enumerate. This lab hand-rolls the whole engine so every part is inspectable:

- **`src/symbolic/terms.ts`** — the term algebra and the one modelled equation (`g^ab = g^ba`).
- **`src/symbolic/unify.ts`** — first-order unification with occurs-check (how a role matches an incoming message).
- **`src/symbolic/intruder.ts`** — the attacker: analysis (`DEC`, `SPLIT`) and synthesis (`PAIR`, `ENC`, `SIGN`, `DH`, `KDF`, `FWD`), each a named rule.
- **`src/symbolic/search.ts`** — the bounded reachability search (breadth-first, deterministic).

The headline result is **Lowe's 1995 attack on Needham-Schroeder Public Key**, rediscovered live: the machine is told the protocol and the goal, never the attack.

**Security model:** symbolic / perfect-cryptography, bounded sessions, in the ProVerif/Tamarin lineage — *not* a computational (provable-security) analysis. **Not production tooling.**

## Exhibits

1. **The checker.** Pick a protocol, press Run, and watch the real search either return an attack trace or exhaust the space. The explored-state counter is the true number of reachable states visited; the bound is shown.
2. **Verdict separation.** Two independent indicators. *Cryptographic primitive: perfect — unbroken* (the maths never breaks in this model) sits beside *Security verdict: ATTACK FOUND / no attack in bound*. A forged-but-accepted outcome reads as **alarm**, never green — colour tracks system integrity, not the raw return value.
3. **The Lowe attack, discovered live.** Load Needham-Schroeder Public Key, set the goal "can the attacker learn Nb?", and run. The trace comes back:

   ```
   A → M : {Na, A}_pkM     A honestly starts a session with M
   M → B : {Na, A}_pkB     M replays it to B, impersonating A
   B → M : {Na, Nb}_pkA    B responds, believing it is A
   M → A : {Na, Nb}_pkA    M forwards it; A accepts, it is addressed to her
   A → M : {Nb}_pkM        A hands M the nonce
   ```
4. **The two-session diagram.** The trace, redrawn as three lanes — honest initiator, attacker, honest responder — with each message tinted by which of the attacker's *two* sessions it belongs to. You watch M forward the same opaque ciphertext out of one session and into the other, and the deceived party's belief ("believes peer = A · actually M") is shown in alarm. Synced to the stepper.
5. **The fix, in one edit.** Tick *"Message 2 includes the responder's identity B"* — Lowe's 1995 repair — and re-run the identical search. No trace found; the verdict explains *why* the relay now fails. One field closes a seventeen-year-old flaw.
6. **The attacker-knowledge panel.** Step through the trace and watch the attacker's known-term set grow. Every term names the rule that derived it (`intercept`, `DEC`, `SPLIT`, …), and the leaked goal is flagged — so nothing here is magic; every deduction is auditable.
7. **Visible search work.** The status line reports the real numbers: reachable states explored, candidate attacker injections weighed, and interleaving depth — evidence the attack was *enumerated*, not scripted. An expandable note lays out the state, the transition relation, and the deduction rules for the curious.
8. **The protocol library.** Needham-Schroeder PK (attack), Needham-Schroeder-Lowe (secure in bound), Naive Diffie-Hellman (MITM found), Signed Diffie-Hellman (secure in bound), and a toy Kerberos entry that links to the sibling **crypto-lab-kerberos** lab rather than rebuilding it.
9. **The honesty panel.** Up top, not buried: this checker assumes perfect cryptography, so "no attack found" means only "no attack in this model, within this bound." It links the side-channel and implementation labs whose attacks it structurally cannot see.

## When to Use It

- To build intuition for **why symbolic analysis matters**: it searches the attack space you did not think of.
- To see the **precise distinction** between a protocol-logic flaw and a broken cipher — the cipher never breaks here.
- **Do NOT** use it to conclude a real protocol is secure. "No attack in bound" is not a proof, and the perfect-crypto abstraction hides entire attack classes (timing, padding, key recovery, implementation bugs). For those, see the linked labs.

## Live Demo

**https://systemslibrarian.github.io/crypto-lab-protocol-checker/**

Run the Needham-Schroeder search, read the attack trace, step the knowledge panel to watch the attacker derive `Nb`, then tick the Lowe fix and re-run to watch the attack vanish. Switch to Diffie-Hellman and toggle signatures to see the same story for key exchange.

## What Can Go Wrong

The model is an abstraction, and its limits are the point of the lab:

- **Perfect cryptography.** Encryption is opaque — no key recovery, no algebraic leakage, no side channels, no timing, no implementation bugs. Every attack in [timing-oracle](https://systemslibrarian.github.io/crypto-lab-timing-oracle/), [power-trace](https://systemslibrarian.github.io/crypto-lab-power-trace/), [kem-trap](https://systemslibrarian.github.io/crypto-lab-kem-trap/), and [padding-oracle](https://systemslibrarian.github.io/crypto-lab-padding-oracle/) is invisible to this checker.
- **Bounded search.** A finite number of sessions and states is explored; the bound is displayed. "No attack found" is always relative to it.
- **One equation only.** The single algebraic property modelled is `g^ab = g^ba` (a canonical unordered DH key). No XOR, no partial-DH unification, no broader equational theory.
- **Not provable security.** Symbolic analysis and computational (game-hopping) proofs are different disciplines; neither subsumes the other. CryptoVerif is the tool on the computational branch.

## Real-World Usage

The Dolev-Yao model underpins the industrial protocol verifiers **ProVerif** and **Tamarin**, which have been used to analyse TLS 1.3, Signal, WireGuard, EMV, and 5G-AKA — repeatedly finding real flaws before deployment. Lowe's 1995 discovery, using the FDR model checker, is the founding example this lab reproduces. This demo is a miniature, hand-rolled engine in that lineage, built for transparency rather than scale.

## How to Run Locally

```bash
npm install
npm run dev        # http://localhost:5173
npm test           # Vitest unit tests + spec KATs
npm run build      # typecheck + production build
npm run preview    # serve the production build on :4317
npm run test:a11y  # axe-core WCAG 2.1 AA gate, both themes (needs a build first)
```

## Related Demos

- [crypto-lab-diffie-hellman-mitm](https://systemslibrarian.github.io/crypto-lab-diffie-hellman-mitm/) — the DH man-in-the-middle, broken by hand; here a machine finds it.
- [crypto-lab-kerberos](https://systemslibrarian.github.io/crypto-lab-kerberos/) — carries a hand-built Lowe-style reflection panel.
- [crypto-lab-padding-oracle](https://systemslibrarian.github.io/crypto-lab-padding-oracle/) · [crypto-lab-timing-oracle](https://systemslibrarian.github.io/crypto-lab-timing-oracle/) — attacks this symbolic model structurally cannot see.

## Build & Verify

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for a one-page definition of the state transition system, the term algebra, and the attacker's deduction rules.

- **Unit, invariant & KAT tests: 52** (Vitest, colocated `src/**/*.test.ts`), run in CI before every deploy — including randomized property tests for unification soundness, analysis monotonicity, DH-key commutativity, search determinism, and bound-monotonicity, plus engine-derived repair-diagnostic checks.
- **Spec KATs: 4** — the published known answers, reproduced by *search*, not script (`src/symbolic/search.test.ts`):
  1. **Needham-Schroeder Public Key → Lowe's attack found**, matching the five-message prefix of Lowe's six-message interleaving, up to the point the attacker holds `Nb` (Lowe, 1995).
  2. **Needham-Schroeder-Lowe → no attack**, state space fully exhausted.
  3. **Naive Diffie-Hellman → MITM found** (the attacker learns the secret sent under the "shared" key).
  4. **Signed Diffie-Hellman → no attack**, a substituted share fails signature verification.
- **Accessibility gate:** `@axe-core/playwright` scans the production build for zero WCAG 2.1 A/AA violations in **both** themes, driving the full demo (attack, fix, DH, Kerberos link) so every dynamic region is scanned. The GitHub Pages deploy is blocked on any violation.

## Performance

The search is deterministic breadth-first over a small bounded scenario; every protocol resolves in a few thousand states and single-digit milliseconds. The explored-state counter animates the real count (respecting `prefers-reduced-motion`).

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
