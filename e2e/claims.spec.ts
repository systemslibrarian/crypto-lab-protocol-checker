import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Functional regression gate for the Protocol Checker demo.
 *
 * The a11y spec proves the page is reachable and scannable; this one proves the
 * page is *right*. The engine has unit tests and four KATs, so what is pinned
 * here is the part no unit test can see: that the rendered page tells the truth
 * about the search it just ran. Nothing is compared against a transcript of the
 * expected attack — every expectation is rebuilt from what the page itself put
 * on screen (the goal named in the scenario line, the lanes named in the ladder
 * head, the terms in the attacker-knowledge panel, the numbers in the status
 * line), so a wrong verdict cannot be papered over by a matching literal.
 *
 *   1. Verdict integrity. "ATTACK FOUND" is asserted to be exactly the verdict
 *      the page's own attacker-knowledge panel implies (goal term present and
 *      flagged), and the secure verdict is asserted against the engine-derived
 *      repair panel naming that same goal as unobtainable. The cryptographic
 *      indicator is pinned to stay "perfect — unbroken" under both, which is the
 *      README's "verdict separation" claim.
 *   2. Every non-success path the app has: the two attack verdicts (NSPK, naive
 *      DH), the two secure verdicts with their derived reason, and the
 *      link-only Kerberos entry whose Run control is inert — each asserted to
 *      reach the state AND to name its cause on screen.
 *   3. Counter consistency. Explored / injections / depth / bound are checked
 *      against each other and against the trace: interleaving depth equals the
 *      number of messages in the returned trace, the exhausted-vs-capped prose
 *      matches the numbers, the verdict note's state count matches the status
 *      line's, and re-running reproduces both exactly (the determinism claim).
 *   4. Trace fidelity. The relay that *is* Lowe's attack is located
 *      structurally — a ciphertext leaving one lane and entering the other
 *      unchanged — rather than by string-matching the published trace, and the
 *      ladder is checked to mirror the trace row for row.
 *   5. Stale state. Toggling the fix or switching protocol must retract the
 *      verdict, the trace, the ladder and the knowledge set immediately — and
 *      must keep them retracted when the counter animation of the abandoned run
 *      fires its reveal a moment later.
 *
 * Regression (fixed with this spec): at message 1 the knowledge panel marked
 * the attacker's entire public baseline — names, public keys, sk(M) — as "new
 * at this step", contradicting the same panel's own "before any message"
 * listing one click earlier. See "stepping the trace".
 *
 * The suite emulates reduced motion so the state counter lands on its true
 * value synchronously and every read is of a settled page; the animated reveal
 * gets its own describe block at the bottom.
 */

// ---- page-derived readers -------------------------------------------------

interface Wire {
  from: string;
  to: string;
  msg: string;
}

interface Known {
  term: string;
  rule: string;
  goal: boolean;
  fresh: boolean;
}

interface Counters {
  explored: number;
  injections: number;
  depth: number;
  bound: number;
}

const num = (s: string): number => Number(s.replace(/,/g, ''));

function parseWire(text: string): Wire {
  const m = /^(\S+)\s+→\s+(\S+)\s+:\s+(.+)$/.exec(text.trim());
  expect(m, `unparsable trace row: ${text}`).not.toBeNull();
  return { from: m![1], to: m![2], msg: m![3].trim() };
}

/** The trace as rows of (sender, recipient, message), read off the wire lines. */
async function wireRows(page: Page): Promise<Wire[]> {
  return (await page.locator('.trace li .wire').allTextContents()).map(parseWire);
}

/** The ladder diagram's rows, in the same shape, for row-for-row comparison. */
async function ladderRows(page: Page): Promise<Wire[]> {
  return page.locator('.ladder-rows li').evaluateAll((els) =>
    els.map((li) => ({
      endpoints: li.querySelector('.rung-endpoints')?.textContent?.trim() ?? '',
      msg: li.querySelector('.rung-msg')?.textContent?.trim() ?? '',
      cls: li.className,
    })),
  ).then((rows) =>
    rows.map((r) => {
      const m = /^(\S+)\s+→\s+(\S+)$/.exec(r.endpoints);
      expect(m, `unparsable ladder endpoints: ${r.endpoints}`).not.toBeNull();
      return { from: m![1], to: m![2], msg: r.msg };
    }),
  );
}

async function knowledge(page: Page): Promise<Known[]> {
  return page.locator('.knowledge li').evaluateAll((els) =>
    els.map((li) => ({
      term: li.querySelector('.term')?.textContent?.trim() ?? '',
      rule: li.querySelector('.rule')?.getAttribute('data-rule') ?? '',
      goal: !!li.querySelector('.goal-hit'),
      fresh: li.classList.contains('fresh'),
    })),
  );
}

/** The four numbers the status line publishes as the real work the search did. */
async function counters(page: Page): Promise<Counters> {
  const text = ((await page.locator('#search-status').textContent()) ?? '').trim();
  const m =
    /Explored ([\d,]+) reachable states — weighing ([\d,]+) candidate attacker injections down to depth (\d+) \(bound: ([\d,]+) states\)/.exec(
      text,
    );
  expect(m, `unparsable status line: ${text}`).not.toBeNull();
  return { explored: num(m![1]), injections: num(m![2]), depth: Number(m![3]), bound: num(m![4]) };
}

/** The secret the page says the search is hunting, taken from the scenario line. */
async function goalTerm(page: Page): Promise<string> {
  const text = ((await page.locator('.scenario-note').textContent()) ?? '').trim();
  const m = /does the attacker learn (\S+)\?/.exec(text);
  expect(m, `no goal in scenario note: ${text}`).not.toBeNull();
  return m![1];
}

/** The attacker's name, taken from the lane the diagram labels as the attacker. */
async function attackerLane(page: Page): Promise<string> {
  const head = page.locator('.ladder-head .lane-head').nth(1);
  await expect(head.locator('.lane-role')).toContainText('attacker');
  return ((await head.locator('.lane-name').textContent()) ?? '').trim();
}

const verdictBox = (page: Page): Locator => page.locator('.verdicts .indicator').nth(1);
const cryptoBox = (page: Page): Locator => page.locator('.verdicts .indicator--crypto');

/** Run the search and wait for the result to be on screen. */
async function runSearch(page: Page): Promise<void> {
  await page.locator('#run-btn').click();
  await expect(verdictBox(page)).not.toHaveClass(/indicator--idle/);
}

/** Select a protocol and set the one-field fix, from a clean idle state. */
async function select(page: Page, key: string, fix = false): Promise<void> {
  await page.locator('#proto-select').selectOption(key);
  if (fix) await page.locator('#fix-toggle').check();
  await expect(verdictBox(page)).toHaveClass(/indicator--idle/);
}

// Uncaught page exceptions fail the test that provoked them. Reset per test;
// a worker only ever runs one test at a time, so this stays test-scoped.
let pageErrors: string[] = [];

test.beforeEach(async ({ page }) => {
  pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(String(error)));
  // The app reads prefers-reduced-motion once, at module load, so the emulation
  // has to be in place before the first navigation. Under it the search result
  // is painted synchronously on click and every read below sees the settled
  // page rather than a frame of the counter animation.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  await expect(page.locator('#run-btn')).toBeVisible();
});

test.afterEach(() => {
  expect(pageErrors).toEqual([]);
});

test('the idle checker claims nothing until it is run', async ({ page }) => {
  await expect(verdictBox(page)).toHaveClass(/indicator--idle/);
  await expect(verdictBox(page)).toContainText('Not run yet');
  await expect(page.locator('#search-status')).toContainText('Idle.');
  await expect(page.locator('.trace li')).toHaveCount(0);
  await expect(page.locator('.ladder-rows li')).toHaveCount(0);
  await expect(page.locator('.knowledge li')).toHaveCount(0);
  await expect(page.locator('.repair-card')).toHaveCount(0);

  // The protocol on screen is the one the picker names, and the schema flags
  // the single message the one-field fix will rewrite.
  await expect(page.locator('#lab-body h3').first()).toHaveText('Protocol under test: Needham-Schroeder Public Key');
  await expect(page.locator('.schema li')).toHaveCount(3);
  await expect(page.locator('.schema li.changed')).toHaveCount(1);
  await expect(page.locator('#run-btn')).toBeEnabled();
});

test('the attack verdict is the verdict the attacker-knowledge panel implies', async ({ page }) => {
  const goal = await goalTerm(page);
  await runSearch(page);

  const facts = await knowledge(page);
  const goalFacts = facts.filter((f) => f.term === goal);

  // Recompute the headline from the page's own knowledge set: the attacker
  // reaches the goal iff the goal term is in it. Then require the rendered
  // verdict to be that verdict, not merely some alarming-looking string.
  const attackReached = goalFacts.length > 0;
  expect(attackReached).toBe(true);
  await expect(verdictBox(page)).toHaveText(new RegExp(attackReached ? 'ATTACK FOUND' : 'No attack in bound'));
  await expect(verdictBox(page)).toHaveClass(new RegExp(attackReached ? 'indicator--alarm' : 'indicator--ok'));

  // The goal is listed once and is the only term flagged as the goal, so the
  // "leaked" marker cannot be pointing at something else.
  expect(goalFacts).toHaveLength(1);
  expect(goalFacts[0].goal).toBe(true);
  expect(facts.filter((f) => f.goal).map((f) => f.term)).toEqual([goal]);

  // The verdict note names the same secret the scenario line set as the goal.
  await expect(verdictBox(page)).toContainText(`the attacker learns ${goal}`);
});

test('the leak is a decryption the attacker was entitled to do — the cipher never breaks', async ({ page }) => {
  const goal = await goalTerm(page);
  await runSearch(page);
  const rows = await wireRows(page);
  const attacker = await attackerLane(page);
  const facts = await knowledge(page);

  // README "verdict separation": an attack found never recolours the primitive
  // indicator, which keeps saying the maths held.
  await expect(cryptoBox(page)).toContainText('Perfect — unbroken');
  await expect(cryptoBox(page)).not.toHaveClass(/indicator--(alarm|ok)/);
  await expect(cryptoBox(page)).toContainText('No key was recovered');

  // Every derivation is auditable: the goal arrived by DEC, and the two inputs
  // that licence that DEC are both on screen — the attacker's own private key
  // in its knowledge, and a ciphertext addressed to that key on the wire.
  const goalFact = facts.find((f) => f.term === goal)!;
  expect(goalFact.rule).toBe('DEC');
  expect(facts.find((f) => f.term === `sk${attacker}`)?.rule).toBe('given');
  expect(rows.map((r) => r.msg)).toContain(`{${goal}}_pk${attacker}`);

  // And the secret never travelled in the clear: no message on the wire *is*
  // the goal, so it was not simply handed over.
  expect(rows.map((r) => r.msg)).not.toContain(goal);

  // Every non-baseline fact names the rule that produced it (README exhibit 6).
  const rules = new Set(facts.map((f) => f.rule));
  expect([...rules].sort()).toEqual(['DEC', 'PUB', 'SPLIT', 'given', 'intercept']);
});

test('the trace is a relay: every message crosses the attacker and one ciphertext is forwarded verbatim', async ({
  page,
}) => {
  await runSearch(page);
  const rows = await wireRows(page);
  expect(rows.length).toBeGreaterThan(0);
  const attacker = await attackerLane(page);

  // The Dolev-Yao premise, checked message by message: the attacker is an
  // endpoint of every single one, and never talks to itself.
  for (const r of rows) {
    expect(r.from === attacker || r.to === attacker).toBe(true);
    expect(r.from).not.toBe(r.to);
  }

  // Locate the relay structurally: a ciphertext that entered the attacker from
  // one honest party and left it, unchanged, to a different one. That — not a
  // matching literal — is what makes the attack a relay rather than a forgery.
  const relays = rows
    .map((r, i) => ({ r, next: rows[i + 1], i }))
    .filter(({ r, next }) => next && r.to === attacker && next.from === attacker && next.msg === r.msg && next.to !== r.from);
  expect(relays).toHaveLength(1);
  expect(relays[0].r.from).not.toBe(relays[0].next.to);

  // The opening message is re-addressed rather than opened: same plaintext
  // body, different recipient key — the attacker impersonating the initiator.
  const parts = (msg: string) => {
    const m = /^\{(.+)\}_pk(\S+)$/.exec(msg);
    expect(m, `not a ciphertext: ${msg}`).not.toBeNull();
    return { body: m![1], to: m![2] };
  };
  const first = parts(rows[0].msg);
  const replayed = parts(rows[1].msg);
  expect(replayed.body).toBe(first.body);
  expect(first.to).toBe(attacker);
  expect(replayed.to).toBe(rows[1].to);
  expect(replayed.to).not.toBe(first.to);

  // Each row's note states the direction it belongs to, so the trace explains
  // itself rather than relying on the arrow glyph alone.
  const notes = await page.locator('.trace li .note').allTextContents();
  expect(notes).toHaveLength(rows.length);
  rows.forEach((r, i) => {
    const expected =
      r.to === attacker
        ? new RegExp(`^${r.from} \\((initiator|responder)\\) sends — intercepted by ${attacker}\\.$`)
        : new RegExp(`^${attacker} delivers a message ${r.to} accepts as (initiator|responder)\\.$`);
    expect(notes[i].trim()).toMatch(expected);
  });
});

test('the ladder mirrors the trace and names exactly who is deceived', async ({ page }) => {
  await runSearch(page);
  const rows = await wireRows(page);
  const attacker = await attackerLane(page);

  // Row for row, the diagram is the trace — no second, prettier story.
  expect(await ladderRows(page)).toEqual(rows);

  const heads = await page.locator('.ladder-head .lane-head').evaluateAll((els) =>
    els.map((el) => ({
      cls: el.className,
      name: el.querySelector('.lane-name')?.textContent?.trim() ?? '',
      role: el.querySelector('.lane-role')?.textContent?.trim() ?? '',
      beliefs: [...el.querySelectorAll('.lane-belief')].map((b) => b.textContent?.trim() ?? ''),
    })),
  );
  expect(heads).toHaveLength(3);
  // The attacker is the middle lane, and it is the party the trace showed on
  // every message.
  expect(heads[1].name).toBe(attacker);
  expect(heads[1].role).toContain('attacker');
  expect(heads[1].beliefs).toEqual([]);

  const deceived = heads.filter((h) => h.cls.includes('lane-deceived'));
  expect(deceived).toHaveLength(1);
  const [believesPeer, actually] = deceived[0].beliefs;
  const peer = /believes peer = (\S+)/.exec(believesPeer)![1];
  expect(actually).toBe(`actually ${attacker}`);

  // The deception paragraph is rebuilt from the lane head's own tokens.
  await expect(page.locator('.deception')).toHaveText(
    `The deception: ${deceived[0].name} believes it is talking to ${peer}. ` +
      `It is talking to ${attacker} — who never had to break a single cipher.`,
  );

  // And the belief really is false in this trace: the deceived party never
  // exchanged a message with the peer it names; every one of its messages went
  // to or came from the attacker.
  const theirs = rows.filter((r) => r.from === deceived[0].name || r.to === deceived[0].name);
  expect(theirs.length).toBeGreaterThan(0);
  for (const r of theirs) expect(r.from === attacker || r.to === attacker).toBe(true);
  expect(rows.some((r) => (r.from === deceived[0].name && r.to === peer) || (r.from === peer && r.to === deceived[0].name))).toBe(
    false,
  );

  // Two tinted sessions, as the README promises: messages in the attacker's
  // session with the deceived party are tinted apart from the other session.
  const tints = await page.locator('.ladder-rows li').evaluateAll((els) =>
    els.map((el) => (el.className.includes('rung-right') ? 'right' : 'left')),
  );
  expect(new Set(tints).size).toBe(2);
  rows.forEach((r, i) => {
    const withDeceived = r.from === deceived[0].name || r.to === deceived[0].name;
    expect(tints[i]).toBe(withDeceived ? 'right' : 'left');
  });
});

test('stepping the trace reveals one message at a time and grows the knowledge set', async ({ page }) => {
  const goal = await goalTerm(page);
  await runSearch(page);
  const rows = await wireRows(page);
  const back = page.getByRole('button', { name: '◀ Step back' });
  const fwd = page.getByRole('button', { name: 'Step ▶' });

  // Fully revealed after a run: the last message is current and there is
  // nowhere further forward to go.
  await expect(page.locator('.step-count')).toHaveText(`message ${rows.length} of ${rows.length}`);
  await expect(fwd).toBeDisabled();

  for (let i = 0; i < rows.length; i += 1) await back.click();
  await expect(page.locator('.step-count')).toHaveText('start');
  await expect(back).toBeDisabled();
  await expect(page.locator('.trace li.shown')).toHaveCount(0);
  await expect(page.locator('.ladder-rows li.shown')).toHaveCount(0);

  // Before any message the attacker holds only the public baseline plus the
  // corrupt party's key — nothing intercepted, nothing derived.
  const atStart = await knowledge(page);
  expect(atStart.length).toBeGreaterThan(0);
  expect([...new Set(atStart.map((f) => f.rule))].sort()).toEqual(['PUB', 'given']);
  expect(atStart.some((f) => f.goal)).toBe(false);
  await expect(page.locator('.knowledge').locator('xpath=following-sibling::p')).toHaveText(/Before any message/);

  for (let i = 0; i < rows.length; i += 1) {
    await fwd.click();
    await expect(page.locator('.step-count')).toHaveText(`message ${i + 1} of ${rows.length}`);
    await expect(page.locator('.trace li.shown')).toHaveCount(i + 1);
    await expect(page.locator('.ladder-rows li.shown')).toHaveCount(i + 1);
    await expect(page.locator('.trace li.current')).toHaveCount(1);
    await expect(page.locator('.trace li').nth(i)).toHaveClass(/current/);

    const facts = await knowledge(page);
    // Knowledge only ever grows as the trace advances.
    for (const f of atStart) expect(facts.map((k) => k.term)).toContain(f.term);

    if (i === 0) {
      // Regression: "new at this step" used to include the whole public
      // baseline the panel had just listed as known before any message. Only
      // what message 1 actually yielded may be highlighted.
      const baseline = facts.filter((f) => f.rule === 'PUB' || f.rule === 'given');
      expect(baseline.map((f) => f.term).sort()).toEqual(atStart.map((f) => f.term).sort());
      expect(baseline.filter((f) => f.fresh)).toEqual([]);
      expect(facts.filter((f) => f.fresh).map((f) => f.term).sort()).toEqual(
        facts.filter((f) => f.rule !== 'PUB' && f.rule !== 'given').map((f) => f.term).sort(),
      );
    }

    // The goal is a secret until the very message that leaks it.
    const leaked = facts.some((f) => f.term === goal);
    expect(leaked).toBe(i === rows.length - 1);
    if (leaked) expect(facts.find((f) => f.term === goal)!.fresh).toBe(true);
  }
  await expect(fwd).toBeDisabled();
});

test('the search counters agree with the trace, the bound, and each other', async ({ page }) => {
  await runSearch(page);
  const rows = await wireRows(page);
  const c = await counters(page);

  expect(c.explored).toBeGreaterThan(0);
  expect(c.injections).toBeGreaterThan(0);
  // The reported interleaving depth IS the length of the trace it returned.
  expect(c.depth).toBe(rows.length);
  // A found attack means the frontier was never exhausted against the cap.
  expect(c.explored).toBeLessThan(c.bound);
  await expect(page.locator('#search-status')).toContainText('found by enumeration');

  // The three highlighted figures are the three numbers in the sentence.
  expect((await page.locator('#search-status .stat-num').allTextContents()).map(num)).toEqual([
    c.explored,
    c.injections,
    c.depth,
  ]);

  // Determinism (README: "deterministic breadth-first"): leaving the protocol
  // and coming back re-runs the identical search to the identical numbers.
  await select(page, 'dh');
  await select(page, 'ns');
  await runSearch(page);
  expect(await counters(page)).toEqual(c);
  expect(await wireRows(page)).toEqual(rows);
});

test("Lowe's fix retracts the verdict, and the re-run derives why the relay fails", async ({ page }) => {
  const goal = await goalTerm(page);
  await runSearch(page);
  const rows = await wireRows(page);
  const attacker = await attackerLane(page);
  await expect(verdictBox(page)).toHaveClass(/indicator--alarm/);

  // Ticking the fix must retract everything the previous protocol proved.
  await page.locator('#fix-toggle').check();
  await expect(verdictBox(page)).toHaveClass(/indicator--idle/);
  await expect(verdictBox(page)).toContainText('Not run yet');
  await expect(page.locator('#search-status')).toContainText('Idle.');
  await expect(page.locator('.trace li')).toHaveCount(0);
  await expect(page.locator('.ladder-card')).toHaveCount(0);
  await expect(page.locator('.knowledge li')).toHaveCount(0);
  await expect(page.locator('#lab-body h3').first()).toHaveText('Protocol under test: Needham-Schroeder-Lowe');
  // One field, one message: the flagged schema line now carries the extra identity.
  await expect(page.locator('.schema li.changed')).toHaveCount(1);
  await expect(page.locator('.schema li.changed')).toContainText('B}_pkA');

  await runSearch(page);
  await expect(verdictBox(page)).toHaveClass(/indicator--ok/);
  await expect(verdictBox(page)).toContainText('No attack in bound');
  // No attack means no trace, no ladder, and no leaked-goal marker anywhere.
  await expect(page.locator('.trace li')).toHaveCount(0);
  await expect(page.locator('.ladder-card')).toHaveCount(0);
  await expect(page.locator('.goal-hit')).toHaveCount(0);
  await expect(page.locator('.panel h3').first()).toContainText('No trace');

  const c = await counters(page);
  expect(c.explored).toBeGreaterThan(0);
  // The prose must match the arithmetic: under the cap => exhausted, not capped.
  expect(c.explored).toBeLessThan(c.bound);
  await expect(page.locator('#search-status')).toContainText('frontier emptied');
  await expect(verdictBox(page)).toContainText('space fully exhausted');
  // The verdict note and the status line report the same state count.
  await expect(verdictBox(page)).toContainText(`within ${c.explored.toLocaleString('en-US')} states`);

  // The reason is derived, and it names the field the fix added: the initiator
  // checks message 2 against its actual peer (the attacker it dialled), while
  // the relayed reply now carries the responder's identity instead.
  const steps = await page.locator('.repair-steps li').allTextContents();
  expect(steps.length).toBeGreaterThanOrEqual(3);
  const conflict = steps.find((s) => s.includes('no longer unify'))!;
  expect(conflict).toBeTruthy();
  const m = /the pattern requires (\S+) where the reply carries (\S+)/.exec(conflict)!;
  expect(m).not.toBeNull();
  expect(m[1]).toBe(attacker); //  what the honest initiator expects to see named
  expect(m[2]).not.toBe(attacker); //  what the responder actually names
  expect(steps[0]).toContain(m[1]);
  expect(steps[1]).toContain(m[2]);
  // ...and the goal the search hunted is stated to be out of reach, by name.
  expect(steps[steps.length - 1]).toContain(`${goal} is not in its knowledge`);
});

test('switching protocols clears the verdict, the trace and the fix toggle', async ({ page }) => {
  await page.locator('#fix-toggle').check();
  await runSearch(page);
  await expect(page.locator('.repair-card')).toBeVisible();

  await page.locator('#proto-select').selectOption('dh');
  await expect(verdictBox(page)).toHaveClass(/indicator--idle/);
  await expect(page.locator('.repair-card')).toHaveCount(0);
  await expect(page.locator('.trace li')).toHaveCount(0);
  await expect(page.locator('.knowledge li')).toHaveCount(0);
  await expect(page.locator('#search-status')).toContainText('Idle.');
  // The fix belongs to the protocol, so it resets with it.
  await expect(page.locator('#fix-toggle')).not.toBeChecked();
  await expect(page.locator('#lab-body h3').first()).toHaveText('Protocol under test: Naive Diffie-Hellman');
});

test('naive Diffie-Hellman: the MITM verdict names the key the attacker owns', async ({ page }) => {
  await select(page, 'dh');
  const goal = await goalTerm(page);
  await runSearch(page);

  const rows = await wireRows(page);
  const attacker = await attackerLane(page);
  const facts = await knowledge(page);

  const attackReached = facts.some((f) => f.term === goal);
  expect(attackReached).toBe(true);
  await expect(verdictBox(page)).toHaveClass(/indicator--alarm/);
  await expect(verdictBox(page)).toContainText(`the attacker learns ${goal}`);
  await expect(cryptoBox(page)).toContainText('Perfect — unbroken');

  // The final message is the secret sealed under a session key, and the page
  // shows why the attacker can open it: one of that key's two shares is an
  // exponent listed in its own knowledge as material it was given, never
  // derived from the honest parties' public shares.
  const sealed = rows[rows.length - 1].msg;
  const m = /^\{(\S+)\}_K\((\S+), (\S+)\)$/.exec(sealed);
  expect(m, `expected a secret under a DH key, got: ${sealed}`).not.toBeNull();
  expect(m![1]).toBe(goal);
  const shares = [m![2], m![3]];
  const owned = shares.filter((s) => facts.find((f) => f.term === s)?.rule === 'given');
  expect(owned).toHaveLength(1);
  // The other share is the honest initiator's, which the attacker only ever saw
  // as a public value g^x on the wire.
  const honestShare = shares.find((s) => !owned.includes(s))!;
  expect(rows.map((r) => r.msg)).toContain(`g^${honestShare}`);
  expect(facts.find((f) => f.term === `g^${owned[0]}`)?.rule).toBe('given');
  expect(facts.find((f) => f.term === goal)!.rule).toBe('DEC');

  // The deceived party is the one that thought it was talking to the peer it
  // never reached; the responder that never ran gets no belief badge at all.
  const heads = await page.locator('.ladder-head .lane-head').evaluateAll((els) =>
    els.map((el) => ({
      name: el.querySelector('.lane-name')?.textContent?.trim() ?? '',
      role: el.querySelector('.lane-role')?.textContent?.trim() ?? '',
      deceived: el.className.includes('lane-deceived'),
      beliefs: [...el.querySelectorAll('.lane-belief')].map((b) => b.textContent?.trim() ?? ''),
    })),
  );
  const idle = heads.find((h) => h.role.includes('did not run'))!;
  expect(idle.beliefs).toEqual([]);
  expect(rows.some((r) => r.from === idle.name || r.to === idle.name)).toBe(false);
  const deceived = heads.filter((h) => h.deceived);
  expect(deceived).toHaveLength(1);
  expect(deceived[0].beliefs[1]).toBe(`actually ${attacker}`);
  expect(/believes peer = (\S+)/.exec(deceived[0].beliefs[0])![1]).toBe(idle.name);
});

test('signed Diffie-Hellman: secure, and the obstacle is the signature it cannot forge', async ({ page }) => {
  await select(page, 'dh', true);
  const goal = await goalTerm(page);
  // Signing both shares is a two-message edit, and the schema says so.
  await expect(page.locator('.schema li.changed')).toHaveCount(2);

  await runSearch(page);
  await expect(verdictBox(page)).toHaveClass(/indicator--ok/);
  await expect(verdictBox(page)).toContainText('No attack in bound');
  await expect(page.locator('.trace li')).toHaveCount(0);
  await expect(page.locator('.goal-hit')).toHaveCount(0);
  await expect(cryptoBox(page)).toContainText('Perfect — unbroken');

  const c = await counters(page);
  expect(c.explored).toBeLessThan(c.bound);
  await expect(page.locator('#search-status')).toContainText('frontier emptied');

  const steps = await page.locator('.repair-steps li').allTextContents();
  const obstacle = steps.find((s) => s.includes('would have to present'))!;
  expect(obstacle).toBeTruthy();
  // The credential it cannot produce is a signature, and the key it lacks is
  // the signer named in the very pattern the initiator now checks (step 1).
  const needed = /would have to present (\[.+?\]_sk(\S+?)) — but the attacker holds no sk\2/.exec(obstacle);
  expect(needed, `unexpected obstacle wording: ${obstacle}`).not.toBeNull();
  expect(steps[0]).toContain(`_sk${needed![2]}`);
  expect(steps[steps.length - 1]).toContain(`${goal} is not in its knowledge`);
});

test('the Kerberos entry is link-only, and Run comes back to life when you leave it', async ({ page }) => {
  await page.locator('#proto-select').selectOption('kerberos');

  // The failure path here is "nothing to run": the control is disabled and the
  // page says why rather than leaving a dead button unexplained.
  await expect(page.locator('#run-btn')).toBeDisabled();
  await expect(page.locator('.verdicts')).toHaveCount(0);
  await expect(page.locator('#search-status')).toHaveCount(0);
  await expect(page.locator('#lab-body')).toContainText('links to the sibling demo');
  const link = page.locator('#lab-body a');
  await expect(link).toHaveAttribute('href', 'https://systemslibrarian.github.io/crypto-lab-kerberos/');
  await expect(link).toHaveText(/Open the Kerberos lab/);

  // Forcing the disabled control must not fabricate a verdict.
  await page.locator('#run-btn').click({ force: true });
  await expect(page.locator('.verdicts')).toHaveCount(0);

  // And it is disabled *because of the selection*, not permanently.
  await page.locator('#proto-select').selectOption('ns');
  await expect(page.locator('#run-btn')).toBeEnabled();
  await runSearch(page);
  await expect(verdictBox(page)).toHaveClass(/indicator--alarm/);
});

test('every library chip agrees with the verdict the checker produces live', async ({ page }) => {
  const chips = await page.locator('.lib-card').evaluateAll((els) =>
    els.map((el) => ({
      title: el.querySelector('h3')?.textContent?.trim() ?? '',
      chip: el.querySelector('.verdict-chip')?.textContent?.trim() ?? '',
      cls: el.querySelector('.verdict-chip')?.className ?? '',
    })),
  );
  expect(chips).toHaveLength(5);
  // Four runnable verdicts plus the link-only entry.
  expect(chips.filter((c) => c.cls.includes('link'))).toHaveLength(1);
  expect(chips.filter((c) => c.cls.includes('attack') || c.cls.includes('secure'))).toHaveLength(4);

  for (const [key, fix] of [
    ['ns', false],
    ['ns', true],
    ['dh', false],
    ['dh', true],
  ] as [string, boolean][]) {
    await select(page, key, fix);
    const title = ((await page.locator('#lab-body h3').first().textContent()) ?? '').replace('Protocol under test: ', '');
    const chip = chips.find((c) => c.title === title);
    expect(chip, `no library chip for ${title}`).toBeTruthy();

    await runSearch(page);
    const found = (await page.locator('.trace li').count()) > 0;
    // Three independent renderings of the same search must agree: the chip
    // computed at mount, the indicator, and whether a trace came back.
    expect(chip!.chip).toBe(found ? '✗ attack found' : '✓ no attack in bound');
    expect(chip!.cls).toContain(found ? 'attack' : 'secure');
    await expect(verdictBox(page)).toHaveClass(new RegExp(found ? 'indicator--alarm' : 'indicator--ok'));
    await expect(verdictBox(page)).toContainText(found ? 'ATTACK FOUND' : 'No attack in bound');
    expect((await page.locator('.goal-hit').count()) > 0).toBe(found);
  }
});

/**
 * The animated path. With motion allowed, the state counter ticks up and the
 * trace is only revealed when it lands — so an abandoned run has a pending
 * reveal that must not resurrect a retracted verdict.
 */
test.describe('with the counter animation running', () => {
  // Undo the beforeEach's reduced-motion emulation and reload, so these two
  // tests exercise the animated reveal the rest of the suite opts out of.
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.goto('.');
  });

  test('the counter lands on the true state count and then reveals the trace', async ({ page }) => {
    await page.locator('#run-btn').click();
    const early = num((await page.locator('#search-status .stat-num').first().textContent()) ?? '0');

    // The reveal is what finishes the animation, so waiting for the last
    // message to be current is waiting for the counter to land.
    await expect(page.locator('.trace li.current')).toHaveCount(1);
    await expect(page.locator('.step-count')).toHaveText(/message (\d+) of \1$/);
    const settled = await counters(page);
    expect(early).toBeLessThanOrEqual(settled.explored);

    // Stepping re-renders the status line straight from the search result, so
    // an animated value that had overshot or stopped short would change here.
    await page.getByRole('button', { name: '◀ Step back' }).click();
    expect(await counters(page)).toEqual(settled);
    expect(settled.depth).toBe(await page.locator('.trace li').count());
  });

  test('a retracted verdict stays retracted when the abandoned run finishes animating', async ({ page }) => {
    await page.locator('#run-btn').click();
    await page.locator('#fix-toggle').check();
    await expect(verdictBox(page)).toHaveClass(/indicator--idle/);

    // Well past the animation's 750ms: the abandoned reveal must not repaint an
    // attack over a protocol that was never searched.
    await page.waitForTimeout(1200);
    await expect(verdictBox(page)).toHaveClass(/indicator--idle/);
    await expect(page.locator('.trace li')).toHaveCount(0);
    await expect(page.locator('.ladder-card')).toHaveCount(0);
    await expect(page.locator('#search-status')).toContainText('Idle.');

    // Same for abandoning mid-run by changing protocol.
    await page.locator('#fix-toggle').uncheck();
    await page.locator('#run-btn').click();
    await page.locator('#proto-select').selectOption('dh');
    await expect(verdictBox(page)).toHaveClass(/indicator--idle/);
    await page.waitForTimeout(1200);
    await expect(verdictBox(page)).toHaveClass(/indicator--idle/);
    await expect(page.locator('.trace li')).toHaveCount(0);
    await expect(page.locator('#lab-body h3').first()).toHaveText('Protocol under test: Naive Diffie-Hellman');
  });
});
