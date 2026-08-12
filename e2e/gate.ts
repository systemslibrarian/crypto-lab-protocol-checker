import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Six rules govern everything here, and every one of them corrects something
 * `driveDemos()` — the whole of the gate this replaces — did:
 *
 *  1. IT SCANNED ONCE, AT THE VERY END, AND THE END WAS THE EMPTIEST STATE ON
 *     THE PAGE. `driveDemos` ran the Lowe attack, stepped the trace, applied the
 *     fix, ran again for the secure verdict, ran the Diffie-Hellman MITM — and
 *     then selected Kerberos. Kerberos is the link-only entry, so `render()`
 *     replaced `#lab-body` with a heading, a paragraph and one link, discarding
 *     every state the drive had just built. The single `scan()` that followed
 *     measured that. Not one of the attack trace, the ladder, the attacker's
 *     knowledge set, the repair panel, either verdict indicator or the stepper
 *     was ever in the DOM at the moment axe looked.
 *
 *  2. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. It pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`, BYPASSING `style.css`'s own reduced-motion block instead of
 *     exercising it — and on this page the preference does real work in the
 *     SCRIPT as well as the stylesheet: `ui.ts` reads
 *     `matchMedia('(prefers-reduced-motion: reduce)')` at module load and takes
 *     a different branch in `animateSearch`, writing the final explored-state
 *     count synchronously instead of ticking it up over 750ms. An injected style
 *     tag cannot reach that branch at all. `boot` asks for the preference and
 *     ASSERTS it took effect.
 *
 *  3. IT FORCE-OPENED THE ONE DISCLOSURE from script
 *     (`details.forEach(d => d.open = true)`). Here `.expert` is opened by
 *     clicking its own `<summary>`, which is also the only way to find out that
 *     `render()` destroys and rebuilds it — so it silently closes again on the
 *     next interaction, and that is a real thing to know about the page rather
 *     than something to paper over.
 *
 *  4. EVERY DRIVE STEP WAS GUARDED. `if (await back.isEnabled()) await
 *     back.click()` for the stepper, in a fixed-count loop: a stepper that
 *     stopped working would have skipped silently and the gate would have gone
 *     green. Here every control's precondition is asserted, the click is
 *     unconditional, and its effect is asserted before the next step.
 *
 *  5. `violations` IS NOT THE WHOLE ORACLE. See `scan`. This palette builds its
 *     state tints out of eight-digit hex (`--surface-2: #16302810`,
 *     `--ok-tint: #10312592`, `--neutral-tint: #10283440`), so they are
 *     translucent and axe reports `incomplete` rather than a ratio for text on
 *     them.
 *
 *  6. IT HAD NO REFLOW, KEYBOARD-SCROLLER OR NON-TEXT-CONTRAST ORACLE, and it
 *     ran at one viewport. This page needs all four: a three-column ladder grid,
 *     two `max-height: 24rem` scrollers, and a stepper whose buttons are
 *     outlined in the decorative border token.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This
 * stylesheet uses the dangerous spelling, `* { animation: none !important }`,
 * so if a `@keyframes` ever arrives with an `opacity: 0` start it will strand
 * whatever it drives.
 *
 * It cannot today, and the assertion is what makes that a measurement rather
 * than a reading: `style.css` declares no `@keyframes` and no `animation`
 * property at all. Its three `opacity` declarations are `.trace li` at `.4`,
 * `.rung` at `.32` and `.btn[disabled]` at `.55` — none of them zero, and all
 * three are measured for real by the contrast walk instead of being trusted.
 *
 * `aria-hidden` subtrees are excluded; see the header of `contrast.ts` for the
 * enumeration of what this lab hides and why none of it carries a value.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. That matters here because `render()` clears `#lab-body` before it
 * rebuilds it: a throw partway through leaves the lab EMPTY, which is a
 * perfectly accessible document and tells you nothing. Attach before `boot`,
 * assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * `index.html`'s `dedupeBanner()` demotes any other implicit banner, and on this
 * page it has something to do: `mountApp` renders `<header class="cl-hero">`
 * inside `#app`, a plain `<div>`, so `closest('main, article, aside, nav,
 * section')` finds nothing to scope it out and it is an implicit banner until
 * the script rewrites it. Asserting the OUTCOME rather than either mechanism
 * means a change to the nesting is caught too.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. That ordering is load-bearing here in a way
 * it is not in most labs: `ui.ts` evaluates
 * `window.matchMedia('(prefers-reduced-motion: reduce)').matches` ONCE, at
 * module scope, so emulation applied after the bundle has run would leave
 * `prefersReduced` false forever and every search would animate its counter.
 *
 * The theme is seeded through `localStorage` rather than by clicking the
 * toggle, which also pins down a real failure mode: `index.html`'s anti-flash
 * script reads `localStorage.getItem('theme')` and the shared bar's
 * `#cl-theme-toggle` writes it. If those keys drifted apart the theme would
 * silently stop persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice.
 *
 * The defaults are asserted because this lab ships IDLE: the protocol picker on
 * Needham-Schroeder, the fix unchecked, no search result, the verdict indicator
 * on `--idle` rather than either of the two states that carry colour, and the
 * expert disclosure shut. That is the first state every reader sees, and the
 * gate this replaces never scanned it — its only scan was of the Kerberos
 * link-only body, several interactions later.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // `mountApp` builds the whole document; a navigation that resolves proves
  // nothing.
  await expect(page.locator('main > section.card')).toHaveCount(4);
  await expect(page.locator('.honesty')).toBeVisible();
  await expect(page.locator('#library-grid .lib-card')).toHaveCount(5);

  // ── The lab's shipped state: idle, unfixed, unrun ────────────────────────
  await expect(page.locator('#proto-select')).toHaveValue('ns');
  await expect(page.locator('#run-btn')).toBeEnabled();
  await expect(page.locator('#fix-toggle')).not.toBeChecked();
  await expect(page.locator('.indicator--idle')).toBeVisible();
  await expect(page.locator('.indicator--alarm')).toHaveCount(0);
  await expect(page.locator('.indicator--ok')).toHaveCount(0);
  await expect(page.locator('.ladder-card')).toHaveCount(0);
  await expect(page.locator('.repair-card')).toHaveCount(0);
  await expect(page.locator('.workbench')).toHaveCount(0);
  await expect(page.locator('#search-status')).toContainText('Idle.');
  await expect(page.locator('details.expert')).toHaveCount(1);
  await expect(page.locator('details[open]')).toHaveCount(0);
  // The protocol schema is rendered before any run, and message 2 is the one the
  // fix rewrites — the `.changed` marker is the page's only non-colour cue for
  // which line the toggle touches.
  await expect(page.locator('.schema li')).toHaveCount(3);
  await expect(page.locator('.schema li.changed')).toHaveCount(1);

  // `[hidden]` has specificity (0,1,0) — identical to a class — so any later
  // `.foo { display: … }` beats it and the attribute silently does nothing.
  // Seven labs in this fleet had exactly that. Measured rather than inferred.
  expect(
    await page.evaluate(() => {
      const el = document.querySelector('.card p');
      if (!el) return 'no probe element';
      el.setAttribute('hidden', '');
      const d = getComputedStyle(el).display;
      el.removeAttribute('hidden');
      return d;
    }),
    'the [hidden] attribute must actually hide — no later class may out-rank it'
  ).toBe('none');

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page has
 * the shapes that break it: the ladder is a three-column CSS grid whose rungs
 * carry unbreakable protocol terms (`{Na, Nb, B}_pkA`, `g^a, [g^a]_skA`), the
 * attacker's knowledge list puts a term and a rule chip on one flex row, and the
 * schema lines are monospace message notation. Each wide thing is meant to fit
 * or to scroll inside its own container; the assertion here is that none of them
 * scrolls the DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This lab already handles its two known cases — `.trace` and `.knowledge` are
 * both built with `role="region"`, `tabindex="0"` and an `aria-label`, and both
 * are `max-height: 24rem; overflow: auto` around lists that routinely exceed
 * that. The assertion stays because those are conventions in `ui.ts` rather than
 * enforcement, and because the content inside them is the evidence for
 * everything this lab claims: the attack trace and the attacker's derived facts.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 1200));
  }
}

/**
 * The 1.4.11 ratchet, soft-wrapped the same way as every other oracle here.
 *
 * This wrapper is the repair of a dead oracle rather than a refactor. In the
 * reference gate every other lab in this fleet was copied from,
 * `expectNoNewNonTextFailures` was reachable only from inside
 * `expectScrollersReachableSoft`, AFTER that function's
 * `if (!COLLECTING) return …` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos carried an empty
 * `nontext-baseline.ts` that was not a clean bill of health but the footprint of
 * a check that had never looked. It is called from `scan()` here.
 */
async function expectNoNewNonTextFailuresSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoNewNonTextFailures(page, label);
  try {
    await expectNoNewNonTextFailures(page, label);
  } catch (e) {
    record(String(e).slice(0, 2500));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 1200));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. This page's controls are exactly the shape that check exists for: a
 * `<select>`, a checkbox, and three buttons whose only boundary is a 1px border
 * over a panel of nearly the same colour.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(
        `NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`
      );
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(
        `NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`
      );
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically. Everything else in that bucket is a real result axe simply
 *    could not finish — including `aria-prohibited-attr`, which is where an
 *    `aria-label` on a role-less element hides, a defect that never reaches the
 *    violations array at all. That one is live here: `ui.ts` puts `aria-label`
 *    on `<ul class="schema">` and on the ladder `<div>`, and both are legal only
 *    because of a role that is easy to drop.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node,
 *    which is the only oracle that sees the trace and ladder steps this page
 *    renders at `opacity: 0.4` and `0.32`.
 *  - non-text contrast and generated content — SC 1.4.11, which axe has no rule
 *    for; see `expectNoNewNonTextFailures`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe therefore runs those
  // FOUR best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // Running the two sets separately and merging is the only way to have both.
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them, and this page has
  // the exact shape they catch: a shared sticky `<header role="banner">` above a
  // hero `<header>` that `dedupeBanner()` has to demote at runtime, with an
  // `<aside role="complementary">` inside that hero and a second one
  // (`.honesty`) at the top of `<main>`.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 20),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await expectNoNewNonTextFailuresSoft(page, label);
  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Run the current protocol and wait for the search to publish its verdict. */
async function runSearch(page: Page, expect_: 'alarm' | 'ok'): Promise<void> {
  await page.click('#run-btn');
  await expect(page.locator(`.indicator--${expect_}`)).toBeVisible();
  // `animateSearch` takes the reduced-motion branch and writes the final count
  // synchronously, then `revealAfterSearch` re-renders at the last step — so the
  // workbench existing is the completion signal the code itself defines.
  await expect(page.locator('.workbench')).toBeVisible();
  await expect(page.locator('#search-status')).toContainText('Explored');
}

/** How many messages the current trace holds, read off the stepper's own text. */
async function traceLength(page: Page): Promise<number> {
  const text = (await page.locator('.step-count').textContent()) ?? '';
  const m = text.match(/of (\d+)/);
  expect(m, `the stepper must report a trace length, got "${text}"`).not.toBeNull();
  return Number(m![1]);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Six things shape this drive:
 *
 *  - THE IDLE STATE IS SCANNED FIRST, AND IT IS THE ONE THE OLD GATE SKIPPED
 *    ENTIRELY. Nothing has run; the verdict is `--idle`, the workbench does not
 *    exist, and `#search-status` is a sentence rather than a count.
 *
 *  - EVERY STEP OF THE STEPPER IS SCANNED, IN BOTH DIRECTIONS. This is not
 *    thoroughness for its own sake: `.trace li` renders at `opacity: 0.4` and
 *    `.rung` at `opacity: 0.32` until the stepper reaches them, so the number of
 *    faded elements — and therefore what the contrast oracle is looking at — is
 *    different at every single step. Walking back to `start` also reaches the
 *    attacker's INITIAL knowledge panel, which is a different list built by a
 *    different code path (`initialKnowledge`) and has its own prose.
 *
 *  - BOTH VERDICTS, ON BOTH RUNNABLE PROTOCOLS. `--alarm` and `--ok` are the two
 *    states that carry colour, and each has ink and tint tokens no other state
 *    paints. The `--ok` state additionally mints the repair panel, which is the
 *    only place `.repair-block` and `.repair-conclusion` appear.
 *
 *  - THE THIRD LIBRARY ENTRY IS A DIFFERENT DOCUMENT. Kerberos is link-only:
 *    `render()` replaces the whole lab body and DISABLES the run button. That is
 *    a real state, it is where the gate this replaces happened to leave the page,
 *    and it is the only state where `#run-btn` is disabled.
 *
 *  - THE DISCLOSURE IS OPENED BY CLICKING ITS SUMMARY, and then re-checked after
 *    the next interaction, because `render()` rebuilds `.expert` from scratch and
 *    it closes again. Forcing `open = true` from script — which is what the old
 *    gate did — hides that behaviour instead of measuring it.
 *
 *  - NO FIXED TIMEOUTS. Every step has a DOM completion signal: an indicator
 *    class, the workbench appearing, the stepper's own message counter, the run
 *    button's disabled state. The drive waits on those. The old gate waited on
 *    `page.waitForTimeout(300)`.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint: idle verdict, no result, no workbench');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  // ── Needham-Schroeder, unfixed: the Lowe attack ─────────────────────────
  await runSearch(page, 'alarm');
  await expect(page.locator('.ladder-card')).toBeVisible();
  await expect(page.locator('.deception')).toBeVisible();
  await expect(page.locator('.knowledge .goal-hit')).toBeVisible();
  const n = await traceLength(page);
  expect(n, 'the Lowe attack trace must have more than one message').toBeGreaterThan(1);
  await scanAt(`NSPK attack found, trace stepped to the end (${n} messages)`);

  // Every step backwards, one at a time — each one fades another rung and
  // another trace row, and the last lands on the initial-knowledge panel.
  for (let i = n - 1; i >= 0; i--) {
    await page.getByRole('button', { name: '◀ Step back' }).click();
    await expect(page.locator('.step-count')).toHaveText(
      i === 0 ? 'start' : `message ${i} of ${n}`
    );
    await scanAt(i === 0 ? 'stepped back to the start, initial knowledge' : `stepped back to message ${i}`);
  }
  await expect(page.getByRole('button', { name: '◀ Step back' })).toBeDisabled();
  await scanAt('at the start, Step back disabled');

  // And forwards again, which is where `.current` and `.fresh` are painted.
  for (let i = 1; i <= n; i++) {
    await page.getByRole('button', { name: 'Step ▶' }).click();
    await expect(page.locator('.step-count')).toHaveText(`message ${i} of ${n}`);
    await expect(page.locator('.trace li.current')).toBeVisible();
    await scanAt(`stepped forward to message ${i} of ${n}`);
  }
  await expect(page.getByRole('button', { name: 'Step ▶' })).toBeDisabled();

  // The one disclosure, opened the way a reader opens it.
  await page.locator('details.expert > summary').click();
  await expect(page.locator('details.expert')).toHaveAttribute('open', '');
  await scanAt('expert disclosure open');

  // ── Lowe's fix: the secure verdict and the derived repair panel ──────────
  await page.check('#fix-toggle');
  // Ticking the fix resets the result, so this is the idle state of the FIXED
  // protocol — a different schema (message 2 now carries B) with no verdict.
  await expect(page.locator('.indicator--idle')).toBeVisible();
  await expect(page.locator('.workbench')).toHaveCount(0);
  await expect(page.locator('.schema li.changed')).toHaveCount(1);
  // `render()` rebuilt `.expert` from scratch, so it is shut again. Asserted
  // rather than worked around: it is a real property of this page.
  await expect(page.locator('details[open]')).toHaveCount(0);
  await scanAt('Lowe fix ticked, protocol re-armed and idle');

  await runSearch(page, 'ok');
  await expect(page.locator('.repair-card')).toBeVisible();
  await expect(page.locator('.repair-steps li')).not.toHaveCount(0);
  await expect(page.locator('.ladder-card')).toHaveCount(0);
  await scanAt('NSL secure in bound, the derived repair panel');

  await page.uncheck('#fix-toggle');
  await expect(page.locator('.indicator--idle')).toBeVisible();
  await scanAt('fix unticked, back to the vulnerable schema');

  // ── Diffie-Hellman: the same engine, a different attack ─────────────────
  await page.selectOption('#proto-select', 'dh');
  await expect(page.locator('#proto-select')).toHaveValue('dh');
  await expect(page.locator('.indicator--idle')).toBeVisible();
  await expect(page.locator('#fix-toggle')).not.toBeChecked();
  await scanAt('Diffie-Hellman selected, idle');

  await runSearch(page, 'alarm');
  await expect(page.locator('.ladder-card')).toBeVisible();
  const dhN = await traceLength(page);
  await scanAt(`DH man-in-the-middle found (${dhN} messages)`);

  await page.getByRole('button', { name: '◀ Step back' }).click();
  await scanAt('DH trace stepped back one message');

  await page.check('#fix-toggle');
  await runSearch(page, 'ok');
  await expect(page.locator('.repair-card')).toBeVisible();
  await scanAt('signed DH secure in bound, repair derived');

  // ── Kerberos: the link-only entry, and the only disabled run button ─────
  await page.selectOption('#proto-select', 'kerberos');
  await expect(page.locator('#run-btn')).toBeDisabled();
  await expect(page.locator('#lab-body a')).toBeVisible();
  await expect(page.locator('.verdicts')).toHaveCount(0);
  await expect(page.locator('#fix-toggle')).toHaveCount(0);
  await scanAt('Kerberos link-only body, run disabled — the old gate’s only scan');

  // ── Back to the top of the library, which resets everything ─────────────
  await page.selectOption('#proto-select', 'ns');
  await expect(page.locator('#run-btn')).toBeEnabled();
  await expect(page.locator('.indicator--idle')).toBeVisible();
  await scanAt('back to Needham-Schroeder, fully reset');
}
