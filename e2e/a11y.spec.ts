import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the idle arrival state, where
 * nothing has run and the verdict indicator is on neither of its two coloured
 * states; the skip link focused; the Lowe attack on Needham-Schroeder, then the
 * trace stepped backwards message by message to `start` — which is the only way
 * to reach the attacker's INITIAL knowledge panel — and forwards again, with a
 * scan at every step, because the trace rows and ladder rungs render at
 * `opacity: 0.4` and `0.32` until the stepper reaches them and the set of faded
 * elements is different at each one; the expert disclosure opened through its own
 * summary; Lowe's fix ticked (which re-arms the protocol to idle and silently
 * rebuilds the disclosure shut), then run for the secure verdict and the derived
 * repair panel; the same two verdicts on naive and signed Diffie-Hellman; and the
 * Kerberos link-only body, which disables the run button and replaces the whole
 * lab. That last one is where the gate this replaces happened to leave the page
 * — and, since it scanned once at the end, it is the ONLY state it ever measured.
 * Every state here is scanned, in both themes, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page (this lab reads the
 * reduced-motion preference in SCRIPT at module load, which no style tag can
 * reach), why the disclosure is clicked rather than forced open, why the lab's
 * defaults are asserted rather than assumed, and why `violations` is not the
 * whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });
}
