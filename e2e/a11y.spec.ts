import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * driveDemos — put EVERY panel into its post-interaction state before scanning.
 * Axe only checks what is in the DOM, so we run the full flow: the Lowe attack
 * (attack found + trace + knowledge), the fix (secure verdict), a DH run, and
 * the link-only Kerberos entry — stepping the trace so the dynamic result
 * regions are all rendered.
 */
async function driveDemos(page: Page): Promise<void> {
  const select = page.locator('#proto-select');

  // 1. Needham-Schroeder: run the attack.
  await select.selectOption('ns');
  await page.locator('#run-btn').click();
  await expect(page.locator('.indicator--alarm')).toBeVisible();
  // step the trace back and forth so both current/idle states are exercised
  const back = page.getByRole('button', { name: '◀ Step back' });
  for (let i = 0; i < 3; i++) if (await back.isEnabled()) await back.click();
  const fwd = page.getByRole('button', { name: 'Step ▶' });
  for (let i = 0; i < 2; i++) if (await fwd.isEnabled()) await fwd.click();

  // 2. Apply the Lowe fix → secure verdict.
  await page.locator('#fix-toggle').check();
  await page.locator('#run-btn').click();
  await expect(page.locator('.indicator--ok')).toBeVisible();

  // 3. Diffie-Hellman: run the MITM.
  await select.selectOption('dh');
  await page.locator('#run-btn').click();
  await expect(page.locator('.indicator--alarm')).toBeVisible();

  // 4. Kerberos: link-only body (run disabled).
  await select.selectOption('kerberos');
  await expect(page.locator('#lab-body a')).toBeVisible();

  // Reveal any collapsed/animated content generically and settle.
  await page.addStyleTag({ content: `*,*::before,*::after{animation:none!important;transition:none!important}` });
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true));
  });
  await page.waitForTimeout(300);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5) })),
  ).toEqual([]);
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.');
  await driveDemos(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemos(page);
  await scan(page);
});
