/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  // Everything this lab owns has been FIXED rather than baselined; the commit
  // that introduced this gate carries the before/after ratio for each. What is
  // left is the SHARED Crypto Lab top bar, which is not this repo's to change.
  //
  // `.cl-btn` draws its edge as
  // `1px solid color-mix(in srgb, var(--accent, #35d6bb) 38%, transparent)`
  // over the bar's fixed `#0b1512`. It reads `--accent` out of `:root`, so it
  // takes this lab's own accent: 2.45:1 in the dark theme and 1.48:1 in the
  // light one. Every repo in this fleet carries a byte-identical copy of that
  // markup and CSS, and `CLAUDE.md` is explicit that a change every lab should
  // get is a reviewed fleet-wide pass and never an overwrite driven from one
  // repo. So it is measured here, ratcheted here, and reported upward. The
  // recorded number is the WORSE of the two themes, so the ratchet cannot be
  // satisfied by whichever theme happens to run first.
  //
  // Everything inside `#app` — the hero, the honesty panel, all four cards and
  // the whole lab — is audited with no exemption, and comes back clean.
  'control-boundary|a.cl-btn': { ratio: 1.48, required: 3, unverified: false },
};
