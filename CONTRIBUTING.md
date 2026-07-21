# Contributing to malskanner

Thanks for helping make AI coding agents safer.

## Ground rules

- **Detectors must be deterministic.** No network, no clock, no model calls inside a
  detector's `scan()`. That is what makes malskanner un-hijackable and its verdicts
  reproducible.
- **Precision first.** A new rule must not fire on mainstream repos. `npm test`
  includes a false-positive guard against the fixtures; before opening a PR, also run
  the scanner against a few large real repos and confirm they stay `OK`.

## Dev setup

```bash
npm install
npm test                              # regenerates fixtures + runs the suite
npm run scan -- test/fixtures/poisoned
npm run build                         # type-check + emit dist/
```

## Adding a detector

1. Create `src/scanner/detectors/your-rule.ts` exporting a `Detector` (copy
   `unicode.ts` as a template).
2. Register it in `src/scanner/detectors/index.ts`.
3. Add **both** a positive test and a negative (clean-input) test in
   `test/detectors.test.ts`.
4. Keep severities honest:
   - `critical` ⇒ **REFUSE** — proven malicious *content* (a decoded instruction, a
     concealed directive).
   - `high` / `medium` ⇒ **WARN** — concealment or impersonation without a proven
     payload.

## Reporting a false positive

Open an issue with the smallest file that reproduces it. False positives are treated
as bugs — the whole product depends on staying trustworthy.
