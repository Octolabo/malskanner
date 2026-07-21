## What & why



## Checklist

- [ ] `npm test` passes (includes the false-positive guard)
- [ ] New/changed detectors have **both** a positive and a negative test
- [ ] Detectors stay deterministic (no network/clock/model in `scan()`)
- [ ] Ran the scanner against a couple of large real repos and confirmed they stay `OK`
- [ ] Severities are honest (`critical` ⇒ REFUSE only for proven malicious content)
