# Migration Auditor V1 — Human Beta Feedback

Please answer only what you can. Do not send source code, credentials, secrets, customer data, or proprietary API specs. File/line examples may be anonymized.

## Tester / workflow
- Tester ID (required, can be anonymous): __________________
- Role: __________________
- What were you migrating? __________________
- Was the migration done by: human / AI agent / vendor / mixed / other
- Current way you normally verify a migration is complete: __________________

## Run
1. Did the audit complete? yes / no / with-help
2. Setup difficulty (1 effortless — 5 hard): ___
3. Overall decision returned: PASS / FAIL / REVIEW
4. Baseline impacted usages reported: ___
5. STILL_PRESENT: ___
6. RESOLVED: ___
7. CHANGED_BUT_UNVERIFIED: ___
8. UNKNOWN: ___

## Accuracy / trust
9. Did it find any stale/missed migration usage you had not noticed? yes / no / not applicable
   - anonymized example: __________________
10. Confirmed wrong findings / false positives: ___
    - anonymized examples: __________________
11. Known affected usages it missed: ___
    - anonymized examples: __________________
12. Was the PASS/FAIL/REVIEW decision trustworthy for this case? yes / partial / no
13. Did the evidence explain *why* each disposition was given? yes / partial / no

## Value
14. Would this have changed whether you approved/merged/released the migration? yes / maybe / no
15. Estimated manual verification time saved: __________________
16. Would you use this again for a relevant API migration? yes / maybe / no
17. How often do you face this problem? yearly / quarterly / monthly / weekly+ / rarely
18. Which is more valuable to you?
    - finding what will break before migration
    - independently checking completeness after migration
    - both
    - neither

## Commercial signal
19. If this reliably caught missed migration call-sites before release, would your team pay for it? yes / maybe / no / not my decision
20. Rough acceptable range/model (range only):
    - $0 / free CLI only
    - one-time $10–50
    - $5–15 per developer/month
    - $20–50 per repo/month
    - $50–200 per org/month
    - higher if integrated into CI/review workflow
    - not sure
21. Main reason you would *not* pay: __________________
22. What would need to be true before you trusted it in CI/release review? __________________

## Product direction
23. Biggest missing capability that blocked value in this test: __________________
24. Did you want it to auto-fix code, or is independent verification more important? __________________
25. Any privacy/security concern? __________________

## Optional permission
- May we quote your feedback anonymously? yes / no
- May we follow up once about this test? yes / no

Free text:
________________________________________________________________
