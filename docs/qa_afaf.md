
# DECONFLICTED - Afaf QA Report

## Purpose

Record the results of final integration testing
for the DECONFLICTED Analyst frontend and demo.

## Test Environment

- Operating system: Windows
- Node.js: v22
- Frontend: React, TypeScript, Vite
- Branch: afaf/analyst-frontend
- Test date: TODO
- Tested commit: TODO

## 1. Fresh Clone Test

- [ ] Clone the team repository into a new folder.
- [ ] Follow the documented setup instructions.
- [ ] Run `make demo`.
- [ ] Confirm that the demo starts successfully.
- [ ] Record any setup or startup errors.

Status: NOT TESTED

Notes: TODO

## 2. Incident List

- [ ] Incident list loads.
- [ ] Severity and status badges appear.
- [ ] Incident budget is displayed correctly.
- [ ] Incident sorting works.
- [ ] Empty incident list is handled.

Status: NOT TESTED

Notes: TODO

## 3. Incident Detail

- [ ] Selecting an incident opens its details.
- [ ] First-alert detection time is correct.
- [ ] Attack timeline displays UTC timestamps.
- [ ] ATT&CK tactics and techniques are displayed.
- [ ] Chain-stop marker appears correctly.
- [ ] Recovered held signals are identified.

Status: NOT TESTED

Notes: TODO

## 4. Evidence Panel

- [ ] Evidence events are grouped by signal.
- [ ] Event details are displayed correctly.
- [ ] Raw evidence can be expanded.
- [ ] Missing events are handled safely.
- [ ] Empty evidence is handled.

Status: NOT TESTED

Notes: TODO

## 5. Response Navigation

- [ ] Proposed response actions are displayed.
- [ ] Review Response button is visible.
- [ ] Response navigation works after integration.
- [ ] No unsafe response is automatically executed.

Status: NOT TESTED

Notes: TODO

## 6. Automated Checks

- [ ] Run `npm test`.
- [ ] Run `npm run lint`.
- [ ] Run `npm run build`.
- [ ] Record the results of all three commands.

Status: NOT TESTED ON TEAM FRONTEND

Notes: Vitest tests are prepared in a temporary
working copy. Final execution is pending the
shared frontend and test setup.

## 7. Offline Demo

- [ ] Disconnect from external network services.
- [ ] Start the intended local demo.
- [ ] Confirm the frontend loads.
- [ ] Confirm incident data is available.
- [ ] Verify the complete demo walkthrough.

Status: NOT TESTED

Notes: TODO

## 8. Issues Found

| Issue | Severity | Status | Notes |
|---|---|---|---|
| Shared frontend integration pending | Pending | Open | Awaiting team frontend |
| Fresh-clone verification pending | Pending | Open | Requires integrated demo |

## 9. Final QA Summary

Overall status: PENDING

Final verification will be completed after
the shared frontend and backend are integrated.

Do not mark any unchecked item as passed
without testing it.
