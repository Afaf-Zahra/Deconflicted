# QA Notes

## Current demo check

### Problem 1: `make demo` fails immediately

Command:

`make demo`

Result:

`Makefile:10: *** missing separator.  Stop.`

The demo does not start because the Makefile reports a syntax error at line 10.

The Makefile was not modified because it is outside the allowed work paths.

## Frontend checks

### Lint

Command:

`cd web && npm run lint`

Result:

`Found 4 warnings and 0 errors.`

Lint completed successfully with no errors.

The warnings are React Compiler guidance about state updates inside effects.

### Tests

Command:

`cd web && npm test`

Result:

`9 passed (9)` test files and `37 passed (37)` tests.

### Production build

Command:

`cd web && npm run build`

Result:

Build completed successfully.

Vite reported a chunk-size warning for a JavaScript asset larger than 500 kB, but the build succeeded.

### Offline check

Command:

`cd web && sh scripts/check_offline.sh`

Result:

`Offline check passed.`

The offline check builds the UI and checks the generated `dist` output for external URL and font CDN references.

## QA summary

The frontend lint, test suite, production build, and offline check pass.

The remaining QA issue is the existing `make demo` Makefile syntax error.
