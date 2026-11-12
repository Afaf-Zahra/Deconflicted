# QA Notes

## Fresh clone demo

### Problem 1: `make demo` fails immediately

Command:

`make demo`

Result:

`Makefile:10: *** missing separator.  Stop.`

The demo does not start because the Makefile reports a syntax error at line 10.

### Problem 2: Web frontend is missing from the fresh clone

The fresh clone contains a `web/` directory with only the `mock/` directory and mock JSON files.

There is no `web/package.json` and no web source tree.

The Makefile references web commands for lint, tests, and build, but the required frontend package and source files are not present in the fresh clone.

### Passing check

Command:

`python -m pytest tests -q`

Result:

`11 passed in 0.06s`
