# Validation

Local checks on 2026-10-02, Python 3.14.6: 32 unittest methods pass, with table-driven cases covering v2/v3, scope/nesting, exact host/port, userinfo/query privacy, scheme handling, percent decoding, traversal ambiguity, route binding, unknown aliases/workspaces, strict JSON, finite numbers, budgets and safe file input. FAIL and OPEN can coexist without hiding the demonstrated violation. Actual downloads/authenticity remain OPEN even for a scoped PASS.

The wheel and sdist built successfully. A fresh consumer environment outside the source tree installed the current wheel with no index and no dependencies; all 32 tests pass with an empty PYTHONPATH. Installed command checks produce expected PASS/FAIL/OPEN and 0/1/2 exits, ASCII JSON and unchanged input bytes. An earlier build predating the final reader capability gate failed that consumer regression; it was rebuilt, force-reinstalled and retested before any publication.

Independent review found that the CLI error fallback omitted the permanent external-evidence fields and that hexadecimal numeric IPv4-style final host labels were admitted. Both were corrected before publication; existing host and CLI regression tables include the reproductions, with the same 32 test methods passing.

All five new runtime files, test source, package/CI metadata, provenance and licensing were read. Formatting and selected syntax/undefined-name checks pass. The selected upstream review is recorded in SOURCE_AUDIT.json; upstream tests, dependencies and original behavior outside this project contract are not claimed fully audited or equivalent.

Reproduce with `PYTHONPATH=src python -m unittest discover -s tests -v`, then `python -m build`. Install the built wheel into a fresh environment, empty PYTHONPATH and rerun the tests from outside the source checkout. Source/package hash and license identity evidence is recorded in the goal's engineering report. Build archive timestamps may change on rebuilding. Remote CI, real package fetching/integration, package authenticity, dependency vulnerability review and CVP application facts remain OPEN until supported by matching independent evidence.
