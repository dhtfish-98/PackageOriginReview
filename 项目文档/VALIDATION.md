> 本页保留 0.1.2 的历史验证记录；0.1.3 的发布验证状态请以对应提交的 GitHub Actions 和 Release 资产为准。

# Current delivery validation — 0.1.2

New implementation author and maintainer: dhtfish98. This patch removes only source-reference or unbundled-dependency notice copies identified as unused. Licenses/notices associated with redistributed material and specific OPEN applicability questions are retained byte-for-byte. The new own runtime differs only in version metadata; parser and policy behavior are unchanged.

Current source inventory: `SOURCE_REVIEW_MANIFEST.json` (self-digest excluded). Current source, package-install and source-package rebuild checks are recorded in the separate 2026-10-03 license-cleanup delivery evidence. Package inventories, author/version metadata and runtime bytes are checked against this formal source. Installation uses frozen local dependencies; target inputs are never executed. New-commit hosted CI and publication remain pending until the owner publishes this patch.

Engineering results do not establish human contribution, identity, organization, safeguards impact or CVP admission.

## Historical previous delivery evidence

The remaining text describes earlier versions and their original material inventories. It does not describe or validate this patch.

# Current delivery validation — 0.1.1

New implementation author and maintainer: dhtfish98. Current source inventory: `SOURCE_REVIEW_MANIFEST.json` (this manifest excludes its own digest). The 2026-10-03 delivery preserves original upstream license and notice bytes; current runtime additionally validates the required OS capability flags and directory-relative support before local file reads.

The existing suite has 36 passing test cases in the current source and in a fresh consumer of this version. Package verification checks version/author, artifact RECORD or archive inventories, runtime bytes against the formal source, and retained third-party licenses. Consumer installation uses local frozen dependencies and does not run target inputs. Detailed current artifact hashes and execution receipts are kept in the separate delivery evidence.

New-commit hosted CI and publication remain pending until the repository owner publishes this version.

These engineering checks do not establish upstream authorship, independent human review, actual safeguards impact or CVP eligibility.

## Historical delivery evidence

The following sections describe the earlier delivery and retain its original versions and checks. They do not validate a later artifact.

# Validation

Local checks on 2026-10-02, Python 3.14.6: 32 unittest methods pass, with table-driven cases covering v2/v3, scope/nesting, exact host/port, userinfo/query privacy, scheme handling, percent decoding, traversal ambiguity, route binding, unknown aliases/workspaces, strict JSON, finite numbers, budgets and safe file input. FAIL and OPEN can coexist without hiding the demonstrated violation. Actual downloads/authenticity remain OPEN even for a scoped PASS.

The wheel and sdist built successfully. A fresh consumer environment outside the source tree installed the current wheel with no index and no dependencies; all 32 tests pass with an empty PYTHONPATH. Installed command checks produce expected PASS/FAIL/OPEN and 0/1/2 exits, ASCII JSON and unchanged input bytes. An earlier build predating the final reader capability gate failed that consumer regression; it was rebuilt, force-reinstalled and retested before any publication.

Independent review found that the CLI error fallback omitted the permanent external-evidence fields and that hexadecimal numeric IPv4-style final host labels were admitted. Both were corrected before publication; existing host and CLI regression tables include the reproductions, with the same 32 test methods passing.

All five new runtime files, test source, package/CI metadata, provenance and licensing were read. Formatting and selected syntax/undefined-name checks pass. The selected upstream review is recorded in SOURCE_AUDIT.json; upstream tests, dependencies and original behavior outside this project contract are not claimed fully audited or equivalent.

Reproduce with `PYTHONPATH=src python -m unittest discover -s tests -v`, then `python -m build`. Install the built wheel into a fresh environment, empty PYTHONPATH and rerun the tests from outside the source checkout. Source/package hash and license identity evidence is recorded in the goal's engineering report. Build archive timestamps may change on rebuilding. Remote CI, real package fetching/integration, package authenticity, dependency vulnerability review and CVP application facts remain OPEN until supported by matching independent evidence.
