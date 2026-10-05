> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# PackageOriginReview


New implementation author: **dhtfish98**. Current project version: **0.1.3**.

Offline review of **declared** npm package-lock v2/v3 registry sources. It checks exact allowed hosts, HTTPS, default TLS port, absence of userinfo/query/fragment, decoded path ambiguity and package-name-to-tarball-route binding. It never downloads, installs or executes a package or configuration.

```sh
python -m pip install .
package-origin-review package-lock.json
package-origin-review package-lock.json --allow-host registry.example.test
```

`--allow-host` replaces the default `registry.npmjs.org` policy; repeats permit a finite list of exact fully qualified ASCII DNS names, with A-label spelling when needed. HTTPS port 443 may be explicit. No domain suffix, wildcard, URL or IP is accepted as host policy. Only the standard root route `/name/-/name-suffix.tgz` or `/@scope/name/-/name-suffix.tgz` is supported; custom registry prefixes have not been modeled. The suffix is shape-checked, not compared to a version pin.

Exit 0/PASS means all declared supported entries meet this origin policy; 1/FAIL means a demonstrated policy violation, possibly alongside incomplete entries; 2/OPEN means incomplete or unsupported analysis without a demonstrated violation. `complete` is false for unknown entries or exhausted budgets. The report always leaves actual fetch origin and package authenticity OPEN, and always states that integrity and version pin checks were not performed. Findings identify insertion indices in the JSON `packages` object, counting the root entry if present; raw paths, resolved URLs, query tokens and userinfo are never echoed.

The [npm format documentation](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/) explains registry substitution and relative tarball locations. We review the declared absolute URL rather than resolving npm configuration: registry settings, redirects and actual bytes received remain unobserved. Alias/name differences, workspace links, non-node_modules workspace paths, linked-store layouts, git/file/link sources, missing/relative resolved values, legacy v1 and other package-manager formats remain OPEN. No root entry is required, allowing hidden v3 manifests; root dependency lists are not a second installation inventory. Empty package maps yield a scoped vacuous PASS with zero checked entries.

JSON must be strict UTF-8 with no duplicate object keys or nonfinite constants. Limits are 4 MiB input, 64 JSON levels, 4,000 non-root entries, 512 finding records, 1,024-character installation paths and 2,048-character URLs; callers can only lower them. Input requires POSIX no-follow descriptors, an ordinary file and no original `..` component; metadata changes during reading are rejected. The bytes observed are identified by SHA-256; this is not an authenticity proof or a guarantee against a writer evading metadata checks.

Supported package names are at most 214 characters, with each unscoped or scope/name component starting with a lowercase ASCII letter or digit and continuing with lowercase letters, digits, dots, underscores or hyphens. Legacy names outside that conservative grammar remain OPEN. Numeric final host labels are not accepted in policy, avoiding IPv4-style address interpretation. These are declared local policy choices, not a complete reimplementation of npm's package-name grammar.

See ORIGIN.md, DEFENSIVE_SCOPE.md, SOURCE_AUDIT.json and VALIDATION.md for the selected upstream scope, contribution and measured checks.

Local-file capability boundary: required OS flags must be exact positive integers. Descriptor walking also requires declared `os.open` directory-relative support. Missing, null, zero, boolean or otherwise invalid required capabilities return a controlled OPEN result before file access. Native Windows local-file reading is outside this POSIX profile.
