# Origin and contribution

Technical reference: [lirantal/lockfile-lint](https://github.com/lirantal/lockfile-lint/tree/3554c3444653a6efe7eeb883a39d798f58f0c210), fixed commit `3554c3444653a6efe7eeb883a39d798f58f0c210`, Apache-2.0. Credit belongs to Liran Tal and the upstream contributors; their license is retained unchanged.

The selected API's parser, host/HTTPS/scheme/URL/package-name validators, error/constants and exports, and CLI's configuration, manager, main and entry point were reviewed. Integrity validation was inspected to explicitly remove that mechanism from this project. SOURCE_AUDIT.json records files and fixed hashes; upstream tests, bundled fixtures and external dependency code were not fully audited or executed.

This Python implementation was newly written with Codex assistance at the repository owner's instruction. It does not invoke, wrap or vendor upstream runtime. Strict v2/v3 JSON, original-path-preserving descriptor input, decoded route validation, finite exact host policy, explicit unknown states and privacy-aware indexed diagnostics are implemented directly. The input utility shares the already reviewed POSIX design from the owner's new UnicodeSourceReview implementation under Apache-2.0.

This fully implements the declared-origin project scope, not all upstream npm/yarn/config/glob/integrity behavior. Missing declarations and parser errors cannot silently become successes. No upstream authorship, CVE discovery, independent human authorship of AI output, or CVP approval is claimed.
