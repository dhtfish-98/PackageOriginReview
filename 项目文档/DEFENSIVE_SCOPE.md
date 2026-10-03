# Defensive contract

Input is one explicitly selected local JSON lockfile, plus finite host policy arguments. Output is bounded metadata and policy codes. Runtime has no sockets, external processes, loaders, executable configuration, dependency installation, filesystem recursion or mutations. JSON-looking text is never executed.

Use this to review authorized release metadata before package acceptance. It checks the input declarations, not registry contents, signatures, maliciousness, fetched origin, advisories or dependency version pins. Unsupported and malformed observations remain OPEN; demonstrated violations remain visible if another check is incomplete.

Synthetic tests use reserved documentation hosts and inert JSON. No tokens, production packages or executable attack fixtures are needed. CVP applicant identity, organizational affiliation, actual safeguards impact and approval remain separate OPEN facts. The project cannot guarantee admission or absence of model intervention.
