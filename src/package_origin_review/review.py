"""Strict npm v2/v3 JSON and registry-route policy; no npm configuration loads."""

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from urllib.parse import unquote_to_bytes, urlsplit

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 4 * 1024 * 1024
    json_depth: int = 64
    entries: int = 4000
    findings: int = 512
    path_chars: int = 1024
    url_chars: int = 2048

    def __post_init__(self):
        ceilings = (4 * 1024 * 1024, 64, 4000, 512, 1024, 2048)
        for value, ceiling in zip(self.__dict__.values(), ceilings, strict=True):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError("invalid_limits")


def _host(value):
    if not isinstance(value, str) or not value.isascii() or not 1 <= len(value) <= 253:
        raise ValueError("invalid_host_policy")
    lowered = value.lower()
    labels = lowered.split(".")
    if (
        len(labels) < 2
        or labels[-1].isdecimal()
        or re.fullmatch(r"0x[0-9a-f]+", labels[-1])
        or not all(_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError("invalid_host_policy")
    return lowered


@dataclass(frozen=True)
class Policy:
    allowed_hosts: tuple[str, ...] = ("registry.npmjs.org",)

    def __post_init__(self):
        if (
            type(self.allowed_hosts) is not tuple
            or not 1 <= len(self.allowed_hosts) <= 32
        ):
            raise ValueError("invalid_host_policy")
        object.__setattr__(
            self,
            "allowed_hosts",
            tuple(sorted(set(_host(h) for h in self.allowed_hosts))),
        )


def _package_name(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 214:
        return False
    parts = value[1:].split("/") if value.startswith("@") else [value]
    return len(parts) == (2 if value.startswith("@") else 1) and all(
        _NAME.fullmatch(p) for p in parts
    )


def _installed_name(path, limits):
    if not isinstance(path, str) or len(path) > limits.path_chars or not path.isascii():
        return None
    parts = path.split("/")
    if any(p in ("", ".", "..") or "\\" in p or ":" in p for p in parts):
        return None
    # First version supports a chain of node_modules/package installations only.
    # Workspace source paths and the .store linked strategy are explicit OPEN.
    i, last = 0, None
    while i < len(parts):
        if parts[i] != "node_modules" or i + 1 >= len(parts):
            return None
        i += 1
        if parts[i].startswith("@"):
            if i + 1 >= len(parts):
                return None
            last = parts[i] + "/" + parts[i + 1]
            i += 2
        else:
            last = parts[i]
            i += 1
        if not _package_name(last):
            return None
    return last


def _duplicate_free(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _json(data, limits):
    text = data.decode("utf-8", errors="strict")
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > limits.json_depth:
                raise ValueError("json_depth_limit")
        elif char in "]}":
            depth -= 1

    def nonfinite(_):
        raise ValueError("nonfinite_json_number")

    def finite_float(value):
        number = float(value)
        if number in (float("inf"), float("-inf")):
            raise ValueError("nonfinite_json_number")
        return number

    return json.loads(
        text,
        object_pairs_hook=_duplicate_free,
        parse_constant=nonfinite,
        parse_float=finite_float,
    )


def _origin(url, package_name, policy, limits):
    if not isinstance(url, str) or not url or len(url) > limits.url_chars:
        return "OPEN", "missing_or_invalid_resolved"
    if any(ord(c) <= 32 or ord(c) >= 127 or c == "\\" for c in url):
        return "FAIL", "ambiguous_url_characters"
    if url.startswith(("git+", "git:", "file:", "link:", "npm:")):
        return "OPEN", "non_registry_dependency"
    try:
        parsed = urlsplit(url)
        if not parsed.scheme:
            return "OPEN", "relative_resolved_needs_registry_configuration"
        if parsed.scheme not in ("https", "http", "ftp"):
            return "OPEN", "unsupported_resolved_scheme"
        if parsed.scheme != "https":
            return "FAIL", "https_required"
        if not parsed.netloc or parsed.hostname is None:
            return "OPEN", "malformed_resolved_url"
        if parsed.username is not None or parsed.password is not None:
            return "FAIL", "userinfo_forbidden"
        if parsed.hostname.lower() not in policy.allowed_hosts:
            return "FAIL", "host_not_allowed"
        # Check textual authority as well as parser output; reject ambiguous ports.
        authority = parsed.netloc.lower()
        if authority not in {parsed.hostname.lower(), parsed.hostname.lower() + ":443"}:
            return "FAIL", "port_or_authority_not_allowed"
        if parsed.query or parsed.fragment or "?" in url or "#" in url:
            return "FAIL", "query_or_fragment_forbidden"
        if not parsed.path.startswith("/") or re.search(
            r"%(?![0-9a-fA-F]{2})", parsed.path
        ):
            return "FAIL", "invalid_registry_path"
        parts = []
        for raw in parsed.path[1:].split("/"):
            part = unquote_to_bytes(raw).decode("ascii", errors="strict")
            if (
                not part
                or part in (".", "..")
                or any(ord(c) <= 32 or ord(c) >= 127 or c in "/\\:%" for c in part)
            ):
                return "FAIL", "ambiguous_registry_path"
            parts.append(part)
        expected = package_name.split("/") + ["-"]
        if len(parts) != len(expected) + 1 or parts[:-1] != expected:
            return "FAIL", "package_route_mismatch"
        basename = package_name.rsplit("/", 1)[-1]
        leaf = parts[-1]
        if (
            not leaf.startswith(basename + "-")
            or not leaf.endswith(".tgz")
            or len(leaf) > 300
        ):
            return "FAIL", "tarball_filename_policy"
        suffix = leaf[len(basename) + 1 : -4]
        if not suffix or not re.fullmatch(r"[A-Za-z0-9._+-]+", suffix):
            return "FAIL", "tarball_filename_policy"
        return "PASS", "declared_route_matches"
    except (ValueError, UnicodeError):
        return "OPEN", "malformed_resolved_url"


def review_bytes(data, *, policy=None, limits=None):
    policy = Policy() if policy is None else policy
    limits = Limits() if limits is None else limits
    if (
        not isinstance(data, bytes)
        or not isinstance(policy, Policy)
        or not isinstance(limits, Limits)
    ):
        raise TypeError("invalid_api_types")
    result = {
        "schema_version": 1,
        "status": "OPEN",
        "complete": False,
        "scope": "declared npm lockfile v2/v3 registry-origin policy only",
        "input_sha256": None,
        "input_bytes": len(data),
        "entries_checked": 0,
        "passed_entries": 0,
        "failed_entries": 0,
        "open_entries": 0,
        "allowed_hosts": list(policy.allowed_hosts),
        "limits": asdict(limits),
        "findings": [],
        "errors": [],
        "actual_fetch_origin": "OPEN",
        "package_authenticity": "OPEN",
        "integrity_or_version_pin_checked": False,
    }
    if len(data) > limits.input_bytes:
        result["errors"].append({"code": "input_byte_limit"})
        return result
    result["input_sha256"] = hashlib.sha256(data).hexdigest()
    try:
        document = _json(data, limits)
    except (UnicodeError, ValueError, RecursionError):
        result["errors"].append({"code": "invalid_or_overlimit_json"})
        return result
    if (
        not isinstance(document, dict)
        or type(document.get("lockfileVersion")) is not int
        or document.get("lockfileVersion") not in (2, 3)
    ):
        result["errors"].append({"code": "unsupported_lockfile_schema"})
        return result
    packages = document.get("packages")
    if not isinstance(packages, dict) or len(packages) > limits.entries + 1:
        result["errors"].append({"code": "packages_missing_or_entry_limit"})
        return result
    result["lockfile_version"] = document["lockfileVersion"]
    if "" in packages and not isinstance(packages[""], dict):
        result["errors"].append({"code": "invalid_root_metadata"})
        return result
    for index, (path, metadata) in enumerate(packages.items()):
        if path == "":
            continue
        if result["entries_checked"] >= limits.entries:
            result["errors"].append({"code": "entry_limit"})
            break
        if len(result["findings"]) >= limits.findings:
            result["errors"].append({"code": "finding_limit"})
            break
        result["entries_checked"] += 1
        name = _installed_name(path, limits)
        if not isinstance(metadata, dict):
            status, code = "OPEN", "invalid_entry_metadata"
        elif name is None:
            status, code = "OPEN", "unsupported_installation_path"
        elif "link" in metadata and type(metadata["link"]) is not bool:
            status, code = "OPEN", "invalid_link_flag"
        elif metadata.get("link"):
            status, code = "OPEN", "workspace_or_link_dependency"
        elif "name" in metadata and metadata["name"] != name:
            status, code = "OPEN", "alias_or_name_declaration_needs_review"
        else:
            status, code = _origin(metadata.get("resolved"), name, policy, limits)
        field = {
            "PASS": "passed_entries",
            "FAIL": "failed_entries",
            "OPEN": "open_entries",
        }[status]
        result[field] += 1
        if status != "PASS":
            # Stable insertion index locates the entry without echoing URL/userinfo.
            result["findings"].append(
                {"entry_index": index, "status": status, "code": code}
            )
    result["complete"] = not result["errors"] and not result["open_entries"]
    result["status"] = (
        "FAIL" if result["failed_entries"] else "PASS" if result["complete"] else "OPEN"
    )
    return result
