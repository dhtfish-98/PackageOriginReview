import argparse
import json
from .input import InputError, read_regular_file
from .review import Limits, Policy, review_bytes


class _UsageError(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise _UsageError("invalid_arguments")


def main(argv=None):
    parser = _Parser(
        description="Offline declared-origin review; actual downloads remain unobserved"
    )
    parser.add_argument("lockfile")
    parser.add_argument(
        "--allow-host",
        action="append",
        help="replace default host policy; exact fully qualified DNS hosts only",
    )
    try:
        args = parser.parse_args(argv)
        limits = Limits()
        policy = Policy(tuple(args.allow_host)) if args.allow_host else Policy()
        result = review_bytes(
            read_regular_file(args.lockfile, limits.input_bytes),
            policy=policy,
            limits=limits,
        )
    except (InputError, ValueError, _UsageError):
        result = {
            "schema_version": 1,
            "status": "OPEN",
            "complete": False,
            "actual_fetch_origin": "OPEN",
            "package_authenticity": "OPEN",
            "integrity_or_version_pin_checked": False,
            "errors": [{"code": "input_or_policy_error"}],
            "findings": [],
        }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[result["status"]]
