"""Minimal .env loader. No dependency on python-dotenv."""
from __future__ import annotations

import os
import sys
from pathlib import Path

# What a `.env` may set. The file is read from whatever directory the CLI runs
# in -- an export someone sent you, a shared work root -- so it is treated as
# untrusted input, and only keys that choose among the user's OWN targets are
# taken from it: which workspace, cluster, instance, namespace, OCI profile,
# region and auth mode.
#
# Not taken, even though they begin AIDP_/OCI_/FABRIC_: keys that change WHERE
# requests or credentials go. These values also reach the `aidp` CLI that
# `publish` runs, so a planted `AIDP_ENDPOINT` would send signed API calls to
# another host and a planted `OCI_CONFIG_FILE` would swap in someone else's
# key -- flagged, unfixed, in the oracle-samples security review (#146).
# They still work when exported in the shell, which is a choice the user made.
# Earlier the rule was any key with one of those prefixes, which kept out
# NODE_OPTIONS and PATH but let both of these through.
ALLOWED_KEYS = frozenset({
    "AIDP_WORKSPACE_KEY", "AIDP_CLUSTER_KEY", "AIDP_INSTANCE_ID",
    "OCI_NAMESPACE", "OCI_CLI_PROFILE", "OCI_CONFIG_PROFILE",
    "OCI_CLI_REGION", "OCI_CLI_AUTH",
})

# Keys that look like this tool's, so ignoring one is worth a warning. A
# stray PATH= or NODE_OPTIONS= was always ignored silently and still is.
KEY_PREFIXES = ("AIDP_", "OCI_", "FABRIC_")


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _unsafe_file(candidate: Path) -> str:
    """Why `candidate` must not be trusted, or "" when it may be read.

    POSIX only: a `.env` someone else owns, or one anyone else can write, is
    not the user's. On Windows `st_mode` carries no owner or ACL bits, so the
    check would say nothing true and is skipped.
    """
    if os.name == "nt" or not hasattr(os, "getuid"):
        return ""
    info = candidate.stat()
    if info.st_uid != os.getuid():
        return "it is owned by another user"
    if info.st_mode & 0o022:
        return "other users can write to it"
    return ""


def load_dotenv(path=".env") -> None:
    candidate = Path(path)
    if not candidate.is_file():
        return
    try:
        problem = _unsafe_file(candidate)
    except OSError:
        return
    if problem:
        _warn(f"ignored {candidate}: {problem}. Fix its owner or "
              f"permissions (chmod 600), or export the settings in your shell.")
        return
    try:
        lines = candidate.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError):
        return
    refused = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        if key not in ALLOWED_KEYS:
            if key.startswith(KEY_PREFIXES):
                refused.append(key)
            continue
        if key not in os.environ:
            os.environ[key] = value
    if refused:
        # Key names only, never values: a value may be a secret.
        _warn(f"ignored {', '.join(sorted(set(refused)))} from {candidate}: a "
              f".env may only set {', '.join(sorted(ALLOWED_KEYS))}. Export any "
              f"other setting in your shell if you mean it.")
