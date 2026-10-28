#!/usr/bin/env python3
"""Verify Skills CLI installation in temporary projects using an offline npm cache.

Populate a dedicated cache with skills@1.7.4 first, then pass --npm-cache if it
is not located at <system temporary directory>/meowpush-skill-npm-cache. This
check never installs global skills, sends notifications, or reads credentials.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


CLI_VERSION = "1.7.4"
AGENTS = {
    "codex": ".agents/skills/meowpush",
    "claude-code": ".claude/skills/meowpush",
    "cursor": ".agents/skills/meowpush",
}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class CheckFailure(Exception):
    pass


def run(command, cwd, environment):
    process = subprocess.run(command, cwd=cwd, env=environment, capture_output=True,
                             text=True, timeout=60)
    if process.returncode:
        # Test inputs are repository paths and empty temporary configuration only.
        output = ANSI.sub("", process.stdout + process.stderr)
        raise CheckFailure("Command failed: " + " ".join(command[:4]) + "\n" + output[-4000:])
    return ANSI.sub("", process.stdout)


def snapshot_runtime(source):
    paths = [Path("SKILL.md"), Path("agents/openai.yaml")]
    for pattern in ("scripts/*.py", "references/*.md"):
        paths.extend(path.relative_to(source) for path in sorted(source.glob(pattern)))
    if not any(path.parts[0] == "scripts" for path in paths):
        raise CheckFailure("No Python runtime files found in the skill source.")
    if not any(path.parts[0] == "references" for path in paths):
        raise CheckFailure("No references found in the skill source.")
    return {path: (source / path).read_bytes() for path in paths}


def verify_installation(root, expected, unrelated_cwd, empty_config, environment):
    for relative, original in expected.items():
        installed = root / relative
        if not installed.is_file() or installed.read_bytes() != original:
            raise CheckFailure("Installed resource is missing or differs: " + str(relative))
    script = root / "scripts/meowpush.py"
    help_text = run([sys.executable, str(script), "--help"], unrelated_cwd, environment)
    if "profiles" not in help_text or "send" not in help_text:
        raise CheckFailure("Installed CLI help did not expose the expected commands.")
    status = json.loads(run([sys.executable, str(script), "--config-dir", str(empty_config),
                             "profiles"], unrelated_cwd, environment))
    if status.get("status") != "not_configured" or status.get("profiles") != []:
        raise CheckFailure("Installed CLI did not inspect the empty temporary configuration correctly.")
    if status.get("credentials_file") != str(empty_config / "pk-credentials.json"):
        raise CheckFailure("Installed CLI used a configuration path outside the test directory.")
    return {"resources_verified": len(expected), "help": "passed", "profiles": "passed",
            "directory_kind": "symlink" if root.is_symlink() else "directory"}


def smoke(source, npm_cache):
    npm = shutil.which("npm")
    if not npm:
        raise CheckFailure("npm is required to run the installation smoke test.")
    command = [npm, "exec", "--offline", "--yes", "--cache", str(npm_cache),
               "--package=skills@" + CLI_VERSION, "--", "skills"]
    environment = dict(os.environ)
    environment["DISABLE_TELEMETRY"] = "1"
    environment["DO_NOT_TRACK"] = "1"
    results = {"ok": True, "cli": "skills", "version": None, "discovered_skills": [],
               "global_install": False, "live_api_requests": False, "modes": {}}
    with tempfile.TemporaryDirectory(prefix="meowpush-install-smoke-") as temporary:
        temporary_root = Path(temporary).resolve()
        unrelated_cwd = temporary_root / "unrelated-working-directory"
        unrelated_cwd.mkdir()
        version = run(command + ["--version"], unrelated_cwd, environment).strip()
        if version != CLI_VERSION:
            raise CheckFailure("The Skills CLI version differs from the pinned test version.")
        results["version"] = version
        discovery = run(command + ["add", str(source), "--list"], unrelated_cwd, environment)
        names = re.findall(r"^\s*│ {4}([a-z0-9-]+)\s*$", discovery, flags=re.MULTILINE)
        if names != ["meowpush"] or not re.search(r"Found 1 skill\b", discovery):
            raise CheckFailure("Expected exactly one discovered skill named meowpush.\n" + discovery)
        results["discovered_skills"] = names
        for mode in ("default", "copy"):
            project = temporary_root / (mode + "-project")
            project.mkdir()
            # Some CLI versions skip absent agent-specific project directories.
            (project / ".claude").mkdir()
            (project / ".cursor").mkdir()
            expected = snapshot_runtime(source)
            arguments = ["add", str(source), "--skill", "meowpush", "-a", *AGENTS, "--yes"]
            if mode == "copy":
                arguments.append("--copy")
            run(command + arguments, project, environment)
            checks = {}
            for agent, relative in AGENTS.items():
                checks[agent] = verify_installation(
                    project / relative, expected, unrelated_cwd,
                    temporary_root / (mode + "-" + agent + "-empty-config"), environment)
                checks[agent]["installed_path"] = relative
            results["modes"][mode] = checks
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--npm-cache", type=Path,
                        default=Path(tempfile.gettempdir()) / "meowpush-skill-npm-cache",
                        help="Dedicated npm cache already containing skills@1.7.4; execution is offline.")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    try:
        result = smoke(source, args.npm_cache.expanduser().resolve())
    except (CheckFailure, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=True))
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
