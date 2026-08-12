# SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

"""Bump the pinned dependency versions in the workflows and README.

Queries the latest GitHub release of rizin, frida, and Cutter and rewrites
the RIZIN_VERSION / FRIDA_VERSION / CUTTER_VERSION pins in the release and
ci workflows when a newer release exists.

Exit codes: 0 on success (changed or not), 1 when a version check fails.
"""

import json
import os
import re
import sys
import urllib.request

WORKFLOWS = [".github/workflows/release.yml", ".github/workflows/ci.yml"]
README = "README.md"

PINS = {
    "RIZIN_VERSION": "rizinorg/rizin",
    "FRIDA_VERSION": "frida/frida",
    "CUTTER_VERSION": "rizinorg/cutter",
}

# example in readme has mention of cutter versions
README_PATTERNS = {
    "CUTTER_VERSION": [
        (r"Cutter-%s-(Linux|macOS|Windows)", "Cutter-%s-%s"),
        (r"Cutter %s AppImage", "Cutter %s AppImage"),
    ],
}


def latest_release(repo):
    """Return tag name of the latest stable release of repo."""
    url = "https://api.github.com/repos/%s/releases/latest" % repo
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "rz-frida-version-bump",
        },
    )
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", "Bearer %s" % token)
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)
    return data["tag_name"]


def version_tuple(version):
    """Version to a comparable int tuple, None for non-numeric ones."""
    digits = re.sub(r"^v", "", version)
    parts = []
    for part in digits.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            return None
    return tuple(parts)


def parse_pins(path):
    """Read pinned versions out of a workflow env block."""
    pins = {}
    with open(path) as f:
        for line in f:
            match = re.match(r"^\s*([A-Z_]+):\s*(\S+)\s*$", line)
            if match and match.group(1) in PINS:
                pins[match.group(1)] = match.group(2)
    return pins


def bump_pin(path, name, current, latest):
    """Rewrite one pin line in a workflow, report whether it changed."""
    content = open(path).read()
    new_content = re.sub(
        r"(^\s*%s:\s*).*$" % re.escape(name),
        lambda m: m.group(1) + latest,
        content,
        count=1,
        flags=re.MULTILINE,
    )
    if new_content != content:
        open(path, "w").write(new_content)
        print("%s (%s): %s -> %s" % (name, path, current, latest))
        return True
    print("%s (%s): %s is current" % (name, path, current))
    return False


def bump_readme(readme, old, latest, patterns):
    """Rewrite the README version mentions, report whether it changed."""
    content = open(readme).read()
    changed = False
    for pattern, fmt in patterns:
        def replace(match, latest=latest, fmt=fmt):
            return fmt % tuple([latest] + list(match.groups()))

        new_content = re.sub(pattern % re.escape(old), replace, content)
        if new_content != content:
            print("README.md: %s -> %s" % (old, latest))
            content = new_content
            changed = True
    if changed:
        open(readme, "w").write(content)
    return changed


def main():
    changed = False
    latest = {}
    for name, repo in PINS.items():
        try:
            latest[name] = latest_release(repo)
        except Exception as e:
            print("error: cannot fetch %s: %s" % (repo, e))
            return 1

    reference = parse_pins(WORKFLOWS[0])
    for workflow in WORKFLOWS:
        pins = parse_pins(workflow)
        for name in PINS:
            current = pins.get(name)
            if current is None:
                if workflow == WORKFLOWS[0]:
                    print("warning: %s pin not found in %s" % (name, workflow))
                continue
            current_tuple = version_tuple(current)
            latest_tuple = version_tuple(latest[name])
            if current_tuple is None or latest_tuple is None:
                print("warning: cannot compare %s: %s vs %s" % (name, current, latest[name]))
                continue
            if latest_tuple > current_tuple:
                changed = bump_pin(workflow, name, current, latest[name]) or changed
            else:
                print("%s (%s): %s is current" % (name, workflow, current))

    for name, patterns in README_PATTERNS.items():
        current = reference.get(name)
        if not current:
            continue
        current_tuple = version_tuple(current)
        latest_tuple = version_tuple(latest[name])
        if current_tuple is None or latest_tuple is None:
            continue
        if latest_tuple > current_tuple:
            changed = bump_readme(README, current, latest[name], patterns) or changed

    print("changed=%s" % ("true" if changed else "false"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
