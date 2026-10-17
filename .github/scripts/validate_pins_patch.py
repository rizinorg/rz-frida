# SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

"""Validate a dependency pin patch before it is uploaded or published.

The only accepted changes are version rewrites of the pin lines in the
workflow env blocks, of the meson frida_version option, and of the Cutter
version examples in the README. File creates, deletes, renames, copies,
mode or binary changes, non-pin edits, and malformed diffs are rejected.
"""

import re
import sys

ALLOWED_PATHS = (
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    "meson_options.txt",
    "README.md",
)

# Pin names that exist in each workflow env block.
WORKFLOW_PINS = {
    ".github/workflows/ci.yml": frozenset(("RIZIN_VERSION", "FRIDA_VERSION")),
    ".github/workflows/release.yml": frozenset(
        ("RIZIN_VERSION", "FRIDA_VERSION", "CUTTER_VERSION")
    ),
}

VERSION = r"v?\d+(?:\.\d+)+"

DIFF_HEADER = re.compile(r"^diff --git a/(\S+) b/(\S+)$")
INDEX_LINE = re.compile(r"^index [0-9a-f]{4,64}\.\.[0-9a-f]{4,64} 100644$")
HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")

PIN_LINE = re.compile(
    r"^  (RIZIN_VERSION|FRIDA_VERSION|CUTTER_VERSION): (" + VERSION + r")$"
)
MESON_LINE = re.compile(
    r"^option\('frida_version', type: 'string', value: '("
    + VERSION
    + r")', description: ('[^']*')\)$"
)

# The Cutter version mentions the bump script rewrites in the README.
README_FILENAME = re.compile(r"Cutter-(" + VERSION + r")-(Linux|macOS|Windows)")
README_PHRASE = re.compile(r"Cutter (" + VERSION + r") AppImage")


class PatchError(Exception):
    """The patch is not a plain dependency version bump."""


def validate_text(text):
    """Raise PatchError unless text is a clean version-only pin patch."""
    if not text.strip():
        raise PatchError("patch is empty")
    lines = text.splitlines()
    paths = set()
    index = 0
    while index < len(lines):
        index = _parse_file(lines, index, paths)
    if not paths:
        raise PatchError("patch has no file diffs")


def _parse_file(lines, index, paths):
    header = DIFF_HEADER.fullmatch(lines[index])
    if header is None:
        raise PatchError(
            "line %d: expected a 'diff --git' header, got %r"
            % (index + 1, lines[index])
        )
    old_path, new_path = header.group(1), header.group(2)
    if old_path != new_path:
        raise PatchError(
            "line %d: diff header renames %s to %s" % (index + 1, old_path, new_path)
        )
    if old_path not in ALLOWED_PATHS:
        raise PatchError(
            "line %d: %s is not an update target" % (index + 1, old_path)
        )
    if old_path in paths:
        raise PatchError("line %d: duplicate diff for %s" % (index + 1, old_path))
    paths.add(old_path)
    index += 1

    if index >= len(lines) or INDEX_LINE.fullmatch(lines[index]) is None:
        raise PatchError(
            "line %d: %s: expected an 'index <hash>..<hash> 100644' line"
            % (index + 1, old_path)
        )
    index += 1
    for marker in ("--- a/" + old_path, "+++ b/" + old_path):
        if index >= len(lines) or lines[index] != marker:
            raise PatchError(
                "line %d: %s: expected %r"
                % (index + 1, old_path, marker)
            )
        index += 1

    blocks = []
    hunks = 0
    while index < len(lines) and not lines[index].startswith("diff --git "):
        hunk = HUNK_HEADER.fullmatch(lines[index])
        if hunk is None:
            raise PatchError(
                "line %d: %s: malformed hunk header %r"
                % (index + 1, old_path, lines[index])
            )
        index += 1
        index, hunk_blocks = _parse_hunk(lines, index, old_path, hunk)
        blocks.extend(hunk_blocks)
        hunks += 1
    if hunks == 0:
        raise PatchError("%s: file diff has no hunks" % old_path)

    _validate_blocks(old_path, blocks)
    return index


def _parse_hunk(lines, index, path, header):
    old_left = int(header.group(2)) if header.group(2) is not None else 1
    new_left = int(header.group(4)) if header.group(4) is not None else 1
    blocks = []
    minus = []
    plus = []
    seen_plus = False

    def flush():
        nonlocal minus, plus, seen_plus
        if minus or plus:
            blocks.append((minus, plus))
        minus, plus, seen_plus = [], [], False

    while old_left > 0 or new_left > 0:
        if index >= len(lines):
            raise PatchError(
                "line %d: %s: hunk is truncated, missing %d old and %d new lines"
                % (index + 1, path, old_left, new_left)
            )
        line = lines[index]
        if line.startswith(" "):
            flush()
            old_left -= 1
            new_left -= 1
        elif line.startswith("-"):
            if seen_plus:
                raise PatchError(
                    "line %d: %s: '-' after '+' in a change block"
                    % (index + 1, path)
                )
            minus.append(line[1:])
            old_left -= 1
        elif line.startswith("+"):
            plus.append(line[1:])
            seen_plus = True
            new_left -= 1
        else:
            raise PatchError(
                "line %d: %s: malformed diff line %r" % (index + 1, path, line)
            )
        if old_left < 0 or new_left < 0:
            raise PatchError(
                "line %d: %s: hunk has more lines than its header declares"
                % (index + 1, path)
            )
        index += 1
    flush()
    if not blocks:
        raise PatchError("%s: hunk changes no lines" % path)
    return index, blocks


def _validate_blocks(path, blocks):
    if path in WORKFLOW_PINS:
        _validate_workflow_blocks(path, blocks)
    elif path == "meson_options.txt":
        _validate_meson_blocks(blocks)
    else:
        _validate_readme_blocks(blocks)


def _validate_workflow_blocks(path, blocks):
    pins = WORKFLOW_PINS[path]
    for minus, plus in blocks:
        if len(minus) != len(plus):
            raise PatchError("%s: pin lines must be edited in place" % path)
        for old_line, new_line in zip(minus, plus):
            old = PIN_LINE.fullmatch(old_line)
            new = PIN_LINE.fullmatch(new_line)
            if old is None or new is None:
                raise PatchError(
                    "%s: not a pin line: %r -> %r" % (path, old_line, new_line)
                )
            name = old.group(1)
            if new.group(1) != name:
                raise PatchError(
                    "%s: pin %s was turned into %s" % (path, name, new.group(1))
                )
            if name not in pins:
                raise PatchError("%s: %s is not pinned in this workflow" % (path, name))
            if old.group(2) == new.group(2):
                raise PatchError(
                    "%s: pin %s keeps the version %s" % (path, name, old.group(2))
                )


def _validate_meson_blocks(blocks):
    for minus, plus in blocks:
        if len(minus) != len(plus):
            raise PatchError("meson_options.txt: option line must be edited in place")
    pairs = [pair for minus, plus in blocks for pair in zip(minus, plus)]
    if len(pairs) != 1:
        raise PatchError(
            "meson_options.txt: expected exactly one frida_version line edit"
        )
    old_line, new_line = pairs[0]
    old = MESON_LINE.fullmatch(old_line)
    new = MESON_LINE.fullmatch(new_line)
    if old is None or new is None:
        raise PatchError(
            "meson_options.txt: not the frida_version option: %r -> %r"
            % (old_line, new_line)
        )
    if old.group(2) != new.group(2):
        raise PatchError(
            "meson_options.txt: frida_version edit changes more than the version"
        )
    if old.group(1) == new.group(1):
        raise PatchError(
            "meson_options.txt: frida_version keeps the value %s" % old.group(1)
        )


def _readme_versions(line):
    versions = [match.group(1) for match in README_FILENAME.finditer(line)]
    versions.extend(match.group(1) for match in README_PHRASE.finditer(line))
    return versions


def _replace_readme_versions(line, version):
    line = README_FILENAME.sub(
        lambda match: "Cutter-%s-%s" % (version, match.group(2)), line
    )
    return README_PHRASE.sub("Cutter %s AppImage" % version, line)


def _validate_readme_blocks(blocks):
    old_versions = set()
    new_versions = set()
    for minus, plus in blocks:
        if len(minus) != len(plus):
            raise PatchError("README.md: version mentions must be edited in place")
        for old_line, new_line in zip(minus, plus):
            old_found = _readme_versions(old_line)
            new_found = _readme_versions(new_line)
            if not old_found or not new_found:
                raise PatchError(
                    "README.md: not a Cutter version mention: %r" % old_line
                )
            if len(set(old_found)) != 1 or len(set(new_found)) != 1:
                raise PatchError(
                    "README.md: mixed Cutter versions in %r -> %r"
                    % (old_line, new_line)
                )
            old_version = old_found[0]
            new_version = new_found[0]
            if old_version == new_version:
                raise PatchError("README.md: %s keeps the version" % old_version)
            expected = _replace_readme_versions(old_line, new_version)
            if expected != new_line:
                raise PatchError(
                    "README.md: %r is not the expected version substitution of %r"
                    % (new_line, old_line)
                )
            old_versions.add(old_version)
            new_versions.add(new_version)
    if len(old_versions) != 1 or len(new_versions) != 1:
        raise PatchError("README.md: inconsistent Cutter versions in the diff")


def main(argv):
    if len(argv) != 2:
        print("usage: validate_pins_patch.py <patch>", file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as handle:
            text = handle.read()
    except OSError as error:
        print("error: cannot read %s: %s" % (argv[1], error), file=sys.stderr)
        return 2
    try:
        validate_text(text)
    except PatchError as error:
        print("::error::pins.patch rejected: %s" % error, file=sys.stderr)
        return 1
    print("pins.patch ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
