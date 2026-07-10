#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

"""Embed the rz-frida agent script as a C string for the backend.

Reads the agent JavaScript and writes a header that defines a NUL terminated
byte array the backend loads into the target. Meson runs this during the build
when Python is available. The checked-in header is the fallback.

When node_modules and frida-compile are present the script bundles
frida-java-bridge into the agent via frida-compile before embedding it.
When the bridge is not installed (non-Android targets, CI without node),
the raw agent source is embedded as-is so the script loads without Java.

    python3 agent/embed_agent.py src/rzfrida_agent.h
"""

import os
import subprocess
import sys


BYTES_PER_ROW = 12


def render(data):
    # REUSE-IgnoreStart
    lines = [
        "// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>",
        "// SPDX-License-Identifier: LGPL-3.0-only",
        "",
        "// Generated from agent/ by agent/embed_agent.py.",
        "// Do not edit by hand, regenerate it after changing the agent.",
        "",
        "#ifndef RZ_FRIDA_AGENT_SOURCE_H",
        "#define RZ_FRIDA_AGENT_SOURCE_H",
        "",
        "static const unsigned char rz_frida_agent_source[] = {",
    ]
    # REUSE-IgnoreEnd
    values = ["0x%02x," % b for b in data]
    values.append("0x00")
    for start in range(0, len(values), BYTES_PER_ROW):
        lines.append("\t" + " ".join(values[start:start + BYTES_PER_ROW]))
    lines.append("};")
    lines.append("")
    lines.append("#endif")
    lines.append("")
    return "\n".join(lines)


def embed(input_path, output_path):
    with open(input_path, "rb") as src:
        data = src.read()
    with open(output_path, "w", newline="\n") as out:
        out.write(render(data))


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: embed_agent.py <output.h>\n")
        return 1

    output_path = argv[1]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    agent_js = os.path.join(script_dir, "rzfrida_agent.js")
    entry_js = os.path.join(script_dir, "entry.js")
    bundle_js = os.path.join(script_dir, "rzfrida_agent.bundle.js")
    frida_compile = os.path.join(script_dir, "node_modules", ".bin", "frida-compile")

    if os.path.isfile(frida_compile) and os.path.isfile(entry_js):
        try:
            subprocess.run(
                [frida_compile, "-o", bundle_js, entry_js],
                cwd=script_dir,
                check=True,
                capture_output=True,
                text=True,
            )
            with open(bundle_js, "rb") as f:
                raw = f.read()
            # keep only js
            js_start = raw.find(b"\xe2\x9c\x84\n")
            if js_start >= 0:
                raw = raw[js_start + 4:]
            with open(bundle_js, "wb") as f:
                f.write(raw)
            embed(bundle_js, output_path)
            return 0
        except (subprocess.CalledProcessError, OSError) as e:
            sys.stderr.write(
                "embed_agent: frida-compile failed (%s), embedding raw agent\n" % e
            )

    embed(agent_js, output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
