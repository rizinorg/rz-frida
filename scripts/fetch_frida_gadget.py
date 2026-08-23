#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

"""Fetch a frida-gadget shared library into the shared cache.

Prints the decompressed .so path on stdout. Cache stays next to the
frida-core devkit cache (~/.cache/rz-frida on Linux).
"""

from __future__ import print_function

import hashlib
import json
import lzma
import os
import random
import shutil
import sys
import time
import urllib.error
import urllib.request

API_RELEASE_TEMPLATE = "https://api.github.com/repos/frida/frida/releases/tags/%s"
DOWNLOAD_TEMPLATE = "https://github.com/frida/frida/releases/download/%s/%s"
USER_AGENT = "rz-frida-gadget-fetch"


def die(message):
    print("error: %s" % message, file=sys.stderr)
    sys.exit(1)


def cache_root():
    """Cache directory shared by every build on this machine."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "rz-frida")


def api_get(url):
    """GET a GitHub API resource with retries, die on failure."""
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
    })
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", "Bearer %s" % token)
    last_error = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                die("no frida release %s exists" % url.rsplit("/", 1)[-1])
            if error.code == 403:
                die("the GitHub API denied the request, likely rate limited, "
                    "retry later or set GITHUB_TOKEN")
            last_error = error
        except (urllib.error.URLError, OSError) as error:
            last_error = error
        time.sleep(2 ** attempt)
    die("cannot reach the GitHub API: %s" % last_error)


def gadget_info(version, platform):
    """Expected sha256 and size of the gadget xz asset."""
    name = "frida-gadget-%s-%s.so.xz" % (version, platform)
    for asset in api_get(API_RELEASE_TEMPLATE % version).get("assets", []):
        if asset.get("name") != name:
            continue
        digest = asset.get("digest") or ""
        if not digest.startswith("sha256:"):
            die("the release API gives no sha256 digest for %s" % name)
        return name, digest[len("sha256:"):], int(asset["size"])
    die("frida release %s has no gadget for platform %s" % (version, platform))


def download(url, dest):
    """Download a file with retries, die on failure."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_error = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                with open(dest, "wb") as output:
                    shutil.copyfileobj(response, output)
            return
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as error:
            last_error = error
            if os.path.exists(dest):
                os.remove(dest)
            time.sleep(2 ** attempt)
    die("could not download %s: %s" % (url, last_error))


def sha256_of(path):
    """Hex sha256 of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decompress_xz(archive, dest):
    """Decompress a single-file .xz into dest."""
    with lzma.open(archive, "rb") as src, open(dest, "wb") as out:
        shutil.copyfileobj(src, out)


def is_cached(so_path, marker):
    """True when the cached gadget is complete and marked."""
    return os.path.isfile(so_path) and os.path.isfile(marker)


def clean_stale_tmp(cache):
    """Drop temp dirs older than an hour."""
    now = time.time()
    if not os.path.isdir(cache):
        return
    for entry in os.listdir(cache):
        if not entry.startswith(".tmp-gadget-"):
            continue
        path = os.path.join(cache, entry)
        try:
            if now - os.path.getmtime(path) > 3600:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            continue


def main():
    if len(sys.argv) != 3:
        die("usage: fetch_frida_gadget.py <frida-version> <platform>")
    version, platform = sys.argv[1], sys.argv[2]
    cache = cache_root()
    so_name = "frida-gadget-%s-%s.so" % (version, platform)
    final_dir = os.path.join(cache, "frida-gadget-%s-%s" % (version, platform))
    so_path = os.path.join(final_dir, so_name)
    marker = os.path.join(final_dir, ".digest")
    if is_cached(so_path, marker):
        print(so_path)
        return 0
    name, expected_sha, expected_size = gadget_info(version, platform)
    os.makedirs(cache, exist_ok=True)
    clean_stale_tmp(cache)
    tmp = os.path.join(cache, ".tmp-gadget-%d-%d" % (os.getpid(), random.randint(0, 1 << 30)))
    os.makedirs(tmp)
    try:
        archive = os.path.join(tmp, name)
        print("downloading %s ..." % name, file=sys.stderr)
        download(DOWNLOAD_TEMPLATE % (version, name), archive)
        actual_sha = sha256_of(archive)
        actual_size = os.path.getsize(archive)
        if actual_sha != expected_sha or actual_size != expected_size:
            die("gadget verification failed: sha256 %s (expected %s), "
                "size %d (expected %d)"
                % (actual_sha, expected_sha, actual_size, expected_size))
        tmp_so = os.path.join(tmp, so_name)
        decompress_xz(archive, tmp_so)
        os.remove(archive)
        with open(os.path.join(tmp, ".digest"), "w") as handle:
            handle.write("%s %d\n" % (expected_sha, expected_size))
        if os.path.isdir(final_dir):
            shutil.rmtree(final_dir, ignore_errors=True)
        os.replace(tmp, final_dir)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if not os.path.isfile(so_path):
        die("gadget extract missed %s" % so_path)
    print(so_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
