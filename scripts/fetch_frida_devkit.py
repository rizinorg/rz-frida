#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

"""Fetch the frida-core devkit for a platform into shared cache."""

import hashlib
import json
import os
import random
import shutil
import sys
import tarfile
import time
import urllib.error
import urllib.request

API_RELEASE_TEMPLATE = "https://api.github.com/repos/frida/frida/releases/tags/%s"
DOWNLOAD_TEMPLATE = "https://github.com/frida/frida/releases/download/%s/%s"
USER_AGENT = "rz-frida-devkit-fetch"


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


def devkit_info(version, platform):
    """Expected sha256 and size of the devkit asset, die on problems."""
    name = "frida-core-devkit-%s-%s.tar.xz" % (version, platform)
    for asset in api_get(API_RELEASE_TEMPLATE % version).get("assets", []):
        if asset.get("name") != name:
            continue
        digest = asset.get("digest") or ""
        if not digest.startswith("sha256:"):
            die("the release API gives no sha256 digest for %s" % name)
        return digest[len("sha256:"):], int(asset["size"])
    die("frida release %s has no devkit for platform %s" % (version, platform))


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


def extract(archive, dest):
    """Extract a tar archive, rejecting paths that escape dest."""
    with tarfile.open(archive, "r") as tar:
        for member in tar:
            if member.name.startswith("/") or ".." in member.name.split("/"):
                die("refusing unsafe path in archive: %s" % member.name)
            try:
                tar.extract(member, dest, set_attrs=True, filter="data")
            except TypeError:
                # python < 3.12 has no filter arg
                tar.extract(member, dest, set_attrs=True)


def is_cached(directory):
    """True when the cached devkit is complete, verified at install time."""
    return os.path.isfile(os.path.join(directory, ".digest")) \
        and os.path.isfile(os.path.join(directory, "frida-core.h"))


def clean_stale_tmp(cache):
    """Drop temp dirs"""
    now = time.time()
    for entry in os.listdir(cache):
        if not entry.startswith(".tmp-"):
            continue
        path = os.path.join(cache, entry)
        try:
            if now - os.path.getmtime(path) > 3600:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            continue


def main():
    if len(sys.argv) != 3:
        die("usage: fetch_frida_devkit.py <frida-version> <platform>")
    version, platform = sys.argv[1], sys.argv[2]
    cache = cache_root()
    final = os.path.join(cache, "frida-core-devkit-%s-%s" % (version, platform))
    if is_cached(final):
        print(final)
        return 0
    expected_sha, expected_size = devkit_info(version, platform)
    os.makedirs(cache, exist_ok=True)
    clean_stale_tmp(cache)
    tmp = os.path.join(cache, ".tmp-%d-%d" % (os.getpid(), random.randint(0, 1 << 30)))
    os.makedirs(tmp)
    try:
        name = "frida-core-devkit-%s-%s.tar.xz" % (version, platform)
        archive = os.path.join(tmp, name)
        download(DOWNLOAD_TEMPLATE % (version, name), archive)
        actual_sha = sha256_of(archive)
        actual_size = os.path.getsize(archive)
        if actual_sha != expected_sha or actual_size != expected_size:
            die("devkit verification failed: sha256 %s (expected %s), "
                "size %d (expected %d)"
                % (actual_sha, expected_sha, actual_size, expected_size))
        extract(archive, tmp)
        if not os.path.isfile(os.path.join(tmp, "frida-core.h")):
            die("devkit archive misses frida-core.h")
        os.remove(archive)
        with open(os.path.join(tmp, ".digest"), "w") as marker:
            marker.write("%s %d\n" % (expected_sha, expected_size))
        if os.path.isdir(final):
            shutil.rmtree(final, ignore_errors=True)
        os.replace(tmp, final)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(final)
    return 0


if __name__ == "__main__":
    sys.exit(main())
