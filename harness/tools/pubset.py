# SPDX-License-Identifier: MIT
"""
pubset.py - shared defaults for the winrbd checkers.

Every checker runs from a fresh clone of this repository with no other directory next to it:

  - the capture set defaults to the public vector set,          harness/vectors/public
  - the cephx keys default to the throw-away public keys,       harness/vectors/public/keys
  - the Ceph data needed at run time (CRUSH ln tables and the in-tree known-answer tests) is read from
    a directory given by --ceph-src, else the environment variable WINRBD_CEPH_SRC, else
    harness/.ceph-ref (git-ignored; filled by harness/tools/fetch-ceph-ref.sh).

Every path is resolved from this file's own location, never from the current directory.

This module also defines the two result lines that harness/tools/run-all.sh reads (the checkers keep their own
human-readable reports as well):

  WINRBD-RESULT tool=<name> passed=<n> failed=<n> skipped=<n>
  WINRBD-SKIP tool=<name> what=<short name> reason=<why>

A check whose input is not in the capture set is reported as a SKIP with its reason; a SKIP never fails a run.

Nothing in here touches key material.
"""

import os
import sys

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(TOOLS_DIR, "..", ".."))
PUBLIC_SET = os.path.join(REPO, "harness", "vectors", "public")
PUBLIC_KEYS = os.path.join(PUBLIC_SET, "keys")
DEFAULT_CEPH_SRC = os.path.join(REPO, "harness", ".ceph-ref")
CEPH_SRC_ENV = "WINRBD_CEPH_SRC"
PINNED_CEPH_COMMIT = "ed27c686770872022f4c1de04f6b0ac5d5384ded"

# Ceph files read at run time (relative to the Ceph source root).  fetch-ceph-ref.sh downloads exactly these.
CRUSH_LN_TABLE = "src/crush/crush_ln_table.h"
CRUSHTOOL_TEST_DIR = "src/test/cli/crushtool"


def is_public_set(captures):
    """True when `captures` is the public vector set of this repository."""
    try:
        return os.path.realpath(captures) == os.path.realpath(PUBLIC_SET)
    except OSError:
        return False


def captures_dir(arg=None):
    """--captures value, or the public set."""
    return os.path.abspath(arg) if arg else PUBLIC_SET


def default_keys_dir(captures):
    """Where the keyrings are when --keys is not given.

    The public set: only harness/vectors/public/keys.  Any other capture set keeps the old layout
    (<captures>/../lab-secrets; the tools add <captures>/secrets/keys themselves)."""
    if is_public_set(captures):
        return PUBLIC_KEYS
    return os.path.join(os.path.dirname(os.path.abspath(captures).rstrip(os.sep)), "lab-secrets")


def ceph_src(arg=None):
    """Directory holding the run-time Ceph data: --ceph-src, else $WINRBD_CEPH_SRC, else harness/.ceph-ref."""
    if arg:
        return os.path.abspath(arg)
    env = os.environ.get(CEPH_SRC_ENV)
    if env:
        return os.path.abspath(env)
    return DEFAULT_CEPH_SRC


def ceph_hint(root):
    return ("the Ceph run-time data is not under %s; run harness/tools/fetch-ceph-ref.sh (or harness/tools/run-all.sh), "
            "or point --ceph-src / %s at a Ceph source tree at commit %s" % (root, CEPH_SRC_ENV, PINNED_CEPH_COMMIT))


# ---------------------------------------------------------------------------------------------------------
# result lines
# ---------------------------------------------------------------------------------------------------------

_SKIPS = []


def skip(tool, what, reason):
    """Record (and print) a check that could not run because its input is not in the capture set."""
    _SKIPS.append((what, reason))
    print("  SKIP %s: %s" % (what, reason), flush=True)


def skips():
    return list(_SKIPS)


def emit_result(tool, passed, failed, extra_skips=()):
    """Print the machine-readable result lines (last thing a checker prints)."""
    allskips = list(_SKIPS) + list(extra_skips)
    for what, reason in allskips:
        print("WINRBD-SKIP tool=%s what=%s reason=%s" % (tool, one_line(what), one_line(reason)))
    print("WINRBD-RESULT tool=%s passed=%d failed=%d skipped=%d" % (tool, passed, failed, len(allskips)))
    sys.stdout.flush()


def one_line(s):
    return " ".join(str(s).split()).replace("|", "/")
