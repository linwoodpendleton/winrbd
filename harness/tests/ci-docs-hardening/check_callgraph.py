#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Mechanical check of the stack rules in docs/design/core-architecture.md section 2.4 and core/README.md:
# no recursion, a bounded call depth and a bounded worst-case stack for every entry point of the core.
#
# It compiles every file of core/sources.txt with gcc -O2 -fcallgraph-info=su (needs gcc 10 or newer), reads the
# per-function stack sizes and call edges that gcc writes (.ci files), and walks the graph:
#
#   * a cycle in the graph is a recursion: failure;
#   * depth = the longest chain of functions from any entry point (frames, not counting calls through function pointers);
#   * stack = the largest sum of the static frame sizes along a chain (the same blind spot: a call through a function
#     pointer, such as a host callback or the crypto override table, ends the chain).
#
# Both numbers are measured, not estimated; the limits below are ratchets set just above today's values so a change
# that makes the worst case grow shows up in review. Lower them when the code gets shallower.
#
#   python3 harness/tests/ci-docs-hardening/check_callgraph.py [--cc gcc] [--depth 14] [--stack 2048] [--keep DIR]
#
# Run by the `static-limits` job of .github/workflows/harness.yml. Exit 0 = within the limits, 1 = not, 2 = tool error.
import argparse
import collections
import glob
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
CORE = os.path.join(REPO, "core")


def compile_all(cc, outdir):
    with open(os.path.join(CORE, "sources.txt")) as f:
        sources = [l.strip() for l in f if l.strip()]
    incs = ["-I" + os.path.join(CORE, "include"), "-I" + os.path.join(CORE, "include", "winrbd")]
    srcdir = os.path.join(CORE, "src")
    incs += ["-I" + os.path.join(srcdir, d) for d in sorted(os.listdir(srcdir)) if os.path.isdir(os.path.join(srcdir, d))]
    for rel in sources:
        base = os.path.basename(rel)
        cmd = [cc, "-std=c99", "-O2", "-fno-stack-protector", "-fcallgraph-info=su", "-c",
               "-o", os.path.join(outdir, base + ".o")] + incs + [os.path.join(CORE, rel)]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        if r.returncode != 0:
            sys.stderr.write("check_callgraph: compiling %s failed:\n%s\n" % (rel, r.stdout))
            sys.exit(2)
    return len(sources)


def read_graph(outdir):
    edges = collections.defaultdict(set)
    size = {}
    for f in glob.glob(os.path.join(outdir, "*.ci")):
        text = open(f).read()
        for m in re.finditer(r'node: \{ title: "([^"]+)" label: "([^"]*)"', text):
            s = re.search(r"(\d+) bytes", m.group(2))
            size[m.group(1)] = int(s.group(1)) if s else 0
        for m in re.finditer(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"', text):
            edges[m.group(1)].add(m.group(2))
    return edges, size


def analyse(edges, size):
    """Longest chain (frames) and largest stack sum from every node; None, chain on a cycle."""
    depth, stack = {}, {}
    state = {}

    def visit(n, path):
        if state.get(n) == 2:
            return None
        if state.get(n) == 1:
            return path[path.index(n):] + [n]
        state[n] = 1
        path.append(n)
        best_d, best_s = 0, 0
        for t in sorted(edges.get(n, ())):
            cyc = visit(t, path)
            if cyc is not None:
                return cyc
            best_d = max(best_d, depth[t])
            best_s = max(best_s, stack[t])
        path.pop()
        state[n] = 2
        depth[n] = 1 + best_d
        stack[n] = size.get(n, 0) + best_s
        return None

    sys.setrecursionlimit(100000)
    for n in sorted(set(size) | set(edges)):
        cyc = visit(n, [])
        if cyc is not None:
            return None, None, cyc
    return depth, stack, None


def chain(n, depth, edges):
    out = [n]
    while edges.get(n):
        n = max(sorted(edges[n]), key=lambda t: depth[t])
        out.append(n)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cc", default=os.environ.get("CC", "gcc"))
    ap.add_argument("--depth", type=int, default=14, help="largest allowed call chain, in frames")
    ap.add_argument("--stack", type=int, default=2048, help="largest allowed static stack along a chain, in bytes")
    ap.add_argument("--keep", help="keep the object and .ci files in this directory")
    a = ap.parse_args()

    tmp = None
    outdir = a.keep
    if outdir is None:
        tmp = tempfile.TemporaryDirectory(prefix="wr_callgraph.")
        outdir = tmp.name
    else:
        os.makedirs(outdir, exist_ok=True)
    n = compile_all(a.cc, outdir)
    edges, size = read_graph(outdir)
    if not size:
        sys.stderr.write("check_callgraph: no call graph information found (gcc 10 or newer is needed)\n")
        return 2
    depth, stack, cyc = analyse(edges, size)
    if cyc is not None:
        print("check_callgraph: RECURSION: " + " > ".join(cyc))
        return 1
    top_d = max(depth, key=lambda k: depth[k])
    top_s = max(stack, key=lambda k: stack[k])
    print("check_callgraph: %d files, %d functions" % (n, len(size)))
    names = [x.replace(REPO + os.sep, "") for x in chain(top_d, depth, edges)]
    print("  deepest chain: %d frames (limit %d): %s" % (depth[top_d], a.depth, " > ".join(names)))
    print("  largest stack: %d bytes (limit %d) from %s" % (stack[top_s], a.stack, top_s.replace(REPO + os.sep, "")))
    bad = 0
    if depth[top_d] > a.depth:
        print("check_callgraph: call depth %d is above the limit %d" % (depth[top_d], a.depth))
        bad = 1
    if stack[top_s] > a.stack:
        print("check_callgraph: stack %d is above the limit %d" % (stack[top_s], a.stack))
        bad = 1
    return bad


if __name__ == "__main__":
    sys.exit(main())
