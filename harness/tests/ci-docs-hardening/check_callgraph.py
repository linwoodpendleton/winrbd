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
# A function defined in one file and only called from another appears in both .ci files, in the second without a size; the size
# that counts is the largest one seen, whatever order the files are read in (an earlier version let the sizeless node win in
# some orders and under-reported the worst chain by about 1.4 KiB).
#
# Both numbers are measured, not estimated; the limits below are ratchets set just above today's values so a change
# that makes the worst case grow shows up in review. Lower them when the code gets shallower. The depth limit is 17 frames since
# part D (it was 14): the deepest chain became the AUTH_SIGNATURE frame going out in secure mode (the handshake, the connection's
# send, the secure frame builder, the first GCM refill, the tag, the GHASH multiplication), which is 1.3 KiB of stack, so the
# stack limit did not move. gcc 13 and gcc 15 measure the same depth.
#
# --link CALLER=CALLEE (repeatable) adds the edge of a call through a function pointer that gcc cannot see (the msgr2 connection
# delivering a message to the upper layer's table, for one). Without it such a call ends the chain and the numbers under-report
# what the callee costs on top of the stack that is already live when it runs; the part C reply path (the OSD session's message
# handler and the decoder under it) is measured this way, from the engine's run down through the receive parser. Both names are
# resolved like an entry name; either one missing from the graph is a tool error. The links are part of the global depth and stack
# measurement too, so a hidden chain cannot slip past the limits just because it goes through a table.
#
# --entry NAME[=BYTES] (repeatable) reports the depth and the static stack of one entry point and, with =BYTES, fails above
# that budget. It exists for the chains of part B (OSD map, CRUSH, placement), of part C (the OSD step, the image step, the codecs)
# and of part D (secure mode: the receive step, the transmit frame, the GCM update chain and the chains around them; budgets are the
# larger of the gcc 13 and gcc 15 measurements plus about 8 %, rounded to 8 bytes), whose budgets are tighter than the global one
# and which would otherwise hide behind the single worst chain of the whole core. An entry that is not in the graph (a rename)
# is a tool error, so a budget cannot silently stop applying.
#
# An --entry has to be a function the core DEFINES. A name that is only called from the core (a function the host provides, a typo
# that still matches a call target) has no frame size in the graph, would measure 0 bytes and pass any budget for ever: it is a tool
# error, like a name that is not in the graph at all.
#
# --glue DIR (repeatable) is the completeness side of the budgets: every function of the core that a C file or header under DIR calls (a name
# of the core that is followed by an opening parenthesis in the code, comments and string literals left out) must be one of the
# --entry names, or the run fails and lists the ones without a budget. Without it a glue file that starts calling a new core function
# is never measured, and the table of budgets quietly stops being "every entry point the glue calls".
#
# --cflag FLAG (repeatable) adds a compiler flag after the defaults, so a later -O level or -m32 wins. It is how the numbers of the
# hosts that matter for the glue are measured: iPXE builds with -Os, and its BIOS images are 32-bit (i386), where pointers, size_t and
# the frames are smaller than on x86_64 (the worst static chain of the core: 2,632 bytes with -m32 -Os, 2,944 with -Os on x86_64, against
# the 3,000-odd of the default -O2 on x86_64). harness/tests/ci-docs-hardening/callgraph_ipxe.sh is the wrapper that fixes those flags and
# carries the budgets of the glue-facing entry points; CI runs it for both. --core DIR measures another copy of the core (the self-test
# of the gates feeds it a copy with a deepened chain).
#
#   python3 harness/tests/ci-docs-hardening/check_callgraph.py [--cc gcc] [--depth 17] [--stack 3328] [--keep DIR] [--core DIR]
#                                                              [--cflag FLAG]... [--link CALLER=CALLEE]... [--chains]
#                                                              [--entry NAME[=BYTES]]... [--glue DIR]...
#
# Run by the `static-limits` job of .github/workflows/harness.yml. Exit 0 = within the limits, 1 = not, 2 = tool error.
import argparse
import collections
import concurrent.futures
import glob
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
CORE = os.path.join(REPO, "core")


def compile_all(cc, outdir, core, cflags):
    with open(os.path.join(core, "sources.txt")) as f:
        sources = [l.strip() for l in f if l.strip()]
    incs = ["-I" + os.path.join(core, "include"), "-I" + os.path.join(core, "include", "winrbd")]
    srcdir = os.path.join(core, "src")
    incs += ["-I" + os.path.join(srcdir, d) for d in sorted(os.listdir(srcdir)) if os.path.isdir(os.path.join(srcdir, d))]
    # one gcc per file, a few at a time (the call graph is read afterwards in a fixed order, so the result does not depend on it)
    def one(rel):
        base = os.path.basename(rel)
        cmd = [cc, "-std=c99", "-O2", "-fno-stack-protector"] + cflags + ["-fcallgraph-info=su", "-c",
               "-o", os.path.join(outdir, base + ".o")] + incs + [os.path.join(core, rel)]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        return rel, r.returncode, r.stdout

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(8, os.cpu_count() or 1))) as pool:
        for rel, rc, out in pool.map(one, sources):
            if rc != 0:
                sys.stderr.write("check_callgraph: compiling %s failed:\n%s\n" % (rel, out))
                sys.exit(2)
    return len(sources)


def read_graph(outdir):
    """Edges, frame sizes, the functions whose frame gcc cannot bound (a VLA or alloca: '(dynamic)' without ',bounded') and the set of
    functions that have a frame size in some file, that is, the ones the core defines (the others are only call targets)."""
    edges = collections.defaultdict(set)
    size = {}
    unbounded = []
    defined = set()
    for f in sorted(glob.glob(os.path.join(outdir, "*.ci"))):
        text = open(f).read()
        for m in re.finditer(r'node: \{ title: "([^"]+)" label: "([^"]*)"', text):
            s = re.search(r"(\d+) bytes(?: \(([a-z,]+)\))?", m.group(2))
            # Every .ci file also lists the functions it only CALLS, as a node without a size. A function that is defined in
            # one file and called from another therefore appears several times, and the node with the size must win whatever
            # order the files are read in (a plain assignment made the result depend on the directory order).
            if s is None:
                size.setdefault(m.group(1), 0)
                continue
            defined.add(m.group(1))
            size[m.group(1)] = max(size.get(m.group(1), 0), int(s.group(1)))
            if s.group(2) not in (None, "static", "dynamic,bounded"):
                unbounded.append(m.group(1))
        for m in re.finditer(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"', text):
            edges[m.group(1)].add(m.group(2))
    return edges, size, unbounded, defined


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


def stack_chain(n, stack, size, edges):
    """The chain that gives the largest stack from n: (function, its own frame) pairs."""
    out = [(n, size.get(n, 0))]
    while edges.get(n):
        n = max(sorted(edges[n]), key=lambda t: stack[t])
        out.append((n, size.get(n, 0)))
    return out


def find_entry(name, depth):
    """A public function is in the graph under its bare name, a static one as '<file>:<name>'. A static name that exists in
    several files is written with the file's path from the repository root ('core/src/osd/wri_osd_sess_up.c:up_message')."""
    if name in depth:
        return name
    hits = sorted(k for k in depth if k.endswith(":" + name) or (":" in name and k.endswith("/" + name)))
    return hits[0] if len(hits) == 1 else None


def chain(n, depth, edges):
    out = [n]
    while edges.get(n):
        n = max(sorted(edges[n]), key=lambda t: depth[t])
        out.append(n)
    return out


_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.S)


def glue_calls(dirs, public):
    """The public functions of the core (names in PUBLIC) that the C files below DIRS call, as name followed by '('. Comments and string
    and character literals are blanked first, so a function that is only mentioned in text does not count. None on a tool error."""
    called = set()
    seen = 0
    for d in dirs:
        if not os.path.isdir(d):
            sys.stderr.write("check_callgraph: --glue %s is not a directory\n" % d)
            return None
        for root, _, names in os.walk(d):
            for n in sorted(names):
                if not n.endswith((".c", ".h")):
                    continue
                seen += 1
                text = _COMMENT.sub(" ", open(os.path.join(root, n), errors="replace").read())
                for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
                    if m.group(1) in public:
                        called.add(m.group(1))
    if seen == 0:
        sys.stderr.write("check_callgraph: --glue %s holds no .c or .h file (a path that moved would otherwise pass for ever)\n" % ", ".join(dirs))
        return None
    return called


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cc", default=os.environ.get("CC", "gcc"))
    ap.add_argument("--depth", type=int, default=17, help="largest allowed call chain, in frames")
    ap.add_argument("--stack", type=int, default=3328, help="largest allowed static stack along a chain, in bytes")
    ap.add_argument("--keep", help="keep the object and .ci files in this directory")
    ap.add_argument("--core", default=CORE, help="the core/ directory to measure (default: the one of this repository)")
    ap.add_argument("--cflag", action="append", default=[], metavar="FLAG",
                    help="an extra compiler flag, after the defaults (-m32, -Os ...); repeatable; use --cflag=-m32 for a flag with a dash")
    ap.add_argument("--link", action="append", default=[], metavar="CALLER=CALLEE",
                    help="add the edge of a call through a function pointer (resolved like an entry name)")
    ap.add_argument("--chains", action="store_true", help="also print the largest-stack chain of every --entry")
    ap.add_argument("--glue", action="append", default=[], metavar="DIR",
                    help="a directory of host glue sources (.c, .h): every core function they call must be an --entry (repeatable)")
    ap.add_argument("--entry", action="append", default=[], metavar="NAME[=BYTES]",
                    help="report one entry point; with =BYTES also fail when its static stack is above that")
    a = ap.parse_args()

    tmp = None
    outdir = a.keep
    if outdir is None:
        tmp = tempfile.TemporaryDirectory(prefix="wr_callgraph.")
        outdir = tmp.name
    else:
        os.makedirs(outdir, exist_ok=True)
    core = os.path.abspath(a.core)
    if not os.path.isfile(os.path.join(core, "sources.txt")):
        sys.stderr.write("check_callgraph: %s has no sources.txt\n" % core)
        return 2
    n = compile_all(a.cc, outdir, core, a.cflag)
    edges, size, unbounded, defined = read_graph(outdir)
    if not size:
        sys.stderr.write("check_callgraph: no call graph information found (gcc 10 or newer is needed)\n")
        return 2
    for spec in a.link:
        src_name, _, dst_name = spec.partition("=")
        nodes = set(size) | set(edges)
        src = find_entry(src_name, {k: 0 for k in nodes})
        dst = find_entry(dst_name, {k: 0 for k in nodes})
        if not dst_name or src is None or dst is None:
            sys.stderr.write("check_callgraph: --link %s: both names must be in the call graph (and a static name that exists in "
                             "more than one file needs its path from the repository root)\n" % spec)
            return 2
        edges[src].add(dst)
    depth, stack, cyc = analyse(edges, size)
    if cyc is not None:
        print("check_callgraph: RECURSION: " + " > ".join(cyc))
        return 1
    top_d = max(depth, key=lambda k: depth[k])
    top_s = max(stack, key=lambda k: stack[k])
    print("check_callgraph: %d files, %d functions%s" % (n, len(size), (" (extra flags: " + " ".join(a.cflag) + ")") if a.cflag else ""))
    names = [x.replace(REPO + os.sep, "") for x in chain(top_d, depth, edges)]
    print("  deepest chain: %d frames (limit %d): %s" % (depth[top_d], a.depth, " > ".join(names)))
    print("  largest stack: %d bytes (limit %d) from %s" % (stack[top_s], a.stack, top_s.replace(REPO + os.sep, "")))
    short = [(f.replace(REPO + os.sep, "").split(":")[-1], sz) for f, sz in stack_chain(top_s, stack, size, edges)]
    print("  largest stack chain: " + " > ".join("%s(%d)" % x for x in short))
    bad = 0
    if unbounded:
        # gcc reports "(dynamic,bounded)" for a frame whose number is an upper bound, which is what the sums use; a plain
        # "(dynamic)" (alloca, a variable-length array) has no bound at all and the core has no business with either.
        print("check_callgraph: frames of unbounded size (a variable-length array or alloca?): " + ", ".join(sorted(unbounded)))
        bad = 1
    for spec in a.entry:
        name, _, budget = spec.partition("=")
        node = find_entry(name, depth)
        if node is None:
            sys.stderr.write("check_callgraph: entry point '%s' is not in the call graph (renamed, removed, or a static name "
                             "that exists in more than one file)\n" % name)
            return 2
        if node not in defined:
            sys.stderr.write("check_callgraph: entry point '%s' is only called in the core, never defined there (a function the host "
                             "provides?): it has no frame size to measure\n" % name)
            return 2
        if budget and not budget.isdigit():
            sys.stderr.write("check_callgraph: the budget of '%s' is not a number: '%s'\n" % (name, budget))
            return 2
        line = "  entry %-28s depth %2d frames, stack %4d bytes" % (name, depth[node], stack[node])
        if budget:
            line += " (budget %s)" % budget
            if stack[node] > int(budget):
                line += " ABOVE THE BUDGET"
                bad = 1
        print(line)
        if a.chains:
            print("      " + " > ".join("%s(%d)" % (f.replace(REPO + os.sep, "").split(":")[-1], sz)
                                         for f, sz in stack_chain(node, stack, size, edges)))
    if a.glue:
        called = glue_calls(a.glue, {k for k in defined if ":" not in k})
        if called is None:
            return 2
        listed = {spec.partition("=")[0] for spec in a.entry}
        missing = sorted(called - listed)
        print("  glue: %d core functions called from %s, %d without an --entry" % (len(called), ", ".join(a.glue), len(missing)))
        if missing:
            print("check_callgraph: the glue calls core functions that have no stack budget: %s (measure each with --entry NAME "
                  "and add it to the table of callgraph_ipxe.sh)" % ", ".join(missing))
            bad = 1
    if depth[top_d] > a.depth:
        print("check_callgraph: call depth %d is above the limit %d" % (depth[top_d], a.depth))
        bad = 1
    if stack[top_s] > a.stack:
        print("check_callgraph: stack %d is above the limit %d" % (stack[top_s], a.stack))
        bad = 1
    return bad


if __name__ == "__main__":
    sys.exit(main())
