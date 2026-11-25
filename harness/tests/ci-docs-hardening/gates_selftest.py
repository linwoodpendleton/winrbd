#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Self-test of the gates that guard the core's fit with iPXE: a gate that cannot fail proves nothing, so each one is fed a copy of the
# core (or of the iPXE shim) with one seeded violation and must reject it, for the right reason, and must accept the same copy without it.
#
#   gate                                      seeded violation (in a COPY; the repository is never touched)
#   ----------------------------------------  ----------------------------------------------------------------------------------------------
#   callgraph_ipxe.sh (stack, i386 -Os)       six 128-byte frames added under the leaf of the largest-stack chain: the global stack limit and
#                                             the budget of wr_client_run are exceeded
#   callgraph_ipxe.sh (depth, x86_64 -Os)     twelve tiny frames under the leaf of the deepest chain: the depth limit is exceeded
#   callgraph_ipxe.sh (entry budgets)         two 300-byte frames at the top of wr_rburl_parse, wr_handoff_decode and wr_ra_read (the entry
#                                             points of the three modules added with the iPXE driver): each one is reported above its budget,
#                                             and no other entry is
#   callgraph_ipxe.sh (renamed entry)         the entry point wr_ra_read renamed: a tool error (2), not a pass
#   callgraph_ipxe.sh (glue completeness)    a glue directory that calls a core function with no budget (wr_client_pool_info): refused, and
#                                             the function named; the same directory with that name only in a comment and a string: accepted
#   check_callgraph.py (entry not defined)   an --entry that the core only calls (a function the host provides): a tool error (2), not a
#                                             0-byte pass
#   check_ipxe_headers.sh (stdint macro)      a core file that uses INT16_MAX (iPXE's <stdint.h> has no limit macros, the shim defines six)
#   check_ipxe_headers.sh (undefined symbol)  a core file that calls abort(), and one that uses __builtin_memmove() with a variable length (a
#                                             call to memmove(), which iPXE has no out-of-line symbol for on x86: the failure that the design
#                                             records): both refused at the link-level check
#   check_ipxe_headers.sh (writable global)   a core file with an initialised global variable: refused (the no-globals rule on the iPXE objects)
#   check_ipxe_headers.sh (shim)              the shim without its uintptr_t typedef, and, one at a time, without each of the six macro
#                                             definitions the core uses: every one must fail
#   check_core_std.sh (C23 keyword)           a core file with a variable called true (a keyword since C23 in gcc 13 and clang 15; an older
#                                             compiler does not make it one and that case is skipped, said aloud)
#
# Every seed is also run in its absence (the control: the unmodified copy passes), so that a failure can only be the seed. A seed whose
# patch point cannot be found in the core (a function renamed, the text changed) is a failure of this test, never a skip: the point of the
# seed is to prove the gate, and a gate whose seed silently stopped applying is a gate nobody tests.
#
# Needs gcc (the call graph is gcc's), python3, sh; the header cases need third_party/ipxe. Exit 0 ok, 1 a gate did not do its job, 77 nothing
# could be run (no gcc 10 or newer). WRT_IPXE_REQUIRE=1 turns the missing iPXE tree into a failure.
#
#   python3 -I harness/tests/ci-docs-hardening/gates_selftest.py [--cc gcc] [--keep]
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
TOOLS = os.path.join(REPO, "harness", "tools")

failures = []
skipped = []
passed = 0


def run(cmd, env=None):
    e = dict(os.environ)
    e.pop("WRT_IPXE_REQUIRE", None)
    if env:
        e.update(env)
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, env=e)
    return r.returncode, r.stdout


def check(name, ok, detail=""):
    global passed
    if ok:
        passed += 1
        print("  ok   %s" % name)
    else:
        failures.append(name)
        print("  FAIL %s" % name)
        if detail:
            print("       " + detail.strip().replace("\n", "\n       ")[:1800])


def expect_fail(name, rc, out, *needles):
    """The gate must exit with 1 and say each of the needles (regular expressions)."""
    missing = [n for n in needles if not re.search(n, out)]
    check(name, rc == 1 and not missing, "exit %d%s\n%s" % (rc, (", output lacks: " + ", ".join(missing)) if missing else "", out[-1500:]))


def copy_core(dst):
    """A copy of core/ at DST/core (the directory must be called core: the call graph's static names are matched by a path that starts
    with it, as in the --link of callgraph_ipxe.sh). Returns the path of the copy."""
    path = os.path.join(dst, "core")
    shutil.copytree(os.path.join(REPO, "core"), path, ignore=shutil.ignore_patterns("*.o", "*.ci"))
    return path


def add_source(core, rel, text):
    path = os.path.join(core, rel)
    with open(path, "w") as f:
        f.write(text)
    with open(os.path.join(core, "sources.txt"), "a") as f:
        f.write(rel + "\n")


def patch_function(core, rel, name, chain_text, call_text):
    """Put chain_text (file-scope definitions) before the definition of NAME in core/REL and call_text as the first statement of its body."""
    path = os.path.join(core, rel)
    src = open(path).read()
    # the core's style: the signature (possibly over several lines) starts at column 0, the opening brace is alone on its line
    m = re.search(r"^(?:[A-Za-z_][\w \t\*]*?[ \t\*])?" + re.escape(name) + r"\s*\([^;{]*?\)\s*\n\{[ \t]*\n", src, re.M)
    if m is None:
        raise RuntimeError("seed point not found: %s in %s (the function was renamed or reformatted: fix this self-test)" % (name, rel))
    body = m.end()
    src = src[:m.start()] + chain_text + src[m.start():body] + call_text + src[body:]
    with open(path, "w") as f:
        f.write(src)


def chain(prefix, n, nbytes, leaf_extra=""):
    """n noinline functions prefix_0 .. prefix_(n-1), each with a volatile frame of about nbytes, each calling the next after touching
    its frame and using the frame afterwards (so no tail call); returns the source text. prefix_0 is the one to call."""
    out = []
    for i in range(n):
        call = "%s_%d();" % (prefix, i + 1) if i + 1 < n else leaf_extra
        out.append("static __attribute__((noinline)) void %s_%d(void)\n{\n\tvolatile unsigned char f[%d];\n\n\tf[0] = %d;\n\t%s\n\tf[1] = f[0];\n}\n\n"
                   % (prefix, i, nbytes, i, call))
    # definitions must precede their use: emit from the last to the first
    return "".join(reversed(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cc", default=os.environ.get("CC", "gcc"))
    ap.add_argument("--keep", action="store_true", help="keep the work directory (the seeded copies of the core)")
    a = ap.parse_args()
    cc = a.cc

    r = subprocess.run([cc, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True) if shutil.which(cc) else None
    if r is None or "clang" in r.stdout.lower():
        print("gates_selftest: %s is not gcc (the call graph is gcc's); skipped" % cc)
        return 77
    probe = tempfile.NamedTemporaryFile("w", suffix=".c", delete=False)
    probe.write("int main(void){return 0;}\n")
    probe.close()
    can_m32 = run([cc, "-m32", "-c", "-nostdinc", "-o", os.devnull, probe.name])[0] == 0
    os.unlink(probe.name)
    # the call graph of the 32-bit build is read from a hosted compile: it needs the system's 32-bit headers (gcc-multilib)
    probe = tempfile.NamedTemporaryFile("w", suffix=".c", delete=False)
    probe.write("#include <stdint.h>\n#include <stddef.h>\nint main(void){return (int)sizeof(size_t) - 4;}\n")
    probe.close()
    can_m32_hosted = run([cc, "-m32", "-c", "-o", os.devnull, probe.name])[0] == 0
    os.unlink(probe.name)
    have_ipxe = os.path.isfile(os.path.join(REPO, "third_party", "ipxe", "src", "include", "compiler.h"))
    if not have_ipxe and os.environ.get("WRT_IPXE_REQUIRE") == "1":
        print("gates_selftest: no iPXE tree and WRT_IPXE_REQUIRE=1")
        return 1

    work = tempfile.mkdtemp(prefix="wr_gates_selftest.")
    cgi = os.path.join(HERE, "callgraph_ipxe.sh")
    hdr = os.path.join(TOOLS, "check_ipxe_headers.sh")
    std = os.path.join(TOOLS, "check_core_std.sh")
    try:
        # ---- the control: the copy as it is passes every gate ----------------------------------------------------------------
        print("controls (the unmodified copy of the core)")
        ctl = copy_core(os.path.join(work, "ctl"))
        for arch in ("x86_64",) + (("i386",) if can_m32_hosted else ()):
            rc, out = run(["sh", cgi, "--cc", cc, "--core", ctl, arch])
            check("callgraph_ipxe.sh %s passes on the unmodified copy" % arch, rc == 0, out[-1500:])
        if not can_m32_hosted:
            skipped.append("i386 call graph cases (this compiler cannot build a hosted 32-bit file: no gcc-multilib)")
        rc, out = run(["sh", std, "-c", cc, "-k", ctl])
        check("check_core_std.sh passes on the unmodified copy", rc == 0, out[-1500:])
        if have_ipxe:
            rc, out = run(["sh", hdr, "-c", cc, "-k", ctl, "-a", "x86_64"])
            check("check_ipxe_headers.sh passes on the unmodified copy", rc == 0, out[-1500:])
        else:
            skipped.append("iPXE header cases (no third_party/ipxe)")

        # ---- call graph seeds ------------------------------------------------------------------------------------------------
        print("call graph")
        if can_m32_hosted:
            core = copy_core(os.path.join(work, "cg_stack"))
            patch_function(core, "src/crush/wri_crush_hash.c", "wri_mix", chain("wri_seed_s", 6, 128), "\twri_seed_s_0();\n")
            rc, out = run(["sh", cgi, "--cc", cc, "--core", core, "i386"])
            expect_fail("six 128-byte frames under the largest-stack leaf are refused (i386 -Os)", rc, out,
                        r"largest stack: \d+ bytes \(limit 2880\)", r"entry wr_client_run .*ABOVE THE BUDGET", r"stack \d+ is above the limit 2880")

        core = copy_core(os.path.join(work, "cg_depth"))
        patch_function(core, "src/crypto/wri_ghash.c", "gh_bmul32", chain("wri_seed_d", 12, 8), "\twri_seed_d_0();\n")
        rc, out = run(["sh", cgi, "--cc", cc, "--core", core, "x86_64"])
        expect_fail("twelve frames under the deepest chain's leaf are refused (x86_64 -Os)", rc, out,
                    r"call depth \d+ is above the limit 19")

        core = copy_core(os.path.join(work, "cg_entries"))
        # wr_ra_read's file may hold it as an exported function with a long signature; the three are at the top of three modules
        patch_function(core, "src/rburl/wri_rburl.c", "wr_rburl_parse", chain("wri_seed_e1", 2, 300), "\twri_seed_e1_0();\n")
        patch_function(core, "src/handoff/wri_handoff_dec.c", "wr_handoff_decode", chain("wri_seed_e2", 2, 300), "\twri_seed_e2_0();\n")
        patch_function(core, "src/ra/wri_ra.c", "wr_ra_read", chain("wri_seed_e3", 2, 300), "\twri_seed_e3_0();\n")
        rc, out = run(["sh", cgi, "--cc", cc, "--core", core, "x86_64"])
        expect_fail("an entry point of each new module above its budget is refused", rc, out,
                    r"entry wr_rburl_parse .*ABOVE THE BUDGET", r"entry wr_handoff_decode .*ABOVE THE BUDGET",
                    r"entry wr_ra_read .*ABOVE THE BUDGET")
        # and the same copy's other entries still pass (the budgets are per entry: the failure is not a blanket one)
        above = sorted(re.findall(r"entry (\S+)\s.*ABOVE THE BUDGET", out))
        check("... and only those (plus wr_handoff_decode_table, which calls wr_handoff_decode)",
              above == ["wr_handoff_decode", "wr_handoff_decode_table", "wr_ra_read", "wr_rburl_parse"], "above: %s\n%s" % (above, out[-1500:]))

        core = copy_core(os.path.join(work, "cg_rename"))
        path = os.path.join(core, "src", "ra", "wri_ra.c")
        text = open(path).read()
        if not re.search(r"\bwr_ra_read\b", text):
            check("seed point for the renamed entry point exists", False, "wr_ra_read not in src/ra/wri_ra.c")
        else:
            for dirpath, _, names in os.walk(core):
                for n in names:
                    if n.endswith((".c", ".h")):
                        p = os.path.join(dirpath, n)
                        t = open(p).read()
                        if "wr_ra_read" in t:
                            open(p, "w").write(re.sub(r"\bwr_ra_read\b", "wr_ra_read_renamed", t))
            rc, out = run(["sh", cgi, "--cc", cc, "--core", core, "x86_64"])
            check("a renamed entry point is a tool error, not a pass", rc == 2 and "wr_ra_read" in out, "exit %d\n%s" % (rc, out[-800:]))

        # the table must be every core function the glue calls: a glue directory that calls one with no budget is refused. Only the code
        # counts: the same name in a comment and in a string literal does not.
        glue = os.path.join(work, "glue_bad")
        os.makedirs(glue)
        with open(os.path.join(glue, "rbd_seed.c"), "w") as f:
            f.write('/* wr_client_map_target ( not a call */\nconst char *t = "wr_client_map_target ( no";\n'
                    'int seed(void)\n{\n\treturn wr_client_pool_info ( 0, 0 );\n}\n')
        rc, out = run(["sh", cgi, "--cc", cc, "--core", ctl, "--glue", glue, "x86_64"])
        expect_fail("a glue call of a core function without a budget is refused", rc, out,
                    r"glue: \d+ core functions called from .*, 1 without an --entry", r"no stack budget: wr_client_pool_info\b")
        check("... and a name that is only in a comment or a string is not a call", "wr_client_map_target" not in out.split("no stack budget")[-1], out[-600:])
        glue = os.path.join(work, "glue_ok")
        os.makedirs(glue)
        with open(os.path.join(glue, "rbd_seed.c"), "w") as f:
            f.write('/* wr_client_pool_info ( not a call */\nconst char *t = "wr_client_pool_info ( no";\nint seed(void)\n{\n\treturn wr_client_run ( 0, 0, 0 );\n}\n')
        rc, out = run(["sh", cgi, "--cc", cc, "--core", ctl, "--glue", glue, "x86_64"])
        check("a glue directory that calls only budgeted functions passes", rc == 0 and "0 without an --entry" in out, "exit %d\n%s" % (rc, out[-800:]))
        rc, out = run(["sh", cgi, "--cc", cc, "--core", ctl, "--glue", os.path.join(work, "no_such_glue_dir"), "x86_64"])
        check("a glue directory that does not exist is a tool error", rc == 2, "exit %d\n%s" % (rc, out[-800:]))

        # an entry that the core only calls (the host provides it) has no frame to measure: a tool error, not a 0-byte pass
        core = copy_core(os.path.join(work, "cg_host_fn"))
        add_source(core, "src/util/wri_seed_host.c",
                   '/* seeded violation of the self-test of the gates */\nextern void wri_seed_host_fn(void);\nvoid wri_seed_host_call(void)\n{\n\twri_seed_host_fn();\n}\n')
        rc, out = run([sys.executable, "-I", os.path.join(HERE, "check_callgraph.py"), "--cc", cc, "--core", core,
                       "--entry", "wri_seed_host_fn=64", "--entry", "wri_seed_host_call=64"])
        check("an entry that is only called in the core is a tool error", rc == 2 and "wri_seed_host_fn" in out and "never defined" in out,
              "exit %d\n%s" % (rc, out[-800:]))

        # ---- the iPXE header gate --------------------------------------------------------------------------------------------
        print("iPXE headers")
        if have_ipxe:
            core = copy_core(os.path.join(work, "h_stdint"))
            add_source(core, "src/util/wri_seed_stdint.c",
                       '/* seeded violation of the self-test of the gates */\n#include "wr_port.h"\nint wri_seed_stdint(void)\n{\n\treturn INT16_MAX;\n}\n')
            rc, out = run(["sh", hdr, "-c", cc, "-k", core, "-a", "x86_64"])
            expect_fail("a core file using INT16_MAX is refused against iPXE's <stdint.h>", rc, out, r"wri_seed_stdint\.c", r"INT16_MAX")
            if can_m32:
                rc, out = run(["sh", hdr, "-c", cc, "-k", core, "-a", "i386"])
                expect_fail("... and for i386", rc, out, r"wri_seed_stdint\.c", r"INT16_MAX")

            # the link-level check: what iPXE does not define out of line has no target at the iPXE link
            core = copy_core(os.path.join(work, "h_undef"))
            add_source(core, "src/util/wri_seed_undef.c",
                       '/* seeded violation of the self-test of the gates */\n#include "wr_port.h"\nextern void abort(void);\nvoid wri_seed_undef(void)\n{\n\tabort();\n}\n')
            rc, out = run(["sh", hdr, "-c", cc, "-k", core, "-a", "x86_64"])
            expect_fail("a core file that needs abort() is refused at the undefined-symbol check", rc, out,
                        r"wri_seed_undef\.c needs the symbol 'abort'", r"would not link into iPXE")
            core = copy_core(os.path.join(work, "h_memmove"))
            add_source(core, "src/util/wri_seed_move.c",
                       '/* seeded violation of the self-test of the gates */\n#include "wr_port.h"\n'
                       'void wri_seed_move(void *d, const void *s, size_t n)\n{\n\t__builtin_memmove(d, s, n);\n}\n')
            rc, out = run(["sh", hdr, "-c", cc, "-k", core, "-a", "x86_64"])
            expect_fail("a compiler builtin that ends in a memmove() call (iPXE has none out of line) is refused", rc, out,
                        r"wri_seed_move\.c needs the symbol 'memmove'")

            core = copy_core(os.path.join(work, "h_global"))
            add_source(core, "src/util/wri_seed_glob.c",
                       '/* seeded violation of the self-test of the gates */\n#include "wr_port.h"\nint wri_seed_counter = 5;\nint wri_seed_next(void)\n{\n\treturn wri_seed_counter++;\n}\n')
            rc, out = run(["sh", hdr, "-c", cc, "-k", core, "-a", "x86_64"])
            expect_fail("a core file with a writable global is refused in the iPXE objects", rc, out,
                        r"wri_seed_glob\.c has writable global state: wri_seed_counter", r"holds writable global state")

            shim_src = os.path.join(REPO, "ipxe", "src", "rbd_core_cfg.h")
            text = open(shim_src).read()
            variants = [("the uintptr_t typedef", r"^typedef __UINTPTR_TYPE__ uintptr_t;\n", r"uintptr_t")]
            for macro in ("INT32_MAX", "UINT32_MAX", "INT64_MAX", "INT64_MIN", "UINT64_MAX", "SIZE_MAX"):
                variants.append(("the definition of " + macro, r"^#ifndef %s\n#define %s [^\n]*\n#endif\n" % (macro, macro), macro))
            for what, pat, needle in variants:
                shim = os.path.join(work, "shim_" + re.sub(r"\W", "_", what))
                os.makedirs(shim)
                new, n = re.subn(pat, "", text, count=1, flags=re.M)
                if n != 1:
                    check("the shim without %s: the seed point exists" % what, False, "pattern not found in ipxe/src/rbd_core_cfg.h (reformatted? fix this self-test)")
                    continue
                with open(os.path.join(shim, "rbd_core_cfg.h"), "w") as f:
                    f.write(new)
                rc, out = run(["sh", hdr, "-c", cc, "-s", shim, "-a", "x86_64"])
                expect_fail("the shim without %s is refused" % what, rc, out, needle)
        # (the iPXE-less runs were noted as skipped above)

        # ---- the language-standard gate -------------------------------------------------------------------------------------
        print("language standard")
        probe_c = os.path.join(work, "kw.c")
        with open(probe_c, "w") as f:
            f.write("int kw(void)\n{\n\tint true = 1;\n\n\treturn true;\n}\n")
        keyword = run([cc, "-std=gnu2x", "-c", "-o", os.devnull, probe_c])[0] != 0
        if keyword:
            core = copy_core(os.path.join(work, "s_true"))
            add_source(core, "src/util/wri_seed_std.c", '/* seeded violation of the self-test of the gates */\nint wri_seed_std(void)\n{\n\tint true = 1;\n\n\treturn true;\n}\n')
            rc, out = run(["sh", std, "-c", cc, "-k", core])
            expect_fail("a core file with a variable called true is refused with -std=gnu2x", rc, out, r"wri_seed_std\.c", r"-std=gnu2x")
        else:
            skipped.append("C23 keyword case (%s does not make true a keyword in -std=gnu2x; the 26.04 guest's gcc 15 does)" % cc)
    finally:
        if a.keep:
            print("kept: " + work)
        else:
            shutil.rmtree(work, ignore_errors=True)

    print("gates_selftest: %d checks passed, %d failed%s" % (passed, len(failures), ("; skipped: " + "; ".join(skipped)) if skipped else ""))
    for s in skipped:
        print("  SKIP " + s)
    if failures:
        return 1
    if passed == 0:
        return 77
    return 0


if __name__ == "__main__":
    sys.exit(main())
