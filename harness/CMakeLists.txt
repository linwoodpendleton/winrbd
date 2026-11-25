# SPDX-License-Identifier: MIT
#
# Harness build: the portable core as a static library, the unit tests (ctest), optional fuzz
# targets, the Linux host library and the lab tools.
#
#   cmake -S harness -B build/harness -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build/harness -j
#   ctest --test-dir build/harness --output-on-failure
#
# Options:
#   WR_WERROR=ON|OFF        warnings are errors (default ON; the core must stay warning clean)
#   WR_SANITIZE=<list>      e.g. address,undefined (default none); skips the libc/globals link checks
#   WR_FUZZ=ON|OFF          build libFuzzer targets (clang only); otherwise fuzz targets replay seeds
#   WR_WITH_OPENSSL=AUTO|ON|OFF   differential crypto tests against OpenSSL when libcrypto is found
#   WR_BUILD_HOST=AUTO|ON|OFF     build harness/host (Linux sockets pump) when it has sources
#
# Adding a module needs NO edit to this file: core/src/**/*.c is globbed, harness/test/test_*.c and
# harness/fuzz/fuzz_*.c are globbed, harness/host/*.c is globbed. Re-run cmake after adding files
# (CONFIGURE_DEPENDS makes make/ninja do it for you).

cmake_minimum_required(VERSION 3.16)
project(winrbd_harness LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug)
endif()

option(WR_WERROR "Treat warnings as errors" ON)
set(WR_SANITIZE "" CACHE STRING "Sanitizers, e.g. address,undefined")
option(WR_FUZZ "Build libFuzzer targets (clang)" OFF)
set(WR_WITH_OPENSSL "AUTO" CACHE STRING "Differential tests against OpenSSL: AUTO, ON, OFF")
set(WR_BUILD_HOST "AUTO" CACHE STRING "Build the Linux host library: AUTO, ON, OFF")

get_filename_component(WR_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(WR_CORE_DIR "${WR_ROOT}/core")
set(WR_VECTOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vectors")

include(cmake/WrWarnings.cmake)

enable_testing()

# ---- the core ------------------------------------------------------------------------------------

file(GLOB_RECURSE WR_CORE_SOURCES CONFIGURE_DEPENDS "${WR_CORE_DIR}/src/*.c")
# core/crush_ln/ is the one LGPL-2.1 directory of the core (the CRUSH log tables, see LICENSE): same library, same flags.
file(GLOB WR_CORE_LGPL_SOURCES CONFIGURE_DEPENDS "${WR_CORE_DIR}/crush_ln/*.c")
list(APPEND WR_CORE_SOURCES ${WR_CORE_LGPL_SOURCES})
file(GLOB_RECURSE WR_CORE_PRIVATE_HEADERS CONFIGURE_DEPENDS "${WR_CORE_DIR}/src/*.h")
file(GLOB WR_CORE_PUBLIC_HEADERS CONFIGURE_DEPENDS "${WR_CORE_DIR}/include/winrbd/*.h")

# Every directory under core/src is an include directory for core sources and for white-box tests.
set(WR_CORE_INCLUDE_DIRS "${WR_CORE_DIR}/include/winrbd")
foreach(_h ${WR_CORE_PRIVATE_HEADERS})
  get_filename_component(_d "${_h}" DIRECTORY)
  list(APPEND WR_CORE_INCLUDE_DIRS "${_d}")
endforeach()
list(REMOVE_DUPLICATES WR_CORE_INCLUDE_DIRS)

add_library(wr_core STATIC ${WR_CORE_SOURCES})
target_include_directories(wr_core PUBLIC "${WR_CORE_DIR}/include" PRIVATE ${WR_CORE_INCLUDE_DIRS})
wr_apply_core_flags(wr_core)

# Internal view for tests and tools that include core/src headers (white-box tests).
add_library(wr_core_internal INTERFACE)
target_include_directories(wr_core_internal INTERFACE ${WR_CORE_INCLUDE_DIRS})
target_link_libraries(wr_core_internal INTERFACE wr_core)

# ---- header self-containment ----------------------------------------------------------------------
# Every core header must compile on its own as the first include of a C99 translation unit.

set(_hdr_src_dir "${CMAKE_CURRENT_BINARY_DIR}/header_check")
file(MAKE_DIRECTORY "${_hdr_src_dir}")
set(_hdr_srcs "")
foreach(_h ${WR_CORE_PUBLIC_HEADERS} ${WR_CORE_PRIVATE_HEADERS})
  get_filename_component(_n "${_h}" NAME_WE)
  set(_f "${_hdr_src_dir}/hdr_${_n}.c")
  file(GENERATE OUTPUT "${_f}" CONTENT "/* generated: header self-containment check */\n#include \"${_h}\"\ntypedef int wr_hdr_check_${_n};\n")
  list(APPEND _hdr_srcs "${_f}")
endforeach()
if(_hdr_srcs)
  add_library(wr_header_check OBJECT ${_hdr_srcs})
  target_include_directories(wr_header_check PRIVATE ${WR_CORE_INCLUDE_DIRS})
  wr_apply_core_flags(wr_header_check)
endif()

# ---- compile with iPXE-like flags (gcc only) ------------------------------------------------------
# iPXE builds with -ffreestanding -Wall -W -Wformat-nonliteral -Wshift-overflow=2 -Werror
# (third_party/ipxe/src/Makefile.housekeeping). The core must be clean without our extra flags.

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_library(wr_core_ipxe_flags OBJECT ${WR_CORE_SOURCES})
  target_include_directories(wr_core_ipxe_flags PRIVATE "${WR_CORE_DIR}/include" ${WR_CORE_INCLUDE_DIRS})
  target_compile_options(wr_core_ipxe_flags PRIVATE -std=gnu99 -ffreestanding -Os -Wall -W -Wformat-nonliteral
                         -Wshift-overflow=2 -Wno-array-bounds -Werror -fno-stack-protector)
endif()

# ---- 32-bit compile (i386 iPXE, 32-bit size_t and pointers) ---------------------------------------
# Compile-only; skipped silently if the toolchain has no 32-bit headers (apt install gcc-multilib).

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  include(CheckCSourceCompiles)
  set(CMAKE_REQUIRED_FLAGS "-m32")
  check_c_source_compiles("#include <stdint.h>\n#include <stddef.h>\nint main(void){return (int)sizeof(size_t) - 4;}" WR_CAN_M32)
  unset(CMAKE_REQUIRED_FLAGS)
  if(WR_CAN_M32)
    add_library(wr_core_m32 OBJECT ${WR_CORE_SOURCES})
    target_include_directories(wr_core_m32 PRIVATE "${WR_CORE_DIR}/include" ${WR_CORE_INCLUDE_DIRS})
    target_compile_options(wr_core_m32 PRIVATE -m32 ${_wr_gnu_core} -fno-stack-protector)
    if(WR_WERROR)
      target_compile_options(wr_core_m32 PRIVATE -Werror)
    endif()
  else()
    message(STATUS "winrbd harness: no 32-bit toolchain, skipping the -m32 compile check")
  endif()
endif()

# ---- build-time checks as tests -------------------------------------------------------------------

add_test(NAME core_sources_in_sync COMMAND sh "${WR_CORE_DIR}/tools/gen_sources.sh" --check)
if(WR_SANITIZE STREQUAL "")
  add_test(NAME core_no_libc COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_no_libc.sh" $<TARGET_FILE:wr_core>)
  add_test(NAME core_no_globals COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_no_globals.sh" $<TARGET_FILE:wr_core>)
endif()
set_tests_properties(core_sources_in_sync PROPERTIES LABELS "core;checks")

# Freestanding smoke (compile and link only): every core file as ISO C99 with -ffreestanding and no system include
# path, linked with -nostdlib next to four memory functions; the link fails if the core needs any other libc symbol.
# What an iPXE or kernel build sees. Independent of the sanitizer flags (it compiles the core itself).
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_test(NAME core_freestanding COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_freestanding.sh"
           "${CMAKE_C_COMPILER}" "${WR_CORE_DIR}" "-O2")
  add_test(NAME core_freestanding_os COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_freestanding.sh"
           "${CMAKE_C_COMPILER}" "${WR_CORE_DIR}" "-Os")
  if(WR_CAN_M32)
    add_test(NAME core_freestanding_m32 COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_freestanding.sh"
             "${CMAKE_C_COMPILER}" "${WR_CORE_DIR}" "-m32 -Os")
  endif()
  set_tests_properties(core_freestanding core_freestanding_os PROPERTIES LABELS "core;checks" SKIP_RETURN_CODE 77)
  if(WR_CAN_M32)
    set_tests_properties(core_freestanding_m32 PROPERTIES LABELS "core;checks" SKIP_RETURN_CODE 77)
  endif()
endif()

# ---- test support ---------------------------------------------------------------------------------

file(GLOB WR_TEST_SUPPORT_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/test/support/*.c")
add_library(wrt_support STATIC ${WR_TEST_SUPPORT_SOURCES})
target_include_directories(wrt_support PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/test/support")
target_link_libraries(wrt_support PUBLIC wr_core_internal)
target_compile_definitions(wrt_support PUBLIC "WRT_VECTOR_DIR=\"${WR_VECTOR_DIR}\"")
wr_apply_test_flags(wrt_support)

# OpenSSL (optional): differential tests only, never a core dependency.
set(WR_HAVE_OPENSSL OFF)
if(NOT WR_WITH_OPENSSL STREQUAL "OFF")
  find_package(OpenSSL QUIET)
  if(OPENSSL_FOUND)
    set(WR_HAVE_OPENSSL ON)
  elseif(WR_WITH_OPENSSL STREQUAL "ON")
    message(FATAL_ERROR "WR_WITH_OPENSSL=ON but OpenSSL was not found")
  endif()
endif()
message(STATUS "winrbd harness: OpenSSL differential tests: ${WR_HAVE_OPENSSL}")

# ---- unit tests -----------------------------------------------------------------------------------
# harness/test/test_<module>_<what>.c  ->  executable + ctest "<module>.<what>", label <module>.
# A test linking OpenSSL names itself test_<module>_<what>_ossl.c and is built only when found.

file(GLOB WR_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/test/test_*.c")
foreach(_src ${WR_TEST_SOURCES})
  get_filename_component(_name "${_src}" NAME_WE)
  set(_needs_ssl OFF)
  if(_name MATCHES "_ossl$")
    set(_needs_ssl ON)
    if(NOT WR_HAVE_OPENSSL)
      message(STATUS "skipping ${_name} (no OpenSSL)")
      continue()
    endif()
  endif()
  add_executable(${_name} "${_src}")
  target_link_libraries(${_name} PRIVATE wr_core_internal wrt_support)
  if(_needs_ssl)
    target_link_libraries(${_name} PRIVATE OpenSSL::Crypto)
  endif()
  wr_apply_test_flags(${_name})
  string(REGEX REPLACE "^test_" "" _short "${_name}")
  string(REGEX REPLACE "^([^_]+)_" "\\1." _ctest "${_short}")
  string(REGEX REPLACE "^([^_]+)_.*$" "\\1" _label "${_short}")
  add_test(NAME ${_ctest} COMMAND ${_name})
  set_tests_properties(${_ctest} PROPERTIES LABELS "${_label}" SKIP_RETURN_CODE 77
                       ENVIRONMENT "WRT_VECTOR_DIR=${WR_VECTOR_DIR}")
endforeach()

# ---- fuzz targets ---------------------------------------------------------------------------------
# harness/fuzz/fuzz_<target>.c defines LLVMFuzzerTestOneInput. With WR_FUZZ=ON (clang) it becomes a
# libFuzzer binary. Otherwise it is linked with fuzz_replay_main.c and ctest replays the seed files
# in harness/fuzz/seeds/<target>/ (a missing directory is an empty corpus and passes).

file(GLOB WR_FUZZ_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/fuzz_*.c")
list(FILTER WR_FUZZ_SOURCES EXCLUDE REGEX "fuzz_replay_main\\.c$")
foreach(_src ${WR_FUZZ_SOURCES})
  get_filename_component(_name "${_src}" NAME_WE)
  if(WR_FUZZ AND CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_executable(${_name} "${_src}")
    target_compile_options(${_name} PRIVATE -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined)
    target_link_options(${_name} PRIVATE -fsanitize=fuzzer,address,undefined)
  else()
    add_executable(${_name} "${_src}" "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/fuzz_replay_main.c")
    add_test(NAME fuzzseed.${_name} COMMAND ${_name} "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/seeds/${_name}")
    set_tests_properties(fuzzseed.${_name} PROPERTIES LABELS "fuzz")
  endif()
  target_link_libraries(${_name} PRIVATE wr_core_internal wrt_support)
  wr_apply_test_flags(${_name})
endforeach()

# ---- Linux host and tools -------------------------------------------------------------------------

file(GLOB WR_HOST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/host/*.c")
if(WR_HOST_SOURCES AND NOT WR_BUILD_HOST STREQUAL "OFF")
  add_library(wr_linux_host STATIC ${WR_HOST_SOURCES})
  target_include_directories(wr_linux_host PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/host")
  target_link_libraries(wr_linux_host PUBLIC wr_core)
  wr_apply_test_flags(wr_linux_host)

  file(GLOB WR_TOOL_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/host/tools/*.c")
  foreach(_src ${WR_TOOL_SOURCES})
    get_filename_component(_name "${_src}" NAME_WE)
    add_executable(${_name} "${_src}")
    target_link_libraries(${_name} PRIVATE wr_linux_host)
    wr_apply_test_flags(${_name})
  endforeach()
endif()

# ---- module linux-host-loop (begin) ----------------------------------------------------------------
# test_host_loop (pthread server + the pump source included with hooks, tests wrl_loop.c over real sockets)
# and test_lab_mon (label lab, skipped without WR_LAB_*) are created by the glob above as host.loop /
# lab.mon. All they need here: threads, a timeout, and no parallel run for the timing-sensitive one.
if(TARGET test_host_loop)
  find_package(Threads REQUIRED)
  target_link_libraries(test_host_loop PRIVATE Threads::Threads)
  set_tests_properties(host.loop PROPERTIES TIMEOUT 120 RUN_SERIAL TRUE)
  # the test also runs the wr-monprobe tool against its simulated monitor (skipped when the path is not given)
  if(TARGET wr-monprobe)
    add_dependencies(test_host_loop wr-monprobe)
    set_property(TEST host.loop APPEND PROPERTY ENVIRONMENT "WR_MONPROBE=$<TARGET_FILE:wr-monprobe>")
  endif()
endif()
if(TARGET test_lab_mon)
  set_tests_properties(lab.mon PROPERTIES TIMEOUT 60)
endif()
# ---- module linux-host-loop (end) ------------------------------------------------------------------

# ---- module host-osd-loop (begin) -------------------------------------------------------------------
# test_host_loop_osd (pthread servers for a simulated monitor and up to 49 simulated OSDs, the pump source included with hooks) is created by the
# glob above as ctest "host.loop.osd" (the glob turns every underscore of the file name after the first into a dot). All it needs here: threads, a timeout, and no parallel run (timing checks, 50 server threads).
if(TARGET test_host_loop_osd)
  find_package(Threads REQUIRED)
  target_link_libraries(test_host_loop_osd PRIVATE Threads::Threads)
  set_tests_properties(host.loop.osd PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
endif()
# ---- module host-osd-loop (end) ---------------------------------------------------------------------

# ---- module live-rbd-tool (begin) -------------------------------------------------------------------
# harness/host/tools/wr-rbd.c is built by the tool glob above. test_host_tool_rbd (ctest host.tool.rbd; the glob turns every underscore into a dot, the design calls it host.tool_rbd) runs it as a child process against
# a simulated monitor and three simulated OSDs over real sockets (pthread server; needs Threads, a long timeout, no parallel run).
# test_lab_rbd (ctest lab.rbd, label lab) runs the same tool against the real lab cluster and skips without WR_LAB_*.
if(TARGET test_host_tool_rbd)
  find_package(Threads REQUIRED)
  target_link_libraries(test_host_tool_rbd PRIVATE Threads::Threads)
  set_tests_properties(host.tool.rbd PROPERTIES TIMEOUT 900 RUN_SERIAL TRUE)
  if(TARGET wr-rbd)
    add_dependencies(test_host_tool_rbd wr-rbd)
    set_property(TEST host.tool.rbd APPEND PROPERTY ENVIRONMENT "WR_RBD=$<TARGET_FILE:wr-rbd>")
  endif()
endif()
if(TARGET test_lab_rbd)
  set_tests_properties(lab.rbd PROPERTIES TIMEOUT 900)
  if(TARGET wr-rbd)
    add_dependencies(test_lab_rbd wr-rbd)
    set_property(TEST lab.rbd APPEND PROPERTY ENVIRONMENT "WR_RBD=$<TARGET_FILE:wr-rbd>")
  endif()
endif()
# ---- module live-rbd-tool (end) ---------------------------------------------------------------------

# ---- module host-sec-loop (begin) -------------------------------------------------------------------
# Secure mode on the Linux host (docs/design/core-architecture.md part D, module tool-modes). harness/host/tools/wr-rbd.c and wr-monprobe.c (--mode, --mode-osd,
# --accel, --require-mode, the secure fields of the stats line) are built by the tool glob above. Both tests are created by the test glob (it turns every underscore of
# the file name after the first into a dot): test_host_loop_sec.c is ctest "host.loop.sec" (pthread servers with secure peers for a monitor and OSDs, the pump and the AES-NI
# hook included with hooks; it also runs wr-monprobe when WR_MONPROBE names it), test_host_tool_rbd_sec.c is ctest "host.tool.rbd.sec" (wr-rbd run as a child process against the
# same kind of servers; needs WR_RBD). Both need threads, a long timeout (the secure peers use the slow independent GCM of the tests: a Debug build with the sanitizers
# takes 5 to 7 minutes on a fast machine, so the limits leave a factor of three for a slow runner) and no parallel run.
if(TARGET test_host_loop_sec)
  find_package(Threads REQUIRED)
  target_link_libraries(test_host_loop_sec PRIVATE Threads::Threads)
  set_tests_properties(host.loop.sec PROPERTIES TIMEOUT 1200 RUN_SERIAL TRUE)
  if(TARGET wr-monprobe)
    add_dependencies(test_host_loop_sec wr-monprobe)
    set_property(TEST host.loop.sec APPEND PROPERTY ENVIRONMENT "WR_MONPROBE=$<TARGET_FILE:wr-monprobe>")
  endif()
endif()
if(TARGET test_host_tool_rbd_sec)
  find_package(Threads REQUIRED)
  target_link_libraries(test_host_tool_rbd_sec PRIVATE Threads::Threads)
  set_tests_properties(host.tool.rbd.sec PROPERTIES TIMEOUT 1800 RUN_SERIAL TRUE)
  if(TARGET wr-rbd)
    add_dependencies(test_host_tool_rbd_sec wr-rbd)
    set_property(TEST host.tool.rbd.sec APPEND PROPERTY ENVIRONMENT "WR_RBD=$<TARGET_FILE:wr-rbd>")
  endif()
endif()
# ---- module host-sec-loop (end) ---------------------------------------------------------------------

# ---- module winrbd-probe (begin) --------------------------------------------------------------------
# harness/src/*.c: end-to-end lab programs built on the Linux host library (winrbd-probe). They may read
# core internals (wr_core_internal), so they are harness-only and never part of a host.
if(TARGET wr_linux_host)
  file(GLOB WR_PROBE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
  foreach(_src ${WR_PROBE_SOURCES})
    get_filename_component(_name "${_src}" NAME_WE)
    add_executable(${_name} "${_src}")
    target_link_libraries(${_name} PRIVATE wr_linux_host wr_core_internal)
    wr_apply_test_flags(${_name})
  endforeach()
endif()
# ---- module winrbd-probe (end) ----------------------------------------------------------------------

# ---- module oracle-cli (begin) ------------------------------------------------------------------------
# harness/oracle/*.c: command-line tools that print what the core's OSD map decoder and placement pipeline answer, in
# the shape of Ceph's own tools (ceph osd map, osdmaptool --test-map-pgs-dump-all, crushtool --test --show-mappings), so
# the two can be diffed. They read core internals (wr_core_internal) and need no host or network. Part B of Phase 1,
# docs/design/core-architecture.md 18.
file(GLOB WR_ORACLE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/oracle/*.c")
# oracle/*_fmt.c are helpers shared by every tool (no main): linked into each tool, never a tool of their own.
set(WR_ORACLE_SHARED ${WR_ORACLE_SOURCES})
list(FILTER WR_ORACLE_SHARED INCLUDE REGEX "_fmt\\.c$")
list(FILTER WR_ORACLE_SOURCES EXCLUDE REGEX "_fmt\\.c$")
foreach(_src ${WR_ORACLE_SOURCES})
  get_filename_component(_name "${_src}" NAME_WE)
  add_executable(${_name} "${_src}" ${WR_ORACLE_SHARED})
  target_include_directories(${_name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/oracle")
  target_link_libraries(${_name} PRIVATE wr_core_internal wrt_support)
  wr_apply_test_flags(${_name})
endforeach()
# test_oracle_cli (ctest oracle.cli) runs the built tool on the committed vectors; oracle.selftest does the same through
# tools/map_oracle_lab.sh --selftest (python3). Both need the tool built first.
if(TARGET wr-maporacle)
  if(TARGET test_oracle_cli)
    add_dependencies(test_oracle_cli wr-maporacle)
    set_property(TEST oracle.cli APPEND PROPERTY ENVIRONMENT "WR_MAPORACLE=$<TARGET_FILE:wr-maporacle>")
    set_tests_properties(oracle.cli PROPERTIES TIMEOUT 600)
  endif()
  find_program(WR_PYTHON3_ORACLE python3)
  if(WR_PYTHON3_ORACLE)
    add_test(NAME oracle.selftest COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tools/map_oracle_lab.sh" --selftest)
    set_tests_properties(oracle.selftest PROPERTIES LABELS "oracle" TIMEOUT 900
                         ENVIRONMENT "WR_MAPORACLE=$<TARGET_FILE:wr-maporacle>")
  endif()
endif()
# ---- module oracle-cli (end) --------------------------------------------------------------------------

# ---- module vectors-b (begin) -------------------------------------------------------------------------
# The map-b public vectors (harness/vectors/public/mapb): sizes, hashes, scrub, CRCs, the chain of incrementals and every
# name hash are verified by a python3 script (no Ceph needed), which also replays every tabulated PG, name, answer, offline map and
# crushtool mapping through the independent python mapper (CRUSH log tables from core/crush_ln/). The content is exercised by the
# map-vectors test.
find_program(WR_PYTHON3 python3)
if(WR_PYTHON3)
  add_test(NAME vectors_mapb_check COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/vectors/public/scripts/capture_mapb.sh" --check)
  set_tests_properties(vectors_mapb_check PROPERTIES LABELS "vectors;checks" TIMEOUT 300)
  # the checker's own error paths: 16 damaged copies of the vectors, each of which --check must reject
  add_test(NAME vectors_mapb_selftest COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/vectors/public/scripts/capture_mapb.sh" --selftest)
  set_tests_properties(vectors_mapb_selftest PROPERTIES LABELS "vectors;checks" TIMEOUT 600)
endif()
# ---- module vectors-b (end) ---------------------------------------------------------------------------

# ---- module place-live (begin) ------------------------------------------------------------------------
# The live placement vectors (harness/vectors/public/placement): made by tools/map_placement_lab.py while the whole client followed the
# lab cluster. place.live (test_place_live.c, created by the glob above) replays them through the core; this checks the files themselves
# (sizes and hashes against INDEX.json, the contiguous chain, epochs.tsv, no stray file, no key-looking text) with python3 only.
if(WR_PYTHON3)
  add_test(NAME vectors_placement_check COMMAND "${WR_PYTHON3}" -I "${CMAKE_CURRENT_SOURCE_DIR}/vectors/public/scripts/check_placement.py")
  set_tests_properties(vectors_placement_check PROPERTIES LABELS "vectors;checks" TIMEOUT 120)
endif()
if(TARGET test_place_live)
  set_tests_properties(place.live PROPERTIES TIMEOUT 600)
endif()
# ---- module place-live (end) --------------------------------------------------------------------------

# ---- module vectors-c (begin) -------------------------------------------------------------------------
# The lab captures of the OSD and RBD message layers (harness/vectors/public/osdc: header reads of ten images, object operations, writes
# with a snapshot context, PG backoffs, data objects of patterned images). osd.vec.replay and rbd.vec.replay (test_osd_vec_replay.c,
# test_rbd_vec_replay.c, created by the glob above; the design calls them osd.vec_replay and rbd.vec_replay) replay them through the real decoders of core/ and skip with a reason when the
# directory is absent; vectors_osdc_check is the independent python checker (sizes and hashes against INDEX.json, no stray file, no
# key-looking text, every message decoded again from its bytes, the refusal table, the data objects against their recipe, the backoffs,
# the coverage the module promises); vectors_osdc_selftest feeds it 23 damaged copies of the vectors, each of which it must reject (the C side adds osd.vec.sweep: the same bytes damaged
# on purpose, and every refusal rule of the request encoder).
if(WR_PYTHON3)
  add_test(NAME vectors_osdc_check COMMAND "${WR_PYTHON3}" -I "${CMAKE_CURRENT_SOURCE_DIR}/vectors/public/scripts/check_osdc.py" check)
  set_tests_properties(vectors_osdc_check PROPERTIES LABELS "vectors;checks" TIMEOUT 120 SKIP_RETURN_CODE 77)
  add_test(NAME vectors_osdc_selftest COMMAND "${WR_PYTHON3}" -I "${CMAKE_CURRENT_SOURCE_DIR}/vectors/public/scripts/check_osdc.py" selftest)
  set_tests_properties(vectors_osdc_selftest PROPERTIES LABELS "vectors;checks" TIMEOUT 600 SKIP_RETURN_CODE 77)
endif()
if(TARGET test_osd_vec_replay)
  set_tests_properties(osd.vec.replay PROPERTIES TIMEOUT 120) # CMake turns every underscore of the file name into a dot
endif()
if(TARGET test_rbd_vec_replay)
  set_tests_properties(rbd.vec.replay PROPERTIES TIMEOUT 300)
endif()
if(TARGET test_osd_vec_backoff)
  set_tests_properties(osd.vec.backoff PROPERTIES TIMEOUT 120)
endif()
if(TARGET test_osd_vec_sweep)
  set_tests_properties(osd.vec.sweep PROPERTIES TIMEOUT 300) # 77 million checks: 2 s plain, 6 s under the sanitizers on the lab VM
endif()
# ---- module vectors-c (end) ---------------------------------------------------------------------------

# ---- module vectors-d (begin) -------------------------------------------------------------------------
# The lab captures of the core's own image I/O (harness/vectors/public/imgio: three scripted sessions of wr-rbd against a real OSD, the
# requests the core sent, the OSD's replies, the stock export of each image before and after). imgio.replay (test_imgio_replay.c, created by
# the glob above) re-encodes every captured request, runs the same scripts through the whole engine against the simulated OSDs and compares
# request by request and answer by answer with the real OSD, then the content with the export; vectors_imgio_check is the independent python
# checker (check_imgio.py: everything check_osdc.py checks plus the image level: object names, snapshot context, the payload against the
# script's patterns, a model of the objects replayed over the requests against every read reply and the export); vectors_imgio_selftest feeds
# it damaged copies. All three skip with a reason when the directory is absent.
if(WR_PYTHON3)
  add_test(NAME vectors_imgio_check COMMAND "${WR_PYTHON3}" -I "${CMAKE_CURRENT_SOURCE_DIR}/vectors/public/scripts/check_imgio.py" check)
  set_tests_properties(vectors_imgio_check PROPERTIES LABELS "vectors;checks" TIMEOUT 120 SKIP_RETURN_CODE 77)
  add_test(NAME vectors_imgio_selftest COMMAND "${WR_PYTHON3}" -I "${CMAKE_CURRENT_SOURCE_DIR}/vectors/public/scripts/check_imgio.py" selftest)
  set_tests_properties(vectors_imgio_selftest PROPERTIES LABELS "vectors;checks" TIMEOUT 600 SKIP_RETURN_CODE 77)
endif()
if(TARGET test_imgio_replay)
  set_tests_properties(imgio.replay PROPERTIES TIMEOUT 300)
endif()
# ---- module vectors-d (end) ---------------------------------------------------------------------------

# ---- module ci26-vm (begin) ---------------------------------------------------------------------------
# tools/ci26_vm.sh (the Ubuntu 26.04 build machine on the shared box) has a self test that needs no VM and no network: the memory and
# core/RAM guards, the refusal to delete in a directory that is not its own, the argument checks. It only needs bash.
find_program(WR_BASH bash)
if(WR_BASH)
  add_test(NAME ci26.selftest COMMAND "${WR_BASH}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/ci26_vm.sh" selftest)
  set_tests_properties(ci26.selftest PROPERTIES LABELS "ci26;checks" TIMEOUT 120)
endif()
# ---- module ci26-vm (end) -----------------------------------------------------------------------------

# ---- module krbd-compare (begin) ---------------------------------------------------------------------
# The comparison with the kernel client (docs/design/core-architecture.md section 33): harness/host/wrl_cmp.c and wrl_cmp_edges.c (the engine and its
# edge generator) are part of the host library by the glob above and need threads (the device's blocking calls run on a worker of their own);
# harness/host/tools/wr-krbdcmp.c is built by the tool glob. Tests (created by the test glob; the glob turns every underscore after the first into
# a dot): host.cmp (every phase and direction against the simulated cluster with an in-process device), host.cmp.edges (the edge generator, no
# network), host.tool.krbdcmp (the built tool over real sockets with a regular file as the device and the test-only flags). krbdcmp.selftest runs
# harness/lab/krbd-compare.sh --selftest against stand-in rbd / ceph commands (no lab needed: an injected failing step must still unmap, remove the
# images and match the state snapshot).
if(TARGET wr_linux_host)
  find_package(Threads REQUIRED)
  target_link_libraries(wr_linux_host PUBLIC Threads::Threads)
  foreach(_t test_host_cmp test_host_cmp_edges)
    if(TARGET ${_t})
      target_link_libraries(${_t} PRIVATE wr_linux_host Threads::Threads)
    endif()
  endforeach()
  if(TARGET test_host_cmp)
    set_tests_properties(host.cmp PROPERTIES TIMEOUT 900 RUN_SERIAL TRUE)
  endif()
  if(TARGET test_host_cmp_edges)
    set_tests_properties(host.cmp.edges PROPERTIES TIMEOUT 120)
  endif()
  if(TARGET test_host_tool_krbdcmp)
    target_link_libraries(test_host_tool_krbdcmp PRIVATE Threads::Threads)
    set_tests_properties(host.tool.krbdcmp PROPERTIES TIMEOUT 1500 RUN_SERIAL TRUE)
    if(TARGET wr-krbdcmp)
      add_dependencies(test_host_tool_krbdcmp wr-krbdcmp)
      set_property(TEST host.tool.krbdcmp APPEND PROPERTY ENVIRONMENT "WR_KRBDCMP=$<TARGET_FILE:wr-krbdcmp>")
    endif()
  endif()
  find_program(WR_BASH_KRBDCMP bash)
  if(WR_BASH_KRBDCMP)
    add_test(NAME krbdcmp.selftest COMMAND "${WR_BASH_KRBDCMP}" "${CMAKE_CURRENT_SOURCE_DIR}/lab/krbd-compare.sh" --selftest)
    set_tests_properties(krbdcmp.selftest PROPERTIES LABELS "krbdcmp;checks" TIMEOUT 600 SKIP_RETURN_CODE 77)
  endif()
else()
  # no host library (WR_BUILD_HOST=OFF, or a platform without it): the two tests that link the engine cannot be built or run
  foreach(_t test_host_cmp test_host_cmp_edges)
    if(TARGET ${_t})
      set_target_properties(${_t} PROPERTIES EXCLUDE_FROM_ALL TRUE)
    endif()
  endforeach()
  set(_wr_cmp_tests "")
  if(TARGET test_host_cmp)
    list(APPEND _wr_cmp_tests host.cmp)
  endif()
  if(TARGET test_host_cmp_edges)
    list(APPEND _wr_cmp_tests host.cmp.edges)
  endif()
  if(_wr_cmp_tests)
    set_tests_properties(${_wr_cmp_tests} PROPERTIES DISABLED TRUE)
  endif()
endif()
# ---- module krbd-compare (end) -----------------------------------------------------------------------

# ---- module crypto-ct (begin) ------------------------------------------------------------------------
# Constant-time checks of the portable crypto (docs/design/core-architecture.md 35.6), no timing involved.
#   crypto.ct.valgrind  test_crypto_ct_vg --drive: runs the test under "valgrind --error-exitcode=99" with the key, IV and data marked
#                       undefined (aesct, ghash, gcm, pgcm, wri_m2s_init and, once the transmit codec exists, a sealed frame), must be
#                       clean, then runs the known-bad control (table AES and an early-exit compare through the same harness), which
#                       Memcheck must report. Skips (77) with a reason when
#                       valgrind or its header (valgrind/memcheck.h) is missing, or in a sanitizer flavour (the sanitizer runtimes do not
#                       run under Valgrind).
#                       WRT_CT_REQUIRE=1 in the environment (CI sets it) turns the missing-Valgrind skip, and the missing-tool skips of
#                       the two rodata tests below, into failures, so the check cannot vanish from a runner image unnoticed.
#   crypto.ct.vg        the same binary with no argument (made by the test glob): the checks in process, the Valgrind requests inert
#                       outside Valgrind. It proves the functional results against the reference and, in the sanitizer flavours, the
#                       memory safety of the harness around them.
#   crypto.ct.rodata    tools/check_ct_rodata.sh: wri_aesct.o, wri_ghash.o, wri_gcm.o and wri_pgcm.o have no read-only (or initialised writable) data
#                       section of 256 bytes or more (the table-driven wri_aes.o must be flagged by the same scan).
#   crypto.ct.rodata.selftest  the same script compiles a 256-byte table, a 4 KiB table and a writable 256-byte table and must flag all
#                       three, and must pass a 64-byte one: proof that the scan sees a lone S-box.
#                       Both need ar and readelf / objdump / size; else they skip.
#                       The plain flavours scan libwr_core.a itself. A sanitizer adds read-only strings and location records to every object
#                       (kilobytes of source paths), so in a sanitizer flavour the same sources (and the table-driven control) are compiled once more with the core's
#                       flags and the flavour's optimisation level but WITHOUT the sanitizer (library wr_ct_scan) and those objects are scanned.
include(CheckIncludeFile)
check_include_file("valgrind/memcheck.h" WR_HAVE_VALGRIND_H)
if(TARGET test_crypto_ct_vg)
  if(WR_HAVE_VALGRIND_H)
    target_compile_definitions(test_crypto_ct_vg PRIVATE WRT_HAVE_VALGRIND_H=1)
  endif()
  if(NOT WR_SANITIZE STREQUAL "")
    target_compile_definitions(test_crypto_ct_vg PRIVATE "WRT_CT_SANITIZE=\"${WR_SANITIZE}\"")
  endif()
  add_test(NAME crypto.ct.valgrind COMMAND test_crypto_ct_vg --drive)
  set_tests_properties(crypto.ct.valgrind PROPERTIES LABELS "crypto;ct" SKIP_RETURN_CODE 77 TIMEOUT 1800)
endif()
# The limit is the smallest section that fails: 256 bytes or more (an AES S-box is exactly 256, so "larger than 256" let a lone one pass;
# the x86-64 objects have 0 to 144). A 16-byte-vector target may need more for the compiler's own mask constants (clang on arm64 puts 17
# of them, 272 bytes, into the object); raise it there on purpose, never to hide a table. The self test compiles real tables to prove that
# the scan flags 256 bytes, 4 KiB and a writable table, and passes a small one.
set(WR_CT_RODATA_LIMIT 256 CACHE STRING "Size (bytes) of a read-only data section from which wri_aesct.o, wri_ghash.o, wri_gcm.o, wri_pgcm.o fail the scan")
find_program(WR_SH_CT sh)
if(WR_SH_CT AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  if(WR_SANITIZE STREQUAL "")
    set(_wr_ct_scan_src "$<TARGET_FILE:wr_core>")
  else()
    set(_wr_ct_dir "${WR_CORE_DIR}/src/crypto")
    add_library(wr_ct_scan OBJECT "${_wr_ct_dir}/wri_aesct.c" "${_wr_ct_dir}/wri_ghash.c" "${_wr_ct_dir}/wri_gcm.c" "${_wr_ct_dir}/wri_pgcm.c" "${_wr_ct_dir}/wri_aes.c")
    target_include_directories(wr_ct_scan PRIVATE "${WR_CORE_DIR}/include" ${WR_CORE_INCLUDE_DIRS})
    target_compile_options(wr_ct_scan PRIVATE ${_wr_gnu_core} -fno-stack-protector)
    if(WR_WERROR)
      target_compile_options(wr_ct_scan PRIVATE -Werror)
    endif()
    set(_wr_ct_scan_src "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/wr_ct_scan.dir")
  endif()
  add_test(NAME crypto.ct.rodata COMMAND "${WR_SH_CT}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_ct_rodata.sh" --limit "${WR_CT_RODATA_LIMIT}" --control wri_aes
           "${_wr_ct_scan_src}" wri_aesct wri_ghash wri_gcm wri_pgcm)
  set_tests_properties(crypto.ct.rodata PROPERTIES LABELS "crypto;ct;checks" SKIP_RETURN_CODE 77 TIMEOUT 120)
  add_test(NAME crypto.ct.rodata.selftest COMMAND "${WR_SH_CT}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_ct_rodata.sh" --limit "${WR_CT_RODATA_LIMIT}"
           --selftest "${CMAKE_C_COMPILER}")
  set_tests_properties(crypto.ct.rodata.selftest PROPERTIES LABELS "crypto;ct;checks" SKIP_RETURN_CODE 77 TIMEOUT 120)
  if(NOT WR_SANITIZE STREQUAL "")
    add_dependencies(wr_core wr_ct_scan) # built with the core, so the scan finds its objects whenever the tests were built
  endif()
endif()
# ---- module crypto-ct (end) --------------------------------------------------------------------------

# ---- module vectors-sec (begin) ----------------------------------------------------------------------
# The lab captures of the core's own secure mode (harness/vectors/public/secure: a monitor and OSD sessions of wr-rbd in secure mode per cephx key type
# against a real v20.2.5 cluster with the connection secret, session key, the plaintext and the wire bytes of every frame, and the AUTH_BAD_METHOD
# answers of daemons that allow only one mode). m2.sec.replay (test_m2_sec_replay.c, created by the glob above) runs the recorded server streams through
# the real secure receive parser in many deliveries, makes the core's secure transmit reproduce the recorded client streams byte for byte, checks the
# pre-auth signatures with the core's transcript code, damages the streams, and replays the refusals into a connection. The independent encoder
# runs at about 1 MB/s and the portable GCM of the core is slow under the sanitizers: the limit leaves a factor of three on the slowest flavour.
# vectors_secure_check is the independent python checker (check_secure_core.py: the cephx exchange replayed from the handshake bytes with the published
# throwaway key, every frame encrypted again and decrypted with a library, the structure of sec.md 2.8, the signatures, the refusals, the file list
# against INDEX.json, no stray file, no key-looking text); vectors_secure_selftest feeds it damaged copies. Both skip (77) with a reason when the
# directory or the python package `cryptography` is absent.
if(WR_PYTHON3)
  add_test(NAME vectors_secure_check COMMAND "${WR_PYTHON3}" -I "${CMAKE_CURRENT_SOURCE_DIR}/vectors/public/scripts/check_secure_core.py" check)
  set_tests_properties(vectors_secure_check PROPERTIES LABELS "vectors;checks" TIMEOUT 300 SKIP_RETURN_CODE 77)
  add_test(NAME vectors_secure_selftest COMMAND "${WR_PYTHON3}" -I "${CMAKE_CURRENT_SOURCE_DIR}/vectors/public/scripts/check_secure_core.py" selftest)
  set_tests_properties(vectors_secure_selftest PROPERTIES LABELS "vectors;checks" TIMEOUT 1800 SKIP_RETURN_CODE 77)
endif()
if(TARGET test_m2_sec_replay)
  set_tests_properties(m2.sec.replay PROPERTIES TIMEOUT 1200 RUN_SERIAL TRUE)
endif()
# lab.secure (test_lab_secure.c of module secure-live, label lab, skips without WR_LAB_*): the live matrix restarts the monitor and the OSDs one at a
# time and runs krbd comparisons, which takes much longer than lab.rbd. The test limits the script itself (WR_LAB_SECURE_DEADLINE, 5400 s by default:
# the script is then told to restore the lab and finish); this timeout is only the backstop 30 minutes later, because ctest ends a test with SIGKILL and
# a script killed that way cannot put the lab back.
if(TARGET test_lab_secure)
  set_tests_properties(lab.secure PROPERTIES TIMEOUT 7200)
endif()
# securelive.selftest: harness/lab/secure-live.sh --selftest, the whole script against stand-in cluster tools (no lab, no network): a full run, the
# refusals, the wire and wrong-key checks, and a failure injected at every step, after which the restore must still run (about 2 minutes: the failure
# injections run four at a time, each in a stand-in cluster of its own). The script never gives its output to `grep -q` through a pipe (under pipefail a
# grep that leaves early makes the writer die of SIGPIPE and a match reads as none: it failed at random on loaded CI runners), see expect_out.
find_program(WR_BASH_SECLIVE bash)
if(WR_BASH_SECLIVE)
  add_test(NAME securelive.selftest COMMAND "${WR_BASH_SECLIVE}" "${CMAKE_CURRENT_SOURCE_DIR}/lab/secure-live.sh" --selftest)
  set_tests_properties(securelive.selftest PROPERTIES LABELS "securelive;checks" TIMEOUT 900 SKIP_RETURN_CODE 77)
endif()
# ---- module vectors-sec (end) ------------------------------------------------------------------------

# ---- module exit-run (begin) -------------------------------------------------------------------------
# The Phase 1 exit run (docs/design/core-architecture.md 40): harness/lab/exit-run.sh (the long randomized comparison with krbd, five runs, the lab
# restored in an EXIT trap) and harness/tools/fault_inject.sh (the fault injector that runs beside it). Tests:
#   faultinject.selftest  fault_inject.sh --selftest: the injector against stand-in ceph / systemctl / pkill commands: the plan (a pure function of the seed,
#                         the deck's counts, the ranges), the dry run, a full run, a failure injected at every step (the restore must still put every daemon,
#                         every OSD and the upmap table back), a cluster that does not heal, a SIGTERM in the middle of a fault, a lab that is not whole at the
#                         start (refused, nothing changed), the argument checks. No lab, no network; needs bash and python3 (about 6 minutes).
#   exitrun.selftest      exit-run.sh --selftest: the whole script against stand-ins, with the cluster forced to secure and a failure injected at every step of
#                         the run: no image, no mapping, the config database as it was, every daemon back under the original mode (about 10 minutes).
#   lab.exit.selftest     the same executable with WR_LAB_EXIT_SELFTEST=1 (no cluster): the test's own verdict on synthetic reports (every way a report can fail
#                         to show a pass), the child's status, stdout and stderr, a command that cannot be run, a child killed by a signal, and the two ways the test
#                         stops the script (the deadline, a signal that reaches the test: SIGTERM passed on, the restore waited for).
#   lab.exit              test_lab_exit.c (created by the test glob, label lab, skipped without WR_LAB_*): exit-run.sh --quick on the real lab cluster, or the
#                         full run with WR_LAB_EXIT_FULL=1. The test limits the script itself (WR_LAB_EXIT_DEADLINE, 3600 s for the quick form: the script is then
#                         told to restore the lab and finish); this timeout is only the backstop, because ctest ends a test with SIGKILL and a script killed
#                         that way cannot put the lab back. A full run is hours: configure with -DWR_LAB_EXIT_TIMEOUT=<seconds> (a day or more) for it.
set(WR_LAB_EXIT_TIMEOUT "7200" CACHE STRING "ctest timeout of lab.exit in seconds (the quick form needs one hour; a full run needs a day or more)")
if(TARGET test_lab_exit)
  set_tests_properties(lab.exit PROPERTIES TIMEOUT ${WR_LAB_EXIT_TIMEOUT})
  add_test(NAME lab.exit.selftest COMMAND test_lab_exit)
  set_tests_properties(lab.exit.selftest PROPERTIES LABELS "exitrun;checks" TIMEOUT 300 SKIP_RETURN_CODE 77
                       ENVIRONMENT "WRT_VECTOR_DIR=${WR_VECTOR_DIR};WR_LAB_EXIT_SELFTEST=1")
  if(TARGET wr-krbdcmp AND TARGET wr-rbd)
    add_dependencies(test_lab_exit wr-krbdcmp wr-rbd)
    set_property(TEST lab.exit APPEND PROPERTY ENVIRONMENT "WR_KRBDCMP=$<TARGET_FILE:wr-krbdcmp>;WR_RBD=$<TARGET_FILE:wr-rbd>")
  endif()
endif()
find_program(WR_BASH_EXITRUN bash)
if(WR_BASH_EXITRUN)
  add_test(NAME faultinject.selftest COMMAND "${WR_BASH_EXITRUN}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/fault_inject.sh" --selftest)
  set_tests_properties(faultinject.selftest PROPERTIES LABELS "exitrun;checks" TIMEOUT 1800 SKIP_RETURN_CODE 77)
  add_test(NAME exitrun.selftest COMMAND "${WR_BASH_EXITRUN}" "${CMAKE_CURRENT_SOURCE_DIR}/lab/exit-run.sh" --selftest)
  set_tests_properties(exitrun.selftest PROPERTIES LABELS "exitrun;checks" TIMEOUT 3600 SKIP_RETURN_CODE 77)
  # These two judge recovery times of a few seconds on stand-in daemons (a restore that must end inside a limit, a fault that must be reached inside a
  # window, signals sent at fixed instants). Run beside other tests of `ctest -j N` on a loaded machine they failed one run in two, and each passed
  # when run alone on the same machine: the contention is the tests' own. RUN_SERIAL runs them with nothing else running; no limit or assertion changes.
  set_tests_properties(faultinject.selftest exitrun.selftest PROPERTIES RUN_SERIAL TRUE)
endif()
# ---- module exit-run (end) ---------------------------------------------------------------------------

# ---- module core-handoff (begin) ---------------------------------------------------------------------
# test_handoff.c (unit tests), test_handoff_vec.c (golden vectors, ctest "handoff.vec") and fuzz_handoff.c (seed replay
# "fuzzseed.fuzz_handoff", seeds in fuzz/seeds/fuzz_handoff) are created by the globs above. The one thing they do not know: the vector
# file is written by a script that must stay in step with it.
find_program(WR_PYTHON3_HANDOFF python3)
if(WR_PYTHON3_HANDOFF)
  add_test(NAME handoff.vectors_in_sync COMMAND "${WR_PYTHON3_HANDOFF}" -I
           "${CMAKE_CURRENT_SOURCE_DIR}/vectors/handoff/gen_handoff_vectors.py" --check)
  set_tests_properties(handoff.vectors_in_sync PROPERTIES LABELS "handoff;checks" SKIP_RETURN_CODE 77)
endif()
# ---- module core-handoff (end) -----------------------------------------------------------------------

# ---- module build-vm (begin) -------------------------------------------------------------------------
# lab/p2/builder/selftest.sh: the offline self-test of the Phase 2 builder scripts (the Ubuntu 26.04 build guest). No VM, no ssh, no network;
# ssh, rsync and the iPXE build.sh are stand-ins. It skips (and says so) the cases that need a Linux /proc, GNU tools or the iPXE checkout.
find_program(WR_BASH_BUILDER bash)
if(WR_BASH_BUILDER)
  add_test(NAME builder.selftest COMMAND "${WR_BASH_BUILDER}" "${CMAKE_CURRENT_SOURCE_DIR}/lab/p2/builder/selftest.sh")
  set_tests_properties(builder.selftest PROPERTIES LABELS "builder;checks" TIMEOUT 300)
endif()
# ---- module build-vm (end) ---------------------------------------------------------------------------

# ---- module qemu-scripts (begin) ---------------------------------------------------------------------
# lab/p2/qemu/selftest.sh: the offline self-test of the Phase 2 QEMU scripts (generator, command lines, option refusals, process-list
# parsing, whole runs against a QEMU stand-in). No KVM, no real QEMU, no cluster. The whole-run cases need Linux, flock and python3 and
# skip (and say so) elsewhere.
find_program(WR_BASH_QEMU_SCRIPTS bash)
if(WR_BASH_QEMU_SCRIPTS)
  add_test(NAME qemu_scripts.selftest COMMAND "${WR_BASH_QEMU_SCRIPTS}" "${CMAKE_CURRENT_SOURCE_DIR}/lab/p2/qemu/selftest.sh")
  set_tests_properties(qemu_scripts.selftest PROPERTIES LABELS "qemu;checks" TIMEOUT 600)
endif()
# ---- module qemu-scripts (end) -----------------------------------------------------------------------

# ---- module winpe-prep (begin) -----------------------------------------------------------------------
# lab/p2/winpe/selftest.sh: the offline self-test of the WinPE preparation scripts (check-layout.sh, import-winpe.sh) and of the tools in run-rows.md. It
# builds synthetic boot media (right names and magic numbers, no Windows file of any kind), disk images from them, and runs the cluster side against
# stand-ins: no VM, no QEMU, no network, no root. It needs sfdisk, sgdisk, mkfs.fat 4.2 (--offset), mtools, python3 and gzip, and exits 77 (skipped)
# when the machine lacks one.
find_program(WR_BASH_WINPE bash)
if(WR_BASH_WINPE)
  add_test(NAME winpe.selftest COMMAND "${WR_BASH_WINPE}" "${CMAKE_CURRENT_SOURCE_DIR}/lab/p2/winpe/selftest.sh")
  # RUN_SERIAL for the same reason as faultinject.selftest / exitrun.selftest (module exit-run): it failed once beside other tests on a loaded machine
  # and passed alone.
  set_tests_properties(winpe.selftest PROPERTIES LABELS "winpe;checks" TIMEOUT 300 SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
endif()
# ---- module winpe-prep (end) -------------------------------------------------------------------------

# ---- module linux-images (begin) ---------------------------------------------------------------------
# lab/p2/images/selftest.sh: the offline test of the Linux guest images of the Phase 2 live matrix: the guest-side table checker
# (rbft-check.c, built here with this build's compiler and flags, sanitizers included, so a Debug / Release / MinSizeRel and an
# ASan/UBSan run each build it their own way), the boot hook and the marker in a sandbox, the build scripts' options and plans,
# import.sh's validation. No VM, no root, no QEMU, no cluster. It skips (77) when bash, python3 or a C compiler is missing.
find_program(WR_BASH_IMAGES bash)
if(WR_BASH_IMAGES AND CMAKE_C_COMPILER)
  string(TOUPPER "${CMAKE_BUILD_TYPE}" _wr_img_bt)
  set(_wr_img_cflags "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${_wr_img_bt}}")
  if(NOT WR_SANITIZE STREQUAL "")
    string(APPEND _wr_img_cflags " -fsanitize=${WR_SANITIZE} -fno-sanitize-recover=undefined")
  endif()
  add_test(NAME images.selftest COMMAND "${WR_BASH_IMAGES}" "${CMAKE_CURRENT_SOURCE_DIR}/lab/p2/images/selftest.sh")
  set_tests_properties(images.selftest PROPERTIES LABELS "images;checks" TIMEOUT 900 SKIP_RETURN_CODE 77
                       ENVIRONMENT "CC=${CMAKE_C_COMPILER};CFLAGS=${_wr_img_cflags}")
endif()
# ---- module linux-images (end) -----------------------------------------------------------------------

# ---- module ipxe-ci (begin) --------------------------------------------------------------------------
# ipxe/tools/build.sh check / check -n: the static checks of the iPXE glue and the core's licence tags (no iPXE tree, no compiler: bash, awk,
# grep, find), and their negative controls (a core file without its WR_FILE_LICENCE_ placeholder, a glue file marked PERMITTED, an unwired
# test, a patch with wrong hunk counts, a workflow that calls a subcommand that does not exist, ... each seeded into a scratch copy and refused
# with its own message; a workflow that dropped a gate; the licence, verify and test-log checks judged on stand-in inputs). The iPXE builds
# themselves are the CI workflow ipxe.yml and need the pinned submodule, so they are not ctest cases.
find_program(WR_BASH_IPXE_CI bash)
if(WR_BASH_IPXE_CI)
  add_test(NAME ipxe_ci.check COMMAND "${WR_BASH_IPXE_CI}" "${CMAKE_CURRENT_SOURCE_DIR}/../ipxe/tools/build.sh" check)
  add_test(NAME ipxe_ci.check_negative COMMAND "${WR_BASH_IPXE_CI}" "${CMAKE_CURRENT_SOURCE_DIR}/../ipxe/tools/build.sh" check -n)
  # check -n copies core/ into a scratch directory once per seeded mistake (about 40): 35 s on an idle box, minutes on a loaded one
  set_tests_properties(ipxe_ci.check ipxe_ci.check_negative PROPERTIES LABELS "ipxe;checks" TIMEOUT 900)
endif()
# ---- module ipxe-ci (end) ----------------------------------------------------------------------------

# ---- module harness-gates (begin) --------------------------------------------------------------------
# The gates that keep the core buildable by iPXE (Phase 2). Each is a script that compiles the core itself (independent of the sanitizer flags
# and of the build type of this tree), so the ones that cost real time are registered once, in the plain GNU flavours, like the object gates.
#   ipxe.check              ipxe/tools/build.sh check: licence and Secure Boot lines of the glue and the self-tests, patch hunk counts, name collisions
#                           (module ipxe-ci registers the same command as ipxe_ci.check, plus its negative controls; this name is the one the gates list)
#   core_std_c              every core file with -std=gnu17 and -std=gnu2x (iPXE sets no -std: gcc 15 defaults to C23), freestanding, iPXE's warnings
#   core_ipxe_headers_*     every core file against iPXE's own reduced <stdint.h> / <string.h> (no uintptr_t, no limit macros), the shim
#                           ipxe/src/rbd_core_cfg.h, and iPXE's flags (the EFI64 ones for x86_64), i386 and x86_64, then the undefined symbols of the
#                           objects (nm): anything outside iPXE's own out-of-line string and libgcc functions is a link failure in iPXE (a call to
#                           memmove(), for one); skips (77) without third_party/ipxe, and a skip is a failure with WRT_IPXE_REQUIRE=1 (the CI job
#                           ipxe-gates sets it)
#   core_callgraph_*        check_callgraph.py with -Os (-m32 for i386, the BIOS images): the global limits and a budget per glue-facing entry point,
#                           and every core function that ipxe/src calls must have one (--glue); i386 skips (77) when the compiler has no 32-bit
#                           system headers (gcc-multilib), a failure with WRT_IPXE_REQUIRE=1
#   gates.selftest          each of the above, fed a copy of the core with one seeded violation, must reject it (and accept the copy without it)
# core_ipxe_headers_*, core_callgraph_* and gates.selftest are registered only in GNU builds without sanitizers (each build type of them runs them: a few
# seconds apiece, the self-test about a minute); ipxe.check and core_std_c are registered in every flavour (seconds).
find_program(WR_SH_GATES sh)
find_program(WR_BASH_GATES bash)
find_program(WR_PYTHON3_GATES python3)
if(WR_BASH_GATES)
  add_test(NAME ipxe.check COMMAND "${WR_BASH_GATES}" "${WR_ROOT}/ipxe/tools/build.sh" check)
  set_tests_properties(ipxe.check PROPERTIES LABELS "ipxe;checks" TIMEOUT 120)
endif()
if(WR_SH_GATES AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_test(NAME core_std_c COMMAND "${WR_SH_GATES}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_core_std.sh" -c "${CMAKE_C_COMPILER}" -k "${WR_CORE_DIR}")
  set_tests_properties(core_std_c PROPERTIES LABELS "core;checks" SKIP_RETURN_CODE 77 TIMEOUT 300)
endif()
if(WR_SH_GATES AND CMAKE_C_COMPILER_ID STREQUAL "GNU" AND WR_SANITIZE STREQUAL "")
  foreach(_a i386 x86_64)
    add_test(NAME core_ipxe_headers_${_a} COMMAND "${WR_SH_GATES}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_ipxe_headers.sh"
             -c "${CMAKE_C_COMPILER}" -k "${WR_CORE_DIR}" -a ${_a})
    set_tests_properties(core_ipxe_headers_${_a} PROPERTIES LABELS "core;checks" SKIP_RETURN_CODE 77 TIMEOUT 300)
    if(WR_PYTHON3_GATES)
      add_test(NAME core_callgraph_${_a} COMMAND "${WR_SH_GATES}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/ci-docs-hardening/callgraph_ipxe.sh"
               --cc "${CMAKE_C_COMPILER}" --core "${WR_CORE_DIR}" ${_a})
      set_tests_properties(core_callgraph_${_a} PROPERTIES LABELS "core;checks" SKIP_RETURN_CODE 77 TIMEOUT 600)
    endif()
  endforeach()
  if(WR_PYTHON3_GATES)
    add_test(NAME gates.selftest COMMAND "${WR_PYTHON3_GATES}" -I "${CMAKE_CURRENT_SOURCE_DIR}/tests/ci-docs-hardening/gates_selftest.py"
             --cc "${CMAKE_C_COMPILER}")
    set_tests_properties(gates.selftest PROPERTIES LABELS "gates;checks" SKIP_RETURN_CODE 77 TIMEOUT 900)
  endif()
endif()
# ---- module harness-gates (end) ----------------------------------------------------------------------

# ---- module qemu-bios (begin) -------------------------------------------------------------------------
# lab/p2/results/bios/bin/selftest.sh: the offline test of the scripts that ran the BIOS rows of the live matrix (the verdicts on synthetic logs with their
# negative controls, the time-stamping and pausing tool against a fake QMP socket, the dry-run command lines of the two run scripts over the stock library, and
# that every script parses). No QEMU, no KVM, no cluster, no network; needs bash and python3.
find_program(WR_BASH_BIOS bash)
find_program(WR_PYTHON3_BIOS python3)
if(WR_BASH_BIOS AND WR_PYTHON3_BIOS)
  add_test(NAME bios.selftest COMMAND "${WR_BASH_BIOS}" "${CMAKE_CURRENT_SOURCE_DIR}/lab/p2/results/bios/bin/selftest.sh")
  set_tests_properties(bios.selftest PROPERTIES LABELS "bios;checks" TIMEOUT 300)
endif()
# ---- module qemu-bios (end) ---------------------------------------------------------------------------

# ---- module qemu-uefi (begin) -------------------------------------------------------------------------
# lab/p2/results/uefi/tools/selftest.sh: the offline test of the scripts that ran the UEFI rows of the live matrix (the verdicts on synthetic logs with their negative
# controls, the Shell extractor on a made-up firmware volume, the generator of the byte-check script and the disk it checks, the table of the rows, and that every
# script parses). No QEMU, no KVM, no cluster, no network; needs bash and python3 (the byte-check disk part is skipped when sfdisk, mkfs.vfat or mtools is missing).
find_program(WR_BASH_UEFI bash)
find_program(WR_PYTHON3_UEFI python3)
if(WR_BASH_UEFI AND WR_PYTHON3_UEFI)
  add_test(NAME uefi.selftest COMMAND "${WR_BASH_UEFI}" "${CMAKE_CURRENT_SOURCE_DIR}/lab/p2/results/uefi/tools/selftest.sh")
  set_tests_properties(uefi.selftest PROPERTIES LABELS "uefi;checks" TIMEOUT 300 SKIP_RETURN_CODE 77)
endif()
# ---- module qemu-uefi (end) ---------------------------------------------------------------------------

# ---- module qemu-robust (begin) -----------------------------------------------------------------------
# lab/p2/results/robust/tools/selftest.sh: the offline test of the scripts that ran the robustness rows (milestone 7): the fault driver lab/p2/qemu/robust.sh against
# a QEMU stand-in and a lab stub (every fault and its undo, the trigger, the key scan), the verdicts of analyze.py on synthetic evidence with their negative controls,
# mkreader.py and (with GNU as and ld) the assembled INT 13h reader, labstate.sh, and that every script parses. No QEMU, no KVM, no cluster, no network; needs bash and
# python3 (the whole-run cases need Linux and flock and skip themselves otherwise).
find_program(WR_BASH_ROBUST bash)
find_program(WR_PYTHON3_ROBUST python3)
if(WR_BASH_ROBUST AND WR_PYTHON3_ROBUST)
  add_test(NAME robust.selftest COMMAND "${WR_BASH_ROBUST}" "${CMAKE_CURRENT_SOURCE_DIR}/lab/p2/results/robust/tools/selftest.sh")
  # RUN_SERIAL for the same reason as faultinject.selftest (module exit-run): its whole-run cases kill and restart stand-in daemons at fixed
  # instants and judge the order of the lab commands; beside other tests of `ctest -j 4` on a loaded machine "osd-kill" failed once (final review,
  # Ubuntu 24.04 guest, clang Release) and the test passed twice when run alone on the same guest. No limit or assertion changes.
  set_tests_properties(robust.selftest PROPERTIES LABELS "robust;checks" TIMEOUT 600 SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
endif()
# ---- module qemu-robust (end) -------------------------------------------------------------------------

# ---- module measure (begin) ---------------------------------------------------------------------------
# lab/p2/results/measure/tools/selftest.sh: the offline test of the scripts of the exit measurements (design 14.4): the analysers on synthetic consoles and captures
# (negative controls included), mkbench.py and, with GNU as and ld for i386, the assembled INT 13h bench program (and, with QEMU, one run of it in software
# emulation on a plain disk), the option refusals of mrun.sh / mimages.sh / krbd.sh / campaign.sh, and summarize.py on synthetic runs. No cluster, no lab VM, no
# network; needs bash and python3 (the QEMU part skips itself without QEMU, the assembly part without GNU as).
find_program(WR_BASH_MEASURE bash)
find_program(WR_PYTHON3_MEASURE python3)
if(WR_BASH_MEASURE AND WR_PYTHON3_MEASURE)
  add_test(NAME measure.selftest COMMAND "${WR_BASH_MEASURE}" "${CMAKE_CURRENT_SOURCE_DIR}/lab/p2/results/measure/tools/selftest.sh")
  set_tests_properties(measure.selftest PROPERTIES LABELS "measure;checks" TIMEOUT 600 SKIP_RETURN_CODE 77)
endif()
# ---- module measure (end) -----------------------------------------------------------------------------

message(STATUS "winrbd harness: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}, core sources: ${WR_CORE_SOURCES}")
