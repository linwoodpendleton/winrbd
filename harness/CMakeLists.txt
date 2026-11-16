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

message(STATUS "winrbd harness: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}, core sources: ${WR_CORE_SOURCES}")
