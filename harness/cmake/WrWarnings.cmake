# SPDX-License-Identifier: MIT
#
# Compiler policy. Core code: strict C99, every warning on, warnings are errors (WR_WERROR).
# Test code: same warnings (so tests stay honest) minus the few that fight with libc-using test helpers.

set(_wr_gnu_core
    -pedantic-errors -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wcast-qual -Wcast-align
    -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls -Wundef -Wvla -Wwrite-strings -Wformat=2
    -Wdouble-promotion -Wswitch-enum -Wframe-larger-than=1024 -fno-common)

function(wr_apply_core_flags target)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE ${_wr_gnu_core} -fno-stack-protector)
    if(WR_WERROR)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
    if(NOT WR_SANITIZE STREQUAL "")
      target_compile_options(${target} PRIVATE -fsanitize=${WR_SANITIZE} -fno-sanitize-recover=all -fno-omit-frame-pointer)
    endif()
  elseif(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  endif()
endfunction()

function(wr_apply_test_flags target)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE -pedantic-errors -Wall -Wextra -Wshadow -Wstrict-prototypes
                           -Wmissing-prototypes -Wundef -Wvla -Wwrite-strings -Wformat=2)
    if(WR_WERROR)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
    if(NOT WR_SANITIZE STREQUAL "")
      target_compile_options(${target} PRIVATE -fsanitize=${WR_SANITIZE} -fno-sanitize-recover=all -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=${WR_SANITIZE})
    endif()
  elseif(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  endif()
endfunction()
