/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * crush_compat.h - the one type the unchanged table header needs.
 *
 * crush_ln_table.h (copied byte for byte from Ceph, see README.md) declares its two tables as
 * "static __s64 name[]" and includes a header called crush_compat.h to get that type. This is
 * our own tiny replacement for the Ceph header of the same name: it only defines __s64, and it
 * defines it as a const type, so the tables land in read-only data. The core has no writable
 * global state (harness/tools/check_no_globals.sh), and this is how that holds without editing
 * the table file.
 *
 * Nothing else may be added here: the directory is the licence boundary (LICENSE, "The CRUSH
 * log table exception").
 */
#ifndef WRI_CRUSH_LN_COMPAT_H
#define WRI_CRUSH_LN_COMPAT_H

#include <stdint.h>

#define __s64 const int64_t

#endif /* WRI_CRUSH_LN_COMPAT_H */
