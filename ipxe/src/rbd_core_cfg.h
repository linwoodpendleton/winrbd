#ifndef _RBD_CORE_CFG_H
#define _RBD_CORE_CFG_H
/* SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL */
/** @file
 *
 * RBD (Ceph) SAN protocol: the core's host configuration header
 *
 * The portable core includes this header first (through WR_HOST_CONFIG_HEADER, which the import step of
 * ipxe/tools/build.sh sets in the imported copy of wr_port.h; see core/include/winrbd/wr_port.h). iPXE's own
 * <stdint.h> is not the C99 one: it has the fixed-width types but no uintptr_t and none of the limit macros
 * (UINT32_MAX, INT64_MIN, SIZE_MAX ...), which the core uses. They are supplied here from the compiler's
 * predefined macros, so they cannot disagree with the types iPXE itself uses.
 *
 * The memory primitives are mapped to iPXE's own (see the end of this file); nothing else is configured.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

#include <stdint.h>
#include <string.h>

typedef __UINTPTR_TYPE__ uintptr_t;

#ifndef INT32_MAX
#define INT32_MAX __INT32_MAX__
#endif
#ifndef UINT32_MAX
#define UINT32_MAX __UINT32_MAX__
#endif
#ifndef INT64_MAX
#define INT64_MAX __INT64_MAX__
#endif
#ifndef INT64_MIN
#define INT64_MIN ( -INT64_MAX - 1 )
#endif
#ifndef UINT64_MAX
#define UINT64_MAX __UINT64_MAX__
#endif
#ifndef SIZE_MAX
#define SIZE_MAX __SIZE_MAX__
#endif

/* iPXE's x86 string functions are inline wrappers around __memcpy() and friends: there is no out-of-line memmove()
 * symbol, so the compiler's __builtin_memmove() (the core's default) would end in an undefined reference
 */
/* iPXE's x86 memcpy() with a constant length of 2, 4, 5, 6 or 8 is a load and a store through a pointer to a wider type. For
 * an operand that is not aligned (the core copies the address bytes of a wr_addr, which follow a one-byte family field,
 * for one) that is undefined C: the UBSan build of the self-tests ("ipxe/tools/build.sh test -u") traps on it, in
 * wri_eaddr_from_wr(). Constant lengths up to 8 are therefore copied a byte at a time (the compiler makes the same
 * moves of it, with no alignment assumption); every other length is iPXE's own.
 */
static inline __attribute__ (( always_inline )) void *
rbd_core_memcpy ( void *dest, const void *src, size_t len ) {
	uint8_t *out = dest;
	const uint8_t *in = src;

	if ( __builtin_constant_p ( len ) && ( len <= 8 ) ) {
		if ( len > 0 )
			out[0] = in[0];
		if ( len > 1 )
			out[1] = in[1];
		if ( len > 2 )
			out[2] = in[2];
		if ( len > 3 )
			out[3] = in[3];
		if ( len > 4 )
			out[4] = in[4];
		if ( len > 5 )
			out[5] = in[5];
		if ( len > 6 )
			out[6] = in[6];
		if ( len > 7 )
			out[7] = in[7];
		return dest;
	}
	return memcpy ( dest, src, len );
}

#define WR_MEMCPY( d, s, n ) rbd_core_memcpy ( ( d ), ( s ), ( n ) )
#define WR_MEMMOVE( d, s, n ) memmove ( ( d ), ( s ), ( n ) )
#define WR_MEMSET( d, c, n ) memset ( ( d ), ( c ), ( n ) )
#define WR_MEMCMP( a, b, n ) memcmp ( ( a ), ( b ), ( n ) )

#endif /* _RBD_CORE_CFG_H */
