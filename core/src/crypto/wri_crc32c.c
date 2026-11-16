/* SPDX-License-Identifier: MIT */
/*
 * wri_crc32c.c - portable raw CRC-32C update (see wri_crc32c.h and docs/spec/msgr2.md 2.5).
 *
 * Table-driven, reflected, no initial or final inversion. Three build-time variants selected
 * by WRI_CRC32C_SLICE (default 4):
 *   1  byte-wise, 1 KiB of table
 *   4  slice-by-4, 4 KiB of table
 *   8  slice-by-8, 8 KiB of table
 * The tables are const data from wri_crc32c_tab.inc (core/tools/gen_crc32c_tab.py); nothing is
 * built at run time and there is no writable state, so the function is reentrant and safe at
 * any IRQL / in any thread. The input is read with byte loads only: any alignment works, any
 * host endianness gives the same result, and the input pointer is never cast.
 */
#include "wri_crc32c.h"

WR_FILE_LICENCE_MIT

#ifndef WRI_CRC32C_SLICE
#define WRI_CRC32C_SLICE 4
#endif

#if WRI_CRC32C_SLICE != 1 && WRI_CRC32C_SLICE != 4 && WRI_CRC32C_SLICE != 8
#error "WRI_CRC32C_SLICE must be 1, 4 or 8"
#endif

static const uint32_t wri_crc32c_tab[WRI_CRC32C_SLICE][256] = {
#include "wri_crc32c_tab.inc"
};

/* Little-endian 32-bit load from four bytes, independent of alignment and host byte order. */
#define WRI_CRC_LD32(q) \
	((uint32_t)(q)[0] | ((uint32_t)(q)[1] << 8) | ((uint32_t)(q)[2] << 16) | ((uint32_t)(q)[3] << 24))

uint32_t wri_crc32c(uint32_t crc, const uint8_t *p, size_t n)
{
	/* a zero-length call returns the seed and never touches p (which may then be NULL) */
	if (n == 0)
		return crc;

#if WRI_CRC32C_SLICE >= 8
	while (n >= 8) {
		uint32_t lo = crc ^ WRI_CRC_LD32(p);
		uint32_t hi = WRI_CRC_LD32(p + 4);

		crc = wri_crc32c_tab[7][lo & 0xFFu] ^ wri_crc32c_tab[6][(lo >> 8) & 0xFFu] ^
		      wri_crc32c_tab[5][(lo >> 16) & 0xFFu] ^ wri_crc32c_tab[4][lo >> 24] ^
		      wri_crc32c_tab[3][hi & 0xFFu] ^ wri_crc32c_tab[2][(hi >> 8) & 0xFFu] ^
		      wri_crc32c_tab[1][(hi >> 16) & 0xFFu] ^ wri_crc32c_tab[0][hi >> 24];
		p += 8;
		n -= 8;
	}
#endif
#if WRI_CRC32C_SLICE >= 4
	while (n >= 4) {
		uint32_t w = crc ^ WRI_CRC_LD32(p);

		crc = wri_crc32c_tab[3][w & 0xFFu] ^ wri_crc32c_tab[2][(w >> 8) & 0xFFu] ^
		      wri_crc32c_tab[1][(w >> 16) & 0xFFu] ^ wri_crc32c_tab[0][w >> 24];
		p += 4;
		n -= 4;
	}
#endif
	while (n > 0) {
		crc = (crc >> 8) ^ wri_crc32c_tab[0][(crc ^ (uint32_t)*p) & 0xFFu];
		p++;
		n--;
	}
	return crc;
}
