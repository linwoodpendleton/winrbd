/* SPDX-License-Identifier: MIT */
/*
 * wri_le.h - byte-order helpers. All wire access in core goes through these; wire structs are
 * never overlaid on buffers (no alignment, endianness or aliasing assumptions).
 */
#ifndef WRI_LE_H
#define WRI_LE_H

#include "wr_port.h"

WR_INLINE uint16_t wri_le16_get(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}

WR_INLINE uint32_t wri_le32_get(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

WR_INLINE uint64_t wri_le64_get(const uint8_t *p)
{
	return (uint64_t)wri_le32_get(p) | ((uint64_t)wri_le32_get(p + 4) << 32);
}

WR_INLINE void wri_le16_put(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xffu);
	p[1] = (uint8_t)(v >> 8);
}

WR_INLINE void wri_le32_put(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xffu);
	p[1] = (uint8_t)((v >> 8) & 0xffu);
	p[2] = (uint8_t)((v >> 16) & 0xffu);
	p[3] = (uint8_t)(v >> 24);
}

WR_INLINE void wri_le64_put(uint8_t *p, uint64_t v)
{
	wri_le32_put(p, (uint32_t)(v & 0xffffffffu));
	wri_le32_put(p + 4, (uint32_t)(v >> 32));
}

WR_INLINE uint16_t wri_be16_get(const uint8_t *p)
{
	return (uint16_t)((uint16_t)((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

WR_INLINE uint32_t wri_be32_get(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

WR_INLINE uint64_t wri_be64_get(const uint8_t *p)
{
	return ((uint64_t)wri_be32_get(p) << 32) | (uint64_t)wri_be32_get(p + 4);
}

WR_INLINE void wri_be16_put(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)(v & 0xffu);
}

WR_INLINE void wri_be32_put(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)((v >> 16) & 0xffu);
	p[2] = (uint8_t)((v >> 8) & 0xffu);
	p[3] = (uint8_t)(v & 0xffu);
}

WR_INLINE void wri_be64_put(uint8_t *p, uint64_t v)
{
	wri_be32_put(p, (uint32_t)(v >> 32));
	wri_be32_put(p + 4, (uint32_t)(v & 0xffffffffu));
}

#endif /* WRI_LE_H */
