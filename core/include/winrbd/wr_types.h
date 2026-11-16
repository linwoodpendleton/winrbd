/* SPDX-License-Identifier: MIT */
/*
 * wr_types.h - basic types shared by the public API and the internals.
 *
 * Only fixed-width types and plain structs. No pointers into core memory are ever handed to
 * a host except where a function says so and states how long the pointer stays valid.
 */
#ifndef WR_TYPES_H
#define WR_TYPES_H

#include "wr_port.h"

/* Bump when any public struct changes layout incompatibly. Checked by wr_client_create(). */
#define WR_ABI_VERSION 1u

/* 0 = success, negative = failure. The codes are in wr_err.h. */
typedef int32_t wr_status;
#define WR_OK 0

/*
 * Connection handle. 0 = none. Low 16 bits = slot index + 1, high 16 bits = generation, so
 * a stale id from a host that raced with a slot reuse is detected and ignored.
 */
typedef uint32_t wr_conn_id;
#define WR_CONN_NONE 0u

/* Time. All deadlines and timeouts are in milliseconds of the host's monotonic clock. */
#define WR_DEADLINE_NONE UINT64_MAX

typedef struct wr_clock {
	uint64_t mono_ms; /* monotonic, never goes back, any epoch */
	uint64_t wall_ms; /* ms since the Unix epoch, 0 = host has no wall clock (see architecture 2.4) */
} wr_clock;

/* A network endpoint as the core wants it dialled. IP bytes are in network order. */
#define WR_AF_IPV4 4u
#define WR_AF_IPV6 6u

typedef struct wr_addr {
	uint8_t family; /* WR_AF_IPV4 or WR_AF_IPV6; 0 = unset */
	uint8_t ip[16]; /* IPv4 uses ip[0..3] */
	uint16_t port;  /* host order */
	uint32_t nonce; /* entity_addr_t nonce; copied unchanged from the map when known, else 0 */
} wr_addr;

/* Read-only gather element: bytes the host must send. */
typedef struct wr_iov {
	const uint8_t *base;
	size_t len;
} wr_iov;

/* A region of memory the host hands to the core. base must be 16-byte aligned. */
typedef struct wr_mem_region {
	void *base;
	size_t size;
} wr_mem_region;

/* Module ids used in log records and error info. */
enum {
	WR_MOD_NONE = 0,
	WR_MOD_UTIL = 1,
	WR_MOD_CRYPTO = 2,
	WR_MOD_M2 = 3, /* msgr2 */
	WR_MOD_AUTH = 4,
	WR_MOD_MON = 5,
	WR_MOD_CLIENT = 6,
	WR_MOD_MAP = 7,   /* osdmap, reserved */
	WR_MOD_CRUSH = 8, /* reserved */
	WR_MOD_OSD = 9,   /* reserved */
	WR_MOD_RBD = 10,  /* reserved */
	WR_MOD_HOST = 11
};

#endif /* WR_TYPES_H */
