/* SPDX-License-Identifier: MIT */
/*
 * wr_config.h - budgets and policy for one client.
 *
 * Every limit that bounds memory or work is a field here, so there are no hidden constants in
 * the decoders: bytes read from the wire are compared with these before they are used.
 * wr_client_mem_required() turns a config into the exact byte counts of the two memory regions
 * the host must supply; wr_client_create() fails with WR_E_BUDGET if the regions are smaller.
 *
 * Start from a profile, then adjust fields. The numbers in the profiles are first estimates
 * (architecture doc, section 3.3); a test prints the real footprint and asserts the budgets.
 */
#ifndef WR_CONFIG_H
#define WR_CONFIG_H

#include "wr_types.h"

/* mode_policy */
#define WR_MODE_CRC_ONLY 1u /* offer connection mode crc only (the only mode implemented so far) */

typedef struct wr_config {
	uint32_t size; /* sizeof(wr_config); set by the profile functions, checked at create */
	uint32_t abi;  /* WR_ABI_VERSION; set by the profile functions */

	/* ---- connections ------------------------------------------------------------------ */
	uint16_t max_conns;      /* live connections: the monitor session + OSD sessions; >= 2 so a
				    renewal can open the new session before closing the old one */
	uint16_t max_handshakes; /* connections that may be inside the handshake at once (each holds
				    two pre-auth transcript buffers) */
	uint32_t rx_buf_bytes;   /* per connection: staging for preambles and small segments */
	uint32_t ctl_buf_bytes;  /* largest control-frame segment accepted (AUTH_DONE carries tickets) */
	uint32_t tx_buf_bytes;   /* per connection: encode buffer for control frames and message fronts; at least
				    2 * (ticket_cap + 256) + 72, so a login that carries a held ticket fits */
	uint32_t preauth_cap;    /* per direction: pre-auth transcript bytes kept (msgr2.md 3.4) */
	uint32_t ticket_cap;     /* largest service ticket blob kept */

	/* ---- monitor messages --------------------------------------------------------------- */
	uint32_t mon_msg_cap;    /* largest monitor MESSAGE front accepted; sizes the bulk region.
				    An MOSDMap can carry up to ~40 maps (mon-client.md 4). */
	uint16_t mapmsg_queue;   /* raw map messages held for the consumer (bulk slots), >= 1 */
	uint16_t reserved16;

	/* ---- timers (ms) -------------------------------------------------------------------- */
	uint32_t connect_timeout_ms;     /* TCP connect, reported by the host via the action timeout */
	uint32_t handshake_timeout_ms;   /* banner to READY; the server drops at 10 s (msgr2.md 3.7) */
	uint32_t keepalive_ms;           /* send KEEPALIVE2 on the monitor connection every so often */
	uint32_t keepalive_timeout_ms;   /* no ACK within this: monitor session is dead */
	uint32_t hunt_backoff_min_ms;    /* first wait before trying the next monitor */
	uint32_t hunt_backoff_max_ms;    /* cap of the exponential back-off */

	/* ---- policy ------------------------------------------------------------------------- */
	uint8_t mode_policy;     /* WR_MODE_* */
	uint8_t reserved8[3];

	/* Room for the later milestones (OSD client, image, secure mode) without an ABI break:
	 * a milestone names words here; the profile functions zero them. */
	uint32_t reserved[24];
} wr_config;

/* Fill *cfg with a profile. They set size and abi and zero everything else first. */
void wr_config_profile_ipxe(wr_config *cfg);    /* 4 MiB malloc heap + umalloc for bulk */
void wr_config_profile_kernel(wr_config *cfg);  /* non-paged preallocated pools */
void wr_config_profile_harness(wr_config *cfg); /* generous, for the Linux harness and tests */

#endif /* WR_CONFIG_H */
