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
	uint8_t map_verify_crc;  /* check the CRC of every full map and incremental (0 = trust the transport's CRC) */
	uint8_t reserved8[2];

	/* ---- OSD map and placement (docs/design/core-architecture.md section 15) -------------- */
	/* The engine decodes the monitor's maps itself only when map_slot_bytes is non-zero; with 0 (what the three
	 * profiles give) it keeps delivering the raw messages (wr_client_mapmsg_peek) as in milestones 1 to 3.
	 * wr_config_enable_maps() fills these fields with the budgets of a profile. wr_client_mem_required() and
	 * wr_client_create() refuse (WR_E_INVAL) a non-zero map_slot_bytes below 16 KiB, map_pools outside 1 .. 8, map_max_osd 0
	 * or above the hard cap of the map store (262144), and crush_work_max 0. */
	uint32_t map_slot_bytes; /* bytes of EACH of the two compact map slots (bulk region); 0 = maps disabled */
	uint32_t map_max_osd;    /* largest max_osd of a map we accept (the per-OSD arrays are sized by the real value) */
	uint16_t map_pools;      /* pools the client tracks, 1 .. 8; the map keeps entries only for these */
	uint16_t map_pg_cache;   /* placement cache entries (arena), 0 = no cache */
	uint32_t map_refetch_ms; /* minimum time between full-map re-requests after a gap or a failure */
	uint32_t crush_work_max; /* bucket evaluations one mapping may spend before WR_E_CRUSH_WORK */

	/* ---- OSD client and RBD images (docs/design/core-architecture.md part C, sections 20 to 29) ------------ */
	/* The OSD client is on only when osd_sessions is non-zero (what the three profiles give is 0); it needs the map module
	 * (map_slot_bytes != 0). wr_config_enable_osd() fills these fields with the budgets of a profile. The engine refuses
	 * (WR_E_INVAL) an enabled OSD client whose max_conns is below osd_sessions + 2, whose max_ops is below ctl_ops + 1,
	 * whose op_bytes_max is above the segment cap of a connection, or with a zero max_images, max_reqs, op_timeout_ms or
	 * osd_front_cap. */
	uint16_t osd_sessions;       /* simultaneous OSD sessions; 0 = OSD client and images disabled */
	uint16_t max_ops;            /* object operations in flight (the op table), control ops included */
	uint16_t ctl_ops;            /* of max_ops, kept for control ops (image open, header refresh): data ops cannot starve them */
	uint16_t max_images;         /* images open at once */
	uint16_t max_reqs;           /* image requests in flight, all images together */
	uint16_t max_snaps;          /* snapshots a writable image's snapshot context may hold (more: WR_E_RBD_SNAPC) */
	uint16_t backoff_slots;      /* MOSDBackoff entries held per OSD session (more: the PG is held whole) */
	uint16_t osd_front_cap;      /* bytes: largest front segment of an OSD message, also the encode scratch of a request */
	uint32_t op_bytes_max;       /* payload bytes of one object operation; larger requests are cut into several */
	uint32_t inflight_bytes_max; /* payload bytes of all operations in flight */
	uint32_t zombie_bytes;       /* bulk: copies of cancelled writes that are still unanswered */
	uint32_t op_timeout_ms;      /* an operation unanswered this long: its OSD session is reset and it is resent */
	uint32_t osd_connect_timeout_ms; /* TCP connect to an OSD (the action timeout of a CONNECT to an OSD) */
	uint32_t hdr_refresh_ms;     /* a writable image re-reads its header (snapshot context, size, features) this often; 0 = never */
	uint32_t img_ctl_bytes;      /* per image: output buffer of the control reads (header calls) */
	uint32_t map_stale_ms;       /* an OSD map that failed to advance this long fails new operations (R-B5); 0 = never */
	uint32_t osd_idle_ms;        /* an OSD session with nothing to do is closed after this; 0 = only when its slot is needed */
	uint8_t osd_flags;           /* WR_OSDF_* */
	uint8_t reserved_osd8[3];
	uint32_t reserved[5];
} wr_config;

/* osd_flags */
#define WR_OSDF_FULL_TRY 0x1u    /* writes carry FULL_TRY: a full pool answers ENOSPC instead of holding the write (default on) */
#define WR_OSDF_HONOR_PAUSE 0x2u /* operations wait while the map carries PAUSERD / PAUSEWR (default on) */
#define WR_OSDF_ORDERSNAP 0x4u   /* writes carry ORDERSNAP: a stale snapshot context answers EOLDSNAPC and the image refreshes (default off until confirmed on the lab) */

/* Fill *cfg with a profile. They set size and abi and zero everything else first. The OSD map module is off. */
void wr_config_profile_ipxe(wr_config *cfg);    /* 4 MiB malloc heap + umalloc for bulk */
void wr_config_profile_kernel(wr_config *cfg);  /* non-paged preallocated pools */
void wr_config_profile_harness(wr_config *cfg); /* generous, for the Linux harness and tests */

/*
 * Switch the OSD map module on with the budgets that go with a profile (architecture 15.3): the two map slots, the largest
 * max_osd, tracked pools, placement cache and the CRUSH work budget. Call it after wr_config_profile_*() and before
 * wr_client_mem_required(): the regions grow by two slots (256 KiB each for iPXE, 1 MiB kernel, 4 MiB harness).
 * Individual fields may be adjusted afterwards.
 */
typedef enum wr_map_profile { WR_MAPS_IPXE = 1, WR_MAPS_KERNEL = 2, WR_MAPS_HARNESS = 3 } wr_map_profile;
void wr_config_enable_maps(wr_config *cfg, wr_map_profile p);

/*
 * Switch the OSD client and the RBD image layer on with the budgets of a profile (architecture doc section 26): OSD sessions
 * and the connections, handshakes and buffers they need, the op table, the image and request tables, timeouts. Call it after
 * wr_config_profile_*() and wr_config_enable_maps() (the image layer needs the map): besides the OSD fields it sets max_conns
 * (osd_sessions + 2) and max_handshakes, and leaves every other field alone. Individual fields may be adjusted afterwards.
 * A bad p leaves the configuration unchanged.
 */
void wr_config_enable_osd(wr_config *cfg, wr_map_profile p);

#endif /* WR_CONFIG_H */
