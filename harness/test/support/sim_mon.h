/* SPDX-License-Identifier: MIT */
/*
 * sim_mon.h - a fake MONITOR for tests (harness code, libc allowed, never part of the core), built on
 * the msgr2 test server sim_m2. Written from docs/spec/cephx.md 3.2 / 3.6 / 3.8 and mon-client.md 3
 * from the SERVER's point of view; it shares no code with the client machines of the core (those are
 * written in other modules of the same wave). From the core it uses only the cipher / envelope layer
 * of the cephx module (wri_cx_seal / wri_cx_open / wri_cx_challenge_proof: the primitives, not the
 * client machine), the cursors and the m2-frame header encoder.
 *
 * One sim_mon is one monitor. It accepts any number of connections (sim_mon_accept); each connection is
 * a sim_m2 server underneath, fed and drained by the test exactly as sim_m2 is:
 *
 *     c = sim_mon_accept(m);        server banner queued
 *     sim_mon_feed(c, bytes, n)     what the client wrote
 *     sim_mon_drain(c, out, cap)    what the monitor wants the client to read
 *
 * cephx (cephx.md 3.2, 3.8): AUTH_REQUEST (mode byte 10..19, entity, global_id) -> AUTH_REPLY_MORE with a
 * server challenge -> AUTH_REQUEST_MORE (CEPHX_GET_AUTH_SESSION_KEY, the proof checked with the principal
 * key of either type) -> AUTH_DONE with the AUTH ticket reply (msg_a under the principal key, usage 4), the
 * connection-secret blob (an encrypted empty string in crc mode) and `extra` with one ticket per
 * requested non-AUTH service (a zero-length blob when only AUTH was asked for). A wrong key, an unknown
 * entity or a key type the monmap does not allow is answered AUTH_BAD_METHOD -13 AFTER the challenge
 * (methods [2], modes [2, 1]). A reclaim (global_id != 0) needs the previous AUTH ticket and answers with
 * ticket_enc = 1 under the previous AUTH session key; a stale or missing one is refused.
 *
 * Monitor messages (mon-client.md 2.2 to 2.6, 3.3 to 3.5, 3.8): MMonGetMap -> MMonMap; MMonSubscribe
 * recorded and served ("monmap": MMonMap when the epoch has been reached; "osdmap": MOSDMap v4 messages
 * built from the stored epochs, with start 0, start N, older than the first stored epoch and start in the
 * future behaving as the table of 3.5.1; continuous and ONETIME flags honoured); MAuth
 * (CEPHX_GET_PRINCIPAL_SESSION_KEY) -> MAuthReply; KEEPALIVE2 is answered by sim_m2. Everything the
 * monitor sends carries priority 196 (what a real monitor sends), flags 3, and the header version and
 * compat of the real message (MMonMap 1/1, MOSDMap 4/3, MAuthReply 1/1).
 *
 * Defaults come from the committed vectors (harness/vectors/monclient): the monmap is mmonmap-e3, the
 * osdmap store holds the full map of epoch 42 (mosdmap-v4-full-e42) and the incrementals of epochs 42 and
 * 43 (mosdmap-v4-inc-e42-e43-synthetic, labelled synthetic there); newest = 42, epoch 43 is committed by
 * sim_mon_push_epoch(). With those defaults the start-0 reply is byte for byte the vector.
 *
 * Fault hooks: sim_mon_restart() (all sessions cut at once, monmap epoch bumped), sim_mon_expire_tickets()
 * (every ticket issued so far stops being accepted), sim_mon_push_epoch() / sim_mon_bump_monmap() (a new
 * epoch is committed and pushed to the subscribers), per-connection plans (silent close = -EBUSY style,
 * refusals, maps held back until sim_mon_release(), no answers at all, a cut after N client messages, any
 * sim_m2 fault such as one-byte chunks), the oversize pad of the MOSDMap front, the epochs per MOSDMap
 * message, short ticket validities.
 */
#ifndef SIM_MON_H
#define SIM_MON_H

#include "sim_m2.h"
#include "wr_key.h"

#define SIM_MON_MAX_CONNS 32u
#define SIM_MON_MAX_PLANS 16u
#define SIM_MON_MAX_EPOCHS 64u /* osdmap epochs the store can hold */
#define SIM_MON_BLOB_MAX 1024u
#define SIM_MON_ISSUED 128u    /* tickets remembered for reclaim / renewal checks: the newest 128 (a login makes 2 to 4) */
#define SIM_MON_SUBS 32u       /* subscription items kept from the last MMonSubscribe (more are decoded and dropped as malformed) */
#define SIM_MON_HELD 16u       /* map messages one connection can hold back */
#define SIM_MON_TSLOTS 6u      /* ticket configuration / record slots, indexed by sim_mon_slot() */

/* ---- configuration ---------------------------------------------------------------------------- */

/* How one kind of ticket is made (a slot per service; see sim_mon_slot). Zero = the default. */
typedef struct sim_mon_tkt_cfg {
	uint8_t key_type;      /* 0 = the type of the key that wraps it (principal for AUTH, AUTH session key otherwise) */
	uint8_t key_len;       /* != 0: use key[0..key_len) as the session key instead of a random one */
	uint8_t key[WR_KEY_MAX];
	uint32_t validity_s;   /* 0 = 259200 (72 h) for AUTH, 3600 for the others */
	uint32_t validity_ns;
	uint32_t blob_len;     /* opaque ticket blob, 0 = 151, 16..SIM_MON_BLOB_MAX */
	uint64_t secret_id;    /* 0 = a running counter */
	uint8_t zero_validity; /* 1: validity 0 s 0 ns whatever validity_s / validity_ns say (cephx.md 3.5: unusable for a client) */
} sim_mon_tkt_cfg;

/* auth behaviour of one connection */
#define SIM_MON_AUTH_NORMAL 0
#define SIM_MON_AUTH_BUSY 1       /* close without any frame at AUTH_REQUEST (the -EBUSY case, no quorum yet) */
#define SIM_MON_AUTH_BAD_METHOD 2 /* AUTH_BAD_METHOD at once, no challenge: result auth_result (0 = -95) */
#define SIM_MON_AUTH_DENY 3       /* challenge first, then AUTH_BAD_METHOD auth_result (0 = -13) whatever the key */

typedef struct sim_mon_plan {
	uint8_t auth;               /* SIM_MON_AUTH_* */
	int32_t auth_result;
	uint8_t hold_maps;          /* MMonMap / MOSDMap are queued until sim_mon_release() (a slow monitor) */
	uint8_t silent;             /* record client messages but answer none of them (a monitor that never answers) */
	uint32_t close_after_msgs;  /* != 0: cut the connection (abruptly) once this many client messages were handled */
	uint8_t has_fault;          /* 1: `fault` is applied to the sim_m2 server of the connection */
	sim_m2_fault fault;         /* start from sim_mon_fault_default() */
} sim_mon_plan;

typedef struct sim_mon_cfg {
	sim_m2_cfg m2;                  /* base of every connection (entity type MON); the defaults trim the buffers */
	char user[WR_ENTITY_MAX];       /* the one principal, "winrbd" for client.winrbd */
	wr_key key;                     /* its key: REQUIRED (there is no default secret) */
	uint32_t allowed_key_types;     /* bit n = key type n is allowed by the monmap; default types 1 and 2 */
	uint64_t seed;                  /* seeds the generator of challenges, session keys, blobs and confounders */
	uint64_t first_global_id;       /* ids handed to new sessions, counting up; default 4100 */
	sim_mon_tkt_cfg tkt[SIM_MON_TSLOTS]; /* per service, see sim_mon_slot() */
	uint32_t omit_services;         /* service bits never granted (an OSD ticket the monitor "forgets") */

	const uint8_t *monmap;          /* NULL = the vector mmonmap-e3 */
	size_t monmap_len;
	uint8_t restart_keeps_epoch;    /* 1: sim_mon_restart() does not bump the monmap epoch */
	uint8_t no_default_osdmaps;     /* 1: the store starts empty (use sim_mon_add_epoch) */
	uint32_t osd_map_message_max;   /* epochs per MOSDMap message, default 40 (capped at SIM_MON_MAX_EPOCHS) */
	uint32_t osdmap_pad;            /* zero bytes added to the last map blob of every MOSDMap: the front stays well formed
					 * but grows (an oversized front); that blob is then no longer a valid map */

	sim_mon_plan plan_default;      /* connection plan beyond the n_plans below */
	sim_mon_plan plans[SIM_MON_MAX_PLANS]; /* plans[k] is the plan of the k-th accepted connection (0 based) */
	uint32_t n_plans;
} sim_mon_cfg;

/* Defaults for everything; the caller still sets `key` (and `user` if not "winrbd"). */
void sim_mon_cfg_default(sim_mon_cfg *c);
/* A sim_m2_fault with every hook off, for sim_mon_plan.fault. */
sim_m2_fault sim_mon_fault_default(void);
/* 0..5 for a single-bit service id 0x01 .. 0x20, else SIM_MON_TSLOTS. */
unsigned sim_mon_slot(uint32_t service);

/* ---- what the monitor recorded ------------------------------------------------------------------- */

typedef struct sim_mon_issued {
	uint8_t have;
	uint32_t service;
	uint64_t global_id, secret_id;
	uint32_t gen;               /* ticket generation, see sim_mon_expire_tickets */
	wr_key key;                 /* the session key handed out */
	uint32_t validity_s, validity_ns;
	uint8_t blob[SIM_MON_BLOB_MAX];
	uint32_t blob_len;
	uint8_t reissued;           /* handed out as ticket_enc = 1 (a reclaim) */
} sim_mon_issued;

typedef struct sim_mon_sub {
	char name[16];              /* cut to 15 bytes; a NUL inside the wire name shows as '?', so it never equals a real name */
	uint64_t start;
	uint8_t flags;
} sim_mon_sub;

typedef struct sim_mon_epoch {
	uint32_t epoch;
	uint8_t *full, *inc;        /* malloc'd; NULL = not stored */
	uint32_t full_len, inc_len;
} sim_mon_epoch;

typedef struct sim_mon sim_mon;
typedef struct sim_mon_conn sim_mon_conn;

typedef struct sim_mon_held {
	uint16_t type, version, compat;
	uint8_t *front;
	uint32_t len;
} sim_mon_held;

struct sim_mon_conn {
	sim_mon *mon;
	sim_m2 *m2;                 /* the msgr2 server of this connection (fault hooks, recorded messages, errors) */
	uint32_t index;             /* accept order, 0 based */
	sim_mon_plan plan;
	uint8_t killed;             /* cut by sim_mon_restart() / close_after_msgs */

	/* cephx state */
	uint8_t stage;              /* 0 none, 1 challenge sent, 2 authenticated */
	uint8_t bad_entity;         /* the AUTH_REQUEST named somebody else (refused after the challenge) */
	uint64_t req_global_id;     /* what AUTH_REQUEST asked for (0 = new) */
	uint64_t server_challenge;
	uint64_t global_id;         /* assigned or reclaimed */
	wr_key auth_key;            /* the AUTH session key of this connection */
	uint8_t *payload;           /* backing store of the last auth payload handed to sim_m2 */

	/* subscriptions */
	struct {
		uint8_t active;
		uint64_t start;
		uint8_t flags;
	} sub_monmap, sub_osdmap;
	sim_mon_sub last_sub[SIM_MON_SUBS]; /* items of the last MMonSubscribe */
	uint32_t n_last_sub;
	char last_host[64];

	sim_mon_held held[SIM_MON_HELD];
	uint32_t n_held;

	/* counters */
	uint32_t n_msgs;            /* client messages handled */
	uint32_t n_getmap, n_subscribe, n_auth_msgs, n_other, n_malformed;
	uint32_t n_monmap_sent, n_osdmap_sent, n_authreply_sent;
	wr_status send_err;         /* first failure of a send (0 = none) */
};

struct sim_mon {
	sim_mon_cfg cfg;
	uint32_t monmap_epoch;
	uint8_t *monmap;
	size_t monmap_len;
	uint8_t fsid[16];
	sim_mon_epoch maps[SIM_MON_MAX_EPOCHS]; /* ascending epoch */
	uint32_t n_maps;
	uint32_t osd_newest;        /* committed */
	uint32_t trim_lower;        /* the trim bound reported in MOSDMap, 0 = the first stored epoch */

	sim_mon_conn *conns[SIM_MON_MAX_CONNS];
	uint32_t n_accepted;        /* ever accepted */

	uint64_t next_gid, next_secret_id;
	uint32_t gen;               /* current ticket generation */
	sim_mon_issued last[SIM_MON_TSLOTS]; /* the last ticket issued per service slot */
	sim_mon_issued ring[SIM_MON_ISSUED];
	uint32_t ring_pos;

	uint32_t n_logins, n_reclaims, n_denied, n_busy, n_renewals, n_renewals_denied;
	uint32_t n_restarts, n_getmap, n_subscribe, n_monmap_sent, n_osdmap_sent;
	uint32_t last_renew_mask;   /* service mask of the last accepted renewal */
	wr_status build_err;        /* first failure to BUILD a cephx reply (a misconfigured ticket); the connection is closed */

	/* internals */
	uint64_t rng;
	void *x;                    /* the cipher context (a wri_ctx) */
	uint8_t *scratch;           /* message build buffer, grown on demand */
	size_t scratch_cap;
};

/* ---- lifecycle ------------------------------------------------------------------------------------- */

/* NULL on a bad key / configuration, out of memory, or when the default vectors cannot be loaded (a
 * message goes to stderr). */
sim_mon *sim_mon_new(const sim_mon_cfg *cfg);
void sim_mon_free(sim_mon *m);

/* A new connection (the server banner is queued). NULL when SIM_MON_MAX_CONNS are live. Connections belong to the
 * monitor: sim_mon_free() frees the ones still open, so no handle may be used (or freed) after it. */
sim_mon_conn *sim_mon_accept(sim_mon *m);
void sim_mon_conn_free(sim_mon_conn *c);
size_t sim_mon_feed(sim_mon_conn *c, const uint8_t *p, size_t n);
size_t sim_mon_drain(sim_mon_conn *c, uint8_t *out, size_t cap);
/* 1 once the client would read EOF (sim_m2_closed). */
int sim_mon_closed(const sim_mon_conn *c);

/* ---- fault hooks and driving the monitor ---------------------------------------------------------- */

/* The monitor restarts: every live connection is cut at once (bytes still queued for the client are
 * never delivered, the client reads EOF), the monmap epoch goes up by one (unless restart_keeps_epoch).
 * Issued tickets and the global id counter survive, as they do in the monitor store. */
void sim_mon_restart(sim_mon *m);
/* Every ticket issued so far is no longer accepted (a reclaim or renewal presenting one is refused). */
void sim_mon_expire_tickets(sim_mon *m);
/* 1 if `blob` is exactly a current ticket this monitor issued for `service` (what an OSD would check). */
int sim_mon_ticket_valid(const sim_mon *m, uint32_t service, const uint8_t *blob, size_t n);
/* monmap epoch + 1 (patched into the blob), pushed to the "monmap" subscribers. */
wr_status sim_mon_bump_monmap(sim_mon *m);
/* Store the maps of one epoch; a NULL part leaves that part of an existing entry as it is. Epochs above
 * osd_newest are stored but not served until sim_mon_push_epoch() commits them. WR_E_RANGE / WR_E_BUDGET. */
wr_status sim_mon_add_epoch(sim_mon *m, uint32_t epoch, const uint8_t *full, size_t full_len, const uint8_t *inc,
			    size_t inc_len);
/* Commit the next stored epoch (osd_newest + 1) and serve the "osdmap" subscribers that were waiting for it.
 * WR_E_RANGE when nothing is stored for it. */
wr_status sim_mon_push_epoch(sim_mon *m);
/* Send up to n held messages of the connection (0 = all), in order. Returns how many were really sent (a message
 * that cannot be sent is dropped, counted in send_err, and does not count). */
uint32_t sim_mon_release(sim_mon_conn *c, uint32_t n);

/* Server-initiated MESSAGE with the monitor's header conventions (priority 196, flags 3, compat given). */
wr_status sim_mon_send_message(sim_mon_conn *c, uint16_t type, uint16_t version, uint16_t compat,
			       const uint8_t *front, uint32_t flen);

#endif /* SIM_MON_H */
