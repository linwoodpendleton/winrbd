/* SPDX-License-Identifier: MIT */
/*
 * wr-monprobe - connect to a Ceph monitor with the winrbd core, authenticate with cephx, and report
 * what the core learned. A lab and diagnostics tool: it proves the whole stack (msgr2 banner, hello,
 * cephx for either key type, monitor subscriptions) against a real cluster.
 *
 *   wr-monprobe --mon <ip[:port]> --user <name> --keyring <file> [--timeout <ms>] [--fsid <uuid>] [-v]
 *               [--mode crc|crc-first|secure-first|secure|stock] [--mode-osd MODE] [--accel] [--require-mode secure|crc]
 *
 * It waits for WR_CS_ACTIVE, prints one line per client event, then the MonMap epoch and fsid (read
 * from the raw MMonMap the monitor sent) and the newest MOSDMap epoch received, and exits 0.
 *
 * Connection modes (msgr2 secure mode, docs/design/core-architecture.md part D): --mode is the offer made to the monitor (crc, crc-first,
 * secure-first, secure or stock; default crc, the behaviour of every earlier run); --mode-osd is accepted so that a script can give the same
 * options to this tool and to wr-rbd (the probe never dials an OSD, so it changes nothing here); --accel uses the host's AES-NI / PCLMULQDQ GCM
 * hook instead of the portable GCM of the core (exit 2 when this build or CPU has none); --require-mode secure|crc asserts the mode the session
 * ended up in: exit 3 when a connection reached READY in the other mode, none reached the required one (an empty count proves nothing) or a secure
 * connection ended on a secret, nonce or tag failure (sec_failures != 0).
 * A fsid mismatch (exit 4) keeps its code, being the more serious finding. A refused offer shows on the event line as
 * status=M2_BAD_METHOD with allowed_modes= (bit v = mode v: 1 crc, 2 secure), allowed_methods= and offered_method=.
 *
 * Output (stdout, one record per line, "@<ms since start> <kind> <key=value ...>"):
 *   event, monmap, osdmap, result, stats (conns_secure= conns_crc= sec_failures= accel= gcm=host|portable gcm_ops=; gcm=host means the hook's
 * key objects were really used) and, with --require-mode, "result require_mode ok=". A diagnostic goes to stderr. The key is read from the
 * keyring file, handed to the core and wiped; it is never printed or logged.
 *
 * Exit status: 0 active (maps printed if they arrived), 1 not active within the timeout, 2 usage or
 * setup error, 3 the client failed fatally, 4 the cluster id of a map differs from --fsid, the maps
 * disagree, or --fsid was given and no map arrived to check it against (FSID_MISMATCH / FSID_UNVERIFIED).
 */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wrl_gcm_aesni.h"
#include "wrl_host.h"

#define PROBE_DEFAULT_TIMEOUT_MS 10000
#define PROBE_MAP_GRACE_MS 3000 /* after ACTIVE, how long to wait for the first MonMap and MOSDMap */
#define PROBE_KEYRING_MAX 4096u

typedef struct probe {
	wr_client *c;
	uint64_t t0;
	int timeout_ms;
	uint64_t active_at; /* mono ms when ACTIVE was first seen, 0 = not yet */
	int have_monmap, have_osdmap, fsid_given, fsid_mismatch, fsid_unverified;
	uint32_t monmap_epoch, osdmap_epoch;
	uint8_t fsid[16], mon_fsid[16], osd_fsid[16], want_fsid[16];
	unsigned n_auth_failed;
} probe;

/* memset the optimiser cannot drop (the buffer is dead afterwards, which invites removing a plain memset). */
static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0)
		*v++ = 0;
}

/* The GCM hook of the host as the core sees it (--accel): a table whose six members count their calls and pass them on to the AES-NI hook,
 * so the stats line can say whether the hook really ran. ctx of the table is this struct; the hook itself ignores its ctx. */
typedef struct gcm_spy {
	wr_prim_ops tab;  /* what the core is given */
	wr_prim_ops hook; /* the hook's own table */
	uint64_t setkeys, starts, updates, finals, wipes;
} gcm_spy;

static wr_status spy_setkey(void *ctx, void *state, const uint8_t key[16])
{
	gcm_spy *g = (gcm_spy *)ctx;

	g->setkeys++;
	return g->hook.gcm_setkey(g->hook.ctx, state, key);
}

static wr_status spy_start(void *ctx, void *state, const uint8_t iv[12], int decrypt)
{
	gcm_spy *g = (gcm_spy *)ctx;

	g->starts++;
	return g->hook.gcm_start(g->hook.ctx, state, iv, decrypt);
}

static void spy_update(void *ctx, void *state, const uint8_t *in, uint8_t *out, size_t n)
{
	gcm_spy *g = (gcm_spy *)ctx;

	g->updates++;
	g->hook.gcm_update(g->hook.ctx, state, in, out, n);
}

static void spy_final_enc(void *ctx, void *state, uint8_t tag[16])
{
	gcm_spy *g = (gcm_spy *)ctx;

	g->finals++;
	g->hook.gcm_final_enc(g->hook.ctx, state, tag);
}

static wr_status spy_final_dec(void *ctx, void *state, const uint8_t tag[16])
{
	gcm_spy *g = (gcm_spy *)ctx;

	g->finals++;
	return g->hook.gcm_final_dec(g->hook.ctx, state, tag);
}

static void spy_wipe(void *ctx, void *state)
{
	gcm_spy *g = (gcm_spy *)ctx;

	g->wipes++;
	g->hook.gcm_wipe(g->hook.ctx, state);
}

/* 0 when the hook is available and the counting table is ready, -1 otherwise (nothing is changed then). */
static int gcm_spy_init(gcm_spy *g)
{
	if (wrl_gcm_aesni_ops(&g->hook) != 0 || g->hook.gcm_setkey == NULL || g->hook.gcm_start == NULL || g->hook.gcm_update == NULL ||
	    g->hook.gcm_final_enc == NULL || g->hook.gcm_final_dec == NULL || g->hook.gcm_wipe == NULL)
		return -1;
	memset(&g->tab, 0, sizeof(g->tab));
	g->tab.size = (uint32_t)sizeof(g->tab);
	g->tab.ctx = g;
	g->tab.gcm_state_bytes = g->hook.gcm_state_bytes;
	g->tab.gcm_setkey = spy_setkey;
	g->tab.gcm_start = spy_start;
	g->tab.gcm_update = spy_update;
	g->tab.gcm_final_enc = spy_final_enc;
	g->tab.gcm_final_dec = spy_final_dec;
	g->tab.gcm_wipe = spy_wipe;
	return 0;
}

/* One of crc, crc-first, secure-first, secure, stock (the words of wr-rbd and wr-krbdcmp); NULL = crc. 0 or -1. */
static int mode_parse(const char *s, uint8_t *out)
{
	if (s == NULL || strcmp(s, "crc") == 0)
		*out = WR_MODE_CRC_ONLY;
	else if (strcmp(s, "crc-first") == 0)
		*out = WR_MODE_CRC_FIRST;
	else if (strcmp(s, "secure-first") == 0)
		*out = WR_MODE_SECURE_FIRST;
	else if (strcmp(s, "secure") == 0)
		*out = WR_MODE_SECURE_ONLY;
	else if (strcmp(s, "stock") == 0)
		*out = WR_MODE_STOCK;
	else
		return -1;
	return 0;
}

static uint64_t probe_now(void)
{
	wr_clock c;

	wrl_clock(&c);
	return c.mono_ms;
}

static void fsid_str(const uint8_t *f, char *out /* 37 bytes */)
{
	static const char hex[] = "0123456789abcdef";
	unsigned i, o = 0;

	for (i = 0; i < 16u; i++) {
		if (i == 4u || i == 6u || i == 8u || i == 10u)
			out[o++] = '-';
		out[o++] = hex[f[i] >> 4];
		out[o++] = hex[f[i] & 15u];
	}
	out[o] = '\0';
}

static int fsid_parse(const char *s, uint8_t *out)
{
	unsigned i, n = 0;

	for (i = 0; s[i] != '\0'; i++) {
		int v;
		char ch = s[i];

		if (ch == '-')
			continue;
		if (ch >= '0' && ch <= '9')
			v = ch - '0';
		else if (ch >= 'a' && ch <= 'f')
			v = ch - 'a' + 10;
		else if (ch >= 'A' && ch <= 'F')
			v = ch - 'A' + 10;
		else
			return -1;
		if (n >= 32u)
			return -1;
		if ((n & 1u) == 0)
			out[n / 2u] = (uint8_t)(v << 4);
		else
			out[n / 2u] = (uint8_t)(out[n / 2u] | v);
		n++;
	}
	return n == 32u ? 0 : -1;
}

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/*
 * MMonMap front = u32 length + MonMap blob; the blob is an envelope (u8 struct_v, u8 compat, u32 len)
 * whose body starts with the 16-byte fsid and the u32 epoch (mon-client.md 2.4.1). Read here by hand
 * so the tool only needs the public API. Returns 0 on success.
 */
static int monmap_ids(const wr_mapmsg *m, uint8_t *fsid, uint32_t *epoch)
{
	const uint8_t *f = m->front;
	size_t blob;

	if (m->front_len < 4u)
		return -1;
	blob = rd32(f);
	if (blob > m->front_len - 4u || blob < 6u + 16u + 4u)
		return -1;
	f += 4;
	if (f[0] < 6u) /* struct_v 6 and up carry this layout */
		return -1;
	if (rd32(f + 2) > blob - 6u || rd32(f + 2) < 20u)
		return -1;
	memcpy(fsid, f + 6, 16);
	*epoch = rd32(f + 6 + 16);
	return 0;
}

static const char *ev_name(wr_ev_kind k)
{
	switch (k) {
	case WR_EV_MON_SESSION_UP:
		return "MON_SESSION_UP";
	case WR_EV_MON_SESSION_DOWN:
		return "MON_SESSION_DOWN";
	case WR_EV_AUTH_FAILED:
		return "AUTH_FAILED";
	case WR_EV_CLUSTER_UNREACHABLE:
		return "CLUSTER_UNREACHABLE";
	case WR_EV_MAPMSG:
		return "MAPMSG";
	case WR_EV_TICKETS_RENEWED:
		return "TICKETS_RENEWED";
	case WR_EV_FATAL:
		return "FATAL";
	case WR_EV_MAP:
		return "MAP";
	case WR_EV_MAP_RESYNC:
		return "MAP_RESYNC";
	case WR_EV_NONE:
	default:
		return "NONE";
	}
}

static void print_event(const probe *p, const wr_event *e)
{
	printf("@%llu event %s", (unsigned long long)(probe_now() - p->t0), ev_name(e->kind));
	if (e->kind == WR_EV_MAPMSG)
		printf(" epoch=%u", (unsigned)e->epoch);
	if (e->err.status != WR_OK)
		printf(" status=%s module=%u peer_result=%d what=\"%s\"", wr_status_name(e->err.status),
		       (unsigned)e->err.module, (int)e->err.peer_result, e->err.what != NULL ? e->err.what : "");
	if (e->err.status == WR_E_M2_BAD_METHOD) /* a0 = allowed methods, a1 = allowed connection modes (bit v = mode v), a2 = the method offered */
		printf(" allowed_modes=0x%llx allowed_methods=0x%llx offered_method=%llu", (unsigned long long)e->err.a1,
		       (unsigned long long)e->err.a0, (unsigned long long)e->err.a2);
	printf("\n");
	fflush(stdout);
}

static void take_map(probe *p, const wr_mapmsg *m)
{
	char id[37];
	uint64_t at = probe_now() - p->t0;

	if (m->kind == WR_MAPMSG_MONMAP) {
		uint8_t f[16];
		uint32_t ep = 0;

		if (monmap_ids(m, f, &ep) != 0) {
			printf("@%llu monmap malformed front_len=%zu\n", (unsigned long long)at, m->front_len);
			return;
		}
		memcpy(p->mon_fsid, f, 16);
		p->monmap_epoch = ep;
		p->have_monmap = 1;
		fsid_str(f, id);
		printf("@%llu monmap epoch=%u fsid=%s msg_version=%u front_len=%zu\n", (unsigned long long)at, (unsigned)ep, id,
		       (unsigned)m->msg_version, m->front_len);
	} else if (m->kind == WR_MAPMSG_OSDMAP) {
		if (m->front_len >= 16u) { /* an MOSDMap front starts with the cluster id */
			memcpy(p->osd_fsid, m->front, 16);
			fsid_str(p->osd_fsid, id);
		} else {
			memset(p->osd_fsid, 0, 16);
			strcpy(id, "?");
		}
		if (!p->have_osdmap || m->newest_epoch > p->osdmap_epoch)
			p->osdmap_epoch = m->newest_epoch;
		p->have_osdmap = 1;
		printf("@%llu osdmap newest_epoch=%u fsid=%s msg_version=%u front_len=%zu\n", (unsigned long long)at,
		       (unsigned)m->newest_epoch, id, (unsigned)m->msg_version, m->front_len);
	}
	fflush(stdout);
}

/* Called by the loop before every step: pull events and maps, decide whether we are done. */
static int probe_stop(void *arg)
{
	probe *p = (probe *)arg;
	wr_event e;
	wr_mapmsg m;

	while (wr_client_next_event(p->c, &e)) {
		print_event(p, &e);
		if (e.kind == WR_EV_AUTH_FAILED)
			p->n_auth_failed++;
	}
	while (wr_client_mapmsg_peek(p->c, &m)) {
		take_map(p, &m);
		wr_client_mapmsg_release(p->c);
	}
	if (wr_client_get_state(p->c) == WR_CS_ACTIVE && p->active_at == 0)
		p->active_at = probe_now();
	if (p->active_at == 0)
		return 0;
	if (p->have_monmap && p->have_osdmap)
		return 1;
	return probe_now() - p->active_at >= PROBE_MAP_GRACE_MS;
}

static void usage(void)
{
	fprintf(stderr, "usage: wr-monprobe --mon <ip[:port]> --user <name> --keyring <file> [--timeout <ms>] [--fsid <uuid>] [-v]\n"
			"                   [--mode crc|crc-first|secure-first|secure|stock] [--mode-osd MODE] [--accel] [--require-mode secure|crc]\n");
}

int main(int argc, char **argv)
{
	const char *mon = NULL, *user = NULL, *keyring = NULL, *fsid_arg = NULL, *mode_arg = NULL, *mode_osd_arg = NULL, *require_arg = NULL;
	uint8_t pol = WR_MODE_CRC_ONLY, pol_osd = 0;
	int accel = 0;
	gcm_spy spy;
	wr_stats ws;
	int timeout_ms = PROBE_DEFAULT_TIMEOUT_MS, i;
	unsigned level = WR_LOG_WARN;
	probe p;
	wr_cluster_spec spec;
	wr_config cfg;
	wr_host_ops ops;
	wr_mem_req req;
	wr_mem_region arena, bulk;
	wrl_loop *loop = NULL;
	wr_client *c = NULL;
	wr_status st;
	static char kr[PROBE_KEYRING_MAX];
	size_t krlen = 0, nmon = 0;
	int rc = 0;
	char id[37];

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];
		int has_val = i + 1 < argc;

		if (strcmp(a, "--mon") == 0 && has_val)
			mon = argv[++i];
		else if (strcmp(a, "--user") == 0 && has_val)
			user = argv[++i];
		else if (strcmp(a, "--keyring") == 0 && has_val)
			keyring = argv[++i];
		else if (strcmp(a, "--fsid") == 0 && has_val)
			fsid_arg = argv[++i];
		else if (strcmp(a, "--mode") == 0 && has_val)
			mode_arg = argv[++i];
		else if (strcmp(a, "--mode-osd") == 0 && has_val)
			mode_osd_arg = argv[++i];
		else if (strcmp(a, "--require-mode") == 0 && has_val)
			require_arg = argv[++i];
		else if (strcmp(a, "--accel") == 0)
			accel = 1;
		else if (strcmp(a, "--timeout") == 0 && has_val) {
			char *end = NULL;
			long v;

			errno = 0; /* atoi would wrap around on a huge value and turn it into a negative (= no) timeout */
			v = strtol(argv[++i], &end, 10);
			if (errno != 0 || end == argv[i] || *end != '\0' || v <= 0 || v > INT_MAX) {
				fprintf(stderr, "wr-monprobe: bad --timeout (milliseconds, 1 to %d)\n", INT_MAX);
				return 2;
			}
			timeout_ms = (int)v;
		} else if (strcmp(a, "-v") == 0)
			level = WR_LOG_DEBUG;
		else {
			usage();
			return 2;
		}
	}
	if (mon == NULL || user == NULL || keyring == NULL) {
		usage();
		return 2;
	}
	memset(&p, 0, sizeof(p));
	memset(&spec, 0, sizeof(spec));
	memset(&spy, 0, sizeof(spy));
	if (mode_parse(mode_arg, &pol) != 0 || (mode_osd_arg != NULL && mode_parse(mode_osd_arg, &pol_osd) != 0)) {
		fprintf(stderr, "wr-monprobe: --mode and --mode-osd take crc, crc-first, secure-first, secure or stock\n");
		return 2;
	}
	if (require_arg != NULL && strcmp(require_arg, "secure") != 0 && strcmp(require_arg, "crc") != 0) {
		fprintf(stderr, "wr-monprobe: --require-mode takes secure or crc\n");
		return 2;
	}
	if (accel && gcm_spy_init(&spy) != 0) {
		fprintf(stderr, "wr-monprobe: --accel: this build or CPU has no AES-NI / PCLMULQDQ GCM hook: refused (run without --accel for the portable code)\n");
		return 2;
	}
	if (strlen(user) >= sizeof(spec.user)) {
		fprintf(stderr, "wr-monprobe: user name too long\n");
		return 2;
	}
	strcpy(spec.user, user);
	if (fsid_arg != NULL) {
		if (fsid_parse(fsid_arg, p.want_fsid) != 0) {
			fprintf(stderr, "wr-monprobe: bad --fsid\n");
			return 2;
		}
		p.fsid_given = 1;
	}
	st = wr_mon_parse_hosts(mon, strlen(mon), spec.mons, WR_MAX_MONS, &nmon);
	if (st != WR_OK) {
		fprintf(stderr, "wr-monprobe: --mon: %s\n", wr_strerror(st));
		return 2;
	}
	spec.n_mons = (uint8_t)nmon;
	st = wrl_read_text_file(keyring, kr, sizeof(kr), &krlen);
	if (st == WR_OK)
		st = wr_key_parse_keyring(&spec.key, kr, krlen);
	wipe(kr, sizeof(kr));
	if (st != WR_OK) {
		fprintf(stderr, "wr-monprobe: keyring %s: %s\n", keyring, wr_strerror(st));
		return 2;
	}
	/* fsid_known stays 0 on purpose: the probe reports the fsid the monitor sends and compares it itself. */

	wr_config_profile_harness(&cfg);
	if (mode_arg != NULL || mode_osd_arg != NULL) { /* without either option the configuration is what it always was: crc only, no secure memory */
		wr_config_enable_secure(&cfg, WR_MAPS_HARNESS, pol);
		if (pol_osd != 0u)
			cfg.mode_policy_osd = pol_osd;
	}
	cfg.mon_msg_cap = 4u * 1024u * 1024u;
	wrl_host_ops_init(&ops, &level);
	if (accel)
		ops.prim = &spy.tab; /* outlives the client */
	st = wr_client_mem_required(&cfg, &req);
	if (st == WR_OK)
		st = wrl_mem_alloc(&arena, req.arena);
	if (st == WR_OK) {
		st = wrl_mem_alloc(&bulk, req.bulk);
		if (st != WR_OK)
			wrl_mem_free(&arena);
	}
	if (st == WR_OK) {
		st = wr_client_create(&cfg, &ops, &spec, arena, bulk, &c);
		wr_key_wipe(&spec.key);
		if (st != WR_OK) {
			wrl_mem_free(&arena);
			wrl_mem_free(&bulk);
		}
	}
	if (st != WR_OK) {
		wr_key_wipe(&spec.key);
		fprintf(stderr, "wr-monprobe: cannot create the client: %s (%s)\n", wr_strerror(st), wr_status_name(st));
		return 2;
	}
	st = wrl_loop_create(c, &loop);
	if (st != WR_OK) {
		fprintf(stderr, "wr-monprobe: cannot create the loop: %s\n", wr_strerror(st));
		wr_client_destroy(c);
		wrl_mem_free(&arena);
		wrl_mem_free(&bulk);
		return 2;
	}

	p.c = c;
	p.timeout_ms = timeout_ms;
	p.t0 = probe_now();
	st = wrl_loop_run(loop, probe_stop, &p, timeout_ms);
	(void)probe_stop(&p); /* pick up what arrived in the last step */

	if (st == WR_E_TIMEOUT && p.active_at != 0)
		st = WR_OK; /* ACTIVE was reached; only the maps are late */
	if (st == WR_OK && p.active_at != 0) {
		if (p.have_monmap && p.have_osdmap && memcmp(p.mon_fsid, p.osd_fsid, 16) != 0)
			p.fsid_mismatch = 1;
		if (p.fsid_given && p.have_monmap && memcmp(p.want_fsid, p.mon_fsid, 16) != 0)
			p.fsid_mismatch = 1;
		if (p.fsid_given && p.have_osdmap && memcmp(p.want_fsid, p.osd_fsid, 16) != 0)
			p.fsid_mismatch = 1; /* a monitor that sent only an MOSDMap is checked against that one */
		if (p.fsid_given && !p.have_monmap && !p.have_osdmap)
			p.fsid_unverified = 1; /* nothing to compare: do not report success */
		if (p.have_monmap)
			fsid_str(p.mon_fsid, id);
		else
			strcpy(id, "none");
		printf("@%llu result active=1 monmap_epoch=%u fsid=%s osdmap_newest_epoch=%u maps=%d%d%s%s\n",
		       (unsigned long long)(probe_now() - p.t0), (unsigned)p.monmap_epoch, id, (unsigned)p.osdmap_epoch,
		       p.have_monmap, p.have_osdmap, p.fsid_mismatch ? " FSID_MISMATCH" : "",
		       p.fsid_unverified ? " FSID_UNVERIFIED" : "");
		rc = (p.fsid_mismatch || p.fsid_unverified) ? 4 : 0;
	} else if (st == WR_E_TIMEOUT) {
		const wr_errinfo *e = wr_client_last_error(c);

		printf("@%llu result active=0 timeout last_error=%s\n", (unsigned long long)(probe_now() - p.t0),
		       wr_status_name(e->status));
		rc = 1;
	} else {
		printf("@%llu result active=0 fatal=%s (%s)\n", (unsigned long long)(probe_now() - p.t0),
		       wr_status_name(st), wr_strerror(st));
		rc = 3;
	}
	memset(&ws, 0, sizeof(ws));
	wr_client_get_stats(c, &ws);
	printf("@%llu stats conns_secure=%u conns_crc=%u sec_failures=%u accel=%d gcm=%s gcm_ops=%llu\n", (unsigned long long)(probe_now() - p.t0),
	       ws.conns_secure, ws.conns_crc, ws.sec_failures, accel, accel && spy.setkeys != 0u ? "host" : "portable", (unsigned long long)spy.updates);
	if (require_arg != NULL) {
		int want_secure = strcmp(require_arg, "secure") == 0;
		/* "every connection was in the mode" needs one that was: an empty count proves nothing */
		/* a secure connection that ended on a secret, nonce or tag failure is not a clean secure run even if the client redialled and carried on */
		int ok = (want_secure ? ws.conns_crc == 0u && ws.conns_secure != 0u : ws.conns_secure == 0u && ws.conns_crc != 0u) && ws.sec_failures == 0u;

		printf("@%llu result require_mode ok=%d wanted=%s conns_secure=%u conns_crc=%u sec_failures=%u\n", (unsigned long long)(probe_now() - p.t0),
		       ok, require_arg, ws.conns_secure, ws.conns_crc, ws.sec_failures);
		if (!ok) {
			fprintf(stderr, "wr-monprobe: --require-mode %s: %u secure and %u crc connection(s) reached READY, %u secure-mode failure(s)\n", require_arg,
				ws.conns_secure, ws.conns_crc, ws.sec_failures);
			if (rc != 4) /* a fsid mismatch is the more serious finding and keeps its code */
				rc = 3;
		}
	}
	fflush(stdout);
	wrl_loop_destroy(loop);
	wr_client_destroy(c);
	wrl_mem_free(&arena);
	wrl_mem_free(&bulk);
	return rc;
}
