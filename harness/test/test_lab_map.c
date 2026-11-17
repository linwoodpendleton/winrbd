/* SPDX-License-Identifier: MIT */
/*
 * test_lab_map.c - the map-enabled client against the REAL lab monitor: it logs in with cephx, receives the monitor's
 * MOSDMap messages over msgr2, decodes them itself, follows the epochs, and places objects. Label "lab": skipped
 * (exit 77) unless the environment names a cluster, so a plain ctest run on any machine stays green. Key material
 * comes from keyring files named in the environment, never from the repository, and is never printed.
 *
 *   WR_LAB_MON            monitor address, literal ip[:port] (the lab: 10.77.0.10:3300); run the test inside the lab VM
 *   WR_LAB_USER_K2        cephx user id for the aes256k key ("winrbd"); WR_LAB_KEYRING_K2 its keyring file
 *   WR_LAB_USER_K1        cephx user id for the legacy aes key ("winrbd-aes"); WR_LAB_KEYRING_K1 its file
 *   WR_LAB_POOLS          comma separated pool names to track (default "winrbd"; at most 8)
 *   WR_LAB_LATE_POOL      a pool to track only AFTER the first map is held (default none): the engine then has to ask the
 *                         monitor again with start 0, which a real monitor answers with a full map of the epoch it already
 *                         sent (docs/spec/osdmap.md 3.1); the test requires the pool to resolve and a second full map to count
 *   WR_LAB_NAMES          object names to place per pool (default 64)
 *   WR_LAB_FOLLOW_S       seconds to keep following the cluster after the first map (default 0). Change the cluster from
 *                         another shell meanwhile (a test pool, an upmap, a reweight): the client has to take every epoch
 *                         by incrementals, and a failed one by a full map, without a single undecodable entry.
 *   WR_LAB_OUT            file that gets one line per placement: the final epoch, pool, object name, PG seed, up and
 *                         acting sets and the primary. A script compares it with `ceph osd map -f json` at that epoch
 *                         (the test cannot call the admin CLI; the comparison is the lab comparison of architecture 18.4).
 *
 * What it checks by itself, per key type: the session becomes active, the first map is adopted (the monitor answers a
 * start-0 subscription with a full map), every tracked pool resolves, every placement is a consistent target (primary
 * in the acting set, every OSD id inside max_osd, the primary's address present, the epoch of the target equal to the
 * held epoch), and the counters show no entry that failed to decode or apply (n_bad == 0, no recorded failure).
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdlib.h>
#include <string.h>

#include "wrt.h"

#include "../host/wrl_sys.c"
#include "../host/wrl_loop.c"

#define LAB_TIMEOUT_MS 20000
#define KEYRING_MAX 4096u
#define MAX_POOLS 8u

typedef struct lab_run {
	wr_client *c;
	wr_pool_h pool[MAX_POOLS];
	unsigned n_pools;
	unsigned n_up, n_auth_failed, n_fatal, n_map_events, n_resync_events;
	uint32_t last_event_epoch;
	uint64_t follow_ms, t_first_map; /* follow window; start of it (0 = no map yet) */
	const char *late;                /* a pool to track after the first map, or NULL */
	unsigned late_tracked;           /* 1 once wr_client_pool_track was called for it */
	wr_status first_err;
} lab_run;

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0)
		*v++ = 0;
}

static int all_pools_ok(lab_run *r)
{
	wr_pool_info pi;
	unsigned i;

	for (i = 0; i < r->n_pools; i++)
		if (wr_client_pool_info(r->c, r->pool[i], &pi) != WR_OK || pi.status != WR_OK)
			return 0;
	return r->n_pools != 0;
}

static int lab_stop(void *arg)
{
	lab_run *r = (lab_run *)arg;
	wr_event e;
	wr_map_info mi;

	while (wr_client_next_event(r->c, &e)) {
		switch (e.kind) {
		case WR_EV_MON_SESSION_UP:
			r->n_up++;
			break;
		case WR_EV_AUTH_FAILED:
			r->n_auth_failed++;
			if (r->first_err == WR_OK)
				r->first_err = e.err.status;
			break;
		case WR_EV_FATAL:
			r->n_fatal++;
			if (r->first_err == WR_OK)
				r->first_err = e.err.status;
			break;
		case WR_EV_MAP:
			r->n_map_events++;
			r->last_event_epoch = e.epoch;
			break;
		case WR_EV_MAP_RESYNC:
			r->n_resync_events++;
			break;
		case WR_EV_NONE:
		case WR_EV_MON_SESSION_DOWN:
		case WR_EV_MAPMSG:
		case WR_EV_TICKETS_RENEWED:
		case WR_EV_CLUSTER_UNREACHABLE:
		default:
			break;
		}
	}
	if (r->n_auth_failed != 0 || r->n_fatal != 0)
		return 1; /* will not fix itself: stop and report */
	if (wr_client_get_state(r->c) != WR_CS_ACTIVE || wr_client_map_info(r->c, &mi) != WR_OK || !all_pools_ok(r))
		return 0;
	if (r->late != NULL && !r->late_tracked) {
		/* every first pool resolved, a map is held: now the late pool, which the held map has no record of */
		if (wr_client_pool_track(r->c, r->late, &r->pool[r->n_pools]) == WR_OK)
			r->n_pools++;
		r->late_tracked = 1;
		return 0;
	}
	if (r->t_first_map == 0)
		r->t_first_map = wrl_clock_ms(CLOCK_MONOTONIC);
	return wrl_clock_ms(CLOCK_MONOTONIC) - r->t_first_map >= r->follow_ms;
}

static void object_name(char *out, size_t cap, unsigned i)
{
	if ((i & 1u) == 0)
		snprintf(out, cap, "rbd_data.0123456789ab.%016x", i);
	else
		snprintf(out, cap, "wrtest-lab-%u", i);
}

static void set_str(char *out, size_t cap, const char *s)
{
	snprintf(out, cap, "%s", s);
}

static void list_ids(FILE *f, const int32_t *v, unsigned n)
{
	unsigned i;

	fputc('[', f);
	for (i = 0; i < n; i++)
		fprintf(f, "%s%d", i ? "," : "", (int)v[i]);
	fputc(']', f);
}

static void place_all(lab_run *r, const char *const *pool_names, unsigned names, FILE *out)
{
	wr_map_info mi;
	unsigned p, i, k;

	WRT_CHECK_STATUS(WR_OK, wr_client_map_info(r->c, &mi));
	if (out != NULL)
		fprintf(out, "epoch %u\n", (unsigned)mi.epoch);
	for (p = 0; p < r->n_pools; p++) {
		for (i = 0; i < names; i++) {
			char nm[64];
			wr_object_id oid;
			wr_target t;
			int found = 0;

			object_name(nm, sizeof(nm), i);
			memset(&oid, 0, sizeof(oid));
			oid.name = nm;
			oid.name_len = strlen(nm);
			WRT_CHECK_STATUS(WR_OK, wr_client_map_target(r->c, r->pool[p], &oid, &t));
			WRT_CHECK_U64(t.epoch, mi.epoch);
			WRT_CHECK(t.n_acting >= 1u && t.n_acting <= WR_MAP_REP_MAX);
			WRT_CHECK(t.n_up <= WR_MAP_REP_MAX);
			for (k = 0; k < t.n_acting; k++) {
				WRT_CHECK(t.acting[k] >= 0 && (uint32_t)t.acting[k] < mi.max_osd);
				if (t.acting[k] == t.acting_primary)
					found = 1;
			}
			WRT_CHECK(found);
			WRT_CHECK(t.primary_addr.family != 0u); /* the primary is up, so the map has its address */
			if (out != NULL) {
				fprintf(out, "%s %s %x up ", pool_names[p], nm, (unsigned)t.pg_seed);
				list_ids(out, t.up, t.n_up);
				fprintf(out, " acting ");
				list_ids(out, t.acting, t.n_acting);
				fprintf(out, " primary %d\n", (int)t.acting_primary);
			}
		}
	}
}

static unsigned split_pools(char *list, const char **names)
{
	unsigned n = 0;
	char *p = list;

	while (*p != '\0' && n < MAX_POOLS) {
		names[n++] = p;
		while (*p != '\0' && *p != ',')
			p++;
		if (*p == ',')
			*p++ = '\0';
	}
	return n;
}

static void run_one(const char *label, unsigned want_type, const char *mon, const char *user, const char *keyring,
		    const char *pools_env, const char *late_pool, unsigned names, unsigned follow_s, const char *out_path)
{
	static char kr[KEYRING_MAX];
	char pools[256];
	const char *pool_names[MAX_POOLS];
	size_t krlen = 0, nmon = 0;
	wr_cluster_spec spec;
	wr_config cfg;
	wr_host_ops ops;
	wr_mem_req req;
	wr_mem_region arena, bulk;
	unsigned level = WR_LOG_WARN;
	wr_client *c = NULL;
	wrl_loop *loop = NULL;
	lab_run r;
	wr_status st;
	wr_map_stats ms;
	wr_map_info mi;
	unsigned i;
	FILE *out = NULL;

	memset(&spec, 0, sizeof(spec));
	memset(&r, 0, sizeof(r));
	WRT_CHECK(strlen(user) < sizeof(spec.user));
	strncpy(spec.user, user, sizeof(spec.user) - 1u);
	WRT_CHECK_STATUS(WR_OK, wr_mon_parse_hosts(mon, strlen(mon), spec.mons, WR_MAX_MONS, &nmon));
	spec.n_mons = (uint8_t)nmon;
	st = wrl_read_text_file(keyring, kr, sizeof(kr), &krlen);
	WRT_CHECK_STATUS(WR_OK, st);
	if (st == WR_OK)
		st = wr_key_parse_keyring(&spec.key, kr, krlen);
	wipe(kr, sizeof(kr));
	WRT_CHECK_STATUS(WR_OK, st);
	if (st != WR_OK) {
		fprintf(stderr, "lab %s: cannot load the key from the keyring file\n", label);
		return;
	}
	WRT_CHECK_U64(spec.key.type, want_type);

	wr_config_profile_harness(&cfg);
	wr_config_enable_maps(&cfg, WR_MAPS_HARNESS);
	wrl_host_ops_init(&ops, &level);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	WRT_CHECK_STATUS(WR_OK, wrl_mem_alloc(&arena, req.arena));
	WRT_CHECK_STATUS(WR_OK, wrl_mem_alloc(&bulk, req.bulk));
	st = wr_client_create(&cfg, &ops, &spec, arena, bulk, &c);
	wr_key_wipe(&spec.key);
	WRT_CHECK_STATUS(WR_OK, st);
	if (st != WR_OK) {
		wrl_mem_free(&arena);
		wrl_mem_free(&bulk);
		return;
	}
	r.c = c;
	r.follow_ms = (uint64_t)follow_s * 1000u;
	set_str(pools, sizeof(pools), pools_env);
	r.n_pools = split_pools(pools, pool_names);
	WRT_CHECK(r.n_pools >= 1u);
	for (i = 0; i < r.n_pools; i++)
		WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(c, pool_names[i], &r.pool[i]));
	if (late_pool != NULL && *late_pool != '\0' && r.n_pools < MAX_POOLS) {
		r.late = late_pool;
		pool_names[r.n_pools] = late_pool; /* its handle will be r.pool[r.n_pools], tracked after the first map */
	}
	WRT_CHECK_STATUS(WR_OK, wrl_loop_create(c, &loop));

	st = wrl_loop_run(loop, lab_stop, &r, (int)(LAB_TIMEOUT_MS + follow_s * 1000u));
	(void)lab_stop(&r);

	WRT_CHECK_STATUS(WR_OK, st);
	WRT_CHECK(wr_client_get_state(c) == WR_CS_ACTIVE);
	WRT_CHECK_U64(r.n_auth_failed, 0);
	WRT_CHECK_U64(r.n_fatal, 0);
	WRT_CHECK(r.n_up >= 1);
	WRT_CHECK(r.n_map_events >= 1);
	WRT_CHECK(all_pools_ok(&r));
	wr_client_map_stats(c, &ms);
	WRT_CHECK_STATUS(WR_OK, wr_client_map_info(c, &mi));
	WRT_CHECK_U64(ms.epoch, mi.epoch);
	WRT_CHECK(ms.n_full >= 1u); /* a start-0 subscription is answered with a full map */
	if (r.late != NULL) {
		WRT_CHECK(r.late_tracked);
		WRT_CHECK(r.n_pools >= 2u); /* the late pool was tracked and is among the resolved ones */
		WRT_CHECK(ms.n_full >= 2u); /* the monitor answered the second start-0 request with a full map */
	}
	WRT_CHECK_U64(ms.n_bad, 0);
	WRT_CHECK_U64(ms.n_msg_bad, 0);
	WRT_CHECK_U64(ms.n_msg_toobig, 0);
	WRT_CHECK_U64(ms.n_fsid_drop, 0);
	WRT_CHECK_U64(ms.last_err, WR_OK);
	WRT_CHECK(ms.newest_seen >= ms.epoch);
	if (out_path != NULL && *out_path != '\0') {
		out = fopen(out_path, "w");
		WRT_CHECK(out != NULL);
	}
	if (r.n_pools >= 1u)
		place_all(&r, pool_names, names, out);
	if (out != NULL)
		fclose(out);
	fprintf(stderr,
		"lab %s: key type %u, held epoch %u (newest seen %u), %u WR_EV_MAP events, %u full maps, %u incrementals, %u "
		"re-requests, %u skipped, %u bad; %u pools x %u names placed\n",
		label, want_type, (unsigned)mi.epoch, (unsigned)ms.newest_seen, r.n_map_events, (unsigned)ms.n_full,
		(unsigned)ms.n_inc, (unsigned)ms.n_resync, (unsigned)ms.n_skipped, (unsigned)ms.n_bad, r.n_pools, names);

	wrl_loop_destroy(loop);
	wr_client_destroy(c);
	wrl_mem_free(&arena);
	wrl_mem_free(&bulk);
}

int main(void)
{
	const char *mon = getenv("WR_LAB_MON");
	const char *u2 = getenv("WR_LAB_USER_K2"), *k2 = getenv("WR_LAB_KEYRING_K2");
	const char *u1 = getenv("WR_LAB_USER_K1"), *k1 = getenv("WR_LAB_KEYRING_K1");
	const char *late = getenv("WR_LAB_LATE_POOL");
	const char *pools = getenv("WR_LAB_POOLS"), *nn = getenv("WR_LAB_NAMES"), *fs = getenv("WR_LAB_FOLLOW_S");
	const char *out = getenv("WR_LAB_OUT");
	int have2 = u2 != NULL && k2 != NULL && *u2 != '\0' && *k2 != '\0';
	int have1 = u1 != NULL && k1 != NULL && *u1 != '\0' && *k1 != '\0';
	unsigned names = 64, follow = 0;

	if (mon == NULL || *mon == '\0' || (!have1 && !have2))
		WRT_SKIP("WR_LAB_MON and WR_LAB_USER_K2 / WR_LAB_KEYRING_K2 (or the K1 pair) are not set");
	if (pools == NULL || *pools == '\0')
		pools = "winrbd";
	if (nn != NULL && *nn != '\0')
		names = (unsigned)strtoul(nn, NULL, 10);
	if (fs != NULL && *fs != '\0')
		follow = (unsigned)strtoul(fs, NULL, 10);
	if (names == 0 || names > 100000u)
		names = 64;
	if (follow > 3600u)
		follow = 3600;
	if (have2)
		run_one("k2 (aes256k)", WR_KEY_TYPE_AES256K, mon, u2, k2, pools, late, names, follow, out);
	if (have1)
		run_one("k1 (aes)", WR_KEY_TYPE_AES, mon, u1, k1, pools, late, names, follow, have2 ? NULL : out);
	return wrt_finish();
}
