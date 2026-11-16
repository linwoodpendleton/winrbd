/* SPDX-License-Identifier: MIT */
/*
 * test_lab_mon.c - the whole client stack against a REAL Ceph monitor (the lab cluster), for each key type.
 * Label "lab": skipped (exit 77) unless the environment names a cluster, so a plain ctest run on any machine
 * stays green. Key material comes from keyring files named in the environment, never from the repository,
 * and is never printed.
 *
 *   WR_LAB_MON            monitor address, literal ip[:port] (the lab: 10.77.0.10:3300); reachable from the
 *                         machine running the test, which for the lab VM means running it inside the VM
 *   WR_LAB_USER_K2        cephx user id for the aes256k key ("winrbd"); WR_LAB_KEYRING_K2 its keyring file
 *   WR_LAB_USER_K1        cephx user id for the legacy aes key ("winrbd-aes"); WR_LAB_KEYRING_K1 its file
 *   WR_LAB_FSID           optional: the cluster id (uuid); when set the MonMap fsid must equal it and the
 *                         engine itself checks every map against it
 *
 * For every configured key the test requires, within 10 s: the session reaches WR_CS_ACTIVE, a MonMap is
 * delivered with a well-formed fsid (equal to WR_LAB_FSID when given), an MOSDMap is delivered with newest
 * epoch >= 1 and the same fsid as the MonMap, and no WR_EV_AUTH_FAILED / WR_EV_FATAL event is raised. Both
 * key types are the ones the lab provisions (harness/lab/README.md): the client.winrbd user holds an
 * aes256k key, client.winrbd-aes a legacy aes key.
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

#define LAB_TIMEOUT_MS 10000
#define KEYRING_MAX 4096u

typedef struct lab_run {
	wr_client *c;
	int have_monmap, have_osdmap;
	uint32_t monmap_epoch, osd_newest;
	uint8_t mon_fsid[16], osd_fsid[16];
	unsigned n_up, n_auth_failed, n_fatal, n_unreachable;
	wr_status first_err;
} lab_run;

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* MMonMap front = u32 length + MonMap envelope (struct_v, compat, u32 len) whose body starts with fsid and
 * epoch (mon-client.md 2.4.1). Hand-read here so the test uses only the public API. */
static int monmap_ids(const wr_mapmsg *m, uint8_t *fsid, uint32_t *epoch)
{
	const uint8_t *f = m->front;
	size_t blob;

	if (m->front_len < 4u)
		return -1;
	blob = rd32(f);
	if (blob > m->front_len - 4u || blob < 26u)
		return -1;
	f += 4;
	if (f[0] < 6u || rd32(f + 2) > blob - 6u || rd32(f + 2) < 20u)
		return -1;
	memcpy(fsid, f + 6, 16);
	*epoch = rd32(f + 6 + 16);
	return 0;
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

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0)
		*v++ = 0;
}

static int lab_stop(void *arg)
{
	lab_run *r = (lab_run *)arg;
	wr_event e;
	wr_mapmsg m;

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
		case WR_EV_CLUSTER_UNREACHABLE:
			r->n_unreachable++;
			break;
		case WR_EV_NONE:
		case WR_EV_MON_SESSION_DOWN:
		case WR_EV_MAPMSG:
		case WR_EV_TICKETS_RENEWED:
		default:
			break;
		}
	}
	while (wr_client_mapmsg_peek(r->c, &m)) {
		if (m.kind == WR_MAPMSG_MONMAP) {
			if (monmap_ids(&m, r->mon_fsid, &r->monmap_epoch) == 0)
				r->have_monmap = 1;
		} else if (m.kind == WR_MAPMSG_OSDMAP && m.front_len >= 16u) {
			memcpy(r->osd_fsid, m.front, 16); /* an MOSDMap front starts with the cluster id */
			if (!r->have_osdmap || m.newest_epoch > r->osd_newest)
				r->osd_newest = m.newest_epoch;
			r->have_osdmap = 1;
		}
		wr_client_mapmsg_release(r->c);
	}
	/* an auth refusal or a fatal error will not fix itself: stop at once and report it */
	if (r->n_auth_failed != 0 || r->n_fatal != 0)
		return 1;
	return wr_client_get_state(r->c) == WR_CS_ACTIVE && r->have_monmap && r->have_osdmap;
}

static void run_one(const char *label, unsigned want_type, const char *mon, const char *user, const char *keyring,
		    const char *fsid_text)
{
	static char kr[KEYRING_MAX];
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
	uint8_t want_fsid[16];
	uint64_t t0, t1;
	int have_want = 0;

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
	WRT_CHECK_U64(spec.key.type, want_type); /* the user really holds the key type this run is for */
	if (fsid_text != NULL) {
		WRT_CHECK(fsid_parse(fsid_text, want_fsid) == 0);
		have_want = fsid_parse(fsid_text, want_fsid) == 0;
		if (have_want) {
			spec.fsid_known = 1;
			memcpy(spec.fsid, want_fsid, 16);
		}
	}

	wr_config_profile_harness(&cfg);
	cfg.mon_msg_cap = 4u * 1024u * 1024u;
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
	WRT_CHECK_STATUS(WR_OK, wrl_loop_create(c, &loop));
	r.c = c;

	t0 = wrl_clock_ms(CLOCK_MONOTONIC);
	st = wrl_loop_run(loop, lab_stop, &r, LAB_TIMEOUT_MS);
	t1 = wrl_clock_ms(CLOCK_MONOTONIC);
	(void)lab_stop(&r);

	WRT_CHECK_STATUS(WR_OK, st);
	WRT_CHECK(wr_client_get_state(c) == WR_CS_ACTIVE);
	WRT_CHECK_U64(r.n_auth_failed, 0);
	WRT_CHECK_U64(r.n_fatal, 0);
	WRT_CHECK(r.n_up >= 1);
	WRT_CHECK(r.have_monmap);
	WRT_CHECK(r.have_osdmap);
	WRT_CHECK(r.monmap_epoch >= 1);
	WRT_CHECK(r.osd_newest >= 1);
	if (r.have_monmap && r.have_osdmap)
		WRT_CHECK_MEM(r.osd_fsid, r.mon_fsid, 16); /* the maps agree about which cluster this is */
	if (have_want && r.have_monmap)
		WRT_CHECK_MEM(r.mon_fsid, want_fsid, 16);
	if (r.have_monmap) {
		uint8_t zero[16];

		memset(zero, 0, sizeof(zero));
		WRT_CHECK(memcmp(r.mon_fsid, zero, 16) != 0);
	}
	fprintf(stderr, "lab %s: key type %u, active in %llu ms, monmap epoch %u, newest osdmap epoch %u, fsid %s\n", label,
		want_type, (unsigned long long)(t1 - t0), (unsigned)r.monmap_epoch, (unsigned)r.osd_newest,
		have_want ? "matches WR_LAB_FSID" : "not pinned (set WR_LAB_FSID)");

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
	const char *fsid = getenv("WR_LAB_FSID");
	int have2 = u2 != NULL && k2 != NULL && *u2 != '\0' && *k2 != '\0';
	int have1 = u1 != NULL && k1 != NULL && *u1 != '\0' && *k1 != '\0';

	if (mon == NULL || *mon == '\0' || (!have1 && !have2))
		WRT_SKIP("WR_LAB_MON and WR_LAB_USER_K2 / WR_LAB_KEYRING_K2 (or the K1 pair) are not set");
	if (fsid != NULL && *fsid == '\0')
		fsid = NULL;
	if (have2)
		run_one("k2 (aes256k)", WR_KEY_TYPE_AES256K, mon, u2, k2, fsid);
	if (have1)
		run_one("k1 (aes)", WR_KEY_TYPE_AES, mon, u1, k1, fsid);
	return wrt_finish();
}
