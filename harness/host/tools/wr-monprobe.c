/* SPDX-License-Identifier: MIT */
/*
 * wr-monprobe - connect to a Ceph monitor with the winrbd core, authenticate with cephx, and report
 * what the core learned. A lab and diagnostics tool: it proves the whole stack (msgr2 banner, hello,
 * cephx for either key type, monitor subscriptions) against a real cluster.
 *
 *   wr-monprobe --mon <ip[:port]> --user <name> --keyring <file> [--timeout <ms>] [--fsid <uuid>] [-v]
 *
 * It waits for WR_CS_ACTIVE, prints one line per client event, then the MonMap epoch and fsid (read
 * from the raw MMonMap the monitor sent) and the newest MOSDMap epoch received, and exits 0.
 *
 * Output (stdout, one record per line, "@<ms since start> <kind> <key=value ...>"):
 *   event, monmap, osdmap, result. A diagnostic goes to stderr. The key is read from the keyring file,
 * handed to the core and wiped; it is never printed or logged.
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
	fprintf(stderr, "usage: wr-monprobe --mon <ip[:port]> --user <name> --keyring <file> [--timeout <ms>] [--fsid <uuid>] [-v]\n");
}

int main(int argc, char **argv)
{
	const char *mon = NULL, *user = NULL, *keyring = NULL, *fsid_arg = NULL;
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
	cfg.mon_msg_cap = 4u * 1024u * 1024u;
	wrl_host_ops_init(&ops, &level);
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
		fprintf(stderr, "wr-monprobe: cannot create the client: %s\n", wr_strerror(st));
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
	fflush(stdout);
	wrl_loop_destroy(loop);
	wr_client_destroy(c);
	wrl_mem_free(&arena);
	wrl_mem_free(&bulk);
	return rc;
}
