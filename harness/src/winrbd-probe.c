/* SPDX-License-Identifier: MIT */
/*
 * winrbd-probe - the Phase 1 part A end-to-end probe. It drives the whole winrbd core (msgr2 in crc
 * mode, cephx, the monitor client) through the Linux host against a real Ceph monitor and proves, in
 * one run, every step a block client needs before it can talk to an OSD:
 *
 *   connect (msgr2 v2, crc mode) -> banner / hello -> cephx login -> client ident -> session up ->
 *   subscribe monmap + osdmap -> receive MMonMap and the first MOSDMap -> stay alive with keepalives.
 *
 *   winrbd-probe --mon <ip[:port]> --user <name> --keyring <file>
 *                [--duration <s>] [--timeout <ms>] [--fsid <uuid>] [-v]
 *
 * --duration is how long the session is kept alive after the maps arrived (default 60 s, 0 = do not
 * wait). Every frame the core accepts passed the msgr2 CRC checks of its segments (a bad one ends the
 * connection with WR_E_M2_FRAME_CRC, which this tool reports as a CRC failure and exits non-zero).
 *
 * Output (stdout, "@<ms> <kind> key=value ..."): event lines, then one summary block:
 *   summary fsid, monmap (epoch and the monitor addresses), osdmap (newest epoch, front bytes, size of
 *   the full map blob, epoch range), tickets (seconds of validity left), session (keepalives sent and
 *   acknowledged, messages received, CRC failures), result.
 * Diagnostics go to stderr. The key is read from the keyring file, handed to the core and wiped; it is
 * never printed or logged.
 *
 * Exit status: 0 healthy for the whole duration; 1 no active session within --timeout; 2 usage or
 * setup error; 3 the client failed fatally; 4 fsid mismatch (between the maps, or against --fsid);
 * 5 authentication refused (wrong key or unknown user); 6 session lost during the keep-alive window
 * or the maps never arrived; 7 a frame failed its CRC.
 *
 * The probe reads two things from core internals that the public API does not expose (ticket
 * validity and keepalive counters); it is harness code, not a model for a host.
 */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wrl_host.h"
#include "wri_client.h"

#define PROBE_DEFAULT_TIMEOUT_MS 15000
#define PROBE_DEFAULT_DURATION_S 60
#define PROBE_MAP_GRACE_MS 5000 /* after the session is up, how long to wait for the first MonMap and MOSDMap */
#define PROBE_KA_GRACE_MS 3000 /* after the window, how long to wait for the answer to the last keepalive */
#define PROBE_KEYRING_MAX 4096u

typedef struct probe {
	wr_client *c;
	uint64_t t0;
	int timeout_ms;
	uint64_t active_at;  /* mono ms when ACTIVE was first seen, 0 = not yet */
	uint64_t done_at;    /* mono ms when the keep-alive window ends, 0 = not started */
	int duration_ms;
	int have_monmap, have_osdmap, fsid_given, fsid_mismatch;
	unsigned n_auth_failed, n_session_up, n_session_down, n_crc_fail, n_events, n_maps;
	wr_errinfo auth_err, down_err, crc_err;
	uint8_t mon_fsid[16], osd_fsid[16], want_fsid[16];
	wri_monmap mm;
	wri_mosdmap_info oi;
	size_t osd_front_len, osd_full_bytes;
	uint32_t osd_msg_version;
	int stop; /* 1 = leave the loop now (failure) */
} probe;

/* memset the optimiser cannot drop (the buffer is dead afterwards, which invites removing a plain memset). */
static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0)
		*v++ = 0;
}

static uint64_t now_ms(void)
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
	case WR_EV_NONE:
	default:
		return "NONE";
	}
}

static void addr_str(const wri_eaddr *a, char *out, size_t cap)
{
	if (a->family == WR_AF_IPV4)
		snprintf(out, cap, "v2:%u.%u.%u.%u:%u/%u", a->ip[0], a->ip[1], a->ip[2], a->ip[3], (unsigned)a->port,
			 (unsigned)a->nonce);
	else if (a->family == WR_AF_IPV6) {
		unsigned i;
		size_t o = (size_t)snprintf(out, cap, "v2:[");

		for (i = 0; i < 16u && o + 8u < cap; i += 2u)
			o += (size_t)snprintf(out + o, cap - o, "%s%x", i ? ":" : "", (unsigned)a->ip[i] << 8 | a->ip[i + 1u]);
		snprintf(out + o, cap - o, "]:%u/%u", (unsigned)a->port, (unsigned)a->nonce);
	} else
		snprintf(out, cap, "(blank)");
}

static void print_err(const char *what_kind, const wr_errinfo *e)
{
	printf(" %s=%s module=%u peer_result=%d what=\"%s\"", what_kind, wr_status_name(e->status), (unsigned)e->module,
	       (int)e->peer_result, e->what != NULL ? e->what : "");
}

static void take_event(probe *p, const wr_event *e)
{
	printf("@%llu event %s", (unsigned long long)(now_ms() - p->t0), ev_name(e->kind));
	if (e->kind == WR_EV_MAPMSG)
		printf(" epoch=%u", (unsigned)e->epoch);
	if (e->err.status != WR_OK)
		print_err("status", &e->err);
	printf("\n");
	fflush(stdout);
	p->n_events++;
	if (e->kind == WR_EV_MON_SESSION_UP)
		p->n_session_up++;
	if (e->kind == WR_EV_AUTH_FAILED) {
		if (p->n_auth_failed++ == 0)
			p->auth_err = e->err;
		p->stop = 1; /* a refused login is final for this tool; the engine would retry with back-off */
	}
	if (e->err.status == WR_E_M2_FRAME_CRC) {
		if (p->n_crc_fail++ == 0)
			p->crc_err = e->err;
	}
	if (e->kind == WR_EV_MON_SESSION_DOWN) {
		p->n_session_down++;
		p->down_err = e->err;
		if (p->active_at != 0)
			p->stop = 1; /* lost the session while we were supposed to keep it */
	}
	if (e->kind == WR_EV_FATAL)
		p->stop = 1;
}

/* Walk the two map lists of an MOSDMap front: fsid(16) u32 n, {u32 epoch, u32 len, blob}*, u32 n, ... Returns
 * the total bytes of the "full map" blobs (0 if none or malformed). The core's header decoder steps over
 * the blobs the same way; this only adds the sizes up. */
static size_t osdmap_full_bytes(const uint8_t *f, size_t n)
{
	size_t off = 16, total = 0;
	unsigned list;

	for (list = 0; list < 2u; list++) {
		uint32_t cnt, i;

		if (n < off + 4u)
			return 0;
		cnt = (uint32_t)f[off] | (uint32_t)f[off + 1] << 8 | (uint32_t)f[off + 2] << 16 | (uint32_t)f[off + 3] << 24;
		off += 4;
		if (cnt > 1024u)
			return 0;
		for (i = 0; i < cnt; i++) {
			uint32_t len;

			if (n < off + 8u)
				return 0;
			len = (uint32_t)f[off + 4] | (uint32_t)f[off + 5] << 8 | (uint32_t)f[off + 6] << 16 |
			      (uint32_t)f[off + 7] << 24;
			off += 8;
			if (len > n - off)
				return 0;
			if (list == 1u)
				total += len;
			off += len;
		}
	}
	return total;
}

static void take_map(probe *p, const wr_mapmsg *m)
{
	char id[37];
	uint64_t at = now_ms() - p->t0;

	p->n_maps++;
	if (m->kind == WR_MAPMSG_MONMAP) {
		const uint8_t *blob;
		size_t blen;

		if (wri_mmonmap_front(m->front, m->front_len, &blob, &blen) != WR_OK ||
		    wri_monmap_decode(blob, blen, &p->mm) != WR_OK) {
			printf("@%llu monmap MALFORMED front_len=%zu\n", (unsigned long long)at, m->front_len);
			p->stop = 1;
			return;
		}
		memcpy(p->mon_fsid, p->mm.fsid, 16);
		p->have_monmap = 1;
		fsid_str(p->mm.fsid, id);
		printf("@%llu monmap epoch=%u fsid=%s mons=%u msg_version=%u front_len=%zu\n", (unsigned long long)at,
		       (unsigned)p->mm.epoch, id, (unsigned)p->mm.n_mons, (unsigned)m->msg_version, m->front_len);
	} else if (m->kind == WR_MAPMSG_OSDMAP) {
		wri_mosdmap_info oi;

		if (wri_mosdmap_info_decode(m->front, m->front_len, m->msg_version, &oi) != WR_OK) {
			printf("@%llu osdmap MALFORMED front_len=%zu\n", (unsigned long long)at, m->front_len);
			p->stop = 1;
			return;
		}
		/* keep the first message that carries a full map (the one a client starts from) */
		if (!p->have_osdmap || (p->oi.n_full == 0 && oi.n_full != 0) || oi.newest_map > p->oi.newest_map) {
			p->oi = oi;
			memcpy(p->osd_fsid, oi.fsid, 16);
			p->osd_front_len = m->front_len;
			p->osd_full_bytes = osdmap_full_bytes(m->front, m->front_len);
			p->osd_msg_version = m->msg_version;
		}
		p->have_osdmap = 1;
		fsid_str(oi.fsid, id);
		printf("@%llu osdmap newest_epoch=%u oldest_epoch=%u fsid=%s inc=%u full=%u range=%u..%u msg_version=%u front_len=%zu\n",
		       (unsigned long long)at, (unsigned)oi.newest_map, (unsigned)oi.oldest_map, id, (unsigned)oi.n_incremental,
		       (unsigned)oi.n_full, (unsigned)oi.first_epoch, (unsigned)oi.last_epoch, (unsigned)m->msg_version,
		       m->front_len);
	}
	fflush(stdout);
}

static void drain(probe *p)
{
	wr_event e;
	wr_mapmsg m;

	while (wr_client_next_event(p->c, &e))
		take_event(p, &e);
	while (wr_client_mapmsg_peek(p->c, &m)) {
		take_map(p, &m);
		wr_client_mapmsg_release(p->c);
	}
}

/* Called by the loop before every step. */
static int probe_stop(void *arg)
{
	probe *p = (probe *)arg;
	uint64_t now = now_ms();

	drain(p);
	if (p->stop)
		return 1;
	if (p->active_at == 0 && wr_client_get_state(p->c) == WR_CS_ACTIVE)
		p->active_at = now;
	if (p->active_at == 0)
		return now - p->t0 >= (uint64_t)p->timeout_ms; /* no session in time */
	if (p->done_at == 0) {
		if (p->have_monmap && p->have_osdmap) {
			p->done_at = now + (uint64_t)p->duration_ms; /* the keep-alive window starts when both maps are in */
			if (p->duration_ms == 0)
				return 1;
		} else if (now - p->active_at >= PROBE_MAP_GRACE_MS)
			return 1; /* the maps never came */
		return 0;
	}
	if (now < p->done_at)
		return 0;
	/* The window is over: do not walk away from a keepalive that is still unanswered (a clean close, and the
	 * capture then holds every ping together with its acknowledgement). */
	return !p->c->mon.ping_out || now >= p->done_at + PROBE_KA_GRACE_MS;
}

static void usage(void)
{
	fprintf(stderr, "usage: winrbd-probe --mon <ip[:port]> --user <name> --keyring <file> [--duration <s>] "
			"[--timeout <ms>] [--fsid <uuid>] [-v]\n");
}

static int parse_int(const char *s, long lo, long hi, int *out)
{
	char *end = NULL;
	long v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0' || v < lo || v > hi)
		return -1;
	*out = (int)v;
	return 0;
}

/* The core's own counters of the monitor connection, if it is still there. */
static void conn_counters(const wr_client *c, uint32_t *ka_ack, uint32_t *msg_in, uint32_t *msg_dropped)
{
	*ka_ack = *msg_in = *msg_dropped = 0;
	if (c->mon.conn_slot != WRI_MON_NO_SLOT && c->mon.conn_slot < c->n_slot && c->slot[c->mon.conn_slot].in_use) {
		const wri_m2_conn *k = &c->slot[c->mon.conn_slot].conn;

		*ka_ack = k->n_ka_ack;
		*msg_in = k->n_msg_in;
		*msg_dropped = k->n_msg_dropped;
	}
}

static void print_ticket(const wr_client *c, const char *name, unsigned slot, uint64_t now)
{
	const wri_cx_ticket *t = &c->cx.ticket[slot];

	if (!t->have) {
		printf(" %s=none", name);
		return;
	}
	if (t->valid_until_ms > now)
		printf(" %s=valid_for_%llus", name, (unsigned long long)((t->valid_until_ms - now) / 1000u));
	else
		printf(" %s=EXPIRED", name);
}

int main(int argc, char **argv)
{
	const char *mon = NULL, *user = NULL, *keyring = NULL, *fsid_arg = NULL;
	int timeout_ms = PROBE_DEFAULT_TIMEOUT_MS, duration_s = PROBE_DEFAULT_DURATION_S, i;
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
			if (parse_int(argv[++i], 1, INT_MAX, &timeout_ms) != 0) {
				fprintf(stderr, "winrbd-probe: bad --timeout (milliseconds, 1 to %d)\n", INT_MAX);
				return 2;
			}
		} else if (strcmp(a, "--duration") == 0 && has_val) {
			if (parse_int(argv[++i], 0, 86400, &duration_s) != 0) {
				fprintf(stderr, "winrbd-probe: bad --duration (seconds, 0 to 86400)\n");
				return 2;
			}
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
		fprintf(stderr, "winrbd-probe: user name too long\n");
		return 2;
	}
	strcpy(spec.user, user);
	if (fsid_arg != NULL) {
		if (fsid_parse(fsid_arg, p.want_fsid) != 0) {
			fprintf(stderr, "winrbd-probe: bad --fsid\n");
			return 2;
		}
		p.fsid_given = 1;
	}
	st = wr_mon_parse_hosts(mon, strlen(mon), spec.mons, WR_MAX_MONS, &nmon);
	if (st != WR_OK) {
		fprintf(stderr, "winrbd-probe: --mon: %s\n", wr_strerror(st));
		return 2;
	}
	spec.n_mons = (uint8_t)nmon;
	st = wrl_read_text_file(keyring, kr, sizeof(kr), &krlen);
	if (st == WR_OK)
		st = wr_key_parse_keyring(&spec.key, kr, krlen);
	wipe(kr, sizeof(kr));
	if (st != WR_OK) {
		fprintf(stderr, "winrbd-probe: keyring %s: %s\n", keyring, wr_strerror(st));
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
		fprintf(stderr, "winrbd-probe: cannot create the client: %s\n", wr_strerror(st));
		return 2;
	}
	st = wrl_loop_create(c, &loop);
	if (st != WR_OK) {
		fprintf(stderr, "winrbd-probe: cannot create the loop: %s\n", wr_strerror(st));
		wr_client_destroy(c);
		wrl_mem_free(&arena);
		wrl_mem_free(&bulk);
		return 2;
	}

	p.c = c;
	p.timeout_ms = timeout_ms;
	p.duration_ms = duration_s * 1000;
	p.t0 = now_ms();
	printf("@0 start mon=%s user=%s timeout_ms=%d duration_s=%d\n", mon, user, timeout_ms, duration_s);
	fflush(stdout);

	/* One loop: until the session is up and both maps are in (or failure), then the keep-alive window.
	 * probe_stop owns every limit (connect timeout, map grace, window). */
	st = WR_OK;
	while (!probe_stop(&p)) {
		/* a short wait so the keep-alive window ends on time even when the client has no timer due */
		st = wrl_loop_step(loop, 200);
		if (st != WR_OK)
			break;
	}
	drain(&p);

	{
		uint32_t ka_ack, msg_in, msg_dropped;
		uint64_t now = now_ms();
		wr_stats stats;
		int active = wr_client_get_state(c) == WR_CS_ACTIVE;
		uint64_t kept_ms = 0;

		if (p.done_at != 0) { /* the keep-alive window started at done_at - duration and ends at done_at */
			uint64_t began = p.done_at - (uint64_t)p.duration_ms;

			kept_ms = now > began ? now - began : 0;
			if (kept_ms > (uint64_t)p.duration_ms)
				kept_ms = (uint64_t)p.duration_ms;
		}
		conn_counters(c, &ka_ack, &msg_in, &msg_dropped);
		wr_client_get_stats(c, &stats);

		if (p.have_monmap && p.have_osdmap && memcmp(p.mon_fsid, p.osd_fsid, 16) != 0)
			p.fsid_mismatch = 1;
		if (p.fsid_given && p.have_monmap && memcmp(p.want_fsid, p.mon_fsid, 16) != 0)
			p.fsid_mismatch = 1;
		if (p.fsid_given && p.have_osdmap && memcmp(p.want_fsid, p.osd_fsid, 16) != 0)
			p.fsid_mismatch = 1;

		if (p.n_auth_failed != 0) {
			printf("@%llu result FAIL reason=auth_refused", (unsigned long long)(now - p.t0));
			print_err("error", &p.auth_err);
			printf("\n");
			fprintf(stderr, "winrbd-probe: authentication refused by the monitor for client.%s (%s): wrong key or unknown user\n",
				user, wr_status_name(p.auth_err.status));
			rc = 5;
		} else if (p.n_crc_fail != 0) {
			printf("@%llu result FAIL reason=frame_crc", (unsigned long long)(now - p.t0));
			print_err("error", &p.crc_err);
			printf("\n");
			fprintf(stderr, "winrbd-probe: a frame failed its checksum\n");
			rc = 7;
		} else if (p.active_at == 0) {
			const wr_errinfo *e = wr_client_last_error(c);

			if (st != WR_OK && st != WR_E_TIMEOUT) {
				printf("@%llu result FAIL reason=fatal status=%s\n", (unsigned long long)(now - p.t0), wr_status_name(st));
				fprintf(stderr, "winrbd-probe: the client failed: %s\n", wr_strerror(st));
				rc = 3;
			} else {
				printf("@%llu result FAIL reason=no_session", (unsigned long long)(now - p.t0));
				print_err("last_error", e);
				printf("\n");
				fprintf(stderr, "winrbd-probe: no active monitor session within %d ms (last error %s)\n", timeout_ms,
					wr_status_name(e->status));
				rc = 1;
			}
		} else if (p.n_session_down != 0) {
			printf("@%llu result FAIL reason=session_lost", (unsigned long long)(now - p.t0));
			print_err("error", &p.down_err);
			printf("\n");
			fprintf(stderr, "winrbd-probe: the monitor session was lost: %s\n", wr_status_name(p.down_err.status));
			rc = 6;
		} else if (st != WR_OK && st != WR_E_TIMEOUT) {
			printf("@%llu result FAIL reason=fatal status=%s\n", (unsigned long long)(now - p.t0), wr_status_name(st));
			fprintf(stderr, "winrbd-probe: the client failed: %s\n", wr_strerror(st));
			rc = 3;
		} else if (!p.have_monmap || !p.have_osdmap) {
			printf("@%llu result FAIL reason=maps_missing monmap=%d osdmap=%d\n", (unsigned long long)(now - p.t0),
			       p.have_monmap, p.have_osdmap);
			fprintf(stderr, "winrbd-probe: the session is up but the %s did not arrive\n",
				p.have_monmap ? "osdmap" : "monmap");
			rc = 6;
		} else if (p.fsid_mismatch) {
			printf("@%llu result FAIL reason=fsid_mismatch\n", (unsigned long long)(now - p.t0));
			fprintf(stderr, "winrbd-probe: the cluster id of the maps differs from each other or from --fsid\n");
			rc = 4;
		} else if (!active) {
			printf("@%llu result FAIL reason=not_active\n", (unsigned long long)(now - p.t0));
			rc = 6;
		}

		if (p.have_monmap || p.have_osdmap) {
			unsigned k;

			fsid_str(p.have_monmap ? p.mon_fsid : p.osd_fsid, id);
			printf("summary fsid=%s\n", id);
			if (p.have_monmap) {
				printf("summary monmap epoch=%u mons=%u\n", (unsigned)p.mm.epoch, (unsigned)p.mm.n_mons);
				for (k = 0; k < p.mm.n_mons && k < WRI_MON_MAXMONS; k++) {
					char as[96];

					addr_str(&p.mm.addr[k], as, sizeof(as));
					printf("summary mon rank=%u addr=%s\n", k, p.mm.rank_valid[k] ? as : "(no msgr2 address)");
				}
			}
			if (p.have_osdmap)
				printf("summary osdmap newest_epoch=%u oldest_epoch=%u front_bytes=%zu full_map_bytes=%zu "
				       "full_maps=%u incrementals=%u msg_version=%u\n",
				       (unsigned)p.oi.newest_map, (unsigned)p.oi.oldest_map, p.osd_front_len, p.osd_full_bytes,
				       (unsigned)p.oi.n_full, (unsigned)p.oi.n_incremental, (unsigned)p.osd_msg_version);
		}
		if (p.active_at != 0) {
			printf("summary tickets");
			print_ticket(c, "auth", WRI_CX_SLOT_AUTH, now);
			print_ticket(c, "osd", WRI_CX_SLOT_OSD, now);
			printf(" global_id=%llu\n", (unsigned long long)c->cx.global_id);
			printf("summary session up_events=%u kept_alive_ms=%llu keepalive_acks=%u messages_in=%u messages_dropped=%u "
			       "crc_failures=%u state=%s\n",
			       p.n_session_up, (unsigned long long)kept_ms,
			       (unsigned)ka_ack, (unsigned)msg_in, (unsigned)msg_dropped, p.n_crc_fail,
			       active ? "ACTIVE" : "NOT_ACTIVE");
			printf("summary pools conns_hiwater=%u mapmsg_hiwater=%u arena_used=%u bulk_used=%u\n",
			       (unsigned)stats.conns_hiwater, (unsigned)stats.mapmsg_hiwater, (unsigned)stats.arena_used,
			       (unsigned)stats.bulk_used);
			if (rc == 0 && duration_s >= 25 && ka_ack == 0) {
				printf("@%llu result FAIL reason=no_keepalive_ack\n", (unsigned long long)(now - p.t0));
				fprintf(stderr, "winrbd-probe: no keepalive was acknowledged during %d s\n", duration_s);
				rc = 6;
			}
		}
		if (rc == 0)
			printf("@%llu result OK\n", (unsigned long long)(now - p.t0));
	}
	fflush(stdout);
	wrl_loop_destroy(loop);
	wr_client_destroy(c);
	wrl_mem_free(&arena);
	wrl_mem_free(&bulk);
	return rc;
}
