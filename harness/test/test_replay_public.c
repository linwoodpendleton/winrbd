/* SPDX-License-Identifier: MIT */
/*
 * Replay of the public captures through the core: the real bytes a stock Ceph 20.2.5 client and monitor / OSD
 * exchanged (harness/vectors/public/pcap, extracted by harness/tools/pcap2stream.py) are fed to the core's
 * own decoders and to the cephx client machine, with the public throw-away keys (public/keys).
 *
 * What is checked, for every crc-mode monitor and OSD connection of the k1-* (aes) and k2-* (aes256k) sessions:
 *
 *   - the frames are parsed by the receive parser of the core (CRCs verified); control frames are decoded;
 *   - the cephx client machine is driven with the captured server payloads and its random draws scripted to the
 *     captured client challenge / nonce: its AUTH_REQUEST and AUTHENTICATE (monitor) or its two authorizers (OSD,
 *     compared after decryption) equal the captured ones, AUTH_DONE is accepted, the tickets are stored;
 *   - the session key the machine derived signs the captured transcripts to the captured AUTH_SIGNATURE of BOTH
 *     peers (the server's signature covers every byte the client sent, ours every byte it received);
 *   - MMonMap and MOSDMap messages decode (fsid, epochs, the one monitor address), KEEPALIVE2 pairs echo the stamp;
 *   - in-session ticket renewal (k?-renew-ttl60): the MAuth the core builds has the captured shape and the captured
 *     MAuthReply is accepted and replaces the service tickets;
 *   - the wrong-key sessions: the core computes the captured (wrong) proof and AUTH_BAD_METHOD (-EACCES) decodes.
 *
 * Secure-mode connections (the "sec" and "def" sessions) are not covered here (they have their own parser test).
 * The test is skipped when python3 or the captures are not available.
 */
#define _POSIX_C_SOURCE 200809L /* mkdtemp, opendir, stat under -std=c99 */

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "auth_cx_srv.h"

#include "wri_m2_frame.h"
#include "wri_mon.h"

#define SEG0_CAP (64u * 1024u)
#define SEG_MAX (8u * 1024u * 1024u)
#define RING_CAP 4096u
#define MAX_CONNS 64u
#define MAX_MSGS 64u
#define MSG_FRONT_CAP (256u * 1024u)
#define MAX_KA 128u
#define PREAUTH_CAP (64u * 1024u)
#define MON_FSID "52762725-e19a-11f1-886d-525400770001"

static uint8_t *g_sink[3];
static uint8_t g_seg0[SEG0_CAP];
static uint64_t g_logged;
static uint32_t g_rng_state = 7;

static uint32_t rnd(void)
{
	g_rng_state ^= g_rng_state << 13;
	g_rng_state ^= g_rng_state >> 17;
	g_rng_state ^= g_rng_state << 5;
	return g_rng_state;
}

static void log_cb(void *log, const uint8_t *p, size_t n)
{
	(void)log;
	(void)p;
	g_logged += n;
}

/* ---- what one direction of one connection held ------------------------------------------------- */

typedef struct msg {
	uint16_t type, version, compat;
	uint8_t *front;
	size_t front_len;
} msg;

typedef struct dirinfo {
	const uint8_t *raw; /* the whole stream */
	size_t raw_len;
	unsigned frames;
	uint8_t *hello, *areq, *more, *done, *bad, *sigf; /* seg0 of the first frame of each tag */
	size_t hello_n, areq_n, more_n, done_n, bad_n, sigf_n;
	uint64_t sig_off; /* stream offset of the first AUTH_SIGNATURE frame; the transcript ends there */
	int have_sig;
	msg msgs[MAX_MSGS];
	unsigned nmsgs;
	uint32_t ka[MAX_KA][2]; /* KEEPALIVE2 / ACK stamps in order */
	unsigned nka;
	int parse_error;
} dirinfo;

typedef struct cconn {
	char session[96];
	int idx, port;
	dirinfo d[2]; /* [0] client to server, [1] server to client */
	uint8_t *c2s, *s2c;
	int peer; /* entity type of the server (HELLO) */
} cconn;

static uint8_t *dup_bytes(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n ? n : 1);

	if (q != NULL && n != 0)
		memcpy(q, p, n);
	return q;
}

static void keep_first(uint8_t **dst, size_t *dn, const uint8_t *p, size_t n)
{
	if (*dst == NULL) {
		*dst = dup_bytes(p, n);
		*dn = n;
	}
}

static void on_frame(dirinfo *di, const wri_m2_rx *rx, uint64_t start)
{
	unsigned tag = rx->desc.tag;
	size_t n0 = rx->stored[0];

	di->frames++;
	switch (tag) {
	case WRI_M2_TAG_HELLO:
		keep_first(&di->hello, &di->hello_n, g_seg0, n0);
		break;
	case WRI_M2_TAG_AUTH_REQUEST:
		keep_first(&di->areq, &di->areq_n, g_seg0, n0);
		break;
	case WRI_M2_TAG_AUTH_REPLY_MORE:
	case WRI_M2_TAG_AUTH_REQUEST_MORE:
		keep_first(&di->more, &di->more_n, g_seg0, n0);
		break;
	case WRI_M2_TAG_AUTH_DONE:
		keep_first(&di->done, &di->done_n, g_seg0, n0);
		break;
	case WRI_M2_TAG_AUTH_BAD_METHOD:
		keep_first(&di->bad, &di->bad_n, g_seg0, n0);
		break;
	case WRI_M2_TAG_AUTH_SIGNATURE:
		if (!di->have_sig) {
			di->have_sig = 1;
			di->sig_off = start;
			keep_first(&di->sigf, &di->sigf_n, g_seg0, n0);
		}
		break;
	case WRI_M2_TAG_KEEPALIVE2:
	case WRI_M2_TAG_KEEPALIVE2_ACK: {
		wri_rd r;
		uint32_t sec = 0, nsec = 0;

		wri_rd_init(&r, g_seg0, n0);
		WRT_CHECK_STATUS(WR_OK, wri_m2_keepalive_decode(&r, &sec, &nsec));
		if (di->nka < MAX_KA) {
			di->ka[di->nka][0] = sec;
			di->ka[di->nka][1] = nsec;
			di->nka++;
		}
		break;
	}
	case WRI_M2_TAG_MESSAGE: {
		wri_m2_hdr2 h;

		WRT_CHECK_STATUS(WR_OK, wri_m2_hdr2_decode(g_seg0, n0, &h));
		if (di->nmsgs < MAX_MSGS && rx->desc.nseg >= 2 && rx->stored[1] <= MSG_FRONT_CAP) {
			msg *m = &di->msgs[di->nmsgs++];

			m->type = h.type;
			m->version = h.version;
			m->compat = h.compat_version;
			m->front_len = rx->stored[1];
			m->front = dup_bytes(g_sink[0], m->front_len);
		}
		break;
	}
	default:
		break;
	}
}

/* Run one stream through the core's receive parser (random pieces), collecting what on_frame wants. */
static void parse_stream(dirinfo *di, const uint8_t *data, size_t len)
{
	wri_m2_rx rx;
	wri_ring ring;
	static uint8_t ringbuf[RING_CAP];
	size_t pos = 0, guard = 0;
	unsigned i;
	int stop = 0;

	di->raw = data;
	di->raw_len = len;
	g_logged = 0;
	wri_ring_init(&ring, ringbuf, sizeof(ringbuf));
	wri_m2_rx_init(&rx, g_seg0, sizeof(g_seg0), SEG_MAX);
	while (!stop && guard++ < 4 * len + 100) {
		uint8_t *w = NULL;
		size_t room = wri_m2_rx_window(&rx, &ring, &w);

		if (room != 0 && pos < len) {
			size_t k = 1 + rnd() % 3000;

			k = k < room ? k : room;
			k = k < len - pos ? k : len - pos;
			memcpy(w, data + pos, k);
			wri_m2_rx_commit(&rx, &ring, k);
			pos += k;
		}
		for (;;) {
			wri_m2_rx_ev ev = wri_m2_rx_step(&rx, &ring, NULL, NULL, log_cb, NULL);

			if (ev == WRI_RXE_NONE)
				break;
			if (ev == WRI_RXE_SEG0) {
				for (i = 1; i < rx.desc.nseg; i++)
					wri_m2_rx_sink(&rx, i, g_sink[i - 1], SEG_MAX);
			} else if (ev == WRI_RXE_FRAME) {
				uint64_t wire = 32 + wri_m2_frame_body_len(&rx.desc);

				on_frame(di, &rx, g_logged - wire);
				wri_m2_rx_next_frame(&rx);
			} else if (ev == WRI_RXE_BANNER) {
				continue;
			} else {
				di->parse_error = 1;
				stop = 1;
				break;
			}
		}
		if (pos >= len && ring.len == 0 && rx.direct == 0)
			stop = 1;
	}
	WRT_CHECK(!di->parse_error);
	WRT_CHECK_U64(g_logged, len); /* every byte consumed, to the last frame */
}

static void free_conn(cconn *cc)
{
	unsigned d, i;

	for (d = 0; d < 2; d++) {
		dirinfo *di = &cc->d[d];

		free(di->hello);
		free(di->areq);
		free(di->more);
		free(di->done);
		free(di->bad);
		free(di->sigf);
		for (i = 0; i < di->nmsgs; i++)
			free(di->msgs[i].front);
	}
	free(cc->c2s);
	free(cc->s2c);
	memset(cc, 0, sizeof(*cc));
}

/* ---- small helpers ---------------------------------------------------------------------------------- */

static int is_dir(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

static int is_file(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

static void remove_tree_flat(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	char p[512];

	if (d == NULL)
		return;
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
		(void)unlink(p);
	}
	closedir(d);
	(void)rmdir(dir);
}

/* A blob (u32 length + bytes) filling a whole segment 0: returns the bytes. */
static int blob_of(const uint8_t *seg, size_t n, const uint8_t **p, size_t *len)
{
	wri_rd r;
	uint32_t l;
	const uint8_t *b;

	wri_rd_init(&r, seg, n);
	l = wri_rd_u32(&r);
	b = wri_rd_bytes(&r, l);
	if (!wri_rd_ok(&r) || wri_rd_left(&r) != 0)
		return -1;
	*p = b;
	*len = l;
	return 0;
}

/* AUTH_REQUEST: method u32, modes vec<u32>, payload blob. */
static int areq_payload(const uint8_t *seg, size_t n, const uint8_t **p, size_t *len)
{
	wri_rd r;
	uint32_t nm, l;

	wri_rd_init(&r, seg, n);
	(void)wri_rd_u32(&r);
	nm = wri_rd_u32(&r);
	if (nm > 16u)
		return -1;
	wri_rd_skip(&r, (size_t)nm * 4u);
	l = wri_rd_u32(&r);
	*p = wri_rd_bytes(&r, l);
	*len = l;
	return wri_rd_ok(&r) && wri_rd_left(&r) == 0 ? 0 : -1;
}

typedef struct counters {
	unsigned sessions, mon_ok, osd_ok, osd_skipped, wrong_ok, sigs, monmaps, osdmaps, renewals, keepalives;
} counters;

/* ---- the transcripts and the two AUTH_SIGNATUREs --------------------------------------------------- */

static void check_signatures(const cconn *cc, const uint8_t *key, size_t klen, counters *cnt)
{
	static uint8_t rxb[PREAUTH_CAP], txb[PREAUTH_CAP];
	wri_m2_preauth pa;
	uint8_t sig[32], ours[32];
	wri_rd r;
	const dirinfo *c = &cc->d[0], *s = &cc->d[1];

	WRT_CHECK(c->have_sig && s->have_sig && key != NULL && klen != 0);
	if (!(c->have_sig && s->have_sig && key != NULL && klen != 0))
		return;
	WRT_CHECK(c->sig_off <= PREAUTH_CAP && s->sig_off <= PREAUTH_CAP);
	wri_m2_preauth_init(&pa, rxb, txb, PREAUTH_CAP);
	/* "received" = what the client got = the server's stream before its signature; "sent" = the client stream */
	wri_m2_preauth_rx(&pa, s->raw, (size_t)s->sig_off);
	wri_m2_preauth_tx(&pa, c->raw, (size_t)c->sig_off);
	wri_m2_preauth_stop(&pa);
	WRT_CHECK_STATUS(WR_OK, pa.err);
	/* the server's signature (HMAC over every byte the client sent) */
	wri_rd_init(&r, s->sigf, s->sigf_n);
	WRT_CHECK_STATUS(WR_OK, wri_m2_auth_sig_decode(&r, sig));
	WRT_CHECK_STATUS(WR_OK, wri_m2_sig_verify(NULL, &pa, key, klen, sig));
	/* ours (HMAC over every byte the client received) equals the client's captured one */
	wri_m2_sig_ours(NULL, &pa, key, klen, ours);
	wri_rd_init(&r, c->sigf, c->sigf_n);
	WRT_CHECK_STATUS(WR_OK, wri_m2_auth_sig_decode(&r, sig));
	WRT_CHECK_MEM(ours, sig, 32);
	wri_m2_preauth_wipe(&pa);
	cnt->sigs += 2;
}

/* ---- messages ------------------------------------------------------------------------------------------ */

static void check_messages(const cconn *cc, const char *session, uint32_t want_epoch, counters *cnt)
{
	unsigned i;
	const dirinfo *s = &cc->d[1], *c = &cc->d[0];

	for (i = 0; i < s->nmsgs; i++) {
		const msg *m = &s->msgs[i];

		if (m->type == WRI_MSG_MON_MAP) {
			const uint8_t *blob;
			size_t bl;
			wri_monmap mm;
			char id[37];
			unsigned k, p = 0;

			WRT_CHECK_STATUS(WR_OK, wri_mmonmap_front(m->front, m->front_len, &blob, &bl));
			WRT_CHECK_STATUS(WR_OK, wri_monmap_decode(blob, bl, &mm));
			for (k = 0; k < 16; k++) {
				static const char h[] = "0123456789abcdef";

				if (k == 4 || k == 6 || k == 8 || k == 10)
					id[p++] = '-';
				id[p++] = h[mm.fsid[k] >> 4];
				id[p++] = h[mm.fsid[k] & 15u];
			}
			id[p] = '\0';
			if (strcmp(id, MON_FSID) != 0)
				fprintf(stderr, "%s: monmap fsid %s\n", session, id);
			WRT_CHECK(strcmp(id, MON_FSID) == 0);
			WRT_CHECK_U64(mm.epoch, 3);
			WRT_CHECK_U64(mm.n_mons, 1);
			WRT_CHECK(mm.rank_valid[0] && mm.addr[0].family == WR_AF_IPV4 && mm.addr[0].port == 3300);
			WRT_CHECK(m->compat <= WRI_MMONMAP_MAX_VERSION);
			cnt->monmaps++;
		} else if (m->type == WRI_MSG_OSD_MAP) {
			wri_mosdmap_info info;

			WRT_CHECK(m->compat <= WRI_MOSDMAP_MAX_VERSION);
			WRT_CHECK_STATUS(WR_OK, wri_mosdmap_info_decode(m->front, m->front_len, m->version, &info));
			WRT_CHECK_U64(info.newest_map, want_epoch);
			WRT_CHECK(info.oldest_map >= 1 && info.oldest_map <= info.newest_map);
			if (info.n_full != 0)
				WRT_CHECK_U64(info.last_epoch, want_epoch);
			WRT_CHECK(m->front_len >= 16 && info.n_full + info.n_incremental >= 1);
			cnt->osdmaps++;
		}
	}
	/* KEEPALIVE2 / ACK: one answer per ping, echoing the stamp */
	WRT_CHECK_U64(s->nka, c->nka);
	for (i = 0; i < s->nka && i < c->nka; i++) {
		WRT_CHECK_U64(s->ka[i][0], c->ka[i][0]);
		WRT_CHECK_U64(s->ka[i][1], c->ka[i][1]);
	}
	cnt->keepalives += s->nka;
}

/* ---- the cephx handshakes --------------------------------------------------------------------------- */

/* Every OSD ticket a monitor connection held over its life (the first one and one per renewal): an OSD connection
 * opened after a renewal authenticates with a renewed ticket. */
#define TK_HIST 8u
#define TK_BLOB_MAX 4096u

typedef struct tk_copy {
	uint8_t blob[TK_BLOB_MAX];
	uint32_t blob_len;
	uint64_t secret_id, valid_until_ms;
	wr_key key;
} tk_copy;

typedef struct menv {
	cxt_env e;
	uint64_t gid;
	int live;
	tk_copy hist[TK_HIST];
	unsigned nhist;
} menv;

static void hist_push(menv *me)
{
	const wri_cx_ticket *t = &me->e.c.ticket[WRI_CX_SLOT_OSD];

	if (!t->have || t->blob_len > TK_BLOB_MAX || me->nhist >= TK_HIST)
		return;
	memcpy(me->hist[me->nhist].blob, t->blob, t->blob_len);
	me->hist[me->nhist].blob_len = t->blob_len;
	me->hist[me->nhist].secret_id = t->secret_id;
	me->hist[me->nhist].valid_until_ms = t->valid_until_ms;
	me->hist[me->nhist].key = t->session_key;
	me->nhist++;
}

/* Make history entry h the held OSD ticket again. */
static void hist_restore(menv *me, unsigned h)
{
	wri_cx_ticket *t = &me->e.c.ticket[WRI_CX_SLOT_OSD];
	const tk_copy *k = &me->hist[h];

	memcpy(t->blob, k->blob, k->blob_len);
	t->blob_len = k->blob_len;
	t->secret_id = k->secret_id;
	t->valid_until_ms = k->valid_until_ms;
	t->session_key = k->key;
	t->have = 1;
	t->gen++;
}

static uint32_t cap_mask_of(const uint8_t *auth, size_t n)
{
	return n >= 4 ? wri_le32_get(auth + n - 4) : 0;
}

static void check_renewals(const cconn *cc, menv *me, counters *cnt)
{
	const dirinfo *c = &cc->d[0], *s = &cc->d[1];
	unsigned i, nreq = 0, nrep = 0;
	const msg *rq[MAX_MSGS], *rp[MAX_MSGS];

	for (i = 0; i < c->nmsgs; i++)
		if (c->msgs[i].type == WRI_MSG_AUTH)
			rq[nreq++] = &c->msgs[i];
	for (i = 0; i < s->nmsgs; i++)
		if (s->msgs[i].type == 18u) /* CEPH_MSG_AUTH_REPLY */
			rp[nrep++] = &s->msgs[i];
	WRT_CHECK_U64(nrep, nreq);
	for (i = 0; i < nreq && i < nrep; i++) {
		wri_rd r;
		uint32_t proto, plen;
		const uint8_t *pay;
		wri_mauth_reply rep;
		uint8_t out[4096];
		wri_wr w;
		size_t ti, pre;
		uint32_t gen_before = me->e.c.ticket[WRI_CX_SLOT_OSD].gen;
		uint32_t tlen, alen;

		/* the captured MAuth: PaxosServiceMessage prefix (18) | protocol | payload blob | monmap epoch */
		wri_rd_init(&r, rq[i]->front, rq[i]->front_len);
		wri_rd_skip(&r, 18);
		proto = wri_rd_u32(&r);
		plen = wri_rd_u32(&r);
		pay = wri_rd_bytes(&r, plen);
		WRT_CHECK(wri_rd_ok(&r) && proto == 2u /* CEPH_AUTH_CEPHX */);
		if (!wri_rd_ok(&r))
			return;
		/* shape: u16 0x0200 | u8 1 | u64 gid | u32 service | ticket (v, id, len, data) | u32 n | sealed | u8 1 | u32 mask */
		wri_rd_init(&r, pay, plen);
		WRT_CHECK_U64(wri_rd_u16(&r), 0x0200);
		(void)wri_rd_u8(&r);
		WRT_CHECK_U64(wri_rd_u64(&r), me->gid);
		WRT_CHECK_U64(wri_rd_u32(&r), WRI_CX_SERVICE_AUTH);
		(void)wri_rd_u8(&r);
		(void)wri_rd_u64(&r);
		tlen = wri_rd_u32(&r);
		wri_rd_skip(&r, tlen);
		pre = plen - wri_rd_left(&r); /* bytes up to the proof length */
		alen = wri_rd_u32(&r);
		WRT_CHECK(wri_rd_ok(&r) && alen < plen);

		wri_wr_init(&w, out, sizeof(out));
		WRT_CHECK_STATUS(WR_OK, wri_cx_renew_build(&me->e.c, cap_mask_of(pay, plen), &w));
		WRT_CHECK_U64(wri_wr_len(&w), plen);
		if (wri_wr_len(&w) == plen && pre <= plen) {
			/* everything but the sealed proof (fresh nonce and confounder) is the captured bytes: the held
			 * AUTH ticket goes out unchanged, the request mask is the captured one */
			WRT_CHECK_MEM(out, pay, pre);
			WRT_CHECK_MEM(out + plen - 5, pay + plen - 5, 5);
			ti = plen - 5 - alen;
			WRT_CHECK_U64(wri_le32_get(out + ti - 4), alen);
		}
		WRT_CHECK_STATUS(WR_OK, wri_mauth_reply_decode(rp[i]->front, rp[i]->front_len, &rep));
		WRT_CHECK_U64(rep.result, 0);
		WRT_CHECK_STATUS(WR_OK, wri_cx_renew_handle(&me->e.c, rep.payload, rep.payload_len));
		WRT_CHECK(me->e.c.ticket[WRI_CX_SLOT_OSD].gen != gen_before && me->e.c.ticket[WRI_CX_SLOT_OSD].have);
		hist_push(me);
		cnt->renewals++;
	}
}

static void replay_mon(const cconn *cc, const wr_key *key, const char *user, int wrong, menv *me, uint32_t want_epoch,
		       counters *cnt)
{
	const dirinfo *c = &cc->d[0], *s = &cc->d[1];
	/* initialised: a failed WRT_CHECK does not stop the test, and gcc -O3 cannot know the helpers set them */
	const uint8_t *areq = NULL, *more_c = NULL, *more_s = NULL, *want_more;
	size_t areq_n = 0, more_cn = 0, more_sn = 0;
	uint8_t out[1024];
	wri_wr w;
	const wri_auth_ops *ops = wri_cx_ops();
	uint64_t chal;

	WRT_CHECK(c->areq && c->more && s->more && c->hello && s->hello);
	if (!(c->areq && c->more && s->more))
		return;
	WRT_CHECK(areq_payload(c->areq, c->areq_n, &areq, &areq_n) == 0);
	WRT_CHECK(blob_of(c->more, c->more_n, &more_c, &more_cn) == 0);
	WRT_CHECK(blob_of(s->more, s->more_n, &more_s, &more_sn) == 0);
	WRT_CHECK(more_cn >= 3 + 16 + 5 + 4);
	if (more_cn < 3 + 16 + 5 + 4)
		return;
	chal = wri_le64_get(more_c + 3); /* AUTHENTICATE: u16 type, u8 v, u64 client challenge, u64 proof, ticket, mask */

	WRT_CHECK(cxt_env_init(&me->e, user, key, 0) == 0);
	me->live = 1;
	cxt_rng_free();
	cxt_rng_push_u64(chal);
	me->e.c.want_mask = cap_mask_of(more_c, more_cn);

	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, ops->begin(&me->e.c, WRI_ENTITY_MON, &w));
	WRT_CHECK_U64(wri_wr_len(&w), areq_n);
	if (wri_wr_len(&w) == areq_n)
		WRT_CHECK_MEM(out, areq, areq_n);

	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, ops->more(&me->e.c, more_s, more_sn, &w));
	want_more = more_c;
	WRT_CHECK_U64(wri_wr_len(&w), more_cn);
	if (wri_wr_len(&w) == more_cn)
		WRT_CHECK_MEM(out, want_more, more_cn); /* the proof included: byte for byte the stock client's */
	WRT_CHECK(g_rng.bad == 0 && g_rng.i == g_rng.n);
	cxt_rng_free();

	if (wrong) {
		wri_rd r;
		wri_m2_bad_method bm;

		WRT_CHECK(s->bad != NULL && s->done == NULL);
		if (s->bad == NULL)
			return;
		wri_rd_init(&r, s->bad, s->bad_n);
		WRT_CHECK_STATUS(WR_OK, wri_m2_bad_method_decode(&r, &bm));
		WRT_CHECK_U64((uint32_t)bm.result, (uint32_t)-13); /* -EACCES */
		WRT_CHECK(bm.n_methods == 1 && bm.allowed_methods[0] == 2u);
		cnt->wrong_ok++;
		return;
	}

	{
		wri_rd r;
		wri_m2_auth_done ad;
		const uint8_t *k = NULL;
		size_t kn = 0;

		WRT_CHECK(s->done != NULL);
		if (s->done == NULL)
			return;
		wri_rd_init(&r, s->done, s->done_n);
		WRT_CHECK_STATUS(WR_OK, wri_m2_auth_done_decode(&r, &ad));
		WRT_CHECK_U64(ad.mode, WRI_CONN_MODE_CRC);
		WRT_CHECK_STATUS(WR_OK, ops->done(&me->e.c, ad.global_id, ad.mode, ad.payload, ad.payload_len));
		WRT_CHECK(me->e.c.st == WRI_CX_DONE);
		WRT_CHECK_U64(me->e.c.global_id, ad.global_id);
		me->gid = ad.global_id;
		hist_push(me);
		WRT_CHECK(wri_cx_have(&me->e.c, WRI_CX_SERVICE_AUTH, me->e.x.now.mono_ms));
		if (me->e.c.want_mask & WRI_CX_SERVICE_OSD) /* the ceph CLI asks for no OSD ticket */
			WRT_CHECK(wri_cx_have(&me->e.c, WRI_CX_SERVICE_OSD, me->e.x.now.mono_ms));
		ops->session_key(&me->e.c, &k, &kn);
		check_signatures(cc, k, kn, cnt);
		cnt->mon_ok++;
	}
	check_messages(cc, cc->session, want_epoch, cnt);
	check_renewals(cc, me, cnt);
}

/* Decrypt the item of an authorizer-shaped sealed blob (usage 0x10 / 0x11 / 0x12) with the ticket's session key. */
static int open_item(const cxt_env *e, const wr_key *k, uint32_t usage, const uint8_t *ct, size_t n, uint8_t *item, size_t cap,
		     size_t *il)
{
	uint8_t scratch[512];
	const uint8_t *it = NULL;
	size_t l = 0;

	if (n > sizeof(scratch))
		return -1;
	if (wri_cx_open(&e->x, k, usage, ct, n, scratch, sizeof(scratch), &it, &l) != WR_OK || l > cap)
		return -1;
	memcpy(item, it, l);
	*il = l;
	return 0;
}

/* An authorizer payload: u8 1 | u64 gid | u32 service | ticket (u8 v, u64 id, u32 len, data) | u32 n | sealed.
 * Returns the offset of the sealed proof and its length; secret_id of the ticket. */
static int authorizer_parts(const uint8_t *p, size_t n, uint64_t *gid, uint64_t *secret_id, size_t *sealed_off, size_t *sealed_len)
{
	wri_rd r;
	uint32_t tl, sl;

	wri_rd_init(&r, p, n);
	(void)wri_rd_u8(&r);
	*gid = wri_rd_u64(&r);
	(void)wri_rd_u32(&r);
	(void)wri_rd_u8(&r);
	*secret_id = wri_rd_u64(&r);
	tl = wri_rd_u32(&r);
	wri_rd_skip(&r, tl);
	sl = wri_rd_u32(&r);
	*sealed_off = n - wri_rd_left(&r);
	wri_rd_skip(&r, sl);
	*sealed_len = sl;
	return wri_rd_ok(&r) && wri_rd_left(&r) == 0 ? 0 : -1;
}

static void replay_osd(const cconn *cc, menv *envs, unsigned nenv, counters *cnt)
{
	const dirinfo *c = &cc->d[0], *s = &cc->d[1];
	const uint8_t *a1 = NULL, *a2 = NULL, *chal = NULL; /* initialised, see replay_mon */
	size_t a1n = 0, a2n = 0, chn = 0, off1 = 0, sl1 = 0, off2 = 0, sl2 = 0, i;
	uint64_t gid = 0, id1 = 0, gid2 = 0, id2 = 0;
	menv *me = NULL;
	wri_rd r;
	wri_m2_auth_done ad;
	const wri_auth_ops *ops = wri_cx_ops();
	uint8_t out[1024], want_item[64], got_item[64], nonce_item[64];
	size_t wl = 0, gl = 0, nl = 0;
	wri_wr w;
	const wri_cx_ticket *t;
	const uint8_t *k = NULL;
	size_t kn = 0;

	WRT_CHECK(c->areq && c->more && s->more && s->done);
	if (!(c->areq && c->more && s->more && s->done))
		return;
	WRT_CHECK(areq_payload(c->areq, c->areq_n, &a1, &a1n) == 0);
	WRT_CHECK(blob_of(c->more, c->more_n, &a2, &a2n) == 0);
	WRT_CHECK(blob_of(s->more, s->more_n, &chal, &chn) == 0);
	WRT_CHECK(authorizer_parts(a1, a1n, &gid, &id1, &off1, &sl1) == 0);
	WRT_CHECK(authorizer_parts(a2, a2n, &gid2, &id2, &off2, &sl2) == 0);
	WRT_CHECK(gid == gid2 && id1 == id2);
	/* the monitor connection that issued this connection's ticket: same global id and the very same ticket bytes
	 * (the authorizer carries the ticket blob as received; secret_id alone only names the rotating key) */
	for (i = 0; i < nenv && me == NULL; i++) {
		unsigned h;

		if (!envs[i].live || envs[i].gid != gid)
			continue;
		for (h = 0; h < envs[i].nhist; h++)
			if (envs[i].hist[h].blob_len <= a1n - 13 && memcmp(a1 + 13, envs[i].hist[h].blob, envs[i].hist[h].blob_len) == 0) {
				me = &envs[i];
				hist_restore(me, h);
				break;
			}
	}
	if (me == NULL) {
		cnt->osd_skipped++;
		fprintf(stderr, "note: %s conn %d: no held ticket matches its authorizer\n", cc->session, cc->idx);
		return;
	}
	t = &me->e.c.ticket[WRI_CX_SLOT_OSD];
	/* the nonce the stock client drew is inside its first authorizer: take it out with the ticket's session key */
	WRT_CHECK(open_item(&me->e, &t->session_key, WRI_CX_USAGE_AUTHORIZE, a1 + off1, sl1, nonce_item, sizeof(nonce_item), &nl) == 0);
	WRT_CHECK(nl >= 9 + 1);
	if (nl < 10)
		return;
	cxt_rng_free();
	cxt_rng_push(nonce_item + 1, 8); /* v 2 | nonce | ... */
	if (t->session_key.type == WR_KEY_TYPE_AES256K) { /* the two confounders (any bytes: only the plaintext is compared) */
		uint8_t conf[16];

		memset(conf, 0x5a, sizeof(conf));
		cxt_rng_push(conf, 16);
		cxt_rng_push(conf, 16);
	}
	me->e.c.st = WRI_CX_IDLE;

	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, ops->begin(&me->e.c, WRI_ENTITY_OSD, &w));
	WRT_CHECK_U64(wri_wr_len(&w), a1n);
	if (wri_wr_len(&w) == a1n) {
		WRT_CHECK_MEM(out, a1, off1); /* v, global id, service, the ticket as held */
		WRT_CHECK(open_item(&me->e, &t->session_key, WRI_CX_USAGE_AUTHORIZE, out + off1, sl1, got_item, sizeof(got_item), &gl) == 0);
		WRT_CHECK(gl == nl && memcmp(got_item, nonce_item, nl) == 0);
	}
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, ops->more(&me->e.c, chal, chn, &w));
	WRT_CHECK_U64(wri_wr_len(&w), a2n);
	if (wri_wr_len(&w) == a2n) {
		WRT_CHECK_MEM(out, a2, off2);
		WRT_CHECK(open_item(&me->e, &t->session_key, WRI_CX_USAGE_AUTHORIZE, a2 + off2, sl2, want_item, sizeof(want_item), &wl) == 0);
		WRT_CHECK(open_item(&me->e, &t->session_key, WRI_CX_USAGE_AUTHORIZE, out + off2, sl2, got_item, sizeof(got_item), &gl) == 0);
		WRT_CHECK(wl >= 18 && gl == wl && memcmp(got_item, want_item, wl) == 0); /* nonce, have_challenge, challenge + 1 */
	}
	WRT_CHECK(g_rng.bad == 0 && g_rng.i == g_rng.n);
	cxt_rng_free();

	wri_rd_init(&r, s->done, s->done_n);
	WRT_CHECK_STATUS(WR_OK, wri_m2_auth_done_decode(&r, &ad));
	WRT_CHECK_U64(ad.mode, WRI_CONN_MODE_CRC);
	WRT_CHECK_STATUS(WR_OK, ops->done(&me->e.c, ad.global_id, ad.mode, ad.payload, ad.payload_len));
	WRT_CHECK(me->e.c.st == WRI_CX_DONE);
	ops->session_key(&me->e.c, &k, &kn);
	check_signatures(cc, k, kn, cnt);
	check_messages(cc, cc->session, 0, cnt);
	cnt->osd_ok++;
}

/* ---- driver ------------------------------------------------------------------------------------------------ */

typedef struct idx_row {
	char session[96], dir[8], file[512];
	int conn, port;
	unsigned long size;
} idx_row;

static int load_key(const char *name, wr_key *key, char *user, size_t usz)
{
	char rel[128];
	uint8_t *buf = NULL;
	size_t n = 0;
	int rc = -1;
	const char *ent;

	snprintf(rel, sizeof(rel), "public/keys/%s.keyring", name);
	if (wrt_read_file(wrt_vec_path(rel), &buf, &n) != 0)
		return -1;
	if (wr_key_parse_keyring(key, (const char *)buf, n) == WR_OK) {
		ent = strstr(name, "vec-");
		if (ent != NULL && strlen(ent) < usz) {
			strcpy(user, ent);
			rc = 0;
		}
	}
	memset(buf, 0, n);
	free(buf);
	return rc;
}

static uint32_t epoch_of(const char *session)
{
	uint8_t *buf = NULL;
	size_t n = 0, off = 0;
	uint32_t ep = 0;

	if (wrt_read_file(wrt_vec_path("public/epochs.tsv"), &buf, &n) != 0)
		return 0;
	while (off < n) {
		char line[256], name[96];
		unsigned long a, b;
		size_t k = 0;

		while (off < n && buf[off] != '\n' && k < sizeof(line) - 1)
			line[k++] = (char)buf[off++];
		while (off < n && buf[off] != '\n')
			off++;
		off++;
		line[k] = '\0';
		if (sscanf(line, "%95s %lu %lu", name, &a, &b) == 3 && strcmp(name, session) == 0)
			ep = (uint32_t)b;
	}
	free(buf);
	return ep;
}

static void do_session(const idx_row *rows, size_t nrows, const char *session, counters *cnt)
{
	cconn *conns = (cconn *)calloc(MAX_CONNS, sizeof(cconn));
	menv *envs = (menv *)calloc(MAX_CONNS, sizeof(menv));
	size_t i, nconn = 0;
	unsigned c;
	wr_key key;
	char user[32];
	int wrong = strstr(session, "wrongkey") != NULL;
	uint32_t want_epoch = epoch_of(session);
	char keyname[64];

	WRT_CHECK(conns != NULL && envs != NULL);
	if (conns == NULL || envs == NULL) {
		free(conns);
		free(envs);
		return;
	}
	snprintf(keyname, sizeof(keyname), "%s.vec-%.2s", wrong ? "wrong" : "client", session);
	WRT_CHECK(load_key(keyname, &key, user, sizeof(user)) == 0);
	WRT_CHECK(want_epoch != 0);

	for (i = 0; i < nrows; i++) {
		const idx_row *rw = &rows[i];
		cconn *cc = NULL;
		uint8_t *data = NULL;
		size_t dlen = 0;
		unsigned d;
		char path[900];

		if (strcmp(rw->session, session) != 0)
			continue;
		for (c = 0; c < nconn; c++)
			if (conns[c].idx == rw->conn)
				cc = &conns[c];
		if (cc == NULL) {
			if (nconn >= MAX_CONNS)
				continue;
			cc = &conns[nconn++];
			snprintf(cc->session, sizeof(cc->session), "%s", rw->session);
			cc->idx = rw->conn;
			cc->port = rw->port;
		}
		d = strcmp(rw->dir, "c2s") == 0 ? 0u : 1u;
		snprintf(path, sizeof(path), "%s", rw->file); /* absolute path built by the caller */
		if (wrt_read_file(path, &data, &dlen) != 0) {
			WRT_CHECK(0 && "cannot read a stream");
			continue;
		}
		if (d == 0)
			cc->c2s = data;
		else
			cc->s2c = data;
		parse_stream(&cc->d[d], data, dlen);
	}
	for (c = 0; c < nconn; c++) {
		cconn *cc = &conns[c];

		if (cc->d[1].hello != NULL) {
			wri_rd r;
			wri_m2_hello h;

			wri_rd_init(&r, cc->d[1].hello, cc->d[1].hello_n);
			if (wri_m2_hello_decode(&r, &h) == WR_OK)
				cc->peer = h.entity_type;
		}
	}
	/* monitors first (they hold the tickets), then the OSD connections that use them */
	for (c = 0; c < nconn; c++)
		if (conns[c].peer == (int)WRI_ENTITY_MON && conns[c].port == 3300)
			replay_mon(&conns[c], &key, user, wrong, &envs[c], want_epoch, cnt);
	for (c = 0; c < nconn; c++)
		if (conns[c].peer == (int)WRI_ENTITY_OSD)
			replay_osd(&conns[c], envs, (unsigned)nconn, cnt);
	cnt->sessions++;
	for (c = 0; c < nconn; c++) {
		if (envs[c].live)
			cxt_env_free(&envs[c].e);
		free_conn(&conns[c]);
	}
	wr_key_wipe(&key);
	free(conns);
	free(envs);
}

int main(void)
{
	char pcapdir[512], tool[512], cmd[1400], outdir[] = "/tmp/wrt_replay_pub_XXXXXX", idx[600], line[512];
	FILE *fi;
	idx_row *rows;
	size_t nrows = 0, i, j;
	counters cnt;
	unsigned k;

	snprintf(pcapdir, sizeof(pcapdir), "%s", wrt_vec_path("public/pcap"));
	snprintf(tool, sizeof(tool), "%s", wrt_vec_path("../tools/pcap2stream.py"));
	if (!is_dir(pcapdir) || !is_file(tool))
		WRT_SKIP("public captures or pcap2stream.py not found");
	if (system("python3 -c 'import sys' >/dev/null 2>&1") != 0)
		WRT_SKIP("python3 not available");
	if (mkdtemp(outdir) == NULL)
		WRT_SKIP("cannot create a temporary directory");
	snprintf(cmd, sizeof(cmd), "PYTHONDONTWRITEBYTECODE=1 python3 -I '%s' '%s' '%s'", tool, outdir, pcapdir);
	if (system(cmd) != 0) {
		remove_tree_flat(outdir);
		WRT_CHECK(0 && "pcap2stream.py failed");
		return wrt_finish();
	}
	for (k = 0; k < 3; k++)
		g_sink[k] = (uint8_t *)malloc(SEG_MAX);
	rows = (idx_row *)calloc(4096, sizeof(idx_row));
	snprintf(idx, sizeof(idx), "%s/index.tsv", outdir);
	fi = fopen(idx, "r");
	if (fi == NULL || rows == NULL) {
		remove_tree_flat(outdir);
		WRT_CHECK(0 && "no index.tsv");
		return wrt_finish();
	}
	while (fgets(line, sizeof(line), fi) && nrows < 4096) {
		idx_row *rw = &rows[nrows];
		char file[256];
		long gap;

		if (sscanf(line, "%95[^\t]\t%d\t%7s\t%d\t%lu\t%ld\t%255s", rw->session, &rw->conn, rw->dir, &rw->port, &rw->size, &gap,
			   file) != 7)
			continue;
		WRT_CHECK(gap == -1);
		snprintf(rw->file, sizeof(rw->file), "%s/%s", outdir, file);
		nrows++;
	}
	fclose(fi);

	memset(&cnt, 0, sizeof(cnt));
	for (i = 0; i < nrows; i++) {
		int seen = 0;

		for (j = 0; j < i; j++)
			if (strcmp(rows[j].session, rows[i].session) == 0)
				seen = 1;
		if (seen)
			continue;
		/* the crc-mode sessions of the two throw-away users; the secure and default-mode ones are not covered here */
		if (strncmp(rows[i].session, "k1-", 3) != 0 && strncmp(rows[i].session, "k2-", 3) != 0)
			continue;
		if (strstr(rows[i].session, "-sec-") != NULL || strstr(rows[i].session, "-def-") != NULL)
			continue;
		do_session(rows, nrows, rows[i].session, &cnt);
	}
	free(rows);
	remove_tree_flat(outdir);
	for (k = 0; k < 3; k++)
		free(g_sink[k]);

	/* 9 crc-mode sessions per key type (the wrong-key one included), see sessions.tsv */
	WRT_CHECK(cnt.sessions == 18);
	WRT_CHECK(cnt.mon_ok >= 20);
	WRT_CHECK(cnt.osd_ok >= 20);
	WRT_CHECK(cnt.wrong_ok == 2);
	WRT_CHECK(cnt.osd_skipped == 0);
	WRT_CHECK(cnt.renewals >= 2);
	WRT_CHECK(cnt.monmaps >= 20 && cnt.osdmaps >= 20);
	WRT_CHECK(cnt.sigs == 2u * (cnt.mon_ok + cnt.osd_ok));
	printf("replayed %u sessions: %u monitor and %u OSD handshakes (%u OSD skipped: ticket not held), %u signatures "
	       "verified, %u wrong-key sessions, %u renewals, %u MonMap, %u MOSDMap, %u keepalive answers\n",
	       cnt.sessions, cnt.mon_ok, cnt.osd_ok, cnt.osd_skipped, cnt.sigs, cnt.wrong_ok, cnt.renewals, cnt.monmaps, cnt.osdmaps,
	       cnt.keepalives);
	return wrt_finish();
}
