/* SPDX-License-Identifier: MIT */
/*
 * Capture replay of the msgr2 control-payload codecs (core/src/msgr2/wri_m2_ctl.c, wri_m2_hdr2.c,
 * wri_m2_preauth.c) against the public captures in vectors/public/pcap.
 *
 * harness/tools/pcap2stream.py extracts the TCP payload streams of every connection; each stream is
 * parsed with the msgr2 receive parser, and every control frame in crc framing goes through the
 * decoder of its tag:
 *
 *   - decode succeeds, consumes exactly segment 0, and encoding the decoded fields reproduces the
 *     captured bytes (HELLO, AUTH_REQUEST, AUTH_BAD_METHOD, AUTH_REPLY_MORE, AUTH_REQUEST_MORE,
 *     AUTH_DONE, AUTH_SIGNATURE, CLIENT_IDENT, SERVER_IDENT, KEEPALIVE2 / _ACK, ACK);
 *   - MESSAGE frames: the 41-byte header2 decodes, re-encodes to the captured bytes, flags are
 *     COMPLETE | NOCRC, data_pre_padding_len and data_off are 0, and seq counts 1, 2, 3, ... per
 *     direction (msgr2.md 2.9, MSG-1 to MSG-3);
 *   - the pre-auth log fed through the parser's log callback holds exactly the stream prefix up to
 *     the end of the server's AUTH_DONE frame (msgr2.md 3.3).
 *
 * Secure-mode connections (and the monitor / manager connections of the default-mode sessions)
 * switch to encrypted preambles after the authentication frames; there the parser stops with a
 * frame CRC error and only the frames before it are checked. The test is skipped when python3 or the
 * captures are not available.
 */
#define _POSIX_C_SOURCE 200809L /* mkdtemp, opendir, stat under -std=c99 */

#include "wrt.h"

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wri_denc.h"
#include "wri_m2_ctl.h"
#include "wri_m2_frame.h"

#define SEG0_CAP (64u * 1024u)
#define SEG_MAX (8u * 1024u * 1024u)
#define RING_CAP 4096u
#define PREAUTH_CAP (64u * 1024u)

static uint32_t g_rng = 12345;

static uint32_t rnd(void)
{
	g_rng ^= g_rng << 13;
	g_rng ^= g_rng >> 17;
	g_rng ^= g_rng << 5;
	return g_rng;
}

struct counts {
	unsigned long hello, auth_request, bad_method, reply_more, request_more, auth_done, auth_sig,
		client_ident, server_ident, missing_features, keepalive, keepalive_ack, ack, message, other,
		preauth_streams;
	unsigned long by_tag[WRI_M2_TAG_MAX + 1u];
};

struct stream_state {
	int c2s;
	uint64_t logged;      /* raw bytes the parser has consumed so far */
	uint64_t next_seq;    /* the MESSAGE seq expected next */
	int seen_hello;
	int preauth_done;     /* AUTH_DONE seen on an s2c stream: the log is stopped */
	uint64_t done_end;    /* stream offset right after the AUTH_DONE frame */
	uint8_t *rxb, *txb;
	wri_m2_preauth pa;
};

static struct stream_state *g_st;

static void log_cb(void *log, const uint8_t *p, size_t n)
{
	struct stream_state *st = (struct stream_state *)log;

	st->logged += n;
	wri_m2_preauth_rx(&st->pa, p, n);
}

/* encode with `f` into an exact-size buffer and compare with the captured bytes */
typedef void (*enc_fn)(wri_wr *w, const void *ctx);

static void same_encoding(const char *what, enc_fn f, const void *ctx, const uint8_t *want, size_t n)
{
	uint8_t *buf = (uint8_t *)malloc(n ? n : 1);
	wri_wr w;

	if (buf == NULL)
		exit(2);
	wri_wr_init(&w, buf, n);
	f(&w, ctx);
	wrt_checks++;
	if (!wri_wr_ok(&w) || wri_wr_len(&w) != n || (n != 0 && memcmp(buf, want, n) != 0)) {
		wrt_failures++;
		fprintf(stderr, "%s: re-encoding does not reproduce the capture (err %d, %zu of %zu bytes)\n", what,
			(int)w.err, wri_wr_len(&w), n);
	}
	free(buf);
}

static void e_hello(wri_wr *w, const void *c) { wri_m2_hello_encode(w, (const wri_m2_hello *)c); }
static void e_bad(wri_wr *w, const void *c) { wri_m2_bad_method_encode(w, (const wri_m2_bad_method *)c); }
static void e_done(wri_wr *w, const void *c) { wri_m2_auth_done_encode(w, (const wri_m2_auth_done *)c); }
static void e_sident(wri_wr *w, const void *c) { wri_m2_server_ident_encode(w, (const wri_m2_server_ident *)c); }
static void e_cident(wri_wr *w, const void *c) { wri_m2_client_ident_encode(w, (const wri_m2_client_ident *)c); }

struct blob {
	const uint8_t *p;
	uint32_t n;
};
static void e_more(wri_wr *w, const void *c)
{
	const struct blob *b = (const struct blob *)c;

	wri_m2_auth_more_encode(w, b->p, b->n);
}

struct areq {
	uint32_t method, modes[16], nmodes;
	struct blob payload;
};
static void e_areq(wri_wr *w, const void *c)
{
	const struct areq *a = (const struct areq *)c;

	wri_m2_auth_request_encode(w, a->method, a->modes, a->nmodes, a->payload.p, a->payload.n);
}

struct u64v {
	uint64_t v;
};
static void e_u64(wri_wr *w, const void *c) { wri_m2_u64_encode(w, ((const struct u64v *)c)->v); }

struct kav {
	uint32_t s, n;
};
static void e_ka(wri_wr *w, const void *c)
{
	wri_m2_keepalive_encode(w, ((const struct kav *)c)->s, ((const struct kav *)c)->n);
}

static void e_sig(wri_wr *w, const void *c) { wri_m2_auth_sig_encode(w, (const uint8_t *)c); }

static void check_frame(struct stream_state *st, struct counts *cn, unsigned tag, const uint8_t *p, size_t n,
			unsigned nseg)
{
	wri_rd r;

	wri_rd_init(&r, p, n);
	switch (tag) {
	case WRI_M2_TAG_HELLO: {
		wri_m2_hello h;

		cn->hello++;
		WRT_CHECK(nseg == 1);
		WRT_CHECK_STATUS(WR_OK, wri_m2_hello_decode(&r, &h));
		if (st->c2s) {
			WRT_CHECK(h.entity_type == WRI_ENTITY_CLIENT);
		} else {
			WRT_CHECK(h.entity_type == WRI_ENTITY_MON || h.entity_type == WRI_ENTITY_OSD ||
				  h.entity_type == 0x10u /* manager */);
		}
		WRT_CHECK(h.peer_addr.family == WR_AF_IPV4 && h.peer_addr.type == WRI_EADDR_TYPE_MSGR2);
		same_encoding("HELLO", e_hello, &h, p, n);
		st->seen_hello = 1;
		break;
	}
	case WRI_M2_TAG_AUTH_REQUEST: {
		struct areq a;
		uint32_t i;
		const uint8_t *pl;
		uint32_t pn = 0;

		cn->auth_request++;
		WRT_CHECK(st->c2s);
		memset(&a, 0, sizeof(a));
		a.method = wri_rd_u32(&r);
		a.nmodes = wri_rd_count(&r, WRI_M2_VEC_WIRE_MAX, 4);
		for (i = 0; i < a.nmodes; i++)
			a.modes[i] = wri_rd_u32(&r);
		pl = wri_denc_blob(&r, &pn, WRI_M2_AUTH_BLOB_MAX);
		WRT_CHECK(wri_rd_ok(&r) && r.pos == r.len);
		WRT_CHECK(a.method == WRI_AUTH_METHOD_CEPHX);
		WRT_CHECK(a.nmodes >= 1 && (a.modes[0] == WRI_CONN_MODE_CRC || a.modes[0] == WRI_CONN_MODE_SECURE));
		a.payload.p = pl;
		a.payload.n = pn;
		if (wri_rd_ok(&r))
			same_encoding("AUTH_REQUEST", e_areq, &a, p, n);
		break;
	}
	case WRI_M2_TAG_AUTH_BAD_METHOD: {
		wri_m2_bad_method b;

		cn->bad_method++;
		WRT_CHECK(!st->c2s);
		WRT_CHECK_STATUS(WR_OK, wri_m2_bad_method_decode(&r, &b));
		/* the vectors of the notes: methods [2], result a negative errno (-13 / -95) */
		WRT_CHECK(b.result < 0 && b.n_methods >= 1 && b.n_modes >= 1);
		if (b.n_methods < WRI_M2_MODES_MAX && b.n_modes < WRI_M2_MODES_MAX)
			same_encoding("AUTH_BAD_METHOD", e_bad, &b, p, n);
		break;
	}
	case WRI_M2_TAG_AUTH_REPLY_MORE:
	case WRI_M2_TAG_AUTH_REQUEST_MORE: {
		struct blob b;

		if (tag == WRI_M2_TAG_AUTH_REPLY_MORE) {
			cn->reply_more++;
			WRT_CHECK(!st->c2s);
		} else {
			cn->request_more++;
			WRT_CHECK(st->c2s);
		}
		WRT_CHECK_STATUS(WR_OK, wri_m2_auth_more_decode(&r, &b.p, &b.n));
		same_encoding("AUTH_*_MORE", e_more, &b, p, n);
		break;
	}
	case WRI_M2_TAG_AUTH_DONE: {
		wri_m2_auth_done d;

		cn->auth_done++;
		WRT_CHECK(!st->c2s);
		WRT_CHECK_STATUS(WR_OK, wri_m2_auth_done_decode(&r, &d));
		WRT_CHECK(d.global_id != 0 && (d.mode == WRI_CONN_MODE_CRC || d.mode == WRI_CONN_MODE_SECURE));
		same_encoding("AUTH_DONE", e_done, &d, p, n);
		break;
	}
	case WRI_M2_TAG_AUTH_SIGNATURE: {
		uint8_t sig[32];

		cn->auth_sig++;
		WRT_CHECK_STATUS(WR_OK, wri_m2_auth_sig_decode(&r, sig));
		same_encoding("AUTH_SIGNATURE", e_sig, sig, p, n);
		break;
	}
	case WRI_M2_TAG_CLIENT_IDENT: {
		wri_m2_client_ident c;
		wri_eaddr addrs[WRI_EADDRVEC_MAX];
		size_t stored = 0, total = 0;

		cn->client_ident++;
		WRT_CHECK(st->c2s);
		memset(&c, 0, sizeof(c));
		WRT_CHECK_STATUS(WR_OK, wri_eaddrvec_decode(&r, addrs, WRI_EADDRVEC_MAX, &stored, &total));
		WRT_CHECK(stored == 1 && total == 1);
		c.addrs[0] = addrs[0];
		WRT_CHECK_STATUS(WR_OK, wri_eaddr_decode(&r, &c.target));
		c.gid = wri_rd_i64(&r);
		c.global_seq = wri_rd_u64(&r);
		c.supported = wri_rd_u64(&r);
		c.required = wri_rd_u64(&r);
		c.flags = wri_rd_u64(&r);
		c.cookie = wri_rd_u64(&r);
		WRT_CHECK(wri_rd_ok(&r) && r.pos == r.len);
		WRT_CHECK(c.addrs[0].type == WRI_EADDR_TYPE_ANY && c.target.type == WRI_EADDR_TYPE_MSGR2);
		WRT_CHECK(c.global_seq >= 1);
		same_encoding("CLIENT_IDENT", e_cident, &c, p, n);
		break;
	}
	case WRI_M2_TAG_SERVER_IDENT: {
		wri_m2_server_ident s;

		cn->server_ident++;
		WRT_CHECK(!st->c2s);
		WRT_CHECK_STATUS(WR_OK, wri_m2_server_ident_decode(&r, &s));
		WRT_CHECK(s.n_addrs >= 1 && s.n_addrs <= WRI_EADDRVEC_MAX);
		/* a monitor or OSD lists its msgr2 address and a legacy one; every real capture has the first */
		WRT_CHECK(s.addrs[0].type == WRI_EADDR_TYPE_MSGR2);
		same_encoding("SERVER_IDENT", e_sident, &s, p, n);
		break;
	}
	case WRI_M2_TAG_IDENT_MISSING_FEATURES: {
		struct u64v v;

		cn->missing_features++;
		WRT_CHECK_STATUS(WR_OK, wri_m2_u64_decode(&r, &v.v));
		same_encoding("IDENT_MISSING_FEATURES", e_u64, &v, p, n);
		break;
	}
	case WRI_M2_TAG_KEEPALIVE2:
	case WRI_M2_TAG_KEEPALIVE2_ACK: {
		struct kav k;

		if (tag == WRI_M2_TAG_KEEPALIVE2)
			cn->keepalive++;
		else
			cn->keepalive_ack++;
		WRT_CHECK_STATUS(WR_OK, wri_m2_keepalive_decode(&r, &k.s, &k.n));
		same_encoding("KEEPALIVE2", e_ka, &k, p, n);
		break;
	}
	case WRI_M2_TAG_ACK: {
		struct u64v v;

		cn->ack++;
		WRT_CHECK_STATUS(WR_OK, wri_m2_u64_decode(&r, &v.v));
		same_encoding("ACK", e_u64, &v, p, n);
		break;
	}
	case WRI_M2_TAG_MESSAGE: {
		wri_m2_hdr2 h;
		uint8_t enc[WRI_M2_HDR2_LEN];

		cn->message++;
		WRT_CHECK(nseg >= 1 && n == WRI_M2_HDR2_LEN);
		WRT_CHECK_STATUS(WR_OK, wri_m2_hdr2_decode(p, n, &h));
		wri_m2_hdr2_encode(enc, &h);
		WRT_CHECK(n == WRI_M2_HDR2_LEN && memcmp(enc, p, WRI_M2_HDR2_LEN) == 0);
		WRT_CHECK(h.flags == WRI_M2_MSGF_COMPLETE_NOCRC);
		WRT_CHECK(h.data_pre_padding_len == 0 && h.data_off == 0);
		WRT_CHECK(h.type != 0 && h.version >= 1 && h.compat_version >= 1 && h.compat_version <= h.version);
		/* seq starts at 1 in each direction and rises by exactly 1 */
		if (h.seq != st->next_seq) {
			wrt_failures++;
			fprintf(stderr, "MESSAGE seq %llu, expected %llu\n", (unsigned long long)h.seq,
				(unsigned long long)st->next_seq);
		}
		wrt_checks++;
		st->next_seq = h.seq + 1;
		break;
	}
	default:
		cn->other++;
		if (tag <= WRI_M2_TAG_MAX)
			cn->by_tag[tag]++;
		break;
	}
}

static void run_stream(const uint8_t *data, size_t len, int c2s, struct counts *cn)
{
	static uint8_t ringbuf[RING_CAP];
	static uint8_t seg0[SEG0_CAP];
	struct stream_state *st = (struct stream_state *)calloc(1, sizeof(*st));
	wri_m2_rx rx;
	wri_ring ring;
	size_t pos = 0, guard = 0;
	int stop = 0;

	if (st == NULL)
		exit(2);
	st->c2s = c2s;
	st->next_seq = 1;
	st->rxb = (uint8_t *)malloc(PREAUTH_CAP);
	st->txb = (uint8_t *)malloc(PREAUTH_CAP);
	if (st->rxb == NULL || st->txb == NULL)
		exit(2);
	wri_m2_preauth_init(&st->pa, st->rxb, st->txb, PREAUTH_CAP);
	g_st = st;
	wri_ring_init(&ring, ringbuf, sizeof(ringbuf));
	wri_m2_rx_init(&rx, seg0, sizeof(seg0), SEG_MAX);
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
			wri_m2_rx_ev ev = wri_m2_rx_step(&rx, &ring, NULL, NULL, log_cb, st);

			if (ev == WRI_RXE_NONE)
				break;
			if (ev == WRI_RXE_FRAME) {
				unsigned tag = rx.desc.tag;

				check_frame(st, cn, tag, seg0, rx.desc.len[0], rx.desc.nseg);
				if (!c2s && tag == WRI_M2_TAG_AUTH_DONE && !st->preauth_done) {
					/* the log must be exactly the stream so far, banner included */
					st->preauth_done = 1;
					st->done_end = st->logged;
					wri_m2_preauth_stop(&st->pa);
					WRT_CHECK(st->pa.err == WR_OK && st->pa.rx_len == st->logged);
					WRT_CHECK(st->pa.tx_len == 0);
					WRT_CHECK(st->pa.rx_len <= len && memcmp(st->rxb, data, st->pa.rx_len) == 0);
					cn->preauth_streams++;
				}
				wri_m2_rx_next_frame(&rx);
			} else if (ev == WRI_RXE_SEG0 || ev == WRI_RXE_BANNER) {
				continue;
			} else if (ev == WRI_RXE_ABORTED) {
				wri_m2_rx_next_frame(&rx);
			} else {
				stop = 1; /* secure mode: the encrypted preamble fails its CRC; nothing after it */
				break;
			}
		}
		if (pos >= len && ring.len == 0 && rx.direct == 0)
			stop = 1;
	}
	/* a server stream that reached AUTH_DONE kept nothing after it in the (stopped) log */
	if (st->preauth_done)
		WRT_CHECK(st->pa.rx_len == st->done_end);
	wri_m2_preauth_wipe(&st->pa);
	g_st = NULL;
	free(st->rxb);
	free(st->txb);
	free(st);
}

static int is_dir(const char *p)
{
	struct stat s;

	return stat(p, &s) == 0 && S_ISDIR(s.st_mode);
}

static int is_file(const char *p)
{
	struct stat s;

	return stat(p, &s) == 0 && S_ISREG(s.st_mode);
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

int main(void)
{
	char pcapdir[512], tool[512], cmd[1400], outdir[] = "/tmp/wrt_m2ctl_replay_XXXXXX", idx[600];
	FILE *fi;
	char line[512];
	struct counts cn;
	unsigned long streams = 0;

	memset(&cn, 0, sizeof(cn));
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
	snprintf(idx, sizeof(idx), "%s/index.tsv", outdir);
	fi = fopen(idx, "r");
	if (fi == NULL) {
		remove_tree_flat(outdir);
		WRT_CHECK(0 && "no index.tsv");
		return wrt_finish();
	}
	while (fgets(line, sizeof(line), fi)) {
		char session[96], dir[8], file[256], path[900];
		int conn, port;
		unsigned long size;
		long gap;
		uint8_t *data = NULL;
		size_t dlen = 0;

		if (sscanf(line, "%95[^\t]\t%d\t%7s\t%d\t%lu\t%ld\t%255s", session, &conn, dir, &port, &size, &gap, file) != 7)
			continue;
		snprintf(path, sizeof(path), "%s/%s", outdir, file);
		if (wrt_read_file(path, &data, &dlen) != 0) {
			WRT_CHECK(0 && "cannot read a stream");
			continue;
		}
		run_stream(data, dlen, strcmp(dir, "c2s") == 0, &cn);
		streams++;
		free(data);
	}
	fclose(fi);
	remove_tree_flat(outdir);

	{
		unsigned t;

		for (t = 0; t <= WRI_M2_TAG_MAX; t++)
			if (cn.by_tag[t])
				printf("other tag %u: %lu\n", t, cn.by_tag[t]);
	}
	WRT_CHECK(streams >= 500);
	/* the capture set covers every tag handled here except keepalive and ACK; the compression frames
	 * (tags 21 and 22, both sides advertise the bit) are outside this module: the minimal client
	 * never advertises it (msgr2.md 4.2) */
	WRT_CHECK(cn.hello >= 500 && cn.auth_request >= 250 && cn.auth_done >= 250 && cn.auth_sig >= 400);
	WRT_CHECK(cn.client_ident >= 200 && cn.server_ident >= 200 && cn.message >= 1000);
	WRT_CHECK(cn.bad_method >= 1 && cn.reply_more >= 100 && cn.request_more >= 100);
	WRT_CHECK(cn.preauth_streams >= 250);
	printf("replayed %lu streams: %lu HELLO, %lu AUTH_REQUEST, %lu AUTH_DONE, %lu AUTH_SIGNATURE, %lu CLIENT_IDENT, "
	       "%lu SERVER_IDENT, %lu MESSAGE, %lu BAD_METHOD, %lu REPLY_MORE, %lu REQUEST_MORE, %lu other, %lu pre-auth logs\n",
	       streams, cn.hello, cn.auth_request, cn.auth_done, cn.auth_sig, cn.client_ident, cn.server_ident,
	       cn.message, cn.bad_method, cn.reply_more, cn.request_more, cn.other, cn.preauth_streams);
	return wrt_finish();
}
