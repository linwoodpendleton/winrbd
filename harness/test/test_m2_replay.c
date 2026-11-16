/* SPDX-License-Identifier: MIT */
/*
 * Capture replay of the msgr2.1 receive parser: harness/tools/pcap2stream.py extracts the TCP
 * payload streams (both directions of every connection) from the public captures in
 * vectors/public/pcap, and every stream goes through the parser in random pieces with sinks
 * attached for segments 1..3.
 *
 * Reference: the same tool walks each stream independently (preamble lengths and CRC only) and
 * writes <stream>.frames. Frame offsets, tags, segment lengths and wire sizes must agree, and a
 * stream the walk calls clean must parse to its last byte with every CRC verified. Secure-mode
 * connections (the "sec" session, the monitor and manager connections of the "def" session) are not crc
 * framing: there the walk stops at the first encrypted preamble and the parser must stop at the
 * same place with a frame CRC error, never with a crash or a wrong frame. The test is skipped
 * when python3 or the captures are not available. The two connections of vectors/msgr2/
 * handshake-skeletons.json (k2-rados-small) are compared frame by frame as well.
 */
#define _POSIX_C_SOURCE 200809L /* mkdtemp, opendir, stat under -std=c99 */

#include "wrt.h"

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wri_m2_frame.h"

#define SEG0_CAP (64u * 1024u)
#define SEG_MAX (8u * 1024u * 1024u)
#define RING_CAP 4096u
#define MAX_FRAMES 100000u
#define MON_PORT 3300
#define MGR_PORT 6800 /* the manager: secure by default like the monitor; OSDs listen on 6802 and up */

typedef struct frame {
	uint64_t off;
	unsigned tag, nseg;
	uint32_t len[4];
	uint64_t wire;
} frame;

typedef struct walk { /* the reference, read from <stream>.frames */
	frame *f;
	size_t n;
	int clean;        /* "end" */
	uint64_t stop_at; /* offset of "stop" */
	char reason[64];
	unsigned banner_len;
} walk;

static uint64_t g_logged;
static uint8_t *g_sink[3];
static uint32_t g_rng = 99;

static uint32_t rnd(void)
{
	g_rng ^= g_rng << 13;
	g_rng ^= g_rng >> 17;
	g_rng ^= g_rng << 5;
	return g_rng;
}

static void log_cb(void *log, const uint8_t *p, size_t n)
{
	(void)log;
	(void)p;
	g_logged += n;
}

static int read_walk(const char *path, walk *w)
{
	FILE *fp = fopen(path, "r");
	char line[256];

	memset(w, 0, sizeof(*w));
	w->f = (frame *)calloc(MAX_FRAMES, sizeof(frame));
	if (fp == NULL || w->f == NULL) {
		if (fp)
			fclose(fp);
		return -1;
	}
	while (fgets(line, sizeof(line), fp)) {
		frame *f = &w->f[w->n];
		unsigned long long off, wire, l0, l1, l2, l3;
		unsigned tag, nseg, bl;

		if (sscanf(line, "banner %u", &bl) == 1) {
			w->banner_len = bl;
		} else if (sscanf(line, "frame %llu %u %u %llu %llu %llu %llu %llu", &off, &tag, &nseg, &l0, &l1, &l2,
				  &l3, &wire) == 8) {
			if (w->n >= MAX_FRAMES)
				break;
			f->off = off;
			f->tag = tag;
			f->nseg = nseg;
			f->len[0] = (uint32_t)l0;
			f->len[1] = (uint32_t)l1;
			f->len[2] = (uint32_t)l2;
			f->len[3] = (uint32_t)l3;
			f->wire = wire;
			w->n++;
		} else if (strncmp(line, "end ", 4) == 0) {
			w->clean = 1;
		} else if (sscanf(line, "stop %llu %63[^\n]", &off, w->reason) >= 1) {
			w->stop_at = off;
		}
	}
	fclose(fp);
	return 0;
}

typedef struct outcome {
	frame *f; /* what the parser found */
	size_t n;
	int errored;
	wr_status status;
	uint64_t consumed; /* bytes the parser took from the stream */
	int banner_ok;
	uint64_t supported, required;
	int at_boundary; /* parser idle between frames, nothing half-read */
} outcome;

static void run_stream(const uint8_t *data, size_t len, outcome *o)
{
	wri_m2_rx rx;
	wri_ring ring;
	static uint8_t ringbuf[RING_CAP];
	static uint8_t seg0[SEG0_CAP];
	size_t pos = 0, guard = 0;
	unsigned i;
	int stop = 0;

	memset(o, 0, sizeof(*o));
	o->f = (frame *)calloc(MAX_FRAMES, sizeof(frame));
	g_logged = 0;
	wri_ring_init(&ring, ringbuf, sizeof(ringbuf));
	wri_m2_rx_init(&rx, seg0, sizeof(seg0), SEG_MAX);
	while (!stop && guard++ < 4 * len + 100) {
		uint8_t *w = NULL;
		size_t room = wri_m2_rx_window(&rx, &ring, &w);
		wri_m2_rx_ev ev;

		if (room != 0 && pos < len) {
			size_t k = 1 + rnd() % 3000;

			k = k < room ? k : room;
			k = k < len - pos ? k : len - pos;
			memcpy(w, data + pos, k);
			wri_m2_rx_commit(&rx, &ring, k);
			pos += k;
		}
		for (;;) {
			ev = wri_m2_rx_step(&rx, &ring, NULL, NULL, log_cb, NULL);
			if (ev == WRI_RXE_NONE)
				break;
			if (ev == WRI_RXE_BANNER) {
				o->banner_ok = 1;
				o->supported = wri_m2_rx_banner(&rx)->supported;
				o->required = wri_m2_rx_banner(&rx)->required;
			} else if (ev == WRI_RXE_SEG0) {
				for (i = 1; i < rx.desc.nseg; i++)
					wri_m2_rx_sink(&rx, i, g_sink[i - 1], SEG_MAX);
			} else if (ev == WRI_RXE_FRAME) {
				frame *f = &o->f[o->n];
				uint64_t wire = 32 + wri_m2_frame_body_len(&rx.desc);

				if (o->n < MAX_FRAMES) {
					f->off = g_logged - wire;
					f->tag = rx.desc.tag;
					f->nseg = rx.desc.nseg;
					memcpy(f->len, rx.desc.len, sizeof(f->len));
					f->wire = wire;
					o->n++;
				}
				for (i = 1; i < rx.desc.nseg; i++)
					WRT_CHECK_U64(rx.stored[i], rx.desc.len[i]);
				wri_m2_rx_next_frame(&rx);
			} else if (ev == WRI_RXE_ABORTED) {
				WRT_CHECK(0 && "unexpected aborted frame in a capture");
				wri_m2_rx_next_frame(&rx);
			} else {
				o->errored = 1;
				o->status = wri_m2_rx_error(&rx)->status;
				stop = 1;
				break;
			}
		}
		if (pos >= len && ring.len == 0 && rx.direct == 0)
			stop = 1;
	}
	o->consumed = g_logged;
	o->at_boundary = rx.state == WRI_RX_PREAMBLE && rx.seg_pos == 0 && rx.pending_ev == WRI_RXE_NONE;
}

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

typedef struct stream_ref { /* a stream kept for the skeleton comparison */
	frame *f;
	size_t n;
} stream_ref;

static void compare_skeleton(const char *name, const stream_ref *c2s, const stream_ref *s2c, int conn_index)
{
	wrt_json j;
	wrt_tok conns, cn, streams;
	size_t si;
	const stream_ref *refs[2];

	refs[0] = c2s;
	refs[1] = s2c;
	if (wrt_json_load_vec(&j, "msgr2/handshake-skeletons.json") != 0) {
		WRT_CHECK(0 && "cannot load handshake-skeletons.json");
		return;
	}
	conns = wrt_json_get(&j, wrt_json_root(&j), "connections");
	cn = wrt_json_at(&j, conns, (size_t)conn_index);
	streams = wrt_json_get(&j, cn, "streams");
	for (si = 0; si < 2; si++) {
		wrt_tok st = wrt_json_at(&j, streams, si);
		wrt_tok fr = wrt_json_get(&j, st, "frames");
		char *dir = wrt_json_strdup(&j, wrt_json_get(&j, st, "direction"));
		size_t i, m = wrt_json_count(&j, fr);
		const stream_ref *r = strcmp(dir, "client_to_server") == 0 ? refs[0] : refs[1];

		free(dir);
		if (r->n != m)
			fprintf(stderr, "%s: skeleton has %zu frames, replay found %zu\n", name, m, r->n);
		WRT_CHECK_U64(r->n, m);
		for (i = 0; i < m && i < r->n; i++) {
			wrt_tok f = wrt_json_at(&j, fr, i);
			wrt_tok lens = wrt_json_get(&j, f, "segment_lengths");
			int ok = 0;
			size_t k;

			WRT_CHECK_U64(r->f[i].tag, wrt_json_int(&j, wrt_json_get(&j, f, "tag"), &ok));
			WRT_CHECK_U64(r->f[i].wire, wrt_json_int(&j, wrt_json_get(&j, f, "wire_size"), &ok));
			WRT_CHECK_U64(r->f[i].nseg, wrt_json_count(&j, lens));
			for (k = 0; k < wrt_json_count(&j, lens) && k < 4; k++)
				WRT_CHECK_U64(r->f[i].len[k], wrt_json_int(&j, wrt_json_at(&j, lens, k), &ok));
		}
	}
	wrt_json_free(&j);
}

int main(void)
{
	char pcapdir[512], tool[512], cmd[1400], outdir[] = "/tmp/wrt_m2_replay_XXXXXX", idx[600];
	FILE *fi;
	char line[512];
	unsigned long streams = 0, frames = 0, clean_streams = 0, secure_streams = 0;
	unsigned long long bytes = 0;
	stream_ref skel_c2s[2], skel_s2c[2]; /* [0] monitor, [1] OSD of k2-rados-small */
	int skel_seen[2] = {0, 0};
	unsigned i;

	snprintf(pcapdir, sizeof(pcapdir), "%s", wrt_vec_path("public/pcap"));
	snprintf(tool, sizeof(tool), "%s", wrt_vec_path("../tools/pcap2stream.py"));
	if (!is_dir(pcapdir) || !is_file(tool))
		WRT_SKIP("public captures or pcap2stream.py not found");
	if (system("python3 -c 'import sys' >/dev/null 2>&1") != 0)
		WRT_SKIP("python3 not available");
	if (mkdtemp(outdir) == NULL)
		WRT_SKIP("cannot create a temporary directory");
	snprintf(cmd, sizeof(cmd), "PYTHONDONTWRITEBYTECODE=1 python3 -I '%s' --frames '%s' '%s'", tool, outdir, pcapdir);
	if (system(cmd) != 0) {
		remove_tree_flat(outdir);
		WRT_CHECK(0 && "pcap2stream.py failed");
		return wrt_finish();
	}
	for (i = 0; i < 3; i++)
		g_sink[i] = (uint8_t *)malloc(SEG_MAX);

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
		size_t dlen = 0, k;
		walk w;
		outcome o;
		int secure_expected, def = 0;

		if (sscanf(line, "%95[^\t]\t%d\t%7s\t%d\t%lu\t%ld\t%255s", session, &conn, dir, &port, &size, &gap, file) != 7)
			continue;
		WRT_CHECK(gap == -1); /* the captures have no holes */
		snprintf(path, sizeof(path), "%s/%s", outdir, file);
		if (wrt_read_file(path, &data, &dlen) != 0) {
			WRT_CHECK(0 && "cannot read a stream");
			continue;
		}
		WRT_CHECK_U64(dlen, size);
		file[strlen(file) - 4] = 0;
		snprintf(path, sizeof(path), "%s/%s.frames", outdir, file);
		if (read_walk(path, &w) != 0) {
			WRT_CHECK(0 && "cannot read the frame walk");
			free(data);
			continue;
		}
		/* which streams are crc framing: all of them except secure-mode connections */
		def = strstr(session, "-def-") != NULL;
		secure_expected = strstr(session, "-sec-") != NULL || (def && (port == 3300 || port == MGR_PORT));
		if (!secure_expected) {
			if (!w.clean)
				fprintf(stderr, "%s: walk did not end cleanly (%s at %llu)\n", file, w.reason,
					(unsigned long long)w.stop_at);
			WRT_CHECK(w.clean);
		} else {
			WRT_CHECK(!w.clean && strcmp(w.reason, "preamble crc") == 0);
		}

		run_stream(data, dlen, &o);
		streams++;
		bytes += dlen;
		WRT_CHECK(o.banner_ok);
		WRT_CHECK_U64(o.supported, 3); /* stock v20.2.5, both sides: REVISION_1 + COMPRESSION, nothing required */
		WRT_CHECK_U64(o.required, 0);
		if (o.n != w.n)
			fprintf(stderr, "%s: parser found %zu frames, walk %zu\n", file, o.n, w.n);
		WRT_CHECK_U64(o.n, w.n);
		for (k = 0; k < o.n && k < w.n; k++) {
			int same = o.f[k].off == w.f[k].off && o.f[k].tag == w.f[k].tag && o.f[k].nseg == w.f[k].nseg &&
				   memcmp(o.f[k].len, w.f[k].len, sizeof(o.f[k].len)) == 0 && o.f[k].wire == w.f[k].wire;

			if (!same)
				fprintf(stderr, "%s: frame %zu differs\n", file, k);
			WRT_CHECK(same);
		}
		frames += o.n;
		if (w.clean) {
			clean_streams++;
			WRT_CHECK_U64(o.errored, 0);
			WRT_CHECK_U64(o.consumed, dlen); /* to the last byte */
			WRT_CHECK(o.at_boundary);
			WRT_CHECK(w.n >= 1 && w.f[0].tag == WRI_M2_TAG_HELLO); /* every connection opens with HELLO */
			if (strcmp(dir, "c2s") == 0 && w.n >= 2)
				WRT_CHECK(w.f[1].tag == WRI_M2_TAG_AUTH_REQUEST);
		} else {
			secure_streams++;
			WRT_CHECK_U64(o.errored, 1);
			WRT_CHECK_STATUS(WR_E_M2_FRAME_CRC, o.status);
			/* it read the bad preamble (32 bytes) and nothing beyond it */
			WRT_CHECK_U64(o.consumed, w.stop_at + 32);
			WRT_CHECK(w.n >= 1 && w.f[0].tag == WRI_M2_TAG_HELLO);
		}

		/* the two connections of the committed skeletons */
		if (strcmp(session, "k2-rados-small") == 0) {
			int which = port == MON_PORT ? 0 : 1;

			if (port == MGR_PORT) {
				/* not part of the skeletons */
			} else if (!skel_seen[which]) {
				stream_ref *tgt = strcmp(dir, "c2s") == 0 ? &skel_c2s[which] : &skel_s2c[which];

				tgt->f = (frame *)malloc(o.n * sizeof(frame) + 1);
				memcpy(tgt->f, o.f, o.n * sizeof(frame));
				tgt->n = o.n;
				if (strcmp(dir, "s2c") == 0)
					skel_seen[which] = 1;
			}
		}
		free(o.f);
		free(w.f);
		free(data);
	}
	fclose(fi);
	remove_tree_flat(outdir);
	for (i = 0; i < 3; i++)
		free(g_sink[i]);

	WRT_CHECK(skel_seen[0] && skel_seen[1]);
	if (skel_seen[0])
		compare_skeleton("mon connection of k2-rados-small", &skel_c2s[0], &skel_s2c[0], 0);
	if (skel_seen[1])
		compare_skeleton("osd connection of k2-rados-small", &skel_c2s[1], &skel_s2c[1], 1);
	free(skel_c2s[0].f);
	free(skel_c2s[1].f);
	free(skel_s2c[0].f);
	free(skel_s2c[1].f);

	WRT_CHECK(streams >= 500);
	WRT_CHECK(frames > 4000);
	printf("replayed %lu streams (%lu crc-mode, %lu secure-mode), %lu frames, %llu bytes\n", streams, clean_streams,
	       secure_streams, frames, bytes);
	return wrt_finish();
}
