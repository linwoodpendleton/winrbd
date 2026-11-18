/* SPDX-License-Identifier: MIT */
/*
 * test_imgio_replay - the lab captures of module vectors-d (harness/vectors/public/imgio/): three scripted image sessions of the winrbd core
 * (wr-rbd in shell mode) against a real Ceph v20.2.5 OSD, with the stock export of every image before and after. Offline, with no cluster:
 *
 *   wire      every request of a capture is rebuilt from its decoded summary and encoded by wri_mosdop_encode; the front must equal what the
 *             core put on the wire byte for byte, every reply must decode by wri_mosdopreply_decode and agree with its summary
 *   replay    the same script is run through the whole engine (public API, the rig of client_osd_rig.h) against the simulated monitor and
 *             OSDs, on an image made like the real one (id, size, order, features, snapshot context, and for the reader the objects the stock
 *             tool wrote). The OSD requests the engine sends must equal the captured ones, command by command: the same objects, operations,
 *             offsets, lengths, flags, snapshot context and payload sizes; and what the simulated OSD answers must equal what the real one
 *             answered (result, per-operation result and output length). That is a differential test of the engine AND of the simulator
 *             against a real OSD
 *   content   what every read returns, and the objects of the simulated store at the end, equal the stock export taken after the session
 *
 * The vectors are not part of a source archive without harness/vectors/public/imgio: then the test skips with its reason.
 */
#include "client_osd_rig.h"
#include "osdc_vec_rig.h"

#define IG_SESS_MAX 8u
#define IG_CMD_MAX 64u
#define IG_REC_MAX 1024u
#define IG_REPORT_MAX 12u

typedef struct ig_cmd {
	char op[12];
	uint64_t off, len;
	char kind[8];
	uint64_t arg;
} ig_cmd;

static unsigned g_reported;
#define IG_BAD(...)                                                                                                                         \
	do {                                                                                                                              \
		WRT_CHECK(0);                                                                                                             \
		if (g_reported++ < IG_REPORT_MAX)                                                                                          \
			fprintf(stderr, __VA_ARGS__);                                                                                         \
	} while (0)

/* ---- the patterns of wr-rbd (a function of the absolute byte offset) --------------------------------------------------------------- */

static uint64_t ig_mix64(uint64_t x)
{
	x += 0x9e3779b97f4a7c15ull;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
	return x ^ (x >> 31);
}

static void ig_pat(uint8_t *buf, const char *kind, uint64_t arg, uint64_t off, size_t n)
{
	size_t i;

	if (strcmp(kind, "zero") == 0) {
		memset(buf, 0, n);
	} else if (strcmp(kind, "byte") == 0) {
		memset(buf, (int)(arg & 255u), n);
	} else if (strcmp(kind, "rand") == 0) {
		for (i = 0; i < n; i++) {
			uint64_t pos = off + i, w = ig_mix64(arg * 0x2545f4914f6cdd1dull + (pos >> 3));

			buf[i] = (uint8_t)(w >> (8u * (unsigned)(pos & 7u)));
		}
	} else {
		memset(buf, 0xEE, n);
		WRT_CHECK(0 && "unknown pattern in a script");
	}
}

/* ---- the session file ------------------------------------------------------------------------------------------------------------- */

static int ig_present(void)
{
	FILE *f = fopen(wrt_vec_path("public/imgio/INDEX.json"), "rb");

	if (f == NULL)
		return 0;
	fclose(f);
	return 1;
}

static int ig_parse_cmd(ig_cmd *c, const char *line)
{
	char buf[160], *w[8];
	unsigned n = 0, i;
	char *p;

	if (strlen(line) >= sizeof(buf))
		return -1;
	strcpy(buf, line);
	for (p = strtok(buf, " "); p != NULL && n < 8u; p = strtok(NULL, " "))
		w[n++] = p;
	if (n < 3u)
		return -1;
	memset(c, 0, sizeof(*c));
	if (strlen(w[0]) >= sizeof(c->op))
		return -1;
	strcpy(c->op, w[0]);
	c->off = strtoull(w[1], NULL, 0);
	c->len = strtoull(w[2], NULL, 0);
	for (i = 3; i + 1u < n; i++)
		if (strcmp(w[i], "--pattern") == 0) {
			char *colon = strchr(w[i + 1], ':');

			if (colon != NULL) {
				*colon = '\0';
				c->arg = strtoull(colon + 1, NULL, 0);
			}
			if (strlen(w[i + 1]) >= sizeof(c->kind))
				return -1;
			strcpy(c->kind, w[i + 1]);
		}
	return 0;
}

typedef struct ig_sess {
	wrt_json j;
	char name[16];
	char image_name[64], image_id[32], prefix[64];
	uint64_t size, features, snap_seq;
	unsigned order, writable, n_snaps, n_cmds, n_ex;
	uint64_t snaps[16];
	ig_cmd cmd[IG_CMD_MAX];
	uint8_t *before, *after;
	size_t before_n, after_n;
	wrt_tok ex; /* the exchanges array */
} ig_sess;

static int ig_load(ig_sess *s, const char *name)
{
	char rel[128];
	wrt_tok img, cmds, sn;
	size_t i;
	char *t;

	memset(s, 0, sizeof(*s));
	snprintf(s->name, sizeof(s->name), "%s", name);
	snprintf(rel, sizeof(rel), "public/imgio/sessions/%s.json", name);
	if (wrt_json_load_vec(&s->j, rel) != 0)
		return -1;
	img = wrt_json_get(&s->j, wrt_json_root(&s->j), "image");
	if (img == WRT_NONE)
		return -1;
	t = wrt_json_strdup(&s->j, wrt_json_get(&s->j, img, "name"));
	snprintf(s->image_name, sizeof(s->image_name), "%s", t != NULL ? t : "");
	free(t);
	t = wrt_json_strdup(&s->j, wrt_json_get(&s->j, img, "id"));
	snprintf(s->image_id, sizeof(s->image_id), "%s", t != NULL ? t : "");
	free(t);
	t = wrt_json_strdup(&s->j, wrt_json_get(&s->j, img, "prefix"));
	snprintf(s->prefix, sizeof(s->prefix), "%s", t != NULL ? t : "");
	free(t);
	s->size = ov_u64(&s->j, img, "size");
	s->features = ov_u64(&s->j, img, "features");
	s->snap_seq = ov_u64(&s->j, img, "snap_seq");
	s->order = (unsigned)ov_int(&s->j, img, "order", 0);
	s->writable = (unsigned)ov_int(&s->j, wrt_json_root(&s->j), "writable", 0);
	sn = wrt_json_get(&s->j, img, "snap_ids");
	s->n_snaps = sn == WRT_NONE ? 0u : (unsigned)wrt_json_count(&s->j, sn);
	if (s->n_snaps > 16u)
		return -1;
	for (i = 0; i < s->n_snaps; i++)
		s->snaps[i] = ov_u64_tok(&s->j, wrt_json_at(&s->j, sn, i));
	cmds = wrt_json_get(&s->j, wrt_json_root(&s->j), "commands");
	s->n_cmds = cmds == WRT_NONE ? 0u : (unsigned)wrt_json_count(&s->j, cmds);
	if (s->n_cmds == 0u || s->n_cmds > IG_CMD_MAX)
		return -1;
	for (i = 0; i < s->n_cmds; i++) {
		char *line = wrt_json_strdup(&s->j, wrt_json_at(&s->j, cmds, i));

		if (line == NULL || ig_parse_cmd(&s->cmd[i], line) != 0) {
			free(line);
			return -1;
		}
		free(line);
	}
	s->ex = wrt_json_get(&s->j, wrt_json_root(&s->j), "exchanges");
	s->n_ex = s->ex == WRT_NONE ? 0u : (unsigned)wrt_json_count(&s->j, s->ex);
	snprintf(rel, sizeof(rel), "public/imgio/images/%s.after.bin", name);
	if (wrt_read_file(wrt_vec_path(rel), &s->after, &s->after_n) != 0)
		return -1;
	snprintf(rel, sizeof(rel), "public/imgio/images/%s.before.bin", name);
	{
		FILE *f = fopen(wrt_vec_path(rel), "rb");

		if (f != NULL) {
			fclose(f);
			if (wrt_read_file(wrt_vec_path(rel), &s->before, &s->before_n) != 0)
				return -1;
		}
	}
	return 0;
}

static void ig_free(ig_sess *s)
{
	free(s->before);
	free(s->after);
	wrt_json_free(&s->j);
}

/* ---- part 1: the wire ---------------------------------------------------------------------------------------------------------------- */

static unsigned g_wire_req, g_wire_rep;

static void check_wire(ig_sess *s)
{
	unsigned i;

	for (i = 0; i < s->n_ex; i++) {
		wrt_tok ex = wrt_json_at(&s->j, s->ex, i);
		ov_msg rq, rp;
		ov_req q;
		wri_mosdopreply r;
		char where[64];

		snprintf(where, sizeof(where), "%s #%u", s->name, i + 1u);
		WRT_CHECK(ov_msg_load(&rq, &s->j, wrt_json_get(&s->j, ex, "request")) == 0);
		WRT_CHECK(ov_msg_load(&rp, &s->j, wrt_json_get(&s->j, ex, "reply")) == 0);
		WRT_CHECK(ov_req_build(&q, &s->j, rq.summary, (uint8_t)rq.version) == 0);
		WRT_CHECK(ov_req_check(&q, &rq, where) == 0);
		g_wire_req++;
		memset(&r, 0, sizeof(r));
		WRT_CHECK_STATUS(WR_OK, wri_mosdopreply_decode(rp.front, rp.front_len, rp.version, rp.compat, &r));
		WRT_CHECK((int64_t)r.result == ov_int(&s->j, rp.summary, "result", 1));
		WRT_CHECK_U64(r.n_ops, wrt_json_count(&s->j, wrt_json_get(&s->j, rq.summary, "ops")));
		WRT_CHECK_U64(r.out_total, rp.data_total);
		WRT_CHECK_U64(rq.tid, rp.tid);
		g_wire_rep++;
		ov_req_free(&q);
		ov_msg_free(&rq);
		ov_msg_free(&rp);
	}
}

/* ---- part 2: the replay ------------------------------------------------------------------------------------------------------------ */

static int rec_cmp_tid(const void *a, const void *b)
{
	const sim_osd_rec *x = (const sim_osd_rec *)a, *y = (const sim_osd_rec *)b;

	return x->tid < y->tid ? -1 : x->tid > y->tid ? 1 : 0;
}

/* Every request the simulated OSDs recorded, in transaction order. */
static unsigned collect(cw *w, sim_osd_rec *out, unsigned cap)
{
	unsigned i, n = 0;

	for (i = 0; i < w->n_osd; i++) {
		uint32_t k, cnt = 0;
		const sim_osd_rec *rs = sim_osd_recs(w->osd[i], &cnt);

		for (k = 0; k < cnt && n < cap; k++)
			out[n++] = rs[k];
	}
	qsort(out, n, sizeof(out[0]), rec_cmp_tid);
	return n;
}

/* One captured exchange, flattened for comparison with a record. */
typedef struct ig_live {
	char oid[96];
	unsigned n_ops;
	uint16_t code[SIM_OSD_OPS_MAX];
	uint64_t off[SIM_OSD_OPS_MAX], len[SIM_OSD_OPS_MAX];
	uint32_t flags, n_snaps;
	uint64_t snap_seq, snapid;
	uint64_t data_len;
	int32_t result;
	int32_t rval[SIM_OSD_OPS_MAX];
	uint32_t out[SIM_OSD_OPS_MAX];
} ig_live;

static int live_of(const ig_sess *s, unsigned i, ig_live *l)
{
	wrt_tok ex = wrt_json_at(&s->j, s->ex, i);
	wrt_tok rq = wrt_json_get(&s->j, ex, "request"), rp = wrt_json_get(&s->j, ex, "reply");
	wrt_tok rs = wrt_json_get(&s->j, rq, "summary"), ps = wrt_json_get(&s->j, rp, "summary");
	wrt_tok ops = wrt_json_get(&s->j, rs, "ops"), pops = wrt_json_get(&s->j, ps, "ops"), rv = wrt_json_get(&s->j, ps, "rvals");
	char *oid = wrt_json_strdup(&s->j, wrt_json_get(&s->j, rs, "oid"));
	size_t k, n;
	int ok = 0;

	memset(l, 0, sizeof(*l));
	if (oid == NULL)
		return -1;
	snprintf(l->oid, sizeof(l->oid), "%s", oid);
	free(oid);
	n = wrt_json_count(&s->j, ops);
	if (n > SIM_OSD_OPS_MAX)
		return -1;
	l->n_ops = (unsigned)n;
	for (k = 0; k < n; k++) {
		wrt_tok o = wrt_json_at(&s->j, ops, k);

		l->code[k] = (uint16_t)ov_int(&s->j, o, "code", 0);
		l->off[k] = (uint64_t)ov_int(&s->j, o, "off", 0);
		l->len[k] = (uint64_t)ov_int(&s->j, o, "len", 0);
		l->rval[k] = (int32_t)wrt_json_int(&s->j, wrt_json_at(&s->j, rv, k), &ok);
		l->out[k] = (uint32_t)ov_int(&s->j, wrt_json_at(&s->j, pops, k), "out_len", 0);
	}
	l->flags = (uint32_t)ov_int(&s->j, rs, "flags", 0);
	l->snap_seq = ov_u64(&s->j, rs, "snap_seq");
	l->snapid = ov_u64(&s->j, rs, "snapid");
	l->n_snaps = (uint32_t)wrt_json_count(&s->j, wrt_json_get(&s->j, rs, "snaps"));
	l->data_len = (uint64_t)ov_int(&s->j, wrt_json_get(&s->j, rq, "data"), "length", 0);
	l->result = (int32_t)ov_int(&s->j, ps, "result", 1);
	return 0;
}

static unsigned g_cmp_pairs, g_cmp_ops;

static void compare_pair(const ig_sess *s, const char *where, const ig_live *l, const sim_osd_rec *r)
{
	unsigned k;
	int bad = 0;

	if (strcmp(l->oid, r->oid) != 0 || l->n_ops != r->n_ops) {
		IG_BAD("%s: live request names %s with %u ops, the engine sent %s with %u ops\n", where, l->oid, l->n_ops, r->oid, r->n_ops);
		return;
	}
	for (k = 0; k < l->n_ops; k++) {
		if (l->code[k] != r->op_code[k])
			bad = 1;
		else if (l->code[k] != WRI_OSD_OP_CALL && (l->off[k] != r->op_off[k] || l->len[k] != r->op_len[k]))
			bad = 1;
		if (bad) {
			IG_BAD("%s: op %u: live code %#x %llu+%llu, the engine sent %#x %llu+%llu\n", where, k, l->code[k], (unsigned long long)l->off[k],
			       (unsigned long long)l->len[k], r->op_code[k], (unsigned long long)r->op_off[k], (unsigned long long)r->op_len[k]);
			return;
		}
		/* what the OSD answered, the real one and the simulated one */
		if (l->rval[k] != r->op_rval[k] || l->out[k] != r->op_out[k]) {
			IG_BAD("%s: op %u (%#x): the real OSD answered rval %d with %u bytes, the simulated one rval %d with %u bytes\n", where, k, l->code[k],
			       l->rval[k], l->out[k], r->op_rval[k], r->op_out[k]);
			return;
		}
		g_cmp_ops++;
	}
	if (l->flags != r->flags) {
		IG_BAD("%s: message flags: live %#x, the engine %#x\n", where, l->flags, r->flags);
		return;
	}
	if (l->snap_seq != r->snap_seq || l->n_snaps != r->n_snaps || l->snapid != r->snapid) {
		IG_BAD("%s: snapshot context: live seq %llu n %u snapid %#llx, the engine seq %llu n %u snapid %#llx\n", where, (unsigned long long)l->snap_seq,
		       l->n_snaps, (unsigned long long)l->snapid, (unsigned long long)r->snap_seq, r->n_snaps, (unsigned long long)r->snapid);
		return;
	}
	if (l->data_len != r->data_len) {
		IG_BAD("%s: payload: live %llu bytes, the engine %u bytes\n", where, (unsigned long long)l->data_len, r->data_len);
		return;
	}
	if ((l->result < 0) != (r->result < 0) || (l->result < 0 && l->result != r->result)) {
		IG_BAD("%s: result: the real OSD %d, the simulated one %d\n", where, l->result, r->result);
		return;
	}
	g_cmp_pairs++;
	(void)s;
}

/* The requests of one command, in any order (a command that spans objects sends one request per object at once). */
static int live_key_cmp(const void *a, const void *b)
{
	const ig_live *x = (const ig_live *)a, *y = (const ig_live *)b;
	int c = strcmp(x->oid, y->oid);

	if (c != 0)
		return c;
	return x->code[0] < y->code[0] ? -1 : x->code[0] > y->code[0] ? 1 : x->off[0] < y->off[0] ? -1 : x->off[0] > y->off[0] ? 1 : 0;
}

static int rec_key_cmp(const void *a, const void *b)
{
	const sim_osd_rec *x = (const sim_osd_rec *)a, *y = (const sim_osd_rec *)b;
	int c = strcmp(x->oid, y->oid);

	if (c != 0)
		return c;
	return x->op_code[0] < y->op_code[0] ? -1 : x->op_code[0] > y->op_code[0] ? 1 : x->op_off[0] < y->op_off[0] ? -1 : x->op_off[0] > y->op_off[0] ? 1 : 0;
}

static void compare_group(const ig_sess *s, const char *label, unsigned a, unsigned b, const sim_osd_rec *recs)
{
	static ig_live live[IG_REC_MAX];
	static sim_osd_rec mine[IG_REC_MAX];
	unsigned i, n = b - a;

	if (n > IG_REC_MAX)
		return;
	for (i = 0; i < n; i++) {
		WRT_CHECK(live_of(s, a + i, &live[i]) == 0);
		mine[i] = recs[a + i];
	}
	qsort(live, n, sizeof(live[0]), live_key_cmp);
	qsort(mine, n, sizeof(mine[0]), rec_key_cmp);
	for (i = 0; i < n; i++) {
		char where[96];

		snprintf(where, sizeof(where), "%s %s request %u of %u", s->name, label, i + 1u, n);
		compare_pair(s, where, &live[i], &mine[i]);
	}
}

static void check_replay(ig_sess *s)
{
	static sim_osd_rec recs[IG_REC_MAX];
	cw w;
	wr_config cfg;
	sim_rbd_image_cfg ic;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	wr_image_info info;
	uint8_t *model, *buf;
	unsigned bounds[IG_CMD_MAX + 2u], nb = 0, i, n_rec;
	uint64_t o, n_obj, obj_size = 1ull << s->order;

	wr_config_profile_harness(&cfg);
	wr_config_enable_maps(&cfg, WR_MAPS_HARNESS);
	wr_config_enable_osd(&cfg, WR_MAPS_HARNESS);
	cfg.mon_msg_cap = 8u * 1024u * 1024u;
	cfg.max_images = 1;
	cfg.hdr_refresh_ms = 0; /* the capture's tool ran with --hdr-refresh 0 */
	WRT_CHECK(cw_open(&w, &cfg, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	memset(&ic, 0, sizeof(ic));
	ic.pool = CW_POOL;
	ic.name = s->image_name;
	ic.id = s->image_id;
	ic.size = s->size;
	ic.order = (uint8_t)s->order;
	ic.features = s->features;
	ic.data_pool = -1;
	ic.snap_seq = s->snap_seq;
	ic.n_snaps = s->n_snaps;
	for (i = 0; i < s->n_snaps; i++)
		ic.snaps[i] = s->snaps[i];
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(w.store, &ic));
	model = (uint8_t *)calloc(1, (size_t)s->size);
	buf = (uint8_t *)malloc(1u << 20);
	WRT_CHECK(model != NULL && buf != NULL);
	if (model == NULL || buf == NULL)
		goto out;
	n_obj = (s->size + obj_size - 1u) / obj_size;
	if (s->before != NULL) {
		WRT_CHECK_U64(s->before_n, s->size);
		memcpy(model, s->before, (size_t)s->size);
		for (o = 0; o < n_obj; o++) {
			char name[160];
			uint64_t len = s->size - o * obj_size < obj_size ? s->size - o * obj_size : obj_size;

			/* the object as the stock tool left it: written up to its last non-zero byte */
			while (len > 0 && s->before[o * obj_size + len - 1u] == 0)
				len--;
			if (len == 0)
				continue;
			snprintf(name, sizeof(name), "%s.%016" PRIx64, s->prefix, o);
			WRT_CHECK_STATUS(WR_OK, sim_store_write(w.store, CW_POOL, name, 0, s->before + o * obj_size, (size_t)len));
		}
	}
	p = cw_params(s->image_name, (int)s->writable);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN)
		goto out;
	WRT_CHECK_STATUS(WR_OK, wr_image_get_info(img, &info));
	WRT_CHECK_U64(info.size_bytes, s->size);
	WRT_CHECK_U64(info.order, s->order);
	WRT_CHECK_U64(info.features, s->features);
	WRT_CHECK_U64(info.n_snaps, s->n_snaps);
	WRT_CHECK_U64(info.snap_seq, s->snap_seq);
	WRT_CHECK(info.writable == s->writable);
	WRT_CHECK(strcmp(info.object_prefix, s->prefix) == 0);
	bounds[nb++] = collect(&w, recs, IG_REC_MAX); /* the open: the id lookup and the header read */
	for (i = 0; i < s->n_cmds; i++) {
		const ig_cmd *c = &s->cmd[i];
		wr_io_req r;
		wr_status want = WR_OK, st;

		WRT_CHECK(c->len <= (1u << 20) && c->off + c->len <= s->size);
		if (strcmp(c->op, "write") == 0) {
			ig_pat(buf, c->kind, c->arg, c->off, (size_t)c->len);
			r = cw_req(WR_IO_WRITE, c->off, c->len, buf);
			st = cw_do(&w, img, &r, 60000);
			memcpy(model + c->off, buf, (size_t)c->len);
		} else if (strcmp(c->op, "discard") == 0 || strcmp(c->op, "zeroes") == 0) {
			r = cw_req(strcmp(c->op, "discard") == 0 ? WR_IO_DISCARD : WR_IO_WRITE_ZEROES, c->off, c->len, NULL);
			st = cw_do(&w, img, &r, 60000);
			memset(model + c->off, 0, (size_t)c->len);
		} else { /* read, verify */
			memset(buf, 0xEE, (size_t)c->len);
			r = cw_req(WR_IO_READ, c->off, c->len, buf);
			st = cw_do(&w, img, &r, 60000);
			if (strcmp(c->op, "verify") == 0) {
				uint8_t *exp = (uint8_t *)malloc((size_t)c->len);

				WRT_CHECK(exp != NULL);
				if (exp != NULL) {
					ig_pat(exp, c->kind, c->arg, c->off, (size_t)c->len);
					WRT_CHECK(memcmp(buf, exp, (size_t)c->len) == 0);
					free(exp);
				}
			}
			WRT_CHECK(memcmp(buf, model + c->off, (size_t)c->len) == 0); /* what a read returns is what the script wrote before */
		}
		WRT_CHECK_STATUS(want, st);
		bounds[nb++] = collect(&w, recs, IG_REC_MAX);
	}
	n_rec = bounds[nb - 1u];
	/* the engine sent as many requests as the real one did, and command by command the same ones */
	WRT_CHECK_U64(n_rec, s->n_ex);
	if (n_rec == s->n_ex) {
		compare_group(s, "open", 0, bounds[0], recs);
		for (i = 0; i < s->n_cmds; i++) {
			char label[48];

			snprintf(label, sizeof(label), "command %u (%s)", i + 1u, s->cmd[i].op);
			compare_group(s, label, bounds[i], bounds[i + 1u], recs);
		}
	}
	/* the content: the whole image through the engine, and the objects of the store, equal the stock export */
	for (o = 0; o < s->size; o += 1u << 20) {
		uint64_t len = s->size - o < (1u << 20) ? s->size - o : (1u << 20);
		wr_io_req r = cw_req(WR_IO_READ, o, len, buf);

		WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 60000));
		WRT_CHECK(memcmp(buf, s->after + o, (size_t)len) == 0);
	}
	WRT_CHECK(memcmp(model, s->after, (size_t)s->size) == 0); /* the script itself, on a flat model, gives the export */
	for (o = 0; o < n_obj; o++) {
		char name[160];
		int exists = 0;
		uint8_t *tmp = (uint8_t *)malloc((size_t)obj_size);
		uint64_t len = s->size - o * obj_size < obj_size ? s->size - o * obj_size : obj_size;

		WRT_CHECK(tmp != NULL);
		if (tmp == NULL)
			break;
		snprintf(name, sizeof(name), "%s.%016" PRIx64, s->prefix, o);
		WRT_CHECK_STATUS(WR_OK, sim_store_read(w.store, CW_POOL, name, 0, tmp, (size_t)len, &exists));
		WRT_CHECK(memcmp(tmp, s->after + o * obj_size, (size_t)len) == 0);
		free(tmp);
	}
	WRT_CHECK_U64(sim_osd_n_violations(w.osd[0]) + sim_osd_n_violations(w.osd[1]) + sim_osd_n_violations(w.osd[2]), 0);
	if (s->writable == 0u) { /* a reader sent nothing that mutates */
		for (i = 0; i < n_rec; i++)
			WRT_CHECK(recs[i].mutating == 0);
	}
out:
	free(model);
	free(buf);
	cw_free(&w);
}

int main(void)
{
	static const char *const names[] = {"w4k", "snap64k", "rd64k"};
	unsigned i;
	wrt_json idx;
	int have_index;

	if (!ig_present())
		WRT_SKIP("harness/vectors/public/imgio is not in this tree");
	have_index = wrt_json_load_vec(&idx, "public/imgio/INDEX.json") == 0;
	WRT_CHECK(have_index);
	if (have_index) {
		wrt_tok sl = wrt_json_get(&idx, wrt_json_root(&idx), "sessions");

		WRT_CHECK_U64(wrt_json_count(&idx, sl), sizeof(names) / sizeof(names[0]));
		for (i = 0; i < wrt_json_count(&idx, sl); i++) {
			char *nm = wrt_json_strdup(&idx, wrt_json_at(&idx, sl, i));

			WRT_CHECK(nm != NULL && strcmp(nm, names[i]) == 0);
			free(nm);
		}
		wrt_json_free(&idx);
	}
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		ig_sess s;

		g_reported = 0;
		WRT_CHECK(ig_load(&s, names[i]) == 0);
		check_wire(&s);
		check_replay(&s);
		ig_free(&s);
	}
	printf("imgio.replay: %u requests re-encoded byte for byte, %u replies decoded, %u request/reply pairs compared with the simulated OSD (%u operations)\n",
	       g_wire_req, g_wire_rep, g_cmp_pairs, g_cmp_ops);
	WRT_CHECK(g_wire_req >= 30u && g_cmp_pairs == g_wire_req);
	return wrt_finish();
}
