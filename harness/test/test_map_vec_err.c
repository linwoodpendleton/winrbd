/* SPDX-License-Identifier: MIT */
/*
 * test_map_vec_err.c - the error paths of the map decoders on REAL Ceph encodings: the committed full maps and incrementals,
 * damaged in every way a hostile or broken monitor could damage them, put through the same rig as the success vectors (inc_rig.h:
 * guard bytes, the held map untouched, magic 0 after a failure, wri_osdmap_check after a success, two pre-fills of the slot).
 *
 *   full maps (osdmap/full-e42.hex, public/mapb/base-e666.hex)
 *       every prefix of the blob is refused (CRC check on and off); every single-byte change (three masks) is refused when the CRC
 *       is checked, and with the check off is either refused with a map status or yields a map that passes the structural check;
 *       a slot one byte short is WR_E_MAP_BUDGET, a slot of exactly the map's size is enough; max_osd above the configured limit is
 *       WR_E_MAP_BUDGET
 *   incrementals (public/mapb: 259 of them applied in order)
 *       at every epoch: the next-but-one epoch, the previous epoch and a repeat are WR_E_MAP_EPOCH; a changed fsid is
 *       WR_E_MAP_FSID (CRC off) or a CRC / fsid refusal (CRC on); a held map decoded with another tracked set is WR_E_MAP_RESYNC;
 *       the result needs exactly the bytes it says (one short is WR_E_MAP_BUDGET)
 *       for the eight largest incrementals every prefix and every single-byte change, for the others a spread of positions
 *   placement
 *       a work budget too small for the CRUSH walk is WR_E_CRUSH_WORK and leaves a clean result; a pool index that is not tracked is
 *       WR_E_POOL_NOT_FOUND; both leave the workspace usable for the next call
 *
 *   CRUSH blobs (public/mapb/crush: 18 maps, crush/crush-getcrushmap.hex)
 *       every prefix is refused or (at a tail boundary) gives a sound region; every changed byte is refused at decode with a documented status, or gives a region that passes
 *       wri_crush_check and on which rules 0 to 2 map four seeds under a work budget: a result of device or bucket ids that fits the room, or
 *       a documented status, and a rule the audit accepted never fails with NO_RULE / UNSUPPORTED / LOOP
 *
 * The first unexpected status stops the run with the file, the position and the byte that was changed.
 */
#include "map_vec_rig.h"

static unsigned n_cases;

static void err_die(const char *what, const char *set, size_t pos, unsigned mask, int verify, wr_status got)
{
	fprintf(stderr, "MISMATCH %s: %s at byte %u (mask 0x%02x, crc check %d): status %d (%s)\n", set, what, (unsigned)pos, mask, verify, (int)got,
		wrt_status_name_(got));
	mv_die();
}

/* Decode `blob` into a fresh slot of `cap` bytes; the rig's checks run inside. */
static wr_status dec(const wri_mapcfg *cfg, const uint8_t *blob, size_t n, size_t cap, wr_errinfo *why)
{
	islot s;
	wr_status st;

	islot_new(&s, cap);
	st = rig_decode(cfg, blob, n, &s, why);
	islot_free(&s);
	n_cases++;
	return st;
}

/* Apply `blob` to `held` into a fresh slot of `cap` bytes. */
static wr_status app(const wri_mapcfg *cfg, const wri_osdmap *held, const uint8_t *blob, size_t n, size_t cap, wr_errinfo *why)
{
	islot s;
	wr_status st;

	islot_new(&s, cap);
	st = rig_apply(cfg, held, blob, n, &s, why);
	islot_free(&s);
	n_cases++;
	return st;
}

/* ---- full maps ------------------------------------------------------------------------------------------------------------ */

static void full_damage(const char *rel, const char *const *names, unsigned nn, uint32_t want_osds)
{
	static const unsigned masks[3] = {0x01u, 0x80u, 0xFFu};
	uint8_t *blob = NULL, *w;
	size_t n = 0, i, cap;
	wri_mapcfg cfg, cfg_nocrc;
	islot big;
	wr_errinfo why = { 0 };
	unsigned mi, refused_on = 0, refused_off = 0, built_off = 0;
	uint32_t bytes, max_osd;

	mv_load_hex(rel, &blob, &n);
	rig_cfg(&cfg, RIG_SLOT_BYTES, MV_MAX_OSD, 1, names, nn);
	rig_cfg(&cfg_nocrc, RIG_SLOT_BYTES, MV_MAX_OSD, 0, names, nn);
	islot_new(&big, RIG_SLOT_BYTES);
	if (rig_decode(&cfg, blob, n, &big, &why) != WR_OK) {
		fprintf(stderr, "map-vectors: %s does not decode: %s\n", rel, why.what != NULL ? why.what : "?");
		mv_die();
	}
	bytes = islot_map(&big)->bytes;
	max_osd = islot_map(&big)->max_osd;
	WRT_CHECK_U64(max_osd, want_osds);
	islot_free(&big);
	cap = (size_t)bytes + 4096u;
	cfg.slot_bytes = cfg_nocrc.slot_bytes = (uint32_t)cap;

	/* the slot: the map's own size is enough, one byte less is a budget refusal and writes nothing outside */
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, blob, n, bytes, &why));
	{
		static const size_t shorts[] = {1, 2, 15, 16, 17, 63, 64, 100, 255, 1000, 4096};
		size_t k;

		for (k = 0; k < sizeof(shorts) / sizeof(shorts[0]); k++)
			if (shorts[k] < bytes) {
				wr_status st = dec(&cfg, blob, n, bytes - shorts[k], &why);

				if (st != WR_E_MAP_BUDGET)
					err_die("a slot too small for the map", rel, shorts[k], 0, 1, st);
			}
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, dec(&cfg, blob, n, 0, &why));
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, dec(&cfg, blob, n, 3, &why));
	}
	/* max_osd above what the configuration accepts */
	{
		wri_mapcfg small = cfg;

		small.max_osd = max_osd - 1u;
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, dec(&small, blob, n, cap, &why));
		small.max_osd = 0;
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, dec(&small, blob, n, cap, &why));
		small.max_osd = max_osd;
		WRT_CHECK_STATUS(WR_OK, dec(&small, blob, n, cap, &why));
	}

	/* every prefix is refused, with the CRC check on and off */
	for (i = 0; i < n; i++) {
		wr_status a = dec(&cfg, blob, i, cap, &why), b = dec(&cfg_nocrc, blob, i, cap, &why);

		if (a == WR_OK || !rig_status_is_map(a))
			err_die("prefix, crc check on", rel, i, 0, 1, a);
		if (b == WR_OK || !rig_status_is_map(b))
			err_die("prefix, crc check off", rel, i, 0, 0, b);
	}
	/* extra bytes after the blob: whatever the answer is, the rig's invariants hold */
	{
		uint8_t *more = (uint8_t *)malloc(n + 9u);

		if (more == NULL) {
			fprintf(stderr, "out of memory\n");
			exit(2);
		}
		memcpy(more, blob, n);
		memset(more + n, 0xA7, 9);
		(void)dec(&cfg, more, n + 1u, cap, &why);
		(void)dec(&cfg, more, n + 9u, cap, &why);
		(void)dec(&cfg_nocrc, more, n + 9u, cap, &why);
		free(more);
	}
	/* every byte changed, three ways */
	w = (uint8_t *)malloc(n);
	if (w == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	for (mi = 0; mi < 3; mi++)
		for (i = 0; i < n; i++) {
			wr_status a, b;

			memcpy(w, blob, n);
			w[i] ^= (uint8_t)masks[mi];
			a = dec(&cfg, w, n, cap, &why);
			if (a == WR_OK || !rig_status_is_map(a))
				err_die("changed byte, crc check on", rel, i, masks[mi], 1, a);
			refused_on++;
			b = dec(&cfg_nocrc, w, n, cap, &why);
			if (b == WR_OK)
				built_off++;
			else if (!rig_status_is_map(b))
				err_die("changed byte, crc check off", rel, i, masks[mi], 0, b);
			else
				refused_off++;
		}
	free(w);
	free(blob);
	fprintf(stderr, "%s: %zu prefixes and %u changed bytes refused with the CRC check on; with it off %u refused, %u gave a map that passes the structural check\n",
		rel, n, refused_on, refused_off, built_off);
}

static void test_full(void)
{
	static const char *const a[] = {".mgr", "winrbd"};

	full_damage("osdmap/full-e42.hex", a, 2, 3);
	full_damage("public/mapb/base-e666.hex", mv_set_a, MV_SET_A_N, 3);
}

/* ---- incrementals -------------------------------------------------------------------------------------------------------- */

typedef struct inc_pick {
	size_t idx[8];
	size_t len[8];
} inc_pick;

/* The eight largest incrementals of the list get the full sweeps. */
static void pick_largest(const wrt_mg_line *ls, size_t nl, inc_pick *p)
{
	size_t i, k;

	for (k = 0; k < 8; k++)
		p->len[k] = 0;
	for (i = 0; i < nl; i++)
		for (k = 0; k < 8; k++)
			if (ls[i].n > p->len[k]) {
				size_t j;

				for (j = 7; j > k; j--) {
					p->len[j] = p->len[j - 1];
					p->idx[j] = p->idx[j - 1];
				}
				p->len[k] = ls[i].n;
				p->idx[k] = i;
				break;
			}
}

static int is_picked(const inc_pick *p, size_t i)
{
	size_t k;

	for (k = 0; k < 8; k++)
		if (p->idx[k] == i && p->len[k] != 0)
			return 1;
	return 0;
}

/* One damaged copy of an incremental. verify on: must be refused; off: refused with a map status or a map that passes the check. */
static void inc_one(const wri_mapcfg *cfg_on, const wri_mapcfg *cfg_off, const wri_osdmap *held, const uint8_t *w, size_t n, size_t cap, size_t pos,
		    unsigned mask, int is_prefix, unsigned *refused_on, unsigned *built_off)
{
	wr_errinfo why = { 0 };
	wr_status a = app(cfg_on, held, w, n, cap, &why), b = app(cfg_off, held, w, n, cap, &why);

	if (a == WR_OK || !rig_status_is_map(a))
		err_die(is_prefix ? "incremental prefix, crc check on" : "incremental changed byte, crc check on", "public/mapb/incrementals.hex", pos, mask, 1, a);
	(*refused_on)++;
	if (b == WR_OK) {
		if (is_prefix)
			err_die("incremental prefix, crc check off", "public/mapb/incrementals.hex", pos, mask, 0, b);
		(*built_off)++;
	} else if (!rig_status_is_map(b)) {
		err_die(is_prefix ? "incremental prefix, crc check off" : "incremental changed byte, crc check off", "public/mapb/incrementals.hex", pos, mask, 0, b);
	}
}

static size_t find16(const uint8_t *p, size_t n, const uint8_t *key)
{
	size_t i, k;

	for (i = 0; i + 16u <= n; i++) {
		for (k = 0; k < 16u && p[i + k] == key[k]; k++)
			;
		if (k == 16u)
			return i;
	}
	return (size_t)-1;
}

static void test_incrementals(void)
{
	wrt_mg_line *ls = NULL;
	size_t nl = 0, i, nbase = 0;
	uint8_t *base = NULL;
	mv_chain c;
	wri_mapcfg cfg_off, cfg_less;
	wr_errinfo why = { 0 };
	inc_pick pick;
	unsigned refused_on = 0, built_off = 0, fsid_cases = 0, epoch_cases = 0, budget_cases = 0, resync_cases = 0;

	if (wrt_mg_load_epoch_lines(wrt_vec_path("public/mapb/incrementals.hex"), &ls, &nl) != 0 || nl != 259u) {
		fprintf(stderr, "map-vectors: public/mapb/incrementals.hex must hold 259 incrementals\n");
		mv_die();
	}
	pick_largest(ls, nl, &pick);
	mv_load_hex("public/mapb/base-e666.hex", &base, &nbase);
	mv_chain_open(&c, mv_set_a, MV_SET_A_N);
	cfg_off = c.cfg;
	cfg_off.verify_crc = 0;
	cfg_less = c.cfg;
	cfg_less.n_pools = (uint8_t)(c.cfg.n_pools - 1u);
	if (mv_chain_full(&c, base, nbase, &why) != WR_OK) {
		fprintf(stderr, "map-vectors: public/mapb/base-e666.hex does not decode\n");
		mv_die();
	}
	for (i = 0; i < nl; i++) {
		const wri_osdmap *held = mv_chain_map(&c);
		size_t cap = (size_t)held->bytes * 2u + 16384u, n = ls[i].n, k, step, pos;
		uint8_t *w;
		wr_status st;
		islot ok;
		uint32_t need;
		wr_errinfo e2;

		/* the incremental itself: apply it, and learn the bytes the result needs */
		islot_new(&ok, cap);
		st = rig_apply(&c.cfg, held, ls[i].p, n, &ok, &e2);
		if (st != WR_OK) {
			fprintf(stderr, "map-vectors: mapb chain, epoch %u: %s\n", ls[i].epoch, e2.what != NULL ? e2.what : "does not follow");
			mv_die();
		}
		need = islot_map(&ok)->bytes;
		islot_free(&ok);

		/* the slot is exactly big enough, or one byte short */
		WRT_CHECK_STATUS(WR_OK, app(&c.cfg, held, ls[i].p, n, need, &why));
		st = app(&c.cfg, held, ls[i].p, n, need - 1u, &why);
		if (st != WR_E_MAP_BUDGET)
			err_die("a result slot one byte short", "public/mapb/incrementals.hex", ls[i].epoch, 0, 1, st);
		budget_cases++;

		/* the epoch: skip one, go back, repeat */
		if (i + 1u < nl) {
			st = app(&c.cfg, held, ls[i + 1u].p, ls[i + 1u].n, cap, &why);
			if (st != WR_E_MAP_EPOCH)
				err_die("the incremental after the next", "public/mapb/incrementals.hex", ls[i + 1u].epoch, 0, 1, st);
			epoch_cases++;
		}
		if (i > 0) {
			st = app(&c.cfg, held, ls[i - 1u].p, ls[i - 1u].n, cap, &why);
			if (st != WR_E_MAP_EPOCH)
				err_die("the previous incremental", "public/mapb/incrementals.hex", ls[i - 1u].epoch, 0, 1, st);
			epoch_cases++;
		}

		/* the fsid: one byte of it changed (the CRC off: the identity check says so; on: the CRC may be first) */
		w = rig_dup(ls[i].p, n);
		pos = find16(w, n, held->fsid);
		if (pos == (size_t)-1) {
			fprintf(stderr, "map-vectors: the fsid is not in the incremental of epoch %u\n", ls[i].epoch);
			mv_die();
		}
		w[pos + 7u] ^= 0x10u;
		st = app(&cfg_off, held, w, n, cap, &why);
		if (st != WR_E_MAP_FSID)
			err_die("fsid changed, crc check off", "public/mapb/incrementals.hex", pos + 7u, 0x10u, 0, st);
		st = app(&c.cfg, held, w, n, cap, &why);
		if (st != WR_E_MAP_FSID && st != WR_E_MAP_CRC)
			err_die("fsid changed, crc check on", "public/mapb/incrementals.hex", pos + 7u, 0x10u, 1, st);
		fsid_cases++;

		/* a held map built with one tracked name more cannot be advanced with a configuration that has one less */
		st = app(&cfg_less, held, ls[i].p, n, cap, &why);
		if (st != WR_E_MAP_RESYNC)
			err_die("a configuration with another number of tracked pools", "public/mapb/incrementals.hex", ls[i].epoch, 0, 1, st);
		resync_cases++;

		/* damage: all of it for the largest, a spread of positions for the rest */
		step = is_picked(&pick, i) ? 1u : (n / 24u > 0 ? n / 24u : 1u); /* every position, or 24 of them */
		memcpy(w, ls[i].p, n);
		for (k = 0; k < n; k += step) {
			inc_one(&c.cfg, &cfg_off, held, w, k, cap, k, 0, 1, &refused_on, &built_off); /* prefix of k bytes */
		}
		for (k = 0; k < n; k += step) {
			unsigned mi;

			for (mi = 0; mi < (is_picked(&pick, i) ? 3u : 1u); mi++) {
				static const unsigned masks[3] = {0x01u, 0x80u, 0xFFu};

				memcpy(w, ls[i].p, n);
				w[k] ^= (uint8_t)masks[mi];
				inc_one(&c.cfg, &cfg_off, held, w, n, cap, k, masks[mi], 0, &refused_on, &built_off);
			}
		}
		free(w);
		if (mv_chain_inc(&c, ls[i].p, n, &why) != WR_OK) {
			fprintf(stderr, "map-vectors: mapb chain, epoch %u does not follow\n", ls[i].epoch);
			mv_die();
		}
	}
	/* a repeat of the incremental just applied */
	{
		wr_status st = app(&c.cfg, mv_chain_map(&c), ls[nl - 1u].p, ls[nl - 1u].n, (size_t)mv_chain_map(&c)->bytes * 2u + 16384u, &why);

		if (st != WR_E_MAP_EPOCH)
			err_die("a repeat of the last incremental", "public/mapb/incrementals.hex", ls[nl - 1u].epoch, 0, 1, st);
		epoch_cases++;
	}
	WRT_CHECK_U64(mv_chain_map(&c)->epoch, 925);
	fprintf(stderr,
		"public/mapb/incrementals.hex: %u damaged copies refused with the CRC check on (%u of them built a map with it off); %u epoch, %u fsid, %u tracked-set and %u budget cases\n",
		refused_on, built_off, epoch_cases, fsid_cases, resync_cases, budget_cases);
	mv_chain_close(&c);
	free(base);
	wrt_mg_free_lines(ls, nl);
}

/* ---- placement ----------------------------------------------------------------------------------------------------------- */

static void test_place_errors(void)
{
	static const char *const names[] = {".mgr", "winrbd"};
	uint8_t *blob = NULL;
	size_t n = 0;
	wri_mapcfg cfg;
	islot s;
	wr_errinfo why = { 0 };
	const wri_osdmap *m;
	wri_pg_result res, good;
	wri_crush_ws ws;
	int widx;
	uint32_t seed;

	mv_load_hex("osdmap/full-e42.hex", &blob, &n);
	rig_cfg(&cfg, RIG_SLOT_BYTES, MV_MAX_OSD, 1, names, 2);
	if (mv_decode_one(&cfg, blob, n, &s, &why) != WR_OK) {
		fprintf(stderr, "map-vectors: osdmap/full-e42.hex does not decode\n");
		mv_die();
	}
	m = islot_map(&s);
	widx = mv_pool_idx(m, 2);
	WRT_CHECK(widx >= 0);
	memset(&ws, 0, sizeof(ws));
	for (seed = 0; seed < wri_map_pools(m)[widx].pg_num; seed++) {
		uint32_t w;

		WRT_CHECK_STATUS(WR_OK, wri_place_pg(m, (uint32_t)widx, seed, MV_WORK_MAX, &ws, &good, NULL));
		WRT_CHECK(good.n_acting != 0);
		/* a budget of 0, 1 or 2 bucket evaluations cannot fit a three-replica mapping over hosts: refused, and a clean result */
		for (w = 0; w < 3; w++) {
			memset(&res, 0x5A, sizeof(res));
			memset(&why, 0, sizeof(why));
			WRT_CHECK_STATUS(WR_E_CRUSH_WORK, wri_place_pg(m, (uint32_t)widx, seed, w, &ws, &res, &why));
			WRT_CHECK_U64(res.n_raw, 0);
			WRT_CHECK_U64(res.n_up, 0);
			WRT_CHECK_U64(res.n_acting, 0);
			WRT_CHECK(res.up_primary == -1 && res.acting_primary == -1);
			WRT_CHECK_STATUS(WR_E_CRUSH_WORK, why.status);
		}
		/* the workspace is reusable: the same PG, enough budget, gives the same answer as before */
		WRT_CHECK_STATUS(WR_OK, wri_place_pg(m, (uint32_t)widx, seed, MV_WORK_MAX, &ws, &res, NULL));
		WRT_CHECK(memcmp(&res, &good, sizeof(res)) == 0);
	}
	/* a pool index that is not tracked, or not in the map */
	memset(&res, 0x5A, sizeof(res));
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wri_place_pg(m, m->n_pools, 0, MV_WORK_MAX, &ws, &res, &why));
	WRT_CHECK_U64(res.n_acting, 0);
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wri_place_pg(m, 0xFFFFFFFFu, 0, MV_WORK_MAX, &ws, &res, &why));
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wri_place_pg(m, WRI_MAP_POOLS_MAX, 0, MV_WORK_MAX, &ws, &res, &why));
	/* a PG seed above pg_num names no PG: the call still answers (no table entry is found), it must not read outside anything */
	WRT_CHECK_STATUS(WR_OK, wri_place_pg(m, (uint32_t)widx, 0xFFFFFFFFu, MV_WORK_MAX, &ws, &res, &why));
	islot_free(&s);
	free(blob);
	fprintf(stderr, "osdmap/full-e42.hex: work budgets 0..2, an untracked pool index and an out-of-range PG seed answered as documented\n");
}

/* ---- the CRUSH blobs --------------------------------------------------------------------------------------------------------- */

/* A hostile CRUSH map must be refused at decode with a documented status, or give a region that passes the structural check and
 * on which every mapping ends in one of a few documented ways: a result of valid device ids that fits the caller's room, or a
 * status. A rule the audit accepted must not fail later with a reason the audit exists to catch. */
static int crush_dec_status_ok(wr_status st)
{
	return st == WR_E_CRUSH_ENCODING || st == WR_E_CRUSH_UNSUPPORTED || st == WR_E_MAP_BUDGET || st == WR_E_MAP_VERSION || st == WR_E_MAP_CORRUPT;
}

static void crush_blob_damage(const char *rel, unsigned *n_dec_ok, unsigned *n_dec_bad, unsigned *n_maps)
{
	static const unsigned masks[2] = {0x01u, 0xFFu};
	uint8_t *blob = NULL, *w, *mem;
	size_t n = 0, i, cap;
	unsigned mi;

	mv_load_hex(rel, &blob, &n);
	cap = n * 4u + 65536u;
	mem = (uint8_t *)malloc(cap);
	w = (uint8_t *)malloc(n);
	if (mem == NULL || w == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	for (mi = 0; mi < 2; mi++)
		for (i = 0; i <= n; i++) {
			wri_crush_ws ws;
			wr_errinfo why = { 0 };
			size_t used = 0;
			uint32_t rule, x, nd, wn;
			const wri_crush *c;
			uint32_t *weights;
			wr_status st;

			memcpy(w, blob, n);
			if (i == n) { /* the last round: the blob cut at every length is covered below; this one is the undamaged blob */
				if (mi != 0)
					break;
			} else {
				w[i] ^= (uint8_t)masks[mi];
			}
			memset(mem, 0xC3, cap);
			memset(&why, 0, sizeof(why));
			st = wri_crush_decode(w, n, mem, cap, &used, &why);
			n_cases++;
			if (st != WR_OK) {
				if (!crush_dec_status_ok(st) || i == n)
					err_die("a changed CRUSH byte (decode)", rel, i, masks[mi], 0, st);
				(*n_dec_bad)++;
				continue;
			}
			(*n_dec_ok)++;
			c = (const wri_crush *)(const void *)mem;
			if (wri_crush_check(c, used) != WR_OK)
				err_die("a CRUSH region that decode accepted fails wri_crush_check", rel, i, masks[mi], 0, WR_E_CRUSH_ENCODING);
			nd = (uint32_t)c->max_devices;
			/* a bucket item with a huge device id raises max_devices (as in the reference); nothing is sized by it, and the caller's weight
			 * array is as long as the caller made it: an id at or above weight_max is out */
			wn = nd < 64u ? nd : 64u;
			weights = (uint32_t *)malloc(((size_t)wn + 1u) * sizeof(uint32_t));
			if (weights == NULL) {
				fprintf(stderr, "out of memory\n");
				exit(2);
			}
			for (x = 0; x < wn; x++)
				weights[x] = (x % 5u == 4u) ? 0x8000u : WRI_OSD_IN_FULL;
			for (rule = 0; rule < c->max_rules && rule < 3u; rule++) {
				wr_status ast = wri_crush_audit_rule(c, rule, 3u, NULL);

				for (x = 0; x < 4u; x++) {
					wri_crush_in in;
					int32_t got[WRI_CRUSH_RESULT_MAX];
					uint32_t ng = 0xDEADu, q;
					wr_status ms;

					memset(&ws, 0, sizeof(ws));
					ws.work = 20000u;
					in.rule = rule;
					in.x = x * 2654435761u;
					in.result_max = 3u;
					in.osd_weight = weights;
					in.weight_max = wn;
					in.args_pool = (int32_t)(x & 1u);
					ms = wri_crush_do_rule(c, &in, &ws, got, &ng, &why);
					if (ms == WR_OK) {
						if (ng > 3u)
							err_die("a mapping returned more than the room", rel, i, masks[mi], 0, ms);
						for (q = 0; q < ng; q++)
							/* a choose step of a type above 0 emits bucket ids: valid for the reference too, and every consumer bounds-checks an OSD id */
							if (got[q] >= 0 ? (uint32_t)got[q] >= nd : (uint32_t)(-1 - got[q]) >= c->max_buckets) {
								fprintf(stderr, "  rule %u x %u: result %u is %d, the map has %u devices and %u bucket slots\n", (unsigned)rule, (unsigned)in.x, (unsigned)q, (int)got[q],
									(unsigned)nd, (unsigned)c->max_buckets);
								err_die("a mapping returned an id that is neither a device nor a bucket", rel, i, masks[mi], 0, ms);
							}
					} else if (ms == WR_E_CRUSH_WORK) {
						/* a budget refusal is always allowed */
					} else if (ast == WR_OK || (ms != WR_E_CRUSH_NO_RULE && ms != WR_E_CRUSH_UNSUPPORTED && ms != WR_E_CRUSH_LOOP)) {
						err_die(ast == WR_OK ? "a mapping failed after the audit accepted the rule" : "a mapping failed with an undocumented status", rel, i,
							masks[mi], 0, ms);
					}
				}
			}
			free(weights);
			(*n_maps)++;
		}
	/* every prefix of the blob */
	for (i = 0; i < n; i++) {
		size_t used = 0;
		wr_errinfo why = { 0 };
		wr_status st = wri_crush_decode(blob, i, mem, cap, &used, &why);

		n_cases++;
		/* the tail of a CRUSH map (tunables, classes, choose_args) is optional on the wire, so a prefix that ends at a tail boundary is a
		 * valid older encoding: it may decode, and then the region must be sound */
		if (st == WR_OK ? wri_crush_check((const wri_crush *)(const void *)mem, used) != WR_OK : !crush_dec_status_ok(st))
			err_die("a prefix of a CRUSH blob", rel, i, 0, 0, st);
	}
	free(w);
	free(mem);
	free(blob);
}

static void test_crush_blobs(void)
{
	wrt_json idx;
	wrt_tok crush;
	size_t i;
	unsigned ok = 0, bad = 0, maps = 0;

	mv_load_json(&idx, "public/mapb/INDEX.json");
	crush = wrt_json_get(&idx, wrt_json_root(&idx), "crush");
	for (i = 0; i < wrt_json_count(&idx, crush); i++) {
		char *h = wrt_json_strdup(&idx, wrt_json_get(&idx, wrt_json_at(&idx, crush, i), "crush")), rel[300];

		if (h == NULL) {
			fprintf(stderr, "map-vectors: INDEX.json crush entry %u has no file\n", (unsigned)i);
			mv_die();
		}
		snprintf(rel, sizeof(rel), "public/mapb/%s", h);
		free(h);
		crush_blob_damage(rel, &ok, &bad, &maps);
	}
	crush_blob_damage("crush/crush-getcrushmap.hex", &ok, &bad, &maps);
	WRT_CHECK(ok > 1000 && bad > 1000);
	WRT_CHECK_U64(maps, ok);
	fprintf(stderr, "CRUSH blobs: %u damaged copies refused at decode, %u decoded and mapped under a work budget (no undocumented status, no id outside the devices and buckets)\n",
		bad, ok);
	wrt_json_free(&idx);
}

int main(void)
{
	test_full();
	test_incrementals();
	test_place_errors();
	test_crush_blobs();
	fprintf(stderr, "map-vectors error paths: %u decodes / applies\n", n_cases);
	return wrt_finish();
}
