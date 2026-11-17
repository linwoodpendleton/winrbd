/* SPDX-License-Identifier: MIT */
/*
 * sim_mon_maps.c - the monmap and osdmap store of the fake monitor and the subscription service:
 * MMonMap (mon-client.md 2.4, 3.4), MOSDMap v4 (2.6) and what a monitor does with a "monmap" /
 * "osdmap" subscription (2.5.1, 3.5.1). The default content is read from the committed vectors
 * (harness/vectors/monclient). Test code: libc allowed.
 */
#include "sim_mon_int.h"

#include "wrt.h"
#include "wrt_mapgen.h"

/* ---- vectors ------------------------------------------------------------------------------------ */

static int load_hex(const char *rel, const char *key, uint8_t **b, size_t *n)
{
	wrt_json j;
	int rc;

	if (wrt_json_load_vec(&j, rel) != 0)
		return -1;
	rc = wrt_json_get_hex(&j, wrt_json_root(&j), key, b, n);
	wrt_json_free(&j);
	return rc;
}

/* A MOSDMap v4 front (mon-client.md 2.6): store its incrementals and full maps; reports the bounds. */
static wr_status take_front(sim_mon *m, const uint8_t *p, size_t n, uint32_t *trim, uint32_t *newest)
{
	wri_rd r;
	uint32_t i, cnt;
	int pass;
	wr_status st = WR_OK;

	for (pass = 0; pass < 2 && st == WR_OK; pass++) { /* pass 0: incrementals, pass 1: full maps */
		if (pass == 0) {
			wri_rd_init(&r, p, n);
			wri_rd_skip(&r, 16);
		}
		cnt = wri_rd_count(&r, SIM_MON_MAX_EPOCHS, 8);
		for (i = 0; i < cnt && wri_rd_ok(&r) && st == WR_OK; i++) {
			uint32_t epoch = wri_rd_u32(&r), len = wri_rd_u32(&r);
			const uint8_t *b = wri_rd_bytes(&r, len);

			if (b == NULL)
				break;
			st = pass == 0 ? sim_mon_add_epoch(m, epoch, NULL, 0, b, len)
				       : sim_mon_add_epoch(m, epoch, b, len, NULL, 0);
		}
	}
	*trim = wri_rd_u32(&r);
	*newest = wri_rd_u32(&r);
	if (st == WR_OK && !wri_rd_ok(&r))
		st = r.err;
	return st;
}

wr_status sim_mon_maps_init(sim_mon *m)
{
	uint8_t *b = NULL;
	size_t n = 0;
	uint32_t trim = 0, newest = 0;
	wr_status st;

	if (m->cfg.monmap != NULL) {
		if (m->cfg.monmap_len < 26u || m->cfg.monmap_len > (1u << 20))
			return WR_E_INVAL;
		b = (uint8_t *)malloc(m->cfg.monmap_len);
		if (b == NULL)
			return WR_E_BUDGET;
		memcpy(b, m->cfg.monmap, m->cfg.monmap_len);
		n = m->cfg.monmap_len;
	} else if (load_hex("monclient/mmonmap-e3.json", "monmap_hex", &b, &n) != 0 || n < 26u) {
		fprintf(stderr, "sim_mon: cannot load monclient/mmonmap-e3.json\n");
		free(b);
		return WR_E_INVAL;
	}
	m->monmap = b;
	m->monmap_len = n;
	memcpy(m->fsid, b + 6, 16); /* struct header (v, compat, len) then the fsid, then the epoch */
	m->monmap_epoch = wri_le32_get(b + 22);
	if (m->cfg.no_default_osdmaps)
		return WR_OK;
	/* full map of epoch 42 */
	if (load_hex("monclient/mosdmap-v4-full-e42.json", "front_hex", &b, &n) != 0) {
		fprintf(stderr, "sim_mon: cannot load monclient/mosdmap-v4-full-e42.json\n");
		return WR_E_INVAL;
	}
	st = take_front(m, b, n, &trim, &newest);
	if (st == WR_OK) {
		m->trim_lower = trim; /* the MOSDMap header carries the monmap's fsid, whatever the stored blobs say */
		m->osd_newest = newest;
	}
	free(b);
	if (st != WR_OK)
		return st;
	/* incrementals of epochs 42 and 43 (synthetic vector): stored, 43 not yet committed */
	if (load_hex("monclient/mosdmap-v4-inc-e42-e43-synthetic.json", "front_hex", &b, &n) != 0) {
		fprintf(stderr, "sim_mon: cannot load the synthetic incremental vector\n");
		return WR_E_INVAL;
	}
	st = take_front(m, b, n, &trim, &newest);
	free(b);
	return st;
}

void sim_mon_maps_free(sim_mon *m)
{
	uint32_t i;

	for (i = 0; i < m->n_maps; i++) {
		free(m->maps[i].full);
		free(m->maps[i].inc);
	}
	m->n_maps = 0;
	free(m->monmap);
	m->monmap = NULL;
}

/* ---- the store ---------------------------------------------------------------------------------- */

static const sim_mon_epoch *find_epoch(const sim_mon *m, uint32_t e)
{
	uint32_t i;

	for (i = 0; i < m->n_maps; i++)
		if (m->maps[i].epoch == e)
			return &m->maps[i];
	return NULL;
}

wr_status sim_mon_add_epoch(sim_mon *m, uint32_t epoch, const uint8_t *full, size_t full_len, const uint8_t *inc,
			    size_t inc_len)
{
	uint32_t i, pos;
	sim_mon_epoch *e;
	uint8_t *cp_full = NULL, *cp_inc = NULL;

	if (epoch == 0 || (full == NULL && inc == NULL) || (full_len == 0 && full != NULL) ||
	    (inc_len == 0 && inc != NULL) || full_len > (32u << 20) || inc_len > (32u << 20))
		return WR_E_RANGE;
	for (pos = 0; pos < m->n_maps && m->maps[pos].epoch < epoch; pos++)
		;
	if ((pos == m->n_maps || m->maps[pos].epoch != epoch) && m->n_maps == SIM_MON_MAX_EPOCHS)
		return WR_E_BUDGET;
	/* copy first, then touch the store: a failed allocation leaves it exactly as it was */
	if (full != NULL) {
		cp_full = (uint8_t *)malloc(full_len);
		if (cp_full == NULL)
			return WR_E_BUDGET;
		memcpy(cp_full, full, full_len);
	}
	if (inc != NULL) {
		cp_inc = (uint8_t *)malloc(inc_len);
		if (cp_inc == NULL) {
			free(cp_full);
			return WR_E_BUDGET;
		}
		memcpy(cp_inc, inc, inc_len);
	}
	if (pos < m->n_maps && m->maps[pos].epoch == epoch) {
		e = &m->maps[pos];
	} else {
		for (i = m->n_maps; i > pos; i--)
			m->maps[i] = m->maps[i - 1u];
		e = &m->maps[pos];
		memset(e, 0, sizeof(*e));
		e->epoch = epoch;
		m->n_maps++;
	}
	if (cp_full != NULL) {
		free(e->full);
		e->full = cp_full;
		e->full_len = (uint32_t)full_len;
	}
	if (cp_inc != NULL) {
		free(e->inc);
		e->inc = cp_inc;
		e->inc_len = (uint32_t)inc_len;
	}
	return WR_OK;
}

/* ---- MMonMap --------------------------------------------------------------------------------------- */

void sim_mon_send_monmap(sim_mon_conn *c)
{
	sim_mon *m = c->mon;
	uint8_t *buf = sim_mon_scratch(m, m->monmap_len + 4u);

	if (buf == NULL || c->killed)
		return;
	wri_le32_put(buf, (uint32_t)m->monmap_len);
	memcpy(buf + 4, m->monmap, m->monmap_len);
	if (sim_mon_send_map_msg(c, (uint16_t)SIM_MSG_MON_MAP, 1, 1, buf, (uint32_t)(m->monmap_len + 4u)) == WR_OK) {
		c->n_monmap_sent++;
		m->n_monmap_sent++;
	}
}

/* "monmap": a map is sent when its epoch has reached the subscription's start (0 = now); a ONETIME
 * subscription then ends, a continuous one waits for the next epoch. */
void sim_mon_serve_monmap(sim_mon_conn *c)
{
	sim_mon *m = c->mon;

	if (c->killed || !c->sub_monmap.active || c->plan.silent)
		return;
	if (c->sub_monmap.start != 0 && c->sub_monmap.start > m->monmap_epoch)
		return;
	sim_mon_send_monmap(c);
	if ((c->sub_monmap.flags & SIM_SUB_ONETIME) != 0)
		c->sub_monmap.active = 0;
	else
		c->sub_monmap.start = (uint64_t)m->monmap_epoch + 1u;
}

wr_status sim_mon_bump_monmap(sim_mon *m)
{
	uint32_t i;

	m->monmap_epoch++;
	if (m->monmap_len >= 26u)
		wri_le32_put(m->monmap + 22, m->monmap_epoch);
	for (i = 0; i < SIM_MON_MAX_CONNS; i++)
		if (m->conns[i] != NULL)
			sim_mon_serve_monmap(m->conns[i]);
	return WR_OK;
}

/* ---- MOSDMap --------------------------------------------------------------------------------------- */

typedef struct ent {
	uint32_t epoch;
	const uint8_t *p;
	uint32_t len;
} ent;

/* One MOSDMap v4 message: fsid, incrementals, full maps, trim bound, newest_map, the removed-snaps block. */
static void emit_osdmap(sim_mon_conn *c, const ent *inc, unsigned ninc, const ent *full, unsigned nfull)
{
	sim_mon *m = c->mon;
	size_t need = 16u + 4u + 4u + 12u + (size_t)m->cfg.osdmap_pad;
	unsigned i;
	uint8_t *buf;
	wri_wr w;
	uint32_t trim = m->trim_lower != 0 ? m->trim_lower : (m->n_maps != 0 ? m->maps[0].epoch : 0);

	for (i = 0; i < ninc; i++)
		need += 8u + inc[i].len;
	for (i = 0; i < nfull; i++)
		need += 8u + full[i].len;
	buf = sim_mon_scratch(m, need);
	if (buf == NULL)
		return;
	wri_wr_init(&w, buf, need);
	wri_wr_bytes(&w, m->fsid, 16);
	wri_wr_u32(&w, ninc);
	for (i = 0; i < ninc; i++) {
		size_t pad = nfull == 0 && i + 1u == ninc ? m->cfg.osdmap_pad : 0u; /* the last blob of the message grows */

		wri_wr_u32(&w, inc[i].epoch);
		wri_wr_u32(&w, (uint32_t)(inc[i].len + pad));
		wri_wr_bytes(&w, inc[i].p, inc[i].len);
		wri_wr_zero(&w, pad);
	}
	wri_wr_u32(&w, nfull);
	for (i = 0; i < nfull; i++) {
		size_t pad = i + 1u == nfull ? m->cfg.osdmap_pad : 0u;

		wri_wr_u32(&w, full[i].epoch);
		wri_wr_u32(&w, (uint32_t)(full[i].len + pad));
		wri_wr_bytes(&w, full[i].p, full[i].len);
		wri_wr_zero(&w, pad);
	}
	wri_wr_u32(&w, trim);
	wri_wr_u32(&w, m->osd_newest);
	wri_wr_u32(&w, 0); /* removed snaps: always empty from a v20.2.5 sender */
	if (!wri_wr_ok(&w))
		return;
	if (sim_mon_send_map_msg(c, (uint16_t)SIM_MSG_OSD_MAP, 4, 3, buf, (uint32_t)wri_wr_len(&w)) == WR_OK) {
		c->n_osdmap_sent++;
		m->n_osdmap_sent++;
	}
}

static const sim_mon_epoch *highest_full_le(const sim_mon *m, uint32_t newest)
{
	const sim_mon_epoch *best = NULL;
	uint32_t i;

	for (i = 0; i < m->n_maps; i++)
		if (m->maps[i].epoch <= newest && m->maps[i].full != NULL)
			best = &m->maps[i];
	return best;
}

static const sim_mon_epoch *lowest_full(const sim_mon *m)
{
	uint32_t i;

	for (i = 0; i < m->n_maps; i++)
		if (m->maps[i].full != NULL)
			return &m->maps[i];
	return NULL;
}

/*
 * "osdmap" (mon-client.md 3.5.1): start 0 = one message with the latest full map; start N inside the
 * stored range = incrementals from N (a full map where no incremental is stored) in messages of at most
 * osd_map_message_max epochs; start older than the first stored epoch = the first full map alone, then
 * the incrementals after it; start above the newest committed epoch = nothing yet. Continuous
 * subscriptions get every chunk up to the newest epoch and keep waiting for the next one; ONETIME ones
 * get ONE chunk (plus the base full map message) and end. A hole in the store ends the run.
 */
void sim_mon_serve_osdmap(sim_mon_conn *c)
{
	sim_mon *m = c->mon;
	uint32_t newest = m->osd_newest, hi = 0, from, maxn = m->cfg.osd_map_message_max, e, k;
	int onetime = (c->sub_osdmap.flags & SIM_SUB_ONETIME) != 0, sent = 0, base_only = 0;
	ent inc[SIM_MON_MAX_EPOCHS] = {{0}}, full[SIM_MON_MAX_EPOCHS] = {{0}}; /* emit_osdmap gets inc with ninc 0 */
	unsigned ni, nf;
	const sim_mon_epoch *x;

	if (c->killed || !c->sub_osdmap.active || c->plan.silent || newest == 0 || m->n_maps == 0)
		return;
	if (c->sub_osdmap.start == 0) {
		x = highest_full_le(m, newest);
		if (x == NULL)
			return;
		ni = 0, nf = 0;
		full[nf].epoch = x->epoch, full[nf].p = x->full, full[nf].len = x->full_len, nf++;
		hi = x->epoch;
		for (e = x->epoch + 1u; e <= newest && ni + 1u < maxn; e++) { /* a store without a full map at the newest epoch */
			const sim_mon_epoch *y = find_epoch(m, e);

			if (y == NULL || y->inc == NULL)
				break;
			inc[ni].epoch = e, inc[ni].p = y->inc, inc[ni].len = y->inc_len, ni++;
			hi = e;
		}
		emit_osdmap(c, inc, ni, full, nf);
		sent = 1;
		from = hi + 1u;
		base_only = 1;
	} else if (c->sub_osdmap.start > newest) {
		return; /* the monitor sends it when that epoch is committed */
	} else {
		from = (uint32_t)c->sub_osdmap.start;
		hi = from - 1u;
		if (from < m->maps[0].epoch) {
			x = lowest_full(m);
			if (x == NULL)
				return;
			full[0].epoch = x->epoch, full[0].p = x->full, full[0].len = x->full_len;
			emit_osdmap(c, inc, 0, full, 1);
			sent = 1;
			hi = x->epoch;
			from = hi + 1u;
		}
	}
	while (!base_only && from <= newest) {
		ni = 0, nf = 0;
		for (e = from, k = 0; e <= newest && k < maxn; e++, k++) {
			x = find_epoch(m, e);
			if (x == NULL || (x->inc == NULL && x->full == NULL))
				break;
			if (x->inc != NULL)
				inc[ni].epoch = e, inc[ni].p = x->inc, inc[ni].len = x->inc_len, ni++;
			else
				full[nf].epoch = e, full[nf].p = x->full, full[nf].len = x->full_len, nf++;
			hi = e;
		}
		if (ni + nf == 0)
			break;
		emit_osdmap(c, inc, ni, full, nf);
		sent = 1;
		from = hi + 1u;
		if (onetime)
			break;
	}
	if (!sent)
		return;
	if (onetime)
		c->sub_osdmap.active = 0;
	else
		c->sub_osdmap.start = (uint64_t)hi + 1u;
}

wr_status sim_mon_push_epoch(sim_mon *m)
{
	uint32_t i;

	if (find_epoch(m, m->osd_newest + 1u) == NULL)
		return WR_E_RANGE;
	m->osd_newest++;
	for (i = 0; i < SIM_MON_MAX_CONNS; i++)
		if (m->conns[i] != NULL)
			sim_mon_serve_osdmap(m->conns[i]);
	return WR_OK;
}

/* ---- the lab chain of harness/vectors/osdmap as the monitor's store ----------------------------------------- */

/*
 * The default store (above) is the monclient capture: the real full map of epoch 42 and the two incrementals of epochs
 * 42 and 43. A test that wants the monitor to walk a longer chain loads the real one instead: osdmap/full-e42.hex and the
 * 89 stored incrementals of osdmap/incrementals.hex (the scrubbed copy of the same lab cluster, so its fsid is the scrubbed
 * one). Declared here and by the test that calls it; sim_mon.h belongs to another module and is not touched by this one.
 *
 * What the store then holds (SIM_MON_MAX_EPOCHS entries at most): epoch 42 with its full map AND its incremental, epochs
 * 43 .. last with their incrementals. The monitor serves it like any store: a start-0 subscription gets one MIXED message
 * (the full map of the newest epoch that has one, then the incrementals after it up to osd_newest), a continuous one gets
 * the incrementals as epochs are committed, a batch of epochs when several were committed since the last push. osd_newest
 * becomes `newest` (42 <= newest <= last <= 89); the epochs above it are committed by sim_mon_push_epoch(). The monitor's
 * fsid (the MOSDMap header and the MonMap blob a client learns it from) becomes the maps' own, so the client's fsid checks
 * pass. The previous store is dropped. WR_E_INVAL for arguments out of range or vectors that cannot be read.
 */
wr_status sim_mon_load_osdmap_vectors(sim_mon *m, uint32_t newest, uint32_t last);

wr_status sim_mon_load_osdmap_vectors(sim_mon *m, uint32_t newest, uint32_t last)
{
	uint8_t *full = NULL;
	size_t nfull = 0, nl = 0, i;
	wrt_mg_line *ls = NULL;
	wr_status st = WR_OK;
	uint32_t e;

	if (m == NULL || newest < 42u || last < newest || last > 89u || last - 42u + 1u > SIM_MON_MAX_EPOCHS)
		return WR_E_INVAL;
	if (wrt_mg_load_hex_file(wrt_vec_path("osdmap/full-e42.hex"), &full, &nfull) != 0)
		return WR_E_INVAL;
	if (wrt_mg_load_epoch_lines(wrt_vec_path("osdmap/incrementals.hex"), &ls, &nl) != 0 || nl != 89u || nfull < 28u ||
	    full[0] < 8u || m->monmap_len < 26u) {
		free(full);
		wrt_mg_free_lines(ls, nl);
		return WR_E_INVAL;
	}
	for (i = 0; i < m->n_maps; i++) { /* the old store goes */
		free(m->maps[i].full);
		free(m->maps[i].inc);
	}
	m->n_maps = 0;
	memcpy(m->fsid, full + 12, 16); /* wrapper envelope (6 bytes), client block envelope (6 bytes), then the fsid */
	memcpy(m->monmap + 6, m->fsid, 16);
	st = sim_mon_add_epoch(m, 42u, full, nfull, ls[41].p, ls[41].n);
	for (e = 43u; st == WR_OK && e <= last; e++)
		st = sim_mon_add_epoch(m, e, NULL, 0, ls[e - 1u].p, ls[e - 1u].n);
	m->osd_newest = newest;
	m->trim_lower = 0;
	free(full);
	wrt_mg_free_lines(ls, nl);
	return st;
}
