/* SPDX-License-Identifier: MIT */
/*
 * wri_client_mem.c - configuration check, memory layout and create-time carving of the engine.
 *
 * One routine, parts_take(), walks the arena allocations of the engine in a fixed order. It runs in
 * two modes: PLAN (no arena, only the byte arithmetic) for wr_client_mem_required, and TAKE (real
 * arena) for create. Both modes execute the same code, so the size a host is told and the bytes
 * create consumes cannot drift apart; the cephx client and the monitor client contribute their own
 * *_mem() sizes in plan mode and their own init functions in take mode.
 *
 * Every allocation uses an alignment of 16 bytes or less (the host contract for the regions), so
 * the padding is the same for every legal base address and the plan is exact.
 *
 * The OSD map store (wri_mapstore.h) is embedded in the client struct (that is part of the first take), and when
 * map_slot_bytes != 0 it adds its placement cache to the arena (after the cephx client's part) and two map slots to
 * the bulk (after the monitor client's part); the sizes are planned with the same takes the store's init makes.
 */
#include "wri_client.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define SEG_CAP_FACTOR 4u               /* segments 1..3 may be this many times mon_msg_cap, so an oversized map */
#define SEG_CAP_MAX (256u * 1024u * 1024u) /* front is read and discarded instead of killing the connection */

/* ---- configuration ----------------------------------------------------------------------------- */

static wr_status check_cfg(const wr_config *cfg)
{
	if (cfg == NULL)
		return WR_E_INVAL;
	if (cfg->size != (uint32_t)sizeof(wr_config) || cfg->abi != WR_ABI_VERSION)
		return WR_E_ABI;
	if (cfg->max_conns < 2u || cfg->max_conns > WRI_CLIENT_CONNS_MAX)
		return WR_E_INVAL;
	if (cfg->max_handshakes < 1u || cfg->max_handshakes > cfg->max_conns || cfg->max_handshakes > WRI_CLIENT_HANDSHAKES_MAX)
		return WR_E_INVAL;
	if (cfg->rx_buf_bytes < WRI_CLIENT_RX_MIN || cfg->ctl_buf_bytes < WRI_CLIENT_CTL_MIN ||
	    cfg->tx_buf_bytes < WRI_CLIENT_TX_MIN || cfg->preauth_cap < WRI_CLIENT_PREAUTH_MIN)
		return WR_E_INVAL;
	/* room for an authentication payload with a ticket in it, see WRI_CLIENT_AUTH_SLACK */
	if ((uint64_t)cfg->tx_buf_bytes <
	    2u * ((uint64_t)cfg->ticket_cap + WRI_CLIENT_AUTH_SLACK) + WRI_CLIENT_TX_FRAME)
		return WR_E_INVAL;
	if (cfg->mode_policy != WR_MODE_CRC_ONLY)
		return WR_E_UNSUPPORTED; /* crc is the only connection mode implemented so far */
	/* the map module (map_slot_bytes != 0): map_pools 1..8, a slot of at least 16 KiB, map_max_osd within the hard cap, a
	 * non-zero CRUSH work budget; wri_mapstore_mem is the one place that knows (and refuses the rest with WR_E_INVAL) */
	if (cfg->map_slot_bytes != 0u) {
		size_t ma = 0, mb = 0;

		return wri_mapstore_mem(cfg, &ma, &mb);
	}
	return WR_OK;
}

static uint32_t seg_cap_for(const wr_config *cfg)
{
	uint64_t big = (uint64_t)cfg->mon_msg_cap * SEG_CAP_FACTOR;
	uint64_t cap = big > SEG_CAP_MAX ? SEG_CAP_MAX : big;

	if (cap < cfg->mon_msg_cap)
		cap = cfg->mon_msg_cap;
	if (cap < cfg->ctl_buf_bytes)
		cap = cfg->ctl_buf_bytes;
	return (uint32_t)cap;
}

/* ---- the allocation walk ------------------------------------------------------------------------ */

typedef struct take {
	wri_arena *a;   /* NULL = plan mode */
	size_t used;    /* plan mode: bytes so far */
	wr_status st;
} take;

/* count objects of elem bytes, 16-byte aligned. Plan mode returns NULL and only counts. */
static void *tk(take *t, size_t count, size_t elem)
{
	void *p;

	if (t->st != WR_OK)
		return NULL;
	if (t->a == NULL) {
		t->st = wri_arena_plan_array(&t->used, count, elem, 16u);
		return NULL;
	}
	p = wri_arena_take_array(t->a, count, elem, 16u);
	if (p == NULL)
		t->st = WR_E_BUDGET;
	return p;
}

typedef struct parts {
	wr_client *c;
	wri_cslot *slot;
	uint8_t *ring, *ctl, *tx;
	wri_m2_preauth *pa;
	uint8_t *pa_used;
	uint8_t *pa_mem;
} parts;

static void parts_take(take *t, const wr_config *cfg, const wri_layout *lay, parts *p)
{
	p->c = (wr_client *)tk(t, 1u, sizeof(wr_client));
	p->slot = (wri_cslot *)tk(t, cfg->max_conns, sizeof(wri_cslot));
	p->ring = (uint8_t *)tk(t, cfg->max_conns, lay->ring);
	p->ctl = (uint8_t *)tk(t, cfg->max_conns, lay->ctl);
	p->tx = (uint8_t *)tk(t, cfg->max_conns, lay->tx);
	p->pa = (wri_m2_preauth *)tk(t, cfg->max_handshakes, sizeof(wri_m2_preauth));
	p->pa_used = (uint8_t *)tk(t, cfg->max_handshakes, 1u);
	p->pa_mem = (uint8_t *)tk(t, 1u, lay->pa_mem);
	(void)tk(t, 0u, 1u); /* pad to 16: the cephx client's own plan starts at an aligned offset */
}

/* ---- layout ---------------------------------------------------------------------------------------- */

wr_status wri_client_layout(const wr_config *cfg, wri_layout *lay)
{
	take t;
	parts p;
	size_t cxn = 0, monn = 0, stride, mapa = 0, mapb = 0;
	wr_status st;

	if (lay == NULL)
		return WR_E_INVAL;
	WR_MEMSET(lay, 0, sizeof(*lay));
	st = check_cfg(cfg);
	if (st != WR_OK)
		return st;
	st = wri_align_up(cfg->rx_buf_bytes, 16u, &lay->ring);
	if (st == WR_OK)
		st = wri_align_up(cfg->ctl_buf_bytes, 16u, &lay->ctl);
	if (st == WR_OK)
		st = wri_align_up(cfg->tx_buf_bytes, 16u, &lay->tx);
	if (st == WR_OK)
		st = wri_align_up(cfg->preauth_cap, 16u, &lay->pa_stride);
	if (st == WR_OK)
		st = wri_mul_sz(lay->pa_stride, 2u, &stride);
	if (st == WR_OK)
		st = wri_mul_sz(stride, cfg->max_handshakes, &lay->pa_mem);
	if (st != WR_OK)
		return st;
	lay->seg_cap_max = seg_cap_for(cfg);

	WR_MEMSET(&t, 0, sizeof(t));
	parts_take(&t, cfg, lay, &p);
	if (t.st != WR_OK)
		return t.st;
	st = wri_cx_client_mem(cfg, &cxn); /* WR_E_INVAL for a ticket_cap outside its range */
	if (st != WR_OK)
		return st;
	st = wri_add_sz(t.used, cxn, &lay->arena);
	if (st != WR_OK)
		return st;
	st = wri_mon_bulk_mem(cfg, &monn); /* WR_E_INVAL for mapmsg_queue / mon_msg_cap out of range */
	if (st != WR_OK)
		return st;
	lay->bulk = monn;
	if (cfg->map_slot_bytes != 0u) { /* the map store: its cache (arena) and its two slots (bulk), in the order init takes them */
		st = wri_mapstore_mem(cfg, &mapa, &mapb);
		if (st == WR_OK && mapa != 0u)
			st = wri_arena_plan(&lay->arena, mapa, 16u);
		if (st == WR_OK)
			st = wri_arena_plan(&lay->bulk, cfg->map_slot_bytes, 16u);
		if (st == WR_OK)
			st = wri_arena_plan(&lay->bulk, cfg->map_slot_bytes, 16u);
		if (st != WR_OK)
			return st;
	}
	return WR_OK;
}

wr_status wr_client_mem_required(const wr_config *cfg, wr_mem_req *out)
{
	wri_layout lay;
	wr_status st;

	if (out == NULL)
		return WR_E_INVAL;
	out->arena = 0;
	out->bulk = 0;
	st = wri_client_layout(cfg, &lay);
	if (st != WR_OK)
		return st;
	out->arena = lay.arena;
	out->bulk = lay.bulk;
	return WR_OK;
}

/* ---- carving ----------------------------------------------------------------------------------------- */

static void init_slots(wr_client *c, const parts *p, const wr_config *cfg, const wri_layout *lay)
{
	uint32_t i;
	size_t stride = lay->pa_stride;

	for (i = 0; i < cfg->max_conns; i++) {
		wri_cslot *s = &p->slot[i];

		wri_m2_conn_bind(&s->conn, (uint16_t)i, p->ring + (size_t)i * lay->ring, cfg->rx_buf_bytes,
				 p->ctl + (size_t)i * lay->ctl, cfg->ctl_buf_bytes, p->tx + (size_t)i * lay->tx,
				 cfg->tx_buf_bytes, lay->seg_cap_max);
		s->conn.pa_slot = WRI_NIL;
		s->connect_deadline_ms = WR_DEADLINE_NONE;
	}
	for (i = 0; i < cfg->max_handshakes; i++) {
		uint8_t *rx = p->pa_mem + (size_t)i * 2u * stride;

		wri_m2_preauth_init(&p->pa[i], rx, rx + stride, cfg->preauth_cap);
	}
	c->slot = p->slot;
	c->n_slot = cfg->max_conns;
	c->pa = p->pa;
	c->pa_used = p->pa_used;
	c->n_pa = cfg->max_handshakes;
}

wr_status wri_client_carve(wri_arena *arena, wri_arena *bulk, const wr_config *cfg, const wri_layout *lay,
			   const wr_host_ops *host, const wr_cluster_spec *spec, uint32_t nonce, wr_client **out)
{
	take t;
	parts p;
	wr_client *c;
	size_t before, cxn = 0;
	wr_status st;

	WR_MEMSET(&t, 0, sizeof(t));
	t.a = arena;
	parts_take(&t, cfg, lay, &p);
	if (t.st != WR_OK)
		return t.st;
	c = p.c;
	c->arena_base = arena->base;
	c->x.host = *host;
	c->x.cfg = *cfg;
	c->state = WR_CS_CREATED;
	c->my_nonce = nonce;
	c->ev_dropped = 0;
	init_slots(c, &p, cfg, lay);
	wri_client_link_init(c);

	st = wri_cx_client_mem(cfg, &cxn);
	if (st != WR_OK)
		return st;
	before = arena->used;
	st = wri_cx_client_init(&c->cx, &c->x, arena, spec);
	if (st != WR_OK)
		return st;
	if (arena->used - before != cxn) /* the cephx module's size function and its init disagree: a bug, not a budget */
		return WR_E_STATE;
	st = wri_mon_init(&c->mon, &c->x, bulk, spec);
	if (st != WR_OK)
		return st;
	st = wri_mapstore_init(&c->map, cfg, arena, bulk); /* inert (enabled = 0, nothing taken) when map_slot_bytes == 0 */
	if (st != WR_OK)
		return st;
	wri_client_map_io_init(c);

	c->arena_used = arena->used;
	c->bulk_used = bulk->used;
	c->stats.arena_used = arena->used > 0xffffffffu ? 0xffffffffu : (uint32_t)arena->used;
	c->stats.bulk_used = bulk->used > 0xffffffffu ? 0xffffffffu : (uint32_t)bulk->used;
	c->magic = WRI_CLIENT_MAGIC;
	*out = c;
	return WR_OK;
}
