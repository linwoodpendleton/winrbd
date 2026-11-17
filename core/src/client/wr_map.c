/* SPDX-License-Identifier: MIT */
/*
 * wr_map.c - the public map and placement API (wr_map.h): thin calls into the map store the engine embeds
 * (wri_mapstore.h, docs/design/core-architecture.md 15.6 and 15.7).
 *
 * Every call checks the client first: a NULL or destroyed client is WR_E_INVAL, and so is a client created without the
 * map module (wr_config.map_slot_bytes == 0), which has no store to ask. Outputs are cleared on every failure.
 * Nothing here points into a map slot; answers are plain structs.
 */
#include "wri_client.h"

WR_FILE_LICENCE_MIT

static int client_ok(const wr_client *c)
{
	return c != NULL && c->magic == WRI_CLIENT_MAGIC;
}

/* The store of a usable client with maps on, else NULL. */
static wri_mapstore *store_of(wr_client *c)
{
	return client_ok(c) && c->map.enabled ? &c->map : NULL;
}

static const wri_mapstore *cstore_of(const wr_client *c)
{
	return client_ok(c) && c->map.enabled ? &c->map : NULL;
}

/* The held map, or why there is none: WR_E_INVAL without a store, WR_E_MAP_NONE before the first map. */
static wr_status held_map(const wr_client *c, const wri_osdmap **m)
{
	const wri_mapstore *s = cstore_of(c);

	*m = NULL;
	if (s == NULL)
		return WR_E_INVAL;
	*m = wri_mapstore_map(s);
	return *m != NULL ? WR_OK : WR_E_MAP_NONE;
}

/* ---- pools ------------------------------------------------------------------------------------------------ */

wr_status wr_client_pool_track(wr_client *c, const char *name, wr_pool_h *out)
{
	wri_mapstore *s = store_of(c);
	size_t n = 0;

	if (out != NULL)
		*out = 0;
	if (s == NULL || name == NULL || out == NULL)
		return WR_E_INVAL;
	while (n <= WRI_MAP_NAME_MAX && name[n] != '\0') /* a name longer than the cap is refused without reading on */
		n++;
	if (n == 0u)
		return WR_E_INVAL;
	if (n > WRI_MAP_NAME_MAX)
		return WR_E_TOOBIG;
	return wri_mapstore_track(s, (const uint8_t *)name, n, out);
}

wr_status wr_client_pool_info(const wr_client *c, wr_pool_h h, wr_pool_info *out)
{
	const wri_mapstore *s = cstore_of(c);
	const wri_map_pool *p = NULL;
	wr_status st;

	if (out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	if (s == NULL)
		return WR_E_INVAL;
	st = wri_mapstore_pool(s, h, &p);
	if (st != WR_OK)
		return st;
	out->id = p->id;
	out->flags = p->flags;
	out->size = p->size;
	out->min_size = p->min_size;
	out->pg_num = p->pg_num;
	out->pgp_num = p->pgp_num;
	out->last_force_op_resend = p->last_force_op_resend;
	out->status = (wr_status)p->status; /* WR_OK, or why this client cannot use the pool (the record is returned either way) */
	return WR_OK;
}

/* ---- the map ----------------------------------------------------------------------------------------------- */

wr_status wr_client_map_info(const wr_client *c, wr_map_info *out)
{
	const wri_osdmap *m;
	wr_status st;

	if (out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	st = held_map(c, &m);
	if (st != WR_OK)
		return st;
	out->epoch = m->epoch;
	out->flags = m->flags; /* raw: enforcing pause and full is the object client's job */
	out->max_osd = m->max_osd;
	out->n_up = m->n_up;
	WR_MEMCPY(out->fsid, m->fsid, sizeof(out->fsid));
	return WR_OK;
}

wr_status wr_client_osd_addr(const wr_client *c, int32_t osd, wr_addr *out, uint8_t *up)
{
	const wri_osdmap *m;
	const wri_osd_addr *a;
	wr_status st;

	if (up != NULL)
		*up = 0;
	if (out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	st = held_map(c, &m);
	if (st != WR_OK)
		return st;
	if (!wri_osd_exists(m, osd))
		return WR_E_RANGE; /* outside 0..max_osd-1, or an id the map has no OSD for */
	a = &wri_map_addr(m)[osd];
	if (a->family == WR_AF_IPV4 || a->family == WR_AF_IPV6) {
		out->family = a->family;
		WR_MEMCPY(out->ip, a->ip, sizeof(out->ip));
		out->port = a->port;
		out->nonce = a->nonce;
	}
	if (up != NULL)
		*up = wri_osd_up(m, osd) ? 1u : 0u;
	return WR_OK;
}

/* ---- placement ---------------------------------------------------------------------------------------------- */

/* Does a size_t fit the core's 32-bit lengths? (Two shifts: no constant comparison for a 32-bit size_t to warn about.) */
static int fits_u32(size_t n)
{
	return ((n >> 16) >> 16) == 0u;
}

static void clear_target(wr_target *out)
{
	WR_MEMSET(out, 0, sizeof(*out));
	out->up_primary = -1;
	out->acting_primary = -1;
}

wr_status wr_client_map_target(wr_client *c, wr_pool_h h, const wr_object_id *oid, wr_target *out)
{
	wri_mapstore *s = store_of(c);
	wri_oid o;

	if (out == NULL)
		return WR_E_INVAL;
	clear_target(out);
	if (s == NULL || oid == NULL)
		return WR_E_INVAL;
	if ((oid->name == NULL && oid->name_len != 0u) || (oid->nspace == NULL && oid->nspace_len != 0u) ||
	    (oid->key == NULL && oid->key_len != 0u))
		return WR_E_INVAL;
	if (!fits_u32(oid->name_len) || !fits_u32(oid->nspace_len) || !fits_u32(oid->key_len))
		return WR_E_TOOBIG; /* far above the placement cap, and not representable in the core's length type */
	WR_MEMSET(&o, 0, sizeof(o));
	o.name = (const uint8_t *)oid->name;
	o.name_len = (uint32_t)oid->name_len;
	o.nspace = (const uint8_t *)oid->nspace;
	o.nspace_len = (uint32_t)oid->nspace_len;
	o.key = (const uint8_t *)oid->key;
	o.key_len = (uint32_t)oid->key_len;
	return wri_mapstore_target(s, h, &o, out);
}

wr_status wr_client_map_target_pg(wr_client *c, wr_pool_h h, uint32_t pg_seed, wr_target *out)
{
	wri_mapstore *s = store_of(c);

	if (out == NULL)
		return WR_E_INVAL;
	clear_target(out);
	if (s == NULL)
		return WR_E_INVAL;
	return wri_mapstore_target_pg(s, h, pg_seed, out);
}

/* ---- counters ------------------------------------------------------------------------------------------------ */

void wr_client_map_stats(const wr_client *c, wr_map_stats *out)
{
	if (out == NULL)
		return;
	WR_MEMSET(out, 0, sizeof(*out));
	if (cstore_of(c) != NULL) {
		wri_mapstore_stats(cstore_of(c), out);
		out->n_msg_toobig = c->mon.n_toobig; /* what the monitor link threw away before the store could see it */
		out->n_msg_bad = c->mon.n_bad_msg;
	}
}
