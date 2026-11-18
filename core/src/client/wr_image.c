/* SPDX-License-Identifier: MIT */
/*
 * wr_image.c - the public image API (wr_image.h): thin calls into the image layer (wri_rbd.h) the engine embeds, the way wr_map.c does for the map
 * store (docs/design/core-architecture.md section 27).
 *
 * A wr_image is a handle of this module (wri_client_osd.h): the client and the slot of the layer's image table. It is how the calls of wr_image.h,
 * which carry no client, find the layer, and how a handle of a destroyed client, or of a slot that holds no image, is recognised (WR_E_INVAL, state
 * WR_IMG_FREE). The argument checks the header documents are made here or by the layer in the order the header lists them; the layer owns everything
 * about what an image or a request is.
 */
#include "wri_client_osd.h"

#include "wri_misc.h"
#include "wri_rbd_io.h"

WR_FILE_LICENCE_MIT

static int client_ok(const wr_client *c)
{
	return c != NULL && c->magic == WRI_CLIENT_MAGIC && c->og != NULL && c->rbd != NULL;
}

/* The client behind a handle, NULL for anything that is not a live handle of a live client. */
static wr_client *client_of(const wr_image *img)
{
	wr_client *c;

	if (img == NULL || img->magic != WRI_IMG_MAGIC || img->c == NULL)
		return NULL;
	c = img->c;
	if (!client_ok(c) || img->slot >= c->og->n_h || img != &c->og->h[img->slot])
		return NULL;
	return c;
}

/* The layer's record of the image, NULL for a handle that is not live or whose slot holds no image. */
static const wri_rbd_img *img_of(const wr_image *img)
{
	wr_client *c = client_of(img);
	const wri_rbd_img *m;

	if (c == NULL)
		return NULL;
	m = &c->rbd->img[img->slot];
	return m->state == (uint8_t)WR_IMG_FREE ? NULL : m;
}

/* ---- open and queries ------------------------------------------------------------------------------------------------------ */

wr_status wr_image_open(wr_client *c, const wr_image_params *p, wr_image **out)
{
	uint32_t slot = 0;
	size_t name_n = 0, id_n = 0;
	wr_status st;

	if (out != NULL)
		*out = NULL;
	if (c == NULL || p == NULL || out == NULL)
		return WR_E_INVAL;
	if (!client_ok(c))
		return WR_E_INVAL; /* destroyed, or created without the OSD client (osd_sessions == 0) */
	st = wri_rbd_open_check_params(p, &name_n, &id_n); /* ABI, NULL / empty strings, both / neither of name and id, lengths, snapshot id */
	if (st != WR_OK)
		return st;
	if (c->state == WR_CS_FAILED)
		return WR_E_STATE;
	st = wri_rbd_open_start(c->rbd, &c->og->pools, p, &slot); /* BUSY (no free slot), what wr_client_pool_track says */
	if (st != WR_OK)
		return st;
	*out = &c->og->h[slot];
	wri_client_osd_note_open(c, slot); /* timed against the clock of the last run: re-based at the next one */
	return WR_OK;
}

wr_status wr_image_get_info(const wr_image *img, wr_image_info *out)
{
	const wri_rbd_img *m;

	if (out != NULL)
		WR_MEMSET(out, 0, sizeof(*out));
	if (out == NULL)
		return WR_E_INVAL;
	m = img_of(img);
	if (m == NULL)
		return WR_E_INVAL;
	if (m->state != (uint8_t)WR_IMG_OPEN && !(m->state == (uint8_t)WR_IMG_FAILED && m->was_open))
		return WR_E_STATE;
	out->size_bytes = m->size;
	out->features = m->features;
	out->flags = m->flags;
	out->snap_seq = m->snapc.seq;
	out->n_snaps = m->snapc.n;
	out->object_size = m->order >= 12u && m->order <= 25u ? (uint32_t)1 << m->order : 0u;
	out->order = m->order;
	out->writable = m->writable;
	out->pool_id = m->pool_id;
	out->data_pool_id = m->data_pool_id;
	out->max_io_bytes = WRI_RBD_IO_MAX;
	WR_MEMCPY(out->image_id, m->id, sizeof(out->image_id) < sizeof(m->id) ? sizeof(out->image_id) : sizeof(m->id));
	out->image_id[sizeof(out->image_id) - 1u] = '\0';
	WR_MEMCPY(out->object_prefix, m->prefix, sizeof(out->object_prefix) < sizeof(m->prefix) ? sizeof(out->object_prefix) : sizeof(m->prefix));
	out->object_prefix[sizeof(out->object_prefix) - 1u] = '\0';
	return WR_OK;
}

wr_image_state wr_image_get_state(const wr_image *img)
{
	const wri_rbd_img *m = img_of(img);

	return m != NULL ? (wr_image_state)m->state : WR_IMG_FREE;
}

const wr_errinfo *wr_image_error(const wr_image *img)
{
	static const wr_errinfo none = {0, 0, 0, 0, 0, 0, 0, 0, 0, NULL};
	const wri_rbd_img *m = img_of(img);

	return m != NULL ? &m->err : &none;
}

uint32_t wr_image_slot(const wr_image *img)
{
	return client_of(img) != NULL ? img->slot : 0u;
}

wr_image *wr_client_image_at(wr_client *c, uint32_t slot)
{
	if (!client_ok(c) || slot >= c->og->n_h || c->rbd->img[slot].state == (uint8_t)WR_IMG_FREE)
		return NULL;
	return &c->og->h[slot];
}

/* ---- block I/O ------------------------------------------------------------------------------------------------------------- */

wr_status wr_image_submit(wr_image *img, wr_io_req *req)
{
	wr_client *c = client_of(img);
	wr_status st;

	if (img == NULL || req == NULL || c == NULL)
		return WR_E_INVAL;
	st = wri_rbd_submit(c->rbd, img->slot, req); /* the layer makes the checks of wr_image.h in its order and answers WR_E_INVAL for a free slot */
	if (st == WR_OK)
		wri_client_osd_note_request(c, req); /* its timeout was taken against the clock of the last run: re-based at the next one */
	return st;
}

wr_io_req *wr_client_next_done(wr_client *c)
{
	if (!client_ok(c))
		return NULL;
	return wri_rbd_next_done(c->rbd);
}

wr_status wr_image_cancel(wr_image *img, wr_io_req *req)
{
	wr_client *c = client_of(img);

	if (img == NULL || req == NULL || c == NULL)
		return WR_E_INVAL;
	return wri_rbd_cancel(c->rbd, img->slot, req);
}

wr_status wr_image_close(wr_image *img, uint32_t flags)
{
	wr_client *c = client_of(img);

	if (img == NULL || c == NULL)
		return WR_E_INVAL;
	return wri_rbd_close(c->rbd, img->slot, flags); /* WR_E_INVAL for a free slot and for flags other than the two */
}

/* ---- counters ---------------------------------------------------------------------------------------------------------------- */

void wr_client_osd_stats(const wr_client *c, wr_osd_stats *out)
{
	if (out == NULL)
		return;
	WR_MEMSET(out, 0, sizeof(*out));
	if (!client_ok(c))
		return;
	wri_client_osd_stats(c, out);
}
