/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_open_ok.c - the open that succeeds, over the real request engine and sim_osd: by name and by id, a plain image, a default-striped one,
 * one with a data pool named by the host, a deep-flatten one, a snapshotted one, as reader and as writer; what the OSD saw on the wire (the object
 * names, one header message of eight calls, the extra read only when a feature bit asks for it); what the image holds afterwards (wr_image_info
 * fields), the events, and that every control slot of the engine is back when it is over.
 */
#include "rbd_open_rig.h"

static orig O;

static void open_ok(orig *o, uint32_t slot, int writer)
{
	wri_rbd_img *m = oimg(o, slot);

	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN);
	WRT_CHECK(m->ros == (uint8_t)WRI_ROS_READY);
	WRT_CHECK(m->writable == (writer ? 1u : 0u) && m->was_open == 1u);
	WRT_CHECK(m->err.status == WR_OK);
	WRT_CHECK(m->ctl_op == WRI_NIL);
	WRT_CHECK(m->open_deadline_ms == WR_DEADLINE_NONE);
	WRT_CHECK(orig_ctl_idle(o));
}

static void test_by_name(int writer)
{
	sim_rbd_image_cfg c = oimg_cfg("img-a", "0123456789ab");
	wr_image_params p = oparams(OR_META, "img-a", NULL, writer);
	uint32_t slot;
	wri_rbd_img *m;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	slot = orig_start(&O, &p, WR_OK);
	WRT_CHECK(slot == 0u);
	m = oimg(&O, 0);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPENING && m->ros == (uint8_t)WRI_ROS_POOLS && m->ctl_op == WRI_NIL);
	WRT_CHECK(strcmp(m->name, "img-a") == 0 && m->id[0] == '\0' && m->pool_h == 0u && !m->has_data_pool);
	(void)orig_settle(&O);
	open_ok(&O, 0, writer);
	WRT_CHECK(strcmp(m->id, "0123456789ab") == 0 && strcmp(m->prefix, "rbd_data.0123456789ab") == 0);
	WRT_CHECK(m->order == 22u && m->size == (64ull << 20) && m->features == 0x21u && m->flags == 0u && m->op_features == 0u);
	WRT_CHECK(m->pool_id == W_POOL && m->data_pool_id == W_POOL);
	WRT_CHECK(m->snapc.seq == 0u && m->snapc.n == 0u && m->snapc.cap == 8u);
	WRT_CHECK(m->next_refresh_ms == (writer ? m->refreshed_ms + 1000u : WR_DEADLINE_NONE));
	WRT_CHECK(m->refreshed_ms >= orig_now(&O) - 100u && m->refreshed_ms <= orig_now(&O));
	/* on the wire: the id object once, then the header object once (the name is looked up, the id is not given) */
	WRT_CHECK(orig_nrec_oid(&O, "rbd_id.img-a") == 1u && orig_nrec_oid(&O, "rbd_header.0123456789ab") == 1u && rig_nrec(&O.r, 0) == 2u);
	{
		const sim_osd_rec *get_id = rig_rec(&O.r, 0, 0), *hdr = rig_rec(&O.r, 0, 1);

		WRT_CHECK(get_id != NULL && get_id->n_ops == 1u && get_id->op_code[0] == WRI_OSD_OP_CALL && get_id->pool == W_POOL);
		WRT_CHECK((get_id->flags & WRI_OSDF_READ) != 0 && (get_id->flags & WRI_OSDF_WRITE) == 0 && !get_id->mutating);
		WRT_CHECK(hdr != NULL && hdr->n_ops == 8u && hdr->snapid == WRI_SNAP_NOSNAP && !hdr->mutating && hdr->result == 0);
		if (hdr != NULL) {
			unsigned k;

			for (k = 0; k < 8; k++)
				WRT_CHECK(hdr->op_code[k] == WRI_OSD_OP_CALL && hdr->op_rval[k] >= 0);
			WRT_CHECK(hdr->data_len > 100u && hdr->data_len < WRI_RBD_CTL_IN);
		}
	}
	/* one image event: it is open */
	WRT_CHECK(O.n_img_ev == 1u && orig_count_ev(&O, WR_EV_IMAGE, 0) == 1u && O.ev[0].st == WR_OK);
	/* nothing more happens by itself: no refresh before hdr_refresh_ms, none for a reader at all */
	orig_tick(&O, 900);
	WRT_CHECK(rig_nrec(&O.r, 0) == 2u && m->ros == (uint8_t)WRI_ROS_READY);
	orig_close(&O);
}

static void test_by_id(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-b", "feedface0001");
	wr_image_params p = oparams(OR_META, NULL, "feedface0001", 1);
	wri_rbd_img *m;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
	(void)orig_settle(&O);
	m = oimg(&O, 0);
	open_ok(&O, 0, 1);
	WRT_CHECK(m->name[0] == '\0' && strcmp(m->id, "feedface0001") == 0);
	WRT_CHECK(rig_nrec(&O.r, 0) == 1u && orig_nrec_oid(&O, "rbd_header.feedface0001") == 1u); /* no get_id */
	orig_close(&O);
	/* both given: the id is used, the name is only kept */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	p = oparams(OR_META, "whatever", "feedface0001", 0);
	WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
	(void)orig_settle(&O);
	open_ok(&O, 0, 0);
	m = oimg(&O, 0);
	WRT_CHECK(strcmp(m->name, "whatever") == 0 && rig_nrec(&O.r, 0) == 1u);
	orig_close(&O);
}

/* Default striping bit (unit == object size, count 1) and an image that is both striped and deep-flatten: one extra read. */
static void test_striped_default(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-s", "5757575757");
	wr_image_params p = oparams(OR_META, "img-s", NULL, 1);
	wri_rbd_img *m;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	c.features = 0x23; /* layering | striping | deep-flatten */
	c.stripe_unit = 1ull << 22;
	c.stripe_count = 1;
	oimg_make(&O, &c);
	WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
	(void)orig_settle(&O);
	m = oimg(&O, 0);
	open_ok(&O, 0, 1);
	WRT_CHECK(m->features == 0x23u && m->hdr.stripe_unit == (1ull << 22) && m->hdr.stripe_count == 1u);
	/* get_id, the header (8 calls), the stripe read (1 call) */
	WRT_CHECK(rig_nrec(&O.r, 0) == 3u);
	{
		const sim_osd_rec *x = rig_rec(&O.r, 0, 2);

		WRT_CHECK(x != NULL && x->n_ops == 1u && strcmp(x->oid, "rbd_header.5757575757") == 0 && x->op_code[0] == WRI_OSD_OP_CALL);
	}
	orig_close(&O);
	/* the same bit with a zero unit and count (an image created without them): the default */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	c.stripe_unit = c.stripe_count = 0;
	oimg_make(&O, &c);
	WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
	(void)orig_settle(&O);
	open_ok(&O, 0, 1);
	orig_close(&O);
}

/* A reader of an image with the operations bit reads op_features too (clone-child would refuse it: the refuse test). */
static void test_operations_reader(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-op", "0a0a0a0a0a0a");
	wr_image_params p = oparams(OR_META, "img-op", NULL, 0);
	wri_rbd_img *m;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	c.features = 0x121; /* layering | deep-flatten | operations */
	c.op_features = 0x8; /* some other operation feature */
	oimg_make(&O, &c);
	WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
	(void)orig_settle(&O);
	m = oimg(&O, 0);
	open_ok(&O, 0, 0);
	WRT_CHECK(m->features == 0x121u && m->op_features == 0x8u);
	WRT_CHECK(rig_nrec(&O.r, 0) == 3u);
	orig_close(&O);
}

/* The data pool: named by the host with the right id; the data objects will be in the data pool, the metadata stays in the image's. */
static void test_data_pool(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-d", "d4d4d4d4d4");
	wr_image_params p = oparams(OR_META, "img-d", NULL, 1);
	wri_rbd_img *m;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	c.features = 0xa1; /* layering | deep-flatten | data pool */
	c.data_pool = W_POOL + 1;
	oimg_make(&O, &c);
	p.data_pool = OR_DATA;
	WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
	WRT_CHECK(O.n_track == 2u && oimg(&O, 0)->has_data_pool && oimg(&O, 0)->data_pool_h == 1u);
	(void)orig_settle(&O);
	m = oimg(&O, 0);
	open_ok(&O, 0, 1);
	WRT_CHECK(m->pool_id == W_POOL && m->data_pool_id == W_POOL + 1 && m->features == 0xa1u);
	WRT_CHECK(strcmp(m->prefix, "rbd_data.2.d4d4d4d4d4") == 0); /* the prefix as stored, verbatim */
	orig_close(&O);
	/* the host names a data pool the image does not use: ignored (the data objects stay in the image's pool) */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	c = oimg_cfg("img-e", "e5e5e5e5e5");
	oimg_make(&O, &c);
	p = oparams(OR_META, "img-e", NULL, 1);
	p.data_pool = OR_DATA;
	WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
	(void)orig_settle(&O);
	m = oimg(&O, 0);
	open_ok(&O, 0, 1);
	WRT_CHECK(m->data_pool_id == W_POOL + 1 && (m->features & WRI_RBD_F_DATA_POOL) == 0u);
	orig_close(&O);
	/* the same pool named twice: the data pool is the image pool */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	p = oparams(OR_META, "img-e", NULL, 0);
	p.data_pool = "";
	WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u); /* an empty data pool name is no data pool */
	WRT_CHECK(!oimg(&O, 0)->has_data_pool && O.n_track == 1u);
	(void)orig_settle(&O);
	open_ok(&O, 0, 0);
	orig_close(&O);
}

static void test_snapshotted(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-snap", "5a5a5a5a5a");
	wr_image_params p = oparams(OR_META, "img-snap", NULL, 1);
	wri_rbd_img *m;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	c.snap_seq = 9;
	c.n_snaps = 3;
	c.snaps[0] = 9;
	c.snaps[1] = 6;
	c.snaps[2] = 2;
	oimg_make(&O, &c);
	WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
	(void)orig_settle(&O);
	m = oimg(&O, 0);
	open_ok(&O, 0, 1);
	WRT_CHECK(m->snapc.seq == 9u && m->snapc.n == 3u && m->snapc.snaps[0] == 9u && m->snapc.snaps[1] == 6u && m->snapc.snaps[2] == 2u);
	WRT_CHECK(m->snapc_status == (int32_t)WR_OK && m->snapc_total == 3u);
	orig_close(&O);
	/* a seq above the ids (snapshots deleted later): fine */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	c.snap_seq = 20;
	oimg_make(&O, &c);
	WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
	(void)orig_settle(&O);
	m = oimg(&O, 0);
	open_ok(&O, 0, 1);
	WRT_CHECK(m->snapc.seq == 20u && m->snapc.n == 3u);
	orig_close(&O);
}

/* A reader does not need the snapshot context: an image with more snapshots than max_snaps still opens for reading (the writer refusal is in the refuse test). */
static void test_reader_many_snaps(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-many", "9b9b9b9b9b");
	wr_image_params p = oparams(OR_META, "img-many", NULL, 0);
	orig_cfg cfg = orig_cfg_default();
	wri_rbd_img *m;
	unsigned i;

	cfg.max_snaps = 2;
	if (orig_open(&O, &cfg) != 0) {
		WRT_CHECK(0);
		return;
	}
	c.snap_seq = 16;
	c.n_snaps = 5;
	for (i = 0; i < 5; i++)
		c.snaps[i] = 16u - i * 2u;
	oimg_make(&O, &c);
	WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
	(void)orig_settle(&O);
	m = oimg(&O, 0);
	open_ok(&O, 0, 0);
	WRT_CHECK(m->snapc.n == 0u && m->snapc_total == 5u);
	orig_close(&O);
}

/* Several images at once: two names, one by id, all from the control reserve; the slots, generations and events are separate. */
static void test_three_images(void)
{
	sim_rbd_image_cfg c1 = oimg_cfg("one", "a1a1a1a1a1"), c2 = oimg_cfg("two", "a2a2a2a2a2"), c3 = oimg_cfg("three", "a3a3a3a3a3");
	wr_image_params p1 = oparams(OR_META, "one", NULL, 1), p2 = oparams(OR_META, "two", NULL, 0), p3 = oparams(OR_META, NULL, "a3a3a3a3a3", 1);
	orig_cfg cfg = orig_cfg_default();
	unsigned k;

	cfg.ctl_ops = 2; /* fewer control slots than images: the third waits for one */
	if (orig_open(&O, &cfg) != 0) {
		WRT_CHECK(0);
		return;
	}
	c2.size = 1ull << 20;
	c3.order = 12;
	oimg_make(&O, &c1);
	oimg_make(&O, &c2);
	oimg_make(&O, &c3);
	WRT_CHECK(orig_start(&O, &p1, WR_OK) == 0u && orig_start(&O, &p2, WR_OK) == 1u && orig_start(&O, &p3, WR_OK) == 2u);
	(void)orig_settle(&O);
	for (k = 0; k < 3; k++) {
		wri_rbd_img *m = oimg(&O, k);

		WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN);
		WRT_CHECK(orig_count_ev(&O, WR_EV_IMAGE, k) == 1u);
	}
	WRT_CHECK(oimg(&O, 1)->size == (1ull << 20) && oimg(&O, 2)->order == 12u && oimg(&O, 0)->order == 22u);
	WRT_CHECK(strcmp(oimg(&O, 0)->id, "a1a1a1a1a1") == 0 && strcmp(oimg(&O, 1)->id, "a2a2a2a2a2") == 0 && strcmp(oimg(&O, 2)->id, "a3a3a3a3a3") == 0);
	WRT_CHECK(orig_ctl_idle(&O));
	orig_close(&O);
}

int main(void)
{
	test_by_name(0);
	test_by_name(1);
	test_by_id();
	test_striped_default();
	test_operations_reader();
	test_data_pool();
	test_snapshotted();
	test_reader_many_snaps();
	test_three_images();
	return wrt_finish();
}
