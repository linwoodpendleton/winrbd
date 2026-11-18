/* SPDX-License-Identifier: MIT */
/*
 * test_osd_req_basic.c - the request engine from submit to completion over real sessions and sim_osd: memory planning, the op table (slots, the control
 * reserve, the free list, tids), the shape checks of submit, every operation kind the layers above use (READ, WRITE, ZERO, TRUNCATE, DELETE, CALL, STAT) with what the
 * OSD saw on the wire (flags, epoch, placement, snapshot context, version), many operations in flight over several OSDs, completion order, the v8 fallback,
 * the data-length checks of a reply and the owner tags.
 */
#include "osd_req_rig.h"

static rig R;

static void tweak_three(rig *r)
{
	unsigned pg;

	for (pg = 0; pg < MW_PG_MAX; pg++)
		r->m.prim[pg] = (int)(pg % 3u);
}

static void fill(uint8_t *p, size_t n, unsigned seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed * 31u + i * 7u + (i >> 8));
}

/* ---- memory and the table ---------------------------------------------------------------------------------------------------------- */

static void test_mem(void)
{
	wr_config c;
	size_t a = 99, b = 99, a2 = 0, b2 = 0;

	memset(&c, 0, sizeof(c));
	wr_config_profile_harness(&c);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_mem(&c, &a, &b));
	WRT_CHECK(a == 0 && b == 0); /* the OSD client is off */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_mem(NULL, &a, &b));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_mem(&c, NULL, &b));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_mem(&c, &a, NULL));
	c.osd_sessions = 4;
	c.osd_front_cap = 2048;
	c.backoff_slots = 8;
	c.max_ops = 16;
	c.ctl_ops = 2;
	c.op_timeout_ms = 5000;
	c.zombie_bytes = 4096;
	WRT_CHECK_STATUS(WR_OK, wri_osdc_mem(&c, &a, &b));
	WRT_CHECK(a > 16u * sizeof(wri_osd_op) && b == 4096u);
	/* growing max_ops grows the arena by exactly the slot and the ring entry (16-byte alignment aside) */
	c.max_ops = 17;
	WRT_CHECK_STATUS(WR_OK, wri_osdc_mem(&c, &a2, &b2));
	WRT_CHECK(a2 > a && a2 - a <= sizeof(wri_osd_op) + 2u * sizeof(uint32_t) + 32u);
	c.max_ops = 16;
	c.zombie_bytes = 0;
	WRT_CHECK_STATUS(WR_OK, wri_osdc_mem(&c, &a2, &b2));
	WRT_CHECK(a2 == a && b2 == 0);
	/* refused configurations */
	c.max_ops = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_mem(&c, &a, &b));
	c.max_ops = 16;
	c.ctl_ops = 16;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_mem(&c, &a, &b));
	c.ctl_ops = 2;
	c.op_timeout_ms = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_mem(&c, &a, &b));
	c.op_timeout_ms = 5000;
	c.osd_front_cap = 100; /* below what a session needs */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_mem(&c, &a, &b));
}

static void test_init_exact(void)
{
	size_t a = 0, b = 0;

	if (rig_open(&R, 2, 3, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	WRT_CHECK_STATUS(WR_OK, wri_osdc_mem(&R.w.e.x.cfg, &a, &b));
	WRT_CHECK(R.a.used == a); /* the plan is exactly what init took from a 64-byte aligned arena */
	WRT_CHECK(R.b.used == b && b == 65536u);
	WRT_CHECK(R.o.n_op == 32u && R.o.n_free == 32u && R.o.n_free_ctl == 2u && R.o.next_tid == 1u && R.o.zcap == 65536u);
	WRT_CHECK(R.o.sess.n == 3u && rig_idle(&R));
	WRT_CHECK(wri_osdc_deadline(&R.o) == WR_DEADLINE_NONE);
	/* init refuses a missing piece */
	{
		wri_osdc o2;
		wri_arena a2, b2;
		wri_osd_map_ops mo = mw_ops(&R.m);
		wri_osd_link l;
		wri_osd_map_ops bad = mo;

		memset(&l, 0, sizeof(l));
		l.ctx = &R.w, l.open = w_open, l.close = w_close, l.send = w_send, l.tx_idle = w_tx_idle, l.have_ticket = w_have_ticket,
		l.handshake_free = w_handshake_free;
		wri_arena_init(&a2, R.mem, 0);
		wri_arena_init(&b2, R.bulk, 0);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_init(NULL, &R.w.e.x, &a2, &b2, &mo, &l));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_init(&o2, NULL, &a2, &b2, &mo, &l));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_init(&o2, &R.w.e.x, &a2, &b2, NULL, &l));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_init(&o2, &R.w.e.x, &a2, &b2, &mo, NULL));
		bad.target = NULL;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_init(&o2, &R.w.e.x, &a2, &b2, &bad, &l));
		WRT_CHECK_STATUS(WR_E_BUDGET, wri_osdc_init(&o2, &R.w.e.x, &a2, &b2, &mo, &l)); /* a zero-byte arena */
	}
	rig_close(&R);
}

static void test_alloc_reserve(void)
{
	uint32_t data[32], ctl[2], i, n = 0;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	/* 32 slots, 2 reserved for control ops: 30 data ops, then only control ops */
	for (i = 0; i < 40; i++) {
		uint32_t s = wri_osdc_alloc(&R.o, 0);

		if (s == WRI_NIL)
			break;
		data[n++] = s;
	}
	WRT_CHECK(n == 30u && R.o.n_free == 2u && R.o.n_free_ctl == 2u);
	WRT_CHECK(wri_osdc_alloc(&R.o, 0) == WRI_NIL);
	ctl[0] = wri_osdc_alloc(&R.o, 1);
	ctl[1] = wri_osdc_alloc(&R.o, 1);
	WRT_CHECK(ctl[0] != WRI_NIL && ctl[1] != WRI_NIL && R.o.n_free == 0u && R.o.n_free_ctl == 0u && R.o.n_ctl_used == 2u);
	WRT_CHECK(wri_osdc_alloc(&R.o, 1) == WRI_NIL && wri_osdc_alloc(&R.o, 0) == WRI_NIL);
	op = wri_osdc_at(&R.o, ctl[0]);
	WRT_CHECK((op->flags & WRI_OPF_CONTROL) != 0 && (op->flags & WRI_OPF_ALLOC) != 0 && op->state == WRI_OP_FREE && op->osd == -1 && op->sess == WRI_NIL);
	op = wri_osdc_at(&R.o, data[0]);
	WRT_CHECK((op->flags & WRI_OPF_CONTROL) == 0);
	/* a control op takes a data slot when its reserve is used up, and the reserve is then still owed: data ops cannot take it */
	wri_osdc_release(&R.o, data[0]);
	WRT_CHECK(R.o.n_free == 1u && R.o.n_free_ctl == 0u);
	WRT_CHECK(wri_osdc_alloc(&R.o, 0) != WRI_NIL); /* the reserve is claimed by the two control ops in use: the data slot is free to take */
	/* release gives control slots back to the reserve */
	wri_osdc_release(&R.o, ctl[0]);
	WRT_CHECK(R.o.n_ctl_used == 1u && R.o.n_free_ctl == 1u && R.o.n_free == 1u);
	WRT_CHECK(wri_osdc_alloc(&R.o, 0) == WRI_NIL); /* one free slot, one reserved */
	WRT_CHECK(wri_osdc_alloc(&R.o, 1) != WRI_NIL);
	/* releasing a slot twice, or a slot that is not the caller's, does nothing */
	wri_osdc_release(&R.o, data[1]);
	wri_osdc_release(&R.o, data[1]);
	WRT_CHECK(R.o.n_free == 1u);
	wri_osdc_release(&R.o, 9999);
	WRT_CHECK(wri_osdc_at(&R.o, 9999) == NULL && wri_osdc_at(NULL, 0) == NULL);
	WRT_CHECK(wri_osdc_alloc(NULL, 0) == WRI_NIL);
	rig_close(&R);
}

/* ---- shape checks ------------------------------------------------------------------------------------------------------------------ */

static uint32_t fresh_read(rig *r, uint8_t *out)
{
	uint32_t i = rq_alloc(r, WRI_OPK_READ, "obj", 7, 0);
	wri_osd_op *op = wri_osdc_at(&r->o, i);

	op->ops[0].code = WRI_OSD_OP_READ;
	op->ops[0].len = 16;
	op->out = out;
	op->out_cap = 16;
	return i;
}

static void test_shape(void)
{
	uint8_t buf[64], d[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	uint32_t i;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	/* a good one first, then every way to get it wrong, each on a fresh slot that stays the owner's */
	i = fresh_read(&R, buf);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_submit(&R.o, i));
	WRT_CHECK_STATUS(WR_E_STATE, wri_osdc_submit(&R.o, i)); /* already submitted */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(&R.o, 9999));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(NULL, 0));
	WRT_CHECK_STATUS(WR_E_STATE, wri_osdc_submit(&R.o, 31)); /* a free slot nobody allocated */

	i = fresh_read(&R, buf);
	op = wri_osdc_at(&R.o, i);
	op->n_ops = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(&R.o, i));
	op->n_ops = 9;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(&R.o, i));
	op->n_ops = 1;
	op->kind = 2;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(&R.o, i));
	op->kind = WRI_OPK_READ;
	op->oid_len = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(&R.o, i));
	op->oid_len = (uint8_t)(WRI_OSD_OID_MAX + 1u);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(&R.o, i));
	op->oid_len = 3;
	op->out = NULL; /* a capacity without a buffer */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(&R.o, i));
	op->out = buf;
	op->out_cap = 8; /* a read of 16 bytes into room for 8: the answer would be a protocol error for the whole session */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(&R.o, i));
	op->out_cap = 16;
	op->data_len = 4; /* data announced, none given, and the sum of the in_len is 0 */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(&R.o, i));
	op->data = d;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(&R.o, i)); /* the sum of in_len (0) is not 4 */
	op->data = NULL;
	op->data_len = 0;
	op->ops[0].code = 0x2201; /* a read-kind message holding a write */
	op->ops[0].in_len = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(&R.o, i));
	op->ops[0].code = 0x9999; /* a code outside the table */
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, wri_osdc_submit(&R.o, i));
	op->ops[0].code = WRI_OSD_OP_CALL;
	op->ops[0].in_len = 5;
	op->ops[0].cls_class_len = 3;
	op->ops[0].cls_method_len = 3; /* 6 > 5 */
	op->data = d;
	op->data_len = 5;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_submit(&R.o, i));
	op->ops[0].cls_method_len = 2;
	WRT_CHECK_STATUS(WR_OK, wri_osdc_submit(&R.o, i)); /* the same slot, now right */
	/* the failures left no trace in the budgets: two ops are in flight */
	WRT_CHECK(R.o.n_inflight == 2u && R.o.inflight_bytes == 16u + 16u + 5u);
	/* eight operations in one message are fine, a write op in a write-kind message too, with a READ among them */
	i = rq_alloc(&R, WRI_OPK_WRITE, "obj", 1, 0);
	op = wri_osdc_at(&R.o, i);
	op->n_ops = 8;
	{
		unsigned k;

		for (k = 0; k < 8; k++)
			op->ops[k].code = k == 3 ? WRI_OSD_OP_READ : WRI_OSD_OP_ZERO;
	}
	WRT_CHECK_STATUS(WR_OK, wri_osdc_submit(&R.o, i));
	rig_close(&R);
}

static void test_tids(void)
{
	uint8_t buf[16];
	uint32_t a, b, c, slot_a;
	uint64_t ta, tb, tc, td;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	a = fresh_read(&R, buf);
	b = fresh_read(&R, buf);
	c = fresh_read(&R, buf);
	WRT_CHECK(wri_osdc_submit(&R.o, a) == WR_OK && wri_osdc_submit(&R.o, b) == WR_OK && wri_osdc_submit(&R.o, c) == WR_OK);
	ta = rq_at(&R, a)->tid, tb = rq_at(&R, b)->tid, tc = rq_at(&R, c)->tid;
	WRT_CHECK(ta == (((uint64_t)1 << 16) | a) && tb == (((uint64_t)2 << 16) | b) && tc == (((uint64_t)3 << 16) | c));
	WRT_CHECK((ta & 0xffffu) == a && (tb & 0xffffu) == b && (tc & 0xffffu) == c && ta < tb && tb < tc);
	WRT_CHECK(R.o.head == a && R.o.tail == c && rq_at(&R, a)->next == b && rq_at(&R, c)->prev == b && R.o.next_tid == 4u);
	/* a released and reused slot gets a new, larger tid: a tid is never reused */
	slot_a = a;
	WRT_CHECK(wri_osdc_cancel(&R.o, a) == WR_OK && wri_osdc_pop_done(&R.o) == a);
	wri_osdc_release(&R.o, a);
	a = fresh_read(&R, buf);
	WRT_CHECK(a == slot_a); /* the free list is LIFO: the same slot again */
	WRT_CHECK_STATUS(WR_OK, wri_osdc_submit(&R.o, a));
	td = rq_at(&R, a)->tid;
	WRT_CHECK((td & 0xffffu) == slot_a && td == (((uint64_t)4 << 16) | slot_a) && td > tc);
	WRT_CHECK(R.o.head == b && rq_at(&R, b)->prev == WRI_NIL && R.o.tail == a && rq_at(&R, c)->next == a && rq_at(&R, a)->prev == c);
	rig_close(&R);
}

/* ---- every operation kind end to end ----------------------------------------------------------------------------------------------- */

static void test_kinds(void)
{
	uint8_t obj[4096], got[4096], w[1000], back[1000];
	uint32_t i;
	const sim_osd_rec *rec;
	wri_osd_op *op;
	int exists;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(obj, sizeof(obj), 3);
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "obj.a", 0, obj, sizeof(obj)));
	/* READ */
	memset(got, 0xEE, sizeof(got));
	i = rq_read(&R, "obj.a", 1024, 2048, got, 0x11);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000));
	op = rq_at(&R, i);
	WRT_CHECK(op->status == WR_OK && op->result >= 0 && op->out_stored == 2048u && op->ops[0].out_len == 2048u);
	WRT_CHECK(memcmp(got, obj + 1024, 2048) == 0 && got[2048] == 0xEE); /* not a byte more than the reply held */
	WRT_CHECK(op->sent_epoch == 10u && op->retry_attempt == 0 && op->osd == 0 && op->state == WRI_OP_DONE && op->sess == WRI_NIL);
	rec = rig_rec(&R, 0, 0);
	WRT_CHECK(rec != NULL && rec->tid == op->tid && rec->epoch == 10u && rec->flags == 0x08400014u && rec->version == 9u && rec->retry_attempt == 0u);
	WRT_CHECK(rec->pool == W_POOL && rec->hash == mw_hash("obj.a", 5) && rec->pg_seed == mw_pg(&R.m, "obj.a") && strcmp(rec->oid, "obj.a") == 0);
	WRT_CHECK(rec->n_ops == 1u && rec->op_code[0] == WRI_OSD_OP_READ && rec->op_off[0] == 1024u && rec->op_len[0] == 2048u && rec->snap_seq == 0u);
	WRT_CHECK(rec->global_id != 0u && rec->executed && !rec->duplicate);
	WRT_CHECK(rig_take(&R, i) == WR_OK && rig_idle(&R));
	/* READ of a short object: fewer bytes come back, the engine reports exactly the count it was given */
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "obj.short", 0, obj, 100));
	memset(got, 0xEE, sizeof(got));
	i = rq_read(&R, "obj.short", 0, 1000, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000));
	op = rq_at(&R, i);
	WRT_CHECK(op->status == WR_OK && op->ops[0].out_len == 100u && op->out_stored == 100u && memcmp(got, obj, 100) == 0 && got[100] == 0xEE);
	WRT_CHECK(rig_take(&R, i) == WR_OK);
	/* READ of an object that does not exist: the whole message fails with ENOENT and nothing is stored */
	memset(got, 0xEE, sizeof(got));
	i = rq_read(&R, "obj.none", 0, 512, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000));
	op = rq_at(&R, i);
	WRT_CHECK(op->status == WR_E_OSD_NOENT && op->result == -WRI_ERRNO_ENOENT && op->out_stored == 0u && got[0] == 0xEE);
	WRT_CHECK(rig_take(&R, i) == WR_E_OSD_NOENT);
	/* WRITE: the bytes land in the store; the write carries WRITE, FULL_TRY, no RETRY */
	fill(w, sizeof(w), 9);
	i = rq_write(&R, "obj.w", 512, w, sizeof(w), NULL, 0x22);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000));
	op = rq_at(&R, i);
	WRT_CHECK(op->status == WR_OK && op->result >= 0 && op->out_stored == 0u && rig_take(&R, i) == WR_OK);
	WRT_CHECK(rig_store_read(&R, "obj.w", 512, back, sizeof(back)) == 1 && memcmp(back, w, sizeof(w)) == 0);
	rec = rig_rec(&R, 0, rig_nrec(&R, 0) - 1u);
	WRT_CHECK(rec->flags == (0x08400024u | WRI_OSDF_FULL_TRY) && rec->mutating && rec->snap_seq == 0u && rec->n_snaps == 0u && rec->data_len == sizeof(w));
	WRT_CHECK(rec->op_code[0] == WRI_OSD_OP_WRITE && rec->op_off[0] == 512u && rec->op_len[0] == sizeof(w));
	/* ZERO in the middle, TRUNCATE, DELETE */
	i = rq_plain(&R, "obj.w", WRI_OSD_OP_ZERO, 600, 100, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_OK);
	WRT_CHECK(rig_store_read(&R, "obj.w", 512, back, sizeof(back)) == 1 && memcmp(back, w, 88) == 0 && back[88] == 0 && back[187] == 0 &&
		  memcmp(back + 188, w + 188, 100) == 0);
	i = rq_plain(&R, "obj.w", WRI_OSD_OP_TRUNCATE, 700, 0, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_OK);
	{
		uint64_t sz = 0;

		WRT_CHECK_STATUS(WR_OK, sim_store_size(R.w.store, W_POOL, "obj.w", &sz));
		WRT_CHECK(sz == 700u);
	}
	i = rq_plain(&R, "obj.w", WRI_OSD_OP_DELETE, 0, 0, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_OK);
	exists = sim_store_exists(R.w.store, W_POOL, "obj.w");
	WRT_CHECK(!exists);
	i = rq_plain(&R, "obj.w", WRI_OSD_OP_DELETE, 0, 0, 0); /* of a missing object: ENOENT, which the image layer takes as success */
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000));
	WRT_CHECK(rq_at(&R, i)->status == WR_E_OSD_NOENT && rig_take(&R, i) == WR_E_OSD_NOENT);
	WRT_CHECK(sim_osd_n_violations(R.w.osd[0]) == 0u && rig_idle(&R));
	rig_close(&R);
}

static void test_call_and_stat(void)
{
	sim_rbd_image_cfg ic;
	uint8_t in[64], out[256], obj[256];
	uint32_t i;
	wri_osd_op *op;
	uint64_t sz = 0;
	uint32_t ms = 0, mn = 0;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	memset(&ic, 0, sizeof(ic));
	ic.pool = W_POOL;
	ic.name = "img0";
	ic.id = "abc123";
	ic.size = 1u << 24;
	ic.order = 22;
	ic.features = 1;
	ic.data_pool = -1;
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(R.w.store, &ic));
	/* one CALL (rbd.get_id) against the id object: class, method, argument back to back in the data segment */
	memcpy(in, "rbdget_id", 9);
	i = rq_alloc(&R, WRI_OPK_READ, "rbd_id.img0", 5, 1); /* a control op: the open's reads */
	op = wri_osdc_at(&R.o, i);
	op->ops[0].code = WRI_OSD_OP_CALL;
	op->ops[0].in_len = 9;
	op->ops[0].cls_class_len = 3;
	op->ops[0].cls_method_len = 6;
	op->data = in;
	op->data_len = 9;
	op->out = out;
	op->out_cap = sizeof(out);
	WRT_CHECK(rq_submit(&R, i) == i && (op->flags & WRI_OPF_CONTROL) != 0);
	WRT_CHECK(rig_until_done(&R, i, 5000));
	WRT_CHECK(op->status == WR_OK && op->ops[0].rval == 0 && op->ops[0].out_len == 4u + 6u && op->out_stored == 10u);
	WRT_CHECK(wri_le32_get(out) == 6u && memcmp(out + 4, "abc123", 6) == 0);
	WRT_CHECK(rig_take(&R, i) == WR_OK && R.o.n_ctl_used == 0u);
	/* two CALLs in one message, outputs back to back and cut by the echoed lengths */
	memcpy(in, "rbdget_object_prefix", 20);
	memcpy(in + 20, "rbdget_snapcontext", 18);
	i = rq_alloc(&R, WRI_OPK_READ, "rbd_header.abc123", 6, 1);
	op = wri_osdc_at(&R.o, i);
	op->n_ops = 2;
	op->ops[0].code = WRI_OSD_OP_CALL;
	op->ops[0].in_len = 20;
	op->ops[0].cls_class_len = 3;
	op->ops[0].cls_method_len = 17;
	op->ops[1].code = WRI_OSD_OP_CALL;
	op->ops[1].in_len = 18;
	op->ops[1].cls_class_len = 3;
	op->ops[1].cls_method_len = 15;
	op->data = in;
	op->data_len = 38;
	op->out = out;
	op->out_cap = sizeof(out);
	WRT_CHECK(rq_submit(&R, i) == i && rig_until_done(&R, i, 5000));
	WRT_CHECK(op->status == WR_OK && op->ops[0].rval == 0 && op->ops[1].rval == 0 && op->ops[0].out_len > 4u && op->ops[1].out_len >= 12u);
	WRT_CHECK(op->out_stored == op->ops[0].out_len + op->ops[1].out_len);
	WRT_CHECK(wri_le32_get(out) + 4u == op->ops[0].out_len && memcmp(out + 4, "rbd_data.abc123", 15) == 0);
	WRT_CHECK(rig_take(&R, i) == WR_OK);
	/* an unknown method fails the whole message (the OSD answers before it runs anything) */
	memcpy(in, "rbdno_such_method", 17);
	i = rq_alloc(&R, WRI_OPK_READ, "rbd_header.abc123", 0, 1);
	op = wri_osdc_at(&R.o, i);
	op->ops[0].code = WRI_OSD_OP_CALL;
	op->ops[0].in_len = 17;
	op->ops[0].cls_class_len = 3;
	op->ops[0].cls_method_len = 14;
	op->data = in;
	op->data_len = 17;
	op->out = out;
	op->out_cap = sizeof(out);
	WRT_CHECK(rq_submit(&R, i) == i && rig_until_done(&R, i, 5000));
	WRT_CHECK(op->status == WR_E_OSD_NOENT && op->result == -WRI_ERRNO_EOPNOTSUPP && op->out_stored == 0u);
	WRT_CHECK(rig_take(&R, i) == WR_E_OSD_NOENT);
	/* STAT of a data object: 16 bytes */
	memset(obj, 0x5a, sizeof(obj));
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "obj.stat", 0, obj, sizeof(obj)));
	i = rq_alloc(&R, WRI_OPK_READ, "obj.stat", 0, 0);
	op = wri_osdc_at(&R.o, i);
	op->ops[0].code = WRI_OSD_OP_STAT;
	op->out = out;
	op->out_cap = 16;
	WRT_CHECK(rq_submit(&R, i) == i && rig_until_done(&R, i, 5000) && op->status == WR_OK && op->ops[0].out_len == 16u);
	WRT_CHECK_STATUS(WR_OK, wri_osd_stat_decode(out, 16, &sz, &ms, &mn));
	WRT_CHECK(sz == sizeof(obj));
	WRT_CHECK(rig_take(&R, i) == WR_OK);
	rig_close(&R);
}

/* ---- what the OSD sees: snapshot context, the version fallback ------------------------------------------------------------------------ */

static void test_snapc(void)
{
	uint64_t ids[3] = {7, 5, 2};
	wri_snapc sc;
	uint8_t d[64], got[64];
	uint32_t i, n;
	const sim_osd_rec *rec;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	memset(&sc, 0, sizeof(sc));
	sc.seq = 7, sc.n = 3, sc.cap = 3, sc.snaps = ids;
	fill(d, sizeof(d), 1);
	i = rq_write(&R, "obj.s", 0, d, sizeof(d), &sc, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_OK);
	n = rig_nrec(&R, 0);
	rec = rig_rec(&R, 0, n - 1u);
	WRT_CHECK(rec->snap_seq == 7u && rec->n_snaps == 3u && rec->snapid == WRI_SNAP_NOSNAP);
	/* the context is read at every transmission: the image's current one, wherever the owner keeps it */
	ids[0] = 9;
	sc.seq = 9;
	i = rq_write(&R, "obj.s", 64, d, sizeof(d), &sc, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_OK);
	rec = rig_rec(&R, 0, rig_nrec(&R, 0) - 1u);
	WRT_CHECK(rec->snap_seq == 9u && rec->n_snaps == 3u);
	/* a read ignores it */
	i = rq_read(&R, "obj.s", 0, 64, got, 0);
	WRT_CHECK(i != WRI_NIL && rq_at(&R, i)->snapc == NULL);
	rq_at(&R, i)->snapc = &sc;
	WRT_CHECK(rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_OK);
	rec = rig_rec(&R, 0, rig_nrec(&R, 0) - 1u);
	WRT_CHECK(rec->snap_seq == 0u && rec->n_snaps == 0u && rec->flags == 0x08400014u);
	/* an invalid context (not descending) is refused by the encoder: the op ends with that, nothing reaches the OSD */
	ids[0] = 2, ids[1] = 5, ids[2] = 7;
	n = rig_nrec(&R, 0);
	i = rq_write(&R, "obj.s", 0, d, sizeof(d), &sc, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000));
	WRT_CHECK(rq_at(&R, i)->status == WR_E_INVAL && rig_nrec(&R, 0) == n && rig_take(&R, i) == WR_E_INVAL);
	WRT_CHECK(R.o.n_failed == 1u && R.o.err.status == WR_E_INVAL && rig_idle(&R));
	rig_close(&R);
}

static void tweak_v8(rig *r) { r->w.ocfg[0].v8_only = 1; }

static void test_v8(void)
{
	uint8_t d[32], got[32];
	uint32_t i;

	if (rig_open(&R, 1, 2, tweak_v8) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(d, sizeof(d), 4);
	i = rq_write(&R, "obj.v8", 0, d, sizeof(d), NULL, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_OK);
	i = rq_read(&R, "obj.v8", 0, sizeof(got), got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_OK && memcmp(got, d, sizeof(d)) == 0);
	WRT_CHECK(rig_rec(&R, 0, 0)->version == 8u && rig_rec(&R, 0, 1)->version == 8u && sim_osd_n_violations(R.w.osd[0]) == 0u);
	rig_close(&R);
}


static void tweak_ordersnap(rig *r)
{
	r->w.e.x.cfg.osd_flags = WR_OSDF_FULL_TRY | WR_OSDF_HONOR_PAUSE | WR_OSDF_ORDERSNAP;
}

/* The config switches and the clock that go into a message when it is encoded: ORDERSNAP on writes only, mtime from the wall clock (the OSD stores it). */
static void test_encode_time_switches(void)
{
	uint8_t d[64], got[64], st[16];
	uint32_t i, n;
	uint64_t sz = 0;
	uint32_t ms = 0, mn = 0;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, tweak_ordersnap) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(d, sizeof(d), 6);
	R.w.e.x.now.wall_ms = 1700000123456ull;
	i = rq_write(&R, "tm", 0, d, sizeof(d), NULL, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 1000) && rig_take(&R, i) == WR_OK);
	n = rig_nrec(&R, 0);
	WRT_CHECK((rig_rec(&R, 0, n - 1u)->flags & WRI_OSDF_ORDERSNAP) != 0u && (rig_rec(&R, 0, n - 1u)->flags & WRI_OSDF_FULL_TRY) != 0u);
	i = rq_read(&R, "tm", 0, 64, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 1000) && rig_take(&R, i) == WR_OK);
	WRT_CHECK((rig_rec(&R, 0, rig_nrec(&R, 0) - 1u)->flags & WRI_OSDF_ORDERSNAP) == 0u && rig_rec(&R, 0, rig_nrec(&R, 0) - 1u)->flags == 0x08400014u);
	/* the OSD kept the wall clock of the write as the object's mtime */
	i = rq_alloc(&R, WRI_OPK_READ, "tm", 0, 0);
	op = wri_osdc_at(&R.o, i);
	op->ops[0].code = WRI_OSD_OP_STAT;
	op->out = st;
	op->out_cap = 16;
	WRT_CHECK(rq_submit(&R, i) == i && rig_until_done(&R, i, 1000) && op->status == WR_OK);
	WRT_CHECK_STATUS(WR_OK, wri_osd_stat_decode(st, 16, &sz, &ms, &mn));
	WRT_CHECK(ms == 1700000123u && mn == 456000000u && sz == 64u);
	WRT_CHECK(rig_take(&R, i) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

/* ---- many in flight, several OSDs, completion order -------------------------------------------------------------------------------- */

static void test_many(void)
{
	enum { N = 24 };
	char name[N][16];
	uint8_t data[N][300], got[N][300];
	uint32_t idx[N], i, k;
	unsigned n_done = 0;
	uint64_t last = 0;

	if (rig_open(&R, 3, 3, tweak_three) != 0) {
		WRT_CHECK(0);
		return;
	}
	for (i = 0; i < N; i++) {
		snprintf(name[i], sizeof(name[i]), "many.%u", i);
		fill(data[i], sizeof(data[i]), i);
		WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, name[i], 0, data[i], sizeof(data[i])));
		memset(got[i], 0, sizeof(got[i]));
		idx[i] = rq_read(&R, name[i], 0, sizeof(got[i]), got[i], 0x100u + i);
		WRT_CHECK(idx[i] != WRI_NIL);
	}
	WRT_CHECK(R.o.n_inflight == (uint32_t)N && R.o.hiwater == (uint32_t)N && wri_osdc_count_owner(&R.o, 0x100u, 0xffffff00u) == (uint32_t)N);
	WRT_CHECK(wri_osdc_deadline(&R.o) <= rig_now(&R)); /* nothing is targeted yet: run now */
	(void)rig_settle(&R);
	for (i = 0; i < N; i++)
		WRT_CHECK(rq_done(&R, idx[i]) && rq_at(&R, idx[i])->status == WR_OK && memcmp(got[i], data[i], sizeof(got[i])) == 0);
	/* one session per OSD, every op went to the OSD its PG names */
	WRT_CHECK(R.o.sess.hiwater == 3u && R.o.n_done == (uint64_t)N && R.o.n_resent == 0u && R.o.n_inflight == 0u && R.o.inflight_bytes == 0u);
	for (k = 0; k < 3; k++) {
		uint32_t n = rig_nrec(&R, k), j;

		last = 0;
		WRT_CHECK(n != 0u);
		for (j = 0; j < n; j++) {
			const sim_osd_rec *rec = rig_rec(&R, k, j);

			WRT_CHECK(rec->pg_seed % 3u == k && rec->tid > last); /* ascending tids on every connection */
			last = rec->tid;
		}
	}
	/* the done list is in completion order and every op comes out exactly once */
	while ((i = wri_osdc_pop_done(&R.o)) != WRI_NIL) {
		WRT_CHECK(rq_at(&R, i)->state == WRI_OP_DONE && (rq_at(&R, i)->flags & WRI_OPF_INRING) == 0);
		wri_osdc_release(&R.o, i);
		n_done++;
	}
	WRT_CHECK(n_done == (uint32_t)N && rig_idle(&R) && wri_osdc_pop_done(&R.o) == WRI_NIL);
	rig_close(&R);
}

static void tweak_hold_rev(rig *r)
{
	r->w.ocfg[0].fault.hold_replies = 1;
	r->w.ocfg[0].fault.reverse_release = 1;
}

static void test_completion_order(void)
{
	uint8_t d[3][64], got[3][64];
	uint32_t i[3], p[3], k;

	if (rig_open(&R, 1, 2, tweak_hold_rev) != 0) {
		WRT_CHECK(0);
		return;
	}
	for (k = 0; k < 3; k++) {
		char nm[16];

		snprintf(nm, sizeof(nm), "ord.%u", k);
		fill(d[k], 64, k);
		WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, nm, 0, d[k], 64));
		i[k] = rq_read(&R, nm, 0, 64, got[k], 0);
	}
	(void)rig_settle(&R);
	WRT_CHECK(sim_osd_n_held(R.w.osd[0]) == 3u && !rq_done(&R, i[0]) && !rq_done(&R, i[1]) && !rq_done(&R, i[2]));
	(void)sim_osd_release(R.w.osd[0], 0); /* newest first */
	(void)rig_settle(&R);
	p[0] = wri_osdc_pop_done(&R.o), p[1] = wri_osdc_pop_done(&R.o), p[2] = wri_osdc_pop_done(&R.o);
	WRT_CHECK(p[0] == i[2] && p[1] == i[1] && p[2] == i[0] && wri_osdc_pop_done(&R.o) == WRI_NIL);
	for (k = 0; k < 3; k++) {
		WRT_CHECK(memcmp(got[k], d[k], 64) == 0);
		wri_osdc_release(&R.o, i[k]);
	}
	WRT_CHECK(rig_idle(&R));
	/* release of a completed op that was not popped yet is refused: the ring would keep a slot that could be reused */
	{
		uint32_t a = rq_read(&R, "ord.0", 0, 64, got[0], 0);

		sim_osd_faults(R.w.osd[0])->hold_replies = 0;
		WRT_CHECK(a != WRI_NIL && rig_until_done(&R, a, 5000));
		wri_osdc_release(&R.o, a);
		WRT_CHECK(rq_at(&R, a)->state == WRI_OP_DONE && R.o.n_free == R.o.n_op - 1u);
		WRT_CHECK(wri_osdc_pop_done(&R.o) == a);
		wri_osdc_release(&R.o, a);
		WRT_CHECK(rig_idle(&R));
	}
	rig_close(&R);
}

/* ---- errno mapping and the data-length checks of a reply ------------------------------------------------------------------------------ */

static void tweak_eio_read(rig *r)
{
	r->w.ocfg[0].fault.force_errno_op = WRI_OSD_OP_READ;
	r->w.ocfg[0].fault.force_errno = -WRI_ERRNO_EIO;
}

static void test_errno(void)
{
	uint8_t got[64];
	uint32_t i;

	if (rig_open(&R, 1, 2, tweak_eio_read) != 0) {
		WRT_CHECK(0);
		return;
	}
	i = rq_read(&R, "x", 0, 64, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000));
	WRT_CHECK(rq_at(&R, i)->status == WR_E_OSD_IO && rq_at(&R, i)->result == -WRI_ERRNO_EIO && rig_take(&R, i) == WR_E_OSD_IO);
	{
		static const int32_t errs[4] = {WRI_ERRNO_EPERM, WRI_ERRNO_ENOSPC, WRI_ERRNO_EBLOCKLISTED, WRI_ERRNO_EINVAL};
		static const wr_status want[4] = {WR_E_OSD_PERM, WR_E_OSD_NOSPC, WR_E_OSD_BLOCKLISTED, WR_E_OSD_ERRNO};
		unsigned k;

		for (k = 0; k < 4; k++) {
			sim_osd_faults(R.w.osd[0])->force_errno = -errs[k];
			i = rq_read(&R, "x", 0, 64, got, 0);
			WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000));
			WRT_CHECK(rq_at(&R, i)->status == want[k] && rq_at(&R, i)->result == -errs[k]);
			WRT_CHECK(rig_take(&R, i) == want[k]);
		}
	}
	/* the first failure is remembered, and a success clears it */
	WRT_CHECK(R.o.err.status != WR_OK && R.o.n_failed == 5u);
	sim_osd_faults(R.w.osd[0])->force_errno_op = 0;
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "x", 0, got, 64));
	i = rq_read(&R, "x", 0, 64, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_OK && R.o.err.status == WR_OK);
	rig_close(&R);
}

static void tweak_eopnotsupp_read(rig *r)
{
	r->w.ocfg[0].fault.force_errno_op = WRI_OSD_OP_READ;
	r->w.ocfg[0].fault.force_errno = -WRI_ERRNO_EOPNOTSUPP;
}

/* "Not supported" is a missing class or method only for a CALL; for a data read it must not look like a missing object (which reads as zeros). The first
 * failure since the last success is the one the engine keeps, with the errno beside it. */
static void test_errno_data_vs_call_and_first_failure(void)
{
	uint8_t got[64];
	uint32_t i;

	if (rig_open(&R, 1, 2, tweak_eopnotsupp_read) != 0) {
		WRT_CHECK(0);
		return;
	}
	i = rq_read(&R, "x", 0, 64, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000));
	WRT_CHECK(rq_at(&R, i)->status == WR_E_OSD_ERRNO && rq_at(&R, i)->result == -WRI_ERRNO_EOPNOTSUPP && rig_take(&R, i) == WR_E_OSD_ERRNO);
	WRT_CHECK(R.o.err.status == WR_E_OSD_ERRNO && R.o.err.peer_result == -WRI_ERRNO_EOPNOTSUPP && R.o.n_failed == 1u);
	sim_osd_faults(R.w.osd[0])->force_errno = -WRI_ERRNO_EIO; /* a second failure: counted, the first stays in err */
	i = rq_read(&R, "x", 0, 64, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_E_OSD_IO);
	WRT_CHECK(R.o.err.status == WR_E_OSD_ERRNO && R.o.err.peer_result == -WRI_ERRNO_EOPNOTSUPP && R.o.n_failed == 2u);
	rig_close(&R);
}

/* A hostile reply: the engine checks it against the op it answers. The simulator's own replies are always right, so these are injected on the
 * connection of the session the op is waiting on, while the real OSD stays silent. */
static uint32_t hold_op(rig *r, const char *oid, int kind_write, uint8_t *out, uint32_t len, uint32_t out_cap, uint32_t *s_out)
{
	static const uint8_t wdata[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	uint32_t i;
	wri_osd_op *op;

	sim_osd_faults(r->w.osd[0])->silent = 1;
	if (kind_write) {
		i = rq_write(r, oid, 0, wdata, sizeof(wdata), NULL, 0);
	} else {
		i = rq_read(r, oid, 0, len, out, 0);
		if (i != WRI_NIL)
			rq_at(r, i)->out_cap = out_cap; /* more room than the read asked for */
	}
	(void)rig_settle(r);
	op = rq_at(r, i);
	WRT_CHECK(op->state == WRI_OP_SENT && op->sess != WRI_NIL);
	*s_out = op->sess;
	return i;
}

static void test_hostile_replies(void)
{
	rframe f;
	uint32_t plen[2], i, s, j;
	uint8_t got[128], junk[128];
	wri_osd_op *op;
	uint64_t tid;
	uint32_t n_stale, n_res;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	memset(junk, 0x44, sizeof(junk));
	/* two operations come back for a one-operation request: the session refuses the reply and the op ends with the protocol error */
	i = hold_op(&R, "obj.h", 0, got, 32, 32, &s);
	op = rq_at(&R, i);
	plen[0] = plen[1] = 0;
	rf_reply(&f, "obj.h", 2, plen, 0, 0);
	WRT_CHECK_STATUS(WR_OK, rig_inject(&R, s, WRI_MSG_OSD_OPREPLY, op->tid, 8, f.b, f.n, NULL, 0));
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_E_OSD_PROTO && R.o.sess.n_bad_replies == 1u && op->out_stored == 0u);
	WRT_CHECK(rig_take(&R, i) == WR_E_OSD_PROTO && R.o.n_failed == 1u && R.o.n_inflight == 0u);
	/* the session closed itself: the next op reconnects after the cool-down and goes through */
	sim_osd_faults(R.w.osd[0])->silent = 0;
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "obj.h", 0, junk, 64));
	i = rq_read(&R, "obj.h", 0, 32, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 10000) && rig_take(&R, i) == WR_OK);
	/* a READ answers more bytes than it asked for although its buffer would hold them: protocol error */
	i = hold_op(&R, "obj.h", 0, got, 32, 128, &s);
	op = rq_at(&R, i);
	plen[0] = 48;
	rf_reply(&f, "obj.h", 1, plen, 0, 0);
	WRT_CHECK_STATUS(WR_OK, rig_inject(&R, s, WRI_MSG_OSD_OPREPLY, op->tid, 8, f.b, f.n, junk, 48));
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_E_OSD_PROTO && op->out_stored == 0u);
	WRT_CHECK(rig_take(&R, i) == WR_E_OSD_PROTO);
	/* a reply to a write that carries data although the op has no output buffer */
	rig_tick(&R, 10000);
	i = hold_op(&R, "obj.h", 1, NULL, 0, 0, &s);
	op = rq_at(&R, i);
	plen[0] = 8;
	rf_reply(&f, "obj.h", 1, plen, 0, 0);
	WRT_CHECK_STATUS(WR_OK, rig_inject(&R, s, WRI_MSG_OSD_OPREPLY, op->tid, 8, f.b, f.n, junk, 8));
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_E_OSD_PROTO);
	WRT_CHECK(rig_take(&R, i) == WR_E_OSD_PROTO);
	/* strays: a tid nobody waits for, a right slot with an old counter, a right counter in the wrong slot */
	rig_tick(&R, 10000);
	i = hold_op(&R, "obj.h", 0, got, 32, 32, &s);
	op = rq_at(&R, i);
	tid = op->tid;
	plen[0] = 32;
	rf_reply(&f, "obj.h", 1, plen, 0, 0);
	j = R.o.n_stray;
	R.o.stalled = 1; /* a stalled engine: replies nobody waits for are no sign that the ops that wait are being served */
	n_res = R.n_resume;
	WRT_CHECK_STATUS(WR_OK, rig_inject(&R, s, WRI_MSG_OSD_OPREPLY, 0x7777777700000000ull, 8, f.b, f.n, junk, 32));
	WRT_CHECK_STATUS(WR_OK, rig_inject(&R, s, WRI_MSG_OSD_OPREPLY, tid - 0x10000ull, 8, f.b, f.n, junk, 32));
	WRT_CHECK_STATUS(WR_OK, rig_inject(&R, s, WRI_MSG_OSD_OPREPLY, tid + 1u, 8, f.b, f.n, junk, 32));
	(void)rig_settle(&R);
	WRT_CHECK(R.o.n_stray == j + 3u && op->state == WRI_OP_SENT && op->tid == tid);
	WRT_CHECK(R.o.stalled == 1u && R.n_resume == n_res);
	/* a reply to an earlier transmission (retry_attempt 5, the op is at 0) is dropped without ending the op */
	n_stale = R.o.n_stale;
	rf_reply(&f, "obj.h", 1, plen, 0, 5);
	WRT_CHECK_STATUS(WR_OK, rig_inject(&R, s, WRI_MSG_OSD_OPREPLY, tid, 8, f.b, f.n, junk, 32));
	(void)rig_settle(&R);
	WRT_CHECK(R.o.n_stale == n_stale + 1u && op->state == WRI_OP_SENT);
	/* retry_attempt -1 (an OSD that does not echo it) and the right one both count */
	memset(got, 0, sizeof(got));
	rf_reply(&f, "obj.h", 1, plen, 0, -1);
	WRT_CHECK_STATUS(WR_OK, rig_inject(&R, s, WRI_MSG_OSD_OPREPLY, tid, 8, f.b, f.n, junk, 32));
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_OK && op->out_stored == 32u && memcmp(got, junk, 32) == 0 && got[32] == 0);
	WRT_CHECK(rig_take(&R, i) == WR_OK);
	/* the same tid again, now that the op is gone: a stray */
	j = R.o.n_stray;
	WRT_CHECK_STATUS(WR_OK, rig_inject(&R, s, WRI_MSG_OSD_OPREPLY, tid, 8, f.b, f.n, junk, 32));
	(void)rig_settle(&R);
	WRT_CHECK(R.o.n_stray == j + 1u && rig_idle(&R));
	rig_close(&R);
}

/* ---- owner tags ----------------------------------------------------------------------------------------------------------------------- */

static void test_owner(void)
{
	uint8_t got[16];
	uint32_t a, b, c;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	a = rq_read(&R, "o", 0, 16, got, 0x00010001u);
	b = rq_read(&R, "o", 0, 16, got, 0x00010002u);
	c = rq_read(&R, "o", 0, 16, got, 0x00020001u);
	WRT_CHECK(wri_osdc_count_owner(&R.o, 0x00010000u, 0xffff0000u) == 2u);
	WRT_CHECK(wri_osdc_count_owner(&R.o, 0x00020000u, 0xffff0000u) == 1u);
	WRT_CHECK(wri_osdc_count_owner(&R.o, 0x00010002u, 0xffffffffu) == 1u);
	WRT_CHECK(wri_osdc_count_owner(&R.o, 0, 0) == 3u && wri_osdc_count_owner(NULL, 0, 0) == 0u);
	WRT_CHECK(wri_osdc_cancel(&R.o, b) == WR_OK);
	WRT_CHECK(wri_osdc_count_owner(&R.o, 0x00010000u, 0xffff0000u) == 2u); /* a finished op is still its owner's until released */
	WRT_CHECK(wri_osdc_pop_done(&R.o) == b);
	wri_osdc_release(&R.o, b);
	WRT_CHECK(wri_osdc_count_owner(&R.o, 0x00010000u, 0xffff0000u) == 1u);
	(void)a;
	(void)c;
	rig_close(&R);
}

/* ---- edges: arguments, counters at their limits ----------------------------------------------------------------------------------- */

static void test_edges(void)
{
	uint8_t got[16];
	uint32_t i, n_done;
	uint64_t done_status;
	wri_ctx x2;
	wri_osdc o2;
	wri_arena a2, b2;
	wri_osd_map_ops mo;
	wri_osd_link l;
	uint8_t *mem;
	size_t a = 0, b = 0;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	wri_osdc_set_event(NULL, NULL, NULL);
	WRT_CHECK(wri_osdc_step(NULL, 4) == 0 && wri_osdc_deadline(NULL) == WR_DEADLINE_NONE && wri_osdc_at(NULL, 0) == NULL && wri_osdc_alloc(NULL, 0) == WRI_NIL);
	WRT_CHECK(wri_osdc_pop_done(NULL) == WRI_NIL && wri_osdc_cancel(NULL, 0) == WR_E_INVAL);
	/* the tid counter at its end: nothing more is admitted (the op stays the owner's) */
	R.o.next_tid = (uint64_t)1 << 47;
	i = rq_alloc(&R, WRI_OPK_READ, "e", 0, 0);
	R.o.op[i].ops[0].code = WRI_OSD_OP_READ;
	R.o.op[i].ops[0].len = 16;
	R.o.op[i].out = got;
	R.o.op[i].out_cap = 16;
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_osdc_submit(&R.o, i));
	wri_osdc_release(&R.o, i);
	R.o.next_tid = 1;
	/* the pass counter wraps: the marks of the old passes are forgotten and the engine goes on */
	R.o.pass = UINT32_MAX;
	i = rq_read(&R, "e", 0, 16, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000) && R.o.pass >= 1u && R.o.pass < 1000u && rig_take(&R, i) == WR_E_OSD_NOENT);
	/* an op completes once: a second completion of a finished op changes nothing */
	i = rq_read(&R, "e", 0, 16, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000));
	n_done = (uint32_t)R.o.n_done;
	done_status = (uint64_t)rq_at(&R, i)->status;
	wri_or_complete(&R.o, i, WR_E_CANCELLED);
	WRT_CHECK(R.o.n_done == n_done && (uint64_t)rq_at(&R, i)->status == done_status && R.o.done_len == 1u);
	WRT_CHECK(rig_take(&R, i) == (wr_status)done_status && rig_idle(&R));
	/* init: what it refuses (a copy of the context with a different configuration; the arenas are fresh) */
	WRT_CHECK_STATUS(WR_OK, wri_osdc_mem(&R.w.e.x.cfg, &a, &b));
	mem = (uint8_t *)calloc(1, a + b + 256u);
	WRT_CHECK(mem != NULL);
	if (mem != NULL) {
		mo = mw_ops(&R.m);
		memset(&l, 0, sizeof(l));
		l.ctx = &R.w, l.open = w_open, l.close = w_close, l.send = w_send, l.tx_idle = w_tx_idle, l.have_ticket = w_have_ticket,
		l.handshake_free = w_handshake_free;
		x2 = R.w.e.x;
		x2.cfg.osd_sessions = 0; /* the OSD client is off: there is no engine to make */
		wri_arena_init(&a2, (uint8_t *)(((uintptr_t)mem + 63u) & ~(uintptr_t)63u), a + 64u);
		wri_arena_init(&b2, (uint8_t *)(((uintptr_t)mem + 63u) & ~(uintptr_t)63u) + a + 64u, b);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_init(&o2, &x2, &a2, &b2, &mo, &l));
		x2 = R.w.e.x;
		x2.cfg.max_ops = 0;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_init(&o2, &x2, &a2, &b2, &mo, &l));
		x2 = R.w.e.x;
		x2.cfg.ctl_ops = x2.cfg.max_ops; /* no data slot at all */
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_init(&o2, &x2, &a2, &b2, &mo, &l));
		x2 = R.w.e.x;
		x2.cfg.op_timeout_ms = 0;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_init(&o2, &x2, &a2, &b2, &mo, &l));
		x2 = R.w.e.x;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_init(&o2, &x2, &a2, NULL, &mo, &l)); /* a zombie area is configured: the bulk region is needed */
		free(mem);
	}
	rig_close(&R);
}

int main(void)
{
	test_mem();
	test_init_exact();
	test_alloc_reserve();
	test_shape();
	test_tids();
	test_kinds();
	test_call_and_stat();
	test_snapc();
	test_v8();
	test_encode_time_switches();
	test_many();
	test_completion_order();
	test_errno();
	test_errno_data_vs_call_and_first_failure();
	test_hostile_replies();
	test_owner();
	test_edges();
	return wrt_finish();
}
