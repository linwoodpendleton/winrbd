/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the fake OSD, part 2: the operations. Requests are built by the test-local encoder of sim_osd_rig.h (and, for the captured ones, taken
 * byte for byte from harness/vectors/osdop) and answered by the OSD, and every rule of docs/spec/osd-ops.md 2.7 is checked on the reply:
 * READ (whole object, short, past the end, holes), SPARSE_READ (extents, holes, clipping), STAT, WRITE (creates, zero length past the end, EINVAL, EFBIG,
 * EMSGSIZE), WRITEFULL, ZERO (hole, rewritten to TRUNCATE at the end, no-op), TRUNCATE, DELETE, CREATE (EXCL, the category string), SETALLOCHINT,
 * GETXATTR, the omap reads with paging, CALL classification; the whole-message -ENOENT of a read-only message, FAILOK, the first failing op stops the
 * message, nothing of a failed message is applied, the output of a changed object is discarded, ZERO echoed as TRUNCATE; the name limits, the
 * snapshot context rules, clones and whiteouts of self-managed snapshots, the hook class, and the lab's own requests replayed against it.
 */
#include "sim_osd_rig.h"

#define POOL OR_POOL

static void up(ore *e, orc *c)
{
	ore_prep(e, WR_KEY_TYPE_AES256K);
	e->cfg.max_object_bytes = 1u << 20; /* a small limit makes EFBIG cheap */
	e->cfg.max_write_bytes = 64u << 10;
	ore_start(e);
	orc_up(c, e);
}

static void down(ore *e, orc *c)
{
	orc_free(c);
	ore_free(e);
}

static void fill(uint8_t *b, size_t n, uint8_t seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		b[i] = (uint8_t)(seed + i * 7u + 3u);
}

static or_req one(const char *oid, or_op op) { return or_one(oid, op); }

static or_req two(const char *oid, or_op a, or_op b)
{
	or_req r = or_one(oid, a);

	or_req_add(&r, b);
	return r;
}

static const or_reply *call(orc *c, const or_req *r)
{
	const or_reply *p = orc_call(c, r);

	WRT_CHECK(p != NULL && p->ok);
	return p != NULL && p->ok ? p : NULL;
}

/* a reply of a message that ran: ACK and ONDISK are set; of one that failed before: they are the request's */
static int acked(const or_reply *p) { return (p->flags & 5) == 5; }

static void put(ore *e, const char *oid, uint64_t off, const uint8_t *d, size_t n)
{
	WRT_CHECK_STATUS(WR_OK, sim_store_write(e->store, POOL, oid, off, d, n));
}

/* ---- reads ----------------------------------------------------------------------------------------------------------------------- */

static void t_read(void)
{
	ore e;
	orc c;
	uint8_t d[100], z[8196];
	or_req r;
	const or_reply *p;
	uint8_t seg[4];

	up(&e, &c);
	fill(d, sizeof(d), 5);
	put(&e, "r1", 0, d, sizeof(d));
	r = one("r1", or_read(0, 0)); /* length 0: the whole object */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->rval[0] == 0 && p->dlen == 100u && acked(p) && p->replay_ver == 0u);
	if (p != NULL && p->dlen == 100u) {
		WRT_CHECK(memcmp(p->data, d, 100) == 0);
		WRT_CHECK_U64(wri_le64_get(p->rec[0] + 14), 100); /* the reply's extent.length is what came back */
		WRT_CHECK_U64(p->payload_len[0], 100);
		WRT_CHECK(p->user_version != 0u);
	}
	r = one("r1", or_read(4, 0)); /* from 4 to the end */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 96u && memcmp(p->data, d + 4, 96) == 0);
	r = one("r1", or_read(40, 1000)); /* crossing the end is shortened */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 60u && p->result == 0 && memcmp(p->data, d + 40, 60) == 0);
	r = one("r1", or_read(100, 10)); /* at the end and past it: nothing, success */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 0u && p->result == 0 && p->rval[0] == 0 && wri_le64_get(p->rec[0] + 14) == 0u);
	r = one("r1", or_read(5000, 10));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 0u && p->result == 0);
	r = one("r1", or_read(10, 10));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 10u && memcmp(p->data, d + 10, 10) == 0);
	/* holes inside the object read as zeros */
	seg[0] = 1, seg[1] = 2, seg[2] = 3, seg[3] = 4;
	put(&e, "r1", 8192, seg, 4);
	r = one("r1", or_read(0, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 8196u);
	if (p != NULL && p->dlen == 8196u) {
		memset(z, 0, sizeof(z));
		memcpy(z, d, 100);
		memcpy(z + 8192, seg, 4);
		WRT_CHECK(memcmp(p->data, z, sizeof(z)) == 0);
	}
	/* a missing object fails the whole message before any op runs: -ENOENT, every rval 0, no data, no ACK */
	r = one("r-missing", or_read(0, 4096));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2 && p->rval[0] == 0 && p->dlen == 0u && p->n_ops == 1u && !acked(p) && (p->flags & 4) != 0);
	r = two("r-missing", or_stat(), or_read(0, 10));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2 && p->n_ops == 2u && p->rval[0] == 0 && p->rval[1] == 0 && p->dlen == 0u);
	/* two reads in one message: both outputs, in order */
	r = two("r1", or_stat(), or_read(0, 10));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->payload_len[0] == 16u && p->payload_len[1] == 10u && p->dlen == 26u);
	if (p != NULL && p->dlen == 26u) {
		WRT_CHECK_U64(wri_le64_get(p->data), 8196);
		WRT_CHECK(memcmp(p->data + 16, d, 10) == 0);
	}
	down(&e, &c);
}

static void t_sparse(void)
{
	ore e;
	orc c;
	uint8_t a[4096], b[100];
	or_req r;
	const or_reply *p;

	up(&e, &c);
	fill(a, sizeof(a), 1);
	fill(b, sizeof(b), 9);
	put(&e, "s1", 0, a, 4096);
	put(&e, "s1", 8192, a, 4096);
	put(&e, "s1", 20000, b, 100); /* inside page 4 */
	/* two allocated runs and a hole between them; absolute offsets, the data of the extents back to back */
	r = one("s1", or_sparse(0, 12288));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->rval[0] == 0 && p->dlen == 4u + 32u + 4u + 8192u);
	if (p != NULL && p->dlen == 4u + 32u + 4u + 8192u) {
		WRT_CHECK(wri_le32_get(p->data) == 2u);
		WRT_CHECK(wri_le64_get(p->data + 4) == 0 && wri_le64_get(p->data + 12) == 4096 && wri_le64_get(p->data + 20) == 8192 && wri_le64_get(p->data + 28) == 4096);
		WRT_CHECK(wri_le32_get(p->data + 36) == 8192u);
		WRT_CHECK(memcmp(p->data + 40, a, 4096) == 0 && memcmp(p->data + 40 + 4096, a, 4096) == 0);
		WRT_CHECK_U64(wri_le64_get(p->rec[0] + 14), 8192); /* extent.length of the reply = the data bytes */
	}
	r = one("s1", or_sparse(4096, 8192)); /* starts in the hole: one extent, clipped to the request */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 4u + 16u + 4u + 4096u && wri_le32_get(p->data) == 1u && wri_le64_get(p->data + 4) == 8192u);
	r = one("s1", or_sparse(100, 200)); /* inside the first run */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 4u + 16u + 4u + 200u && wri_le64_get(p->data + 4) == 100u && wri_le64_get(p->data + 12) == 200u);
	if (p != NULL && p->dlen == 224u)
		WRT_CHECK(memcmp(p->data + 24, a + 100, 200) == 0);
	r = one("s1", or_sparse(4096, 4096)); /* only a hole: u32 0, u32 0 */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 8u && wri_le32_get(p->data) == 0u && wri_le32_get(p->data + 4) == 0u && p->result == 0);
	r = one("s1", or_sparse(20050, 1000)); /* clipped at the end of the object (20100) */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 4u + 16u + 4u + 50u && wri_le64_get(p->data + 4) == 20050u && wri_le64_get(p->data + 12) == 50u);
	r = one("s1", or_sparse(0, 0)); /* length 0 asks for nothing (not "the whole object") */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 8u && wri_le32_get(p->data) == 0u);
	r = one("s1", or_sparse(30000, 10));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 8u && p->result == 0);
	r = one("s-missing", or_sparse(0, 4096));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2 && p->dlen == 0u);
	down(&e, &c);
}

/* ---- writes -------------------------------------------------------------------------------------------------------------------- */

static void t_write(void)
{
	ore e;
	orc c;
	uint8_t d[200], back[300], big[70000];
	or_req r;
	const or_reply *p;
	uint64_t sz = 0;
	int ex = 0;
	or_op bad;

	up(&e, &c);
	fill(d, sizeof(d), 3);
	/* WRITE creates the object; a write is answered with ACK | ONDISK, replay version, no output */
	r = one("w1", or_write(10, d, 100));
	r.mtime_s = 1700000123u;
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->rval[0] == 0 && p->dlen == 0u && acked(p) && p->replay_ver != 0u && p->replay_epoch == 42u && p->user_version != 0u);
	WRT_CHECK(sim_store_size(e.store, POOL, "w1", &sz) == WR_OK && sz == 110u);
	memset(back, 0xee, sizeof(back));
	(void)sim_store_read(e.store, POOL, "w1", 0, back, 110, &ex);
	WRT_CHECK(ex && memcmp(back + 10, d, 100) == 0 && back[0] == 0 && back[9] == 0);
	r = one("w1", or_stat());
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 16u && wri_le64_get(p->data) == 110u && wri_le32_get(p->data + 8) == 1700000123u && wri_le32_get(p->data + 12) == 0u);
	/* the versions go up with every change */
	{
		uint64_t v1 = sim_store_version(e.store, POOL, "w1"), v2;

		r = one("w1", or_write(0, d, 4));
		p = call(&c, &r);
		v2 = sim_store_version(e.store, POOL, "w1");
		WRT_CHECK(v2 > v1 && p != NULL && p->user_version == v2);
	}
	/* zero bytes at an offset past the end extend the object; at the end they change nothing but create */
	r = one("w2", or_write(5000, d, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0);
	WRT_CHECK(sim_store_size(e.store, POOL, "w2", &sz) == WR_OK && sz == 5000u);
	/* length differs from the data: -EINVAL, the op fails (it ran) */
	bad = or_write(0, d, 100);
	wri_le64_put(bad.rec + 14, 99);
	r = one("w3", bad);
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -22 && p->rval[0] == -22 && acked(p) && !sim_store_exists(e.store, POOL, "w3"));
	/* the object size limit (1 MiB here): offset == max fails even for length 0 */
	r = one("w4", or_write(1u << 20, d, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27 && p->rval[0] == -27);
	r = one("w4", or_write((1u << 20) - 100, d, 101));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	r = one("w4", or_write((1u << 20) - 100, d, 100));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0);
	/* a message with more data than osd_max_write_size (64 KiB here): -EMSGSIZE before anything runs */
	fill(big, sizeof(big), 1);
	r = one("w5", or_write(0, big, 70000));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -90 && p->rval[0] == 0 && !acked(p) && !sim_store_exists(e.store, POOL, "w5"));
	r = one("w5", or_write(0, big, 65536));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0);
	/* WRITEFULL replaces and shrinks, creates when absent */
	r = one("w1", or_writefull(d, 20));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0);
	WRT_CHECK(sim_store_size(e.store, POOL, "w1", &sz) == WR_OK && sz == 20u);
	(void)sim_store_read(e.store, POOL, "w1", 0, back, 20, &ex);
	WRT_CHECK(memcmp(back, d, 20) == 0);
	r = one("w6", or_writefull(d, 200));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && sim_store_exists(e.store, POOL, "w6"));
	r = one("w6", or_writefull(d, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && sim_store_size(e.store, POOL, "w6", &sz) == WR_OK && sz == 0u);
	/* the librbd shape: SETALLOCHINT (FAILOK) then WRITE */
	r = two("w7", or_allochint(), or_write(0, d, 50));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->n_ops == 2u && p->rval[0] == 0 && p->rval[1] == 0);
	WRT_CHECK(sim_store_size(e.store, POOL, "w7", &sz) == WR_OK && sz == 50u);
	down(&e, &c);
}

static void t_zero_truncate_delete(void)
{
	ore e;
	orc c;
	uint8_t d[8192], back[8192];
	or_req r;
	const or_reply *p;
	uint64_t sz = 0;
	int ex = 0;

	up(&e, &c);
	fill(d, sizeof(d), 7);
	put(&e, "z1", 0, d, 8192);
	/* a range in the middle: the pages it covers are holes, the rest is zeroed in place */
	r = one("z1", or_zero(100, 200));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->code[0] == 0x2204 && acked(p));
	(void)sim_store_read(e.store, POOL, "z1", 0, back, 8192, &ex);
	WRT_CHECK(memcmp(back, d, 100) == 0 && back[100] == 0 && back[299] == 0 && memcmp(back + 300, d + 300, 7892) == 0);
	WRT_CHECK(sim_store_size(e.store, POOL, "z1", &sz) == WR_OK && sz == 8192u);
	/* a whole page becomes a hole: the sparse read shows it */
	r = one("z1", or_zero(0, 4096));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->code[0] == 0x2204);
	r = one("z1", or_sparse(0, 8192));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && wri_le32_get(p->data) == 1u && wri_le64_get(p->data + 4) == 4096u && wri_le64_get(p->data + 12) == 4096u);
	/* a range that reaches the end becomes a TRUNCATE at the offset: the reply says so, the object does not grow */
	r = one("z1", or_zero(6000, 100000));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->code[0] == 0x2203);
	WRT_CHECK(sim_store_size(e.store, POOL, "z1", &sz) == WR_OK && sz == 6000u);
	r = one("z1", or_zero(6000, 10)); /* at or past the end: nothing */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && sz == 6000u && p->code[0] == 0x2204);
	r = one("z1", or_zero(100, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->code[0] == 0x2204);
	/* an absent object: success, nothing is created */
	r = one("z-missing", or_zero(0, 4096));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && !sim_store_exists(e.store, POOL, "z-missing"));
	r = one("z-missing", or_truncate(4096));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && !sim_store_exists(e.store, POOL, "z-missing"));
	/* TRUNCATE extends sparsely and shrinks; the bytes beyond a shrink are gone for good */
	r = one("z1", or_truncate(3u << 20 >> 2));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && sim_store_size(e.store, POOL, "z1", &sz) == WR_OK && sz == 786432u);
	r = one("z1", or_truncate(1u << 20));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	r = one("z1", or_truncate(5000));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0);
	r = one("z1", or_truncate(786432));
	(void)call(&c, &r);
	r = one("z1", or_read(4096, 4000));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 4000u);
	if (p != NULL && p->dlen == 4000u) {
		uint32_t i, nz = 0;

		for (i = 904; i < 4000u; i++)
			nz += p->data[i] != 0;
		WRT_CHECK_U64(nz, 0);
	}
	/* DELETE: -ENOENT when absent (the op ran, so ACK is set), gone otherwise */
	r = one("z1", or_delete());
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && !sim_store_exists(e.store, POOL, "z1"));
	r = one("z1", or_delete());
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2 && p->rval[0] == -2 && acked(p));
	WRT_CHECK_U64(sim_store_n_clones(e.store, POOL, "z1"), 0);
	down(&e, &c);
}

static void t_create_hint_xattr_omap(void)
{
	ore e;
	orc c;
	or_req r;
	const or_reply *p;
	uint8_t d[16];
	uint64_t sz = 1;
	char key[32];
	uint32_t i, n, off;
	const uint8_t *q;

	up(&e, &c);
	fill(d, sizeof(d), 2);
	r = one("c1", or_create(1));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && sim_store_size(e.store, POOL, "c1", &sz) == WR_OK && sz == 0u);
	r = one("c1", or_create(1));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -17 && p->rval[0] == -17);
	r = one("c1", or_create(0)); /* exists, not exclusive: a no-op */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0);
	{
		or_op op = or_create(0); /* the retired category string: well formed is fine, malformed is -EINVAL */
		uint8_t cat[6] = {2, 0, 0, 0, 'a', 'b'};

		op.ext = NULL;
		or_op_setpay(&op, cat, 6);
		r = one("c1", op);
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == 0);
		cat[0] = 9;
		or_op_setpay(&op, cat, 6);
		r = one("c1", op);
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -22);
	}
	r = one("c2", or_allochint()); /* creates an empty object by itself */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && sim_store_size(e.store, POOL, "c2", &sz) == WR_OK && sz == 0u);
	/* GETXATTR: the value; -ENODATA when the attribute is absent, -ENOENT when the object is */
	WRT_CHECK_STATUS(WR_OK, sim_store_xattr_set(e.store, POOL, "c1", "user.k", d, sizeof(d)));
	r = one("c1", or_getxattr("user.k"));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 16u && memcmp(p->data, d, 16) == 0 && wri_le32_get(p->rec[0] + 10) == 16u);
	r = one("c1", or_getxattr("nope"));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -61 && p->rval[0] == -61 && acked(p));
	r = one("c-missing", or_getxattr("user.k"));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2 && !acked(p));
	/* omap: 1100 keys, the page of 1024 and the one after it */
	for (i = 0; i < 1100u; i++) {
		uint8_t v[3];

		snprintf(key, sizeof(key), "key%05u", i);
		v[0] = (uint8_t)i, v[1] = (uint8_t)(i >> 8), v[2] = 7;
		WRT_CHECK_STATUS(WR_OK, sim_store_omap_set(e.store, POOL, "om", key, v, 3));
	}
	r = one("om", or_omap_vals("", 1024, ""));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen > 8u);
	if (p != NULL && p->dlen > 8u) {
		n = wri_le32_get(p->data);
		WRT_CHECK_U64(n, 1024);
		off = 4;
		for (i = 0; i < n; i++) { /* key string, value blob */
			uint32_t kl = wri_le32_get(p->data + off), vl;

			WRT_CHECK(kl == 8u && memcmp(p->data + off + 4, "key", 3) == 0);
			off += 4u + kl;
			vl = wri_le32_get(p->data + off);
			WRT_CHECK(vl == 3u);
			off += 4u + vl;
		}
		WRT_CHECK_U64(p->data[off], 1); /* truncated */
		WRT_CHECK_U64(off + 1u, p->dlen);
	}
	r = one("om", or_omap_vals("key01023", 1024, ""));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0);
	if (p != NULL) {
		n = wri_le32_get(p->data);
		WRT_CHECK_U64(n, 76);
		WRT_CHECK_U64(p->data[p->dlen - 1], 0); /* not truncated: the end marker */
	}
	r = one("om", or_omap_vals("", 10, "key0010"));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && wri_le32_get(p->data) == 10u && p->data[p->dlen - 1] == 0u); /* exactly 10 match: not cut */
	r = one("om", or_omap_vals("", 5, "key0010"));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && wri_le32_get(p->data) == 5u && p->data[p->dlen - 1] == 1u); /* one more matching key: cut */
	r = one("om", or_omap_vals("", 0, ""));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && wri_le32_get(p->data) == 0u && p->data[p->dlen - 1] == 1u);
	r = one("om", or_omap_vals("", 10, "zzz"));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && wri_le32_get(p->data) == 0u && p->data[p->dlen - 1] == 0u);
	r = one("om", or_omap_keys("key00009", 3));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && wri_le32_get(p->data) == 3u && p->data[p->dlen - 1] == 1u && memcmp(p->data + 8, "key00010", 8) == 0);
	{
		const char *want[3] = {"key00003", "nokey", "key00001"};

		r = one("om", or_omap_bykeys(want, 3)); /* absent keys are left out; the map comes back in key order */
		p = call(&c, &r);
		WRT_CHECK(p != NULL && wri_le32_get(p->data) == 2u);
		q = p != NULL ? p->data : NULL;
		if (q != NULL)
			WRT_CHECK(memcmp(q + 8, "key00001", 8) == 0);
	}
	/* an object without omap: an empty result, not an error; a missing object is the whole-message -ENOENT */
	r = one("c1", or_omap_vals("", 10, ""));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 5u);
	r = one("c-missing", or_omap_vals("", 10, ""));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2);
	down(&e, &c);
}

/* ---- message level rules ---------------------------------------------------------------------------------------------------------- */

static void t_message_rules(void)
{
	ore e;
	orc c;
	uint8_t d[64], back[64];
	or_req r;
	const or_reply *p;
	uint64_t sz = 0;
	int ex = 0;
	or_op de;

	up(&e, &c);
	fill(d, sizeof(d), 1);
	put(&e, "m1", 0, d, 64);
	/* the first failing op without FAILOK stops the message: its error is the result, the ones after keep rval 0 and are not run */
	r = two("m1", or_create(1), or_write(0, d, 10));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -17 && p->rval[0] == -17 && p->rval[1] == 0 && acked(p));
	/* with FAILOK the result goes back to 0, the op keeps its error, the later ops run */
	de = or_delete();
	wri_le32_put(de.rec + 2, 2);
	r = two("m-none", de, or_write(0, d, 10));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->rval[0] == -2 && p->rval[1] == 0 && sim_store_exists(e.store, POOL, "m-none"));
	/* nothing of a failed message is applied: the write before the failing op is rolled back, a created object is gone again */
	fill(d, 64, 99);
	r = two("m1", or_write(0, d, 64), or_create(1));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -17);
	fill(d, 64, 1);
	(void)sim_store_read(e.store, POOL, "m1", 0, back, 64, &ex);
	WRT_CHECK(memcmp(back, d, 64) == 0);
	{
		uint32_t before = sim_store_n_objects(e.store);

		r = two("m-new", or_write(0, d, 64), or_create(1)); /* EXCL after a write that made the object: -EEXIST */
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -17 && !sim_store_exists(e.store, POOL, "m-new") && sim_store_n_objects(e.store) == before);
	}
	/* the output of a message that changed the object is discarded, the rvals stay; a message that changed nothing keeps its output */
	r = two("m1", or_write(0, d, 4), or_read(0, 16));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 0u && p->payload_len[1] == 0u && p->rval[1] == 0);
	r = two("m1", or_create(0), or_read(0, 16)); /* CREATE of an existing object changes nothing */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 16u && p->payload_len[1] == 16u);
	/* a read-only message that fails inside: the earlier outputs are delivered */
	{
		or_op bad = or_getxattr("nope");

		r = two("m1", or_read(0, 8), bad);
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -61 && p->rval[1] == -61 && p->payload_len[0] == 8u && p->payload_len[1] == 0u && p->dlen == 8u);
	}
	/* unknown op codes: the op fails with -EOPNOTSUPP when it runs */
	{
		or_op u;

		or_op_init(&u, 0x1299, 0);
		r = one("m1", u);
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -95 && p->rval[0] == -95 && acked(p));
		or_op_init(&u, 0x2299, 0);
		r = one("m1", u);
		WRT_CHECK(call(&c, &r) != NULL);
		WRT_CHECK(sim_store_version(e.store, POOL, "m1") != 0u && !sim_store_is_whiteout(e.store, POOL, "m1"));
		WRT_CHECK(sim_store_size(e.store, POOL, "m1", &sz) == WR_OK && sz == 64u);
	}
	/* the flags of a request are looked at: PARALLELEXEC is -EINVAL, the rest is up to the op codes */
	r = one("m1", or_read(0, 4));
	r.flags = 0x08400214u;
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -22 && !acked(p));
	/* the name rules: empty, 2048 and 2049 bytes, a namespace of 257 */
	{
		char name[2100];
		const or_reply *q;

		memset(name, 'n', sizeof(name));
		name[2048] = '\0';
		r = one(name, or_write(0, d, 8));
		q = call(&c, &r);
		WRT_CHECK(q != NULL && q->result == 0);
		name[2049] = '\0';
		name[2048] = 'n';
		r = one(name, or_write(0, d, 8));
		q = call(&c, &r);
		WRT_CHECK(q != NULL && q->result == -36 && !acked(q));
		r = one("", or_write(0, d, 8));
		q = call(&c, &r);
		WRT_CHECK(q != NULL && q->result == -22);
		r = one("ns-obj", or_write(0, d, 8));
		memset(name, 's', 257);
		name[257] = '\0';
		r.nspace = name;
		q = call(&c, &r);
		WRT_CHECK(q != NULL && q->result == -36);
		r.nspace = "tenant";
		q = call(&c, &r);
		WRT_CHECK(q != NULL && q->result == 0);
		r = one("ns-obj", or_read(0, 8)); /* the namespace is part of the name: the default one does not have it */
		q = call(&c, &r);
		WRT_CHECK(q != NULL && q->result == -2);
		r.nspace = "tenant";
		q = call(&c, &r);
		WRT_CHECK(q != NULL && q->result == 0 && q->dlen == 8u);
	}
	/* CALL records are checked before anything runs: the lengths must add up to the payload */
	{
		or_op op = or_call("rbd", "get_id", NULL, 0);

		wri_le32_put(op.rec + 9, 99); /* indata_len that is not in the payload */
		r = one("m1", op);
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -22 && !acked(p));
	}
	down(&e, &c);
}

static or_req snapw(const char *oid, or_op op, uint64_t seq, const uint64_t *snaps, uint32_t n);

/* ---- sparse reads report exact byte ranges, as the lab's object store does -------------------------------------------------------------------------- */

/* "off+len off+len ..." of the extent map of a SPARSE_READ reply, "!" when the reply is malformed; the data length must be the sum of the extents */
static const char *ext_str(const or_reply *p, char *out, size_t cap)
{
	uint32_t n, i, at = 0;
	uint64_t total = 0;

	out[0] = '\0';
	if (p == NULL || !p->ok || p->result != 0 || p->dlen < 8u)
		return "!";
	n = wri_le32_get(p->data);
	if (n > 64u || 8u + 16u * (uint64_t)n > p->dlen)
		return "!";
	for (i = 0; i < n; i++) {
		int w = snprintf(out + at, cap - at, "%s%llu+%llu", i != 0 ? " " : "", (unsigned long long)wri_le64_get(p->data + 4u + 16u * i),
				 (unsigned long long)wri_le64_get(p->data + 12u + 16u * i));

		at += (uint32_t)w;
		total += wri_le64_get(p->data + 12u + 16u * i);
	}
	if (wri_le32_get(p->data + 4u + 16u * n) != total || p->dlen != 8u + 16u * n + total)
		return "!";
	return out;
}

static void sparse_is(orc *c, const char *oid, uint64_t off, uint64_t len, const char *want)
{
	char buf[256];
	or_req r = one(oid, or_sparse(off, len));
	const or_reply *p = orc_call(c, &r);

	if (strcmp(ext_str(p, buf, sizeof(buf)), want) != 0)
		fprintf(stderr, "sparse(%llu, %llu) on %s: got \"%s\", want \"%s\"\n", (unsigned long long)off, (unsigned long long)len, oid,
			p != NULL ? ext_str(p, buf, sizeof(buf)) : "(no reply)", want);
	WRT_CHECK(p != NULL && strcmp(ext_str(p, buf, sizeof(buf)), want) == 0);
}

static void wr_at(orc *c, const char *oid, uint64_t off, uint32_t n, uint8_t ch)
{
	uint8_t *d = (uint8_t *)malloc(n != 0 ? n : 1u);
	or_req r;

	memset(d, ch, n);
	r = one(oid, or_write(off, d, n));
	WRT_CHECK(call(c, &r) != NULL);
	free(d);
}

/* Every expectation below is what the lab's OSD (BlueStore) answered to the same operations: the ranges are exact bytes, a zeroed middle of a
 * block is a hole of its own, writes that touch are one range, and a write of zeros is data. */
static void t_sparse_exact(void)
{
	ore e;
	orc c;
	or_req r;
	const or_reply *p;

	ore_prep(&e, WR_KEY_TYPE_AES256K);
	e.cfg.max_object_bytes = 8u << 20;
	ore_start(&e);
	orc_up(&c, &e);
	wr_at(&c, "sp1", 0, 4096, 'A');
	wr_at(&c, "sp1", 1u << 20, 4096, 'B');
	wr_at(&c, "sp1", (2u << 20) + 17u, 100, 'C');
	sparse_is(&c, "sp1", 0, 3u << 20, "0+4096 1048576+4096 2097169+100");
	sparse_is(&c, "sp1", 100, 200, "100+200");
	sparse_is(&c, "sp1", 5000, 1000, "");
	sparse_is(&c, "sp1", 4096, 1u << 20, "1048576+4096");
	sparse_is(&c, "sp1", (2u << 20) + 10u, 1000, "2097169+100");
	sparse_is(&c, "sp1", (2u << 20) + 117u, 100, "");
	sparse_is(&c, "sp1", (2u << 20) + 200u, 100, "");
	r = one("sp1", or_zero(100, 200));
	WRT_CHECK(call(&c, &r) != NULL);
	sparse_is(&c, "sp1", 0, 4096, "0+100 300+3796");
	r = one("sp1", or_zero(0, 4096));
	WRT_CHECK(call(&c, &r) != NULL);
	sparse_is(&c, "sp1", 0, 8192, "");
	{
		static uint8_t z[4096];

		r = one("sp1", or_write(8192, z, sizeof(z))); /* zeros written on purpose are data */
		WRT_CHECK(call(&c, &r) != NULL);
	}
	sparse_is(&c, "sp1", 8192, 4096, "8192+4096");
	wr_at(&c, "sp1", 20000, 3, 'x');
	sparse_is(&c, "sp1", 16384, 8192, "20000+3");
	sparse_is(&c, "sp1", 19000, 2000, "20000+3");
	/* a hole-only object (truncated longer) and an object that is not there */
	r = one("sp2", or_create(0));
	WRT_CHECK(call(&c, &r) != NULL);
	r = one("sp2", or_truncate(100000));
	WRT_CHECK(call(&c, &r) != NULL);
	sparse_is(&c, "sp2", 0, 100000, "");
	r = one("sp-absent", or_sparse(0, 100));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2);
	/* ranges that touch merge, ranges that overlap are their union, a zero inside a big write splits it, a truncate cuts, an extension adds no data */
	wr_at(&c, "sp3", 0, 100, 'a');
	wr_at(&c, "sp3", 100, 100, 'b');
	wr_at(&c, "sp3", 300, 50, 'c');
	wr_at(&c, "sp3", 349, 10, 'd');
	sparse_is(&c, "sp3", 0, 1000, "0+200 300+59");
	wr_at(&c, "sp3", 10000, 70000, 'e');
	sparse_is(&c, "sp3", 0, 100000, "0+200 300+59 10000+70000");
	wr_at(&c, "sp3", 200000, 300, 'f');
	wr_at(&c, "sp3", 200500, 300, 'g');
	sparse_is(&c, "sp3", 190000, 20000, "200000+300 200500+300");
	r = one("sp3", or_zero(10100, 60000));
	WRT_CHECK(call(&c, &r) != NULL);
	sparse_is(&c, "sp3", 0, 100000, "0+200 300+59 10000+100 70100+9900");
	r = one("sp3", or_truncate(250));
	WRT_CHECK(call(&c, &r) != NULL);
	sparse_is(&c, "sp3", 0, 1000, "0+200");
	r = one("sp3", or_truncate(5000));
	WRT_CHECK(call(&c, &r) != NULL);
	sparse_is(&c, "sp3", 0, 10000, "0+200");
	wr_at(&c, "sp3", 4999, 1, 'z');
	sparse_is(&c, "sp3", 0, 10000, "0+200 4999+1");
	{
		static uint8_t w[10000];

		memset(w, 'w', sizeof(w));
		r = one("sp3", or_writefull(w, sizeof(w)));
		WRT_CHECK(call(&c, &r) != NULL);
	}
	sparse_is(&c, "sp3", 0, 20000, "0+10000");
	r = one("sp3", or_zero(0, 4096));
	WRT_CHECK(call(&c, &r) != NULL);
	sparse_is(&c, "sp3", 0, 20000, "4096+5904");
	r = one("sp3", or_zero(5000, 100));
	WRT_CHECK(call(&c, &r) != NULL);
	sparse_is(&c, "sp3", 0, 20000, "4096+904 5100+4900");
	sparse_is(&c, "sp3", 0, 0, ""); /* a length of 0 asks for nothing */
	/* a snapshot's clone keeps the ranges it had */
	{
		const uint64_t s4[1] = {4};

		r = snapw("sp3", or_zero(0, 20000), 4, s4, 1); /* clone for snapshot 4, then the head is truncated to 0 */
		WRT_CHECK(call(&c, &r) != NULL);
		r = one("sp3", or_sparse(0, 20000));
		r.snapid = 4;
		p = call(&c, &r);
		WRT_CHECK(p != NULL && strcmp(ext_str(p, (char[128]){0}, 128), "4096+904 5100+4900") == 0);
	}
	down(&e, &c);
}

/* ---- 64-bit extremes in the extent fields (what a hostile or buggy client sends) ------------------------------------------------------------------ */

static void t_extreme_extents(void)
{
	ore e;
	orc c;
	uint8_t d[100];
	or_req r;
	const or_reply *p;
	uint64_t sz = 0;

	up(&e, &c);
	fill(d, sizeof(d), 9);
	put(&e, "ex", 0, d, 100);
	/* reads: no wrap-around, the answer is clipped to the object */
	r = one("ex", or_read(UINT64_MAX, UINT64_MAX));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 0u);
	r = one("ex", or_read(50, UINT64_MAX));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 50u && memcmp(p->data, d + 50, 50) == 0);
	r = one("ex", or_read(UINT64_MAX - 10u, 100));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 0u);
	r = one("ex", or_sparse(UINT64_MAX, 1));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 8u && wri_le32_get(p->data) == 0u && wri_le32_get(p->data + 4) == 0u);
	r = one("ex", or_sparse(50, UINT64_MAX));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 4u + 16u + 4u + 50u && wri_le32_get(p->data) == 1u && wri_le64_get(p->data + 4) == 50u &&
		  wri_le64_get(p->data + 12) == 50u);
	r = one("ex", or_sparse(0, 1ull << 63));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && wri_le64_get(p->data + 12) == 100u);
	/* mutations: -EFBIG before anything is looked at or changed, never a wrap into a small range */
	r = one("ex", or_write(UINT64_MAX, d, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	r = one("ex", or_write(UINT64_MAX - 1u, d, 2));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	r = one("ex", or_zero(UINT64_MAX, UINT64_MAX));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	r = one("ex", or_zero(1, UINT64_MAX));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	r = one("ex", or_zero(UINT64_MAX, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	r = one("ex", or_truncate(UINT64_MAX));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	{
		or_op w = or_write(0, d, 8);

		wri_le64_put(w.rec + 14, UINT64_MAX); /* the claimed length is not the payload */
		r = one("ex", w);
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -22);
		w = or_writefull(d, 8);
		wri_le64_put(w.rec + 14, 7);
		r = one("ex", w);
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -22);
	}
	{
		or_op g = or_getxattr("name");

		wri_le32_put(g.rec + 6, 0xffffffffu); /* a name length that is not the payload */
		r = one("ex", g);
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -22);
	}
	WRT_CHECK(sim_store_size(e.store, POOL, "ex", &sz) == WR_OK && sz == 100u);
	down(&e, &c);
}

/* ---- the object size limit: ZERO and TRUNCATE order of checks, checked against the lab's OSD (osd_max_object_size 128 MiB there, 1 MiB here) -------------- */

static void t_range_limits(void)
{
	enum { MAX = 1 << 20 };
	ore e;
	orc c;
	uint8_t d[100];
	or_req r;
	const or_reply *p;
	uint64_t sz = 0;

	up(&e, &c);
	fill(d, sizeof(d), 3);
	put(&e, "rl", 0, d, 100);
	/* ZERO that reaches the end is turned into a TRUNCATE at the offset, and the TRUNCATE still checks the ORIGINAL length: -EFBIG, nothing changes */
	r = one("rl", or_zero(50, MAX));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27 && p->rval[0] == -27 && acked(p));
	WRT_CHECK(sim_store_size(e.store, POOL, "rl", &sz) == WR_OK && sz == 100u);
	r = one("rl", or_zero(10, (uint64_t)MAX + 1u));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	/* an ordinary ZERO (the range ends before the object does) is checked before the object is looked at: an absent object and a length of 0
	 * do not hide -EFBIG */
	r = one("rl-absent", or_zero(MAX, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27 && !sim_store_exists(e.store, POOL, "rl-absent"));
	r = one("rl-absent", or_zero(MAX, 5));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	r = one("rl", or_zero(MAX, 1));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	r = one("rl", or_zero(10, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->code[0] == 0x2204);
	/* at or past the end the ZERO is a no-op even when offset + length is beyond the limit (the offset is inside it) */
	r = one("rl", or_zero(MAX - 1, 5));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->code[0] == 0x2204);
	r = one("rl", or_zero(MAX - 5, 5));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0);
	WRT_CHECK(sim_store_size(e.store, POOL, "rl", &sz) == WR_OK && sz == 100u);
	r = one("rl", or_zero(0, MAX)); /* the whole object and exactly the limit: allowed, the object is truncated to 0 */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->code[0] == 0x2203);
	WRT_CHECK(sim_store_size(e.store, POOL, "rl", &sz) == WR_OK && sz == 0u);
	/* TRUNCATE: an absent object is a no-op before any check; otherwise offset >= limit is -EFBIG and the length field counts too */
	r = one("rl-absent", or_truncate(MAX));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && !sim_store_exists(e.store, POOL, "rl-absent"));
	r = one("rl", or_truncate(MAX));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	r = one("rl", or_truncate(MAX - 1));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && sim_store_size(e.store, POOL, "rl", &sz) == WR_OK && sz == (uint64_t)MAX - 1u);
	{
		or_op t = or_truncate(10);

		wri_le64_put(t.rec + 14, (uint64_t)MAX); /* a client that puts a length here: 10 + MAX is over the limit */
		r = one("rl", t);
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -27);
	}
	/* WRITE: zero bytes at the limit is -EFBIG and creates nothing; one byte at the last position is fine, two are not */
	r = one("rl-w", or_write(MAX, d, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27 && !sim_store_exists(e.store, POOL, "rl-w"));
	r = one("rl-w", or_write(MAX - 1, d, 1));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && sim_store_size(e.store, POOL, "rl-w", &sz) == WR_OK && sz == (uint64_t)MAX);
	r = one("rl-w", or_write(MAX - 1, d, 2));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -27);
	down(&e, &c);
}

/* ---- snapshots ---------------------------------------------------------------------------------------------------------------------- */

static or_req snapw(const char *oid, or_op op, uint64_t seq, const uint64_t *snaps, uint32_t n)
{
	or_req r = one(oid, op);
	uint32_t i;

	r.snap_seq = seq;
	r.n_snaps = n;
	for (i = 0; i < n; i++)
		r.snaps[i] = snaps[i];
	return r;
}

static void t_snapshots(void)
{
	ore e;
	orc c;
	uint8_t A[64], B[64], Cc[64];
	or_req r;
	const or_reply *p;
	const uint64_t s3[1] = {3}, s53[2] = {5, 3};
	int ex = 0;
	uint8_t back[64];

	up(&e, &c);
	memset(A, 'A', 64);
	memset(B, 'B', 64);
	memset(Cc, 'C', 64);
	r = snapw("sn", or_write(0, A, 64), 0, NULL, 0); /* an image without snapshots */
	WRT_CHECK(call(&c, &r) != NULL && sim_store_n_clones(e.store, POOL, "sn") == 0u);
	/* a write under a context that has a snapshot (3) newer than the object's last-seen one makes a clone of A */
	r = snapw("sn", or_write(0, B, 64), 3, s3, 1);
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && sim_store_n_clones(e.store, POOL, "sn") == 1u);
	(void)sim_store_read_snap(e.store, POOL, "sn", 3, 0, back, 64, &ex);
	WRT_CHECK(ex && memcmp(back, A, 64) == 0);
	(void)sim_store_read(e.store, POOL, "sn", 0, back, 64, &ex);
	WRT_CHECK(memcmp(back, B, 64) == 0);
	/* the same context again: no new clone */
	r = snapw("sn", or_write(0, B, 32), 3, s3, 1);
	WRT_CHECK(call(&c, &r) != NULL && sim_store_n_clones(e.store, POOL, "sn") == 1u);
	/* reads by snapshot id through the wire */
	r = one("sn", or_read(0, 64));
	r.snapid = 3;
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 64u && memcmp(p->data, A, 64) == 0);
	r.snapid = 4; /* newer than every clone and than the context: the head */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 64u && memcmp(p->data, B, 32) == 0);
	r.snapid = 2; /* the object did not exist at snapshot 2 (the clone holds 3 only) */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2 && !acked(p));
	r = one("sn", or_stat());
	r.snapid = 3;
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && wri_le64_get(p->data) == 64u);
	/* a second snapshot: clone 5 holds B; 4 was never a snapshot of this image */
	r = snapw("sn", or_write(0, Cc, 64), 5, s53, 2);
	WRT_CHECK(call(&c, &r) != NULL && sim_store_n_clones(e.store, POOL, "sn") == 2u);
	r = one("sn", or_read(0, 64));
	r.snapid = 5;
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 64u && memcmp(p->data, B, 64) == 0);
	r.snapid = 4;
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2);
	r.snapid = 3;
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->dlen == 64u && memcmp(p->data, A, 64) == 0);
	/* a stale context (seq 3 after 5): no clone and the head is overwritten; ORDERSNAP refuses it with -EOLDSNAPC */
	r = snapw("sn", or_write(0, A, 64), 3, s3, 1);
	WRT_CHECK(call(&c, &r) != NULL && sim_store_n_clones(e.store, POOL, "sn") == 2u);
	r.flags = 0x08400064u;
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -85 && !acked(p));
	/* DELETE with live snapshots leaves a whiteout: the head is gone for readers, the snapshots are not */
	r = snapw("sn", or_delete(), 5, s53, 2);
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && sim_store_is_whiteout(e.store, POOL, "sn") && !sim_store_exists(e.store, POOL, "sn"));
	r = one("sn", or_read(0, 64));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2 && !acked(p));
	r.snapid = 5;
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 64u);
	r = snapw("sn", or_delete(), 5, s53, 2); /* a delete of a whiteout is -ENOENT */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2 && p->rval[0] == -2);
	/* a new write recreates the head: no clone (nothing was there to keep) */
	r = snapw("sn", or_write(0, B, 64), 5, s53, 2);
	WRT_CHECK(call(&c, &r) != NULL && sim_store_exists(e.store, POOL, "sn") && !sim_store_is_whiteout(e.store, POOL, "sn") && sim_store_n_clones(e.store, POOL, "sn") == 2u);
	/* a delete under a newer context first clones the head, then leaves the whiteout */
	{
		const uint64_t s753[3] = {7, 5, 3};

		r = snapw("sn", or_delete(), 7, s753, 3);
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == 0 && sim_store_n_clones(e.store, POOL, "sn") == 3u && sim_store_is_whiteout(e.store, POOL, "sn"));
		r = one("sn", or_read(0, 64));
		r.snapid = 7;
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 64u && memcmp(p->data, B, 64) == 0);
	}
	/* no snapshots: a delete removes everything, and the name is free again */
	r = snapw("plain", or_write(0, A, 64), 0, NULL, 0);
	(void)call(&c, &r);
	r = snapw("plain", or_delete(), 0, NULL, 0);
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && !sim_store_is_whiteout(e.store, POOL, "plain") && !sim_store_exists(e.store, POOL, "plain"));
	/* a context of 100 snapshots (a long-lived image): accepted, one clone that serves every one of them */
	{
		uint64_t many[100];
		uint32_t i;

		for (i = 0; i < 100u; i++)
			many[i] = 300u - i; /* 300 .. 201, descending */
		r = snapw("many", or_write(0, A, 64), 0, NULL, 0);
		WRT_CHECK(call(&c, &r) != NULL);
		r = snapw("many", or_write(0, B, 64), 300, many, 100);
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == 0 && sim_osd_n_violations(e.osd) == 0u && sim_store_n_clones(e.store, POOL, "many") == 1u);
		r = one("many", or_read(0, 64));
		r.snapid = 250;
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 64u && memcmp(p->data, A, 64) == 0);
		r.snapid = 200; /* older than every snapshot of the context: the object was not there */
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -2);
	}
	/* a write may not name a snapshot; an invalid context is -EINVAL; neither is applied */
	r = one("bad", or_write(0, A, 8));
	r.snapid = 3;
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -22 && !acked(p) && !sim_store_exists(e.store, POOL, "bad"));
	{
		const uint64_t up_[2] = {3, 5}, zero_then[2] = {0, 0}, over[1] = {9};

		r = snapw("bad", or_write(0, A, 8), 5, up_, 2); /* ascending */
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -22);
		r = snapw("bad", or_write(0, A, 8), 5, over, 1); /* a snapshot newer than the seq */
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -22);
		r = snapw("bad", or_write(0, A, 8), 5, zero_then, 2); /* a 0 followed by another entry */
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -22);
		r = snapw("bad", or_write(0, A, 8), 0xfffffffffffffffeull, NULL, 0); /* seq above the maximum */
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -22);
		r = snapw("bad", or_read(0, 8), 0xfffffffffffffffeull, up_, 2); /* a read does not care */
		p = call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -2);
	}
	down(&e, &c);
}

/* ---- classes through the hook and the classification ----------------------------------------------------------------------------------- */

static int hook(void *ctx, sim_osd_cls_call *call, int run)
{
	uint32_t *n = (uint32_t *)ctx;

	if (strcmp(call->cls, "t0hook") != 0)
		return 0;
	if (strcmp(call->method, "echo") == 0 || strcmp(call->method, "poke") == 0 || strcmp(call->method, "pos") == 0) {
		if (!run) {
			call->writes = strcmp(call->method, "poke") == 0;
			return 1;
		}
		(*n)++;
		memcpy(call->out, call->in, call->in_len);
		call->out_len = call->in_len;
		call->rval = strcmp(call->method, "pos") == 0 ? 7 : 0;
		return 1;
	}
	return 0;
}

static void t_classes(void)
{
	ore e;
	orc c;
	or_req r;
	const or_reply *p;
	uint32_t runs = 0;
	uint8_t d[16];

	up(&e, &c);
	fill(d, sizeof(d), 4);
	put(&e, "k1", 0, d, 16);
	/* an unknown class: -EPERM before anything runs (the capture); an unknown method of a known class: -EOPNOTSUPP */
	r = one("k1", or_call("t0nosuchclass", "get", NULL, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -1 && p->rval[0] == 0 && !acked(p));
	r = one("k1", or_call("rbd", "t0_no_such_method", NULL, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -95 && p->rval[0] == 0 && !acked(p));
	r = two("k1", or_read(0, 4), or_call("lock", "t0_no_such_method", NULL, 0)); /* the whole message fails, the read does not run */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -95 && p->dlen == 0u);
	/* the hook: classification asks first (a read, a writer), execution follows */
	sim_osd_set_class_hook(e.osd, hook, &runs);
	r = one("k1", or_call("t0hook", "echo", "hello", 5));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 5u && memcmp(p->data, "hello", 5) == 0 && wri_le64_get(p->rec[0] + 14) == 5u && runs == 1u);
	{
		uint32_t n;
		const sim_osd_rec *rec = sim_osd_recs(e.osd, &n);

		WRT_CHECK(!rec[n - 1u].mutating);
	}
	r = one("k1", or_call("t0hook", "pos", "x", 1)); /* a positive return code is the op's rval and, last, the result of a read */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 7 && p->rval[0] == 7);
	r = one("k1", or_call("t0hook", "poke", "data", 4)); /* a writer that does not change the object: not discarded */
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 4u);
	{
		uint32_t n;
		const sim_osd_rec *rec = sim_osd_recs(e.osd, &n);

		WRT_CHECK(rec[n - 1u].mutating);
	}
	r = one("k1", or_call("t0hook", "unknown", NULL, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -1); /* the hook does not know the method: the class is unknown to the OSD */
	r = one("k1", or_call("t0other", "echo", NULL, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -1);
	sim_osd_set_class_hook(e.osd, NULL, NULL);
	r = one("k1", or_call("t0hook", "echo", "x", 1));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -1);
	down(&e, &c);
}

/* ---- a model ---------------------------------------------------------------------------------------------------------------------------- */

static uint64_t rng_state = 0x243f6a8885a308d3ull;

static uint32_t rnd(uint32_t n)
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (uint32_t)(((rng_state * 0x2545f4914f6cdd1dull) >> 33) % n);
}

/* Random writes, zeroes, truncates, full writes, deletes and reads through the wire against a flat byte array: every answer and, now and then, the
 * whole object in the store must be what the array says (holes are zeros, ZERO to the end is a TRUNCATE, nothing grows by a ZERO). */
static void t_model(void)
{
	enum { MAXSZ = 72000 };
	ore e;
	orc c;
	static uint8_t m[MAXSZ], buf[6000], back[MAXSZ];
	uint64_t msize = 0;
	int mex = 0;
	uint32_t step, bad_sparse = 0;

	up(&e, &c);
	memset(m, 0, sizeof(m));
	for (step = 0; step < 4000u; step++) {
		uint32_t k = rnd(100), off = rnd(65000), len = rnd(6000) + (rnd(8) == 0 ? 0u : 1u);
		or_req r;
		const or_reply *p;

		if (k < 30) { /* WRITE */
			fill(buf, len, (uint8_t)step);
			r = one("model", or_write(off, buf, len));
			p = call(&c, &r);
			WRT_CHECK(p != NULL && p->result == 0);
			if (len != 0) {
				memcpy(m + off, buf, len);
				if (off + len > msize)
					msize = off + len;
			} else if (off > msize) {
				msize = off;
			}
			mex = 1;
		} else if (k < 42) { /* ZERO */
			r = one("model", or_zero(off, len));
			p = call(&c, &r);
			WRT_CHECK(p != NULL && p->result == 0);
			if (mex && len != 0) {
				if (off + len >= msize) {
					if (off < msize) {
						memset(m + off, 0, (size_t)(msize - off));
						msize = off;
					}
				} else {
					memset(m + off, 0, len);
				}
			}
		} else if (k < 50) { /* TRUNCATE */
			r = one("model", or_truncate(off));
			p = call(&c, &r);
			WRT_CHECK(p != NULL && p->result == 0);
			if (mex) {
				if (off < msize)
					memset(m + off, 0, (size_t)(msize - off));
				msize = off;
			}
		} else if (k < 54) { /* WRITEFULL */
			fill(buf, len, (uint8_t)(step * 3u));
			r = one("model", or_writefull(buf, len));
			p = call(&c, &r);
			WRT_CHECK(p != NULL && p->result == 0);
			memset(m, 0, sizeof(m));
			memcpy(m, buf, len);
			msize = len;
			mex = 1;
		} else if (k < 56) { /* DELETE */
			r = one("model", or_delete());
			p = call(&c, &r);
			WRT_CHECK(p != NULL && p->result == (mex ? 0 : -2));
			memset(m, 0, sizeof(m));
			msize = 0;
			mex = 0;
		} else if (k < 80) { /* READ */
			uint64_t want = 0;

			r = one("model", or_read(off, rnd(4) == 0 ? 0u : len));
			p = call(&c, &r);
			if (p == NULL)
				continue;
			if (!mex) {
				WRT_CHECK(p->result == -2);
				continue;
			}
			{
				uint64_t rl = wri_le64_get(r.ops[0].rec + 14);

				if (off < msize)
					want = rl == 0 ? msize - off : (rl < msize - off ? rl : msize - off);
			}
			WRT_CHECK(p->result == 0 && p->dlen == want);
			if (p->dlen == want && want != 0)
				WRT_CHECK(memcmp(p->data, m + off, (size_t)want) == 0);
		} else { /* SPARSE_READ: the extents are ascending, inside the request, and the rest of the request is zeros */
			r = one("model", or_sparse(off, len));
			p = call(&c, &r);
			if (p == NULL)
				continue;
			if (!mex) {
				WRT_CHECK(p->result == -2);
				continue;
			}
			WRT_CHECK(p->result == 0 && p->dlen >= 8u);
			if (p->dlen >= 8u) {
				uint32_t n = wri_le32_get(p->data), i, at = 4, dat;
				uint64_t pos = off, end = off + len, total = 0;
				uint8_t *got = (uint8_t *)calloc(1, len + 1u);

				if (n > 2000u || 4u + 16u * n + 4u > p->dlen) {
					bad_sparse++;
				} else {
					dat = 4u + 16u * n + 4u;
					for (i = 0; i < n; i++) {
						uint64_t eo = wri_le64_get(p->data + at), el = wri_le64_get(p->data + at + 8);

						at += 16;
						if (eo < pos || eo + el > end || eo + el > msize || dat + total + el > p->dlen) {
							bad_sparse++;
							break;
						}
						memcpy(got + (eo - off), p->data + dat + total, (size_t)el);
						total += el;
						pos = eo + el;
					}
					if (wri_le32_get(p->data + 4u + 16u * n) != total)
						bad_sparse++;
					{
						uint64_t clip = off < msize ? (len < msize - off ? len : msize - off) : 0;

						if (memcmp(got, m + off, (size_t)clip) != 0)
							bad_sparse++;
					}
				}
				free(got);
			}
		}
		if (step % 250u == 249u) {
			int ex = 0;
			uint64_t sz = 0;

			(void)sim_store_read(e.store, POOL, "model", 0, back, MAXSZ, &ex);
			WRT_CHECK((ex != 0) == (mex != 0));
			WRT_CHECK(memcmp(back, m, MAXSZ) == 0);
			if (mex)
				WRT_CHECK(sim_store_size(e.store, POOL, "model", &sz) == WR_OK && sz == msize);
		}
	}
	WRT_CHECK_U64(bad_sparse, 0);
	down(&e, &c);
}

/* ---- the lab's own requests ------------------------------------------------------------------------------------------------------------- */

static int load_msg(const char *rel, uint8_t **front, size_t *flen, uint8_t **data, size_t *dlen, wrt_json *j, uint64_t *tid)
{
	wrt_tok root, rq, dt;
	int ok = 0;

	*data = NULL;
	*dlen = 0;
	if (wrt_json_load_vec(j, rel) != 0)
		return -1;
	root = wrt_json_root(j);
	rq = wrt_json_get(j, root, "request");
	if (wrt_json_get_hex(j, rq, "front_hex", front, flen) != 0)
		return -1;
	*tid = (uint64_t)wrt_json_int(j, wrt_json_get(j, rq, "tid"), &ok);
	dt = wrt_json_get(j, rq, "data");
	if (dt != WRT_NONE && wrt_json_get(j, dt, "hex") != WRT_NONE)
		return wrt_json_get_hex(j, dt, "hex", data, dlen);
	return 0;
}

/* replays the request of vector `rel` and compares the reply's decoded fields with the lab's */
static const or_reply *replay(orc *c, const char *rel, wrt_json *rj, int *ok)
{
	uint8_t *front = NULL, *data = NULL;
	size_t fl = 0, dl = 0;
	uint64_t tid = 0;
	wrt_json j;
	const or_reply *p;

	static uint64_t next_tid = 1000;

	*ok = 0;
	orc_forget(c);
	if (load_msg(rel, &front, &fl, &data, &dl, &j, &tid) != 0) {
		WRT_CHECK(!"vector loads");
		return NULL;
	}
	tid = next_tid++; /* the lab's tids are all 1: a write under one tid twice would be a resend */
	orc_send_raw(c, 42, 9, 3, tid, front, (uint32_t)fl, NULL, 0, data, (uint32_t)dl, 0);
	p = orc_reply(c, tid);
	WRT_CHECK(p != NULL && p->ok);
	*rj = j;
	free(front);
	free(data);
	*ok = p != NULL && p->ok;
	return *ok ? p : NULL;
}

static void check_against(const wrt_json *j, const or_reply *p)
{
	wrt_tok rp = wrt_json_get(j, wrt_json_root(j), "reply"), sm = wrt_json_get(j, rp, "summary"), ops;
	int ok = 0;
	size_t i;

	WRT_CHECK_U64((uint64_t)p->result, (uint64_t)wrt_json_int(j, wrt_json_get(j, sm, "result"), &ok));
	WRT_CHECK_U64((uint64_t)p->flags, (uint64_t)wrt_json_int(j, wrt_json_get(j, sm, "flags"), &ok));
	WRT_CHECK_U64(p->epoch, (uint64_t)wrt_json_int(j, wrt_json_get(j, sm, "epoch"), &ok));
	ops = wrt_json_get(j, sm, "ops");
	WRT_CHECK_U64(p->n_ops, wrt_json_count(j, ops));
	for (i = 0; i < wrt_json_count(j, ops) && i < p->n_ops; i++) {
		wrt_tok o = wrt_json_at(j, ops, i);

		WRT_CHECK_U64(p->payload_len[i], (uint64_t)wrt_json_int(j, wrt_json_get(j, o, "payload_len"), &ok));
		WRT_CHECK_U64(p->code[i], (uint64_t)wrt_json_int(j, wrt_json_get(j, o, "code"), &ok));
	}
	{
		wrt_tok rv = wrt_json_get(j, sm, "rvals");

		for (i = 0; i < wrt_json_count(j, rv) && i < p->n_ops; i++)
			WRT_CHECK_U64((uint64_t)p->rval[i], (uint64_t)wrt_json_int(j, wrt_json_at(j, rv, i), &ok));
	}
}

static void t_lab_vectors(void)
{
	ore e;
	orc c;
	wrt_json j;
	const or_reply *p;
	int ok;
	uint8_t pattern[100];
	uint32_t i;

	up(&e, &c);
	for (i = 0; i < 100u; i++)
		pattern[i] = (uint8_t)((i * 7u + 3u) % 251u);
	/* 01: rados put (WRITEFULL of 100 bytes); 02: stat; 03: read 4 MiB of it; 04: read of a missing object; 05: rados rm with FULL_FORCE */
	p = replay(&c, "osdop/01-rados-put-small.json", &j, &ok);
	if (ok) {
		check_against(&j, p);
		WRT_CHECK(sim_store_exists(e.store, POOL, "t0-small"));
		wrt_json_free(&j);
	}
	{
		uint8_t back[100];
		int ex = 0;

		(void)sim_store_read(e.store, POOL, "t0-small", 0, back, 100, &ex);
		WRT_CHECK(ex && memcmp(back, pattern, 100) == 0);
	}
	p = replay(&c, "osdop/02-rados-stat.json", &j, &ok);
	if (ok) {
		wrt_tok rq = wrt_json_get(&j, wrt_json_root(&j), "request");
		(void)rq;
		check_against(&j, p);
		WRT_CHECK(p->dlen == 16u && wri_le64_get(p->data) == 100u);
		wrt_json_free(&j);
	}
	p = replay(&c, "osdop/03-rados-read-whole.json", &j, &ok);
	if (ok) {
		check_against(&j, p);
		WRT_CHECK(p->dlen == 100u && memcmp(p->data, pattern, 100) == 0);
		wrt_json_free(&j);
	}
	p = replay(&c, "osdop/04-rados-read-enoent.json", &j, &ok);
	if (ok) {
		check_against(&j, p);
		wrt_json_free(&j);
	}
	p = replay(&c, "osdop/05-rados-delete.json", &j, &ok);
	if (ok) {
		check_against(&j, p);
		WRT_CHECK(!sim_store_exists(e.store, POOL, "t0-small"));
		wrt_json_free(&j);
	}
	down(&e, &c);
}

int main(void)
{
	t_read();
	t_sparse();
	t_write();
	t_zero_truncate_delete();
	t_create_hint_xattr_omap();
	t_message_rules();
	t_extreme_extents();
	t_sparse_exact();
	t_range_limits();
	t_snapshots();
	t_classes();
	t_model();
	t_lab_vectors();
	return wrt_finish();
}
