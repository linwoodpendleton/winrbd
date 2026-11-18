/* SPDX-License-Identifier: MIT */
/*
 * test_osd_sess_bo.c - the MOSDBackoff table of a session (design 21.5, osd-ops.md 3.7): BLOCK stored and acknowledged with the BLOCK's epoch, UNBLOCK
 * removing by id and telling the request layer which PG to resend, ACK_BLOCK ignored, what a position inside a range is (bit-reversed hash order,
 * half-open range, one object), coarse entries (long names, keys, namespaces, a position of another pool), a full table (merged into an entry of the
 * same PG, ids kept, the unblock of any of them), the table cleared when the connection is lost, the ACK_BLOCK bytes, a transmit queue that has no room
 * (the frame waits, nothing is lost), and the same against the real connection and sim_osd's BLOCK / UNBLOCK.
 */
#include "osd_sess_world.h"

static osr R;
static uint32_t S;

static int fresh(unsigned bo_slots)
{
	osr_free(&R);
	if (osr_init(&R, 3, 2048, bo_slots) != 0) {
		WRT_CHECK(0);
		return -1;
	}
	S = osr_get(&R, 1, ALL_FEATURES);
	WRT_CHECK(S != WRI_NIL);
	return S == WRI_NIL ? -1 : 0;
}

static uint32_t rev32(uint32_t v)
{
	uint32_t r = 0;
	unsigned i;

	for (i = 0; i < 32; i++)
		r |= ((v >> i) & 1u) << (31u - i);
	return r;
}

/* A BLOCK / UNBLOCK as the OSD sends it: the front bytes, with the strings kept alive in `st`. */
typedef struct blk {
	wri_mbackoff m;
	char bname[400], ename[400], bkey[40], ekey[40], bns[40], ens[40];
	uint8_t front[2048];
	uint32_t n;
} blk;

static void mk(blk *b, uint8_t op, uint64_t id, int64_t pool, uint32_t pg, uint32_t epoch, const char *bn, uint32_t bh, const char *en, uint32_t eh)
{
	memset(b, 0, sizeof(*b));
	b->m.pool = pool;
	b->m.pg_seed = pg;
	b->m.map_epoch = epoch;
	b->m.op = op;
	b->m.id = id;
	snprintf(b->bname, sizeof(b->bname), "%s", bn);
	snprintf(b->ename, sizeof(b->ename), "%s", en);
	b->m.begin.oid = (const uint8_t *)b->bname;
	b->m.begin.oid_len = (uint32_t)strlen(b->bname);
	b->m.begin.hash = bh;
	b->m.begin.snap = WRI_SNAP_NOSNAP;
	b->m.begin.pool = pool;
	b->m.end.oid = (const uint8_t *)b->ename;
	b->m.end.oid_len = (uint32_t)strlen(b->ename);
	b->m.end.hash = eh;
	b->m.end.snap = WRI_SNAP_NOSNAP;
	b->m.end.pool = pool;
	b->m.begin.key = b->m.end.key = (const uint8_t *)"";
	b->m.begin.nspace = b->m.end.nspace = (const uint8_t *)"";
	b->n = rf_backoff(b->front, sizeof(b->front), &b->m, op);
	WRT_CHECK(b->n != 0u);
}

static wr_status deliver(const blk *b)
{
	return osr_frame(&R, S, WRI_MSG_OSD_BACKOFF, 0, 1, 1, b->front, b->n, NULL, 0, NULL, 0, NULL);
}

static int blocked(int64_t pool, uint32_t pg, uint32_t hash, const char *name)
{
	return wri_osd_sess_blocked(&R.t, S, pool, pg, hash, (const uint8_t *)name, (uint32_t)strlen(name));
}

#define POOL 2
#define PG 3u

/* ---- BLOCK, ACK_BLOCK, UNBLOCK -------------------------------------------------------------------------------------------------- */

static void test_block_ack_unblock(void)
{
	blk b;
	wri_mbackoff ack;
	const fk_sent *a;
	uint32_t lo = rev32(0x30000000u), hi = rev32(0x50000000u);

	if (fresh(4) != 0)
		return;
	mk(&b, WRI_BACKOFF_BLOCK, 5, POOL, PG, 77, "", lo, "", hi);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(R.t.s[S].n_backoff == 1u && R.t.n_backoff_blocks == 1u && R.t.n_backoff_overflow == 0u && R.t.n_backoff_noack == 0u);
	/* the acknowledgement: type 61, priority 63, v1 / compat 1, queued at once on this very connection */
	WRT_CHECK(R.f.n_sent == 1u);
	a = &R.f.sent[0];
	WRT_CHECK(a->slot == R.t.s[S].conn_slot && a->m.type == 61u && a->m.priority == 63u && a->m.version == 1u && a->m.compat_version == 1u);
	WRT_CHECK(a->m.tid == 0u && a->m.data_len == 0u);
	/* its bytes are the BLOCK with the op changed, at the epoch of the BLOCK: spg_t 24, epoch 4 (77), op (2), id 8, the two positions */
	WRT_CHECK(a->front_len == b.n && a->front[28] == 2u && wri_le32_get(a->front + 24) == 77u && wri_le64_get(a->front + 29) == 5u);
	WRT_CHECK(memcmp(a->front, b.front, 28) == 0 && memcmp(a->front + 29, b.front + 29, b.n - 29u) == 0);
	WRT_CHECK_STATUS(WR_OK, wri_mbackoff_decode(a->front, a->front_len, 1, 1, &ack));
	WRT_CHECK(ack.op == WRI_BACKOFF_ACK_BLOCK && ack.id == 5u && ack.pool == POOL && ack.pg_seed == PG && ack.map_epoch == 77u);
	WRT_CHECK(ack.begin.hash == lo && ack.end.hash == hi && ack.begin.oid_len == 0u && ack.end.oid_len == 0u);
	/* the OSD's ACK_BLOCK, if it ever sends one, is not a BLOCK: nothing happens */
	mk(&b, WRI_BACKOFF_ACK_BLOCK, 5, POOL, PG, 77, "", lo, "", hi);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(R.t.s[S].n_backoff == 1u && R.f.n_sent == 1u && R.r.n_unblock == 0u && R.t.n_backoff_blocks == 1u);
	/* a position holds if its bit-reversed hash lies in [lo, hi): the hash of every object of the PG is spread over all of it */
	WRT_CHECK(blocked(POOL, PG, rev32(0x40000000u), "rbd_data.1.0000000000000007"));
	WRT_CHECK(blocked(POOL, PG, rev32(0x30000001u), "x"));
	WRT_CHECK(!blocked(POOL, PG, rev32(0x2fffffffu), "x"));
	WRT_CHECK(!blocked(POOL, PG, rev32(0x50000000u), "x"));      /* the end is not in the range */
	WRT_CHECK(blocked(POOL, PG, rev32(0x4fffffffu), "x"));        /* the last key before it is */
	/* another PG or another pool is never held by it, whatever the hash */
	WRT_CHECK(!blocked(POOL, PG + 1u, rev32(0x40000000u), "x"));
	WRT_CHECK(!blocked(POOL + 1, PG, rev32(0x40000000u), "x"));
	/* bad arguments */
	WRT_CHECK(wri_osd_sess_blocked(&R.t, S, POOL, PG, rev32(0x40000000u), NULL, 3) == 0);
	WRT_CHECK(wri_osd_sess_blocked(&R.t, 99, POOL, PG, rev32(0x40000000u), (const uint8_t *)"x", 1) == 0);
	WRT_CHECK(wri_osd_sess_blocked(NULL, 0, POOL, PG, 0, (const uint8_t *)"x", 1) == 0);
	WRT_CHECK(wri_osd_sess_blocked(&R.t, S, POOL, PG, rev32(0x40000000u), (const uint8_t *)"", 0) == 1); /* an empty name is a position too */
	/* UNBLOCK: by id, whatever range it names (the PG may have split: a smaller one removes the entry anyway) */
	mk(&b, WRI_BACKOFF_UNBLOCK, 5, POOL, PG, 77, "", lo, "", rev32(0x40000000u));
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(R.t.s[S].n_backoff == 0u && R.r.n_unblock == 1u && R.r.unblock[0].s == S && R.r.unblock[0].pool == POOL && R.r.unblock[0].pg == PG);
	WRT_CHECK(!blocked(POOL, PG, rev32(0x40000000u), "x") && R.f.n_sent == 1u); /* an UNBLOCK is not acknowledged */
	/* an UNBLOCK of an id that is not held: nothing to release (the table never lost one) */
	mk(&b, WRI_BACKOFF_UNBLOCK, 6, POOL, PG, 77, "", lo, "", hi);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(R.r.n_unblock == 1u);
	/* an UNBLOCK that names another PG than the entry it removes releases both */
	mk(&b, WRI_BACKOFF_BLOCK, 7, POOL, PG, 80, "", lo, "", hi);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	mk(&b, WRI_BACKOFF_UNBLOCK, 7, POOL, PG + 8u, 81, "", lo, "", hi);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(R.r.n_unblock == 3u && R.r.unblock[1].pg == PG && R.r.unblock[2].pg == PG + 8u);
	WRT_CHECK(R.t.s[S].n_backoff == 0u);
	/* a repeated BLOCK id replaces its entry */
	mk(&b, WRI_BACKOFF_BLOCK, 9, POOL, PG, 82, "", lo, "", hi);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(R.t.s[S].n_backoff == 1u && R.t.n_backoff_blocks == 4u); /* ids 5, 7, 9 and 9 again; the ACK_BLOCK and the UNBLOCKs are no BLOCKs */
}

/* ---- positions ------------------------------------------------------------------------------------------------------------------ */

static void test_positions(void)
{
	blk b;
	uint32_t h = rev32(0x40000000u);

	if (fresh(8) != 0)
		return;
	/* one object: begin == end */
	mk(&b, WRI_BACKOFF_BLOCK, 1, POOL, PG, 5, "rbd_data.9.0000000000000001", h, "rbd_data.9.0000000000000001", h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(blocked(POOL, PG, h, "rbd_data.9.0000000000000001"));
	WRT_CHECK(!blocked(POOL, PG, h, "rbd_data.9.0000000000000002"));
	WRT_CHECK(!blocked(POOL, PG, h + 1u, "rbd_data.9.0000000000000001"));
	/* a range inside one hash value: names order inside it, [begin, end) */
	mk(&b, WRI_BACKOFF_BLOCK, 2, POOL, PG, 5, "b", h ^ 0x55u, "d", h ^ 0x55u);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(blocked(POOL, PG, h ^ 0x55u, "b") && blocked(POOL, PG, h ^ 0x55u, "c") && blocked(POOL, PG, h ^ 0x55u, "czzz"));
	WRT_CHECK(!blocked(POOL, PG, h ^ 0x55u, "a") && !blocked(POOL, PG, h ^ 0x55u, "d") && !blocked(POOL, PG, h ^ 0x55u, "e"));
	WRT_CHECK(!blocked(POOL, PG, h ^ 0x55u, "")); /* a proper prefix sorts first */
	/* the whole PG as the OSD sends it: from the lowest position to the "max" object */
	mk(&b, WRI_BACKOFF_BLOCK, 3, POOL, PG + 1u, 5, "", 0, "", 0);
	b.m.end.max = 1;
	b.n = rf_backoff(b.front, sizeof(b.front), &b.m, WRI_BACKOFF_BLOCK);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	{
		unsigned i;
		uint32_t hs[] = {0, 1, 0x80000000u, 0xdeadbeefu, 0xffffffffu};

		for (i = 0; i < sizeof(hs) / sizeof(hs[0]); i++) {
			WRT_CHECK(blocked(POOL, PG + 1u, hs[i], "any.name"));
			WRT_CHECK(!blocked(POOL, PG + 2u, hs[i], "any.name"));
		}
	}
	/* an entry is exact: names up to 96 bytes are kept as they are */
	{
		char name[97];

		memset(name, 'n', sizeof(name));
		name[96] = 0;
		mk(&b, WRI_BACKOFF_BLOCK, 4, POOL, PG + 3u, 5, name, h, name, h);
		WRT_CHECK_STATUS(WR_OK, deliver(&b));
		WRT_CHECK(R.t.n_backoff_overflow == 0u);
		WRT_CHECK(blocked(POOL, PG + 3u, h, name));
		name[95] = 'o';
		WRT_CHECK(!blocked(POOL, PG + 3u, h, name));
	}
	WRT_CHECK(R.t.n_backoff_noack == 0u && R.f.n_sent == 4u);
}

/* ---- coarse entries ------------------------------------------------------------------------------------------------------------- */

static void test_coarse(void)
{
	blk b;
	uint32_t h = rev32(0x40000000u);
	char name[400];
	unsigned before;

	if (fresh(8) != 0)
		return;
	/* a name of 97 bytes cannot be kept: the entry holds every request of its PG */
	memset(name, 'q', sizeof(name));
	name[97] = 0;
	mk(&b, WRI_BACKOFF_BLOCK, 1, POOL, PG, 5, name, h, name, h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(R.t.n_backoff_overflow == 1u && R.t.s[S].n_backoff == 1u && R.f.n_sent == 1u); /* still acknowledged, with the full names */
	WRT_CHECK(blocked(POOL, PG, 0, "anything") && blocked(POOL, PG, 0xffffffffu, "") && !blocked(POOL, PG + 1u, 0, "anything"));
	mk(&b, WRI_BACKOFF_UNBLOCK, 1, POOL, PG, 5, name, h, name, h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(!blocked(POOL, PG, 0, "anything") && R.r.n_unblock == 1u && R.t.s[S].n_backoff == 0u);
	/* a locator key, a namespace, a position of another pool: all coarse */
	{
		unsigned k;

		for (k = 0; k < 3; k++) {
			before = R.t.n_backoff_overflow;
			mk(&b, WRI_BACKOFF_BLOCK, 10u + k, POOL, PG, 5, "n", h, "n", h);
			if (k == 0)
				b.m.begin.key = (const uint8_t *)"loc", b.m.begin.key_len = 3;
			if (k == 1)
				b.m.end.nspace = (const uint8_t *)"ns", b.m.end.nspace_len = 2;
			if (k == 2)
				b.m.begin.pool = POOL + 1;
			b.n = rf_backoff(b.front, sizeof(b.front), &b.m, WRI_BACKOFF_BLOCK);
			WRT_CHECK(b.n != 0u);
			WRT_CHECK_STATUS(WR_OK, deliver(&b));
			WRT_CHECK(R.t.n_backoff_overflow == before + 1u && blocked(POOL, PG, 0x1234u, "zzz"));
			mk(&b, WRI_BACKOFF_UNBLOCK, 10u + k, POOL, PG, 5, "n", h, "n", h);
			WRT_CHECK_STATUS(WR_OK, deliver(&b));
			WRT_CHECK(!blocked(POOL, PG, 0x1234u, "zzz"));
		}
	}
	/* names so long that the acknowledgement does not fit its buffer: held, counted, not acknowledged (the OSD is not told, nothing is lost) */
	{
		unsigned sent = R.f.n_sent;

		memset(name, 'z', sizeof(name));
		name[390] = 0;
		mk(&b, WRI_BACKOFF_BLOCK, 20, POOL, PG, 5, name, h, name, h);
		WRT_CHECK_STATUS(WR_OK, deliver(&b));
		WRT_CHECK(R.f.n_sent == sent && R.t.n_backoff_noack == 1u && blocked(POOL, PG, 0, "x"));
		mk(&b, WRI_BACKOFF_UNBLOCK, 20, POOL, PG, 5, name, h, name, h);
		WRT_CHECK_STATUS(WR_OK, deliver(&b));
		WRT_CHECK(!blocked(POOL, PG, 0, "x"));
	}
	/* a send that fails (the queue filled between the check and the send): counted, the entry stays */
	{
		R.f.send_st = WR_E_BUSY;
		mk(&b, WRI_BACKOFF_BLOCK, 21, POOL, PG, 5, "m", h, "m", h);
		WRT_CHECK_STATUS(WR_OK, deliver(&b));
		WRT_CHECK(R.t.n_backoff_noack == 2u && blocked(POOL, PG, h, "m"));
		R.f.send_st = WR_OK;
	}
}

/* ---- a full table ------------------------------------------------------------------------------------------------------------ */

static void test_full_table(void)
{
	blk b;
	uint32_t h = rev32(0x40000000u);
	unsigned i, sent;

	if (fresh(4) != 0)
		return;
	/* four exact entries of four PGs fill it */
	for (i = 0; i < 4; i++) {
		mk(&b, WRI_BACKOFF_BLOCK, 100u + i, POOL, PG + i, 5, "a", h, "a", h);
		WRT_CHECK_STATUS(WR_OK, deliver(&b));
	}
	WRT_CHECK(R.t.s[S].n_backoff == 4u && R.t.n_backoff_overflow == 0u);
	/* a fifth BLOCK of a PG that has an entry: merged into it (the entry becomes the whole PG), the id kept, acknowledged */
	sent = R.f.n_sent;
	mk(&b, WRI_BACKOFF_BLOCK, 200, POOL, PG + 1u, 6, "zz", h, "zz", h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(R.t.n_backoff_overflow == 1u && R.t.s[S].n_backoff == 4u && R.f.n_sent == sent + 1u && !R.t.s[S].bo_lost);
	WRT_CHECK(blocked(POOL, PG + 1u, 0, "whatever") && !blocked(POOL, PG, 0, "whatever")); /* only the merged PG is wider */
	WRT_CHECK(blocked(POOL, PG, h, "a") && !blocked(POOL, PG, h, "b"));                     /* the others are still exact */
	/* the first of the two ids ends: the PG stays held (the second BLOCK still stands) and the request layer is told to look again */
	mk(&b, WRI_BACKOFF_UNBLOCK, 101, POOL, PG + 1u, 6, "a", h, "a", h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(blocked(POOL, PG + 1u, 0, "whatever") && R.r.n_unblock == 1u && R.r.unblock[0].pg == PG + 1u && R.t.s[S].n_backoff == 4u);
	mk(&b, WRI_BACKOFF_UNBLOCK, 200, POOL, PG + 1u, 6, "zz", h, "zz", h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(!blocked(POOL, PG + 1u, 0, "whatever") && R.r.n_unblock == 2u && R.t.s[S].n_backoff == 3u);
	/* the other order: the second id ends first, the entry keeps the first */
	mk(&b, WRI_BACKOFF_BLOCK, 201, POOL, PG + 1u, 7, "k", h, "k", h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b)); /* a free slot now: exact */
	WRT_CHECK(R.t.s[S].n_backoff == 4u && blocked(POOL, PG + 1u, h, "k") && !blocked(POOL, PG + 1u, h, "j"));
	mk(&b, WRI_BACKOFF_BLOCK, 202, POOL, PG + 1u, 7, "l", h, "l", h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b)); /* full: merged */
	WRT_CHECK(blocked(POOL, PG + 1u, h, "j"));
	mk(&b, WRI_BACKOFF_UNBLOCK, 202, POOL, PG + 1u, 7, "l", h, "l", h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(blocked(POOL, PG + 1u, h, "j")); /* the entry is the whole PG now, held by 201 */
	mk(&b, WRI_BACKOFF_UNBLOCK, 201, POOL, PG + 1u, 7, "k", h, "k", h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	WRT_CHECK(!blocked(POOL, PG + 1u, h, "j") && R.t.s[S].n_backoff == 3u);
	/* a BLOCK of a PG with no entry and no room: not held, acknowledged, counted; its UNBLOCK still tells the layer */
	mk(&b, WRI_BACKOFF_BLOCK, 300, POOL, PG + 1u, 8, "e", h, "e", h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b)); /* takes the free slot */
	mk(&b, WRI_BACKOFF_BLOCK, 301, POOL, PG + 7u, 8, "e", h, "e", h);
	sent = R.f.n_sent;
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	/* the delivery before took the last free slot, so this one found the table full and no entry of its PG: acknowledged all the same */
	WRT_CHECK(R.t.s[S].n_backoff == 4u && !blocked(POOL, PG + 7u, h, "e") && R.f.n_sent == sent + 1u);
	WRT_CHECK(R.t.s[S].bo_lost == 1u && R.t.n_backoff_overflow == 3u); /* the merges of 200 and 202, and this one */
	mk(&b, WRI_BACKOFF_UNBLOCK, 301, POOL, PG + 7u, 8, "e", h, "e", h);
	{
		unsigned n = R.r.n_unblock;

		WRT_CHECK_STATUS(WR_OK, deliver(&b));
		WRT_CHECK(R.r.n_unblock == n + 1u && R.r.unblock[n].pg == PG + 7u);
	}
}

/* More ids than a coarse entry has room for. */
static void test_extra_ids(void)
{
	blk b;
	uint32_t h = rev32(0x40000000u);
	unsigned i;

	if (fresh(1) != 0)
		return;
	mk(&b, WRI_BACKOFF_BLOCK, 1, POOL, PG, 5, "a", h, "a", h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b));
	for (i = 0; i < 12; i++) { /* a one-slot table: the other twelve ids fit the entry */
		mk(&b, WRI_BACKOFF_BLOCK, 2u + i, POOL, PG, 5, "b", h, "b", h);
		WRT_CHECK_STATUS(WR_OK, deliver(&b));
		WRT_CHECK(!R.t.s[S].bo_lost && R.t.s[S].n_backoff == 1u && blocked(POOL, PG, 0, "z"));
	}
	mk(&b, WRI_BACKOFF_BLOCK, 99, POOL, PG, 5, "c", h, "c", h);
	WRT_CHECK_STATUS(WR_OK, deliver(&b)); /* the thirteenth: no room for its id */
	WRT_CHECK(R.t.s[S].bo_lost == 1u && R.f.n_sent == 14u);
	/* ids end in any order: the PG is free again only after the last of the held ones */
	for (i = 0; i < 13; i++) {
		uint64_t id = (i * 5u) % 13u + 1u;

		WRT_CHECK(blocked(POOL, PG, 0, "z"));
		mk(&b, WRI_BACKOFF_UNBLOCK, id, POOL, PG, 5, "a", h, "a", h);
		WRT_CHECK_STATUS(WR_OK, deliver(&b));
		WRT_CHECK(R.r.n_unblock == i + 1u);
	}
	WRT_CHECK(!blocked(POOL, PG, 0, "z") && R.t.s[S].n_backoff == 0u);
}

/* ---- a model run ---------------------------------------------------------------------------------------------------------------- */

typedef struct mblk {
	uint64_t id;
	uint32_t pg, lo, hi; /* exact: the bit-reversed keys [lo, hi) of PG pg; coarse: the whole PG */
	int coarse;
} mblk;

static uint32_t rnd_state = 0x2545f491u;

static uint32_t rnd(void)
{
	rnd_state ^= rnd_state << 13;
	rnd_state ^= rnd_state >> 17;
	rnd_state ^= rnd_state << 5;
	return rnd_state;
}

/* Random BLOCKs (exact ranges and coarse ones: names above 96 bytes) and UNBLOCKs over three PGs and a table of three or four slots, so the
 * merge, the extra ids and the take-over of an entry by the next id all happen. The table may only ever HOLD MORE than the OSD asked for, and
 * only lose a hold (bo_lost) when it ran out of room for a new PG: until then every position the live BLOCKs cover is held, a PG without a live
 * BLOCK holds nothing, every UNBLOCK of a live id is reported with its PG, and when the last live id ends the table is empty. */
static void test_model(void)
{
	static char longname[200];
	unsigned round, op, i, k, n_lost_rounds = 0, n_held_checked = 0, n_merged = 0;

	memset(longname, 'q', sizeof(longname) - 1u);
	for (round = 0; round < 300; round++) {
		mblk live[24];
		unsigned n_live = 0, slots = 3u + round % 2u;
		uint64_t next_id = 1;
		blk b;

		if (fresh(slots) != 0)
			return;
		for (op = 0; op < 40; op++) {
			unsigned pg = PG + rnd() % 3u;
			uint32_t r = rnd() % 8u;

			if (r < 3u && n_live < 24u) { /* BLOCK */
				mblk *m = &live[n_live];
				uint32_t lo = rnd() >> 4, hi;

				m->id = next_id++;
				m->pg = pg;
				m->coarse = (r == 2u && (rnd() & 3u) == 0u);
				hi = lo + 1u + (rnd() >> 6);
				m->lo = lo;
				m->hi = hi;
				if (m->coarse)
					mk(&b, WRI_BACKOFF_BLOCK, m->id, POOL, pg, 5, longname, rev32(lo), "", rev32(hi));
				else
					mk(&b, WRI_BACKOFF_BLOCK, m->id, POOL, pg, 5, "", rev32(lo), "", rev32(hi));
				n_live++;
				WRT_CHECK_STATUS(WR_OK, deliver(&b));
			} else if (n_live != 0u) { /* UNBLOCK of a live id; sometimes of one the OSD never sent */
				unsigned v = rnd() % n_live, before = R.r.n_unblock;
				mblk gone = live[v];

				live[v] = live[n_live - 1u];
				n_live--;
				mk(&b, WRI_BACKOFF_UNBLOCK, gone.id, POOL, gone.pg, 5, "", rev32(gone.lo), "", rev32(gone.hi));
				WRT_CHECK_STATUS(WR_OK, deliver(&b));
				if (!R.t.s[S].bo_lost) {
					WRT_CHECK(R.r.n_unblock == before + 1u);
					WRT_CHECK(before >= FK_LOG || (R.r.unblock[before].pg == gone.pg && R.r.unblock[before].pool == POOL));
				}
			}
			for (k = 0; k < 12u; k++) { /* probes */
				uint32_t ph = rnd(), key = rev32(ph);
				unsigned ppg = PG + rnd() % 3u;
				int want_in = 0, any_live = 0;

				for (i = 0; i < n_live; i++) {
					if (live[i].pg != ppg)
						continue;
					any_live = 1;
					if (live[i].coarse || (live[i].lo <= key && key < live[i].hi))
						want_in = 1;
				}
				if (!R.t.s[S].bo_lost && want_in) {
					WRT_CHECK(blocked(POOL, ppg, ph, "obj"));
					n_held_checked++;
				}
				if (!any_live)
					WRT_CHECK(!blocked(POOL, ppg, ph, "obj")); /* nothing outlives its last id (a PG that lost a hold holds nothing either) */
			}
			WRT_CHECK(R.t.s[S].n_backoff <= slots);
		}
		n_lost_rounds += R.t.s[S].bo_lost ? 1u : 0u;
		n_merged += R.t.n_backoff_overflow != 0u ? 1u : 0u;
		while (n_live != 0u) { /* end them all: the table must come out empty */
			mblk gone = live[--n_live];

			mk(&b, WRI_BACKOFF_UNBLOCK, gone.id, POOL, gone.pg, 5, "", rev32(gone.lo), "", rev32(gone.hi));
			WRT_CHECK_STATUS(WR_OK, deliver(&b));
		}
		WRT_CHECK(R.t.s[S].n_backoff == 0u && !blocked(POOL, PG, 0, "obj") && !blocked(POOL, PG + 1u, 0, "obj") &&
			  !blocked(POOL, PG + 2u, 0, "obj"));
	}
	printf("backoff model: 300 rounds, %u with a lost hold, %u with a full table or coarse entry, %u held positions checked\n", n_lost_rounds, n_merged, n_held_checked);
	WRT_CHECK(n_held_checked > 1000u && n_lost_rounds > 5u && n_lost_rounds < 200u);
}

/* ---- the table is cleared with the connection ----------------------------------------------------------------------------------- */

static void test_cleared_on_loss(void)
{
	blk b;
	uint32_t h = rev32(0x40000000u);
	unsigned how;

	for (how = 0; how < 3; how++) {
		uint32_t s2;
		unsigned i;

		if (fresh(4) != 0)
			return;
		for (i = 0; i < 5; i++) { /* the fifth makes bo_lost true */
			mk(&b, WRI_BACKOFF_BLOCK, 1u + i, POOL, PG + i, 5, "a", h, "a", h);
			WRT_CHECK_STATUS(WR_OK, deliver(&b));
		}
		WRT_CHECK(R.t.s[S].n_backoff == 4u && R.t.s[S].bo_lost == 1u && blocked(POOL, PG, h, "a"));
		if (how == 0) {
			osr_closed(&R, S, WR_E_NET_CLOSED);
		} else if (how == 1) {
			wr_errinfo e;

			memset(&e, 0, sizeof(e));
			e.status = WR_E_OSD_PROTO;
			wri_osd_sess_reset(&R.t, S, &e);
		} else {
			wri_osd_sess_reset(&R.t, S, NULL);
		}
		/* gone with the connection (osd-ops.md 3.7 item 4): nothing is held, nothing leaks into the next session of that slot */
		WRT_CHECK(R.t.s[S].n_backoff == 0u && R.t.s[S].bo_lost == 0u && !blocked(POOL, PG, h, "a"));
		for (i = 0; i < 4; i++)
			WRT_CHECK(!R.t.s[S].bo[i].used && R.t.s[S].bo[i].id == 0u);
		WRT_CHECK(R.r.n_lost == 1u);
		R.x.now.mono_ms += 20000;
		s2 = osr_get(&R, 1, ALL_FEATURES);
		WRT_CHECK(s2 != WRI_NIL && R.t.s[s2].n_backoff == 0u && !blocked(POOL, PG, h, "a"));
		(void)s2;
	}
}

/* ---- a transmit queue with no room ------------------------------------------------------------------------------------------ */

static void test_tx_busy(void)
{
	blk b;
	uint32_t h = rev32(0x40000000u);
	fr_out o;

	if (fresh(4) != 0)
		return;
	R.f.tx_idle = 0;
	mk(&b, WRI_BACKOFF_BLOCK, 1, POOL, PG, 5, "a", h, "a", h);
	/* the frame is held, not lost: plan answers BUSY, nothing was stored or sent */
	WRT_CHECK_STATUS(WR_E_BUSY, osr_frame(&R, S, WRI_MSG_OSD_BACKOFF, 0, 1, 1, b.front, b.n, NULL, 0, NULL, 0, &o));
	WRT_CHECK(R.t.s[S].n_backoff == 0u && R.f.n_sent == 0u && R.t.n_backoff_blocks == 0u && wri_osd_sess_ready(&R.t, S));
	WRT_CHECK_STATUS(WR_E_BUSY, osr_frame(&R, S, WRI_MSG_OSD_BACKOFF, 0, 1, 1, b.front, b.n, NULL, 0, NULL, 0, &o));
	R.f.tx_idle = 1;
	WRT_CHECK_STATUS(WR_OK, osr_frame(&R, S, WRI_MSG_OSD_BACKOFF, 0, 1, 1, b.front, b.n, NULL, 0, NULL, 0, &o));
	WRT_CHECK(R.t.s[S].n_backoff == 1u && R.f.n_sent == 1u && R.t.n_backoff_noack == 0u);
	/* a reply is not held back by the queue: it needs no answer */
	R.f.tx_idle = 0;
	{
		rframe f;
		uint32_t plen[1] = {0};

		rf_reply(&f, "o", 1, plen, 0, 0);
		WRT_CHECK_STATUS(WR_OK, osr_frame(&R, S, WRI_MSG_OSD_OPREPLY, 9, 8, 2, f.b, f.n, NULL, 0, NULL, 0, &o));
		WRT_CHECK(R.r.n_reply == 1u);
	}
	R.f.tx_idle = 1;
	/* an idle queue that still refuses the ACK_BLOCK (a link fault): counted, the hold stays, the UNBLOCK still releases it */
	R.f.send_st = WR_E_BUSY;
	mk(&b, WRI_BACKOFF_BLOCK, 2, POOL, PG + 1u, 5, "a", h, "a", h);
	WRT_CHECK_STATUS(WR_OK, osr_frame(&R, S, WRI_MSG_OSD_BACKOFF, 0, 1, 1, b.front, b.n, NULL, 0, NULL, 0, &o));
	WRT_CHECK(R.t.n_backoff_noack == 1u && R.t.s[S].n_backoff == 2u && blocked(POOL, PG + 1u, h, "a"));
	R.f.send_st = WR_OK;
	mk(&b, WRI_BACKOFF_UNBLOCK, 2, POOL, PG + 1u, 5, "a", h, "a", h);
	WRT_CHECK_STATUS(WR_OK, osr_frame(&R, S, WRI_MSG_OSD_BACKOFF, 0, 1, 1, b.front, b.n, NULL, 0, NULL, 0, &o));
	WRT_CHECK(R.t.s[S].n_backoff == 1u && !blocked(POOL, PG + 1u, h, "a") && R.r.n_unblock == 1u);
}

/* ---- against the real connection and the simulator ------------------------------------------------------------------------------- */

static void test_real_connection(void)
{
	static world W;
	uint32_t s;
	uint8_t data[4096];

	if (w_open_world(&W, 1, 2, 2048, 8, WR_KEY_TYPE_AES256K) != 0 || w_start(&W) != 0) {
		WRT_CHECK(0);
		return;
	}
	s = w_get(&W, 0);
	WRT_CHECK(s != WRI_NIL);
	if (s == WRI_NIL) {
		w_free(&W);
		return;
	}
	/* a PG-wide backoff, [start, "max") of PG 3 of pool 2, as sim_osd sends it */
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_backoff(w_srv(&W, s), WRI_BACKOFF_BLOCK, 41, W_POOL, 3, 9, "", 0, SIM_OSD_BO_MAX, 0));
	(void)w_pump(&W);
	WRT_CHECK(sim_osd_n_acks(W.osd[0]) == 1u && W.t.s[s].n_backoff == 1u && W.t.n_backoff_blocks == 1u);
	WRT_CHECK(wri_osd_sess_blocked(&W.t, s, W_POOL, 3, 0x12345678u, (const uint8_t *)"rbd_data.7.0000000000000003", 27));
	WRT_CHECK(!wri_osd_sess_blocked(&W.t, s, W_POOL, 4, 0x12345678u, (const uint8_t *)"rbd_data.7.0000000000000003", 27));
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_backoff(w_srv(&W, s), WRI_BACKOFF_UNBLOCK, 41, W_POOL, 3, 9, "", 0, SIM_OSD_BO_MAX, 0));
	(void)w_pump(&W);
	WRT_CHECK(W.t.s[s].n_backoff == 0u && W.r.n_unblock == 1u && W.r.unblock[0].pool == W_POOL && W.r.unblock[0].pg == 3u);
	/* an object-level backoff, one byte at a time */
	W.rx_chunk = 1;
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_backoff(w_srv(&W, s), WRI_BACKOFF_BLOCK, 42, W_POOL, 3, 9, "rbd_data.7.0000000000000003", 0x12345678u,
						     "rbd_data.7.0000000000000003", 0x12345678u));
	(void)w_pump(&W);
	W.rx_chunk = 0;
	WRT_CHECK(sim_osd_n_acks(W.osd[0]) == 2u);
	WRT_CHECK(wri_osd_sess_blocked(&W.t, s, W_POOL, 3, 0x12345678u, (const uint8_t *)"rbd_data.7.0000000000000003", 27));
	WRT_CHECK(!wri_osd_sess_blocked(&W.t, s, W_POOL, 3, 0x12345678u, (const uint8_t *)"rbd_data.7.0000000000000004", 27));
	/* the transmit queue is full (the host has not consumed it): the BLOCK waits behind it, then the acknowledgement goes out and nothing was lost */
	memset(data, 0x11, sizeof(data));
	W.tx_hold = 1;
	WRT_CHECK_STATUS(WR_OK, w_op(&W, s, 77, "rbd_data.7.0000000000000009", WRI_OSD_OP_WRITE, 0, sizeof(data), data, 0));
	WRT_CHECK(!wri_osd_sess_tx_idle(&W.t, s));
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_backoff(w_srv(&W, s), WRI_BACKOFF_BLOCK, 43, W_POOL, 5, 10, "", 0, SIM_OSD_BO_MAX, 0));
	(void)w_pump(&W);
	WRT_CHECK(W.t.s[s].n_backoff == 1u && sim_osd_n_acks(W.osd[0]) == 2u && W.ec[W.t.s[s].conn_slot].c.stalled);
	W.tx_hold = 0;
	(void)w_pump(&W);
	WRT_CHECK(W.t.s[s].n_backoff == 2u && sim_osd_n_acks(W.osd[0]) == 3u && wri_osd_sess_ready(&W.t, s) && sim_osd_n_violations(W.osd[0]) == 0u);
	WRT_CHECK(wri_osd_sess_blocked(&W.t, s, W_POOL, 5, 7, (const uint8_t *)"x", 1));
	/* the OSD restarts: every backoff is gone with the connection */
	sim_osd_restart(W.osd[0]);
	(void)w_pump(&W);
	WRT_CHECK(W.t.s[s].n_backoff == 0u && !wri_osd_sess_blocked(&W.t, s, W_POOL, 5, 7, (const uint8_t *)"x", 1));
	w_free(&W);
}

int main(void)
{
	test_block_ack_unblock();
	test_positions();
	test_coarse();
	test_full_table();
	test_extra_ids();
	test_model();
	test_cleared_on_loss();
	test_tx_busy();
	test_real_connection();
	osr_free(&R);
	return wrt_finish();
}
