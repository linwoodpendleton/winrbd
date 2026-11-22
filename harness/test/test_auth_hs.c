/* SPDX-License-Identifier: MIT */
/*
 * One cephx handshake per slot (core/src/auth/wri_cx_hs.c, architecture 21.2).
 *
 * The client holds the identity (principal key, tickets, global id); every handshake lives in its own
 * wri_cx_hs. The tests drive several of them against servers that are built from the cipher layer only
 * (wri_cx_seal / wri_cx_open; the monitor is sim_mon, the OSD is written here from cephx.md 2.7 / 3.3):
 *
 *   - interleave: two OSD handshakes and a monitor renewal (a reclaim of the global id with the held AUTH
 *     ticket) advanced in EVERY order a scheduler could pick (all 1680 interleavings of three actors of
 *     three steps each; a sample of them under a sanitizer), for every combination of principal /
 *     session key type, with the monitor on a slot and with the monitor on the embedded handshake of
 *     wri_cx_ops(). All finish, each with its own
 *     session key and its own nonce + 1.
 *   - a failing handshake (damaged challenge, wrong nonce, malformed begin) leaves the others and the
 *     client's own error alone, and its slot is reusable;
 *   - a begin on one slot supersedes only that slot;
 *   - a ticket swapped between begin and done fails the handshakes that began before the swap, nothing else;
 *   - a failed monitor done forgets every ticket (the shared rule): OSD handshakes in flight fail with
 *     WR_E_STATE, and a clean login afterwards works;
 *   - wipe leaves zeros (slot, client and the arena behind it);
 *   - the slot memory API and the argument checks.
 * The monitor and the OSD of the tests are the harness's, not the core's.
 */
#include "auth_cx_srv.h"

#include "sim_mon.h"

static int all_zero(const void *p, size_t n);

#define NACT 3u
#define MON_STEPS 3u

enum { K_OSD, K_MON_HS, K_MON_EMB };
enum { F_NONE, F_CHAL_BIT, F_NONCE2, F_DONE_BIT };

typedef struct world {
	cxt_env e;
	sim_mon *m;
	sim_mon_conn *mc[16];
	unsigned nmc;
	uint8_t *hsmem;
	wri_cx_hs *hs;
	uint32_t nhs;
	uint64_t next_chal;
} world;

typedef struct actor {
	int kind, fault;
	const wri_auth_ops *ops;
	void *a;
	wri_cx_hs *hs; /* NULL for the embedded handshake */
	unsigned step;
	sim_mon_conn *mc;
	wr_key okey;    /* OSD: the session key the server holds for the ticket this handshake will use */
	uint64_t chal;  /* OSD: the server's challenge */
	uint64_t nonce; /* OSD: the authorizer nonce the server saw */
	uint64_t gid;   /* the global id the done step carries */
	uint8_t reply_key[WR_KEY_MAX]; /* MON: the AUTH session key the monitor handed out */
	size_t reply_key_len;
	uint8_t pend[8192]; /* the server payload that waits for the client */
	size_t pn;
} actor;

/* ---- the world ------------------------------------------------------------------------------------ */

static sim_mon *mon_new(unsigned pt, unsigned ot)
{
	sim_mon_cfg c;
	wr_key pk = cxt_key(pt, 5);

	sim_mon_cfg_default(&c);
	c.key = pk;
	memset(c.user, 0, sizeof(c.user));
	strcpy(c.user, "winrbd");
	c.tkt[sim_mon_slot(WRI_CX_SERVICE_OSD)].key_type = (uint8_t)ot;
	return sim_mon_new(&c);
}

static int world_open(world *w, sim_mon *m, unsigned pt)
{
	wr_key pk = cxt_key(pt, 5);
	size_t need = 0, i;
	wri_arena a;

	memset(w, 0, sizeof(*w));
	w->m = m;
	cxt_rng_free();
	if (cxt_env_init(&w->e, "client.winrbd", &pk, 0) != 0)
		return -1;
	if (wri_cx_hs_mem(&w->e.x.cfg, &need) != WR_OK)
		return -1;
	w->hsmem = (uint8_t *)calloc(1, need + WRI_ARENA_SLACK + 64);
	if (w->hsmem == NULL)
		return -1;
	wri_arena_init(&a, (uint8_t *)(((uintptr_t)w->hsmem + 63u) & ~(uintptr_t)63u), need + WRI_ARENA_SLACK);
	if (wri_cx_hs_carve(&a, &w->e.x.cfg, &w->hs, &w->nhs) != WR_OK)
		return -1;
	for (i = 0; i < w->nhs; i++)
		if (wri_cx_hs_init(&w->hs[i], &w->e.c) != WR_OK)
			return -1;
	w->next_chal = 0x0102030405060708ull;
	return 0;
}

static void world_close(world *w)
{
	unsigned i;

	for (i = 0; i < w->nmc; i++)
		sim_mon_conn_free(w->mc[i]);
	w->nmc = 0;
	cxt_env_free(&w->e);
	free(w->hsmem);
	w->hsmem = NULL;
}

static sim_mon_conn *world_conn(world *w)
{
	sim_mon_conn *c = sim_mon_accept(w->m);

	WRT_CHECK(c != NULL && w->nmc < 16u);
	if (c != NULL && w->nmc < 16u)
		w->mc[w->nmc++] = c;
	return c;
}

static const wr_key *sim_osd_key(const world *w)
{
	return &w->m->last[sim_mon_slot(WRI_CX_SERVICE_OSD)].key;
}

/* ---- actors --------------------------------------------------------------------------------------- */

static void actor_osd(world *w, actor *x, wri_cx_hs *h)
{
	memset(x, 0, sizeof(*x));
	x->kind = K_OSD;
	x->ops = wri_cx_hs_ops();
	x->a = h;
	x->hs = h;
	x->okey = *sim_osd_key(w);
	x->chal = w->next_chal;
	w->next_chal = w->next_chal * 0x100000001b3ull + 0x9e37u; /* a distinct challenge per OSD handshake */
}

static void actor_mon(world *w, actor *x, wri_cx_hs *h) /* h NULL: the embedded handshake */
{
	memset(x, 0, sizeof(*x));
	x->kind = h != NULL ? K_MON_HS : K_MON_EMB;
	x->ops = h != NULL ? wri_cx_hs_ops() : wri_cx_ops();
	x->a = h != NULL ? (void *)h : (void *)&w->e.c;
	x->hs = h;
	x->mc = world_conn(w);
}

/* The OSD server's reading of a client authorizer: u8 1 | u64 gid | u32 4 | ticket blob | u32 len | proof. */
static void osd_open_authorizer(world *w, actor *x, const uint8_t *az, size_t n, uint64_t *nonce, int *have,
				uint64_t *po)
{
	wri_rd r;
	const uint8_t *blob, *pl, *item = NULL;
	size_t il = 0;
	uint8_t scratch[256];
	uint32_t blen, pn;

	wri_rd_init(&r, az, n);
	WRT_CHECK(wri_rd_u8(&r) == 1);
	WRT_CHECK(wri_rd_u64(&r) == w->e.c.global_id);
	WRT_CHECK(wri_rd_u32(&r) == WRI_CX_SERVICE_OSD);
	blob = az + r.pos;
	blen = 13u + wri_le32_get(blob + 9);
	WRT_CHECK(wri_rd_bytes(&r, blen) == blob);
	pn = wri_rd_u32(&r);
	pl = wri_rd_bytes(&r, pn);
	WRT_CHECK(wri_rd_ok(&r) && wri_rd_left(&r) == 0);
	WRT_CHECK(sim_mon_ticket_valid(w->m, WRI_CX_SERVICE_OSD, blob + 13, blen - 13u)); /* the data a real OSD would check */
	*nonce = *po = 0;
	*have = -1;
	WRT_CHECK_STATUS(WR_OK, wri_cx_open(&w->e.x, &x->okey, WRI_CX_USAGE_AUTHORIZE, pl, pn, scratch, sizeof(scratch),
					    &item, &il));
	if (item != NULL && il == 18u) {
		WRT_CHECK(item[0] == 2);
		*nonce = wri_le64_get(item + 1);
		*have = item[9];
		*po = wri_le64_get(item + 10);
	} else {
		WRT_CHECK(0);
	}
}

static size_t osd_seal_challenge(world *w, actor *x, uint8_t *out, size_t cap)
{
	uint8_t item[9];
	size_t n = 0;

	item[0] = 1;
	wri_le64_put(item + 1, x->chal);
	WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&w->e.x, &x->okey, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, item, sizeof(item), out,
					    cap, &n));
	return n;
}

static size_t osd_seal_reply(world *w, actor *x, uint64_t npo, uint8_t *out, size_t cap)
{
	uint8_t item[9], ct[200];
	size_t n = 0;

	item[0] = 1;
	wri_le64_put(item + 1, npo);
	WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&w->e.x, &x->okey, WRI_CX_USAGE_AUTHORIZE_REPLY, item, sizeof(item), ct,
					    sizeof(ct), &n));
	wri_le32_put(out, (uint32_t)n);
	memcpy(out + 4, ct, n);
	(void)cap;
	return n + 4;
}

static const uint32_t g_modes[1] = {1};

/* One step (begin, more, done) of the actor: the client call and the server's half of it. */
static wr_status step(world *w, actor *x)
{
	uint8_t out[4096];
	wri_wr wr;
	wr_status st;
	unsigned s = x->step++;

	if (x->kind == K_OSD) {
		uint64_t nonce, po;
		int have;

		if (s == 0) { /* begin: the first authorizer, no challenge yet */
			wri_wr_init(&wr, out, sizeof(out));
			st = x->ops->begin(x->a, WRI_ENTITY_OSD, &wr);
			if (st != WR_OK)
				return st;
			osd_open_authorizer(w, x, out, wri_wr_len(&wr), &nonce, &have, &po);
			WRT_CHECK(have == 0 && po == 0);
			x->nonce = nonce;
			x->pn = osd_seal_challenge(w, x, x->pend, sizeof(x->pend));
			return WR_OK;
		}
		if (s == 1) { /* more: the challenge in, the answering authorizer out */
			if (x->fault == F_CHAL_BIT)
				x->pend[x->pn / 2] ^= 1u;
			wri_wr_init(&wr, out, sizeof(out));
			st = x->ops->more(x->a, x->pend, x->pn, &wr);
			if (st != WR_OK)
				return st;
			osd_open_authorizer(w, x, out, wri_wr_len(&wr), &nonce, &have, &po);
			WRT_CHECK(have == 1 && nonce == x->nonce && po == x->chal + 1u); /* its own nonce and challenge */
			x->gid = w->e.c.global_id;
			x->pn = osd_seal_reply(w, x, x->nonce + (x->fault == F_NONCE2 ? 2u : 1u), x->pend, sizeof(x->pend));
			return WR_OK;
		}
		return x->ops->done(x->a, x->gid, WRI_CONN_MODE_CRC, x->pend, x->pn);
	}

	/* monitor: the server is sim_mon behind its payload-level auth callbacks */
	{
		sim_m2_auth_reply rep;
		sim_m2_auth_ops *au = &x->mc->m2->auth;
		int verdict;

		if (s == 0) {
			wri_wr_init(&wr, out, sizeof(out));
			st = x->ops->begin(x->a, WRI_ENTITY_MON, &wr);
			if (st != WR_OK)
				return st;
			memset(&rep, 0, sizeof(rep));
			verdict = au->request(au->ctx, 2, g_modes, 1, out, (uint32_t)wri_wr_len(&wr), &rep);
			WRT_CHECK(verdict == SIM_AUTH_MORE && rep.payload_len <= sizeof(x->pend));
			x->pn = rep.payload_len;
			memcpy(x->pend, rep.payload, x->pn);
			return WR_OK;
		}
		if (s == 1) {
			wri_wr_init(&wr, out, sizeof(out));
			st = x->ops->more(x->a, x->pend, x->pn, &wr);
			if (st != WR_OK)
				return st;
			memset(&rep, 0, sizeof(rep));
			verdict = au->more(au->ctx, out, (uint32_t)wri_wr_len(&wr), &rep);
			WRT_CHECK(verdict == SIM_AUTH_DONE && rep.payload_len <= sizeof(x->pend));
			x->pn = rep.payload_len;
			memcpy(x->pend, rep.payload, x->pn);
			x->gid = rep.global_id;
			x->reply_key_len = rep.key_len;
			memcpy(x->reply_key, rep.key, rep.key_len);
			if (x->fault == F_DONE_BIT && x->pn > 48u)
				x->pend[40] ^= 0x10u; /* inside msg_a of the AUTH ticket */
			return WR_OK;
		}
		return x->ops->done(x->a, x->gid, WRI_CONN_MODE_CRC, x->pend, x->pn);
	}
}

static void step_ok(world *w, actor *x)
{
	WRT_CHECK_STATUS(WR_OK, step(w, x));
}

static void run_rest(world *w, actor *x)
{
	while (x->step < MON_STEPS)
		step_ok(w, x);
}

/* The finished handshake's session key and gid are the ones its own server holds. */
static void check_finished(world *w, actor *x)
{
	const uint8_t *k = NULL;
	size_t kn = 0;

	x->ops->session_key(x->a, &k, &kn);
	WRT_CHECK(k != NULL);
	if (k == NULL)
		return;
	if (x->kind == K_OSD) {
		WRT_CHECK(kn == x->okey.len && memcmp(k, x->okey.secret, kn) == 0);
		WRT_CHECK(x->ops->ident_gid(x->a, WRI_ENTITY_OSD) == (int64_t)w->e.c.global_id);
		WRT_CHECK(x->hs != NULL && x->hs->authorizer_nonce == 0 && x->hs->st == WRI_CX_DONE);
	} else {
		WRT_CHECK(kn == x->reply_key_len && memcmp(k, x->reply_key, kn) == 0);
		WRT_CHECK(x->ops->ident_gid(x->a, WRI_ENTITY_MON) == (int64_t)x->gid); /* a reclaim: its id */
	}
}

/* A first login on the embedded handshake: AUTH and OSD tickets, a global id. */
static void login(world *w)
{
	actor m;

	w->e.c.want_mask = WRI_CX_WANT_MASK;
	actor_mon(w, &m, NULL);
	run_rest(w, &m);
	WRT_CHECK(wri_cx_have(&w->e.c, WRI_CX_SERVICE_AUTH, w->e.x.now.mono_ms));
	WRT_CHECK(wri_cx_have(&w->e.c, WRI_CX_SERVICE_OSD, w->e.x.now.mono_ms));
	WRT_CHECK(w->e.c.global_id != 0);
	WRT_CHECK(m.ops->ident_gid(m.a, WRI_ENTITY_MON) == -1); /* a new id was asked for: nothing to claim yet */
	WRT_CHECK(w->e.c.st == WRI_CX_DONE);
}

/* ---- 1. every interleaving -------------------------------------------------------------------------- */

/*
 * Every interleaving runs in the plain builds. Under a sanitizer (about twenty times slower) one in
 * ASAN_STRIDE of them runs: the memory checks need coverage of the paths, not of every order.
 */
#if defined(__SANITIZE_ADDRESS__)
#define WRT_HS_SAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define WRT_HS_SAN 1
#endif
#endif
#ifdef WRT_HS_SAN
#define ASAN_STRIDE 7ul
#else
#define ASAN_STRIDE 1ul
#endif

static unsigned long g_sched, g_sched_bad, g_leaf;

static void run_schedule(sim_mon *m, unsigned pt, int mon_embedded, const uint8_t *seq)
{
	world w;
	actor osd[2], mon;
	actor *act[NACT];
	unsigned i;
	unsigned long before = wrt_failures;
	uint32_t gen_osd;

	if (world_open(&w, m, pt) != 0) {
		WRT_CHECK(0);
		return;
	}
	login(&w);
	gen_osd = w.e.c.ticket[WRI_CX_SLOT_OSD].gen;
	w.e.c.want_mask = WRI_CX_SERVICE_AUTH; /* the renewal asks for the AUTH ticket only: the OSD ticket stays */
	actor_osd(&w, &osd[0], &w.hs[0]);
	actor_osd(&w, &osd[1], &w.hs[1]);
	actor_mon(&w, &mon, mon_embedded ? NULL : &w.hs[2]);
	act[0] = &osd[0];
	act[1] = &osd[1];
	act[2] = &mon;
	for (i = 0; i < NACT * MON_STEPS; i++)
		step_ok(&w, act[seq[i]]);
	check_finished(&w, &osd[0]);
	check_finished(&w, &osd[1]);
	check_finished(&w, &mon);
	WRT_CHECK(osd[0].nonce != osd[1].nonce && osd[0].chal != osd[1].chal); /* distinct handshakes */
	WRT_CHECK(w.hs[0].err.status == WR_OK && w.hs[1].err.status == WR_OK);
	WRT_CHECK(w.e.c.ticket[WRI_CX_SLOT_OSD].gen == gen_osd); /* the renewal did not replace the OSD ticket */
	g_sched++;
	if (wrt_failures != before)
		g_sched_bad++;
	world_close(&w);
}

static void gen_schedules(sim_mon *m, unsigned pt, int emb, uint8_t *seq, unsigned depth, unsigned *cnt)
{
	unsigned a;

	if (depth == NACT * MON_STEPS) {
		if (g_leaf++ % ASAN_STRIDE == 0)
			run_schedule(m, pt, emb, seq);
		return;
	}
	for (a = 0; a < NACT; a++) {
		if (cnt[a] == MON_STEPS)
			continue;
		cnt[a]++;
		seq[depth] = (uint8_t)a;
		gen_schedules(m, pt, emb, seq, depth + 1, cnt);
		cnt[a]--;
	}
}

static void test_interleave(void)
{
	static const unsigned types[2][2] = {{WR_KEY_TYPE_AES256K, WR_KEY_TYPE_AES256K},
					     {WR_KEY_TYPE_AES, WR_KEY_TYPE_AES},
					     };
	static const unsigned mixed[2][2] = {{WR_KEY_TYPE_AES256K, WR_KEY_TYPE_AES}, {WR_KEY_TYPE_AES, WR_KEY_TYPE_AES256K}};
	unsigned i, emb;

	/* all orders: both key types (principal and session keys of the same type) and both monitor wirings */
	for (i = 0; i < 2; i++) {
		sim_mon *m = mon_new(types[i][0], types[i][1]);

		WRT_CHECK(m != NULL);
		if (m == NULL)
			continue;
		for (emb = 0; emb < 2; emb++) {
			uint8_t seq[NACT * MON_STEPS];
			unsigned cnt[NACT] = {0, 0, 0};

			gen_schedules(m, types[i][0], (int)emb, seq, 0, cnt);
		}
		sim_mon_free(m);
	}
	/* the mixed pairs (a ticket whose key type differs from the key that wrapped it, cephx.md 3.4): the three
	 * orders that matter most, a lock-step round robin, one handshake at a time, and the reverse round robin */
	for (i = 0; i < 2; i++) {
		sim_mon *m = mon_new(mixed[i][0], mixed[i][1]);
		static const uint8_t rr[NACT * MON_STEPS] = {0, 1, 2, 0, 1, 2, 0, 1, 2};
		static const uint8_t ser[NACT * MON_STEPS] = {0, 0, 0, 1, 1, 1, 2, 2, 2};
		static const uint8_t rev[NACT * MON_STEPS] = {2, 1, 0, 2, 1, 0, 2, 1, 0};

		WRT_CHECK(m != NULL);
		if (m == NULL)
			continue;
		for (emb = 0; emb < 2; emb++) {
			run_schedule(m, mixed[i][0], (int)emb, rr);
			run_schedule(m, mixed[i][0], (int)emb, ser);
			run_schedule(m, mixed[i][0], (int)emb, rev);
		}
		sim_mon_free(m);
	}
	WRT_CHECK(g_leaf == 4ul * 1680ul);
	WRT_CHECK(g_sched == (4ul * 1680ul + ASAN_STRIDE - 1ul) / ASAN_STRIDE + 12ul);
	WRT_CHECK(g_sched_bad == 0);
}

/* ---- 2. failures stay inside their handshake -------------------------------------------------------- */

/* The client's own error record: nothing written, the way a clean client has it. */
static int client_err_clean(const world *w)
{
	return w->e.c.err.status == WR_OK && w->e.c.err.what == NULL && w->e.c.err.line == 0;
}

static int hs_same(const wri_cx_hs *a, const wri_cx_hs *b)
{
	return a->cl == b->cl && a->st == b->st && a->target_type == b->target_type && a->req_new_gid == b->req_new_gid &&
	       a->server_challenge == b->server_challenge && a->client_challenge == b->client_challenge &&
	       a->authorizer_nonce == b->authorizer_nonce && a->osd_gen == b->osd_gen && a->sess_key == b->sess_key &&
	       a->sess_key_len == b->sess_key_len && a->err.status == b->err.status;
}

static void test_failure_isolated(unsigned pt, unsigned ot)
{
	sim_mon *m = mon_new(pt, ot);
	world w;
	actor a, b, mo;
	wri_cx_hs snap;
	wri_wr wr;
	uint8_t o[512];
	const uint8_t *k;
	size_t kn;

	WRT_CHECK(m != NULL);
	if (m == NULL || world_open(&w, m, pt) != 0) {
		WRT_CHECK(0);
		return;
	}
	login(&w);
	w.e.c.want_mask = WRI_CX_SERVICE_AUTH;
	actor_osd(&w, &a, &w.hs[0]);
	a.fault = F_CHAL_BIT; /* the challenge reaches the client damaged */
	actor_osd(&w, &b, &w.hs[1]);
	actor_mon(&w, &mo, &w.hs[2]);
	WRT_CHECK(client_err_clean(&w)); /* the client's own error: none so far */

	step_ok(&w, &a);
	step_ok(&w, &b);
	step_ok(&w, &mo);
	WRT_CHECK(a.hs->authorizer_nonce != 0 && b.hs->authorizer_nonce != 0 && a.hs->authorizer_nonce != b.hs->authorizer_nonce);
	step_ok(&w, &b);
	snap = *b.hs;
	WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, step(&w, &a)); /* A fails ... */
	WRT_CHECK(a.hs->st == WRI_CX_FAILED && a.hs->err.status == WR_E_AUTH_DECRYPT && a.hs->authorizer_nonce == 0);
	WRT_CHECK(a.hs->server_challenge == 0 && a.hs->client_challenge == 0 && a.hs->sess_key == NULL);
	WRT_CHECK(hs_same(&snap, b.hs)); /* ... B did not notice */
	WRT_CHECK(client_err_clean(&w)); /* a slot never writes the client's error */
	a.ops->session_key(a.a, &k, &kn);
	WRT_CHECK(k == NULL && kn == 0);
	WRT_CHECK(a.ops->ident_gid(a.a, WRI_ENTITY_OSD) == -1);
	step_ok(&w, &mo); /* the monitor renewal and B go on */
	step_ok(&w, &b);
	step_ok(&w, &mo);
	check_finished(&w, &b);
	check_finished(&w, &mo);

	/* the failed slot is reusable at once: a fresh begin clears its error and it completes */
	actor_osd(&w, &a, &w.hs[0]);
	run_rest(&w, &a);
	WRT_CHECK(a.hs->err.status == WR_OK);
	check_finished(&w, &a);

	/* a wrong nonce in the final reply fails at done, again only that slot */
	actor_osd(&w, &a, &w.hs[0]);
	a.fault = F_NONCE2;
	actor_osd(&w, &b, &w.hs[1]);
	step_ok(&w, &a);
	step_ok(&w, &b);
	step_ok(&w, &a);
	step_ok(&w, &b);
	snap = *b.hs;
	WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, step(&w, &a));
	WRT_CHECK(a.hs->st == WRI_CX_FAILED && a.hs->authorizer_nonce == 0 && a.hs->err.status == WR_E_AUTH_DECRYPT);
	WRT_CHECK(hs_same(&snap, b.hs));
	step_ok(&w, &b);
	check_finished(&w, &b);
	WRT_CHECK(client_err_clean(&w));

	/* out-of-order and malformed calls: only the slot that was called is affected */
	actor_osd(&w, &a, &w.hs[0]);
	actor_osd(&w, &b, &w.hs[1]);
	step_ok(&w, &b);
	snap = *b.hs;
	wri_wr_init(&wr, o, sizeof(o));
	WRT_CHECK_STATUS(WR_E_INVAL, a.ops->begin(a.a, 9, &wr)); /* neither monitor nor OSD */
	WRT_CHECK(a.hs->st == WRI_CX_FAILED && a.hs->err.status == WR_E_INVAL);
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, a.ops->done(a.a, 1, 1, o, 0)); /* done on a failed slot */
	WRT_CHECK(hs_same(&snap, b.hs));
	wri_wr_init(&wr, o, sizeof(o));
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, a.ops->more(&w.hs[3], o, 0, &wr)); /* more on a slot that never began */
	WRT_CHECK(w.hs[3].st == WRI_CX_FAILED && hs_same(&snap, b.hs));
	step_ok(&w, &b);
	step_ok(&w, &b);
	check_finished(&w, &b);

	world_close(&w);
	sim_mon_free(m);
}

/* ---- 3. a begin supersedes its own slot only ---------------------------------------------------------- */

static void test_superseded(void)
{
	sim_mon *m = mon_new(WR_KEY_TYPE_AES256K, WR_KEY_TYPE_AES256K);
	world w;
	actor a, a2, b;
	wri_cx_hs snap;
	uint64_t n1;

	WRT_CHECK(m != NULL);
	if (m == NULL || world_open(&w, m, WR_KEY_TYPE_AES256K) != 0) {
		WRT_CHECK(0);
		return;
	}
	login(&w);
	actor_osd(&w, &a, &w.hs[0]);
	actor_osd(&w, &b, &w.hs[1]);
	step_ok(&w, &a);
	n1 = a.hs->authorizer_nonce;
	step_ok(&w, &b);
	step_ok(&w, &b);
	snap = *b.hs;
	/* the connection of slot 0 died without telling anybody and the slot starts again: new nonce, B untouched */
	actor_osd(&w, &a2, &w.hs[0]);
	step_ok(&w, &a2);
	WRT_CHECK(a2.hs->authorizer_nonce != n1 && a2.hs->authorizer_nonce == a2.nonce);
	WRT_CHECK(hs_same(&snap, b.hs));
	/* the late challenge of the dead connection is answered under the NEW nonce: the dead server's own reply to
	 * that would be refused by its nonce check, which is what keeps two handshakes apart */
	step_ok(&w, &a2);
	step_ok(&w, &b);
	check_finished(&w, &b);
	run_rest(&w, &a2);
	check_finished(&w, &a2);
	/* B's server, given A2's reply bytes, would not be answered: a reply built on another handshake's nonce fails */
	actor_osd(&w, &a, &w.hs[0]);
	actor_osd(&w, &b, &w.hs[1]);
	step_ok(&w, &a);
	step_ok(&w, &b);
	step_ok(&w, &a);
	step_ok(&w, &b);
	{
		uint8_t swap[256];
		size_t sn = a.pn;

		memcpy(swap, a.pend, sn); /* A's server reply, delivered on B's connection */
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, b.ops->done(b.a, b.gid, WRI_CONN_MODE_CRC, swap, sn));
		WRT_CHECK(b.hs->st == WRI_CX_FAILED);
		WRT_CHECK(a.hs->st == WRI_CX_OSD_SENT_CHALLENGE && a.hs->authorizer_nonce == a.nonce);
		step_ok(&w, &a);
		check_finished(&w, &a);
	}
	world_close(&w);
	sim_mon_free(m);
}

/* ---- 4. a ticket swapped under a handshake ---------------------------------------------------------- */

static void test_ticket_swap(unsigned pt, unsigned ot)
{
	sim_mon *m = mon_new(pt, ot);
	world w;
	actor a, b, c, mo;
	wri_cx_hs snap;
	wr_key old_key;

	WRT_CHECK(m != NULL);
	if (m == NULL || world_open(&w, m, pt) != 0) {
		WRT_CHECK(0);
		return;
	}
	login(&w);
	old_key = *sim_osd_key(&w);
	actor_osd(&w, &a, &w.hs[0]); /* begins before the swap, goes on after it */
	actor_osd(&w, &b, &w.hs[1]); /* begins before the swap, answered the challenge, done after it */
	step_ok(&w, &a);
	step_ok(&w, &b);
	step_ok(&w, &b);
	/* a monitor renewal that brings a NEW OSD ticket (want = AUTH | OSD) replaces the slot */
	w.e.c.want_mask = WRI_CX_WANT_MASK;
	actor_mon(&w, &mo, &w.hs[2]);
	run_rest(&w, &mo);
	WRT_CHECK(memcmp(sim_osd_key(&w)->secret, old_key.secret, old_key.len) != 0); /* really a new key */
	/* a handshake that begins after the swap uses the new ticket */
	actor_osd(&w, &c, &w.hs[3]);
	step_ok(&w, &c);
	snap = *c.hs;
	WRT_CHECK_STATUS(WR_E_STATE, step(&w, &a)); /* the ticket A began with is gone */
	WRT_CHECK(a.hs->st == WRI_CX_FAILED && a.hs->err.status == WR_E_STATE && a.hs->authorizer_nonce == 0);
	WRT_CHECK(hs_same(&snap, c.hs));
	WRT_CHECK_STATUS(WR_E_STATE, step(&w, &b)); /* done of B: same */
	WRT_CHECK(b.hs->st == WRI_CX_FAILED && b.hs->err.status == WR_E_STATE);
	WRT_CHECK(hs_same(&snap, c.hs));
	step_ok(&w, &c);
	step_ok(&w, &c);
	check_finished(&w, &c);
	WRT_CHECK(c.okey.len == sim_osd_key(&w)->len && memcmp(c.okey.secret, sim_osd_key(&w)->secret, c.okey.len) == 0);
	check_finished(&w, &mo);
	/* the failed ones start over on the new ticket */
	actor_osd(&w, &a, &w.hs[0]);
	run_rest(&w, &a);
	check_finished(&w, &a);
	world_close(&w);
	sim_mon_free(m);
}

/* ---- 5. a failed monitor done forgets every ticket (the shared rule) -------------------------------- */

static void test_forget_rule(void)
{
	sim_mon *m = mon_new(WR_KEY_TYPE_AES256K, WR_KEY_TYPE_AES256K);
	world w;
	actor a, b, mo;

	WRT_CHECK(m != NULL);
	if (m == NULL || world_open(&w, m, WR_KEY_TYPE_AES256K) != 0) {
		WRT_CHECK(0);
		return;
	}
	login(&w);
	w.e.c.want_mask = WRI_CX_SERVICE_AUTH;
	actor_osd(&w, &a, &w.hs[0]);
	actor_osd(&w, &b, &w.hs[1]);
	actor_mon(&w, &mo, &w.hs[2]);
	mo.fault = F_DONE_BIT;
	step_ok(&w, &a);
	step_ok(&w, &b);
	step_ok(&w, &b);
	step_ok(&w, &mo);
	step_ok(&w, &mo);
	WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, step(&w, &mo));
	WRT_CHECK(mo.hs->st == WRI_CX_FAILED && mo.hs->err.status == WR_E_AUTH_DECRYPT);
	WRT_CHECK(mo.hs->err.what != NULL && mo.hs->server_challenge == 0 && mo.hs->client_challenge == 0);
	WRT_CHECK(client_err_clean(&w)); /* the store's note went into the slot, not the client */
	WRT_CHECK(w.e.c.global_id == 0 && !w.e.c.ticket[WRI_CX_SLOT_AUTH].have && !w.e.c.ticket[WRI_CX_SLOT_OSD].have);
	/* the handshakes in flight find their ticket gone: a clean failure, not a completion with a stale key */
	WRT_CHECK_STATUS(WR_E_STATE, step(&w, &a));
	WRT_CHECK_STATUS(WR_E_STATE, step(&w, &b));
	WRT_CHECK(a.hs->st == WRI_CX_FAILED && b.hs->st == WRI_CX_FAILED && a.hs->authorizer_nonce == 0);
	/* and a clean login afterwards, then OSD handshakes on the slots again */
	{
		actor n;
		world_close(&w);
		if (world_open(&w, m, WR_KEY_TYPE_AES256K) != 0) {
			WRT_CHECK(0);
			sim_mon_free(m);
			return;
		}
		login(&w);
		actor_osd(&w, &n, &w.hs[0]);
		run_rest(&w, &n);
		check_finished(&w, &n);
	}
	world_close(&w);
	sim_mon_free(m);
}

/* ---- 5b. what a finished slot keeps: its id, and a key view that never outlives its ticket ----------- */

static void test_view_and_gid(unsigned pt, unsigned ot)
{
	sim_mon *m = mon_new(pt, ot);
	world w;
	actor a, b, mo, mo2;
	const uint8_t *k = NULL;
	size_t kn = 0;
	uint64_t gid0;

	WRT_CHECK(m != NULL);
	if (m == NULL || world_open(&w, m, pt) != 0) {
		WRT_CHECK(0);
		return;
	}
	login(&w);
	gid0 = w.e.c.global_id;
	actor_osd(&w, &a, &w.hs[0]);
	run_rest(&w, &a);
	check_finished(&w, &a);
	/* a monitor handshake that brings a new OSD ticket: A keeps its id but its key view is gone */
	w.e.c.want_mask = WRI_CX_WANT_MASK;
	actor_mon(&w, &mo, &w.hs[2]);
	run_rest(&w, &mo);
	check_finished(&w, &mo);
	a.ops->session_key(a.a, &k, &kn);
	WRT_CHECK(k == NULL && kn == 0);
	WRT_CHECK(a.ops->ident_gid(a.a, WRI_ENTITY_OSD) == (int64_t)gid0);
	/* a second monitor handshake replaces the AUTH ticket: the first one's key view is gone, the second's is valid */
	actor_mon(&w, &mo2, &w.hs[3]);
	run_rest(&w, &mo2);
	check_finished(&w, &mo2);
	mo.ops->session_key(mo.a, &k, &kn);
	WRT_CHECK(k == NULL && kn == 0);
	WRT_CHECK(mo.ops->ident_gid(mo.a, WRI_ENTITY_MON) == (int64_t)gid0);
	/* B finishes, then a failed monitor done forgets every ticket and the id: B's id stays, its key view is gone */
	actor_osd(&w, &b, &w.hs[1]);
	run_rest(&w, &b);
	check_finished(&w, &b);
	actor_mon(&w, &mo, &w.hs[2]);
	step_ok(&w, &mo);
	step_ok(&w, &mo);
	mo.gid = 0; /* a monitor that assigns id 0 */
	WRT_CHECK_STATUS(WR_E_AUTH_GID0, step(&w, &mo));
	WRT_CHECK(w.e.c.global_id == 0 && !w.e.c.ticket[WRI_CX_SLOT_OSD].have);
	b.ops->session_key(b.a, &k, &kn);
	WRT_CHECK(k == NULL && kn == 0);
	WRT_CHECK(b.ops->ident_gid(b.a, WRI_ENTITY_OSD) == (int64_t)gid0);
	/* a begin on the slot starts over: no id, no key from the earlier life */
	WRT_CHECK(wri_cx_hs_ops()->ident_gid(&w.hs[0], WRI_ENTITY_OSD) == (int64_t)gid0);
	{
		uint8_t o[512];
		wri_wr wr;

		wri_wr_init(&wr, o, sizeof(o));
		WRT_CHECK_STATUS(WR_E_AUTH_TICKET_EXPIRED, wri_cx_hs_ops()->begin(&w.hs[0], WRI_ENTITY_OSD, &wr));
		WRT_CHECK(w.hs[0].gid == 0 && w.hs[0].sess_key == NULL && w.hs[0].key_gen == 0);
		WRT_CHECK(wri_cx_hs_ops()->ident_gid(&w.hs[0], WRI_ENTITY_OSD) == -1);
	}
	world_close(&w);
	sim_mon_free(m);
}

/* A global id above 2^63 would read as a negative int64 in CLIENT_IDENT (-1 means "none"): refused, and the
 * shared failure rule applies (everything is forgotten). Neither the monitor's id 0 nor 2^63 - 1 are affected. */
static void test_gid_range(void)
{
	static const uint64_t bad[] = {1ull << 63, 0xffffffffffffffffull};
	unsigned i;

	for (i = 0; i < 2; i++) {
		sim_mon *m = mon_new(WR_KEY_TYPE_AES256K, WR_KEY_TYPE_AES256K);
		world w;
		actor mo;

		WRT_CHECK(m != NULL);
		if (m == NULL || world_open(&w, m, WR_KEY_TYPE_AES256K) != 0) {
			WRT_CHECK(0);
			return;
		}
		actor_mon(&w, &mo, &w.hs[0]);
		step_ok(&w, &mo);
		step_ok(&w, &mo);
		mo.gid = bad[i];
		WRT_CHECK_STATUS(WR_E_AUTH_PROTO, step(&w, &mo));
		WRT_CHECK(mo.hs->st == WRI_CX_FAILED && mo.hs->err.status == WR_E_AUTH_PROTO && mo.hs->gid == 0);
		WRT_CHECK(w.e.c.global_id == 0 && !w.e.c.ticket[WRI_CX_SLOT_AUTH].have);
		WRT_CHECK(mo.ops->ident_gid(mo.a, WRI_ENTITY_MON) == -1);
		world_close(&w);
		sim_mon_free(m);
	}
}

/* ---- 5c. the error paths of the machine, on one slot ------------------------------------------------- */

typedef struct epw {
	cxt_env e;
	wri_cx_hs h;
	wr_key ak, ok; /* the AUTH and OSD session keys the "server" hands out */
} epw;

static int ep_open(epw *p, unsigned kt)
{
	wr_key pk = cxt_key(kt, 5);

	memset(p, 0, sizeof(*p));
	cxt_rng_free();
	p->ak = cxt_key(kt, 0x31);
	p->ok = cxt_key(kt, 0x47);
	if (cxt_env_init(&p->e, "client.winrbd", &pk, 0) != 0 || wri_cx_hs_init(&p->h, &p->e.c) != WR_OK) {
		WRT_CHECK(0);
		return -1;
	}
	return 0;
}

static size_t ep_seal(epw *p, const wr_key *k, uint32_t usage, const uint8_t *item, size_t n, uint8_t *out, size_t cap)
{
	size_t o = 0;

	WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&p->e.x, k, usage, item, n, out, cap, &o));
	return o;
}

/* The slot has failed with exactly `want` (or, want == WR_OK, with whatever st is) and says so in its own record. */
static void ep_failed(const epw *p, wr_status st, wr_status want)
{
	const uint8_t *k = (const uint8_t *)1;
	size_t kn = 1;

	WRT_CHECK(st != WR_OK && (want == WR_OK || st == want));
	WRT_CHECK(p->h.st == WRI_CX_FAILED && p->h.err.status == st && p->h.err.what != NULL);
	WRT_CHECK(p->e.c.err.status == WR_OK); /* a slot never writes the client's record */
	WRT_CHECK(p->h.authorizer_nonce == 0 && p->h.server_challenge == 0 && p->h.client_challenge == 0 && p->h.gid == 0);
	wri_cx_hs_ops()->session_key((void *)&p->h, &k, &kn);
	WRT_CHECK(k == NULL && kn == 0);
	WRT_CHECK(wri_cx_hs_ops()->ident_gid((void *)&p->h, WRI_ENTITY_MON) == -1);
}

static void ep_forgotten(const epw *p)
{
	WRT_CHECK(p->e.c.global_id == 0 && !p->e.c.ticket[WRI_CX_SLOT_AUTH].have && !p->e.c.ticket[WRI_CX_SLOT_OSD].have);
}

static wr_status ep_mon_begin_more(epw *p)
{
	uint8_t b[256], chal[9];
	wri_wr w;
	wr_status st;

	wri_wr_init(&w, b, sizeof(b));
	st = wri_cx_hs_ops()->begin(&p->h, WRI_ENTITY_MON, &w);
	if (st != WR_OK)
		return st;
	chal[0] = 1;
	wri_le64_put(chal + 1, CXT_CHAL);
	wri_wr_init(&w, b, sizeof(b));
	return wri_cx_hs_ops()->more(&p->h, chal, sizeof(chal), &w);
}

/* A monitor AUTH_DONE up to and including the AUTH ticket reply, then `tail` (cbl and extra, as the test wants them). */
static size_t ep_done_payload(epw *p, const uint8_t *tail, size_t tn, uint8_t *out, size_t cap)
{
	cxt_dopt o;
	size_t n;

	cxt_dopt_default(&p->e, &o, &p->ak, &p->ok);
	o.tail = 0;
	n = cxt_build_done(&p->e, &o, out, cap);
	WRT_CHECK(n != 0 && n + tn <= cap);
	if (tn != 0)
		memcpy(out + n, tail, tn);
	return n + tn;
}

/* cbl = u32 total | body ... followed by `extra` = u32 0 */
static void ep_cbl_case(unsigned kt, int shape)
{
	epw p;
	uint8_t tail[400], ct[200], item[8], buf[2048];
	size_t tn = 0, cn, n;
	wr_status st;
	wri_wr w;

	if (ep_open(&p, kt) != 0)
		return;
	wri_wr_init(&w, tail, sizeof(tail));
	switch (shape) {
	case 0: /* the inner length claims more than the blob holds */
		wri_wr_u32(&w, 8);
		wri_wr_u32(&w, 100);
		wri_wr_u32(&w, 0);
		break;
	case 1: /* a valid sealed blob plus one stray byte */
		memset(item, 0, 4);
		cn = ep_seal(&p, &p.ak, WRI_CX_USAGE_CONN_SECRET, item, 4, ct, sizeof(ct));
		wri_wr_u32(&w, (uint32_t)(4u + cn + 1u));
		wri_wr_u32(&w, (uint32_t)cn);
		wri_wr_bytes(&w, ct, cn);
		wri_wr_u8(&w, 0x77);
		break;
	case 2: /* a secret string that claims 50 bytes and has none */
	case 3: /* an item too short to hold the string length */
		memset(item, 0, sizeof(item));
		item[0] = 50;
		cn = ep_seal(&p, &p.ak, WRI_CX_USAGE_CONN_SECRET, item, shape == 2 ? 4u : 2u, ct, sizeof(ct));
		wri_wr_u32(&w, (uint32_t)(4u + cn));
		wri_wr_u32(&w, (uint32_t)cn);
		wri_wr_bytes(&w, ct, cn);
		break;
	case 4: /* sealed under the wrong key */
		memset(item, 0, 4);
		cn = ep_seal(&p, &p.ok, WRI_CX_USAGE_CONN_SECRET, item, 4, ct, sizeof(ct));
		wri_wr_u32(&w, (uint32_t)(4u + cn));
		wri_wr_u32(&w, (uint32_t)cn);
		wri_wr_bytes(&w, ct, cn);
		break;
	default: /* cbl longer than the payload */
		wri_wr_u32(&w, 1000);
		break;
	}
	if (shape != 5)
		wri_wr_u32(&w, 0); /* extra: none */
	tn = wri_wr_len(&w);
	n = ep_done_payload(&p, tail, tn, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, ep_mon_begin_more(&p));
	st = wri_cx_hs_ops()->done(&p.h, 4100, WRI_CONN_MODE_CRC, buf, n);
	if (shape == 0 || shape == 1 || shape == 2 || shape == 3)
		ep_failed(&p, st, WR_E_AUTH_PROTO);
	else if (shape == 4)
		ep_failed(&p, st, WR_E_AUTH_DECRYPT);
	else
		ep_failed(&p, st, WR_OK);
	ep_forgotten(&p);
	cxt_env_free(&p.e);
}

static void ep_mon_more_cases(unsigned kt)
{
	epw p;
	uint8_t b[256], chal[9], small[16];
	wri_wr w;
	wr_status st;

	if (ep_open(&p, kt) != 0)
		return;
	/* a second AUTH_REPLY_MORE on the same handshake: protocol error, and the slot says so */
	WRT_CHECK_STATUS(WR_OK, ep_mon_begin_more(&p));
	chal[0] = 1;
	wri_le64_put(chal + 1, CXT_CHAL);
	wri_wr_init(&w, b, sizeof(b));
	st = wri_cx_hs_ops()->more(&p.h, chal, sizeof(chal), &w);
	ep_failed(&p, st, WR_E_AUTH_PROTO);
	/* the answer does not fit the connection's buffer */
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, wri_cx_hs_ops()->begin(&p.h, WRI_ENTITY_MON, &w));
	wri_wr_init(&w, small, sizeof(small));
	st = wri_cx_hs_ops()->more(&p.h, chal, sizeof(chal), &w);
	ep_failed(&p, st, WR_OK);
	/* a challenge shorter than its fields, and a zero one */
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, wri_cx_hs_ops()->begin(&p.h, WRI_ENTITY_MON, &w));
	wri_wr_init(&w, b, sizeof(b));
	st = wri_cx_hs_ops()->more(&p.h, chal, 5, &w);
	ep_failed(&p, st, WR_OK);
	memset(chal + 1, 0, 8);
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, wri_cx_hs_ops()->begin(&p.h, WRI_ENTITY_MON, &w));
	wri_wr_init(&w, b, sizeof(b));
	st = wri_cx_hs_ops()->more(&p.h, chal, sizeof(chal), &w);
	ep_failed(&p, st, WR_E_AUTH_PROTO);
	/* a principal key the proof cannot be made with */
	chal[1] = 1;
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, wri_cx_hs_ops()->begin(&p.h, WRI_ENTITY_MON, &w));
	p.e.c.principal.type = 9;
	wri_wr_init(&w, b, sizeof(b));
	st = wri_cx_hs_ops()->more(&p.h, chal, sizeof(chal), &w);
	ep_failed(&p, st, WR_OK);
	cxt_env_free(&p.e);

	/* a reclaim whose old AUTH ticket is dropped between begin and more */
	if (ep_open(&p, kt) != 0)
		return;
	WRT_CHECK_STATUS(WR_OK, cxt_good_mon(&p.e, &p.ak, &p.ok, 4100));
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, wri_cx_hs_ops()->begin(&p.h, WRI_ENTITY_MON, &w));
	WRT_CHECK(p.h.req_new_gid == 0); /* a reclaim: the held id and the held ticket */
	chal[0] = 1;
	wri_le64_put(chal + 1, CXT_CHAL);
	wri_cx_slot_clear(&p.e.c, WRI_CX_SLOT_AUTH);
	wri_wr_init(&w, b, sizeof(b));
	st = wri_cx_hs_ops()->more(&p.h, chal, sizeof(chal), &w);
	p.e.c.err.status = WR_OK;
	ep_failed(&p, st, WR_E_STATE);
	cxt_env_free(&p.e);
}

static void ep_osd_cases(unsigned kt)
{
	epw p;
	uint8_t b[512], ct[200], item[16], rep[256];
	wri_wr w;
	wr_status st;
	size_t cn;
	unsigned c;

	/* the authorizer does not fit the connection's buffer */
	if (ep_open(&p, kt) != 0)
		return;
	WRT_CHECK_STATUS(WR_OK, cxt_good_mon(&p.e, &p.ak, &p.ok, 4100));
	wri_wr_init(&w, b, 20);
	st = wri_cx_hs_ops()->begin(&p.h, WRI_ENTITY_OSD, &w);
	ep_failed(&p, st, WR_OK);
	WRT_CHECK(p.e.c.ticket[WRI_CX_SLOT_OSD].have && p.e.c.global_id == 4100); /* an OSD failure forgets nothing */

	/* the challenge: a second more, a truncated one, a damaged one, and an answer that does not fit */
	for (c = 0; c < 4; c++) {
		wri_wr_init(&w, b, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, wri_cx_hs_ops()->begin(&p.h, WRI_ENTITY_OSD, &w));
		memset(item, 0x11, sizeof(item));
		cn = ep_seal(&p, &p.ok, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, item, c == 1 ? 4u : 9u, ct, sizeof(ct));
		if (c == 2)
			ct[cn / 2] ^= 4u;
		wri_wr_init(&w, b, c == 3 ? 24u : sizeof(b));
		st = wri_cx_hs_ops()->more(&p.h, ct, cn, &w);
		if (c == 0) {
			WRT_CHECK_STATUS(WR_OK, st);
			wri_wr_init(&w, b, sizeof(b));
			st = wri_cx_hs_ops()->more(&p.h, ct, cn, &w); /* the same reply again */
			ep_failed(&p, st, WR_E_AUTH_PROTO);
		} else {
			ep_failed(&p, st, c == 2 ? WR_E_AUTH_DECRYPT : WR_OK);
		}
		WRT_CHECK(all_zero(p.e.c.scratch, p.e.c.scratch_cap)); /* nothing decrypted is left behind */
	}

	/* the final reply: damaged, truncated, a secret that claims more bytes than the item holds, stray bytes
	 * after it, a length beyond it (a complete secret of either mode is test_auth_secret.c's) */
	for (c = 0; c < 5; c++) {
		uint64_t nonce_item;
		size_t rn;

		wri_wr_init(&w, b, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, wri_cx_hs_ops()->begin(&p.h, WRI_ENTITY_OSD, &w));
		memset(item, 0, sizeof(item));
		item[0] = 1;
		wri_le64_put(item + 1, 7);
		cn = ep_seal(&p, &p.ok, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, item, 9, ct, sizeof(ct));
		wri_wr_init(&w, b, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, wri_cx_hs_ops()->more(&p.h, ct, cn, &w));
		nonce_item = p.h.authorizer_nonce + 1u;
		item[0] = c == 2 ? 2u : 1u;
		wri_le64_put(item + 1, nonce_item);
		wri_le32_put(item + 9, 5); /* v2: a connection secret of 5 bytes, of which 3 are there */
		memset(item + 13, 0x33, 3);
		cn = ep_seal(&p, &p.ok, WRI_CX_USAGE_AUTHORIZE_REPLY, item, c == 1 ? 4u : (c == 2 ? 16u : 9u), ct, sizeof(ct));
		if (c == 0)
			ct[cn - 1] ^= 1u;
		wri_le32_put(rep, (uint32_t)(c == 4 ? cn + 40u : cn));
		memcpy(rep + 4, ct, cn);
		rn = 4u + cn;
		if (c == 3) {
			rep[rn++] = 0x55;
		}
		st = wri_cx_hs_ops()->done(&p.h, 4100, WRI_CONN_MODE_CRC, rep, rn);
		ep_failed(&p, st, c == 0 ? WR_E_AUTH_DECRYPT : (c == 1 ? WR_OK : (c == 2 ? WR_E_TRUNCATED : WR_E_AUTH_PROTO)));
		WRT_CHECK(all_zero(p.e.c.scratch, p.e.c.scratch_cap));
		WRT_CHECK(p.e.c.ticket[WRI_CX_SLOT_OSD].have && p.e.c.global_id == 4100); /* still: nothing forgotten */
	}
	cxt_env_free(&p.e);
}

static void test_error_paths(void)
{
	static const unsigned kts[2] = {WR_KEY_TYPE_AES256K, WR_KEY_TYPE_AES};
	unsigned i, shape;

	for (i = 0; i < 2; i++) {
		for (shape = 0; shape < 6; shape++)
			ep_cbl_case(kts[i], (int)shape);
		ep_mon_more_cases(kts[i]);
		ep_osd_cases(kts[i]);
	}
}

/* ---- 6. wipe leaves zeros --------------------------------------------------------------------------- */

static int all_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i] != 0)
			return 0;
	return 1;
}

static void test_wipe(unsigned pt, unsigned ot)
{
	sim_mon *m = mon_new(pt, ot);
	world w;
	actor a, b;
	wri_cx_hs snap;
	uint8_t keycopy[WR_KEY_MAX];
	size_t kl;
	const uint8_t *k = (const uint8_t *)1;
	size_t kn = 1;
	wri_wr wr;
	uint8_t o[64];

	WRT_CHECK(m != NULL);
	if (m == NULL || world_open(&w, m, pt) != 0) {
		WRT_CHECK(0);
		return;
	}
	login(&w);
	kl = w.e.c.ticket[WRI_CX_SLOT_OSD].session_key.len;
	memcpy(keycopy, w.e.c.ticket[WRI_CX_SLOT_OSD].session_key.secret, kl);
	actor_osd(&w, &a, &w.hs[0]);
	actor_osd(&w, &b, &w.hs[1]);
	step_ok(&w, &a);
	step_ok(&w, &b);
	step_ok(&w, &a);
	step_ok(&w, &b);
	WRT_CHECK(a.hs->authorizer_nonce != 0 && a.hs->server_challenge != 0);
	snap = *b.hs;
	/* the connection of slot 0 is gone: its slot is wiped mid-handshake */
	wri_cx_hs_wipe(a.hs);
	WRT_CHECK(all_zero(a.hs, sizeof(*a.hs)));
	WRT_CHECK(hs_same(&snap, b.hs)); /* B is not affected */
	WRT_CHECK(memcmp(w.e.c.ticket[WRI_CX_SLOT_OSD].session_key.secret, keycopy, kl) == 0); /* nor is the store */
	a.ops->session_key(a.a, &k, &kn);
	WRT_CHECK(k == NULL && kn == 0);
	wri_wr_init(&wr, o, sizeof(o));
	WRT_CHECK_STATUS(WR_E_INVAL, a.ops->begin(a.a, WRI_ENTITY_OSD, &wr)); /* an unbound slot does nothing */
	WRT_CHECK(all_zero(a.hs, sizeof(*a.hs)));
	wri_cx_hs_wipe(a.hs); /* idempotent */
	wri_cx_hs_wipe(NULL);
	step_ok(&w, &b);
	check_finished(&w, &b);
	/* a finished slot keeps no secret of its own: wipe, and the key view is gone */
	wri_cx_hs_wipe(b.hs);
	WRT_CHECK(all_zero(b.hs, sizeof(*b.hs)));
	WRT_CHECK(memcmp(w.e.c.ticket[WRI_CX_SLOT_OSD].session_key.secret, keycopy, kl) == 0);
	/* a slot can be bound again and used */
	WRT_CHECK_STATUS(WR_OK, wri_cx_hs_init(&w.hs[0], &w.e.c));
	actor_osd(&w, &a, &w.hs[0]);
	run_rest(&w, &a);
	check_finished(&w, &a);
	WRT_CHECK(w.hs[0].err.status == WR_OK);

	/* the client's wipe, with an embedded OSD handshake in flight: the struct and the arena behind it are zero */
	{
		wri_cx_client *c = &w.e.c;
		wri_wr w2;
		uint8_t buf[512];

		wri_wr_init(&w2, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_OK, wri_cx_ops()->begin(c, WRI_ENTITY_OSD, &w2));
		WRT_CHECK(c->authorizer_nonce != 0 && c->st == WRI_CX_OSD_SENT_AUTHORIZER);
		WRT_CHECK(!all_zero(w.e.mem, w.e.memsz)); /* tickets are in there */
		wri_cx_client_wipe(c);
		WRT_CHECK(all_zero(c, sizeof(*c)));
		WRT_CHECK(all_zero(w.e.mem, w.e.memsz)); /* blobs and scratch wiped */
		/* slots bound to a wiped client refuse to work and hold nothing */
		wri_wr_init(&w2, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_ops()->begin(&w.hs[0], WRI_ENTITY_OSD, &w2));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_ops()->begin(c, WRI_ENTITY_OSD, &w2));
	}
	world_close(&w); /* wipes again: idempotent */
	sim_mon_free(m);
}

/* ---- 7. memory, binding, arguments ----------------------------------------------------------------- */

static void test_api(void)
{
	wr_config cfg;
	size_t need = 0;
	wri_arena a;
	wri_cx_hs *hs = NULL;
	uint32_t n = 99;
	uint8_t *mem;
	unsigned i;
	cxt_env e;
	wr_key pk = cxt_key(WR_KEY_TYPE_AES, 3);
	const uint8_t *k = (const uint8_t *)1;
	size_t kn = 1;
	wri_wr wr;
	uint8_t o[64];

	memset(&cfg, 0, sizeof(cfg));
	wr_config_profile_harness(&cfg);
	WRT_CHECK(cfg.max_handshakes >= 2u);
	WRT_CHECK_STATUS(WR_OK, wri_cx_hs_mem(&cfg, &need));
	WRT_CHECK(need >= (size_t)cfg.max_handshakes * sizeof(wri_cx_hs));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_mem(&cfg, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_mem(NULL, &need));
	WRT_CHECK(need == 0);
	cfg.max_handshakes = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_mem(&cfg, &need));
	wr_config_profile_harness(&cfg);
	WRT_CHECK_STATUS(WR_OK, wri_cx_hs_mem(&cfg, &need));

	/* carve exactly what mem() said (16-byte aligned base: one slack of padding allowed) */
	mem = (uint8_t *)calloc(1, need + WRI_ARENA_SLACK + 16u);
	WRT_CHECK(mem != NULL);
	wri_arena_init(&a, mem, need + WRI_ARENA_SLACK);
	WRT_CHECK_STATUS(WR_OK, wri_cx_hs_carve(&a, &cfg, &hs, &n));
	WRT_CHECK(hs != NULL && n == cfg.max_handshakes && ((uintptr_t)hs & 15u) == 0);
	for (i = 0; i < n; i++)
		WRT_CHECK(all_zero(&hs[i], sizeof(hs[i])) && hs[i].cl == NULL);
	/* too small: nothing is taken, nothing is returned */
	wri_arena_init(&a, mem, 16u);
	hs = (wri_cx_hs *)1;
	n = 99;
	WRT_CHECK_STATUS(WR_E_BUDGET, wri_cx_hs_carve(&a, &cfg, &hs, &n));
	WRT_CHECK(hs == NULL && n == 0 && a.used == 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_carve(NULL, &cfg, &hs, &n));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_carve(&a, NULL, &hs, &n));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_carve(&a, &cfg, NULL, &n));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_carve(&a, &cfg, &hs, NULL));
	free(mem);

	/* the two tables are different tables; both answer garbage arguments without touching anything */
	WRT_CHECK(wri_cx_hs_ops() != wri_cx_ops() && wri_cx_hs_ops() == wri_cx_hs_ops());
	wri_wr_init(&wr, o, sizeof(o));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_ops()->begin(NULL, WRI_ENTITY_OSD, &wr));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_ops()->more(NULL, o, 0, &wr));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_ops()->done(NULL, 1, 1, o, 0));
	wri_cx_hs_ops()->session_key(NULL, &k, &kn);
	WRT_CHECK(k == NULL && kn == 0);
	WRT_CHECK(wri_cx_hs_ops()->ident_gid(NULL, WRI_ENTITY_OSD) == -1);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_init(NULL, NULL));

	WRT_CHECK(cxt_env_init(&e, "winrbd", &pk, 0) == 0);
	{
		wri_cx_hs h;

		memset(&h, 0xAA, sizeof(h)); /* garbage in the slot: init leaves a clean idle one */
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_init(&h, NULL));
		WRT_CHECK_STATUS(WR_OK, wri_cx_hs_init(&h, &e.c));
		WRT_CHECK(h.cl == &e.c && h.st == WRI_CX_IDLE && h.authorizer_nonce == 0 && h.err.status == WR_OK);
		/* no ticket yet: an OSD begin fails in the slot and says why; the client is not touched */
		wri_wr_init(&wr, o, sizeof(o));
		WRT_CHECK_STATUS(WR_E_AUTH_TICKET_EXPIRED, wri_cx_hs_ops()->begin(&h, WRI_ENTITY_OSD, &wr));
		WRT_CHECK(h.err.status == WR_E_AUTH_TICKET_EXPIRED && h.st == WRI_CX_FAILED && e.c.err.status == WR_OK &&
			  e.c.st == WRI_CX_IDLE);
		/* a monitor begin on the slot asks for a new session, and leaves the embedded handshake idle */
		wri_wr_init(&wr, o, sizeof(o));
		WRT_CHECK_STATUS(WR_OK, wri_cx_hs_ops()->begin(&h, WRI_ENTITY_MON, &wr));
		WRT_CHECK(h.st == WRI_CX_MON_SENT_REQ && h.req_new_gid == 1 && e.c.st == WRI_CX_IDLE && e.c.req_new_gid == 0);
		WRT_CHECK(wri_cx_hs_ops()->ident_gid(&h, WRI_ENTITY_MON) == -1);
		WRT_CHECK_STATUS(WR_E_AUTH_PROTO, wri_cx_hs_ops()->done(&h, 1, 1, o, 0)); /* done before more */
		/* a payload pointer that is NULL with a length is refused */
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_hs_ops()->done(&h, 1, 1, NULL, 4));
		wri_cx_hs_wipe(&h);
	}
	cxt_env_free(&e);
}

int main(void)
{
	test_api();
	test_interleave();
	test_failure_isolated(WR_KEY_TYPE_AES256K, WR_KEY_TYPE_AES256K);
	test_failure_isolated(WR_KEY_TYPE_AES, WR_KEY_TYPE_AES);
	test_failure_isolated(WR_KEY_TYPE_AES256K, WR_KEY_TYPE_AES);
	test_superseded();
	test_ticket_swap(WR_KEY_TYPE_AES256K, WR_KEY_TYPE_AES256K);
	test_ticket_swap(WR_KEY_TYPE_AES, WR_KEY_TYPE_AES);
	test_ticket_swap(WR_KEY_TYPE_AES, WR_KEY_TYPE_AES256K);
	test_forget_rule();
	test_view_and_gid(WR_KEY_TYPE_AES256K, WR_KEY_TYPE_AES256K);
	test_view_and_gid(WR_KEY_TYPE_AES, WR_KEY_TYPE_AES256K);
	test_gid_range();
	test_error_paths();
	test_wipe(WR_KEY_TYPE_AES256K, WR_KEY_TYPE_AES256K);
	test_wipe(WR_KEY_TYPE_AES, WR_KEY_TYPE_AES);
	test_wipe(WR_KEY_TYPE_AES256K, WR_KEY_TYPE_AES);
	return wrt_finish();
}
