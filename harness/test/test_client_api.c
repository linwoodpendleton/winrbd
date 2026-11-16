/* SPDX-License-Identifier: MIT */
/*
 * test_client_api.c - argument validation of every public entry point of wr_client.h: NULL pointers,
 * wrong abi / size of the configuration and the host table, zero-sized, misaligned, missing and
 * overlapping regions, unusable keys and users, a dead random source, handles that were destroyed.
 * Nothing here needs a monitor: a valid connection id is obtained from the first CONNECT action.
 */
#include "wrt.h"

#include "wri_client.h"

static uint64_t g_rng = 0x1234567890abcdefull;

static wr_status h_random(void *ctx, uint8_t *out, size_t n)
{
	size_t i;

	if (ctx != NULL && *(int *)ctx != 0)
		return WR_E_HOST_RANDOM;
	for (i = 0; i < n; i++) {
		g_rng ^= g_rng >> 12;
		g_rng ^= g_rng << 25;
		g_rng ^= g_rng >> 27;
		out[i] = (uint8_t)((g_rng * 0x2545f4914f6cdd1dull) >> 56);
	}
	return WR_OK;
}

typedef struct fx {
	wr_config cfg;
	wr_host_ops host;
	wr_cluster_spec spec;
	int rng_fail;
	uint8_t *raw_a, *raw_b;
	uint8_t *a, *b; /* 64-byte aligned */
	wr_mem_req req;
} fx;

static void fx_init(fx *f)
{
	uint8_t raw[32];
	size_t i;
	uintptr_t p;

	memset(f, 0, sizeof(*f));
	wr_config_profile_ipxe(&f->cfg);
	f->host.size = (uint32_t)sizeof(f->host);
	f->host.ctx = &f->rng_fail;
	f->host.random = h_random;
	for (i = 0; i < sizeof(raw); i++)
		raw[i] = (uint8_t)(i * 3u + 9u);
	strcpy(f->spec.user, "winrbd");
	WRT_CHECK_STATUS(WR_OK, wr_key_from_raw(&f->spec.key, WR_KEY_TYPE_AES256K, raw, 32));
	f->spec.n_mons = 1;
	f->spec.mons[0].family = WR_AF_IPV4;
	f->spec.mons[0].ip[0] = 10, f->spec.mons[0].ip[1] = 77, f->spec.mons[0].ip[3] = 10;
	f->spec.mons[0].port = 0; /* 0 means the default 3300 */
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&f->cfg, &f->req));
	f->raw_a = (uint8_t *)calloc(1, f->req.arena + 256u);
	f->raw_b = (uint8_t *)calloc(1, f->req.bulk + 256u);
	if (f->raw_a == NULL || f->raw_b == NULL)
		abort();
	p = ((uintptr_t)f->raw_a + 63u) & ~(uintptr_t)63u;
	f->a = (uint8_t *)p;
	p = ((uintptr_t)f->raw_b + 63u) & ~(uintptr_t)63u;
	f->b = (uint8_t *)p;
}

static void fx_free(fx *f)
{
	free(f->raw_a);
	free(f->raw_b);
}

static wr_status fx_create(fx *f, wr_client **out)
{
	return wr_client_create(&f->cfg, &f->host, &f->spec, (wr_mem_region){f->a, f->req.arena}, (wr_mem_region){f->b, f->req.bulk}, out);
}

static int all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

static void test_create_args(void)
{
	fx f;
	wr_client *c = (wr_client *)1;
	wr_mem_region ra, rb;
	wr_config bad;
	wr_host_ops hbad;
	wr_cluster_spec sbad;

	fx_init(&f);
	ra = (wr_mem_region){f.a, f.req.arena};
	rb = (wr_mem_region){f.b, f.req.bulk};

	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &f.spec, ra, rb, NULL));
	c = (wr_client *)1;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(NULL, &f.host, &f.spec, ra, rb, &c));
	WRT_CHECK(c == NULL); /* *out is cleared on every failure */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, NULL, &f.spec, ra, rb, &c));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, NULL, ra, rb, &c));

	bad = f.cfg;
	bad.abi = WR_ABI_VERSION + 1u;
	WRT_CHECK_STATUS(WR_E_ABI, wr_client_create(&bad, &f.host, &f.spec, ra, rb, &c));
	bad = f.cfg;
	bad.size = (uint32_t)sizeof(bad) - 4u;
	WRT_CHECK_STATUS(WR_E_ABI, wr_client_create(&bad, &f.host, &f.spec, ra, rb, &c));
	bad = f.cfg;
	bad.size = (uint32_t)sizeof(bad) + 8u;
	WRT_CHECK_STATUS(WR_E_ABI, wr_client_create(&bad, &f.host, &f.spec, ra, rb, &c));
	hbad = f.host;
	hbad.size = (uint32_t)sizeof(hbad) - 1u;
	WRT_CHECK_STATUS(WR_E_ABI, wr_client_create(&f.cfg, &hbad, &f.spec, ra, rb, &c));
	hbad = f.host;
	hbad.random = NULL;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &hbad, &f.spec, ra, rb, &c));

	/* regions: zero sized, missing, misaligned, overlapping */
	WRT_CHECK_STATUS(WR_E_BUDGET, wr_client_create(&f.cfg, &f.host, &f.spec, (wr_mem_region){f.a, 0}, rb, &c));
	WRT_CHECK_STATUS(WR_E_BUDGET, wr_client_create(&f.cfg, &f.host, &f.spec, ra, (wr_mem_region){f.b, 0}, &c));
	WRT_CHECK_STATUS(WR_E_BUDGET, wr_client_create(&f.cfg, &f.host, &f.spec, (wr_mem_region){NULL, 0}, (wr_mem_region){NULL, 0}, &c));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &f.spec, (wr_mem_region){NULL, f.req.arena}, rb, &c));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &f.spec, ra, (wr_mem_region){NULL, f.req.bulk}, &c));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &f.spec, (wr_mem_region){f.a + 8, f.req.arena}, rb, &c));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &f.spec, ra, (wr_mem_region){f.b + 4, f.req.bulk}, &c));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &f.spec, (wr_mem_region){f.b, f.req.arena}, rb, &c)); /* the arena inside the bulk */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &f.spec, (wr_mem_region){f.a, (size_t)-1}, rb, &c)); /* wraps the address space */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &f.spec, ra, (wr_mem_region){f.b, (size_t)-1}, &c));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &f.spec, (wr_mem_region){f.b + 16, f.req.arena}, rb, &c)); /* starts inside the bulk */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &f.spec, ra, (wr_mem_region){f.a + 16, f.req.bulk}, &c)); /* the bulk starts inside the arena */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &f.spec, rb, rb, &c));                                  /* the same region twice */
	WRT_CHECK(c == NULL);
	WRT_CHECK(all_zero(f.a, f.req.arena) && all_zero(f.b, f.req.bulk)); /* nothing was written by any refusal */

	/* the cluster description */
	sbad = f.spec;
	memset(sbad.user, 'x', sizeof(sbad.user)); /* not terminated */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &sbad, ra, rb, &c));
	sbad = f.spec;
	sbad.user[0] = '\0';
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &sbad, ra, rb, &c));
	sbad = f.spec;
	strcpy(sbad.user, "client.");
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &sbad, ra, rb, &c));
	sbad = f.spec;
	sbad.key.type = 3;
	WRT_CHECK(wr_client_create(&f.cfg, &f.host, &sbad, ra, rb, &c) != WR_OK);
	sbad = f.spec;
	sbad.key.len = 20; /* type 2 needs 32 */
	WRT_CHECK(wr_client_create(&f.cfg, &f.host, &sbad, ra, rb, &c) != WR_OK);
	sbad = f.spec;
	sbad.key.type = WR_KEY_TYPE_AES;
	sbad.key.len = 16;
	WRT_CHECK_STATUS(WR_OK, wr_client_create(&f.cfg, &f.host, &sbad, ra, rb, &c)); /* type 1 is fine */
	wr_client_destroy(c);
	memset(f.a, 0, f.req.arena);
	memset(f.b, 0, f.req.bulk);
	sbad = f.spec;
	sbad.n_mons = 0;
	WRT_CHECK_STATUS(WR_E_MON_NO_V2_ADDR, wr_client_create(&f.cfg, &f.host, &sbad, ra, rb, &c));
	sbad = f.spec;
	sbad.mons[0].family = 0;
	WRT_CHECK_STATUS(WR_E_MON_NO_V2_ADDR, wr_client_create(&f.cfg, &f.host, &sbad, ra, rb, &c));
	sbad = f.spec;
	sbad.n_mons = WR_MAX_MONS + 1;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&f.cfg, &f.host, &sbad, ra, rb, &c));
	WRT_CHECK(c == NULL);
	WRT_CHECK(all_zero(f.a, f.req.arena) && all_zero(f.b, f.req.bulk));

	/* a dead random source: no client, memory untouched */
	f.rng_fail = 1;
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, fx_create(&f, &c));
	WRT_CHECK(c == NULL);
	WRT_CHECK(all_zero(f.a, f.req.arena) && all_zero(f.b, f.req.bulk));
	f.rng_fail = 0;

	/* and the good case, "client." prefix or not, port 0 = 3300 */
	WRT_CHECK_STATUS(WR_OK, fx_create(&f, &c));
	WRT_CHECK(c != NULL);
	WRT_CHECK(wr_client_get_state(c) == WR_CS_CREATED);
	WRT_CHECK(strcmp(c->cx.user, "winrbd") == 0);
	wr_client_destroy(c);
	memset(f.a, 0, f.req.arena);
	memset(f.b, 0, f.req.bulk);
	strcpy(f.spec.user, "client.winrbd");
	WRT_CHECK_STATUS(WR_OK, fx_create(&f, &c));
	WRT_CHECK(c != NULL && strcmp(c->cx.user, "winrbd") == 0); /* a leading "client." is stripped */
	wr_client_destroy(c);
	fx_free(&f);
}

/* One allocation split in two, back to back (wr_client.h: the two regions may be one allocation): accepted, and the
 * engine keeps to its own part. */
static void test_adjacent_regions(void)
{
	fx f;
	wr_client *c = NULL;
	uint8_t *one;
	wr_stats st;

	fx_init(&f);
	free(f.raw_b); /* one buffer for both parts instead of the two that fx_init made */
	f.raw_b = (uint8_t *)calloc(1, f.req.arena + f.req.bulk + 256u);
	if (f.raw_b == NULL)
		abort();
	one = (uint8_t *)((((uintptr_t)f.raw_b) + 63u) & ~(uintptr_t)63u);
	WRT_CHECK_U64(f.req.arena % 16u, 0); /* the second part is 16-byte aligned too */
	WRT_CHECK_STATUS(WR_OK, wr_client_create(&f.cfg, &f.host, &f.spec, (wr_mem_region){one, f.req.arena},
						 (wr_mem_region){one + f.req.arena, f.req.bulk}, &c));
	WRT_CHECK(c != NULL);
	if (c != NULL) {
		wr_client_get_stats(c, &st);
		WRT_CHECK_U64(st.arena_used, f.req.arena);
		WRT_CHECK_U64(st.bulk_used, f.req.bulk);
		wr_client_destroy(c);
	}
	fx_free(&f);
}

/* Every call with NULL or nonsense arguments: nothing crashes, outputs are cleared. */
static void test_null_handles(void)
{
	wr_action a;
	wr_event e;
	wr_mapmsg m;
	wr_stats st;
	wr_iov iov[2];
	uint8_t *p = (uint8_t *)1;
	uint8_t junk[8] = {0};
	wr_clock clk = {1000, 0};
	wr_run_result r;
	const wr_errinfo *er;

	r = wr_client_run(NULL, &clk, 0);
	WRT_CHECK(r.next_deadline_ms == WR_DEADLINE_NONE && r.more_work == 0);
	wr_client_destroy(NULL);
	a.kind = WR_ACT_TX_READY;
	WRT_CHECK(wr_client_next_action(NULL, &a) == 0 && a.kind == WR_ACT_NONE);
	WRT_CHECK(wr_client_next_action(NULL, NULL) == 0);
	wr_conn_connected(NULL, 1);
	wr_conn_closed(NULL, 1, 5);
	WRT_CHECK_U64(wr_conn_rx_window(NULL, 1, &p), 0);
	WRT_CHECK(p == NULL);
	WRT_CHECK_U64(wr_conn_rx_window(NULL, 1, NULL), 0);
	wr_conn_rx_commit(NULL, 1, 4);
	WRT_CHECK_U64(wr_conn_rx_push(NULL, 1, junk, sizeof(junk)), 0);
	WRT_CHECK_U64(wr_conn_tx_peek(NULL, 1, iov, 2), 0);
	wr_conn_tx_consume(NULL, 1, 4);
	e.kind = WR_EV_FATAL;
	WRT_CHECK(wr_client_next_event(NULL, &e) == 0 && e.kind == WR_EV_NONE);
	WRT_CHECK(wr_client_next_event(NULL, NULL) == 0);
	m.kind = WR_MAPMSG_OSDMAP;
	WRT_CHECK(wr_client_mapmsg_peek(NULL, &m) == 0 && m.front == NULL && m.front_len == 0);
	WRT_CHECK(wr_client_mapmsg_peek(NULL, NULL) == 0);
	wr_client_mapmsg_release(NULL);
	WRT_CHECK(wr_client_get_state(NULL) == WR_CS_FAILED);
	er = wr_client_last_error(NULL);
	WRT_CHECK(er != NULL && er->status == WR_OK);
	memset(&st, 0xff, sizeof(st));
	wr_client_get_stats(NULL, &st);
	WRT_CHECK(st.conns_in_use == 0 && st.arena_used == 0 && st.bulk_used == 0);
	wr_client_get_stats(NULL, NULL);
}

static void test_live_handle_args(void)
{
	fx f;
	wr_client *c = NULL;
	wr_clock clk = {1000, 0};
	wr_action a;
	wr_iov iov[8];
	uint8_t *p = (uint8_t *)1;
	uint8_t junk[16] = {0};
	wr_run_result r;
	wr_stats st;
	wr_event e;
	wr_mapmsg m;
	wr_conn_id id;
	size_t room;

	fx_init(&f);
	WRT_CHECK_STATUS(WR_OK, fx_create(&f, &c));
	if (c == NULL) {
		fx_free(&f);
		return;
	}
	/* run without a clock does nothing and does not start the machine */
	r = wr_client_run(c, NULL, 0);
	WRT_CHECK(r.next_deadline_ms == WR_DEADLINE_NONE && r.more_work == 0);
	WRT_CHECK(wr_client_get_state(c) == WR_CS_CREATED);
	WRT_CHECK(wr_client_next_action(c, &a) == 0);
	WRT_CHECK(wr_client_next_action(c, NULL) == 0);
	WRT_CHECK(wr_client_next_event(c, &e) == 0);
	WRT_CHECK(wr_client_next_event(c, NULL) == 0);
	WRT_CHECK(wr_client_mapmsg_peek(c, &m) == 0);
	WRT_CHECK(wr_client_mapmsg_peek(c, NULL) == 0);
	wr_client_mapmsg_release(c); /* nothing held */
	wr_client_get_stats(c, NULL);

	r = wr_client_run(c, &clk, 0);
	WRT_CHECK(wr_client_get_state(c) == WR_CS_HUNTING);
	WRT_CHECK(r.next_deadline_ms != 0);
	WRT_CHECK(wr_client_next_action(c, &a) == 1 && a.kind == WR_ACT_CONNECT);
	WRT_CHECK(a.addr.family == WR_AF_IPV4 && a.addr.port == 3300 && a.addr.ip[0] == 10 && a.addr.ip[1] == 77 && a.addr.ip[3] == 10);
	WRT_CHECK_U64(a.timeout_ms, f.cfg.connect_timeout_ms);
	id = a.conn;

	/* invalid ids and arguments of a handle that is alive */
	WRT_CHECK_U64(wr_conn_rx_window(c, 0, &p), 0);
	WRT_CHECK(p == NULL);
	WRT_CHECK_U64(wr_conn_rx_window(c, id + 1u, &p), 0); /* the slot index of another (free) slot */
	WRT_CHECK_U64(wr_conn_rx_window(c, id ^ 0x10000u, &p), 0); /* the generation is wrong */
	WRT_CHECK_U64(wr_conn_rx_window(c, 0xffffu, &p), 0);   /* the slot index beyond the table */
	WRT_CHECK_U64(wr_conn_rx_push(c, id ^ 0x10000u, junk, sizeof(junk)), 0);
	wr_conn_connected(c, id ^ 0x10000u); /* ignored: still waiting for the real one */
	WRT_CHECK(wr_client_next_action(c, &a) == 0);
	/* not connected yet: no window, nothing to send */
	WRT_CHECK_U64(wr_conn_rx_window(c, id, &p), 0);
	WRT_CHECK_U64(wr_conn_rx_push(c, id, junk, sizeof(junk)), 0);
	WRT_CHECK_U64(wr_conn_tx_peek(c, id, iov, 8), 0);

	wr_conn_connected(c, id);
	wr_conn_connected(c, id); /* a second report is harmless */
	WRT_CHECK(wr_client_next_action(c, &a) == 1 && a.kind == WR_ACT_TX_READY);
	room = wr_conn_rx_window(c, id, NULL); /* a NULL pointer slot is fine */
	WRT_CHECK(room >= 64u);
	WRT_CHECK_U64(wr_conn_rx_push(c, id, NULL, 5), 0);
	WRT_CHECK_U64(wr_conn_rx_push(c, id, junk, 0), 0);
	WRT_CHECK_U64(wr_conn_tx_peek(c, id, NULL, 8), 0);
	WRT_CHECK_U64(wr_conn_tx_peek(c, id, iov, 0), 0);
	WRT_CHECK(wr_conn_tx_peek(c, id, iov, 1) == 1);
	wr_conn_tx_consume(c, id, 0);
	wr_conn_rx_commit(c, id, 0);
	wr_client_get_stats(c, &st);
	WRT_CHECK_U64(st.conns_in_use, 1);
	WRT_CHECK_U64(st.handshakes_in_use, 1);

	/* garbage instead of a banner: the connection fails, the engine asks the host to close it (once) */
	memset(junk, 'z', sizeof(junk));
	WRT_CHECK_U64(wr_conn_rx_push(c, id, junk, sizeof(junk)), sizeof(junk));
	(void)wr_client_run(c, &clk, 0);
	WRT_CHECK(wr_client_next_action(c, &a) == 1 && a.kind == WR_ACT_CLOSE && a.conn == id);
	WRT_CHECK(wr_client_next_action(c, &a) == 0);
	WRT_CHECK_U64(wr_conn_rx_window(c, id, &p), 0); /* a failed connection takes no more bytes */
	WRT_CHECK_U64(wr_conn_tx_peek(c, id, iov, 8), 0);
	wr_client_get_stats(c, &st);
	WRT_CHECK_U64(st.handshakes_in_use, 0); /* the handshake slot went back when the connection failed */
	WRT_CHECK_U64(st.conns_in_use, 1);      /* the slot stays until the host reports the close */
	wr_conn_closed(c, id, 0);
	wr_conn_closed(c, id, 0); /* twice: ignored */
	wr_client_get_stats(c, &st);
	WRT_CHECK_U64(st.conns_in_use, 0);
	WRT_CHECK(wr_client_last_error(c)->status != WR_OK);
	WRT_CHECK(wr_client_last_error(c)->status == WR_E_M2_BANNER || wr_client_last_error(c)->status == WR_E_M2_PEER_V1 ||
		  wr_client_last_error(c)->status == WR_E_M2_FRAME_FORM);

	/* destroyed handles are inert */
	wr_client_destroy(c);
	WRT_CHECK(wr_client_get_state(c) == WR_CS_FAILED);
	r = wr_client_run(c, &clk, 0);
	WRT_CHECK(r.next_deadline_ms == WR_DEADLINE_NONE);
	WRT_CHECK(wr_client_next_action(c, &a) == 0);
	WRT_CHECK_U64(wr_conn_rx_window(c, id, &p), 0);
	WRT_CHECK(wr_client_next_event(c, &e) == 0);
	wr_client_destroy(c);
	fx_free(&f);
}

int main(void)
{
	test_create_args();
	test_adjacent_regions();
	test_null_handles();
	test_live_handle_args();
	return wrt_finish();
}
