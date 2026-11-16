/* SPDX-License-Identifier: MIT */
/*
 * sim_mon.c - the fake monitor of the harness (see sim_mon.h): configuration, lifecycle, the
 * connection table, message dispatch (MMonGetMap, MMonSubscribe, MAuth), sending with the monitor's
 * header conventions, and the restart / expiry hooks. The cephx server side is in sim_mon_auth.c, the
 * map store and subscription service in sim_mon_maps.c. Test code: libc allowed.
 */
#include "sim_mon_int.h"

/* ---- configuration ------------------------------------------------------------------------------- */

sim_m2_fault sim_mon_fault_default(void)
{
	sim_m2_fault f;

	memset(&f, 0, sizeof(f));
	f.out_limit = -1;
	return f;
}

void sim_mon_cfg_default(sim_mon_cfg *c)
{
	unsigned i;

	memset(c, 0, sizeof(*c));
	sim_m2_cfg_default(&c->m2);
	c->m2.entity_type = SIM_M2_ENT_MON;
	c->m2.preauth_cap = 64u << 10; /* a monitor handshake is a few hundred bytes */
	memcpy(c->user, "winrbd", 7);
	c->allowed_key_types = (1u << WR_KEY_TYPE_AES) | (1u << WR_KEY_TYPE_AES256K);
	c->seed = 0x5eed5eed12345678ull;
	c->first_global_id = 4100;
	c->osd_map_message_max = 40;
	c->plan_default.fault = sim_mon_fault_default();
	for (i = 0; i < SIM_MON_MAX_PLANS; i++)
		c->plans[i].fault = sim_mon_fault_default();
}

unsigned sim_mon_slot(uint32_t service)
{
	switch (service) {
	case 0x01u: return 0;
	case 0x02u: return 1;
	case 0x04u: return 2;
	case 0x08u: return 3;
	case 0x10u: return 4;
	case 0x20u: return 5;
	default: return SIM_MON_TSLOTS;
	}
}

/* ---- generator, cipher context, scratch ------------------------------------------------------------ */

uint64_t sim_mon_rand64(sim_mon *m)
{
	uint64_t x = m->rng;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	m->rng = x;
	return x * 0x2545f4914f6cdd1dull;
}

void sim_mon_rand(sim_mon *m, uint8_t *out, size_t n)
{
	size_t i = 0;

	while (i < n) {
		uint64_t v = sim_mon_rand64(m);
		unsigned k;

		for (k = 0; k < 8 && i < n; k++, i++)
			out[i] = (uint8_t)(v >> (8u * k));
	}
}

static wr_status host_random(void *ctx, uint8_t *out, size_t n)
{
	sim_mon_rand((sim_mon *)ctx, out, n);
	return WR_OK;
}

const wri_ctx *sim_mon_ctx(const sim_mon *m) { return (const wri_ctx *)m->x; }

uint8_t *sim_mon_scratch(sim_mon *m, size_t n)
{
	if (n > m->scratch_cap) {
		uint8_t *q = (uint8_t *)realloc(m->scratch, n);

		if (q == NULL)
			return NULL;
		m->scratch = q;
		m->scratch_cap = n;
	}
	return m->scratch;
}

/* ---- lifecycle ------------------------------------------------------------------------------------- */

static int key_ok(const wr_key *k)
{
	if (k->type == WR_KEY_TYPE_AES)
		return k->len >= 16u && k->len <= WR_KEY_MAX;
	if (k->type == WR_KEY_TYPE_AES256K)
		return k->len >= 32u && k->len <= WR_KEY_MAX;
	return 0;
}

sim_mon *sim_mon_new(const sim_mon_cfg *cfg)
{
	sim_mon *m;
	wri_ctx *x;

	if (cfg == NULL || !key_ok(&cfg->key) || cfg->n_plans > SIM_MON_MAX_PLANS || cfg->user[0] == '\0' ||
	    memchr(cfg->user, '\0', sizeof(cfg->user)) == NULL || cfg->osd_map_message_max == 0 ||
	    cfg->osdmap_pad > (64u << 20))
		return NULL;
	m = (sim_mon *)calloc(1, sizeof(*m));
	x = (wri_ctx *)calloc(1, sizeof(*x));
	if (m == NULL || x == NULL) {
		free(m);
		free(x);
		return NULL;
	}
	m->cfg = *cfg;
	if (m->cfg.osd_map_message_max > SIM_MON_MAX_EPOCHS)
		m->cfg.osd_map_message_max = SIM_MON_MAX_EPOCHS;
	m->x = x;
	m->rng = cfg->seed != 0 ? cfg->seed : 0x5eed5eed12345678ull;
	m->next_gid = cfg->first_global_id != 0 ? cfg->first_global_id : 4100u;
	m->next_secret_id = 7001;
	m->gen = 1;
	x->host.size = (uint32_t)sizeof(x->host);
	x->host.ctx = m;
	x->host.random = host_random;
	if (sim_mon_maps_init(m) != WR_OK) {
		sim_mon_free(m);
		return NULL;
	}
	return m;
}

void sim_mon_free(sim_mon *m)
{
	uint32_t i;

	if (m == NULL)
		return;
	for (i = 0; i < SIM_MON_MAX_CONNS; i++)
		if (m->conns[i] != NULL)
			sim_mon_conn_free(m->conns[i]);
	sim_mon_maps_free(m);
	wri_secure_zero(m->ring, sizeof(m->ring));
	wri_secure_zero(m->last, sizeof(m->last));
	wr_key_wipe(&m->cfg.key);
	free(m->scratch);
	free(m->x);
	free(m);
}

static void conn_drop_held(sim_mon_conn *c)
{
	uint32_t i;

	for (i = 0; i < c->n_held; i++)
		free(c->held[i].front);
	c->n_held = 0;
}

sim_mon_conn *sim_mon_accept(sim_mon *m)
{
	sim_mon_conn *c;
	sim_m2_cfg cfg;
	sim_m2_auth_ops ops;
	uint32_t slot;

	for (slot = 0; slot < SIM_MON_MAX_CONNS && m->conns[slot] != NULL; slot++)
		;
	if (slot == SIM_MON_MAX_CONNS)
		return NULL;
	c = (sim_mon_conn *)calloc(1, sizeof(*c));
	if (c == NULL)
		return NULL;
	c->mon = m;
	c->index = m->n_accepted;
	c->plan = c->index < m->cfg.n_plans ? m->cfg.plans[c->index] : m->cfg.plan_default;
	cfg = m->cfg.m2;
	cfg.entity_type = SIM_M2_ENT_MON;
	if (c->plan.has_fault)
		cfg.f = c->plan.fault;
	if (m->cfg.osdmap_pad != 0 && cfg.seg_cap < m->cfg.osdmap_pad + (256u << 10))
		cfg.seg_cap = m->cfg.osdmap_pad + (256u << 10); /* the oversized front must be sendable */
	memset(&ops, 0, sizeof(ops));
	ops.ctx = c;
	ops.request = sim_mon_auth_request;
	ops.more = sim_mon_auth_more;
	c->payload = (uint8_t *)malloc(SIM_MON_PAYLOAD);
	c->m2 = sim_m2_new(&cfg, &ops);
	if (c->payload == NULL || c->m2 == NULL) {
		free(c->payload);
		sim_m2_free(c->m2);
		free(c);
		return NULL;
	}
	c->m2->on_message = sim_mon_on_message;
	c->m2->on_message_ctx = c;
	m->conns[slot] = c;
	m->n_accepted++;
	return c;
}

void sim_mon_conn_free(sim_mon_conn *c)
{
	uint32_t i;

	if (c == NULL)
		return;
	for (i = 0; i < SIM_MON_MAX_CONNS; i++)
		if (c->mon->conns[i] == c)
			c->mon->conns[i] = NULL;
	conn_drop_held(c);
	wr_key_wipe(&c->auth_key);
	free(c->payload);
	sim_m2_free(c->m2);
	free(c);
}

size_t sim_mon_feed(sim_mon_conn *c, const uint8_t *p, size_t n) { return sim_m2_feed(c->m2, p, n); }
size_t sim_mon_drain(sim_mon_conn *c, uint8_t *out, size_t cap) { return sim_m2_drain(c->m2, out, cap); }
int sim_mon_closed(const sim_mon_conn *c) { return sim_m2_closed(c->m2); }

/* ---- sending --------------------------------------------------------------------------------------- */

wr_status sim_mon_send_message(sim_mon_conn *c, uint16_t type, uint16_t version, uint16_t compat,
			       const uint8_t *front, uint32_t flen)
{
	sim_m2 *s = c->m2;
	uint8_t h[WRI_M2_HDR2_LEN];
	wri_m2_hdr2 hd;
	wri_m2_seg_src seg[2];
	wr_status st;

	if (c->killed || s->state != SIM_M2_ST_READY)
		return WR_E_STATE;
	memset(&hd, 0, sizeof(hd));
	hd.seq = s->out_seq + 1u;
	hd.type = type;
	hd.priority = (uint16_t)SIM_MON_PRIO;
	hd.version = version;
	hd.ack_seq = s->in_seq;
	hd.flags = WRI_M2_MSGF_COMPLETE_NOCRC;
	hd.compat_version = compat;
	wri_m2_hdr2_encode(h, &hd);
	seg[0].p = h, seg[0].len = sizeof(h), seg[0].ref = 0;
	seg[1].p = front, seg[1].len = flen, seg[1].ref = 0;
	st = sim_m2_send_frame(s, WRI_M2_TAG_MESSAGE, seg, flen != 0 ? 2u : 1u);
	if (st == WR_OK)
		s->out_seq++;
	if (st != WR_OK && c->send_err == WR_OK)
		c->send_err = st;
	return st;
}

wr_status sim_mon_send_map_msg(sim_mon_conn *c, uint16_t type, uint16_t version, uint16_t compat,
			       const uint8_t *front, uint32_t len)
{
	sim_mon_held *h;

	if (!c->plan.hold_maps)
		return sim_mon_send_message(c, type, version, compat, front, len);
	if (c->n_held == SIM_MON_HELD) {
		c->send_err = c->send_err != WR_OK ? c->send_err : WR_E_BUDGET;
		return WR_E_BUDGET;
	}
	h = &c->held[c->n_held];
	h->front = (uint8_t *)malloc(len != 0 ? len : 1u);
	if (h->front == NULL) {
		c->send_err = c->send_err != WR_OK ? c->send_err : WR_E_BUDGET;
		return WR_E_BUDGET;
	}
	memcpy(h->front, front, len);
	h->len = len;
	h->type = type, h->version = version, h->compat = compat;
	c->n_held++;
	return WR_OK;
}

uint32_t sim_mon_release(sim_mon_conn *c, uint32_t n)
{
	uint32_t done = 0;

	while (c->n_held != 0 && (n == 0 || done < n)) {
		sim_mon_held h = c->held[0];

		wr_status st = sim_mon_send_message(c, h.type, h.version, h.compat, h.front, h.len);

		free(h.front);
		memmove(&c->held[0], &c->held[1], (c->n_held - 1u) * sizeof(c->held[0]));
		c->n_held--;
		if (st == WR_OK) /* send_err already has the reason of a failure */
			done++;
	}
	return done;
}

/* An abrupt end: the bytes queued for the client are never delivered and it reads EOF. */
void sim_mon_cut(sim_mon_conn *c)
{
	sim_m2 *s = c->m2;

	if (c->killed)
		return;
	c->killed = 1;
	conn_drop_held(c);
	s->cfg.f.out_limit = (int64_t)s->delivered;
	s->cfg.f.out_limit_close = 1;
	sim_m2_close(s);
}

/* ---- message handling ------------------------------------------------------------------------------ */

static void on_subscribe(sim_mon_conn *c, const uint8_t *p, uint32_t n)
{
	wri_rd r;
	uint32_t cnt, i, hl;
	sim_mon_sub items[SIM_MON_SUBS];
	const uint8_t *host;

	wri_rd_init(&r, p, n);
	cnt = wri_rd_count(&r, SIM_MON_SUBS, 4u + 9u);
	memset(items, 0, sizeof(items));
	for (i = 0; i < cnt && wri_rd_ok(&r); i++) {
		uint32_t nl = wri_rd_u32(&r), k, keep;
		const uint8_t *nm = wri_rd_bytes(&r, nl);

		if (nm == NULL)
			break;
		/* any name is legal on the wire (a monitor ignores the ones it does not serve): keep a cut copy, and
		 * never let an embedded NUL or the cut make it equal to "monmap" / "osdmap" */
		keep = nl < sizeof(items[i].name) - 1u ? nl : (uint32_t)sizeof(items[i].name) - 1u;
		for (k = 0; k < keep; k++)
			items[i].name[k] = nm[k] != 0 ? (char)nm[k] : '?';
		items[i].start = wri_rd_u64(&r);
		items[i].flags = wri_rd_u8(&r);
	}
	hl = wri_rd_u32(&r);
	host = wri_rd_bytes(&r, hl);
	if (!wri_rd_ok(&r) || wri_rd_left(&r) != 0 || host == NULL) {
		c->n_malformed++; /* a real monitor fails the decode and drops the message */
		return;
	}
	c->n_subscribe++;
	c->mon->n_subscribe++;
	memcpy(c->last_sub, items, sizeof(items));
	c->n_last_sub = cnt;
	memset(c->last_host, 0, sizeof(c->last_host));
	memcpy(c->last_host, host, hl < sizeof(c->last_host) ? hl : sizeof(c->last_host) - 1u);
	for (i = 0; i < cnt; i++) {
		if (strcmp(items[i].name, "monmap") == 0) {
			c->sub_monmap.active = 1;
			c->sub_monmap.start = items[i].start;
			c->sub_monmap.flags = items[i].flags;
			sim_mon_serve_monmap(c);
		} else if (strcmp(items[i].name, "osdmap") == 0) {
			c->sub_osdmap.active = 1;
			c->sub_osdmap.start = items[i].start;
			c->sub_osdmap.flags = items[i].flags;
			sim_mon_serve_osdmap(c);
		}
	}
}

void sim_mon_on_message(void *ctx, sim_m2 *s, const sim_m2_msg *msg)
{
	sim_mon_conn *c = (sim_mon_conn *)ctx;
	const uint8_t *front = msg->seg[0];
	uint32_t flen = msg->seg_len[0];

	(void)s;
	if (c->killed)
		return;
	c->n_msgs++;
	switch (msg->type) {
	case SIM_MSG_MON_GET_MAP:
		c->n_getmap++;
		c->mon->n_getmap++;
		if (!c->plan.silent)
			sim_mon_send_monmap(c);
		break;
	case SIM_MSG_MON_SUBSCRIBE:
		on_subscribe(c, front != NULL ? front : (const uint8_t *)"", flen);
		break;
	case SIM_MSG_AUTH:
		c->n_auth_msgs++;
		if (!c->plan.silent)
			sim_mon_on_mauth(c, front != NULL ? front : (const uint8_t *)"", flen);
		break;
	default:
		c->n_other++;
		break;
	}
	if (c->plan.close_after_msgs != 0 && c->n_msgs >= c->plan.close_after_msgs)
		sim_mon_cut(c);
}

/* ---- hooks ------------------------------------------------------------------------------------------ */

void sim_mon_restart(sim_mon *m)
{
	uint32_t i;

	for (i = 0; i < SIM_MON_MAX_CONNS; i++)
		if (m->conns[i] != NULL)
			sim_mon_cut(m->conns[i]);
	m->n_restarts++;
	if (!m->cfg.restart_keeps_epoch)
		(void)sim_mon_bump_monmap(m);
}

void sim_mon_expire_tickets(sim_mon *m) { m->gen++; }
