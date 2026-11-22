/* SPDX-License-Identifier: MIT */
/*
 * m2_conn_sec_cx.h - the "real cephx" world of the m2-conn-sec tests (test_m2_conn_sec_*.c, fuzz_m2_conn_sec.c). Harness code, libc allowed,
 * never part of the core, static inline so each test carries its own copy.
 *
 * What it adds to the rig of m2_conn_rig.h: instead of the stub auth and the scripted sim_m2 server, a connection of the rig talks to the
 * fake monitor (sim_mon) or the fake OSD (sim_osd) of the harness and authenticates with the product's own cephx machine (wri_cx_client for
 * the monitor, wri_cx_hs for an OSD, the two wri_auth_ops tables of wri_cx.h). Both simulators carry the secure peer of sim_m2_sec.h, so
 * the connection secret really travels the two ways of cephx.md 2.7 (the monitor's `cbl`, the OSD's authorizer reply of version 2) and
 * really is the key of the frames that follow: a client that took the wrong 64 bytes, or the right ones in the wrong place, could not read
 * the server's signature.
 *
 *   cxw_init(&w, key_type)   defaults for the monitor (w.mcfg) and one OSD (w.ocfg), a client key of type 1 (AES) or 2 (AES256K); the
 *                            test changes the configuration (allowed modes, secure-mode fault hooks) next
 *   cxw_start(&w)            creates the monitor, the object store, the OSD and the cephx client
 *   cxw_mon_rig(&w, &r)      r = rig_init'ed by the caller: the rig's connection is a monitor connection (call rig_start after)
 *   cxw_osd_rig(&w, &r)      the same for an OSD connection (needs a monitor login first: the OSD ticket comes from it)
 *   cxw_free(&w)             after the rigs were freed
 */
#ifndef M2_CONN_SEC_CX_H
#define M2_CONN_SEC_CX_H

#include "auth_cx_srv.h"
#include "m2_conn_rig.h"
#include "sim_mon.h"
#include "sim_osd.h"
#include "wri_cx.h"

typedef struct cxw {
	cxt_env e;            /* the cephx client (principal key, tickets) and its context */
	sim_mon_cfg mcfg;
	sim_osd_cfg ocfg;
	sim_mon *mon;
	sim_store *store;
	sim_osd *osd;
	wri_cx_hs hs;         /* the handshake slot of the OSD connection */
	unsigned key_type;
	sim_mon_conn *mc;     /* the connections the rigs talk to (freed by cxw_free) */
	sim_osd_conn *oc[8];
	unsigned n_oc;
	int started;
} cxw;

#define CXW_MON_PORT 3300u
#define CXW_OSD_PORT 6801u
#define CXW_OSD_NONCE 0x4e4fu

/* 0 = ok. Nothing is created yet: the caller adjusts mcfg / ocfg (modes, hooks) and then starts the world. */
static WRT_UNUSED int cxw_init(cxw *w, unsigned key_type)
{
	wr_key pk = cxt_key(key_type, 5);

	memset(w, 0, sizeof(*w));
	w->key_type = key_type;
	cxt_rng_free();
	sim_mon_cfg_default(&w->mcfg);
	w->mcfg.key = pk;
	memset(w->mcfg.user, 0, sizeof(w->mcfg.user));
	strcpy(w->mcfg.user, "winrbd");
	w->mcfg.m2.server_port = (uint16_t)CXW_MON_PORT;
	w->mcfg.m2.check_target = 1;
	sim_osd_cfg_default(&w->ocfg);
	w->ocfg.id = 0;
	w->ocfg.seed = 11u;
	w->ocfg.m2.server_port = (uint16_t)CXW_OSD_PORT;
	w->ocfg.m2.server_nonce = CXW_OSD_NONCE;
	w->ocfg.m2.check_target = 1;
	return 0;
}

static WRT_UNUSED int cxw_start(cxw *w)
{
	wr_key pk = cxt_key(w->key_type, 5);

	w->mon = sim_mon_new(&w->mcfg);
	w->store = sim_store_new();
	if (w->mon == NULL || w->store == NULL)
		return -1;
	w->ocfg.mon = w->mon;
	w->ocfg.store = w->store;
	w->osd = sim_osd_new(&w->ocfg);
	if (w->osd == NULL)
		return -2;
	if (cxt_env_init(&w->e, "client.winrbd", &pk, 0) != 0)
		return -3;
	w->e.x.cfg.handshake_timeout_ms = 10000;
	w->started = 1;
	return 0;
}

static WRT_UNUSED void cxw_free(cxw *w)
{
	unsigned i;

	for (i = 0; i < w->n_oc; i++)
		sim_osd_conn_free(w->oc[i]);
	if (w->mc != NULL)
		sim_mon_conn_free(w->mc);
	if (w->started)
		cxt_env_free(&w->e);
	sim_osd_free(w->osd);
	sim_store_free(w->store);
	sim_mon_free(w->mon);
	memset(w, 0, sizeof(*w));
}

/* The rig's connection becomes a monitor connection of this world. */
static WRT_UNUSED void cxw_mon_rig(cxw *w, rig *r)
{
	if (w->mc != NULL) { /* one monitor connection at a time: the cephx client's embedded handshake serves one */
		sim_mon_conn_free(w->mc);
		w->mc = NULL;
	}
	w->mc = sim_mon_accept(w->mon);
	if (w->mc == NULL)
		abort();
	r->ext_s = w->mc->m2;
	r->role = WRI_ENTITY_MON;
	r->ops = wri_cx_ops();
	r->ops_ctx = &w->e.c;
	r->scfg.entity_type = SIM_M2_ENT_MON;
	rig_set_target(r, (uint16_t)CXW_MON_PORT);
}

/* The rig's connection becomes an OSD connection of this world (the handshake slot is bound to the client here). */
static WRT_UNUSED void cxw_osd_rig(cxw *w, rig *r)
{
	if (w->n_oc >= sizeof(w->oc) / sizeof(w->oc[0]))
		abort();
	w->oc[w->n_oc] = sim_osd_accept(w->osd);
	if (w->oc[w->n_oc] == NULL)
		abort();
	r->ext_s = sim_osd_conn_m2(w->oc[w->n_oc++]);
	if (wri_cx_hs_init(&w->hs, &w->e.c) != WR_OK)
		abort();
	r->role = WRI_ENTITY_OSD;
	r->ops = wri_cx_hs_ops();
	r->ops_ctx = &w->hs;
	r->scfg.entity_type = SIM_M2_ENT_OSD;
	rig_set_target_ip(r, 10, (uint16_t)CXW_OSD_PORT, CXW_OSD_NONCE);
}

#endif /* M2_CONN_SEC_CX_H */
