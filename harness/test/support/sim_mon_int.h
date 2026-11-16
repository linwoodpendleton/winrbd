/* SPDX-License-Identifier: MIT */
/*
 * sim_mon_int.h - internals shared by the files of the fake monitor (sim_mon.c: lifecycle, dispatch,
 * sending; sim_mon_auth.c: the cephx server side and renewal; sim_mon_maps.c: the monmap / osdmap store
 * and the subscriptions). Not for tests.
 */
#ifndef SIM_MON_INT_H
#define SIM_MON_INT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sim_mon.h"
#include "wri_cursor.h"
#include "wri_ctx.h"
#include "wri_cx.h"
#include "wri_denc.h"
#include "wri_le.h"
#include "wri_m2_ctl.h"
#include "wri_misc.h"

#define SIM_MON_PAYLOAD 65536u /* per connection: the auth payload / MAuthReply result_bl being built */
#define SIM_MON_PRIO 196u      /* CEPH_MSG_PRIO_HIGH, what a monitor sends */

#define SIM_MSG_MON_MAP 4u
#define SIM_MSG_MON_GET_MAP 5u
#define SIM_MSG_MON_SUBSCRIBE 15u
#define SIM_MSG_AUTH 17u
#define SIM_MSG_AUTH_REPLY 18u
#define SIM_MSG_OSD_MAP 41u

#define SIM_SUB_ONETIME 1u

/* generator and cipher context */
uint64_t sim_mon_rand64(sim_mon *m);
void sim_mon_rand(sim_mon *m, uint8_t *out, size_t n);
const wri_ctx *sim_mon_ctx(const sim_mon *m);
/* a scratch buffer of at least n bytes (contents undefined, valid until the next call) */
uint8_t *sim_mon_scratch(sim_mon *m, size_t n);

/* sending: map messages honour the connection plan's hold_maps; everything else goes out at once */
wr_status sim_mon_send_map_msg(sim_mon_conn *c, uint16_t type, uint16_t version, uint16_t compat,
			       const uint8_t *front, uint32_t len);
void sim_mon_cut(sim_mon_conn *c); /* abrupt close: queued bytes are never delivered */
void sim_mon_on_message(void *ctx, sim_m2 *s, const sim_m2_msg *msg); /* sim_m2 on_message hook */

/* cephx (sim_mon_auth.c) */
int sim_mon_auth_request(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p,
			 uint32_t n, sim_m2_auth_reply *rep);
int sim_mon_auth_more(void *ctx, const uint8_t *p, uint32_t n, sim_m2_auth_reply *rep);
void sim_mon_on_mauth(sim_mon_conn *c, const uint8_t *front, uint32_t n);

/* maps (sim_mon_maps.c) */
wr_status sim_mon_maps_init(sim_mon *m);
void sim_mon_maps_free(sim_mon *m);
void sim_mon_send_monmap(sim_mon_conn *c);
void sim_mon_serve_monmap(sim_mon_conn *c);
void sim_mon_serve_osdmap(sim_mon_conn *c);

#endif /* SIM_MON_INT_H */
