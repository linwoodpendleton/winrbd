/* SPDX-License-Identifier: MIT */
/*
 * test_osd_skel.c - the skeleton of part C (OSD sessions, RBD open, image I/O) keeps its promises.
 *
 * The modules of docs/design/core-architecture.md section 29 replace stubs and add code behind frozen headers; this test pins what the
 * skeleton itself guarantees until then and afterwards:
 *   - the new status codes exist with their documented numbers, names and texts, and the new event kinds their numbers;
 *   - the constants of the wire (message types, op codes, flag words) have the values the spec notes give, and the layouts the modules share
 *     (the op record, the op slot, the backoff entry, the request table entry, wr_io_req.priv) have the documented sizes;
 *   - wr_config kept its size (the new fields come out of the reserved words), the profiles leave the OSD client off, and
 *     wr_config_enable_osd() fills exactly the documented fields with the documented budgets and keeps the engine's own limits satisfied;
 *   - the public image API: NULL arguments, and pointers that are no live client or image handle, are WR_E_INVAL (the glue module replaced the stubs; the contract is test_client_osd_api.c);
 *   - the sim-osd module: the configuration defaults, a configuration without a monitor or a store is refused, the store can be created.
 */
#include <stddef.h>

#include "wrt.h"
#include "winrbd.h"
#include "sim_osd.h"
#include "wri_client_osd.h"
#include "wri_osd_msg.h"
#include "wri_osd_req.h"
#include "wri_osd_sess.h"
#include "wri_rbd.h"
#include "wri_rbd_cls.h"
#include "wri_rbd_io.h"
#include "wri_rbd_open.h"

static void test_status_codes(void)
{
	WRT_CHECK_U64(-WR_E_OSD_PROTO, 200);
	WRT_CHECK_U64(-WR_E_OSD_VERSION, 201);
	WRT_CHECK_U64(-WR_E_OSD_REDIRECT, 202);
	WRT_CHECK_U64(-WR_E_OSD_PERM, 203);
	WRT_CHECK_U64(-WR_E_OSD_IO, 204);
	WRT_CHECK_U64(-WR_E_OSD_NOSPC, 205);
	WRT_CHECK_U64(-WR_E_OSD_BLOCKLISTED, 206);
	WRT_CHECK_U64(-WR_E_OSD_NOENT, 207);
	WRT_CHECK_U64(-WR_E_OSD_ERRNO, 208);
	WRT_CHECK_U64(-WR_E_OSD_MAP_STALE, 209);
	WRT_CHECK_U64(-WR_E_RBD_NOT_FOUND, 220);
	WRT_CHECK_U64(-WR_E_RBD_FEATURES, 222);
	WRT_CHECK_U64(-WR_E_RBD_PARENT, 224);
	WRT_CHECK_U64(-WR_E_RBD_SNAPC, 226);
	WRT_CHECK_U64(-WR_E_RBD_CLOSED, 232);
	WRT_CHECK(strcmp(wr_status_name(WR_E_OSD_BLOCKLISTED), "WR_E_OSD_BLOCKLISTED") == 0);
	WRT_CHECK(strcmp(wr_status_name(WR_E_RBD_STRIPING), "WR_E_RBD_STRIPING") == 0);
	WRT_CHECK(strcmp(wr_strerror(WR_E_RBD_READONLY), "image was opened read-only") == 0);
	WRT_CHECK(strlen(wr_strerror(WR_E_OSD_MAP_STALE)) > 8u);
	/* the ranges of wr_err.h: nothing of this part below 200 or above 239 */
	WRT_CHECK(WR_E_OSD_PROTO <= -200 && WR_E_RBD_CLOSED >= -239);
	/* the module ids exist since part A */
	WRT_CHECK(WR_MOD_OSD == 9 && WR_MOD_RBD == 10);
	WRT_CHECK(WR_EV_IMAGE == 10 && WR_EV_IO_STALL == 11 && WR_EV_IO_RESUME == 12);
}

static void test_wire_constants(void)
{
	WRT_CHECK(WRI_MSG_OSD_OP == 42u && WRI_MSG_OSD_OPREPLY == 43u && WRI_MSG_OSD_BACKOFF == 61u && WRI_MSG_OSD_MAP == 41u);
	WRT_CHECK(WRI_MOSDOP_VERSION == 9u && WRI_MOSDOP_COMPAT == 3u && WRI_MOSDOPREPLY_VERSION == 8u);
	/* op code = mode | type | number (osd-ops.md 2.6) */
	WRT_CHECK(WRI_OSD_OP_READ == (0x1000u | 0x0200u | 1u));
	WRT_CHECK(WRI_OSD_OP_WRITE == (0x2000u | 0x0200u | 1u));
	WRT_CHECK(WRI_OSD_OP_CALL == (0x1000u | 0x0400u | 1u));
	WRT_CHECK(WRI_OSD_OP_SPARSE_READ == 0x1205u && WRI_OSD_OP_ZERO == 0x2204u && WRI_OSD_OP_DELETE == 0x2205u);
	/* the flag words of plain RBD data I/O (osd-ops.md 2.4) */
	WRT_CHECK_U64(WRI_OSDF_BASE_READ, 0x08400014u);
	WRT_CHECK_U64(WRI_OSDF_BASE_WRITE, 0x08400024u);
	WRT_CHECK_U64(WRI_SNAP_NOSNAP, 0xfffffffffffffffeull);
	WRT_CHECK(WR_SNAP_HEAD == WRI_SNAP_NOSNAP);
	WRT_CHECK(WRI_OSD_OPREC_LEN == 38u);
	/* rbd feature bits (rbd-format2.md 2.8) */
	WRT_CHECK(WRI_RBD_F_LAYERING == 0x1u && WRI_RBD_F_DATA_POOL == 0x80u && WRI_RBD_F_DIRTY_CACHE == 0x800u && WRI_RBD_F_ALL == 0xfffu);
	/* every open read of the header fits one message */
	WRT_CHECK(WRI_OSD_OPS_MAX >= 8u);
	/* an RBD object name: prefix + '.' + 16 hex digits must fit the 95 byte limit with a 95 byte prefix */
	WRT_CHECK(WRI_RBD_OBJNAME_MAX == 96u && WRI_OSD_OID_MAX >= WRI_RBD_OBJNAME_MAX);
	WRT_CHECK(WRI_RBD_NAME_MAX + 7u <= 95u);
}

static void test_layouts(void)
{
	printf("sizeof: wri_osd_opd %zu, wri_osd_op %zu, wri_backoff %zu, wri_osd_sess %zu, wri_rbd_img %zu, wri_rbd_rq %zu, wr_io_req %zu\n",
	       sizeof(wri_osd_opd), sizeof(wri_osd_op), sizeof(wri_backoff), sizeof(wri_osd_sess), sizeof(wri_rbd_img), sizeof(wri_rbd_rq),
	       sizeof(wr_io_req));
	WRT_CHECK(sizeof(wri_osd_opd) % 8u == 0u);
	WRT_CHECK(sizeof(wri_osd_op) <= 576u);        /* the op table is max_ops of these (design 26.2) */
	WRT_CHECK(sizeof(wri_backoff) <= 256u);
	WRT_CHECK(sizeof(wri_rbd_rq) <= 96u);
	WRT_CHECK(sizeof(((wr_io_req *)0)->priv) == 64u);
	WRT_CHECK(sizeof(wri_rbd_rqpriv) <= sizeof(((wr_io_req *)0)->priv));
	WRT_CHECK(WRI_RBD_CTL_IN >= 8u * 64u); /* eight calls with their names and arguments */
	/* the config kept its size: the OSD fields come out of the reserved words (ABI) */
	WRT_CHECK_U64(sizeof(wr_config), 164u);
	WRT_CHECK(offsetof(wr_config, osd_sessions) == offsetof(wr_config, crush_work_max) + sizeof(uint32_t));
	WRT_CHECK(sizeof(wr_image_info) % 8u == 0u);
}

static void profile(wr_config *c, int which, wr_map_profile mp)
{
	if (which == 0)
		wr_config_profile_ipxe(c);
	else if (which == 1)
		wr_config_profile_kernel(c);
	else
		wr_config_profile_harness(c);
	wr_config_enable_maps(c, mp);
}

static void test_enable_osd(void)
{
	static const wr_map_profile mp[3] = {WR_MAPS_IPXE, WR_MAPS_KERNEL, WR_MAPS_HARNESS};
	static const unsigned want_sessions[3] = {6, 16, 48};
	int i;

	for (i = 0; i < 3; i++) {
		wr_config a, b, c;
		wr_mem_req mem;

		profile(&a, i, mp[i]);
		WRT_CHECK(a.osd_sessions == 0u && a.max_ops == 0u && a.osd_flags == 0u); /* the profiles leave the OSD client off */
		b = a;
		wr_config_enable_osd(&b, mp[i]);
		WRT_CHECK_U64(b.osd_sessions, want_sessions[i]);
		WRT_CHECK_U64(b.max_conns, want_sessions[i] + 2u);
		WRT_CHECK(b.max_handshakes >= a.max_handshakes && b.max_handshakes <= b.max_conns);
		WRT_CHECK(b.max_ops > b.ctl_ops && b.ctl_ops >= 2u);
		WRT_CHECK(b.max_images >= 1u && b.max_reqs >= 1u && b.op_timeout_ms >= 1000u && b.osd_front_cap >= 1024u);
		WRT_CHECK(b.op_bytes_max >= 64u * 1024u && b.inflight_bytes_max >= b.op_bytes_max);
		WRT_CHECK(b.osd_connect_timeout_ms > 0u && b.osd_connect_timeout_ms <= b.connect_timeout_ms);
		WRT_CHECK((b.osd_flags & WR_OSDF_FULL_TRY) != 0u && (b.osd_flags & WR_OSDF_HONOR_PAUSE) != 0u);
		WRT_CHECK((b.osd_flags & WR_OSDF_ORDERSNAP) == 0u); /* off until the lab confirms EOLDSNAPC (R-C8) */
		WRT_CHECK(WRI_OSDF_ORDERSNAP == 0x40u && b.map_stale_ms == 30000u);
		/* the data segment of one connection (4 x mon_msg_cap, architecture 5.2) holds the biggest operation */
		WRT_CHECK((uint64_t)b.op_bytes_max <= (uint64_t)b.mon_msg_cap * 4u);
		/* the engine's own limits are satisfied (it ignores the OSD fields until the glue module) */
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&b, &mem));
		/* only the documented fields changed */
		c = b;
		c.max_conns = a.max_conns;
		c.max_handshakes = a.max_handshakes;
		c.osd_sessions = a.osd_sessions;
		c.max_ops = a.max_ops;
		c.ctl_ops = a.ctl_ops;
		c.max_images = a.max_images;
		c.max_reqs = a.max_reqs;
		c.max_snaps = a.max_snaps;
		c.backoff_slots = a.backoff_slots;
		c.osd_front_cap = a.osd_front_cap;
		c.op_bytes_max = a.op_bytes_max;
		c.inflight_bytes_max = a.inflight_bytes_max;
		c.zombie_bytes = a.zombie_bytes;
		c.op_timeout_ms = a.op_timeout_ms;
		c.osd_connect_timeout_ms = a.osd_connect_timeout_ms;
		c.hdr_refresh_ms = a.hdr_refresh_ms;
		c.img_ctl_bytes = a.img_ctl_bytes;
		c.map_stale_ms = a.map_stale_ms;
		c.osd_idle_ms = a.osd_idle_ms;
		c.osd_flags = a.osd_flags;
		WRT_CHECK(memcmp(&c, &a, sizeof(a)) == 0);
	}
	{
		wr_config a, b;

		profile(&a, 1, WR_MAPS_KERNEL);
		b = a;
		wr_config_enable_osd(&b, (wr_map_profile)0); /* not a profile: unchanged */
		WRT_CHECK(memcmp(&a, &b, sizeof(a)) == 0);
		wr_config_enable_osd(&b, (wr_map_profile)99);
		WRT_CHECK(memcmp(&a, &b, sizeof(a)) == 0);
	}
}

/* The public image API has no stubs any more (module client-glue-osd): a pointer that is no live client and no live image handle is WR_E_INVAL everywhere
 * (the full contract is test_client_osd_api.c). The structures below are stand-ins that never match the magic of a client or of a handle. */
static void test_public_stubs(void)
{
	wr_image_params p;
	wr_image *img = (wr_image *)(void *)&p; /* read, never matched: it is no handle */
	wr_image_info info;
	wr_io_req req;
	wr_osd_stats st;
	wr_client *c = (wr_client *)(void *)&p;
	wr_image *out = img;

	memset(&p, 0, sizeof(p));
	memset(&req, 0, sizeof(req));
	p.size = (uint32_t)sizeof(p);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_open(NULL, &p, &out));
	WRT_CHECK(out == NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_open(c, NULL, &out));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_open(c, &p, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_open(c, &p, &out)); /* not a live client */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_get_info(NULL, &info));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_get_info(img, &info)); /* not a live image */
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_FREE);
	WRT_CHECK(wr_image_error(img) != NULL && wr_image_error(img)->status == WR_OK);
	WRT_CHECK(wr_image_error(NULL) != NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_submit(NULL, &req));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_submit(img, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_submit(img, &req));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_cancel(img, &req));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_close(NULL, WR_CLOSE_DRAIN));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_close(img, WR_CLOSE_ABANDON));
	WRT_CHECK(wr_client_next_done(c) == NULL);
	WRT_CHECK(wr_client_image_at(c, 0) == NULL);
	memset(&st, 0xa5, sizeof(st));
	wr_client_osd_stats(c, &st);
	WRT_CHECK(st.ops_inflight == 0u && st.ops_done == 0u && st.zombie_bytes_max == 0u);
}

static void test_sim_osd(void)
{
	sim_osd_cfg cfg;
	sim_store *st;

	sim_osd_cfg_default(&cfg);
	WRT_CHECK(cfg.m2.entity_type == SIM_M2_ENT_OSD);
	WRT_CHECK(cfg.max_write_bytes == 90u * 1024u * 1024u);
	WRT_CHECK(cfg.max_object_bytes == 128u * 1024u * 1024u);
	WRT_CHECK(sim_osd_new(&cfg) == NULL); /* no monitor and no store: a configuration that cannot work */
	WRT_CHECK(sim_osd_new(NULL) == NULL);
	st = sim_store_new();
	WRT_CHECK(st != NULL);
	if (st != NULL) {
		WRT_CHECK(sim_store_n_objects(st) == 0u);
		cfg.store = st;
		WRT_CHECK(sim_osd_new(&cfg) == NULL); /* still no monitor */
		sim_store_free(st);
	}
}

int main(void)
{
	test_status_codes();
	test_wire_constants();
	test_layouts();
	test_enable_osd();
	test_public_stubs();
	test_sim_osd();
	return wrt_finish();
}
