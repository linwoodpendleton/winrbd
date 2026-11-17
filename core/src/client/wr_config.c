/* SPDX-License-Identifier: MIT */
/*
 * Configuration profiles.
 *
 * The numbers follow the table of the architecture document (section 5.2) and were checked against the
 * real footprint of the engine (harness/test/test_client_mem.c prints and asserts it; test_client_pump.c
 * prints how full the sized buffers get in a real session):
 *
 *   profile  arena            bulk               budget asserted in test_client_mem
 *   ipxe     110656 B (108 KiB)  1054720 B (1030 KiB)  arena <= 128 KiB, bulk <= 1 MiB + 16 KiB
 *   kernel   474784 B (464 KiB)  8394752 B (8198 KiB)  arena <= 512 KiB, bulk <= 8 MiB + 32 KiB
 *   harness  2516848 B (2.4 MiB) 33562624 B (32 MiB)   not budgeted (generous, for tests and tools)
 *
 * (every client embeds the OSD map store's own state, about 2 KiB of the arena, inert while the map module is off.) With the
 * map module on (wr_config_enable_maps() below; two map slots in the bulk, the placement cache in the arena):
 *
 *   ipxe     115520 B (113 KiB)  1579008 B (1542 KiB)   arena <= 128 KiB, bulk <= 1.5 MiB + 64 KiB
 *   kernel   513696 B (502 KiB)  10491904 B (10246 KiB) arena <= 512 KiB, bulk <= 10 MiB + 64 KiB
 *   harness  3139440 B (3.0 MiB) 41951232 B (40 MiB)    not budgeted
 *
 * (the bulk is mapmsg_queue slots of mon_msg_cap plus two renewal buffers of ticket_cap + 2 KiB.)
 * What a monitor session really uses of the per-connection buffers (cephx type 2, 151-byte test tickets):
 * transcripts 840 B received / 249 B sent (the largest control segment, AUTH_DONE, is therefore under 700 B),
 * encode buffer 213 B. The profile values keep the headroom a real cluster needs (AUTH_DONE carries two tickets of up to ticket_cap,
 * an OSD authorizer is about 1.3 KiB and the encode buffer must hold two of them, see wri_m2_conn.h), so
 * none of them was lowered; the connection and handshake counts are what the ipxe heap budget is made of.
 */
#include "wr_config.h"

WR_FILE_LICENCE_MIT

static void wri_config_common(wr_config *cfg)
{
	WR_MEMSET(cfg, 0, sizeof(*cfg));
	cfg->size = (uint32_t)sizeof(*cfg);
	cfg->abi = WR_ABI_VERSION;
	cfg->mode_policy = WR_MODE_CRC_ONLY;
	cfg->connect_timeout_ms = 5000;
	cfg->handshake_timeout_ms = 8000; /* the server drops at 10 s */
	cfg->keepalive_ms = 10000;
	cfg->keepalive_timeout_ms = 30000;
	cfg->hunt_backoff_min_ms = 500;
	cfg->hunt_backoff_max_ms = 15000;
}

void wr_config_profile_ipxe(wr_config *cfg)
{
	wri_config_common(cfg);
	cfg->max_conns = 4;
	cfg->max_handshakes = 1;
	cfg->rx_buf_bytes = 4096;
	cfg->ctl_buf_bytes = 8192;
	cfg->tx_buf_bytes = 8192;
	cfg->preauth_cap = 8192;
	cfg->ticket_cap = 1024;
	cfg->mon_msg_cap = 1024 * 1024;
	cfg->mapmsg_queue = 1;
}

void wr_config_profile_kernel(wr_config *cfg)
{
	wri_config_common(cfg);
	cfg->max_conns = 8;
	cfg->max_handshakes = 2;
	cfg->rx_buf_bytes = 16384;
	cfg->ctl_buf_bytes = 16384;
	cfg->tx_buf_bytes = 16384;
	cfg->preauth_cap = 16384;
	cfg->ticket_cap = 1024;
	cfg->mon_msg_cap = 4 * 1024 * 1024;
	cfg->mapmsg_queue = 2;
}

void wr_config_profile_harness(wr_config *cfg)
{
	wri_config_common(cfg);
	cfg->max_conns = 16;
	cfg->max_handshakes = 4;
	cfg->rx_buf_bytes = 65536;
	cfg->ctl_buf_bytes = 16384;
	cfg->tx_buf_bytes = 65536;
	cfg->preauth_cap = 16384;
	cfg->ticket_cap = 2048;
	cfg->mon_msg_cap = 16 * 1024 * 1024;
	cfg->mapmsg_queue = 2;
}

/*
 * OSD map module (docs/design/core-architecture.md 15.3). Opt-in: the three profiles above leave map_slot_bytes at 0, so
 * an engine built from a plain profile keeps delivering raw map messages exactly as in milestones 1 to 3 (hosts such as
 * wr-monprobe and the older tests rely on it). Opting in costs bulk memory (two slots) and a little arena (the placement
 * cache), see the table in section 15.3; the rest of the config is untouched, so call this after wr_config_profile_*().
 */
void wr_config_enable_maps(wr_config *cfg, wr_map_profile p)
{
	switch (p) {
	case WR_MAPS_IPXE:
		cfg->map_slot_bytes = 256u * 1024u;
		cfg->map_max_osd = 2048;
		cfg->map_pools = 2;
		cfg->map_pg_cache = 32;
		cfg->crush_work_max = 200000u;
		cfg->map_verify_crc = 0;
		break;
	case WR_MAPS_KERNEL:
		cfg->map_slot_bytes = 1024u * 1024u;
		cfg->map_max_osd = 8192;
		cfg->map_pools = 4;
		cfg->map_pg_cache = 256;
		cfg->crush_work_max = 1000000u;
		cfg->map_verify_crc = 1;
		break;
	case WR_MAPS_HARNESS:
		cfg->map_slot_bytes = 4u * 1024u * 1024u;
		cfg->map_max_osd = 32768;
		cfg->map_pools = 8;
		cfg->map_pg_cache = 4096;
		cfg->crush_work_max = 4000000u;
		cfg->map_verify_crc = 1;
		break;
	default:
		return; /* not a profile: leave the configuration exactly as it was (maps stay as they were, off after a plain profile) */
	}
	cfg->map_refetch_ms = 1000;
}
