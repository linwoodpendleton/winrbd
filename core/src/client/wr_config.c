/* SPDX-License-Identifier: MIT */
/*
 * Configuration profiles.
 *
 * The numbers follow the table of the architecture document (section 5.2) and were checked against the
 * real footprint of the engine (harness/test/test_client_mem.c prints and asserts it; test_client_pump.c
 * prints how full the sized buffers get in a real session):
 *
 *   profile  arena            bulk               budget asserted in test_client_mem
 *   ipxe     108592 B (106 KiB)  1054720 B (1030 KiB)  arena <= 128 KiB, bulk <= 1 MiB + 16 KiB
 *   kernel   472720 B (462 KiB)  8394752 B (8198 KiB)  arena <= 512 KiB, bulk <= 8 MiB + 32 KiB
 *   harness  2514784 B (2.4 MiB) 33562624 B (32 MiB)   not budgeted (generous, for tests and tools)
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
