/* SPDX-License-Identifier: MIT */
/*
 * Smoke test of the skeleton: public headers, status table, config profiles, and the entry-point
 * contract. Replaced in spirit by the per-module tests of the implementation waves; kept as the
 * canary that the build, the header set and the ABI constants still fit together.
 */
#include "wrt.h"
#include "winrbd.h"

static void test_status_table(void)
{
	WRT_CHECK(strcmp(wr_strerror(WR_OK), "success") == 0);
	WRT_CHECK(strcmp(wr_status_name(WR_E_M2_FRAME_CRC), "WR_E_M2_FRAME_CRC") == 0);
	WRT_CHECK(strcmp(wr_strerror(WR_E_TRUNCATED), "input ended before the structure was complete") == 0);
	WRT_CHECK(strcmp(wr_status_name(-9999), "WR_E_UNKNOWN") == 0);
	WRT_CHECK(strcmp(wr_strerror(-9999), "unknown status") == 0);
	/* codes are negative and stable: spot-check the documented numbers */
	WRT_CHECK_U64(-WR_E_INVAL, 1);
	WRT_CHECK_U64(-WR_E_M2_BANNER, 40);
	WRT_CHECK_U64(-WR_E_AUTH_DENIED, 80);
	WRT_CHECK_U64(-WR_E_MON_MAP_VERSION, 100);
}

static void test_profiles(void)
{
	wr_config c;

	wr_config_profile_ipxe(&c);
	WRT_CHECK_U64(c.size, sizeof(wr_config));
	WRT_CHECK_U64(c.abi, WR_ABI_VERSION);
	WRT_CHECK(c.max_conns >= 2);
	WRT_CHECK(c.mapmsg_queue >= 1);
	WRT_CHECK(c.handshake_timeout_ms < 10000); /* the server drops unfinished handshakes at 10 s */
	wr_config_profile_kernel(&c);
	WRT_CHECK(c.mon_msg_cap >= 1024 * 1024);
	wr_config_profile_harness(&c);
	WRT_CHECK(c.max_handshakes >= 1);
}

static void test_entry_contract(void)
{
	wr_config cfg;
	wr_mem_req req;
	wr_client *c = (wr_client *)1;
	wr_mem_region none = {NULL, 0};
	wr_host_ops host;
	wr_cluster_spec spec;

	wr_config_profile_harness(&cfg);
	memset(&host, 0, sizeof(host));
	memset(&spec, 0, sizeof(spec));
	/* the engine is real now: the size query works, and a create with a host that does not fill in its ABI
	 * size (and no memory) is refused with a status and leaves no object behind */
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	WRT_CHECK(req.arena != 0 && req.bulk != 0);
	WRT_CHECK(wr_client_create(&cfg, &host, &spec, none, none, &c) != WR_OK);
	WRT_CHECK(c == NULL);
	WRT_CHECK(wr_client_last_error(NULL) != NULL);
}

int main(void)
{
	test_status_table();
	test_profiles();
	test_entry_contract();
	return wrt_finish();
}
