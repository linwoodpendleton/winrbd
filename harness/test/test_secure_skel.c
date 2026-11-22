/* SPDX-License-Identifier: MIT */
/*
 * test_secure_skel.c - the skeleton of part D (secure mode, docs/design/core-architecture.md sections 32 to 41) keeps its promises.
 *
 * The modules of section 38 replace stubs and add code behind frozen headers; this test pins what the skeleton itself guarantees
 * until then (and what must stay true afterwards unless a module's task says otherwise):
 *   - the new status codes exist with their documented numbers, names and texts;
 *   - the constants of the secure framing have the values of docs/spec/msgr2-secure-mode.md, and the transmit / receive state that every
 *     module shares has bounded size (the memory plan of section 36 is made of these);
 *   - wr_config kept its size (the new fields come out of the reserved words), the profiles still offer crc only, and
 *     wr_config_enable_secure() fills exactly the documented fields (the engine's acceptance of the policies is client.sec.*);
 *   - the host GCM hook members sit behind `size` and the portable path is chosen when they are absent;
 *   - a fresh parser and queue are crc (the codec seam pointers are NULL).
 * The stub assertions of the modules that replaced stubs are gone (aesct, ghash, gcm, m2-sec-core, m2-sec-tx, m2-sec-rx: their own tests are crypto.*,
 * m2.sec.nonce / init / len / switch, m2.sec.tx.frames / stream / diff, m2.sec_rx_frames / bad / budget); m2-conn-sec and client-glue-sec are in
 * as well (their tests are m2.conn.sec.* and client.sec.*), so nothing here depends on a stub any more.
 */
#include <stddef.h>

#include "wrt.h"
#include "winrbd.h"
#include "wri_aesct.h"
#include "wri_gcm.h"
#include "wri_ghash.h"
#include "wri_m2_conn.h"
#include "wri_m2_modes.h"
#include "wri_m2_sec.h"
#include "wri_pgcm.h"

static void test_status_codes(void)
{
	WRT_CHECK_U64(-WR_E_M2_SECRET, 60);
	WRT_CHECK_U64(-WR_E_M2_NONCE, 61);
	WRT_CHECK_U64(-WR_E_M2_SEC_TAG, 62);
	WRT_CHECK(strcmp(wr_status_name(WR_E_M2_SEC_TAG), "WR_E_M2_SEC_TAG") == 0);
	WRT_CHECK(strcmp(wr_strerror(WR_E_M2_SECRET), "connection secret missing, too short or unusable") == 0);
	WRT_CHECK(strlen(wr_strerror(WR_E_M2_NONCE)) > 16u);
	/* the neighbours did not move */
	WRT_CHECK_U64(-WR_E_M2_HANDSHAKE_TIMEOUT, 59);
	WRT_CHECK_U64(-WR_E_AUTH_DENIED, 80);
}

static void test_constants(void)
{
	/* msgr2-secure-mode.md 2.6, 2.8: 16 key + 2 x 12 nonce seeds = 40, the servers send 64; preamble 32 + inline 48 = 80, + tag = 96 */
	WRT_CHECK(WRI_M2S_SECRET_MIN == 40u && WRI_M2S_KEY_LEN + 2u * WRI_M2S_NONCE_LEN == WRI_M2S_SECRET_MIN);
	WRT_CHECK(WRI_M2S_SECRET_MAX >= 64u);
	WRT_CHECK(WRI_M2S_P1_PLAIN == WRI_M2_PREAMBLE_LEN + WRI_M2S_INLINE && WRI_M2S_P1_WIRE == WRI_M2S_P1_PLAIN + WRI_M2S_TAG_LEN);
	WRT_CHECK(WRI_M2S_EPI_LEN == WRI_M2S_BLOCK && WRI_M2S_BLOCK == 16u && WRI_M2S_TAG_LEN == 16u && WRI_M2S_NONCE_LEN == 12u);
	WRT_CHECK(WRI_GCM_IV_LEN == WRI_M2S_NONCE_LEN && WRI_GCM_TAG_LEN == WRI_M2S_TAG_LEN);
	WRT_CHECK(WRI_M2S_OPS_LIMIT_DEFAULT == ((uint64_t)1 << 40));
	WRT_CHECK(WRI_M2_OFFER_CRC == 1u && WRI_M2_OFFER_SECURE == 2u);
	WRT_CHECK(WRI_CONN_MODE_CRC == 1u && WRI_CONN_MODE_SECURE == 2u);
}

static void test_layouts(void)
{
	printf("sizeof: wri_aesct_ctx %zu, wri_ghash %zu, wri_gcm %zu, wri_pgcm %zu, wri_m2s %zu, wri_m2s_rx %zu, wri_m2s_tx %zu, wri_m2s_slot %zu\n",
	       sizeof(wri_aesct_ctx), sizeof(wri_ghash), sizeof(wri_gcm), sizeof(wri_pgcm), sizeof(wri_m2s), sizeof(wri_m2s_rx),
	       sizeof(wri_m2s_tx), sizeof(wri_m2s_slot));
	WRT_CHECK(sizeof(wri_aesct_ctx) <= 512u);
	WRT_CHECK(sizeof(wri_ghash) <= 64u);
	WRT_CHECK(sizeof(wri_gcm) <= 704u);
	WRT_CHECK(sizeof(wri_pgcm) <= 704u + 16u); /* the union: the larger of the portable object and WR_GCM_HOST_STATE_MAX */
	WRT_CHECK(sizeof(((wri_pgcm *)0)->u.host_state) == WR_GCM_HOST_STATE_MAX);
	/* one connection's secure state, without the bounce buffer: the memory plan of section 36 budgets 2 KiB for it */
	WRT_CHECK(sizeof(wri_m2s_slot) <= 2048u);
	WRT_CHECK(sizeof(wri_m2s_rx) <= 192u && sizeof(wri_m2s_tx) <= 160u);
	WRT_CHECK(wri_m2s_slot_bytes() == sizeof(wri_m2s_slot));
	/* the config kept its size: the new fields come out of the reserved words (ABI) */
	WRT_CHECK_U64(sizeof(wr_config), 164u);
	WRT_CHECK(offsetof(wr_config, mode_policy_osd) == offsetof(wr_config, mode_policy) + 2u);
	/* the host table grew behind `size`; an old host table (size = the part A end) still names no GCM member */
	WRT_CHECK(offsetof(wr_prim_ops, gcm_state_bytes) > offsetof(wr_prim_ops, aes_cbc_dec));
	/* a fresh connection and a fresh parser / queue are crc: the seam pointers are zero */
	{
		wri_m2_rx rx;
		wri_m2_txq q;
		uint8_t buf[64];

		wri_m2_rx_init(&rx, buf, sizeof(buf), 1024u);
		wri_m2_txq_init(&q, buf, sizeof(buf));
		WRT_CHECK(rx.sx == NULL && q.sx == NULL);
	}
}

static void test_enable_secure(void)
{
	static const wr_map_profile mp[3] = {WR_MAPS_IPXE, WR_MAPS_KERNEL, WR_MAPS_HARNESS};
	static const uint32_t want_chunk[3] = {4096u, 16384u, 65536u};
	int i;

	for (i = 0; i < 3; i++) {
		wr_config a, b;
		wr_mem_req mem;

		if (i == 0)
			wr_config_profile_ipxe(&a);
		else if (i == 1)
			wr_config_profile_kernel(&a);
		else
			wr_config_profile_harness(&a);
		WRT_CHECK(a.mode_policy == WR_MODE_CRC_ONLY && a.mode_policy_osd == 0u && a.sec_tx_chunk == 0u); /* crc only: no secure memory */
		b = a;
		wr_config_enable_secure(&b, mp[i], WR_MODE_STOCK);
		WRT_CHECK_U64(b.mode_policy, WR_MODE_STOCK);
		WRT_CHECK_U64(b.mode_policy_osd, 0);
		WRT_CHECK_U64(b.sec_tx_chunk, want_chunk[i]);
		WRT_CHECK(b.sec_tx_chunk % 16u == 0u && b.sec_tx_chunk >= 256u);
		/* the engine takes every policy (module client-glue-sec): the memory plan of a secure policy is client.sec.mem's business, here it only has to work */
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&b, &mem));
		b = a;
		b.mode_policy_osd = WR_MODE_SECURE_ONLY;
		WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&b, &mem)); /* a secure OSD policy needs sec_tx_chunk (the bounce buffer): 0 is refused, never a silent crc */
		/* a bad policy or profile is never a silent crc: it poisons the policy (0), touches nothing else, and the engine refuses the configuration */
		{
			static const struct {
				uint8_t policy;
				int profile_ok;
			} bad[] = {{0, 1}, {6, 1}, {255, 1}, {WR_MODE_SECURE_ONLY, 0}, {WR_MODE_STOCK, 0}};
			unsigned k;

			for (k = 0; k < sizeof(bad) / sizeof(bad[0]); k++) {
				wr_config c = a;

				c.mode_policy = WR_MODE_SECURE_ONLY; /* what the host had asked for before the failing call */
				wr_config_enable_secure(&c, bad[k].profile_ok ? mp[i] : (wr_map_profile)0, bad[k].policy);
				WRT_CHECK_U64(c.mode_policy, 0); /* no policy: not the crc-only default, not the earlier value */
				WRT_CHECK(c.mode_policy_osd == a.mode_policy_osd && c.sec_tx_chunk == a.sec_tx_chunk);
				WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&c, &mem));
				c.mode_policy = a.mode_policy;
				WRT_CHECK(memcmp(&a, &c, sizeof(a)) == 0); /* and that was the only field */
			}
		}
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&a, &mem));
	}
}

int main(void)
{
	test_status_codes();
	test_constants();
	test_layouts();
	test_enable_secure();
	return wrt_finish();
}
