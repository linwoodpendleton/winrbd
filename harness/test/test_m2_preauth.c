/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of core/src/msgr2/wri_m2_preauth.c (the pre-auth transcripts and the two
 * AUTH_SIGNATURE values; msgr2.md 3.3, 3.4).
 *
 *  - msgr2/preauth-hmac.json: both signatures verify over transcripts fed in arbitrary chunk sizes,
 *    through the NULL-table reference and through an override table; the two must_not_verify values
 *    do not match, and the first of them is reproduced from the wrong transcript it was made from;
 *  - the two logs are independent; overflow is sticky (WR_E_M2_PREAUTH_TOOBIG), never partial;
 *  - stop() freezes without wiping, wipe() zeroes content and lengths;
 *  - no key material (NULL key or length 0) gives 32 zero bytes.
 */
#include "wrt.h"

#include "wri_hash.h"
#include "wri_m2_ctl.h"
#include "wri_m2_frame.h"
#include "wri_prim.h"

static uint8_t *xalloc(size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n ? n : 1);

	if (!q) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	return q;
}

static int is_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i])
			return 0;
	return 1;
}

struct vec {
	uint8_t *key, *rx, *tx, *csig, *ssig, *bad1, *bad2;
	size_t klen, rxn, txn;
};

static int load_vec(wrt_json *j, struct vec *v)
{
	wrt_tok root, bad;
	size_t n1 = 0, n2 = 0, ns = 0, nc = 0;

	memset(v, 0, sizeof(*v));
	if (wrt_json_load_vec(j, "msgr2/preauth-hmac.json") != 0)
		return -1;
	root = wrt_json_root(j);
	bad = wrt_json_get(j, root, "must_not_verify");
	if (wrt_json_get_hex(j, root, "session_key_secret_hex", &v->key, &v->klen) != 0 ||
	    wrt_json_get_hex(j, root, "bytes_received_by_client_hex", &v->rx, &v->rxn) != 0 ||
	    wrt_json_get_hex(j, root, "bytes_sent_by_client_hex", &v->tx, &v->txn) != 0 ||
	    wrt_json_get_hex(j, root, "client_signature_hex", &v->csig, &nc) != 0 ||
	    wrt_json_get_hex(j, root, "server_signature_hex", &v->ssig, &ns) != 0 ||
	    wrt_json_get_hex(j, bad, "client_signature_without_server_banner", &v->bad1, &n1) != 0 ||
	    wrt_json_get_hex(j, bad, "server_signature_including_the_clients_own_signature_frame", &v->bad2,
			     &n2) != 0)
		return -1;
	if (nc != 32 || ns != 32 || n1 != 32 || n2 != 32)
		return -1;
	return 0;
}

/* ---- a counting override table ------------------------------------------------------------ */

static unsigned hmac_calls;

static void fake_hmac(void *ctx, const uint8_t *key, size_t klen, const wr_iov *iov, size_t niov,
		      uint8_t out[32])
{
	(void)ctx;
	hmac_calls++;
	wri_hmac_sha256(key, klen, iov, niov, out);
}

static void test_vector(const struct vec *v)
{
	enum { CAP = 1024 };
	size_t chunks[] = {1, 3, 7, 26, 64, 4096};
	size_t c;

	for (c = 0; c < sizeof(chunks) / sizeof(chunks[0]); c++) {
		uint8_t *rxb = xalloc(CAP), *txb = xalloc(CAP);
		wri_m2_preauth p;
		uint8_t sig[32];

		wri_m2_preauth_init(&p, rxb, txb, CAP);
		WRT_CHECK(p.enabled == 1 && p.err == WR_OK && p.rx_len == 0 && p.tx_len == 0 && p.cap == CAP);
		/* interleave the two directions, as a real handshake does */
		{
			size_t a = 0, b = 0;

			while (a < v->rxn || b < v->txn) {
				size_t ka = v->rxn - a < chunks[c] ? v->rxn - a : chunks[c];
				size_t kb = v->txn - b < chunks[c] ? v->txn - b : chunks[c];

				wri_m2_preauth_rx(&p, v->rx + a, ka);
				wri_m2_preauth_tx(&p, v->tx + b, kb);
				a += ka;
				b += kb;
			}
		}
		WRT_CHECK(p.rx_len == v->rxn && p.tx_len == v->txn && p.err == WR_OK);
		WRT_CHECK_MEM(rxb, v->rx, v->rxn);
		WRT_CHECK_MEM(txb, v->tx, v->txn);
		wri_m2_preauth_stop(&p);
		wri_m2_sig_ours(NULL, &p, v->key, v->klen, sig);
		WRT_CHECK_MEM(sig, v->csig, 32);
		wri_m2_sig_expected(NULL, &p, v->key, v->klen, sig);
		WRT_CHECK_MEM(sig, v->ssig, 32);
		/* the "must not verify" values differ from what the right transcripts give */
		wri_m2_sig_ours(NULL, &p, v->key, v->klen, sig);
		WRT_CHECK(memcmp(sig, v->bad1, 32) != 0);
		wri_m2_sig_expected(NULL, &p, v->key, v->klen, sig);
		WRT_CHECK(memcmp(sig, v->bad2, 32) != 0);
		/* swapping the roles does not verify either */
		wri_m2_sig_ours(NULL, &p, v->key, v->klen, sig);
		WRT_CHECK(memcmp(sig, v->ssig, 32) != 0);
		wri_m2_sig_expected(NULL, &p, v->key, v->klen, sig);
		WRT_CHECK(memcmp(sig, v->csig, 32) != 0);
		free(rxb);
		free(txb);
	}
}

static void test_wrong_transcripts(const struct vec *v)
{
	uint8_t rxb[1024], txb[1024];
	wri_m2_preauth p;
	uint8_t sig[32];

	/* without the server banner (the first 26 bytes received): this is the documented wrong value */
	wri_m2_preauth_init(&p, rxb, txb, sizeof(rxb));
	wri_m2_preauth_rx(&p, v->rx + WRI_M2_BANNER_LEN, v->rxn - WRI_M2_BANNER_LEN);
	wri_m2_sig_ours(NULL, &p, v->key, v->klen, sig);
	WRT_CHECK_MEM(sig, v->bad1, 32);
	WRT_CHECK(memcmp(sig, v->csig, 32) != 0);
	/* one flipped bit anywhere changes the signature */
	{
		size_t i;

		for (i = 0; i < v->rxn; i += 17) {
			uint8_t sv[32];

			wri_m2_preauth_init(&p, rxb, txb, sizeof(rxb));
			wri_m2_preauth_rx(&p, v->rx, i);
			{
				uint8_t flipped = (uint8_t)(v->rx[i] ^ 0x01);

				wri_m2_preauth_rx(&p, &flipped, 1);
			}
			wri_m2_preauth_rx(&p, v->rx + i + 1, v->rxn - i - 1);
			wri_m2_sig_ours(NULL, &p, v->key, v->klen, sv);
			WRT_CHECK(memcmp(sv, v->csig, 32) != 0);
		}
	}
	/* a different key does not verify */
	wri_m2_preauth_init(&p, rxb, txb, sizeof(rxb));
	wri_m2_preauth_rx(&p, v->rx, v->rxn);
	{
		uint8_t k2[32];

		memcpy(k2, v->key, 32);
		k2[31] ^= 0x80;
		wri_m2_sig_ours(NULL, &p, k2, 32, sig);
		WRT_CHECK(memcmp(sig, v->csig, 32) != 0);
	}
}

static void test_independent(const struct vec *v)
{
	uint8_t rxb[1024], txb[1024];
	wri_m2_preauth p;
	uint8_t a[32], b[32], empty[32];

	/* everything into the receive log: the send log stays empty and signs to HMAC of nothing */
	wri_m2_preauth_init(&p, rxb, txb, sizeof(rxb));
	wri_m2_preauth_rx(&p, v->rx, v->rxn);
	WRT_CHECK(p.tx_len == 0 && p.rx_len == v->rxn);
	wri_m2_sig_ours(NULL, &p, v->key, v->klen, a);
	WRT_CHECK_MEM(a, v->csig, 32);
	wri_m2_sig_expected(NULL, &p, v->key, v->klen, b);
	wri_hmac_sha256(v->key, v->klen, NULL, 0, empty);
	WRT_CHECK_MEM(b, empty, 32);
	/* a tap function is usable where a wri_m2_log_fn is expected */
	{
		wri_m2_log_fn f1 = wri_m2_preauth_rx, f2 = wri_m2_preauth_tx;

		wri_m2_preauth_init(&p, rxb, txb, sizeof(rxb));
		f1(&p, v->rx, 5);
		f2(&p, v->tx, 9);
		WRT_CHECK(p.rx_len == 5 && p.tx_len == 9);
	}
}

static void test_prim_dispatch(const struct vec *v)
{
	uint8_t rxb[1024], txb[1024];
	wri_m2_preauth p;
	wr_prim_ops ops;
	uint8_t sig[32];

	memset(&ops, 0, sizeof(ops));
	ops.size = (uint32_t)sizeof(ops);
	ops.hmac_sha256 = fake_hmac;
	wri_m2_preauth_init(&p, rxb, txb, sizeof(rxb));
	wri_m2_preauth_rx(&p, v->rx, v->rxn);
	wri_m2_preauth_tx(&p, v->tx, v->txn);
	hmac_calls = 0;
	wri_m2_sig_ours(&ops, &p, v->key, v->klen, sig);
	WRT_CHECK_MEM(sig, v->csig, 32);
	WRT_CHECK(hmac_calls == 1);
	wri_m2_sig_expected(&ops, &p, v->key, v->klen, sig);
	WRT_CHECK_MEM(sig, v->ssig, 32);
	WRT_CHECK(hmac_calls == 2);
	/* no key: the override is not consulted at all */
	wri_m2_sig_ours(&ops, &p, NULL, 0, sig);
	WRT_CHECK(hmac_calls == 2);
}

static void test_zero_key(const struct vec *v)
{
	uint8_t rxb[1024], txb[1024];
	wri_m2_preauth p;
	uint8_t sig[32], zero[32];

	memset(zero, 0, sizeof(zero));
	wri_m2_preauth_init(&p, rxb, txb, sizeof(rxb));
	wri_m2_preauth_rx(&p, v->rx, v->rxn);
	wri_m2_preauth_tx(&p, v->tx, v->txn);
	memset(sig, 0xAA, sizeof(sig));
	wri_m2_sig_ours(NULL, &p, NULL, 0, sig);
	WRT_CHECK_MEM(sig, zero, 32);
	memset(sig, 0xAA, sizeof(sig));
	wri_m2_sig_expected(NULL, &p, NULL, 0, sig);
	WRT_CHECK_MEM(sig, zero, 32);
	memset(sig, 0xAA, sizeof(sig));
	wri_m2_sig_ours(NULL, &p, v->key, 0, sig); /* non-NULL key, length 0: still "no key" */
	WRT_CHECK_MEM(sig, zero, 32);
	memset(sig, 0xAA, sizeof(sig));
	wri_m2_sig_expected(NULL, &p, NULL, 32, sig); /* NULL key with a length: no key either */
	WRT_CHECK_MEM(sig, zero, 32);
	/* and with empty logs and a key it is the HMAC of nothing, not zeros */
	wri_m2_preauth_init(&p, rxb, txb, sizeof(rxb));
	wri_m2_sig_ours(NULL, &p, v->key, v->klen, sig);
	{
		uint8_t e[32];

		wri_hmac_sha256(v->key, v->klen, NULL, 0, e);
		WRT_CHECK_MEM(sig, e, 32);
		WRT_CHECK(!is_zero(sig, 32));
	}
}

static void test_overflow(void)
{
	uint8_t *rxb = xalloc(16), *txb = xalloc(16);
	wri_m2_preauth p;
	uint8_t data[40];
	size_t i;

	for (i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)(i + 1);
	/* exactly cap bytes fit, in pieces, in both logs */
	wri_m2_preauth_init(&p, rxb, txb, 16);
	wri_m2_preauth_rx(&p, data, 10);
	wri_m2_preauth_rx(&p, data + 10, 6);
	wri_m2_preauth_tx(&p, data, 16);
	WRT_CHECK(p.rx_len == 16 && p.tx_len == 16 && p.err == WR_OK);
	WRT_CHECK_MEM(rxb, data, 16);
	/* one more byte: sticky error, nothing appended, lengths unchanged */
	wri_m2_preauth_rx(&p, data, 1);
	WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, p.err);
	WRT_CHECK(p.rx_len == 16 && p.tx_len == 16);
	/* stop and wipe do not clear the error */
	wri_m2_preauth_stop(&p);
	WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, p.err);
	wri_m2_preauth_wipe(&p);
	WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, p.err);

	/* a single oversized append is refused as a whole: no partial copy */
	memset(rxb, 0xCC, 16);
	wri_m2_preauth_init(&p, rxb, txb, 16);
	wri_m2_preauth_rx(&p, data, 17);
	WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, p.err);
	WRT_CHECK(p.rx_len == 0);
	{
		uint8_t cc[16];

		memset(cc, 0xCC, sizeof(cc));
		WRT_CHECK_MEM(rxb, cc, 16);
	}
	/* after the error the other log stops too (the handshake is dead) */
	wri_m2_preauth_tx(&p, data, 4);
	WRT_CHECK(p.tx_len == 0);

	/* a failing tx append is the same */
	wri_m2_preauth_init(&p, rxb, txb, 16);
	wri_m2_preauth_tx(&p, data, 9);
	wri_m2_preauth_tx(&p, data, 8);
	WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, p.err);
	WRT_CHECK(p.tx_len == 9);

	/* zero-length appends are free, including with a NULL pointer */
	wri_m2_preauth_init(&p, rxb, txb, 16);
	wri_m2_preauth_rx(&p, NULL, 0);
	wri_m2_preauth_tx(&p, data, 0);
	WRT_CHECK(p.err == WR_OK && p.rx_len == 0 && p.tx_len == 0);
	/* NULL data with a length is a caller bug, recorded */
	wri_m2_preauth_rx(&p, NULL, 3);
	WRT_CHECK(p.err != WR_OK && p.rx_len == 0);

	/* capacity 0, or a missing buffer, refuses everything */
	wri_m2_preauth_init(&p, rxb, txb, 0);
	wri_m2_preauth_rx(&p, data, 1);
	WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, p.err);
	wri_m2_preauth_init(&p, NULL, txb, 16);
	WRT_CHECK(p.cap == 0);
	wri_m2_preauth_tx(&p, data, 1);
	WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, p.err);
	/* a log that is already full refuses the next byte (the room check cannot wrap) */
	wri_m2_preauth_init(&p, rxb, txb, 16);
	p.rx_len = 16;
	wri_m2_preauth_rx(&p, data, 1);
	WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, p.err);
	free(rxb);
	free(txb);
}

static void test_stop_wipe(const struct vec *v)
{
	uint8_t *rxb = xalloc(512), *txb = xalloc(512);
	wri_m2_preauth p;
	uint8_t before[32], after[32], extra[8], ref[32];

	memset(rxb, 0x11, 512);
	memset(txb, 0x22, 512);
	memset(extra, 0x99, sizeof(extra));
	wri_m2_preauth_init(&p, rxb, txb, 512);
	wri_m2_preauth_rx(&p, v->rx, v->rxn);
	wri_m2_preauth_tx(&p, v->tx, v->txn);
	/* stop: later bytes (our own AUTH_SIGNATURE frame, the server's) never enter a log */
	wri_m2_preauth_stop(&p);
	WRT_CHECK(p.enabled == 0);
	wri_m2_sig_ours(NULL, &p, v->key, v->klen, before);
	wri_m2_preauth_rx(&p, extra, sizeof(extra));
	wri_m2_preauth_tx(&p, extra, sizeof(extra));
	WRT_CHECK(p.rx_len == v->rxn && p.tx_len == v->txn && p.err == WR_OK);
	wri_m2_sig_ours(NULL, &p, v->key, v->klen, after);
	WRT_CHECK_MEM(before, after, 32);
	WRT_CHECK_MEM(before, v->csig, 32);
	WRT_CHECK_MEM(rxb, v->rx, v->rxn); /* kept, not wiped */
	WRT_CHECK_MEM(txb, v->tx, v->txn);
	/* wipe: the used bytes are zero, the rest untouched, lengths 0, still disabled */
	wri_m2_preauth_wipe(&p);
	WRT_CHECK(is_zero(rxb, v->rxn) && is_zero(txb, v->txn));
	WRT_CHECK(rxb[v->rxn] == 0x11 && txb[v->txn] == 0x22);
	WRT_CHECK(p.rx_len == 0 && p.tx_len == 0 && p.enabled == 0);
	wri_m2_preauth_rx(&p, extra, sizeof(extra));
	WRT_CHECK(p.rx_len == 0);
	/* after the wipe the logs are empty: signatures are over nothing */
	wri_m2_sig_ours(NULL, &p, v->key, v->klen, after);
	wri_hmac_sha256(v->key, v->klen, NULL, 0, ref);
	WRT_CHECK_MEM(after, ref, 32);
	/* init revives the object for the next handshake */
	wri_m2_preauth_init(&p, rxb, txb, 512);
	wri_m2_preauth_rx(&p, extra, sizeof(extra));
	WRT_CHECK(p.enabled == 1 && p.rx_len == sizeof(extra) && p.err == WR_OK);
	free(rxb);
	free(txb);
}

static void test_null_args(const struct vec *v)
{
	uint8_t sig[32];
	wri_m2_preauth p;
	uint8_t rxb[8], txb[8];

	wri_m2_preauth_init(NULL, rxb, txb, 8);
	wri_m2_preauth_rx(NULL, v->rx, 4);
	wri_m2_preauth_tx(NULL, v->rx, 4);
	wri_m2_preauth_stop(NULL);
	wri_m2_preauth_wipe(NULL);
	memset(sig, 0xAA, sizeof(sig));
	wri_m2_sig_ours(NULL, NULL, v->key, v->klen, sig);
	WRT_CHECK(is_zero(sig, 32));
	memset(sig, 0xAA, sizeof(sig));
	wri_m2_sig_expected(NULL, NULL, v->key, v->klen, sig);
	WRT_CHECK(is_zero(sig, 32));
	wri_m2_preauth_init(&p, rxb, txb, 8);
	wri_m2_sig_ours(NULL, &p, v->key, v->klen, NULL);
	wri_m2_sig_expected(NULL, &p, v->key, v->klen, NULL);
	wri_m2_preauth_wipe(&p); /* wipe of an untouched object */
	WRT_CHECK(p.rx_len == 0);
}

/* ---- wri_m2_sig_verify: the checked, constant-time comparison -------------------------------- */

static void test_verify(const struct vec *v)
{
	uint8_t rxb[1024], txb[1024];
	uint8_t bad[32], zero[32];
	wri_m2_preauth p;
	size_t i;

	memset(zero, 0, sizeof(zero));
	wri_m2_preauth_init(&p, rxb, txb, sizeof(rxb));
	wri_m2_preauth_rx(&p, v->rx, v->rxn);
	wri_m2_preauth_tx(&p, v->tx, v->txn);
	/* still logging: refused, so our own signature frame cannot slip into the transcript unnoticed */
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_sig_verify(NULL, &p, v->key, v->klen, v->ssig));
	wri_m2_preauth_stop(&p);
	WRT_CHECK_STATUS(WR_OK, wri_m2_sig_verify(NULL, &p, v->key, v->klen, v->ssig));
	/* our own signature is not the server's */
	WRT_CHECK_STATUS(WR_E_M2_SIGNATURE, wri_m2_sig_verify(NULL, &p, v->key, v->klen, v->csig));
	WRT_CHECK_STATUS(WR_E_M2_SIGNATURE, wri_m2_sig_verify(NULL, &p, v->key, v->klen, v->bad2));
	WRT_CHECK_STATUS(WR_E_M2_SIGNATURE, wri_m2_sig_verify(NULL, &p, v->key, v->klen, zero));
	/* every single-bit change of the right value is refused, every byte position */
	for (i = 0; i < 32; i++) {
		memcpy(bad, v->ssig, 32);
		bad[i] ^= (uint8_t)(1u << (i & 7u));
		WRT_CHECK_STATUS(WR_E_M2_SIGNATURE, wri_m2_sig_verify(NULL, &p, v->key, v->klen, bad));
	}
	/* a wrong key */
	{
		uint8_t k2[32];

		memcpy(k2, v->key, 32);
		k2[31] ^= 1;
		WRT_CHECK_STATUS(WR_E_M2_SIGNATURE, wri_m2_sig_verify(NULL, &p, k2, sizeof(k2), v->ssig));
	}
	/* the all-zero signature is only right for "no key" spelled (NULL, 0); a half-spelled key is a bug */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_sig_verify(NULL, &p, NULL, 32, zero));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_sig_verify(NULL, &p, v->key, 0, zero));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_sig_verify(NULL, NULL, v->key, v->klen, v->ssig));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_sig_verify(NULL, &p, v->key, v->klen, NULL));
	WRT_CHECK_STATUS(WR_OK, wri_m2_sig_verify(NULL, &p, NULL, 0, zero));
	WRT_CHECK_STATUS(WR_E_M2_SIGNATURE, wri_m2_sig_verify(NULL, &p, NULL, 0, v->ssig));
	/* an override table is used for the HMAC */
	hmac_calls = 0;
	{
		wr_prim_ops ops;

		memset(&ops, 0, sizeof(ops));
		ops.size = (uint32_t)sizeof(ops);
		ops.hmac_sha256 = fake_hmac;
		WRT_CHECK_STATUS(WR_OK, wri_m2_sig_verify(&ops, &p, v->key, v->klen, v->ssig));
		WRT_CHECK(hmac_calls == 1);
	}
	/* wipe: the log is gone, so the old signature no longer verifies */
	wri_m2_preauth_wipe(&p);
	WRT_CHECK_STATUS(WR_E_M2_SIGNATURE, wri_m2_sig_verify(NULL, &p, v->key, v->klen, v->ssig));
}

static void test_verify_overflow(const struct vec *v)
{
	uint8_t rxb[16], txb[16], data[17];
	wri_m2_preauth p;

	memset(data, 0x5a, sizeof(data));
	wri_m2_preauth_init(&p, rxb, txb, sizeof(rxb));
	wri_m2_preauth_tx(&p, data, sizeof(data)); /* one byte too many */
	wri_m2_preauth_stop(&p);
	WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, p.err);
	/* even the HMAC of the truncated (empty) log is never accepted: the transcript is unusable */
	{
		uint8_t want[32];

		wri_m2_sig_expected(NULL, &p, v->key, v->klen, want);
		WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, wri_m2_sig_verify(NULL, &p, v->key, v->klen, want));
	}
	/* a pre-auth object with no buffers fails closed as well */
	wri_m2_preauth_init(&p, NULL, NULL, 64);
	wri_m2_preauth_rx(&p, data, 1);
	wri_m2_preauth_stop(&p);
	{
		uint8_t zero[32];

		memset(zero, 0, sizeof(zero));
		WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, wri_m2_sig_verify(NULL, &p, NULL, 0, zero));
	}
}

int main(void)
{
	wrt_json j;
	struct vec v;

	if (load_vec(&j, &v) != 0) {
		fprintf(stderr, "cannot load msgr2/preauth-hmac.json\n");
		return 1;
	}
	WRT_CHECK(v.klen == 32 && v.rxn > WRI_M2_BANNER_LEN);
	test_vector(&v);
	test_wrong_transcripts(&v);
	test_independent(&v);
	test_prim_dispatch(&v);
	test_zero_key(&v);
	test_overflow();
	test_stop_wipe(&v);
	test_verify(&v);
	test_verify_overflow(&v);
	test_null_args(&v);
	free(v.key);
	free(v.rx);
	free(v.tx);
	free(v.csig);
	free(v.ssig);
	free(v.bad1);
	free(v.bad2);
	wrt_json_free(&j);
	return wrt_finish();
}
