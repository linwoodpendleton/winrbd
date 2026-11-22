/* SPDX-License-Identifier: MIT */
/*
 * fuzz_m2_sec_tx - the secure transmit side (core/src/msgr2/wri_m2_sec_tx.c, wri_m2_sec_tx2.c) against the independent peer of
 * harness/test/support/sim_m2_sec.c (an AES-GCM and framing written from the spec note with ref_gcm, sharing nothing with the core).
 *
 * The input is a script (see test/m2_sec_tx_scn.h): byte 0 picks the encode buffer size, byte 1 the bounce size, bytes 2 .. 5 the connection
 * secret, then steps: send a frame (tag, one to four segments of lengths from empty through every edge of the 16 / 48 / 96 arithmetic to tens
 * of kilobytes), let the host consume some bytes (one at a time, odd sizes, whatever the peek shows), drain, reset the connection in the
 * middle of a stream. Properties, any violation traps:
 *   - no crash, no undefined behaviour, no read of a caller segment after the host consumed the frame it belongs to (segments are allocated
 *     exactly and freed the moment their frame is out), no write into them, no write outside the encode and bounce buffers (guard bands);
 *   - the bytes the host consumed are exactly what the independent encoder makes of the frames the core accepted (same key, same nonces),
 *     less what a reset dropped, so a frame refused with WR_E_BUSY or WR_E_TOOBIG took no nonce; the independent decoder reads them back
 *     segment for segment (a difference between the two is a finding in the core or in the reference, never a flake);
 *   - the pending count is exact after every step, the peek is repeatable and shows progress while anything is pending.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define TXR_CHECK(cond)                                                                           \
	do {                                                                                      \
		if (!(cond)) {                                                                    \
			fprintf(stderr, "fuzz_m2_sec_tx: property violated at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			__builtin_trap();                                                         \
		}                                                                                 \
	} while (0)

#include "../test/m2_sec_tx_scn.h"

#define MAX_INPUT 4096u
#define DATA_BUDGET (48u * 1024u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > MAX_INPUT)
		size = MAX_INPUT;
	txr_scenario(data, size, NULL, DATA_BUDGET, NULL, NULL);
	return 0;
}
