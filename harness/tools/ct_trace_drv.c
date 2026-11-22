/* SPDX-License-Identifier: MIT */
/*
 * ct_trace_drv.c - the driver of ct_trace_check.sh (design 41.4): one fixed sequence of calls into the constant-time crypto of the core,
 * with the key, the IV, the additional data and the data all taken from a file, so that the script can run it under Valgrind's lackey
 * tool with many different secrets and compare what it executed and which addresses it touched. It prints nothing and keeps nothing
 * between runs; the only thing that varies from one run to the next is the content of the file.
 *
 *   ct_trace_drv FILE             the constant-time path (AES-128 and AES-256: key schedule, blocks, counter mode; GHASH; GCM seal and open
 *                                 in odd pieces with additional data, both key sizes; the dispatcher with the portable code)
 *   ct_trace_drv FILE control     the table-driven AES of the cephx code, which is NOT constant time: the script requires its traces to
 *                                 differ, or it proves nothing about the method
 *
 * Exit status: 0 the calls worked and every round trip agreed, 2 the file could not be read, 3 a call refused, 1 a round trip disagreed.
 * Built by the script with the system compiler against core/src (a host program: it may use libc).
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wri_aes.h"
#include "wri_aesct.h"
#include "wri_gcm.h"
#include "wri_ghash.h"
#include "wri_pgcm.h"

#define FILE_BYTES 512

static uint8_t in[FILE_BYTES];
static uint8_t outb[FILE_BYTES], outc[FILE_BYTES], tag[16];
static wri_gcm g;
static wri_pgcm pg;

static int control(void)
{
	wri_aes_ctx a;
	uint8_t blk[16];

	memcpy(blk, in + 64, 16);
	if (wri_aes_setkey(&a, in, 16) != WR_OK)
		return 3;
	wri_aes_enc_block(&a, blk, blk);
	return 0;
}

int main(int argc, char **argv)
{
	wri_aesct_ctx c;
	wri_ghash gh;
	uint8_t ctr[16];
	size_t n, i;
	int fd, bad = 0;

	if (argc < 2)
		return 2;
	fd = open(argv[1], O_RDONLY);
	if (fd < 0 || read(fd, in, sizeof(in)) != (ssize_t)sizeof(in))
		return 2;
	close(fd);
	if (argc > 2)
		return control();
	for (i = 16; i <= 32; i += 16) {
		if (wri_aesct_setkey(&c, in, i) != WR_OK)
			return 3;
		for (n = 1; n <= 9; n++)
			wri_aesct_encrypt_blocks(&c, in + 100, outb, n);
		memcpy(ctr, in + 40, 12);
		ctr[12] = 0xff; /* the counter is about to wrap */
		ctr[13] = 0xff;
		ctr[14] = 0xff;
		ctr[15] = 0xfd;
		for (n = 1; n < 200; n += 37)
			wri_aesct_ctr32(&c, ctr, in + 200, outb, n);
		wri_aesct_wipe(&c);
	}
	wri_ghash_init(&gh, in + 16);
	wri_ghash_blocks(&gh, in + 100, 7);
	wri_ghash_blocks(&gh, in + 220, 3);
	wri_ghash_get(&gh, tag);
	wri_ghash_wipe(&gh);
	for (i = 16; i <= 32; i += 16) {
		if (wri_gcm_setkey(&g, in, i) != WR_OK || wri_gcm_start(&g, in + 32, 12, 0) != WR_OK || wri_gcm_aad(&g, in + 300, 21) != WR_OK ||
		    wri_gcm_update(&g, in + 100, outb, 23) != WR_OK || wri_gcm_update(&g, in + 123, outb + 23, 64) != WR_OK ||
		    wri_gcm_update(&g, in + 187, outb + 87, 100) != WR_OK || wri_gcm_final_enc(&g, tag) != WR_OK)
			return 3;
		if (wri_gcm_start(&g, in + 32, 12, 1) != WR_OK || wri_gcm_aad(&g, in + 300, 21) != WR_OK ||
		    wri_gcm_update(&g, outb, outc, 187) != WR_OK || wri_gcm_final_dec(&g, tag) != WR_OK) /* the right tag: a public "yes" */
			return 3;
		if (memcmp(outc, in + 100, 187) != 0)
			bad = 1;
		wri_gcm_wipe(&g);
	}
	if (wri_pgcm_setkey(&pg, NULL, in + 5) != WR_OK || wri_pgcm_start(&pg, in + 70, 0) != WR_OK ||
	    wri_pgcm_update(&pg, in + 100, outb, 80) != WR_OK || wri_pgcm_final_enc(&pg, tag) != WR_OK)
		return 3;
	if (wri_pgcm_start(&pg, in + 70, 1) != WR_OK || wri_pgcm_update(&pg, outb, outc, 80) != WR_OK || wri_pgcm_final_dec(&pg, tag) != WR_OK)
		return 3;
	if (memcmp(outc, in + 100, 80) != 0)
		bad = 1;
	wri_pgcm_wipe(&pg);
	return bad;
}
