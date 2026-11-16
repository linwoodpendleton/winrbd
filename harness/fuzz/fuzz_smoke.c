/* SPDX-License-Identifier: MIT */
/*
 * Smoke fuzz target: proves the fuzz wiring (libFuzzer build and seed replay). It exercises the status
 * table with arbitrary integers. Real targets (one per decoder boundary) arrive with their modules.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "wr_err.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int32_t st = 0;

	if (size >= 4)
		memcpy(&st, data, 4);
	/* must never return NULL and never crash for any value */
	if (!wr_strerror(st) || !wr_status_name(st))
		__builtin_trap();
	return 0;
}
