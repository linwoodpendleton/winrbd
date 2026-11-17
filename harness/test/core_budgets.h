/* SPDX-License-Identifier: MIT */
/*
 * core_budgets.h - the documented memory budgets of the configuration profiles, written down once.
 *
 * Used by test_core_budgets.c (the engine must fit) and test_core_docs.c (core/README.md must say the same). Source of
 * the numbers: docs/design/core-architecture.md section 5.2 and the footprint table in core/README.md.
 *
 *   profile  arena budget  bulk budget
 *   ipxe     128 KiB       1 MiB + 16 KiB        (the arena comes out of the 4 MiB iPXE malloc heap, the bulk of umalloc)
 *   kernel   512 KiB       8 MiB + 32 KiB        (non-paged pool)
 *   harness  4 MiB         40 MiB                (not a product profile; a sanity cap so it cannot grow unnoticed)
 *
 * With the OSD map module on (wr_config_enable_maps(), architecture 15.3: two map slots in the bulk, the placement cache
 * in the arena; the store struct itself is part of every client):
 *
 *   ipxe     128 KiB       1.5 MiB + 64 KiB      (arena 113 KiB, bulk 1542 KiB; the 4 MiB heap holds the arena only)
 *   kernel   512 KiB       10 MiB + 64 KiB       (arena 502 KiB, bulk 10246 KiB)
 *   harness  4 MiB         48 MiB                (sanity cap; 3.0 MiB / 40 MiB)
 */
#ifndef WR_TEST_CORE_BUDGETS_H
#define WR_TEST_CORE_BUDGETS_H

#define WRB_IPXE_ARENA (128u * 1024u)
#define WRB_IPXE_BULK (1024u * 1024u + 16u * 1024u)
#define WRB_KERNEL_ARENA (512u * 1024u)
#define WRB_KERNEL_BULK (8u * 1024u * 1024u + 32u * 1024u)
#define WRB_HARNESS_ARENA (4u * 1024u * 1024u)
#define WRB_HARNESS_BULK (40u * 1024u * 1024u)

/* the same profiles with the map module on (core/README.md "Memory footprint" has the measured numbers) */
#define WRB_IPXE_MAPS_ARENA (128u * 1024u)
#define WRB_IPXE_MAPS_BULK (1536u * 1024u + 64u * 1024u)
#define WRB_KERNEL_MAPS_ARENA (512u * 1024u)
#define WRB_KERNEL_MAPS_BULK (10u * 1024u * 1024u + 64u * 1024u)
#define WRB_HARNESS_MAPS_ARENA (4u * 1024u * 1024u)
#define WRB_HARNESS_MAPS_BULK (48u * 1024u * 1024u)

#endif /* WR_TEST_CORE_BUDGETS_H */
