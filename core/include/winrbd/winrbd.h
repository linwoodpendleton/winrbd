/* SPDX-License-Identifier: MIT */
/*
 * winrbd.h - umbrella header of the portable core. A host includes only this.
 *
 * API version history (WR_ABI_VERSION in wr_types.h):
 *   1  Phase 1, milestones 1 to 3: client engine, msgr2 + cephx monitor session, raw map delivery.
 *      Phase 1 part B (milestones 4 and 5) adds wr_map.h (OSD map, pools, object placement) and new
 *      wr_config fields taken from its reserved words: no ABI change, no version bump.
 * Later milestones add wr_image.h (RBD image open and block I/O) and extend wr_client.h.
 */
#ifndef WINRBD_H
#define WINRBD_H

#include "wr_client.h"
#include "wr_config.h"
#include "wr_err.h"
#include "wr_host.h"
#include "wr_key.h"
#include "wr_map.h"
#include "wr_port.h"
#include "wr_types.h"

#endif /* WINRBD_H */
