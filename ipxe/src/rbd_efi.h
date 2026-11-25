#ifndef _RBD_EFI_H
#define _RBD_EFI_H
/* SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL */
/** @file
 *
 * RBD (Ceph) SAN protocol: EFI device path, the interfaces of rbd_efi.c
 *
 * rbd_efi.c answers efi_describe for the block device (docs/design/ipxe-driver.md, section 6). The path is built in two
 * steps so that the part that decides the bytes can be tested on a Linux host, where there is no firmware, no network device
 * and no EFI library:
 *
 *   1. PURE: functions over plain buffers (rbd_efi_node_len(), rbd_efi_node_build(), rbd_efi_uri_redact(),
 *      rbd_efi_prefix_len(), rbd_efi_compose()). They keep no state, read nothing but their arguments and give the same
 *      answer for the same arguments. They are compiled into every build and linked into the self-test program.
 *   2. FIRMWARE: rbd_efi_path() (EFI builds only; elsewhere it returns NULL): gets the identity of the device from the
 *      session (rbd_session_efi_source()), asks iPXE for the path of the network device that routes to the first monitor
 *      (efi_netdev_path()), and composes the two.
 *
 * Licence: GPL2_OR_LATER_OR_UBDL, like iPXE's own SAN code. Not a candidate for a PERMITTED Secure Boot status: see rbd_efi.c.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

#include <stdint.h>
#include <stddef.h>
#include "rbd_priv.h"

/** Longest URI the "uri" device path carries (before and after redaction); a longer one is refused, not cut */
#define RBD_EFI_URI_MAX 1024

/** Longest device path (every node, the end node included) this file builds or accepts as a prefix */
#define RBD_EFI_PATH_MAX 4096

/**
 * What the device path says about the image
 *
 * Plain data, no iPXE type: filled in by the session (rbd_session_efi_source()) or by a test. Every pointer must stay valid
 * for the duration of the call that receives the structure. Nothing here is secret and nothing secret may be put here: the
 * path is installed on a firmware handle that every loaded driver and image can read.
 */
struct rbd_efi_ident {
	/** Path flavour, enum rbd_devpath (the URI option "devpath") */
	uint8_t devpath;
	/** The cluster id is known (the URI option "fsid"); if not, the vendor node carries 16 zero bytes */
	uint8_t fsid_known;
	/** Cluster id */
	uint8_t fsid[16];
	/** Pool name (required) */
	const char *pool;
	/** Image name (required) */
	const char *image;
	/** Snapshot name; NULL or "" for the head */
	const char *snap;
	/** The URI as the user gave it (devpath=uri): the password component and every query option that is not a known
	 * option name are removed by rbd_efi_uri_redact() before it goes into the path; may be NULL otherwise
	 */
	const char *uri;
};

/** What a session tells the EFI path code about its image (EFI builds) */
struct rbd_efi_source {
	/** Identity of the image (the devpath member is overwritten by the device's own) */
	struct rbd_efi_ident ident;
	/** First monitor: the network device that routes to it is the prefix of the path; family 0 = none */
	wr_addr mon;
};

/** The vendor node's GUID, 9041fce5-0402-4eae-b3c1-bd75adf50455, in the on-wire (mixed endian) layout of an EFI_GUID */
extern const uint8_t rbd_efi_vendor_guid[16];

extern size_t rbd_efi_node_len ( const struct rbd_efi_ident *ident );
extern size_t rbd_efi_node_build ( const struct rbd_efi_ident *ident,
				   void *out, size_t max );
extern size_t rbd_efi_uri_redact ( const char *uri, char *out, size_t max );
extern size_t rbd_efi_prefix_len ( const void *path, size_t max );
extern EFI_DEVICE_PATH_PROTOCOL *
rbd_efi_compose ( const void *prefix, size_t prefix_max,
		  const struct rbd_efi_ident *ident );

/**
 * Get the identity of a session's image for the EFI device path (provided by rbd_session.c)
 *
 * @v session		Cluster session
 * @v source		Structure to fill in (zeroed by the caller)
 * @ret rc		Return status code
 *
 * Owned by the session module (wave 3, "ipxe-driver-core"): it keeps the pool, image, snapshot, cluster id, first monitor
 * and the redacted URI text of the spec that opened the session (the spec itself is wiped after the open, key included, so
 * the session has to keep these few strings). rbd_efi.c ships a WEAK default that fails with -ENOTSUP, so the driver builds
 * and fails closed ("no device path") until the strong definition exists; a strong definition in another object replaces
 * it, nothing else changes.
 */
extern int rbd_session_efi_source ( struct rbd_session *session,
				    struct rbd_efi_source *source );

#endif /* _RBD_EFI_H */
