#ifndef _RBD_PRIV_H
#define _RBD_PRIV_H
/* SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL */
/** @file
 *
 * RBD (Ceph) SAN protocol: the interfaces between the glue files
 *
 * This is the "host shim" of the iPXE profile of the portable core (docs/design/ipxe-driver.md, section 4). The
 * core is sans-IO: it never opens a socket, reads a clock or allocates memory. The glue files below do all of that
 * through iPXE's own interfaces and keep no protocol logic of their own. One file per concern, so that a reader
 * who wants to audit one function of the driver reads one file:
 *
 *   rbd_uri.c      the "rbd" URI opener, the settings, the URI -> struct rbd_spec translation
 *   rbd_session.c  the shared cluster session: memory plan, wr_client, image, the process that runs the core,
 *                  reopen with cached maps (a session outlives the block device that opened it)
 *   rbd_conn.c     the pump host: connection table over iPXE TCP sockets, timers, time and random
 *   rbd_block.c    the block device interface: read, write, capacity, commands, cancel, readahead hook
 *   rbd_efi.c      efi_describe: the EFI device path
 *   rbd_acpi.c     the handoff ACPI table ("rBFT") as an acpi_model
 *   rbd_errors.c   wr_status -> iPXE error code, console messages
 *
 * The structures below are the contract between the modules. This header belongs to the session / block module
 * (rbd_session.c, rbd_block.c, rbd_stack.c): everything the other glue files need from the session and the device is
 * declared here; what only the session, the block device, the diagnostics and their self-tests share is in rbd_session.h
 * and rbd_block.h (so that the other modules do not see the session's internals).
 *
 * Licence: GPL2_OR_LATER_OR_UBDL, like iPXE's own SAN code. The core (MIT) is linked in unchanged.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

#include <stdint.h>
#include <stddef.h>
#include <ipxe/refcnt.h>
#include <ipxe/list.h>
#include <ipxe/interface.h>
#include <ipxe/retry.h>
#include <ipxe/process.h>
#include <ipxe/acpi.h>
#include <ipxe/uri.h>
#include <ipxe/efi/efi_path.h>
#include "winrbd.h"

/** Block size presented to the SAN layer (RBD has no sector size; BIOS and UEFI want 512) */
#define RBD_BLKSIZE 512

/** Largest block count of one SAN command (4 MiB at 512 bytes: the iPXE profile's inflight_bytes_max) */
#define RBD_MAX_COUNT 8192

/** Longest pool, image or snapshot name accepted in a URI (including the NUL) */
#define RBD_NAME_MAX 128

/** Default time to wait for the image to open (ms); the SAN layer itself waits for ever */
#define RBD_DEFAULT_OPEN_TIMEOUT_MS 20000

/** Default readahead window (KiB); 0 disables readahead */
#define RBD_DEFAULT_READAHEAD_KIB 2048

/** A session with no device is kept this long (ms), then destroyed (docs/design/ipxe-driver.md, section 11) */
#define RBD_SESSION_GRACE_MS 120000U

/** The cluster is closed on a path that has waited (command pending or image opening) this long with the cluster unreachable (ms) */
#define RBD_STALL_CLOSE_MS 30000U

/** Request timeout of a readahead prefetch (ms): well below the SAN layer's 15 s, so that a command parked on a line is not held long */
#define RBD_PREFETCH_TIMEOUT_MS 4000U

/** EFI device path flavours (URI option "devpath") */
enum rbd_devpath {
	RBD_DEVPATH_VENDOR = 0,		/**< network path + vendor node (default) */
	RBD_DEVPATH_URI,		/**< network path + URI node (like the HTTP SAN protocol) */
	RBD_DEVPATH_SATA,		/**< network path + SATA node (like AoE) */
};

/** What the handoff table carries of the credentials (URI option "handoff") */
enum rbd_handoff {
	RBD_HANDOFF_NOKEY = 0,		/**< identity, monitors, image: no key (default) */
	RBD_HANDOFF_KEY = 1,		/**< ... and the cephx key (explicit opt-in) */
	RBD_HANDOFF_NONE = 2,		/**< no table at all */
};

/**
 * What a URI and the settings ask for
 *
 * Built by rbd_uri.c, consumed by rbd_session.c. Holds the cephx key while a session is being created: whoever
 * owns a struct rbd_spec calls rbd_spec_wipe() when done.
 */
struct rbd_spec {
	/** cephx user id without the "client." prefix */
	char user[WR_ENTITY_MAX];
	/** Pool of the image */
	char pool[RBD_NAME_MAX];
	/** Image name */
	char image[RBD_NAME_MAX];
	/** Snapshot name ("" = head; anything else is refused until the core can open snapshots) */
	char snap[RBD_NAME_MAX];
	/** Monitor addresses (literals: the core does no name resolution) */
	wr_addr mons[WR_MAX_MONS];
	/** Number of monitor addresses */
	uint8_t n_mons;
	/** Cluster id check (fsid=...) */
	uint8_t fsid_known;
	uint8_t fsid[16];
	/** Connection mode policy, WR_MODE_* (default WR_MODE_CRC_ONLY, as the core's profiles) */
	uint8_t mode;
	/** Open read-only (profile R1) instead of as a writer (profile P1) */
	uint8_t read_only;
	/** EFI device path flavour, enum rbd_devpath */
	uint8_t devpath;
	/** Handoff table content, enum rbd_handoff */
	uint8_t handoff;
	/** Time to wait for the image to open (ms) */
	uint32_t open_timeout_ms;
	/** Readahead window (KiB), 0 = off */
	uint32_t readahead_kib;
	/** cephx key (from the "rbd-key" setting) */
	wr_key key;
	/** The URI as the user gave it (devpath=uri only; borrowed, NULL when the opener does not provide it: the device path then cannot
	 * be built and the SAN hook fails with a console line). The password component and unknown options are removed by rbd_efi.c.
	 */
	const char *uri;
};

/** A shared cluster session: one wr_client, its image, its sockets (rbd_session.c) */
struct rbd_session;

/** An RBD block device: what one SAN path talks to (rbd_block.c) */
struct rbd_device {
	/** Reference count */
	struct refcnt refcnt;
	/** Block device interface (plugged into the SAN path) */
	struct interface block;
	/** The session (reference held) */
	struct rbd_session *session;
	/** ACPI descriptor for the handoff table */
	struct acpi_descriptor desc;
	/** EFI device path flavour */
	uint8_t devpath;
	/** Handoff content */
	uint8_t handoff;
	/** The device is attached to its session (counted in the session's devices; the session's grace period waits for it) */
	uint8_t attached;
	/** The session's list of attached devices */
	struct list_head list;
};

/* rbd_uri.c */
extern int rbd_parse_uri ( struct uri *uri, struct rbd_spec *spec );
extern void rbd_spec_wipe ( struct rbd_spec *spec );

/* rbd_session.c */
extern int rbd_session_open ( const struct rbd_spec *spec,
			      struct rbd_session **session );
extern void rbd_session_put ( struct rbd_session *session );

/* rbd_block.c */
extern int rbd_device_open ( struct interface *parent,
			     struct rbd_session *session,
			     const struct rbd_spec *spec );

/* rbd_efi.c */
extern EFI_DEVICE_PATH_PROTOCOL * rbd_efi_path ( struct rbd_device *rbd );

/* rbd_errors.c */
extern int rbd_rc ( wr_status status );
extern void rbd_report ( const char *what, wr_status status );
extern int rbd_rc_peer ( wr_status status, int32_t peer_result );
extern void rbd_report_peer ( const char *what, wr_status status,
			      int32_t peer_result, uint64_t detail );

/** Handoff table signature: "rBFT" (RBD boot firmware table), see docs/design/handoff-table.md */
#define RBFT_SIG ACPI_SIGNATURE ( 'r', 'B', 'F', 'T' )

/** The handoff table model (rbd_acpi.c) */
extern struct acpi_model rbd_model;

#endif /* _RBD_PRIV_H */
