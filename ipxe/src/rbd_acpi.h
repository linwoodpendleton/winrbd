#ifndef _RBD_ACPI_H
#define _RBD_ACPI_H
/* SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL */
/** @file
 *
 * RBD (Ceph) SAN protocol: the handoff ACPI table, private declarations
 *
 * rbd_priv.h is the contract between the glue files and is frozen; what only the handoff table needs lives here: the data
 * the table is built from, the three small steps of building it (so that a self-test can run each without firmware), and the
 * one function the cluster session has to provide (rbd_session_handoff).
 *
 * The table itself (layout, rules, the checksum) is the core's codec (core/src/handoff, wr_handoff.h); this file set only
 * collects the inputs from iPXE's state and hands the bytes to iPXE's install callback.
 *
 * Licence: GPL2_OR_LATER_OR_UBDL, like iPXE's own SAN code.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

#include <stdint.h>
#include <stddef.h>
#include "rbd_priv.h"
#include "wr_handoff.h"

/** Monitor port the table carries when the session left it zero (the table never holds a port 0) */
#define RBD_ACPI_MON_PORT 3300

/**
 * What the cluster session tells the handoff table about the open image
 *
 * Filled in by rbd_session_handoff() into memory owned by the caller. The strings and the key stay owned by the session:
 * the pointers are valid while the caller holds a reference to the session (the device does) and are never kept past the
 * call that received them.
 */
struct rbd_handoff_source {
	/** cephx user id (a leading "client." is accepted, as the core accepts it) */
	const char *user;
	/** Pool of the image */
	const char *pool;
	/** Image name */
	const char *image;
	/** Image id, or NULL or "" when not known */
	const char *image_id;
	/** Snapshot name, or NULL or "" for the head */
	const char *snap;
	/** The session's cephx key (used only when the device asked for handoff=key), or NULL */
	const wr_key *key;
	/** Monitor addresses as the request gave them (a family of 0 is skipped, a port of 0 is the default port) */
	wr_addr mons[WR_MAX_MONS];
	/** Number of entries in mons */
	uint8_t n_mons;
	/** The cluster id was checked (fsid is valid) */
	uint8_t fsid_known;
	/** Cluster id */
	uint8_t fsid[16];
	/** Connection mode policy, WR_MODE_* */
	uint8_t mode;
	/** The image was opened read-only */
	uint8_t read_only;
};

/**
 * What iPXE knows about the network device that reaches the first monitor
 *
 * Built by rbd_acpi_nic() from iPXE's routing table and the settings of the device, in the form the table carries it (IP
 * bytes in network order, an IPv4 address in the first four bytes).
 */
struct rbd_handoff_nic {
	/** Address family of the route: 4 or 6 (0 = unknown) */
	uint8_t family;
	/** The address was configured by hand (a setting of the device itself), not learnt (DHCP, SLAAC) */
	uint8_t is_static;
	/** Prefix length of the address */
	uint8_t prefix;
	/** Ethernet MAC address */
	uint8_t mac[6];
	/** VLAN id, 0 when the device is not a VLAN device */
	uint16_t vlan;
	/** Link MTU (without the link-layer header) */
	uint16_t mtu;
	/** Source address of the route */
	uint8_t ip[16];
	/** Default gateway (0 = none) */
	uint8_t gateway[16];
	/** First DNS server (0 = none) */
	uint8_t dns[16];
};

/**
 * Everything one table is built from, and the table
 *
 * One heap object (about 2 KiB: the BIOS stack is 4 KiB, so nothing of this size goes on a stack); the table buffer holds
 * the cephx key when handoff=key was asked for, so the object is wiped before it is freed.
 */
struct rbd_acpi_work {
	/** From the session */
	struct rbd_handoff_source src;
	/** From the network device */
	struct rbd_handoff_nic nic;
	/** The core's description of the table (built from src and nic) */
	wr_handoff_info info;
	/** The table: ACPI header and body, at most WR_HANDOFF_MAX_TABLE bytes (aligned: iPXE's backends read it as a struct acpi_header) */
	uint8_t table[WR_HANDOFF_MAX_TABLE] __attribute__ (( aligned ( 8 ) ));
};

/**
 * Get the data of the handoff table from a session
 *
 * @v session		Cluster session
 * @v source		Handoff data to fill in (an all-zero object)
 * @ret rc		0 when the image is open and *source is filled in; -EINPROGRESS while the session is still opening
 *			the image; another error when it has failed
 *
 * PROVIDED BY rbd_session.c (module ipxe-driver-core). rbd_acpi.c carries a weak default that fails closed with -ENOTSUP so
 * that the file set links before the session exists: the session's definition replaces it. The image must be open before the
 * function succeeds, so that the table is only ever installed for a device that works.
 */
extern int rbd_session_handoff ( struct rbd_session *session,
				 struct rbd_handoff_source *source );

/** A function that provides the handoff data of a session (rbd_session_handoff(); a fake in the self-tests) */
typedef int ( rbd_handoff_source_t ) ( struct rbd_session *session,
				       struct rbd_handoff_source *source );

/* rbd_acpi.c: the descriptor of a device (for the block device's acpi_describe operation) */
extern struct acpi_descriptor * rbd_acpi_describe ( struct rbd_device *rbd );

/* rbd_acpi.c: the model's two operations over an explicit source of data (the model calls them with rbd_session_handoff) */
extern int rbd_acpi_complete_with ( struct acpi_descriptor *desc,
				    rbd_handoff_source_t *source );
extern int rbd_acpi_install_with ( int ( * install )
				   ( struct acpi_header *acpi ),
				   rbd_handoff_source_t *source );

/* rbd_acpi.c: the steps of building one table */
extern const wr_addr * rbd_handoff_first_mon ( const struct rbd_handoff_source *src );
extern int rbd_acpi_nic ( const wr_addr *mon, struct rbd_handoff_nic *nic );
extern int rbd_acpi_build ( struct rbd_acpi_work *work, unsigned int handoff,
			    size_t *len );

#endif /* _RBD_ACPI_H */
