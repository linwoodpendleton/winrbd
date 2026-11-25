/*
 * Copyright (C) 2026 the winrbd authors.
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

/* Secure Boot: FORBIDDEN, like every file of the driver (docs/design/ipxe-driver.md, section 13). This file parses nothing from
 * the network, but it handles the cephx key (the table carries it on request) and it is only ever linked into a build that
 * also contains the rest of the driver, which has not had the security review iPXE requires for PERMITTED. A file that "looks
 * harmless" does not change that: the licence and Secure Boot checks look at the whole binary.
 */
FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

/** @file
 *
 * RBD (Ceph) SAN protocol: the handoff ACPI table
 *
 * After the boot loader exits iPXE's world, a boot-start driver has to find the same image again. The "rBFT" table
 * (docs/design/handoff-table.md) carries the way: monitors, user, pool, image, the network settings of the NIC iPXE used and,
 * only when asked for, the cephx key. The layout, the rules and the encoding are the core's (wr_handoff_encode_table); this file
 * is the iPXE side of it: an acpi_model in iPXE's own sense (the pattern of the iBFT in src/drivers/block/ibft.c and of the
 * aBFT in src/net/aoe.c), which gathers the inputs and hands the bytes to the install callback of the EFI or BIOS backend.
 *
 *   - Every device has an ACPI descriptor (rbd_acpi_describe). The SAN layer adds it to the model's list when it describes the
 *     path and waits until complete() says 0, which it does once the image is open and the NIC route of the first monitor is
 *     known.
 *   - install() walks the list and builds each table FROM CURRENT STATE, every time: iPXE's EFI backend uninstalls every table
 *     it installed and installs them all again on each description pass, and the BIOS backend clears its area and installs again.
 *     Nothing is kept between calls (no static buffer, no cached table), so two installs of an unchanged world are byte for byte
 *     the same and a changed world (another address after a DHCP renewal) shows in the next table.
 *   - iPXE overwrites the OEM ID and OEM table ID of every table it installs and fixes the checksum afterwards; nothing here
 *     depends on them. The table is identified by its signature ("rBFT"), its checksum and the magic at the start of its body.
 *   - A table that does not fit the design maximum (1,024 bytes) is refused with a console line, never truncated.
 *   - The table is built in one heap object (the BIOS stack is 4 KiB), which holds the key when handoff=key was asked for and is
 *     wiped before it is freed. The table, key included, must never be printed here. (iPXE's own backends dump an installed
 *     table at their DEBUG level: a build with DEBUG=efi_block or DEBUG=int13 prints it, key included; those are debugging
 *     builds, and the design says so.)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <byteswap.h>
#include <config/general.h>
#include <ipxe/netdevice.h>
#include <ipxe/tcpip.h>
#include <ipxe/in.h>
#include <ipxe/ip.h>
#ifdef NET_PROTO_IPV6
#include <ipxe/ipv6.h>
#endif
#include <ipxe/vlan.h>
#include <ipxe/settings.h>
#include <ipxe/acpi.h>
#include "rbd_acpi.h"

/* The monitors of a session are copied into the codec's description one by one: the session's table must not be larger than
 * the codec's (a core change of one without the other would overflow info->mons: a build error is the right alarm).
 */
typedef char rbd_acpi_mons_fit[ ( WR_MAX_MONS <= WR_HANDOFF_MAX_MONS ) ? 1 : -1 ];

/**
 * Wipe memory in a way the compiler does not remove
 *
 * @v data		Data
 * @v len		Length of data
 */
static void rbd_acpi_wipe ( void *data, size_t len ) {
	volatile uint8_t *byte = data;

	while ( len-- )
		*byte++ = 0;
}

/**
 * Copy bytes, whatever their alignment
 *
 * @v dest		Destination
 * @v src		Source
 * @v len		Length
 *
 * Not memcpy(): on x86 iPXE's memcpy() of a length known at compile time (2, 4, 5, 6, 8, 12, 16 bytes) is written as 32-bit
 * accesses (__constant_memcpy in bits/string.h), which assume the addresses are aligned, and the fields of the table and of its
 * inputs (a MAC address, an IPv4 address inside a byte array) are not. The hardware does not mind, but it is undefined
 * behaviour, and the self-test program runs with UBSan to prove there is none. The loop is the one of iPXE's generic_memcpy().
 */
static void rbd_acpi_copy ( void *dest, const void *src, size_t len ) {
	uint8_t *dest_bytes = dest;
	const uint8_t *src_bytes = src;

	while ( len-- )
		*(dest_bytes++) = *(src_bytes++);
}

/**
 * Convert a core status of the handoff codec to an iPXE error code
 *
 * @v status		Core status
 * @ret rc		iPXE return status code
 */
static int rbd_acpi_rc ( wr_status status ) {

	switch ( status ) {
	case WR_E_HO_TOO_BIG:
	case WR_E_TOOBIG:
		return -ENOSPC;
	case WR_E_HO_FIELD:
	case WR_E_INVAL:
		return -EINVAL;
	default:
		return rbd_rc ( status );
	}
}

/******************************************************************************
 *
 * The session
 *
 ******************************************************************************
 */

/**
 * Get the data of the handoff table from a session (default: fail closed)
 *
 * @v session		Cluster session
 * @v source		Handoff data to fill in
 * @ret rc		-ENOTSUP
 *
 * The cluster session (rbd_session.c) provides the real function. This one only lets the glue link before it does, and keeps a
 * build that forgot to provide it from ever installing a table with made-up content.
 */
__weak int rbd_session_handoff ( struct rbd_session *session __unused,
				 struct rbd_handoff_source *source __unused ) {

	return -ENOTSUP;
}

/******************************************************************************
 *
 * The network device
 *
 ******************************************************************************
 */

/**
 * Get the first usable monitor
 *
 * @v src		Handoff data
 * @ret mon		First monitor with an address, or NULL
 */
const wr_addr * rbd_handoff_first_mon ( const struct rbd_handoff_source *src ) {
	unsigned int i;

	for ( i = 0 ; ( ( i < src->n_mons ) && ( i < WR_MAX_MONS ) ) ; i++ ) {
		if ( ( src->mons[i].family == WR_AF_IPV4 ) ||
		     ( src->mons[i].family == WR_AF_IPV6 ) )
			return &src->mons[i];
	}
	return NULL;
}

/**
 * Get the prefix length of the IPv4 network of a device's address
 *
 * @v parent		Settings of the network device
 * @v address		Address of the device
 * @ret prefix		Prefix length, or -EINVAL if the netmask is not a prefix (it has a 0 bit before a 1 bit)
 *
 * The prefix is that of the network the address lives on, not that of the routing table entry that was picked for the
 * monitor: iPXE keeps the default gateway, and every static route, as entries of their own (src/net/ipv4.c,
 * ipv4_add_miniroutes) whose netmask is 0 or the route's, so a monitor beyond the local subnet would be given prefix 0 by
 * its route. The mask is read the way iPXE reads it when it builds the local route: the "netmask" setting of the device
 * and, when that is absent, the default of the address class (the class test and the three defaults follow the same step of
 * ipv4_add_miniroutes() in src/net/ipv4.c, an iPXE file under the same licence).
 */
static int rbd_acpi_prefix4 ( struct settings *parent, struct in_addr address ) {
	struct in_addr netmask;
	uint32_t mask;
	uint32_t host;
	unsigned int prefix = 0;

	netmask.s_addr = 0;
	fetch_ipv4_setting ( parent, &netmask_setting, &netmask );
	if ( ! netmask.s_addr ) {
		if ( IN_IS_CLASSA ( address.s_addr ) ) {
			netmask.s_addr = INADDR_NET_CLASSA;
		} else if ( IN_IS_CLASSB ( address.s_addr ) ) {
			netmask.s_addr = INADDR_NET_CLASSB;
		} else if ( IN_IS_CLASSC ( address.s_addr ) ) {
			netmask.s_addr = INADDR_NET_CLASSC;
		}
	}

	/* A prefix mask is ones followed by zeroes: the host part ~mask is then 2^n - 1, and host & ( host + 1 ) is 0 */
	mask = ntohl ( netmask.s_addr );
	host = ~mask;
	if ( host & ( host + 1 ) )
		return -EINVAL;
	for ( ; mask ; mask >>= 1 )
		prefix += ( mask & 1 );
	return prefix;
}

/**
 * Get the first DNS server of a device
 *
 * @v parent		Settings of the network device
 * @v v6		Look for an IPv6 server
 * @v dns		Address to fill in (16 bytes, already zero)
 *
 * Settings of the device first; then every block, because a server set by hand with "set dns" is global and is the one iPXE's
 * resolver uses. No server is not an error: the field stays zero.
 */
static void rbd_acpi_dns ( struct settings *parent, int v6, uint8_t *dns ) {
	struct in_addr in;

	if ( ! v6 ) {
		if ( ( fetch_ipv4_array_setting ( parent, &dns_setting, &in,
						  1 ) < 0 ) &&
		     ( fetch_ipv4_array_setting ( NULL, &dns_setting, &in,
						  1 ) < 0 ) )
			return;
		rbd_acpi_copy ( dns, &in, sizeof ( in ) );
		return;
	}
#ifdef NET_PROTO_IPV6
	{
		struct in6_addr in6;

		if ( ( fetch_ipv6_array_setting ( parent, &dns6_setting, &in6,
						  1 ) < 0 ) &&
		     ( fetch_ipv6_array_setting ( NULL, &dns6_setting, &in6,
						  1 ) < 0 ) )
			return;
		rbd_acpi_copy ( dns, &in6, sizeof ( in6 ) );
	}
#endif
}

/**
 * Describe the network device that reaches a monitor
 *
 * @v mon		Monitor address
 * @v nic		Network device description to fill in
 * @ret rc		Return status code: -EHOSTUNREACH while no open device has a route to the monitor
 *
 * The device is the one iPXE's routing table picks for the monitor (tcpip_netdev(): the device a connection to it uses). The
 * address and the gateway are those of that route; the prefix is that of the device's own network (rbd_acpi_prefix4(): the
 * route of an off-link monitor is a default or static route whose netmask says nothing about the NIC); the other values are
 * those of the device and of its settings, as the iBFT takes them (src/drivers/block/ibft.c, ibft_fill_nic).
 */
int rbd_acpi_nic ( const wr_addr *mon, struct rbd_handoff_nic *nic ) {
	struct sockaddr_tcpip st;
	struct net_device *netdev;
	struct settings *parent;
	struct settings *origin;
	int rc;

	memset ( nic, 0, sizeof ( *nic ) );
	memset ( &st, 0, sizeof ( st ) );

	/* Build the destination address, and find the device */
	if ( mon->family == WR_AF_IPV4 ) {
		struct sockaddr_in *sin = ( ( struct sockaddr_in * ) &st );

		sin->sin_family = AF_INET;
		rbd_acpi_copy ( &sin->sin_addr, mon->ip, sizeof ( sin->sin_addr ) );
	} else if ( mon->family == WR_AF_IPV6 ) {
#ifdef NET_PROTO_IPV6
		struct sockaddr_in6 *sin6 = ( ( struct sockaddr_in6 * ) &st );

		sin6->sin6_family = AF_INET6;
		rbd_acpi_copy ( &sin6->sin6_addr, mon->ip, sizeof ( sin6->sin6_addr ) );
#else
		/* This build has no IPv6: a connection to the monitor is not possible either */
		return -ENOTSUP;
#endif
	} else {
		return -EINVAL;
	}
	netdev = tcpip_netdev ( &st );
	if ( ! netdev )
		return -EHOSTUNREACH;
	parent = netdev_settings ( netdev );

	/* Link layer: the address of the physical interface, the VLAN, the MTU */
	if ( ( rc = netdev->ll_protocol->eth_addr ( netdev->ll_addr,
						    nic->mac ) ) != 0 ) {
		DBGC ( netdev, "RBD %s has no Ethernet address: %s\n",
		       netdev->name, strerror ( rc ) );
		return rc;
	}
	nic->vlan = vlan_tag ( netdev );
	nic->mtu = ( ( netdev->mtu > 0xffff ) ? 0xffff : netdev->mtu );

	/* Network layer: the address of the route, its prefix, the gateway */
	if ( mon->family == WR_AF_IPV4 ) {
		struct sockaddr_in *sin = ( ( struct sockaddr_in * ) &st );
		struct ipv4_miniroute *miniroute;
		struct in_addr dest = sin->sin_addr;
		struct in_addr ip;
		struct in_addr gateway;

		miniroute = ipv4_route ( 0, &dest );
		if ( ( ! miniroute ) || ( miniroute->netdev != netdev ) )
			return -EHOSTUNREACH;
		rc = rbd_acpi_prefix4 ( parent, miniroute->address );
		if ( rc < 0 ) {
			DBGC ( netdev, "RBD %s has a netmask that is not a "
			       "prefix\n", netdev->name );
			return rc;
		}
		nic->family = 4;
		rbd_acpi_copy ( nic->ip, &miniroute->address, sizeof ( ip ) );
		nic->prefix = rc;

		/* The next hop if the monitor is off-link, else the default gateway of the device */
		gateway = miniroute->gateway;
		if ( ( ! gateway.s_addr ) &&
		     ( fetch_ipv4_setting ( parent, &gateway_setting,
					    &gateway ) < 0 ) )
			gateway.s_addr = 0;
		rbd_acpi_copy ( nic->gateway, &gateway, sizeof ( gateway ) );
		rbd_acpi_dns ( parent, 0, nic->dns );

		/* Configured by hand if the device's own settings hold the address */
		fetch_setting ( parent, &ip_setting, &origin, NULL, &ip,
				sizeof ( ip ) );
		nic->is_static = ( origin == parent );
	} else {
#ifdef NET_PROTO_IPV6
		struct sockaddr_in6 *sin6 = ( ( struct sockaddr_in6 * ) &st );
		struct ipv6_miniroute *miniroute;
		struct in6_addr *dest = &sin6->sin6_addr;
		struct in6_addr gateway;
		struct in6_addr ip;

		miniroute = ipv6_route ( 0, &dest );
		if ( ( ! miniroute ) || ( miniroute->netdev != netdev ) )
			return -EHOSTUNREACH;
		nic->family = 6;
		rbd_acpi_copy ( nic->ip, &miniroute->address, sizeof ( ip ) );
		nic->prefix = miniroute->prefix_len;

		/* The router if the monitor is off-link, else the default router of the device */
		memset ( &gateway, 0, sizeof ( gateway ) );
		if ( dest != &sin6->sin6_addr ) {
			rbd_acpi_copy ( &gateway, dest, sizeof ( gateway ) );
		} else if ( fetch_ipv6_setting ( parent, &gateway6_setting,
						 &gateway ) < 0 ) {
			memset ( &gateway, 0, sizeof ( gateway ) );
		}
		rbd_acpi_copy ( nic->gateway, &gateway, sizeof ( gateway ) );
		rbd_acpi_dns ( parent, 1, nic->dns );

		/* Configured by hand if the device's own settings hold this very address */
		if ( ( fetch_setting ( parent, &ip6_setting, &origin, NULL, &ip,
				       sizeof ( ip ) ) >= 0 ) &&
		     ( origin == parent ) ) {
			nic->is_static =
				( memcmp ( &ip, &miniroute->address,
					   sizeof ( ip ) ) == 0 );
		}
#endif
	}
	return 0;
}

/******************************************************************************
 *
 * The table
 *
 ******************************************************************************
 */

/**
 * Build one handoff table
 *
 * @v work		Work object: src and nic filled in; info and table are built
 * @v handoff		What the table carries of the credentials (RBD_HANDOFF_NOKEY or RBD_HANDOFF_KEY)
 * @ret len		Length of the table (in work->table)
 * @ret rc		Return status code
 *
 * A pure function of its inputs: no state is read or kept, so the same inputs give the same bytes. A refusal prints one
 * console line that says why (never the names, never the key) and returns an error; nothing is truncated.
 */
int rbd_acpi_build ( struct rbd_acpi_work *work, unsigned int handoff,
		     size_t *len ) {
	const struct rbd_handoff_source *src = &work->src;
	const struct rbd_handoff_nic *nic = &work->nic;
	wr_handoff_info *info = &work->info;
	const char *user;
	unsigned int i;
	wr_status st;

	*len = 0;
	memset ( info, 0, sizeof ( *info ) );

	/* The device decides what the table carries of the credentials */
	if ( ( handoff != RBD_HANDOFF_NOKEY ) &&
	     ( handoff != RBD_HANDOFF_KEY ) ) {
		DBGC ( work, "RBD handoff mode %d builds no table\n", handoff );
		return -EINVAL;
	}

	/* Identity: user (as the core uses it: one leading "client." is not part of the id), pool, image, snapshot */
	user = ( src->user ? src->user : "" );
	if ( strncmp ( user, "client.", 7 ) == 0 )
		user += 7;
	info->auth = WR_HANDOFF_AUTH_CEPHX;
	info->entity = user;
	info->pool = src->pool;
	info->image = src->image;
	info->image_id = src->image_id;
	info->snapshot = src->snap;

	/* Monitors in the order given, those without an address skipped, the default port filled in */
	for ( i = 0 ; ( ( i < src->n_mons ) && ( i < WR_MAX_MONS ) ) ; i++ ) {
		if ( ( src->mons[i].family != WR_AF_IPV4 ) &&
		     ( src->mons[i].family != WR_AF_IPV6 ) )
			continue;
		info->mons[info->mon_count] = src->mons[i];
		info->mons[info->mon_count].nonce = 0;
		if ( ! info->mons[info->mon_count].port )
			info->mons[info->mon_count].port = RBD_ACPI_MON_PORT;
		info->mon_count++;
	}

	/* Mode, cluster id, access */
	info->msgr_mode = src->mode;
	if ( src->mode == WR_MODE_SECURE_ONLY )
		info->flags |= WR_HANDOFF_F_SECURE_REQUIRED;
	if ( src->fsid_known ) {
		info->flags |= WR_HANDOFF_F_FSID;
		rbd_acpi_copy ( info->fsid, src->fsid, sizeof ( info->fsid ) );
	}
	if ( src->read_only )
		info->flags |= WR_HANDOFF_F_READONLY;

	/* The key only on request */
	if ( handoff == RBD_HANDOFF_KEY ) {
		if ( ( ! src->key ) || ( ! src->key->len ) ) {
			printf ( "rbd: handoff=key was asked for, but the image "
				 "was opened without a key: no handoff table\n" );
			return -EINVAL;
		}
		info->flags |= WR_HANDOFF_F_KEY;
		info->key_type = src->key->type;
		info->key_len = src->key->len;
		info->key = src->key->secret;
	}

	/* The network device of the first monitor */
	info->nic_family = nic->family;
	info->nic_prefix = nic->prefix;
	info->nic_vlan = nic->vlan;
	info->nic_mtu = nic->mtu;
	if ( nic->vlan )
		info->flags |= WR_HANDOFF_F_VLAN;
	if ( nic->is_static )
		info->flags |= WR_HANDOFF_F_NIC_STATIC;
	rbd_acpi_copy ( info->nic_mac, nic->mac, sizeof ( info->nic_mac ) );
	rbd_acpi_copy ( info->nic_ip, nic->ip, sizeof ( info->nic_ip ) );
	rbd_acpi_copy ( info->nic_gateway, nic->gateway, sizeof ( info->nic_gateway ) );
	rbd_acpi_copy ( info->nic_dns, nic->dns, sizeof ( info->nic_dns ) );

	/* Encode: refused, never truncated, when it does not fit the design maximum */
	st = wr_handoff_encode_table ( info, work->table, sizeof ( work->table ),
				       len );
	if ( st == WR_E_HO_TOO_BIG ) {
		printf ( "rbd: the handoff table would be %zd bytes, more than "
			 "the limit of %d: no handoff table (shorter pool, "
			 "image or snapshot names, or fewer monitors)\n", *len,
			 ( int ) WR_HANDOFF_MAX_TABLE );
		*len = 0;
		return -ENOSPC;
	}
	if ( st != WR_OK ) {
		rbd_report ( "build the handoff table", st );
		*len = 0;
		return rbd_acpi_rc ( st );
	}
	return 0;
}

/******************************************************************************
 *
 * The model
 *
 ******************************************************************************
 */

/**
 * Get the descriptor of a device
 *
 * @v rbd		RBD device
 * @ret desc		ACPI descriptor, or NULL when the device installs no table (handoff=none)
 *
 * This is the device's acpi_describe operation: the SAN layer registers what it returns with acpi_add() (which holds a
 * reference to the device) and removes it with acpi_del(). The descriptor is initialised once, on first use.
 */
struct acpi_descriptor * rbd_acpi_describe ( struct rbd_device *rbd ) {

	if ( rbd->handoff == RBD_HANDOFF_NONE )
		return NULL;
	if ( ! rbd->desc.model )
		acpi_init ( &rbd->desc, &rbd_model, &rbd->refcnt );
	return &rbd->desc;
}

/**
 * Check whether a handoff descriptor is complete
 *
 * @v desc		ACPI descriptor
 * @v source		Source of the handoff data
 * @ret rc		Return status code
 *
 * -EINPROGRESS until the image is open and the network device that reaches the first monitor is known: the SAN layer then
 * keeps the connections running (the case of the iBFT before DHCP has finished). A session that has failed gives its error,
 * which the SAN layer reports when the path is closed. A problem that waiting cannot cure returns 0 and is reported by install()
 * (sandev_describe() loops for ever on any error of an open path).
 */
int rbd_acpi_complete_with ( struct acpi_descriptor *desc,
			     rbd_handoff_source_t *source ) {
	struct rbd_device *rbd = container_of ( desc, struct rbd_device, desc );
	struct rbd_handoff_nic nic;
	struct rbd_handoff_source *src;
	const wr_addr *mon;
	int rc;

	/* A device that asked for no table has nothing to wait for */
	if ( rbd->handoff == RBD_HANDOFF_NONE )
		return 0;

	/* A device that has let go of its session (the path is closed) cannot say anything: never hand NULL to the source */
	if ( ! rbd->session )
		return -ENOTCONN;

	/* The image must be open */
	src = zalloc ( sizeof ( *src ) );
	if ( ! src )
		return -ENOMEM;
	if ( ( rc = source ( rbd->session, src ) ) != 0 )
		goto out;

	/* The route to the first monitor must be known. Only "no route yet" is a reason to wait: the SAN layer asks again for ever
	 * while the path is open, so a problem that waiting cannot cure (no monitor with an address, a device without an Ethernet
	 * address, a family this build does not have) is not reported here, where it would make sanhook hang on a screen that says
	 * nothing. It is reported by install(), which names it on the console and fails the description.
	 */
	mon = rbd_handoff_first_mon ( src );
	if ( ! mon ) {
		rc = 0;
		goto out;
	}
	rc = rbd_acpi_nic ( mon, &nic );
	if ( rc == -EHOSTUNREACH )
		rc = -EINPROGRESS;
	else if ( rc != 0 )
		rc = 0;

 out:
	free ( src );
	return rc;
}

/**
 * Check whether a handoff descriptor is complete
 *
 * @v desc		ACPI descriptor
 * @ret rc		Return status code
 */
static int rbd_acpi_complete ( struct acpi_descriptor *desc ) {

	return rbd_acpi_complete_with ( desc, rbd_session_handoff );
}

/**
 * Install the handoff table(s)
 *
 * @v install		Installation method
 * @v source		Source of the handoff data
 * @ret rc		Return status code
 *
 * One table per device, built from the state at this moment (see the top of this file); the first failure ends the pass.
 */
int rbd_acpi_install_with ( int ( * install ) ( struct acpi_header *acpi ),
			    rbd_handoff_source_t *source ) {
	struct rbd_acpi_work *work;
	struct rbd_device *rbd;
	const wr_addr *mon;
	size_t len;
	int rc = 0;

	/* Nothing to install, nothing to allocate */
	if ( list_empty ( &rbd_model.descs ) )
		return 0;
	work = zalloc ( sizeof ( *work ) );
	if ( ! work )
		return -ENOMEM;

	list_for_each_entry ( rbd, &rbd_model.descs, desc.list ) {

		/* A device that asked for no table (it should not be registered at all) */
		if ( rbd->handoff == RBD_HANDOFF_NONE )
			continue;

		/* Gather the inputs afresh (a device without its session cannot be described) */
		memset ( work, 0, sizeof ( *work ) );
		if ( ! rbd->session ) {
			printf ( "rbd: cannot describe the image for the handoff "
				 "table: %s\n", strerror ( -ENOTCONN ) );
			rc = -ENOTCONN;
			break;
		}
		if ( ( rc = source ( rbd->session, &work->src ) ) != 0 ) {
			printf ( "rbd: cannot describe the image for the handoff "
				 "table: %s\n", strerror ( rc ) );
			break;
		}
		mon = rbd_handoff_first_mon ( &work->src );
		if ( ! mon ) {
			printf ( "rbd: no monitor address for the handoff table\n" );
			rc = -EINVAL;
			break;
		}
		if ( ( rc = rbd_acpi_nic ( mon, &work->nic ) ) != 0 ) {
			printf ( "rbd: no network device for the handoff table: "
				 "%s%s\n", strerror ( rc ),
				 ( rc == -ENOTSUP ) ? " (a monitor with an IPv6 "
				 "address needs an iPXE build with IPv6)" :
				 ( rc == -EINVAL ) ? " (the netmask of the "
				 "device is not a prefix length)" : "" );
			break;
		}

		/* Build and install the table */
		if ( ( rc = rbd_acpi_build ( work, rbd->handoff,
					     &len ) ) != 0 )
			break;
		if ( ( rc = install ( ( struct acpi_header * ) work->table ) )
		     != 0 ) {
			DBGC ( rbd, "RBD could not install the handoff table: "
			       "%s\n", strerror ( rc ) );
			break;
		}
	}

	/* The object may hold the key */
	rbd_acpi_wipe ( work, sizeof ( *work ) );
	free ( work );
	return rc;
}

/**
 * Install the handoff table(s)
 *
 * @v install		Installation method
 * @ret rc		Return status code
 */
static int rbd_acpi_install ( int ( * install ) ( struct acpi_header *acpi ) ) {

	return rbd_acpi_install_with ( install, rbd_session_handoff );
}

/** The handoff table model */
struct acpi_model rbd_model __acpi_model = {
	.descs = LIST_HEAD_INIT ( rbd_model.descs ),
	.complete = rbd_acpi_complete,
	.install = rbd_acpi_install,
};
