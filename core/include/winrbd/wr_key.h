/* SPDX-License-Identifier: MIT */
/*
 * wr_key.h - cephx keys and the cluster description a client is created from.
 */
#ifndef WR_KEY_H
#define WR_KEY_H

#include "wr_err.h"
#include "wr_types.h"

#define WR_KEY_MAX 64        /* bytes of raw secret kept */
#define WR_MAX_MONS 8        /* monitor addresses in a wr_cluster_spec */
#define WR_ENTITY_MAX 64     /* bytes of the user id including the terminating NUL */

#define WR_KEY_TYPE_AES 1u     /* "aes": AES-128-CBC, fixed IV (legacy) */
#define WR_KEY_TYPE_AES256K 2u /* "aes256k": AES-256 CTS + HMAC-SHA384 (default on a new cluster) */

/* A cephx key. The secret is wiped by wr_key_wipe() and by wr_client_destroy(); never log it. */
typedef struct wr_key {
	uint8_t type;           /* WR_KEY_TYPE_* */
	uint8_t len;            /* bytes used in secret: type 1 >= 16, type 2 >= 32 */
	uint8_t secret[WR_KEY_MAX];
} wr_key;

/* Build a key from raw secret bytes; validates type and length (cephx.md 2.3). */
wr_status wr_key_from_raw(wr_key *out, unsigned type, const uint8_t *secret, size_t len);

/*
 * Parse the base64 form that appears after "key = " in a keyring: base64 of
 * {u16 type, utime created, u16 len, secret} (cephx.md 2.3). Whitespace around is ignored.
 */
wr_status wr_key_parse_base64(wr_key *out, const char *b64, size_t n);

/* Find the first "key = <base64>" line in keyring text and parse it. */
wr_status wr_key_parse_keyring(wr_key *out, const char *text, size_t n);

/* Zero the secret in a way the compiler cannot remove. */
void wr_key_wipe(wr_key *k);

/*
 * What a client connects to and as whom. Monitor addresses are LITERAL v2 addresses: the core
 * does no name resolution (mon-client.md section 4); the host resolves names first.
 */
typedef struct wr_cluster_spec {
	char user[WR_ENTITY_MAX];       /* id without the type, "winrbd" for client.winrbd; a leading
					   "client." is accepted and stripped */
	wr_key key;
	wr_addr mons[WR_MAX_MONS];      /* family 0 entries are ignored; port 0 means 3300 */
	uint8_t n_mons;
	uint8_t fsid_known;             /* 1 = fsid below is checked against the monmap and maps */
	uint8_t fsid[16];
} wr_cluster_spec;

/*
 * Parse a mon_host style list of literal addresses into out[] (at most max entries):
 * "10.77.0.10", "10.77.0.10:3300", "[v2:10.77.0.10:3300,v1:10.77.0.10:6789]", "[fd00::1]:3300",
 * separated by commas, spaces or semicolons. v1-only entries are dropped. Returns the count in
 * *n_out; WR_E_MON_HOSTS_SYNTAX on a malformed list, WR_E_MON_NO_V2_ADDR if none is left.
 */
wr_status wr_mon_parse_hosts(const char *text, size_t n, wr_addr *out, size_t max, size_t *n_out);

#endif /* WR_KEY_H */
