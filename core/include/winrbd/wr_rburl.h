/* SPDX-License-Identifier: MIT */
/*
 * wr_rburl.h - the pieces of an rbd:// URL, parsed into what a client is opened with.
 *
 *   rbd://[user@]mon[:port][,mon[:port]...]/pool/image[@snap][?option=value[&option=value...]]
 *
 * The host (the iPXE glue, a test tool, a kernel driver) splits the URL with its own URI code and hands the
 * pieces over as plain text; this module owns everything that looks at them: the user, the monitor list, the path,
 * the options and their values, the setting-supplied user and key. Nothing here allocates, keeps state, calls the
 * libc (only the memory primitives of wr_port.h) or uses more than a few hundred bytes of stack.
 *
 * Input rules (docs/design/ipxe-driver.md section 8):
 *
 *   - Every text is a pointer and a length (no NUL needed, none looked for). A NULL pointer means "absent" and
 *     needs a length of 0; a non-NULL pointer with a length of 0 is "present and empty".
 *   - `authority` is the text between "//" (after any user@) and the first "/", exactly as written in the URL. A
 *     host that splits "host:port" at the last colon (iPXE's parse_uri does) rebuilds it as host + ":" + port
 *     first: a list "10.0.0.1:3300,10.0.0.2:3300" arrives from such a split as host "10.0.0.1:3300,10.0.0.2" and
 *     port "3300". Monitor addresses are literals (wr_mon_parse_hosts); a host name is WR_E_MON_HOSTS_SYNTAX.
 *   - `user`, `password` presence, `authority` and `path` are what the host's URI code already percent-decoded
 *     (iPXE decodes them in place); they are NOT decoded again. `query` is the raw text after the "?"; option
 *     names and values are percent-decoded here, after the text is split at "&" and "=".
 *   - A password component is refused (WR_E_RBURL_PASSWORD): the URL is echoed by errors, debug output and menus, a
 *     key in it would leak. The key comes from the `key` setting text only.
 *
 * Output: a wr_rburl_spec with every field set (defaults where the URL says nothing) or an error. On ANY error the
 * spec is wiped (zeroed, the key through wr_key_wipe), so a half-parsed key never survives a failure. The spec holds
 * the cephx key while it lives: the owner calls wr_rburl_spec_wipe() when done, and keeps it off the stack of a
 * firmware that has 4 KiB of it (it is 772 bytes, with no pointer in it, on 32 and 64 bits alike).
 *
 * Errors. Every kind of mistake has its own status (WR_E_RBURL_* below, in a block of its own, codes 260 to 279;
 * wr_rburl_strerror / wr_rburl_status_name know them and fall back to wr_strerror / wr_status_name for the rest)
 * and, when the caller passes a wr_errinfo, the structured detail: err->what is a static string naming the URL
 * part or the option ("input", "password", "user" or "rbd-user" (the setting, when it is the one that is wrong),
 * "monitors", "path", "pool", "image", "snapshot", "query", "key", "mode", "ro", "timeout", "readahead", "fsid",
 * "devpath", "handoff", "mapmem", "monmsg", or "option" when no option name could be identified). For an option error a0 is the byte offset of the option's raw name in `query`, a1 its raw length
 * and, for a value error, a2 the offset of the raw value, so a host can say which part of the URL is wrong
 * without echoing the URL. NO key, password or secret text is ever put in a status, a what string or an offset.
 *
 * Statuses of other modules that this parser returns unchanged: WR_E_INVAL (NULL spec or input, a NULL text with
 * a length, an unusable argument), WR_E_MON_HOSTS_SYNTAX and WR_E_MON_NO_V2_ADDR (from wr_mon_parse_hosts), and
 * WR_E_UNSUPPORTED for a snapshot ("@snap" is parsed and validated, then refused until the core can open
 * snapshots: wr_image_params.snap_id).
 */
#ifndef WR_RBURL_H
#define WR_RBURL_H

#include "wr_config.h"
#include "wr_err.h"
#include "wr_key.h"
#include "wr_types.h"

/* ---- statuses ---------------------------------------------------------------------------------------------- */

/*
 * X(NAME, code, "English text"): same shape as WR_STATUS_LIST in wr_err.h, so the block can move there unchanged.
 * Codes 260 .. 279 are reserved for this module (wr_err.h holds 1 .. 232 and the handoff codec's 240 .. 259).
 */
#define WR_RBURL_STATUS_LIST(X)                                                                           \
	X(WR_E_RBURL_PASSWORD, 260, "the URL has a password part; the cephx key must come from the rbd-key setting") \
	X(WR_E_RBURL_NO_USER, 261, "no cephx user: write it before the @ in the URL or set rbd-user")        \
	X(WR_E_RBURL_BAD_USER, 262, "cephx user id is empty, too long, repeats the client. prefix or uses characters outside A-Z a-z 0-9 . _ -") \
	X(WR_E_RBURL_NO_KEY, 263, "no cephx key: set rbd-key")                                               \
	X(WR_E_RBURL_BAD_KEY, 264, "rbd-key is not a cephx key (a base64 key or a keyring \"key = ...\" line)") \
	X(WR_E_RBURL_NO_MONS, 265, "no monitor address in the URL")                                          \
	X(WR_E_RBURL_MANY_MONS, 266, "more monitor addresses than this client keeps")                        \
	X(WR_E_RBURL_PATH, 267, "the path must be /pool/image or /pool/image@snapshot")                      \
	X(WR_E_RBURL_NAME, 268, "pool, image or snapshot name is empty or has a character that is not allowed") \
	X(WR_E_RBURL_NAME_LONG, 269, "pool, image or snapshot name is longer than 127 bytes")                \
	X(WR_E_RBURL_TOO_LONG, 270, "a URL part or setting is longer than this parser accepts")              \
	X(WR_E_RBURL_ESCAPE, 271, "bad percent escape, or a character in the query that must be percent-encoded") \
	X(WR_E_RBURL_OPT_SYNTAX, 272, "an option is not of the form name=value")                             \
	X(WR_E_RBURL_OPT_UNKNOWN, 273, "unknown option name")                                                \
	X(WR_E_RBURL_OPT_DUP, 274, "option given more than once")                                            \
	X(WR_E_RBURL_OPT_VALUE, 275, "the value of the option is not one of the accepted words, numbers or ids") \
	X(WR_E_RBURL_OPT_RANGE, 276, "the number is outside the range the option accepts")

enum {
#define WR_X_RBURL_ENUM(name, code, text) name = -(code),
	WR_RBURL_STATUS_LIST(WR_X_RBURL_ENUM)
#undef WR_X_RBURL_ENUM
	WR_RBURL_STATUS_ENUM_END_ = 0
};

/* Static English text and symbolic name; statuses outside the block above go to wr_strerror / wr_status_name. Never NULL. */
const char *wr_rburl_strerror(wr_status st);
const char *wr_rburl_status_name(wr_status st);

/* ---- limits and defaults --------------------------------------------------------------------------------- */

#define WR_RBURL_NAME_MAX 128u         /* bytes of a pool, image or snapshot name including the NUL (names are at most 127) */
#define WR_RBURL_AUTHORITY_MAX 1024u   /* bytes of the monitor list text */
#define WR_RBURL_PATH_MAX 512u         /* bytes of the path text */
#define WR_RBURL_QUERY_MAX 1024u       /* bytes of the raw query */
#define WR_RBURL_USER_TEXT_MAX 256u    /* bytes of a user text (URI or setting), before the id limit of WR_ENTITY_MAX */
#define WR_RBURL_KEY_TEXT_MAX 1024u    /* bytes of the key setting text */

#define WR_RBURL_TIMEOUT_MIN_S 1u      /* timeout=<seconds> */
#define WR_RBURL_TIMEOUT_MAX_S 600u
#define WR_RBURL_TIMEOUT_DEFAULT_MS 20000u
#define WR_RBURL_READAHEAD_MAX_KIB 16384u /* readahead=<KiB>, 0 = off */
#define WR_RBURL_READAHEAD_DEFAULT_KIB 2048u
#define WR_RBURL_MAPMEM_MIN_KIB 16u    /* mapmem=<KiB per map slot>: the core refuses a slot below 16 KiB */
#define WR_RBURL_MAPMEM_MAX_KIB 16384u
#define WR_RBURL_MONMSG_MIN_KIB 64u    /* monmsg=<KiB of the largest monitor message> */
#define WR_RBURL_MONMSG_MAX_KIB 16384u

/* devpath= and handoff= values (the same numbers as enum rbd_devpath and enum rbd_handoff of the iPXE glue) */
#define WR_RBURL_DEVPATH_VENDOR 0u
#define WR_RBURL_DEVPATH_URI 1u
#define WR_RBURL_DEVPATH_SATA 2u
#define WR_RBURL_HANDOFF_NOKEY 0u
#define WR_RBURL_HANDOFF_KEY 1u
#define WR_RBURL_HANDOFF_NONE 2u

/* ---- input and output ------------------------------------------------------------------------------------- */

typedef struct wr_rburl_in {
	const char *user;           /* URI user part, decoded; NULL = no "user@" in the URL */
	size_t user_len;
	const char *authority;      /* monitor list "host[:port][,host[:port]...]", see the rules above; NULL = none */
	size_t authority_len;
	const char *path;           /* decoded path with its leading "/": "/pool/image" or "/pool/image@snap" */
	size_t path_len;
	const char *query;          /* raw query (after the "?", before any "#"); NULL = no "?" in the URL */
	size_t query_len;
	uint8_t has_password;       /* 1 = the URL had a password component (even an empty one): refused */
	uint8_t reserved8[7];
	const char *set_user;       /* "rbd-user" setting text, used when the URL has no user; NULL = unset */
	size_t set_user_len;
	const char *set_key;        /* "rbd-key" setting text: the base64 key or a keyring "key = ..." line; NULL = unset */
	size_t set_key_len;
} wr_rburl_in;

typedef struct wr_rburl_spec {
	char user[WR_ENTITY_MAX];            /* cephx id without "client."; never itself starts with "client." (refused) */
	char pool[WR_RBURL_NAME_MAX];
	char image[WR_RBURL_NAME_MAX];
	char snap[WR_RBURL_NAME_MAX];        /* "" = head (a snapshot is refused today, so always "" on success) */
	wr_addr mons[WR_MAX_MONS + 1u];      /* literal monitor addresses, v2, port filled (3300 by default); the last slot is the
						parser's scratch and is zero on return */
	uint8_t n_mons;                      /* 1 .. WR_MAX_MONS */
	uint8_t fsid_known;                  /* fsid=<uuid> was given */
	uint8_t fsid[16];
	uint8_t mode;                        /* WR_MODE_CRC_ONLY (default), _CRC_FIRST, _SECURE_FIRST, _SECURE_ONLY */
	uint8_t read_only;                   /* ro=1 */
	uint8_t devpath;                     /* WR_RBURL_DEVPATH_* */
	uint8_t handoff;                     /* WR_RBURL_HANDOFF_* */
	uint8_t reserved8[2];
	uint32_t open_timeout_ms;            /* timeout=<s> * 1000 (default 20000) */
	uint32_t readahead_kib;              /* readahead=<KiB> (default 2048, 0 = off) */
	uint32_t mapmem_kib;                 /* mapmem=<KiB per map slot>, 0 = the profile's size */
	uint32_t monmsg_kib;                 /* monmsg=<KiB>, 0 = the profile's size */
	wr_key key;                          /* from the key setting; wipe with wr_rburl_spec_wipe() */
} wr_rburl_spec;

/*
 * Parse the pieces in `in` into `out`. `err` may be NULL; when given it is zeroed first and, on failure, holds the
 * detail described above (module WR_MOD_HOST). The whole input is validated before anything is returned: the first
 * mistake found wins, in this order: password, user, monitors, path, query (left to right), key, snapshot.
 * Returns WR_OK, or a status; on failure `out` is wiped.
 */
WR_MUST_CHECK wr_status wr_rburl_parse(const wr_rburl_in *in, wr_rburl_spec *out, wr_errinfo *err);

/* Zero a spec, the key through wr_key_wipe(); safe on a spec that was never filled, NULL is ignored. */
void wr_rburl_spec_wipe(wr_rburl_spec *spec);

#endif /* WR_RBURL_H */
