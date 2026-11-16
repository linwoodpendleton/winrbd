/* SPDX-License-Identifier: MIT */
/*
 * wrl_host.h - the Linux user-space host of the core ("wrl" = winrbd Linux). It implements the shim of
 * wr_host.h and the transport pump of wr_client.h with POSIX sockets, so the protocol code can be
 * developed and debugged here, where debugging is cheap (docs/ROADMAP.md, ground rules). It is the
 * model for the iPXE and Windows hosts: each of those is a different ~300 lines around the same calls.
 *
 * Part 1 (system services) is implemented by harness/host/wrl_sys.c, part 2 (the socket pump) by
 * harness/host/wrl_loop.c. Everything here is harness code: libc, POSIX and malloc are allowed.
 */
#ifndef WRL_HOST_H
#define WRL_HOST_H

#include "winrbd/winrbd.h"

/* ---- part 1: system services -------------------------------------------------------------- */

/* Read both clocks (CLOCK_MONOTONIC and CLOCK_REALTIME) in milliseconds. */
void wrl_clock(wr_clock *out);

/* wr_host_ops.random: getrandom(2), never a weak fallback. Returns WR_E_HOST_RANDOM on failure. */
wr_status wrl_random(void *ctx, uint8_t *out, size_t n);

/* wr_host_ops.log: one line on stderr per record. ctx is a pointer to unsigned = max level to print,
 * or NULL for WR_LOG_INFO. Key material never reaches a record (core rule), so nothing is scrubbed here. */
void wrl_log_stderr(void *ctx, const wr_log_rec *rec);

/* Fill ops with wrl_random and wrl_log_stderr (log level in *max_level, which must outlive the client;
 * NULL = WR_LOG_INFO) and no primitive overrides. */
void wrl_host_ops_init(wr_host_ops *ops, unsigned *max_level);

/* Allocate / free a core memory region: 64-byte aligned, zeroed; wrl_mem_free wipes before freeing
 * (the arena holds keys). size 0 gives {NULL, 0}. */
wr_status wrl_mem_alloc(wr_mem_region *out, size_t size);
void wrl_mem_free(wr_mem_region *r);

/* Read a small text file (keyring, config) into buf (NUL-terminated, at most cap-1 bytes). *len gets the
 * length. WR_E_RANGE if the file is larger than cap-1 bytes, WR_E_INVAL if it cannot be opened or read, is
 * not a regular file or an argument is bad, WR_E_ENCODING if it contains a NUL byte. On any error buf is
 * left as an empty string (whatever was read is wiped) and *len is 0. The caller wipes buf when done with
 * a keyring. */
wr_status wrl_read_text_file(const char *path, char *buf, size_t cap, size_t *len);

/* ---- part 2: socket pump ------------------------------------------------------------------ */

typedef struct wrl_loop wrl_loop;

/*
 * Bind a pump to a client. The loop does not own the client. It holds at most 64 sockets (the harness
 * profile uses 16); a CONNECT beyond that is answered with wr_conn_closed(EMFILE). Not thread-safe: the
 * loop and its client belong to one thread (wr_client.h, one owner).
 */
wr_status wrl_loop_create(wr_client *c, wrl_loop **out);
/* Closes every socket it still holds, without telling the client (which may be gone already). */
void wrl_loop_destroy(wrl_loop *l);

/*
 * One iteration of the reference loop, turned so that the wait comes first: sleep in poll(2) for socket
 * events (at most max_wait_ms; also no longer than until the client's next deadline or the nearest connect
 * deadline; 0 = do not wait; negative = no limit from the caller), then wr_client_run, drain the actions,
 * and move bytes. The sleep is skipped when the previous step made progress (bytes moved, an action
 * served, a connection ended) or the engine asked for another call at once; an idle client sleeps until
 * its next timer. Because the wait is first, whatever a step produced (events, map messages, still queued
 * in the client) can be pulled by the caller as soon as the step returns. The poll interest is read
 * from the engine at the start of every wait, so releasing a map message (which reopens a closed receive
 * window) needs no extra call.
 * Returns WR_OK, or the fatal status if the client reached WR_CS_FAILED.
 *
 * Per connection: the connect uses the timeout the action carries (0 = 5 s); a connect, send or recv
 * failure, a reset or an EOF ends the connection with wr_conn_closed(errno) (0 = orderly EOF); a
 * WR_ACT_CLOSE closes the socket and is answered with wr_conn_closed(0). SIGPIPE is never raised.
 */
wr_status wrl_loop_step(wrl_loop *l, int max_wait_ms);

/*
 * Run steps until stop(arg) returns non-zero (checked before every step, so also before the first) or
 * timeout_ms elapsed (negative = no limit). Returns WR_OK if stop fired, WR_E_TIMEOUT on timeout, or the
 * fatal status. stop is the place to call wr_client_next_event / wr_client_mapmsg_peek.
 */
wr_status wrl_loop_run(wrl_loop *l, int (*stop)(void *arg), void *arg, int timeout_ms);

/* Sockets currently held (connecting or connected). For diagnostics and leak checks in tests. */
unsigned wrl_loop_open_sockets(const wrl_loop *l);

#endif /* WRL_HOST_H */
