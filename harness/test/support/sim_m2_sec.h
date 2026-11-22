/* SPDX-License-Identifier: MIT */
/*
 * sim_m2_sec.h - the secure-mode peer of the test servers (harness code, libc allowed, never part of the core).
 *
 * Written from docs/spec/msgr2-secure-mode.md (2.5 to 2.8, 3.3, 3.4, 5.2) with the independent AES-GCM of ref_gcm.h and
 * nothing from core/ but the status codes of wr_err.h: not a helper, not the CRC. (The test servers around it still use the core's plain
 * frame layer for the crc handshake, as before; once AUTH_DONE has switched a conversation to secure, every byte in both
 * directions goes through this file.)
 *
 * Three layers, each usable without the others:
 *
 *   1. The secret and the streams. sim_sec_slice() cuts a connection secret as 2.6 says (key = S[0..15], seed A =
 *      S[16..27], seed B = S[28..39]); sim_sec_ctx_init() builds the two directions of one side: the client sends with seed B
 *      and receives with seed A, the server (`server` = 1, "crossed") the other way round. One key, two nonce streams; a
 *      nonce is stepped after every GCM operation (rev 1: the little-endian 64-bit counter in bytes 4..11, no carry).
 *
 *   2. The encoder, sim_sec_encode(): any frame shape (1 to 4 segments, any lengths, one to three GCM operations, empty
 *      segment 0, 4 MiB data segments) into the exact wire bytes. A sim_sec_mut describes a deliberate defect: some are put
 *      into the PLAINTEXT before encryption, so the tag is right and the receiver has to catch them behind the tag (a
 *      wrong preamble CRC, the compressed flag, nseg 0 or 5, a bad epilogue nibble, garbage padding, late_status = 1, a
 *      lying length); some change the key or the nonce of an operation (a repeated nonce, a skipped one, a wrong key); some
 *      are applied to the finished bytes (one bit flipped in part N at byte K, a tag that belongs to other data, a frame cut
 *      at byte N).
 *
 *   3. The decoder, sim_sec_dec: bytes in (any chunking, one byte at a time included), whole frames out. It decrypts part
 *      by part in the order of the wire, takes one nonce per part, verifies each tag BEFORE it looks at the plaintext, then
 *      checks the preamble with the rules of the spec (CRC seed 0, tag 1..22, nseg 1..4, flags and reserved byte zero,
 *      unused slots zero, last segment non-empty when there are several, lengths against the caps, late_status 0x1 or 0xe)
 *      and ignores the padding. An error is sticky and says which rule broke.
 *
 * sim_sec_log keeps every secret a simulator issued, so a test can check that every connection got its own.
 *
 * Speed is a non-goal (ref_gcm does about 1 MB/s): keep bulk frames to what a test needs.
 */
#ifndef SIM_M2_SEC_H
#define SIM_M2_SEC_H

#include <stddef.h>
#include <stdint.h>

#include "ref_gcm.h"
#include "wr_err.h"

#define SIM_SEC_KEY 16u
#define SIM_SEC_NONCE 12u
#define SIM_SEC_TAG 16u
#define SIM_SEC_BLOCK 16u
#define SIM_SEC_PRE 32u        /* the preamble */
#define SIM_SEC_INLINE 48u     /* bytes of segment 0 that travel in part 1 */
#define SIM_SEC_P1_PLAIN 80u   /* preamble + inline */
#define SIM_SEC_P1_WIRE 96u    /* + tag */
#define SIM_SEC_EPI 16u        /* the epilogue block */
#define SIM_SEC_SECRET_LEN 64u /* what a server issues */
#define SIM_SEC_SECRET_MIN 40u /* what the slicing needs */
#define SIM_SEC_SECRET_MAX 128u
#define SIM_SEC_MAX_SEG 4u
#define SIM_SEC_TAG_MAX 22u    /* highest frame tag of the spec (COMPRESSION_DONE) */
#define SIM_SEC_LATE_COMPLETE 0x0eu
#define SIM_SEC_LATE_ABORTED 0x01u

/* ---- 1. the secret and the two nonce streams ------------------------------------------------------------------- */

/* One direction of one side: the key schedule, the nonce seed it started from and the IV of the next operation. */
typedef struct sim_sec_dir {
	ref_gcm_key gk;
	uint8_t key[SIM_SEC_KEY];
	uint8_t seed[SIM_SEC_NONCE];
	uint8_t nonce[SIM_SEC_NONCE]; /* the IV the next operation uses */
	uint64_t ops;                 /* operations done in this direction */
	uint8_t keyed;
} sim_sec_dir;

typedef struct sim_sec_ctx {
	sim_sec_dir tx, rx;
} sim_sec_ctx;

/* Cut a secret: 0, or -1 when n < SIM_SEC_SECRET_MIN. Any of the outputs may be NULL. */
int sim_sec_slice(const uint8_t *secret, size_t n, uint8_t key[SIM_SEC_KEY], uint8_t seed_a[SIM_SEC_NONCE],
		  uint8_t seed_b[SIM_SEC_NONCE]);
/* The two directions of one side. server = 0: tx seed B, rx seed A (the client, "not crossed"); server = 1: the other way.
 * 0, or -1 for a secret shorter than SIM_SEC_SECRET_MIN (the context is then unusable). */
int sim_sec_ctx_init(sim_sec_ctx *c, const uint8_t *secret, size_t n, int server);
/* One direction from a key and a seed (a test that wants a stream of its own). */
void sim_sec_dir_init(sim_sec_dir *d, const uint8_t key[SIM_SEC_KEY], const uint8_t seed[SIM_SEC_NONCE]);
/* Overwrite the counter (bytes 4..11) of the NEXT nonce; bytes 0..3 stay. The seed is not touched (a refusal "back at the
 * seed" is the core's rule, not this file's). */
void sim_sec_dir_set_counter(sim_sec_dir *d, uint64_t ctr);
uint64_t sim_sec_dir_counter(const sim_sec_dir *d);
/* Step a nonce (revision 1). */
void sim_sec_nonce_step(uint8_t nonce[SIM_SEC_NONCE]);
/* Patch the counters of the two seeds of a secret (seed A is S[16..27], its counter S[20..27]; seed B is S[28..39], its
 * counter S[32..39]): how a test gets a stream that starts near 2^64. */
void sim_sec_secret_set_counters(uint8_t *secret, size_t n, int set_a, uint64_t ctr_a, int set_b, uint64_t ctr_b);
void sim_sec_ctx_wipe(sim_sec_ctx *c);
/* Overwrite n bytes with zeros in a way the compiler may not drop (volatile stores): for every local copy of a key, a secret or
 * plaintext in the simulators and their tests (a plain memset before a free or a return is a dead store the optimiser removes). */
void sim_sec_wipe(void *p, size_t n);

/* The raw CRC-32C update (seed given, no inversion of its own): the preamble uses seed 0. */
uint32_t sim_sec_crc32c(uint32_t seed, const uint8_t *p, size_t n);

/* ---- the log of issued secrets ------------------------------------------------------------------------------------- */

#define SIM_SEC_LOG_MAX 256u
typedef struct sim_sec_log {
	uint32_t n;                                  /* secrets issued, all of them */
	uint32_t kept;                               /* the first SIM_SEC_LOG_MAX are kept */
	uint32_t len[SIM_SEC_LOG_MAX];
	uint8_t secret[SIM_SEC_LOG_MAX][SIM_SEC_SECRET_MAX];
} sim_sec_log;
void sim_sec_log_add(sim_sec_log *l, const uint8_t *secret, size_t n);
/* 1 when every kept secret differs from every other one (and none is all zero). */
int sim_sec_log_distinct(const sim_sec_log *l);
/* 1 when `secret` (n bytes) is one of the kept ones. */
int sim_sec_log_has(const sim_sec_log *l, const uint8_t *secret, size_t n);

/* ---- 2. the encoder --------------------------------------------------------------------------------------------- */

typedef struct sim_sec_spec {
	uint8_t tag;
	unsigned nseg;              /* 1..4 segments given; trailing empty ones are dropped like a sender does (keep at least one) */
	const uint8_t *seg[4];      /* may be NULL for an empty segment */
	uint32_t len[4];
	uint16_t align[4];          /* 0 = the default: 8, 8, 8, 4096 */
} sim_sec_spec;

/* sim_sec_mut.mask bits. Everything is off at zero. */
#define SIM_SEC_M_LATE 0x0001u       /* epilogue byte 0 = late_status (only a frame with several segments has an epilogue) */
#define SIM_SEC_M_FLAGS 0x0002u      /* preamble byte 26 = pre_flags (1 = the compressed flag) */
#define SIM_SEC_M_RESERVED 0x0004u   /* preamble byte 27 = pre_reserved */
#define SIM_SEC_M_PRE_NSEG 0x0008u   /* preamble byte 1 = pre_nseg (the segments that follow are the real ones) */
#define SIM_SEC_M_PRE_TAG 0x0010u    /* preamble byte 0 = pre_tag */
#define SIM_SEC_M_PRE_LEN 0x0020u    /* the segments in pre_len_mask (bit i = segment i) are announced with pre_len[i] */
#define SIM_SEC_M_PRE_CRC 0x0040u    /* the preamble CRC is wrong (byte 0 xor pre_crc_xor, 1 when that is 0) */
#define SIM_SEC_M_PAD 0x0080u        /* every padding byte (part 1 fill, part 2 and 3 padding, epilogue bytes 1..15) = pad_fill */
#define SIM_SEC_M_SLOT 0x0100u       /* the first unused segment slot of the preamble holds slot_junk (the length field's first byte) */
#define SIM_SEC_M_KEEP_TAIL 0x0200u  /* do not drop trailing empty segments (an empty last segment on the wire) */
#define SIM_SEC_M_NONCE 0x0400u      /* the nonce_part-th GCM operation of the frame (1 = the first, whichever part that is) uses counter + nonce_delta
				      * (-1 repeats the last nonce, +1 skips one); the stream itself steps normally */
#define SIM_SEC_M_KEY 0x0800u        /* the whole frame is sealed under a key one bit off */
#define SIM_SEC_M_FLIP 0x1000u       /* one bit of the finished bytes: part flip_part, byte flip_byte of its wire bytes, bit flip_bit */
#define SIM_SEC_M_TAG 0x2000u        /* the tag of part tag_part is a valid tag over different data (the ciphertext is right) */
#define SIM_SEC_M_TRUNC 0x4000u      /* only the first truncate_at bytes of the frame are produced */

/* flip_region: where flip_byte counts from. */
#define SIM_SEC_R_RAW 0u       /* byte flip_byte of the part's wire bytes (ciphertext, then its tag) */
#define SIM_SEC_R_TAG 1u       /* byte flip_byte of the part's tag */
#define SIM_SEC_R_EPILOGUE 2u  /* byte flip_byte of the epilogue block's ciphertext (part 3 only) */

typedef struct sim_sec_mut {
	uint32_t mask;
	uint8_t late_status;
	uint8_t pre_flags, pre_reserved, pre_nseg, pre_tag, pre_crc_xor, slot_junk, pad_fill;
	uint8_t pre_len_mask;
	uint32_t pre_len[4];
	int32_t nonce_delta;
	uint8_t nonce_part;       /* the operation number 1..3 (0 = 1); counts operations, a frame without part 2 has operations 1 = part 1 and 2 = part 3;
				   * above the frame's number of operations the encoder refuses (-1) */
	uint8_t flip_part;        /* the part 1..3 (part 2 = the rest of segment 0, part 3 = segments 1.. and the epilogue; both only when the frame has them) */
	uint8_t flip_region;      /* SIM_SEC_R_* */
	uint8_t flip_bit;         /* 0..7 */
	uint8_t tag_part;         /* the part 1..3, as flip_part */
	uint32_t flip_byte;
	uint32_t truncate_at;
} sim_sec_mut;

/* The pieces, for a caller that wants control of the PLAINTEXT of every part (a fuzzer that chooses the bytes of the preamble and of each
 * segment, a test that builds a frame the encoder would refuse): the 32-byte preamble of a spec with a mutation applied and its CRC
 * computed, and one GCM operation by hand. A frame is then part 1 = seal(preamble || 48 inline bytes), part 2 = seal(...), part 3 =
 * seal(padded segments || epilogue), each with the next nonce in wire order. */
void sim_sec_preamble(const sim_sec_spec *f, const sim_sec_mut *m, uint8_t pre[SIM_SEC_PRE]);
/* Seal n plaintext bytes with the next nonce of tx (stepped, ops counted); out gets n ciphertext bytes then the tag (n + 16 bytes; in == out is
 * allowed). 0, or -1 when tx is not keyed. */
int sim_sec_seal(sim_sec_dir *tx, const uint8_t *plain, size_t n, uint8_t *out);

/* The wire bytes of a well-formed frame of this shape (trailing empty segments dropped), 0 for a bad shape; *nops = GCM
 * operations (1, 2 or 3), *parts = the wire bytes of each (parts may be NULL). */
size_t sim_sec_frame_len(const sim_sec_spec *f, unsigned *nops, size_t parts[3]);
/* The same for the frame that sim_sec_encode(f, m) builds: with SIM_SEC_M_KEEP_TAIL the empty trailing segments stay, and a frame that
 * would have had one segment gets an epilogue and a third operation (32 bytes more). m may be NULL (= sim_sec_frame_len). Every other
 * mutation leaves the size alone (a truncated frame is shorter: its length is what the caller gets in *n of the encoder). */
size_t sim_sec_frame_len_m(const sim_sec_spec *f, const sim_sec_mut *m, unsigned *nops, size_t parts[3]);
/* Encode one frame with the next nonces of `tx` (one per operation, stepped after each). m may be NULL. out must hold
 * sim_sec_frame_len_m(f, m) bytes (sim_sec_frame_len() is enough for every mutation but KEEP_TAIL). *n gets the bytes produced. 0, or -1
 * for a bad shape, a buffer too small, a mutation that names a part (flip_part, tag_part, nonce_part) the frame does not have, or out of
 * memory: the stream is then exactly as it was before the call (nonce and operation count are restored; nothing is stepped). */
int sim_sec_encode(sim_sec_dir *tx, const sim_sec_spec *f, const sim_sec_mut *m, uint8_t *out, size_t cap, size_t *n);

/* ---- 3. the decoder -------------------------------------------------------------------------------------------------- */

typedef struct sim_sec_frame {
	uint8_t tag, nseg, flags, reserved;
	uint16_t align[4];
	uint32_t len[4];
	const uint8_t *seg[4];     /* plaintext, cut to len[i]; valid until the next call of the decoder (never NULL for a used segment) */
	uint8_t late_status;       /* the epilogue's byte 0 (0 when the frame has no epilogue) */
	uint8_t pre[SIM_SEC_PRE];  /* the decrypted preamble, as sent */
	unsigned ops;              /* GCM operations the frame took */
	size_t wire;               /* wire bytes of the frame */
} sim_sec_frame;

#define SIM_SEC_DEC_NEED 0     /* not enough bytes for the next step */
#define SIM_SEC_DEC_FRAME 1
#define SIM_SEC_DEC_ABORTED 2  /* a complete frame with late_status 0x1: the content must be dropped */
#define SIM_SEC_DEC_ERROR (-1)

typedef struct sim_sec_dec {
	sim_sec_dir *rx;           /* borrowed: the direction this decoder reads */
	uint32_t cap0, capn;       /* segment length caps (segment 0, the others); 0 = 1 GiB */
	uint8_t *in;               /* unconsumed input */
	size_t in_cap, in_head, in_len;
	uint8_t *out;              /* the plaintext of the frame being built / last returned */
	size_t out_cap;
	int state;
	/* the frame being read */
	sim_sec_frame f;
	uint8_t inline_[SIM_SEC_INLINE];
	uint64_t pad[4];
	size_t seg_off[4];         /* offset of each segment in `out` */
	size_t consumed;
	/* the verdict */
	wr_status err;             /* sticky: WR_E_M2_SEC_TAG, _FRAME_CRC, _FRAME_FORM, _FRAME_TOOBIG, _TAG, WR_E_NOMEM-like WR_E_BUDGET */
	const char *why;
	uint64_t n_frames;
} sim_sec_dec;

void sim_sec_dec_init(sim_sec_dec *d, sim_sec_dir *rx, uint32_t cap0, uint32_t capn);
void sim_sec_dec_free(sim_sec_dec *d);
/* Append bytes; 0, or -1 when out of memory. */
int sim_sec_dec_feed(sim_sec_dec *d, const uint8_t *p, size_t n);
/* Advance as far as the buffered bytes allow. FRAME / ABORTED fill *f (valid until the next call), ERROR is sticky (d->err,
 * d->why), NEED means feed more. */
int sim_sec_dec_next(sim_sec_dec *d, sim_sec_frame *f);
/* Bytes fed and not yet consumed by a finished part. */
size_t sim_sec_dec_buffered(const sim_sec_dec *d);
/* Take the unconsumed bytes out of the decoder (a switch back to another parser); returns how many were copied. */
size_t sim_sec_dec_take(sim_sec_dec *d, uint8_t *out, size_t cap);

/* ---- the faults of a simulated server in secure mode ------------------------------------------------------------------ */

/* Lives in sim_m2_fault.sec (one set per connection, so a monitor plan or an OSD connection can carry them). Zero = off. */
typedef struct sim_sec_fault {
	sim_sec_mut mut;          /* applied to the server frame whose 1-based number (sim_m2.n_tx_frames) is mut_frame */
	uint32_t mut_frame;       /* 0 = off */
	uint8_t mut_close;        /* after a frame cut by M_TRUNC the server closes (EOF) instead of just stalling */
	uint8_t wrong_seed_tx;    /* the server sends with the seed the client sends with (not crossed) */
	uint8_t wrong_seed_rx;    /* the server reads with the seed the client reads with */
	uint8_t wrong_key_tx;     /* every secure frame of the server is sealed under a key one bit off */
	uint8_t omit_secret;      /* secure was negotiated, but no secret goes into the auth payload (empty cbl, OSD reply v1); the server stays plain */
	uint8_t secret_in_crc;    /* crc was negotiated and a secret goes into the auth payload anyway */
	uint32_t secret_len;      /* 0 = 64; above SIM_SEC_SECRET_MAX is cut to it; below 40 the server cannot slice it and stays plain */
	uint8_t has_ctr_a, has_ctr_b; /* patch the issued secret: the counters of seed A / seed B */
	uint64_t ctr_a, ctr_b;
} sim_sec_fault;

/* Secret generation of a server connection (sim_m2_cfg.sec). */
typedef struct sim_sec_cfg {
	uint64_t seed;                         /* 0 = the simulator picks one; every connection of a monitor / OSD gets its own */
	uint8_t issue_at_done;                 /* 1: a server whose auth callbacks never ask for the secret (the scripted ones of sim_m2.h) still goes
						* secure after an AUTH_DONE with mode secure, with a secret issued at that moment; 0 (the default, and what
						* it always was): such a server stops reading, "secure mode is not simulated". The cephx callbacks of
						* sim_mon and sim_osd ask for the secret, so they need neither. */
	uint8_t fixed_len;                     /* != 0: this secret (fixed_len bytes, at most SIM_SEC_SECRET_MAX: more is cut) instead of a random one,
						* every time */
	uint8_t fixed[SIM_SEC_SECRET_MAX];
} sim_sec_cfg;

#endif /* SIM_M2_SEC_H */
