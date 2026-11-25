/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the rBFT handoff table codec (core/src/handoff).
 *
 * Byte 0 selects the mode, the rest is the payload (an exact-size heap copy, so ASan sees any over-read):
 *
 *   mode % 4 == 0  the payload is a body: decode; on success the encoder must write the same bytes back (the decoder takes
 *                  one canonical form only), the second decode must agree, the strings and the key must lie inside the input;
 *                  on failure the output structure must be all zero
 *   mode % 4 == 1  the payload is a whole ACPI table: decode_table; on success the body re-encodes to the same bytes
 *   mode % 4 == 2  the payload is a body that gets a valid ACPI header (length, checksum) so the fuzzer reaches the body
 *                  parser through the table entry point; the verdicts that depend only on the length are checked
 *   mode % 4 == 3  the payload is turned into a description (half of the time forced valid): encode must give a defined status,
 *                  write nothing on a refusal, give the same bytes twice, and the result must decode to the same description
 *
 * A violated property traps.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wr_config.h"
#include "wr_handoff.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

static uint8_t *heap_copy(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n ? n : 1);

	if (q != NULL && n != 0)
		memcpy(q, p, n);
	return q;
}

static int is_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t k;

	for (k = 0; k < n; k++)
		if (b[k] != 0)
			return 0;
	return 1;
}

static int inside(const void *p, const uint8_t *base, size_t n)
{
	const uint8_t *q = (const uint8_t *)p;

	return q >= base && q < base + n;
}

/* the strings and the key of a decoded description point into the decoded bytes */
static void check_pointers(const wr_handoff_info *d, const uint8_t *base, size_t n)
{
	const char *s[6];
	size_t k;

	s[0] = d->entity;
	s[1] = d->pool;
	s[2] = d->rbd_namespace;
	s[3] = d->image;
	s[4] = d->image_id;
	s[5] = d->snapshot;
	for (k = 0; k < 6; k++)
		check(s[k] == NULL || inside(s[k], base, n));
	check(d->pool != NULL && d->image != NULL);
	check((d->key != NULL) == ((d->flags & WR_HANDOFF_F_KEY) != 0));
	check(d->key == NULL || (inside(d->key, base, n) && inside(d->key + d->key_len - 1, base, n)));
}

static void fuzz_body(const uint8_t *p, size_t n)
{
	uint8_t *buf = heap_copy(p, n);
	uint8_t out[WR_HANDOFF_MAX_TABLE];
	wr_handoff_info d, d2;
	size_t len = 0;
	wr_status st;

	if (buf == NULL)
		return;
	st = wr_handoff_decode(buf, n, &d);
	check(st == wr_handoff_decode(buf, n, NULL));
	if (st == WR_OK) {
		check(n >= WR_HANDOFF_FIXED_LEN && n <= WR_HANDOFF_MAX_BODY);
		check_pointers(&d, buf, n);
		check(wr_handoff_encode(&d, out, sizeof(out), &len) == WR_OK);
		check(len == n && memcmp(out, buf, n) == 0);
		check(wr_handoff_decode(out, len, &d2) == WR_OK);
		check(d2.flags == d.flags && d2.mon_count == d.mon_count && d2.key_len == d.key_len);
	} else {
		check(is_zero(&d, sizeof(d)));
	}
	free(buf);
}

static void fuzz_table(const uint8_t *p, size_t n)
{
	uint8_t *buf = heap_copy(p, n);
	uint8_t out[WR_HANDOFF_MAX_TABLE];
	wr_handoff_info d;
	size_t len = 0, tlen;
	wr_status st;

	if (buf == NULL)
		return;
	st = wr_handoff_decode_table(buf, n, &d);
	if (st == WR_OK) {
		tlen = (size_t)buf[4] | ((size_t)buf[5] << 8) | ((size_t)buf[6] << 16) | ((size_t)buf[7] << 24);
		check(tlen >= WR_HANDOFF_ACPI_HDR_LEN + WR_HANDOFF_FIXED_LEN && tlen <= WR_HANDOFF_MAX_TABLE && tlen <= n);
		check_pointers(&d, buf, n);
		check(wr_handoff_encode_table(&d, out, sizeof(out), &len) == WR_OK);
		check(len == tlen);
		/* the OEM fields (and so the checksum byte) are the host's: signature, length, revision and the body are what the encoder writes */
		check(memcmp(out + WR_HANDOFF_ACPI_HDR_LEN, buf + WR_HANDOFF_ACPI_HDR_LEN, tlen - WR_HANDOFF_ACPI_HDR_LEN) == 0);
		check(memcmp(out, buf, 9) == 0);
	} else {
		check(is_zero(&d, sizeof(d)));
	}
	free(buf);
}

static void fuzz_wrapped(const uint8_t *p, size_t n)
{
	uint8_t hdr[WR_HANDOFF_ACPI_HDR_LEN];
	uint8_t *buf;
	size_t total = WR_HANDOFF_ACPI_HDR_LEN + n, k;
	wr_status st;
	wr_handoff_info d;

	if (n > 2048)
		return;
	buf = (uint8_t *)malloc(total);
	if (buf == NULL)
		return;
	memset(hdr, 0, sizeof(hdr));
	memcpy(hdr, "rBFT", 4);
	hdr[4] = (uint8_t)(total & 0xff);
	hdr[5] = (uint8_t)((total >> 8) & 0xff);
	hdr[8] = 1;
	memcpy(buf, hdr, sizeof(hdr));
	if (n != 0)
		memcpy(buf + sizeof(hdr), p, n);
	if (total <= WR_HANDOFF_MAX_TABLE)
		check(wr_handoff_fix_checksum(buf, total) == WR_OK);
	st = wr_handoff_decode_table(buf, total, &d);
	if (total < WR_HANDOFF_ACPI_HDR_LEN + WR_HANDOFF_FIXED_LEN)
		check(st == WR_E_HO_LENGTH);
	else if (total > WR_HANDOFF_MAX_TABLE)
		check(st == WR_E_HO_TOO_BIG);
	else /* the header is right: what is left to refuse is the body (its own signature, version and length fields included) */
		check(st != WR_E_HO_CHECKSUM && st != WR_E_TRUNCATED);
	if (st == WR_OK) {
		/* the body of the table is what decode accepts on its own */
		check(wr_handoff_decode(buf + WR_HANDOFF_ACPI_HDR_LEN, n, NULL) == WR_OK);
		check_pointers(&d, buf, total);
	}
	/* one flipped bit anywhere is never accepted */
	if (st == WR_OK && total <= WR_HANDOFF_MAX_TABLE) {
		k = (size_t)p[n - 1] % total;
		buf[k] = (uint8_t)(buf[k] ^ (1u << (p[0] % 8u)));
		check(wr_handoff_decode_table(buf, total, NULL) != WR_OK);
	}
	free(buf);
}

/* ---- mode 3: a description from the bytes ---------------------------------------------------------- */

typedef struct src {
	const uint8_t *p;
	size_t n, pos;
} src;

static uint8_t take(src *s)
{
	return s->pos < s->n ? s->p[s->pos++] : 0;
}

static uint16_t take16(src *s)
{
	uint16_t lo = take(s);

	return (uint16_t)(lo | (uint16_t)(take(s) << 8));
}

static const char *take_str(src *s, char *buf, int maybe_long)
{
	uint8_t sel = take(s);
	size_t len = sel % 24u, k;

	if (maybe_long && (sel & 0x80u) != 0)
		len = 250u + sel % 8u;
	for (k = 0; k < len; k++)
		buf[k] = (char)('a' + take(s) % 26u);
	buf[len] = '\0';
	return buf;
}

static void fuzz_info(const uint8_t *p, size_t n)
{
	src s;
	static char strs[6][300];
	wr_handoff_info i;
	uint8_t key[64 + 8], t1[WR_HANDOFF_MAX_TABLE + 64], t2[WR_HANDOFF_MAX_TABLE + 64], clean[WR_HANDOFF_MAX_TABLE + 64];
	uint8_t sane;
	size_t k, len1 = 0, len2 = 0, b;
	wr_status st;

	s.p = p;
	s.n = n;
	s.pos = 0;
	memset(&i, 0, sizeof(i));
	sane = take(&s) & 1u;
	i.flags = take(&s);
	i.flags |= (uint32_t)(take(&s) & 1u) << 31;
	i.auth = take(&s) % 3u;
	i.msgr_mode = take(&s) % 6u;
	i.key_type = take(&s) % 4u;
	i.key_len = take(&s) % 72u;
	i.mon_count = take(&s) % 10u;
	i.nic_family = take(&s) % 8u;
	i.nic_prefix = (uint8_t)(take(&s) % 140u);
	i.nic_vlan = take16(&s);
	i.nic_mtu = take16(&s);
	for (k = 0; k < 16; k++) {
		i.fsid[k] = take(&s);
		i.nic_ip[k] = take(&s);
		i.nic_gateway[k] = take(&s);
		i.nic_dns[k] = take(&s);
	}
	for (k = 0; k < 6; k++)
		i.nic_mac[k] = take(&s);
	for (k = 0; k < WR_HANDOFF_MAX_MONS; k++) {
		i.mons[k].family = take(&s) % 7u;
		i.mons[k].port = take16(&s);
		for (b = 0; b < 16; b++)
			i.mons[k].ip[b] = take(&s);
		i.mons[k].nonce = take(&s);
	}
	for (k = 0; k < sizeof(key); k++)
		key[k] = take(&s);
	i.key = key;
	i.entity = take_str(&s, strs[0], !sane);
	i.pool = take_str(&s, strs[1], !sane);
	i.rbd_namespace = take_str(&s, strs[2], 0);
	i.image = take_str(&s, strs[3], !sane);
	i.image_id = take_str(&s, strs[4], 0);
	i.snapshot = take_str(&s, strs[5], 0);
	if (sane) {
		/* force every rule of wr_handoff_info; what is left to vary is the content and the size */
		i.flags &= WR_HANDOFF_F_ALL;
		i.auth = WR_HANDOFF_AUTH_CEPHX;
		i.msgr_mode = (uint8_t)(1u + i.msgr_mode % 4u);
		if (i.msgr_mode != WR_MODE_SECURE_ONLY)
			i.flags &= ~(uint32_t)WR_HANDOFF_F_SECURE_REQUIRED;
		if ((i.flags & WR_HANDOFF_F_KEY) != 0) {
			i.key_type = (uint8_t)(1u + i.key_type % 2u);
			i.key_len = (uint8_t)(i.key_type == WR_KEY_TYPE_AES ? WR_HANDOFF_KEY_MIN_AES : WR_HANDOFF_KEY_MIN_AES256K);
			i.key_len = (uint8_t)(i.key_len + take(&s) % (WR_HANDOFF_KEY_MAX - i.key_len + 1u));
		} else {
			i.key_type = 0;
			i.key_len = 0;
		}
		i.mon_count = (uint8_t)(1u + i.mon_count % 8u);
		for (k = 0; k < WR_HANDOFF_MAX_MONS; k++) {
			i.mons[k].family = (i.mons[k].family & 1u) ? WR_AF_IPV4 : WR_AF_IPV6;
			if (i.mons[k].port == 0)
				i.mons[k].port = 3300;
			if (i.mons[k].family == WR_AF_IPV4)
				memset(i.mons[k].ip + 4, 0, 12);
		}
		i.nic_family = i.nic_family % 3u == 0 ? 0 : (uint8_t)((i.nic_family & 1u) ? 4 : 6);
		if (i.nic_family == 0) {
			i.nic_prefix = 0;
			i.flags &= ~(uint32_t)WR_HANDOFF_F_NIC_STATIC;
			memset(i.nic_ip, 0, 16);
			memset(i.nic_gateway, 0, 16);
			memset(i.nic_dns, 0, 16);
		} else if (i.nic_family == 4) {
			i.nic_prefix = (uint8_t)(i.nic_prefix % 33u);
			memset(i.nic_ip + 4, 0, 12);
			memset(i.nic_gateway + 4, 0, 12);
			memset(i.nic_dns + 4, 0, 12);
		} else {
			i.nic_prefix = (uint8_t)(i.nic_prefix % 129u);
		}
		if ((i.flags & WR_HANDOFF_F_VLAN) != 0)
			i.nic_vlan = (uint16_t)(1u + i.nic_vlan % 4094u);
		else
			i.nic_vlan = 0;
		if ((i.flags & WR_HANDOFF_F_FSID) == 0)
			memset(i.fsid, 0, 16);
		i.rbd_namespace = NULL;
		if (i.entity[0] == '\0')
			i.entity = "u";
		if (i.pool[0] == '\0')
			i.pool = "p";
		if (i.image[0] == '\0')
			i.image = "i";
	}

	memset(t1, 0xA5, sizeof(t1));
	memset(clean, 0xA5, sizeof(clean));
	st = wr_handoff_encode_table(&i, t1, sizeof(t1), &len1);
	if (st != WR_OK) {
		check(st == WR_E_HO_FIELD || st == WR_E_UNSUPPORTED || st == WR_E_HO_TOO_BIG);
		check(memcmp(t1, clean, sizeof(t1)) == 0);
		if (sane)
			check(st == WR_E_HO_TOO_BIG);
		check((st == WR_E_HO_TOO_BIG) ? len1 > WR_HANDOFF_MAX_TABLE : len1 == 0);
		return;
	}
	check(len1 >= WR_HANDOFF_ACPI_HDR_LEN + WR_HANDOFF_FIXED_LEN && len1 <= WR_HANDOFF_MAX_TABLE);
	/* the same bytes again, from a different dirty buffer */
	memset(t2, 0x5A, sizeof(t2));
	check(wr_handoff_encode_table(&i, t2, sizeof(t2), &len2) == WR_OK);
	check(len1 == len2 && memcmp(t1, t2, len1) == 0);
	/* it decodes, and decodes to the description that was encoded */
	{
		uint8_t *e = heap_copy(t1, len1);
		wr_handoff_info d;
		uint8_t back[WR_HANDOFF_MAX_TABLE];
		size_t bl = 0;

		if (e == NULL)
			return;
		check(wr_handoff_decode_table(e, len1, &d) == WR_OK);
		check(d.flags == i.flags && d.auth == i.auth && d.msgr_mode == i.msgr_mode && d.mon_count == i.mon_count);
		check(d.key_len == i.key_len && d.key_type == i.key_type && d.nic_vlan == i.nic_vlan);
		check(memcmp(d.fsid, i.fsid, 16) == 0 && memcmp(d.nic_ip, i.nic_ip, 16) == 0);
		check(strcmp(d.pool, i.pool) == 0 && strcmp(d.image, i.image) == 0);
		check((d.entity == NULL) == (i.entity[0] == '\0') && (d.entity == NULL || strcmp(d.entity, i.entity) == 0));
		check((d.key == NULL) == ((i.flags & WR_HANDOFF_F_KEY) == 0));
		check(d.key == NULL || memcmp(d.key, i.key, i.key_len) == 0);
		for (k = 0; k < i.mon_count; k++)
			check(d.mons[k].family == i.mons[k].family && d.mons[k].port == i.mons[k].port && d.mons[k].nonce == 0 &&
			      memcmp(d.mons[k].ip, i.mons[k].ip, 16) == 0);
		check(wr_handoff_encode_table(&d, back, sizeof(back), &bl) == WR_OK && bl == len1 && memcmp(back, t1, len1) == 0);
		/* one byte too little room: refused, nothing written */
		memset(t2, 0x5A, sizeof(t2));
		check(wr_handoff_encode_table(&i, t2, len1 - 1, &len2) == WR_E_TOOBIG && len2 == len1);
		check(t2[0] == 0x5A && t2[len1 - 2] == 0x5A);
		free(e);
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0)
		return 0;
	switch (data[0] % 4u) {
	case 0:
		fuzz_body(data + 1, size - 1);
		break;
	case 1:
		fuzz_table(data + 1, size - 1);
		break;
	case 2:
		if (size > 1)
			fuzz_wrapped(data + 1, size - 1);
		break;
	default:
		fuzz_info(data + 1, size - 1);
		break;
	}
	return 0;
}
