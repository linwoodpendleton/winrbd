/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of the rBFT handoff table codec (core/src/handoff, wr_handoff.h):
 *   - the byte layout of one table, checked field by field against the design document (independent of the vector file)
 *   - a round trip of every field, for hand-made and for pseudo-random descriptions
 *   - the encoder is a pure function: two encodes (and an encode into a dirty buffer, and an encode of a description
 *     with garbage in the unused parts) give the same bytes
 *   - the size cap: 1,024 bytes fit, 1,025 are refused, nothing is truncated, nothing is written on a refusal
 *   - every refusal of the encoder and of the decoder, the key only with its flag
 *   - truncation at every length, a single flipped bit anywhere (caught by the checksum), random damage that keeps the
 *     checksum valid (the decoder accepts only what the encoder would write back byte for byte)
 *   - the OEM fields of a host and the checksum fix, trailing bytes in a BIOS scan buffer, the statuses' texts
 * The golden vectors are in test_handoff_vec.c.
 */
#include "wrt.h"
#include "wr_handoff.h"
#include "wr_key.h"

#define BUFSZ 2048u

/* ---- descriptions ---------------------------------------------------------------------------------- */

static void set_mon4(wr_addr *a, uint8_t last, uint16_t port)
{
	memset(a, 0, sizeof(*a));
	a->family = WR_AF_IPV4;
	a->ip[0] = 10;
	a->ip[1] = 77;
	a->ip[3] = last;
	a->port = port;
}

static const uint8_t k32[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
				17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

/* The typical table: three IPv4 monitors, DHCP NIC, no key. */
static void typical(wr_handoff_info *i)
{
	memset(i, 0, sizeof(*i));
	i->auth = WR_HANDOFF_AUTH_CEPHX;
	i->msgr_mode = WR_MODE_CRC_ONLY;
	i->mon_count = 3;
	set_mon4(&i->mons[0], 10, 3300);
	set_mon4(&i->mons[1], 11, 3300);
	set_mon4(&i->mons[2], 12, 6789);
	i->nic_family = 4;
	i->nic_prefix = 24;
	i->nic_mtu = 1500;
	i->nic_mac[0] = 0x52;
	i->nic_mac[1] = 0x54;
	i->nic_mac[5] = 0x56;
	i->nic_ip[0] = 10;
	i->nic_ip[1] = 77;
	i->nic_ip[3] = 50;
	i->nic_gateway[0] = 10;
	i->nic_gateway[1] = 77;
	i->nic_gateway[3] = 1;
	i->nic_dns[0] = 10;
	i->nic_dns[1] = 77;
	i->nic_dns[3] = 2;
	i->entity = "winrbd-boot";
	i->pool = "winrbd";
	i->image = "boot-win11";
}

static void with_key(wr_handoff_info *i, unsigned type, size_t n)
{
	i->flags |= WR_HANDOFF_F_KEY;
	i->key_type = (uint8_t)type;
	i->key_len = (uint8_t)n;
	i->key = k32; /* only the first n bytes are read; n <= 32 in this helper */
}

static void check_same(const wr_handoff_info *got, const wr_handoff_info *want)
{
	size_t k;
	int mons = 1;

	WRT_CHECK_U64(got->flags, want->flags);
	WRT_CHECK_U64(got->auth, want->auth);
	WRT_CHECK_U64(got->msgr_mode, want->msgr_mode);
	WRT_CHECK_U64(got->key_type, want->key_type);
	WRT_CHECK_U64(got->key_len, want->key_len);
	WRT_CHECK_U64(got->mon_count, want->mon_count);
	WRT_CHECK_U64(got->nic_family, want->nic_family);
	WRT_CHECK_U64(got->nic_prefix, want->nic_prefix);
	WRT_CHECK_U64(got->nic_vlan, want->nic_vlan);
	WRT_CHECK_U64(got->nic_mtu, want->nic_mtu);
	WRT_CHECK_MEM(got->fsid, want->fsid, sizeof(want->fsid));
	WRT_CHECK_MEM(got->nic_mac, want->nic_mac, sizeof(want->nic_mac));
	WRT_CHECK_MEM(got->nic_ip, want->nic_ip, sizeof(want->nic_ip));
	WRT_CHECK_MEM(got->nic_gateway, want->nic_gateway, sizeof(want->nic_gateway));
	WRT_CHECK_MEM(got->nic_dns, want->nic_dns, sizeof(want->nic_dns));
#define SAME_STR(f)                                                                               \
	WRT_CHECK((got->f == NULL) == (want->f == NULL || want->f[0] == '\0') &&                  \
		  (got->f == NULL || strcmp(got->f, want->f) == 0))
	SAME_STR(entity);
	SAME_STR(pool);
	SAME_STR(rbd_namespace);
	SAME_STR(image);
	SAME_STR(image_id);
	SAME_STR(snapshot);
#undef SAME_STR
	for (k = 0; k < want->mon_count && k < WR_HANDOFF_MAX_MONS; k++)
		if (got->mons[k].family != want->mons[k].family || got->mons[k].port != want->mons[k].port ||
		    got->mons[k].nonce != 0 || memcmp(got->mons[k].ip, want->mons[k].ip, 16) != 0)
			mons = 0;
	WRT_CHECK(mons);
	if ((want->flags & WR_HANDOFF_F_KEY) != 0)
		WRT_CHECK(got->key != NULL && memcmp(got->key, want->key, want->key_len) == 0);
	else
		WRT_CHECK(got->key == NULL);
}

static uint8_t *exact(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n != 0 ? n : 1);

	if (q != NULL && n != 0)
		memcpy(q, p, n);
	return q;
}

static int all_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t k;

	for (k = 0; k < n; k++)
		if (b[k] != 0)
			return 0;
	return 1;
}

/* ---- the layout, byte by byte ---------------------------------------------------------------------- */

static unsigned rd16(const uint8_t *p)
{
	return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void test_layout(void)
{
	wr_handoff_info i;
	uint8_t t[BUFSZ];
	const uint8_t *b, *area;
	size_t len = 0, k;
	uint8_t sum = 0;

	typical(&i);
	i.flags = WR_HANDOFF_F_READONLY | WR_HANDOFF_F_FSID | WR_HANDOFF_F_VLAN | WR_HANDOFF_F_NIC_STATIC;
	i.nic_vlan = 100;
	for (k = 0; k < 16; k++)
		i.fsid[k] = (uint8_t)(0xA0 + k);
	i.image_id = "abc123";
	i.snapshot = "s1";
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, t, sizeof(t), &len));

	/* the ACPI header */
	WRT_CHECK_MEM(t, "rBFT", 4);
	WRT_CHECK_U64(rd32(t + 4), len);
	WRT_CHECK_U64(t[8], 1); /* revision */
	for (k = 0; k < len; k++)
		sum = (uint8_t)(sum + t[k]);
	WRT_CHECK_U64(sum, 0);
	for (k = 10; k < 36; k++)
		WRT_CHECK_U64(t[k], 0); /* the OEM and creator fields are the host's */
	/* the fixed part */
	b = t + 36;
	area = b + 116;
	WRT_CHECK_MEM(b, "WRBT", 4);
	WRT_CHECK_U64(rd16(b + 4), 1);
	WRT_CHECK_U64(rd16(b + 6), 116);
	WRT_CHECK_U64(rd32(b + 8), 0x1d); /* ro, static, vlan, fsid */
	WRT_CHECK_U64(b[12], 1);          /* cephx */
	WRT_CHECK_U64(b[13], WR_MODE_CRC_ONLY);
	WRT_CHECK_U64(b[14], 0);
	WRT_CHECK_U64(b[15], 0);
	WRT_CHECK_U64(b[16], 3);
	WRT_CHECK_U64(b[17], 4);
	WRT_CHECK_U64(b[18], 24);
	WRT_CHECK_U64(b[19], 0);
	WRT_CHECK_U64(b[20], 0xA0);
	WRT_CHECK_U64(b[35], 0xAF);
	WRT_CHECK_U64(b[36], 0x52);
	WRT_CHECK_U64(b[41], 0x56);
	WRT_CHECK_U64(rd16(b + 42), 100);
	WRT_CHECK_U64(rd16(b + 44), 1500);
	WRT_CHECK_U64(rd16(b + 46), 0);
	WRT_CHECK_U64(b[48], 10);
	WRT_CHECK_U64(b[51], 50);
	WRT_CHECK_U64(b[52], 0);
	WRT_CHECK_U64(b[67], 1);
	WRT_CHECK_U64(b[83], 2);
	/* offsets: strings in the order entity, pool, namespace, image, image id, snapshot, then monitors */
	WRT_CHECK_U64(rd16(b + 96), 0);                       /* "winrbd-boot\0" 12 bytes */
	WRT_CHECK_U64(rd16(b + 98), 12);                      /* "winrbd\0" 7 */
	WRT_CHECK_U64(rd16(b + 100), 0xffff);                 /* no namespace */
	WRT_CHECK_U64(rd16(b + 102), 19);                     /* "boot-win11\0" 11 */
	WRT_CHECK_U64(rd16(b + 104), 30);                     /* "abc123\0" 7 */
	WRT_CHECK_U64(rd16(b + 106), 37);                     /* "s1\0" 3 */
	WRT_CHECK_U64(rd16(b + 108), 40);                     /* 3 x 20 */
	WRT_CHECK_U64(rd16(b + 110), 0xffff);                 /* no key */
	WRT_CHECK_U64(rd32(b + 112), 0);
	WRT_CHECK_MEM(area, "winrbd-boot", 12);
	WRT_CHECK_MEM(area + 12, "winrbd", 7);
	WRT_CHECK_MEM(area + 19, "boot-win11", 11);
	WRT_CHECK_MEM(area + 30, "abc123", 7);
	WRT_CHECK_MEM(area + 37, "s1", 3);
	/* a monitor record: family, reserved, port, 16 address bytes */
	WRT_CHECK_U64(area[40], 4);
	WRT_CHECK_U64(area[41], 0);
	WRT_CHECK_U64(rd16(area + 42), 3300);
	WRT_CHECK_U64(area[44], 10);
	WRT_CHECK_U64(area[47], 10);
	WRT_CHECK_U64(area[48], 0);
	WRT_CHECK_U64(rd16(area + 40 + 40 + 2), 6789);
	WRT_CHECK_U64(len, 36u + 116u + 40u + 60u);

	/* with a key: its offset follows the records, its type and length are in the fixed part */
	typical(&i);
	with_key(&i, WR_KEY_TYPE_AES256K, 32);
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, t, sizeof(t), &len));
	b = t + 36;
	WRT_CHECK_U64(rd32(b + 8), WR_HANDOFF_F_KEY);
	WRT_CHECK_U64(b[14], 2);
	WRT_CHECK_U64(b[15], 32);
	WRT_CHECK_U64(rd16(b + 110), 30 + 60);
	WRT_CHECK_MEM(b + 116 + 90, k32, 32);
	WRT_CHECK_U64(len, 36u + 116u + 90u + 32u);
}

/* ---- round trips ---------------------------------------------------------------------------------- */

static void roundtrip(const wr_handoff_info *i)
{
	uint8_t body[BUFSZ], table[BUFSZ], again[BUFSZ];
	size_t bn = 0, tn = 0, an = 0;
	wr_handoff_info d, d2;
	uint8_t *eb, *et;

	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode(i, body, sizeof(body), &bn));
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(i, table, sizeof(table), &tn));
	WRT_CHECK_U64(tn, bn + WR_HANDOFF_ACPI_HDR_LEN);
	WRT_CHECK_MEM(table + WR_HANDOFF_ACPI_HDR_LEN, body, bn);
	eb = exact(body, bn);
	et = exact(table, tn);
	if (eb == NULL || et == NULL) {
		WRT_CHECK(0 && "out of memory");
		free(eb);
		free(et);
		return;
	}
	WRT_CHECK_STATUS(WR_OK, wr_handoff_decode(eb, bn, &d));
	check_same(&d, i);
	WRT_CHECK_STATUS(WR_OK, wr_handoff_decode_table(et, tn, &d2));
	check_same(&d2, i);
	/* what was decoded encodes back to the same bytes */
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode(&d, again, sizeof(again), &an));
	WRT_CHECK(an == bn && memcmp(again, body, bn) == 0);
	free(eb);
	free(et);
}

static void test_roundtrip_hand(void)
{
	wr_handoff_info i;
	size_t k;

	typical(&i);
	roundtrip(&i);

	typical(&i);
	with_key(&i, WR_KEY_TYPE_AES256K, 32);
	i.flags |= WR_HANDOFF_F_READONLY;
	roundtrip(&i);

	typical(&i);
	with_key(&i, WR_KEY_TYPE_AES, 16);
	roundtrip(&i);

	/* eight IPv6 monitors, IPv6 NIC, every optional string, VLAN, fsid, secure required */
	typical(&i);
	i.mon_count = 8;
	for (k = 0; k < 8; k++) {
		memset(&i.mons[k], 0, sizeof(i.mons[k]));
		i.mons[k].family = WR_AF_IPV6;
		i.mons[k].port = (uint16_t)(3300 + k);
		i.mons[k].ip[0] = 0xfd;
		i.mons[k].ip[15] = (uint8_t)(k + 1);
		i.mons[k].nonce = 0x1234; /* not carried */
	}
	i.nic_family = 6;
	i.nic_prefix = 64;
	memset(i.nic_ip, 0xfd, 16);
	memset(i.nic_gateway, 0xfe, 16);
	memset(i.nic_dns, 0xfc, 16);
	i.flags = WR_HANDOFF_F_VLAN | WR_HANDOFF_F_FSID | WR_HANDOFF_F_SECURE_REQUIRED | WR_HANDOFF_F_NIC_STATIC;
	i.msgr_mode = WR_MODE_SECURE_ONLY;
	i.nic_vlan = 4094;
	memset(i.fsid, 0x11, 16);
	i.image_id = "0123456789ab";
	i.snapshot = "snap";
	roundtrip(&i);

	/* no authentication, nothing optional */
	typical(&i);
	i.auth = WR_HANDOFF_AUTH_NONE;
	i.entity = NULL;
	i.nic_family = 0;
	i.nic_prefix = 0;
	memset(i.nic_ip, 0, 16);
	memset(i.nic_gateway, 0, 16);
	memset(i.nic_dns, 0, 16);
	i.mon_count = 1;
	roundtrip(&i);

	/* an entity is allowed (and kept) without cephx; "" is the same as NULL */
	typical(&i);
	i.auth = WR_HANDOFF_AUTH_NONE;
	i.snapshot = "";
	roundtrip(&i);

	/* all four modes */
	for (k = WR_MODE_CRC_ONLY; k <= WR_MODE_SECURE_ONLY; k++) {
		typical(&i);
		i.msgr_mode = (uint8_t)k;
		roundtrip(&i);
	}
	/* strings of 1 and of 255 bytes */
	{
		static char s255[256], s1[2] = "x";

		memset(s255, 'q', 255);
		s255[255] = '\0';
		typical(&i);
		i.pool = s1;
		i.image = s255;
		i.entity = s255;
		roundtrip(&i);
	}
	/* IPv4 monitors may be mixed with IPv6 ones */
	typical(&i);
	i.mons[1].family = WR_AF_IPV6;
	i.mons[1].ip[9] = 9;
	roundtrip(&i);
}

/* xorshift, deterministic */
static uint32_t rnd(uint32_t *s)
{
	uint32_t x = *s;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	*s = x;
	return x;
}

static const char *rnd_str(uint32_t *s, char *buf, size_t maxlen)
{
	size_t n = 1 + rnd(s) % maxlen, k;

	for (k = 0; k < n; k++)
		buf[k] = (char)('a' + rnd(s) % 26);
	buf[n] = '\0';
	return buf;
}

/* A valid description from a seed: every rule of wr_handoff_info holds. */
static void rnd_info(wr_handoff_info *i, uint32_t *s, char strs[6][260], uint8_t keybuf[64])
{
	size_t k;
	unsigned maxlen = (rnd(s) % 4 == 0) ? 255 : 30;

	memset(i, 0, sizeof(*i));
	i->auth = (uint8_t)(rnd(s) % 5 == 0 ? WR_HANDOFF_AUTH_NONE : WR_HANDOFF_AUTH_CEPHX);
	i->msgr_mode = (uint8_t)(1 + rnd(s) % 4);
	i->flags = rnd(s) & (WR_HANDOFF_F_READONLY | WR_HANDOFF_F_FSID | WR_HANDOFF_F_VLAN | WR_HANDOFF_F_NIC_STATIC);
	if (i->msgr_mode == WR_MODE_SECURE_ONLY && rnd(s) % 2 != 0)
		i->flags |= WR_HANDOFF_F_SECURE_REQUIRED;
	i->mon_count = (uint8_t)(1 + rnd(s) % 8);
	for (k = 0; k < i->mon_count; k++) {
		size_t b;

		i->mons[k].family = (uint8_t)(rnd(s) % 2 ? WR_AF_IPV4 : WR_AF_IPV6);
		i->mons[k].port = (uint16_t)(1 + rnd(s) % 65535);
		for (b = 0; b < (i->mons[k].family == WR_AF_IPV4 ? 4u : 16u); b++)
			i->mons[k].ip[b] = (uint8_t)rnd(s);
	}
	i->nic_family = (uint8_t)(rnd(s) % 3 == 0 ? 0 : (rnd(s) % 2 ? 4 : 6));
	if (i->nic_family == 0)
		i->flags &= ~(uint32_t)WR_HANDOFF_F_NIC_STATIC;
	else {
		size_t w = i->nic_family == 4 ? 4u : 16u, b;

		i->nic_prefix = (uint8_t)(rnd(s) % (i->nic_family == 4 ? 33u : 129u));
		for (b = 0; b < w; b++) {
			i->nic_ip[b] = (uint8_t)rnd(s);
			i->nic_gateway[b] = (uint8_t)rnd(s);
			i->nic_dns[b] = (uint8_t)rnd(s);
		}
	}
	for (k = 0; k < 6; k++)
		i->nic_mac[k] = (uint8_t)rnd(s);
	i->nic_mtu = (uint16_t)rnd(s);
	if ((i->flags & WR_HANDOFF_F_VLAN) != 0)
		i->nic_vlan = (uint16_t)(1 + rnd(s) % 4094);
	if ((i->flags & WR_HANDOFF_F_FSID) != 0)
		for (k = 0; k < 16; k++)
			i->fsid[k] = (uint8_t)rnd(s);
	i->pool = rnd_str(s, strs[1], maxlen);
	i->image = rnd_str(s, strs[3], maxlen);
	if (i->auth == WR_HANDOFF_AUTH_CEPHX || rnd(s) % 2 != 0)
		i->entity = rnd_str(s, strs[0], maxlen);
	if (rnd(s) % 2 != 0)
		i->image_id = rnd_str(s, strs[4], 16);
	if (rnd(s) % 3 == 0)
		i->snapshot = rnd_str(s, strs[5], 16);
	if (i->auth == WR_HANDOFF_AUTH_CEPHX && rnd(s) % 2 != 0) {
		i->flags |= WR_HANDOFF_F_KEY;
		i->key_type = (uint8_t)(1 + rnd(s) % 2);
		i->key_len = (uint8_t)(i->key_type == WR_KEY_TYPE_AES ? WR_HANDOFF_KEY_MIN_AES : WR_HANDOFF_KEY_MIN_AES256K);
		i->key_len = (uint8_t)(i->key_len + rnd(s) % (WR_HANDOFF_KEY_MAX - i->key_len + 1u));
		for (k = 0; k < 64; k++)
			keybuf[k] = (uint8_t)rnd(s);
		i->key = keybuf;
	}
}

static void test_roundtrip_random(void)
{
	uint32_t s = 0x9e3779b9u;
	unsigned n, fit = 0, big = 0;

	for (n = 0; n < 3000; n++) {
		wr_handoff_info i;
		char strs[6][260];
		uint8_t keybuf[64], buf[BUFSZ];
		size_t len;
		wr_status st;

		rnd_info(&i, &s, strs, keybuf);
		st = wr_handoff_encode_table(&i, buf, sizeof(buf), &len);
		if (st == WR_E_HO_TOO_BIG) {
			big++; /* long names with eight monitors and a key can exceed the cap: refused, never truncated */
			WRT_CHECK(len > WR_HANDOFF_MAX_TABLE);
			continue;
		}
		WRT_CHECK_STATUS(WR_OK, st);
		fit++;
		roundtrip(&i);
	}
	WRT_CHECK(fit > 2000 && big > 0);
}

/* ---- pure function ---------------------------------------------------------------------------------- */

static void test_identical(void)
{
	wr_handoff_info i, j;
	uint8_t a[BUFSZ], b[BUFSZ], c[BUFSZ];
	size_t la, lb, lc, k;

	typical(&i);
	with_key(&i, WR_KEY_TYPE_AES256K, 32);
	memset(a, 0xAA, sizeof(a));
	memset(b, 0x55, sizeof(b));
	memset(c, 0x00, sizeof(c));
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, a, sizeof(a), &la));
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, b, sizeof(b), &lb));
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, c, la, &lc)); /* and into a buffer of exactly its size */
	WRT_CHECK(la == lb && la == lc && memcmp(a, b, la) == 0 && memcmp(a, c, la) == 0);

	/* garbage in the parts of the description the layout does not use changes nothing */
	j = i;
	for (k = j.mon_count; k < WR_HANDOFF_MAX_MONS; k++)
		memset(&j.mons[k], 0x77, sizeof(j.mons[k]));
	for (k = 0; k < j.mon_count; k++)
		j.mons[k].nonce = 0xdeadbeefu;
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&j, b, sizeof(b), &lb));
	WRT_CHECK(la == lb && memcmp(a, b, la) == 0);
	{
		char pool_copy[16] = "winrbd\0junkjunk";
		char img_copy[24] = "boot-win11\0zzzzzzzzzzz";

		j = i;
		j.pool = pool_copy;
		j.image = img_copy;
		WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&j, b, sizeof(b), &lb));
		WRT_CHECK(la == lb && memcmp(a, b, la) == 0);
	}
	/* a key pointer without the flag, with no length, is ignored */
	j = i;
	j.flags = 0;
	j.key_type = 0;
	j.key_len = 0;
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode(&j, b, sizeof(b), &lb));
	/* and the same table is rebuilt after other tables were built in between (no state kept) */
	for (k = 0; k < 50; k++) {
		wr_handoff_info o;

		typical(&o);
		o.image = "something-else";
		WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&o, c, sizeof(c), &lc));
	}
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, c, sizeof(c), &lc));
	WRT_CHECK(la == lc && memcmp(a, c, la) == 0);
}

/* ---- the size cap ------------------------------------------------------------------------------------ */

static void test_size_cap(void)
{
	wr_handoff_info i;
	static char ent[256], img[256], pool[256];
	uint8_t key[64], t[BUFSZ], clean[BUFSZ];
	size_t len = 0, k;

	memset(ent, 'e', 255);
	memset(img, 'i', 255);
	memset(pool, 'p', 135);
	for (k = 0; k < 64; k++)
		key[k] = (uint8_t)(k + 1);
	typical(&i);
	i.mon_count = 8;
	for (k = 0; k < 8; k++)
		set_mon4(&i.mons[k], (uint8_t)(10 + k), 3300);
	i.flags = WR_HANDOFF_F_KEY;
	i.key_type = WR_KEY_TYPE_AES256K;
	i.key_len = 64;
	i.key = key;
	i.entity = ent;
	i.image = img;
	i.pool = pool; /* 135 bytes: the table is exactly 1,024 bytes */

	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, t, sizeof(t), &len));
	WRT_CHECK_U64(len, WR_HANDOFF_MAX_TABLE);
	roundtrip(&i);
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode(&i, t, sizeof(t), &len));
	WRT_CHECK_U64(len, WR_HANDOFF_MAX_BODY);

	/* one byte more: refused as too big, the size it would need is reported, nothing is written */
	pool[135] = 'p';
	pool[136] = '\0';
	memset(t, 0xA5, sizeof(t));
	memset(clean, 0xA5, sizeof(clean));
	WRT_CHECK_STATUS(WR_E_HO_TOO_BIG, wr_handoff_encode_table(&i, t, sizeof(t), &len));
	WRT_CHECK_U64(len, WR_HANDOFF_MAX_TABLE + 1);
	WRT_CHECK(memcmp(t, clean, sizeof(t)) == 0);
	WRT_CHECK_STATUS(WR_E_HO_TOO_BIG, wr_handoff_encode(&i, t, sizeof(t), &len));
	WRT_CHECK_U64(len, WR_HANDOFF_MAX_BODY + 1);
	WRT_CHECK(memcmp(t, clean, sizeof(t)) == 0);
	/* even into a buffer that would hold it: the design maximum is not a buffer size */
	{
		static uint8_t big[4096];

		WRT_CHECK_STATUS(WR_E_HO_TOO_BIG, wr_handoff_encode_table(&i, big, sizeof(big), &len));
	}
	/* a body of 989 bytes does not decode, a table of 1025 neither (see the vectors for the table) */
	{
		uint8_t b[BUFSZ];

		pool[135] = '\0';
		WRT_CHECK_STATUS(WR_OK, wr_handoff_encode(&i, b, sizeof(b), &len));
		memset(b + len, 0, 1);
		WRT_CHECK_STATUS(WR_E_HO_TOO_BIG, wr_handoff_decode(b, len + 1, NULL));
	}

	/* a buffer that is too small: TOOBIG with the needed size, nothing written; NULL with cap 0 asks the size */
	typical(&i);
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode(&i, t, sizeof(t), &len));
	{
		size_t need = len, l2 = 0;

		memset(t, 0xA5, sizeof(t));
		WRT_CHECK_STATUS(WR_E_TOOBIG, wr_handoff_encode(&i, t, need - 1, &l2));
		WRT_CHECK_U64(l2, need);
		WRT_CHECK(memcmp(t, clean, sizeof(t)) == 0);
		WRT_CHECK_STATUS(WR_E_TOOBIG, wr_handoff_encode(&i, NULL, 0, &l2));
		WRT_CHECK_U64(l2, need);
		WRT_CHECK_STATUS(WR_E_TOOBIG, wr_handoff_encode_table(&i, NULL, 0, &l2));
		WRT_CHECK_U64(l2, need + 36);
		WRT_CHECK_STATUS(WR_E_TOOBIG, wr_handoff_encode(&i, t, 0, &l2));
		WRT_CHECK_STATUS(WR_OK, wr_handoff_encode(&i, t, need, &l2));
	}
}

/* ---- refusals of the encoder ----------------------------------------------------------------------------- */

typedef void (*mut_fn)(wr_handoff_info *i);

static void m_flag_bit6(wr_handoff_info *i) { i->flags |= 0x40u; }
static void m_flag_high(wr_handoff_info *i) { i->flags |= 0x80000000u; }
static void m_auth2(wr_handoff_info *i) { i->auth = 2; }
static void m_mode0(wr_handoff_info *i) { i->msgr_mode = 0; }
static void m_mode5(wr_handoff_info *i) { i->msgr_mode = 5; }
static void m_secreq_crc(wr_handoff_info *i) { i->flags |= WR_HANDOFF_F_SECURE_REQUIRED; }
static void m_secreq_crcfirst(wr_handoff_info *i) { i->flags |= WR_HANDOFF_F_SECURE_REQUIRED; i->msgr_mode = WR_MODE_SECURE_FIRST; }
static void m_mons0(wr_handoff_info *i) { i->mon_count = 0; }
static void m_mons9(wr_handoff_info *i) { i->mon_count = 9; }
static void m_mons255(wr_handoff_info *i) { i->mon_count = 255; }
static void m_mon_port0(wr_handoff_info *i) { i->mons[1].port = 0; }
static void m_mon_fam0(wr_handoff_info *i) { i->mons[2].family = 0; }
static void m_mon_fam5(wr_handoff_info *i) { i->mons[0].family = 5; }
static void m_mon_v4tail(wr_handoff_info *i) { i->mons[0].ip[4] = 1; }
static void m_mon_v4tail15(wr_handoff_info *i) { i->mons[2].ip[15] = 1; }
static void m_fam5(wr_handoff_info *i) { i->nic_family = 5; }
static void m_pfx33(wr_handoff_info *i) { i->nic_prefix = 33; }
static void m_pfx129(wr_handoff_info *i) { i->nic_family = 6; i->nic_prefix = 129; }
static void m_ip_tail(wr_handoff_info *i) { i->nic_ip[4] = 1; }
static void m_gw_tail(wr_handoff_info *i) { i->nic_gateway[15] = 1; }
static void m_dns_tail(wr_handoff_info *i) { i->nic_dns[8] = 1; }
static void m_fam0_ip(wr_handoff_info *i) { i->nic_family = 0; i->nic_prefix = 0; memset(i->nic_gateway, 0, 16); memset(i->nic_dns, 0, 16); }
static void m_fam0_pfx(wr_handoff_info *i) { memset(i->nic_ip, 0, 16); memset(i->nic_gateway, 0, 16); memset(i->nic_dns, 0, 16); i->nic_family = 0; }
static void m_static_nofam(wr_handoff_info *i) { i->nic_family = 0; i->nic_prefix = 0; memset(i->nic_ip, 0, 16); memset(i->nic_gateway, 0, 16); memset(i->nic_dns, 0, 16); i->flags |= WR_HANDOFF_F_NIC_STATIC; }
static void m_vlan_noflag(wr_handoff_info *i) { i->nic_vlan = 3; }
static void m_vlan_flag0(wr_handoff_info *i) { i->flags |= WR_HANDOFF_F_VLAN; i->nic_vlan = 0; }
static void m_vlan_4095(wr_handoff_info *i) { i->flags |= WR_HANDOFF_F_VLAN; i->nic_vlan = 4095; }
static void m_fsid_noflag(wr_handoff_info *i) { i->fsid[7] = 1; }
static void m_pool_null(wr_handoff_info *i) { i->pool = NULL; }
static void m_pool_empty(wr_handoff_info *i) { i->pool = ""; }
static void m_image_null(wr_handoff_info *i) { i->image = NULL; }
static void m_entity_null(wr_handoff_info *i) { i->entity = NULL; }
static void m_ns(wr_handoff_info *i) { i->rbd_namespace = "ns"; }
static void m_key_noflag_len(wr_handoff_info *i) { i->key_len = 16; i->key = k32; i->key_type = WR_KEY_TYPE_AES; }
static void m_key_noflag_type(wr_handoff_info *i) { i->key_type = WR_KEY_TYPE_AES; }
static void m_key_flag_null(wr_handoff_info *i) { with_key(i, WR_KEY_TYPE_AES256K, 32); i->key = NULL; }
static void m_key_flag_len0(wr_handoff_info *i) { with_key(i, WR_KEY_TYPE_AES256K, 0); }
static void m_key_flag_type0(wr_handoff_info *i) { with_key(i, 0, 32); }
static void m_key_flag_type3(wr_handoff_info *i) { with_key(i, 3, 32); }
static void m_key_aes_15(wr_handoff_info *i) { with_key(i, WR_KEY_TYPE_AES, 15); }
static void m_key_aes256k_31(wr_handoff_info *i) { with_key(i, WR_KEY_TYPE_AES256K, 31); }
static void m_key_aes256k_16(wr_handoff_info *i) { with_key(i, WR_KEY_TYPE_AES256K, 16); }
static void m_key_aes_1(wr_handoff_info *i) { with_key(i, WR_KEY_TYPE_AES, 1); }
static void m_key_len65(wr_handoff_info *i) { with_key(i, WR_KEY_TYPE_AES256K, 32); i->key_len = 65; }
static void m_key_len255(wr_handoff_info *i) { with_key(i, WR_KEY_TYPE_AES256K, 32); i->key_len = 255; }
static void m_key_auth_none(wr_handoff_info *i) { with_key(i, WR_KEY_TYPE_AES256K, 32); i->auth = WR_HANDOFF_AUTH_NONE; }

static void test_encode_refusals(void)
{
	static const struct {
		const char *name;
		mut_fn f;
		wr_status want;
	} cases[] = {
		{"flag bit 6", m_flag_bit6, WR_E_HO_FIELD},
		{"flag bit 31", m_flag_high, WR_E_HO_FIELD},
		{"auth 2", m_auth2, WR_E_HO_FIELD},
		{"mode 0", m_mode0, WR_E_HO_FIELD},
		{"mode 5", m_mode5, WR_E_HO_FIELD},
		{"secure required with crc", m_secreq_crc, WR_E_HO_FIELD},
		{"secure required with secure-first", m_secreq_crcfirst, WR_E_HO_FIELD},
		{"no monitors", m_mons0, WR_E_HO_FIELD},
		{"nine monitors", m_mons9, WR_E_HO_FIELD},
		{"255 monitors", m_mons255, WR_E_HO_FIELD},
		{"monitor port 0", m_mon_port0, WR_E_HO_FIELD},
		{"monitor family 0", m_mon_fam0, WR_E_HO_FIELD},
		{"monitor family 5", m_mon_fam5, WR_E_HO_FIELD},
		{"IPv4 monitor, byte 4 set", m_mon_v4tail, WR_E_HO_FIELD},
		{"IPv4 monitor, byte 15 set", m_mon_v4tail15, WR_E_HO_FIELD},
		{"nic family 5", m_fam5, WR_E_HO_FIELD},
		{"IPv4 prefix 33", m_pfx33, WR_E_HO_FIELD},
		{"IPv6 prefix 129", m_pfx129, WR_E_HO_FIELD},
		{"IPv4 address tail", m_ip_tail, WR_E_HO_FIELD},
		{"IPv4 gateway tail", m_gw_tail, WR_E_HO_FIELD},
		{"IPv4 dns tail", m_dns_tail, WR_E_HO_FIELD},
		{"family 0 with an address", m_fam0_ip, WR_E_HO_FIELD},
		{"family 0 with a prefix", m_fam0_pfx, WR_E_HO_FIELD},
		{"static without a family", m_static_nofam, WR_E_HO_FIELD},
		{"vlan id without flag", m_vlan_noflag, WR_E_HO_FIELD},
		{"vlan flag with id 0", m_vlan_flag0, WR_E_HO_FIELD},
		{"vlan id 4095", m_vlan_4095, WR_E_HO_FIELD},
		{"fsid without flag", m_fsid_noflag, WR_E_HO_FIELD},
		{"no pool", m_pool_null, WR_E_HO_FIELD},
		{"empty pool", m_pool_empty, WR_E_HO_FIELD},
		{"no image", m_image_null, WR_E_HO_FIELD},
		{"no entity with cephx", m_entity_null, WR_E_HO_FIELD},
		{"namespace", m_ns, WR_E_UNSUPPORTED},
		{"key bytes without the flag", m_key_noflag_len, WR_E_HO_FIELD},
		{"key type without the flag", m_key_noflag_type, WR_E_HO_FIELD},
		{"key flag without key bytes", m_key_flag_null, WR_E_HO_FIELD},
		{"key flag with length 0", m_key_flag_len0, WR_E_HO_FIELD},
		{"key flag with type 0", m_key_flag_type0, WR_E_HO_FIELD},
		{"key flag with type 3", m_key_flag_type3, WR_E_HO_FIELD},
		{"aes key of 15 bytes", m_key_aes_15, WR_E_HO_FIELD},
		{"aes key of 1 byte", m_key_aes_1, WR_E_HO_FIELD},
		{"aes256k key of 31 bytes", m_key_aes256k_31, WR_E_HO_FIELD},
		{"aes256k key of 16 bytes", m_key_aes256k_16, WR_E_HO_FIELD},
		{"key length 65", m_key_len65, WR_E_HO_FIELD},
		{"key length 255", m_key_len255, WR_E_HO_FIELD},
		{"key with auth none", m_key_auth_none, WR_E_HO_FIELD},
	};
	size_t c;
	static char s256[257];

	memset(s256, 's', 256);
	for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
		wr_handoff_info i;
		uint8_t buf[BUFSZ], clean[BUFSZ];
		size_t len = 99;
		wr_status st;

		typical(&i);
		cases[c].f(&i);
		memset(buf, 0xA5, sizeof(buf));
		memset(clean, 0xA5, sizeof(clean));
		st = wr_handoff_encode(&i, buf, sizeof(buf), &len);
		if (st != cases[c].want)
			fprintf(stderr, "  (case: %s)\n", cases[c].name);
		WRT_CHECK_STATUS(cases[c].want, st);
		WRT_CHECK_U64(len, 0);
		WRT_CHECK(memcmp(buf, clean, sizeof(buf)) == 0);
		st = wr_handoff_encode_table(&i, buf, sizeof(buf), &len);
		WRT_CHECK_STATUS(cases[c].want, st);
		WRT_CHECK_U64(len, 0);
		WRT_CHECK(memcmp(buf, clean, sizeof(buf)) == 0);
	}
	/* strings of 256 bytes, for each of the five that can carry one */
	{
		wr_handoff_info i;
		const char **f[5];
		size_t k, len;
		uint8_t buf[BUFSZ];

		for (k = 0; k < 5; k++) {
			typical(&i);
			i.image_id = "x";
			i.snapshot = "y";
			f[0] = &i.entity;
			f[1] = &i.pool;
			f[2] = &i.image;
			f[3] = &i.image_id;
			f[4] = &i.snapshot;
			*f[k] = s256;
			WRT_CHECK_STATUS(WR_E_HO_FIELD, wr_handoff_encode(&i, buf, sizeof(buf), &len));
		}
	}
	/* an unterminated string cannot be passed: slen is bounded, a 4 KiB run without NUL is "too long" and is never read past 256 bytes */
	{
		static char run[300];
		wr_handoff_info i;
		size_t len;
		uint8_t buf[BUFSZ];

		memset(run, 'z', 299); /* the NUL is at 299 */
		run[299] = '\0';
		typical(&i);
		i.image = run;
		WRT_CHECK_STATUS(WR_E_HO_FIELD, wr_handoff_encode(&i, buf, sizeof(buf), &len));
	}
	/* arguments */
	{
		wr_handoff_info i;
		uint8_t buf[BUFSZ];
		size_t len = 5;

		typical(&i);
		WRT_CHECK_STATUS(WR_E_INVAL, wr_handoff_encode(&i, buf, sizeof(buf), NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wr_handoff_encode(NULL, buf, sizeof(buf), &len));
		WRT_CHECK_U64(len, 0);
		len = 5;
		WRT_CHECK_STATUS(WR_E_INVAL, wr_handoff_encode(&i, NULL, 10, &len));
		WRT_CHECK_U64(len, 0);
		WRT_CHECK_STATUS(WR_E_INVAL, wr_handoff_encode_table(&i, buf, sizeof(buf), NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wr_handoff_encode_table(NULL, buf, sizeof(buf), &len));
		WRT_CHECK_STATUS(WR_E_INVAL, wr_handoff_encode_table(&i, NULL, 10, &len));
	}
}

/* ---- the key only with its flag ---------------------------------------------------------------------- */

static int contains(const uint8_t *hay, size_t hn, const uint8_t *needle, size_t nn)
{
	size_t k;

	for (k = 0; k + nn <= hn; k++)
		if (memcmp(hay + k, needle, nn) == 0)
			return 1;
	return 0;
}

static void test_key_only_with_flag(void)
{
	wr_handoff_info i;
	uint8_t t[BUFSZ];
	size_t len;
	static const uint8_t marker[16] = {0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE, 0x01};

	/* with the flag the key is in the table, once; without it the same description is refused rather than dropped,
	 * and the table of a description that has no key does not contain the bytes of a key that sits next to it in memory */
	typical(&i);
	i.flags = WR_HANDOFF_F_KEY;
	i.key_type = WR_KEY_TYPE_AES;
	i.key_len = 16;
	i.key = marker;
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, t, sizeof(t), &len));
	WRT_CHECK(contains(t, len, marker, 16));
	i.flags = 0;
	WRT_CHECK_STATUS(WR_E_HO_FIELD, wr_handoff_encode_table(&i, t, sizeof(t), &len));
	i.key_type = 0;
	i.key_len = 0; /* the pointer is still set: ignored */
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, t, sizeof(t), &len));
	WRT_CHECK(!contains(t, len, marker, 16));
	WRT_CHECK(!contains(t, len, marker, 4));
	{
		wr_handoff_info d;
		uint8_t *e = exact(t, len);

		WRT_CHECK(e != NULL);
		if (e != NULL) {
			WRT_CHECK_STATUS(WR_OK, wr_handoff_decode_table(e, len, &d));
			WRT_CHECK(d.key == NULL && d.key_len == 0 && d.key_type == 0 && (d.flags & WR_HANDOFF_F_KEY) == 0);
		}
		free(e);
	}
}

/* The key length floor is the one wr_key_from_raw applies: 16 for aes, 32 for aes256k, 64 for both at most. */
static void test_key_length_bounds(void)
{
	static const struct {
		unsigned type;
		size_t len;
		wr_status want;
	} cases[] = {
		{WR_KEY_TYPE_AES, 15, WR_E_HO_FIELD},    {WR_KEY_TYPE_AES, 16, WR_OK},
		{WR_KEY_TYPE_AES, 17, WR_OK},            {WR_KEY_TYPE_AES, 32, WR_OK},
		{WR_KEY_TYPE_AES, 64, WR_OK},            {WR_KEY_TYPE_AES, 65, WR_E_HO_FIELD},
		{WR_KEY_TYPE_AES256K, 31, WR_E_HO_FIELD}, {WR_KEY_TYPE_AES256K, 32, WR_OK},
		{WR_KEY_TYPE_AES256K, 33, WR_OK},        {WR_KEY_TYPE_AES256K, 64, WR_OK},
		{WR_KEY_TYPE_AES256K, 65, WR_E_HO_FIELD},
	};
	uint8_t key[255], t[BUFSZ];
	size_t c, k;

	for (k = 0; k < sizeof(key); k++)
		key[k] = (uint8_t)(k * 7u + 1u);
	for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
		wr_handoff_info i, d;
		wr_key kk;
		size_t len = 0;
		wr_status st;

		typical(&i);
		i.flags = WR_HANDOFF_F_KEY;
		i.key_type = (uint8_t)cases[c].type;
		i.key_len = (uint8_t)cases[c].len;
		i.key = key;
		st = wr_handoff_encode_table(&i, t, sizeof(t), &len);
		WRT_CHECK_STATUS(cases[c].want, st);
		if (st == WR_OK) {
			uint8_t *e = exact(t, len);

			WRT_CHECK(e != NULL);
			if (e != NULL) {
				WRT_CHECK_STATUS(WR_OK, wr_handoff_decode_table(e, len, &d));
				/* what the table accepts is what the core takes as a key */
				WRT_CHECK_STATUS(WR_OK, wr_key_from_raw(&kk, d.key_type, d.key, d.key_len));
				wr_key_wipe(&kk);
			}
			free(e);
		}
		/* the same refusal from the core's own constructor: the codec is never more lenient than it */
		WRT_CHECK((wr_key_from_raw(&kk, (unsigned)cases[c].type, key, cases[c].len) == WR_OK) == (cases[c].want == WR_OK));
		wr_key_wipe(&kk);
	}
}

/* ---- decoder: truncation, bit flips, damage ----------------------------------------------------------- */

static void test_truncation(void)
{
	static const unsigned variants[] = {0, 1, 2};
	size_t v;

	for (v = 0; v < sizeof(variants) / sizeof(variants[0]); v++) {
		wr_handoff_info i;
		uint8_t body[BUFSZ], table[BUFSZ];
		size_t bn, tn, n;

		typical(&i);
		if (variants[v] == 1)
			with_key(&i, WR_KEY_TYPE_AES256K, 32);
		if (variants[v] == 2) {
			i.image_id = "abcdef";
			i.snapshot = "s";
		}
		WRT_CHECK_STATUS(WR_OK, wr_handoff_encode(&i, body, sizeof(body), &bn));
		WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, table, sizeof(table), &tn));
		/* the table cut at every length: always refused, always as truncated (the length field says more than is there) */
		for (n = 0; n < tn; n++) {
			uint8_t *cut = exact(table, n);
			wr_handoff_info o;

			memset(&o, 0xEE, sizeof(o));
			if (cut == NULL) {
				WRT_CHECK(0 && "out of memory");
				continue;
			}
			WRT_CHECK_STATUS(WR_E_TRUNCATED, wr_handoff_decode_table(cut, n, &o));
			WRT_CHECK(all_zero(&o, sizeof(o)));
			free(cut);
		}
		/* the body cut at every length: always refused (what status depends on what is missing) */
		for (n = 0; n < bn; n++) {
			uint8_t *cut = exact(body, n);
			wr_handoff_info o;

			memset(&o, 0xEE, sizeof(o));
			if (cut == NULL) {
				WRT_CHECK(0 && "out of memory");
				continue;
			}
			WRT_CHECK(wr_handoff_decode(cut, n, &o) != WR_OK);
			WRT_CHECK(all_zero(&o, sizeof(o)));
			if (n < WR_HANDOFF_FIXED_LEN)
				WRT_CHECK_STATUS(WR_E_TRUNCATED, wr_handoff_decode(cut, n, NULL));
			free(cut);
		}
	}
}

static void test_bitflips(void)
{
	wr_handoff_info i, d;
	uint8_t table[BUFSZ];
	size_t tn, byte;
	unsigned bit;
	static const unsigned variants[] = {0, 1};
	size_t v;

	for (v = 0; v < 2; v++) {
		typical(&i);
		i.image_id = "id0";
		i.snapshot = "sn";
		if (variants[v] == 1)
			with_key(&i, WR_KEY_TYPE_AES256K, 32);
		WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, table, sizeof(table), &tn));
		for (byte = 0; byte < tn; byte++) {
			for (bit = 0; bit < 8; bit++) {
				uint8_t *t = exact(table, tn);
				wr_status st;

				if (t == NULL) {
					WRT_CHECK(0 && "out of memory");
					continue;
				}
				t[byte] = (uint8_t)(t[byte] ^ (1u << bit));
				st = wr_handoff_decode_table(t, tn, &d);
				WRT_CHECK(st != WR_OK);
				/* a flip outside signature, length and revision reaches the checksum, which refuses it */
				if (byte >= 9)
					WRT_CHECK_STATUS(WR_E_HO_CHECKSUM, st);
				WRT_CHECK(all_zero(&d, sizeof(d)));
				free(t);
			}
		}
	}
}

/* Random damage with the checksum repaired: either refused, or accepted and then encodes back to the same bytes. */
static void test_random_damage(void)
{
	uint32_t s = 0xC0FFEE11u;
	unsigned n, accepted = 0, refused = 0;

	for (n = 0; n < 40000; n++) {
		wr_handoff_info i, d;
		char strs[6][260];
		uint8_t keybuf[64], table[BUFSZ], again[BUFSZ];
		size_t tn, an, k, flips;
		wr_status st;
		uint8_t *t;

		rnd_info(&i, &s, strs, keybuf);
		if (wr_handoff_encode_table(&i, table, sizeof(table), &tn) != WR_OK)
			continue;
		flips = 1 + rnd(&s) % 3;
		for (k = 0; k < flips; k++) {
			/* damage the body only; most of the time the fixed part, where the offsets are */
			size_t at = 36 + (rnd(&s) % 3 == 0 ? rnd(&s) % (tn - 36) : rnd(&s) % 116);
			uint8_t m = (uint8_t)rnd(&s);

			switch (rnd(&s) % 3) {
			case 0:
				table[at] = (uint8_t)(table[at] ^ (1u << (m % 8)));
				break;
			case 1:
				table[at] = m;
				break;
			default:
				table[at] = 0;
				break;
			}
		}
		WRT_CHECK_STATUS(WR_OK, wr_handoff_fix_checksum(table, tn));
		t = exact(table, tn);
		if (t == NULL) {
			WRT_CHECK(0 && "out of memory");
			continue;
		}
		st = wr_handoff_decode_table(t, tn, &d);
		if (st == WR_OK) {
			accepted++;
			WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&d, again, sizeof(again), &an));
			WRT_CHECK(an == tn && memcmp(again, t, tn) == 0); /* one way to say it */
		} else {
			refused++;
			WRT_CHECK(all_zero(&d, sizeof(d)));
		}
		free(t);
	}
	WRT_CHECK(accepted > 0 && refused > 1000);
}

static void test_decode_args(void)
{
	wr_handoff_info i, d;
	uint8_t table[BUFSZ];
	size_t tn;

	memset(&d, 0xEE, sizeof(d));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_handoff_decode(NULL, 0, &d));
	WRT_CHECK(all_zero(&d, sizeof(d)));
	memset(&d, 0xEE, sizeof(d));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_handoff_decode_table(NULL, 100, &d));
	WRT_CHECK(all_zero(&d, sizeof(d)));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_handoff_decode(NULL, 0, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_handoff_fix_checksum(NULL, 100));

	typical(&i);
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, table, sizeof(table), &tn));
	WRT_CHECK_STATUS(WR_E_TRUNCATED, wr_handoff_decode(table, 0, NULL));
	WRT_CHECK_STATUS(WR_E_TRUNCATED, wr_handoff_decode(table, 7, NULL));
	/* a body that begins with the ACPI header is not a body */
	WRT_CHECK_STATUS(WR_E_HO_SIGNATURE, wr_handoff_decode(table, tn, NULL));
	/* and a body is not a table */
	WRT_CHECK_STATUS(WR_E_HO_SIGNATURE, wr_handoff_decode_table(table + 36, tn - 36, NULL));
	/* fix_checksum refuses a length that is not the header's */
	WRT_CHECK_STATUS(WR_E_HO_LENGTH, wr_handoff_fix_checksum(table, tn - 1));
	WRT_CHECK_STATUS(WR_E_TRUNCATED, wr_handoff_fix_checksum(table, 35));
	/* one more than the design maximum, with a header that says so, is not a table either */
	{
		static uint8_t big[WR_HANDOFF_MAX_TABLE + 1];

		memset(big, 0, sizeof(big));
		memcpy(big, "rBFT", 4);
		big[4] = (uint8_t)((WR_HANDOFF_MAX_TABLE + 1u) & 0xffu);
		big[5] = (uint8_t)((WR_HANDOFF_MAX_TABLE + 1u) >> 8);
		WRT_CHECK_STATUS(WR_E_HO_TOO_BIG, wr_handoff_fix_checksum(big, sizeof(big)));
		WRT_CHECK_U64(big[9], 0);
	}
#if SIZE_MAX > 0xffffffffu
	/* a 64-bit length whose low 32 bits equal the header's field is not the header's length (no wrap into the field) */
	WRT_CHECK_STATUS(WR_E_HO_LENGTH, wr_handoff_fix_checksum(table, (size_t)tn + ((size_t)1 << 32)));
#endif
}

/* ---- the host's OEM fields, a scan buffer ------------------------------------------------------------- */

static void test_host_oem_and_scan(void)
{
	wr_handoff_info i, d;
	uint8_t table[BUFSZ], scan[BUFSZ];
	size_t tn, k;
	uint8_t *t;

	typical(&i);
	WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&i, table, sizeof(table), &tn));
	/* what iPXE does: write its own OEM id and table id, then fix the checksum */
	memcpy(table + 10, "FENSYS", 6);
	memcpy(table + 16, "iPXE\0\0\0\0", 8);
	t = exact(table, tn);
	WRT_CHECK(t != NULL);
	if (t == NULL)
		return;
	WRT_CHECK_STATUS(WR_E_HO_CHECKSUM, wr_handoff_decode_table(t, tn, NULL)); /* not yet */
	WRT_CHECK_STATUS(WR_OK, wr_handoff_fix_checksum(t, tn));
	WRT_CHECK_STATUS(WR_OK, wr_handoff_decode_table(t, tn, &d));
	check_same(&d, &i);
	free(t);
	/* every OEM and creator byte can be anything once the checksum is fixed */
	for (k = 10; k < 36; k++) {
		uint8_t save = table[k];

		table[k] = (uint8_t)(save ^ 0xA5);
		WRT_CHECK_STATUS(WR_OK, wr_handoff_fix_checksum(table, tn));
		WRT_CHECK_STATUS(WR_OK, wr_handoff_decode_table(table, tn, &d));
		check_same(&d, &i);
		table[k] = save;
	}
	WRT_CHECK_STATUS(WR_OK, wr_handoff_fix_checksum(table, tn));

	/* a scan buffer is bigger than the table: the bytes after the header's length are ignored (a body decode is exact) */
	memset(scan, 0xCC, sizeof(scan));
	memcpy(scan, table, tn);
	WRT_CHECK_STATUS(WR_OK, wr_handoff_decode_table(scan, sizeof(scan), &d));
	check_same(&d, &i);
	WRT_CHECK_STATUS(WR_E_HO_LAYOUT, wr_handoff_decode(scan + 36, 900, NULL));
}

static void test_status_texts(void)
{
	static const wr_status st[] = {WR_E_HO_SIGNATURE, WR_E_HO_VERSION, WR_E_HO_LENGTH, WR_E_HO_CHECKSUM,
				       WR_E_HO_OFFSET,    WR_E_HO_FIELD,   WR_E_HO_TOO_BIG, WR_E_HO_LAYOUT};
	size_t k, j;

	for (k = 0; k < sizeof(st) / sizeof(st[0]); k++) {
		WRT_CHECK(strcmp(wr_strerror(st[k]), "unknown status") != 0);
		WRT_CHECK(strncmp(wr_status_name(st[k]), "WR_E_HO_", 8) == 0);
		WRT_CHECK(st[k] <= -240 && st[k] >= -259);
		for (j = k + 1; j < sizeof(st) / sizeof(st[0]); j++)
			WRT_CHECK(st[k] != st[j]);
	}
}

int main(void)
{
	test_layout();
	test_roundtrip_hand();
	test_roundtrip_random();
	test_identical();
	test_size_cap();
	test_encode_refusals();
	test_key_only_with_flag();
	test_key_length_bounds();
	test_truncation();
	test_bitflips();
	test_random_damage();
	test_decode_args();
	test_host_oem_and_scan();
	test_status_texts();
	return wrt_finish();
}
