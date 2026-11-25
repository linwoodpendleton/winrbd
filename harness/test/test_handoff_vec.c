/* SPDX-License-Identifier: MIT */
/*
 * Golden vectors of the rBFT handoff table, version 1 (harness/vectors/handoff/handoff-v1.json, written by the
 * independent Python implementation gen_handoff_vectors.py). For every valid table: the encoder reproduces the
 * body and the whole table byte for byte, the decoder returns every described field, and decode followed by
 * encode returns the input. For every refusal: the decoder (or the encoder) fails with the stated status, leaves its
 * output empty (decode) or the buffer untouched (encode), and never reads outside an exact-size copy of the input.
 */
#include "wrt.h"
#include "wr_handoff.h"

#define MAXBUF 2048u

typedef struct vinfo {
	wr_handoff_info i;
	char *str[6]; /* owned copies of the strings */
	uint8_t *key; /* owned */
	size_t key_n;
} vinfo;

static void vinfo_free(vinfo *v)
{
	size_t k;

	for (k = 0; k < 6; k++)
		free(v->str[k]);
	free(v->key);
	memset(v, 0, sizeof(*v));
}

/* member `key` of obj as a string; NULL when absent or empty (absent and empty are the same thing in a table) */
static char *get_str(const wrt_json *j, wrt_tok obj, const char *key)
{
	char *s;
	wrt_tok t = wrt_json_get(j, obj, key);

	if (t == WRT_NONE)
		return NULL;
	s = wrt_json_strdup(j, t);
	if (s != NULL && s[0] == '\0') {
		free(s);
		return NULL;
	}
	return s;
}

static int64_t get_int(const wrt_json *j, wrt_tok obj, const char *key, int64_t dflt)
{
	int ok = 0;
	wrt_tok t = wrt_json_get(j, obj, key);
	int64_t v;

	if (t == WRT_NONE)
		return dflt;
	v = wrt_json_int(j, t, &ok);
	return ok ? v : dflt;
}

static void get_bytes(const wrt_json *j, wrt_tok obj, const char *key, uint8_t *dst, size_t want)
{
	uint8_t *b = NULL;
	size_t n = 0;

	if (wrt_json_get_hex(j, obj, key, &b, &n) != 0 || n != want) {
		WRT_CHECK(0 && "hex field of the wrong size");
		free(b);
		return;
	}
	memcpy(dst, b, n);
	free(b);
}

static int load_info(const wrt_json *j, wrt_tok t, vinfo *v)
{
	static const char *names[6] = {"entity", "pool", "rbd_namespace", "image", "image_id", "snapshot"};
	wrt_tok mons = wrt_json_get(j, t, "mons");
	size_t k, n;
	uint8_t *kb = NULL;

	memset(v, 0, sizeof(*v));
	v->i.flags = (uint32_t)get_int(j, t, "flags", 0);
	v->i.auth = (uint8_t)get_int(j, t, "auth", 0);
	v->i.msgr_mode = (uint8_t)get_int(j, t, "msgr_mode", 0);
	v->i.key_type = (uint8_t)get_int(j, t, "key_type", 0);
	v->i.nic_family = (uint8_t)get_int(j, t, "nic_family", 0);
	v->i.nic_prefix = (uint8_t)get_int(j, t, "nic_prefix", 0);
	v->i.nic_vlan = (uint16_t)get_int(j, t, "nic_vlan", 0);
	v->i.nic_mtu = (uint16_t)get_int(j, t, "nic_mtu", 0);
	get_bytes(j, t, "fsid", v->i.fsid, 16);
	get_bytes(j, t, "nic_mac", v->i.nic_mac, 6);
	get_bytes(j, t, "nic_ip", v->i.nic_ip, 16);
	get_bytes(j, t, "nic_gateway", v->i.nic_gateway, 16);
	get_bytes(j, t, "nic_dns", v->i.nic_dns, 16);
	for (k = 0; k < 6; k++)
		v->str[k] = get_str(j, t, names[k]);
	v->i.entity = v->str[0];
	v->i.pool = v->str[1];
	v->i.rbd_namespace = v->str[2];
	v->i.image = v->str[3];
	v->i.image_id = v->str[4];
	v->i.snapshot = v->str[5];

	n = mons == WRT_NONE ? 0 : wrt_json_count(j, mons);
	WRT_CHECK(n <= WR_HANDOFF_MAX_MONS);
	if (n > WR_HANDOFF_MAX_MONS)
		n = WR_HANDOFF_MAX_MONS;
	for (k = 0; k < n; k++) {
		wrt_tok m = wrt_json_at(j, mons, k);

		v->i.mons[k].family = (uint8_t)get_int(j, m, "family", 0);
		v->i.mons[k].port = (uint16_t)get_int(j, m, "port", 0);
		get_bytes(j, m, "ip", v->i.mons[k].ip, 16);
	}
	v->i.mon_count = (uint8_t)get_int(j, t, "mon_count", (int64_t)n);

	if (wrt_json_get_hex(j, t, "key", &kb, &v->key_n) != 0)
		return -1;
	v->key = kb;
	v->i.key = v->key_n != 0 ? v->key : NULL;
	v->i.key_len = (uint8_t)get_int(j, t, "key_len", (int64_t)v->key_n);
	return 0;
}

static int streq(const char *a, const char *b)
{
	if (a == NULL || a[0] == '\0')
		return b == NULL || b[0] == '\0';
	return b != NULL && strcmp(a, b) == 0;
}

/* every field of a decoded table against the described one (nonce of a monitor is not carried) */
static void check_same(const wr_handoff_info *got, const wr_handoff_info *want, const char *name)
{
	size_t k;
	int mon_ok = 1;

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
	WRT_CHECK_MEM(got->fsid, want->fsid, 16);
	WRT_CHECK_MEM(got->nic_mac, want->nic_mac, 6);
	WRT_CHECK_MEM(got->nic_ip, want->nic_ip, 16);
	WRT_CHECK_MEM(got->nic_gateway, want->nic_gateway, 16);
	WRT_CHECK_MEM(got->nic_dns, want->nic_dns, 16);
	WRT_CHECK(streq(got->entity, want->entity));
	WRT_CHECK(streq(got->pool, want->pool));
	WRT_CHECK(streq(got->rbd_namespace, want->rbd_namespace));
	WRT_CHECK(streq(got->image, want->image));
	WRT_CHECK(streq(got->image_id, want->image_id));
	WRT_CHECK(streq(got->snapshot, want->snapshot));
	for (k = 0; k < want->mon_count && k < WR_HANDOFF_MAX_MONS; k++)
		if (got->mons[k].family != want->mons[k].family || got->mons[k].port != want->mons[k].port ||
		    got->mons[k].nonce != 0 || memcmp(got->mons[k].ip, want->mons[k].ip, 16) != 0)
			mon_ok = 0;
	WRT_CHECK(mon_ok);
	if ((want->flags & WR_HANDOFF_F_KEY) != 0 && want->key != NULL)
		WRT_CHECK(got->key != NULL && memcmp(got->key, want->key, want->key_len) == 0);
	else
		WRT_CHECK(got->key == NULL);
	if (!mon_ok)
		fprintf(stderr, "  (vector %s)\n", name);
}

/* an exact-size heap copy, so ASan sees any read past the input */
static uint8_t *exact(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n != 0 ? n : 1);

	if (q != NULL && n != 0)
		memcpy(q, p, n);
	return q;
}

static int32_t status_of(const char *name)
{
	static const struct {
		const char *n;
		int32_t v;
	} map[] = {
		{"WR_E_TRUNCATED", WR_E_TRUNCATED},       {"WR_E_TOOBIG", WR_E_TOOBIG},
		{"WR_E_UNSUPPORTED", WR_E_UNSUPPORTED},   {"WR_E_HO_SIGNATURE", WR_E_HO_SIGNATURE},
		{"WR_E_HO_VERSION", WR_E_HO_VERSION},     {"WR_E_HO_LENGTH", WR_E_HO_LENGTH},
		{"WR_E_HO_CHECKSUM", WR_E_HO_CHECKSUM},   {"WR_E_HO_OFFSET", WR_E_HO_OFFSET},
		{"WR_E_HO_FIELD", WR_E_HO_FIELD},         {"WR_E_HO_TOO_BIG", WR_E_HO_TOO_BIG},
		{"WR_E_HO_LAYOUT", WR_E_HO_LAYOUT},
	};
	size_t k;

	for (k = 0; k < sizeof(map) / sizeof(map[0]); k++)
		if (strcmp(map[k].n, name) == 0)
			return map[k].v;
	fprintf(stderr, "unknown status name %s in the vectors\n", name);
	WRT_CHECK(0 && "status name");
	return 0;
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

static void test_valid(const wrt_json *j, wrt_tok arr)
{
	size_t n = wrt_json_count(j, arr), c;

	WRT_CHECK(n >= 8);
	for (c = 0; c < n; c++) {
		wrt_tok e = wrt_json_at(j, arr, c);
		char *name = wrt_json_strdup(j, wrt_json_get(j, e, "name"));
		vinfo v;
		uint8_t *body = NULL, *table = NULL, *eb, *et;
		size_t bn = 0, tn = 0, len, len2;
		uint8_t out[MAXBUF], out2[MAXBUF];
		wr_handoff_info dec;

		WRT_CHECK(name != NULL);
		WRT_CHECK(load_info(j, wrt_json_get(j, e, "info"), &v) == 0);
		WRT_CHECK(wrt_json_get_hex(j, e, "body", &body, &bn) == 0);
		WRT_CHECK(wrt_json_get_hex(j, e, "table", &table, &tn) == 0);
		if (body == NULL || table == NULL) {
			free(body);
			free(table);
			free(name);
			vinfo_free(&v);
			continue;
		}
		WRT_CHECK(tn == bn + WR_HANDOFF_ACPI_HDR_LEN);

		/* encode the described table: byte for byte the vector, twice (the same bytes from a dirty buffer) */
		memset(out, 0xA5, sizeof(out));
		WRT_CHECK_STATUS(WR_OK, wr_handoff_encode(&v.i, out, sizeof(out), &len));
		WRT_CHECK_U64(len, bn);
		WRT_CHECK_MEM(out, body, bn);
		memset(out2, 0x5A, sizeof(out2));
		WRT_CHECK_STATUS(WR_OK, wr_handoff_encode(&v.i, out2, sizeof(out2), &len2));
		WRT_CHECK(len2 == len && memcmp(out, out2, len) == 0);
		WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&v.i, out, sizeof(out), &len));
		WRT_CHECK_U64(len, tn);
		WRT_CHECK_MEM(out, table, tn);
		/* exactly the size needed is enough, one byte less is refused and tells the size */
		WRT_CHECK_STATUS(WR_OK, wr_handoff_encode_table(&v.i, out2, tn, &len2));
		memset(out2, 0xC3, sizeof(out2));
		WRT_CHECK_STATUS(WR_E_TOOBIG, wr_handoff_encode_table(&v.i, out2, tn - 1, &len2));
		WRT_CHECK_U64(len2, tn);
		WRT_CHECK(out2[0] == 0xC3 && out2[tn - 1] == 0xC3);

		/* decode the vector: every field, from the body and from the table; then back again */
		eb = exact(body, bn);
		et = exact(table, tn);
		WRT_CHECK(eb != NULL && et != NULL);
		if (eb != NULL && et != NULL) {
			wr_handoff_info again;

			memset(&dec, 0xEE, sizeof(dec));
			WRT_CHECK_STATUS(WR_OK, wr_handoff_decode(eb, bn, &dec));
			check_same(&dec, &v.i, name);
			WRT_CHECK_STATUS(WR_OK, wr_handoff_encode(&dec, out2, sizeof(out2), &len2));
			WRT_CHECK(len2 == bn && memcmp(out2, body, bn) == 0);
			memset(&again, 0xEE, sizeof(again));
			WRT_CHECK_STATUS(WR_OK, wr_handoff_decode_table(et, tn, &again));
			check_same(&again, &v.i, name);
			WRT_CHECK_STATUS(WR_OK, wr_handoff_decode(eb, bn, NULL));
			WRT_CHECK_STATUS(WR_OK, wr_handoff_decode_table(et, tn, NULL));
			/* the strings and the key of the decoded table point into the buffer that was decoded */
			WRT_CHECK((const uint8_t *)dec.pool >= eb && (const uint8_t *)dec.pool < eb + bn);
		}
		free(eb);
		free(et);
		free(body);
		free(table);
		free(name);
		vinfo_free(&v);
	}
}

static void test_refuse_decode(const wrt_json *j, wrt_tok arr)
{
	size_t n = wrt_json_count(j, arr), c;

	WRT_CHECK(n >= 50);
	for (c = 0; c < n; c++) {
		wrt_tok e = wrt_json_at(j, arr, c);
		char *name = wrt_json_strdup(j, wrt_json_get(j, e, "name"));
		char *kind = wrt_json_strdup(j, wrt_json_get(j, e, "kind"));
		char *st = wrt_json_strdup(j, wrt_json_get(j, e, "status"));
		uint8_t *hex = NULL, *buf;
		size_t hn = 0;
		wr_handoff_info out;
		int32_t got;

		WRT_CHECK(name != NULL && kind != NULL && st != NULL);
		WRT_CHECK(wrt_json_get_hex(j, e, "hex", &hex, &hn) == 0);
		buf = exact(hex, hn);
		if (buf != NULL && kind != NULL && st != NULL) {
			memset(&out, 0xEE, sizeof(out));
			if (strcmp(kind, "table") == 0)
				got = wr_handoff_decode_table(buf, hn, &out);
			else
				got = wr_handoff_decode(buf, hn, &out);
			if (got != status_of(st))
				fprintf(stderr, "  (refusal vector %s)\n", name != NULL ? name : "?");
			WRT_CHECK_STATUS(status_of(st), got);
			WRT_CHECK(all_zero(&out, sizeof(out))); /* nothing half-decoded, no pointer left behind */
			if (strcmp(kind, "table") == 0)
				WRT_CHECK(wr_handoff_decode_table(buf, hn, NULL) == status_of(st));
			else
				WRT_CHECK(wr_handoff_decode(buf, hn, NULL) == status_of(st));
		}
		free(buf);
		free(hex);
		free(name);
		free(kind);
		free(st);
	}
}

static void test_refuse_encode(const wrt_json *j, wrt_tok arr)
{
	size_t n = wrt_json_count(j, arr), c;

	WRT_CHECK(n >= 20);
	for (c = 0; c < n; c++) {
		wrt_tok e = wrt_json_at(j, arr, c);
		char *name = wrt_json_strdup(j, wrt_json_get(j, e, "name"));
		char *st = wrt_json_strdup(j, wrt_json_get(j, e, "status"));
		vinfo v;
		uint8_t buf[MAXBUF], clean[MAXBUF];
		size_t len = 77;
		int32_t want, got;

		WRT_CHECK(st != NULL && name != NULL);
		WRT_CHECK(load_info(j, wrt_json_get(j, e, "info"), &v) == 0);
		want = st != NULL ? status_of(st) : 0;
		memset(buf, 0xA5, sizeof(buf));
		memset(clean, 0xA5, sizeof(clean));
		got = wr_handoff_encode(&v.i, buf, sizeof(buf), &len);
		if (got != want)
			fprintf(stderr, "  (encode refusal %s)\n", name != NULL ? name : "?");
		WRT_CHECK_STATUS(want, got);
		WRT_CHECK(memcmp(buf, clean, sizeof(buf)) == 0); /* nothing written */
		if (want == WR_E_HO_TOO_BIG)
			WRT_CHECK(len > WR_HANDOFF_MAX_BODY);
		else
			WRT_CHECK_U64(len, 0);
		len = 77;
		got = wr_handoff_encode_table(&v.i, buf, sizeof(buf), &len);
		WRT_CHECK_STATUS(want, got);
		WRT_CHECK(memcmp(buf, clean, sizeof(buf)) == 0);
		if (want == WR_E_HO_TOO_BIG)
			WRT_CHECK(len > WR_HANDOFF_MAX_TABLE);
		else
			WRT_CHECK_U64(len, 0);
		vinfo_free(&v);
		free(name);
		free(st);
	}
}

int main(void)
{
	wrt_json j;

	if (wrt_json_load_vec(&j, "handoff/handoff-v1.json") != 0) {
		fprintf(stderr, "harness/vectors/handoff/handoff-v1.json is missing or not valid JSON\n");
		return 1; /* a missing vector file is a failure, not a skip */
	}
	test_valid(&j, wrt_json_get(&j, wrt_json_root(&j), "valid"));
	test_refuse_decode(&j, wrt_json_get(&j, wrt_json_root(&j), "refuse_decode"));
	test_refuse_encode(&j, wrt_json_get(&j, wrt_json_root(&j), "refuse_encode"));
	wrt_json_free(&j);
	return wrt_finish();
}
