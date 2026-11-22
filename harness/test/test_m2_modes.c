/* SPDX-License-Identifier: MIT */
/*
 * Unit test of the connection-mode policy (core/src/msgr2/wri_m2_modes.h, design 34.2): every policy x peer type x OSD override
 * against the table, unknown values, the order of the offer list, the empty and odd masks, the stock client's offer (spec 2.9, written
 * here as the option strings the reference client parses) and the memory-plan question wri_m2_policy_may_secure.
 */
#include "wrt.h"

#include "wri_m2_modes.h"

#define CRC WRI_CONN_MODE_CRC
#define SEC WRI_CONN_MODE_SECURE

typedef struct row {
	uint8_t policy;
	size_t n;
	uint32_t list[2];
	uint8_t mask;
} row;

/* The table of design 34.2 (monitor and OSD columns of one policy are equal except STOCK). */
static const row k_rows[] = {
    {WR_MODE_CRC_ONLY, 1, {CRC, 0}, WRI_M2_OFFER_CRC},
    {WR_MODE_CRC_FIRST, 2, {CRC, SEC}, WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE},
    {WR_MODE_SECURE_FIRST, 2, {SEC, CRC}, WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE | WRI_M2_OFFER_SECURE_FIRST},
    {WR_MODE_SECURE_ONLY, 1, {SEC, 0}, WRI_M2_OFFER_SECURE},
};
#define NROWS (sizeof(k_rows) / sizeof(k_rows[0]))

/* What `policy` should give for peer type `peer` (the STOCK row differs per peer). */
static const row *expect_row(uint8_t policy, uint8_t peer, row *stock)
{
	size_t i;

	if (policy == WR_MODE_STOCK) {
		*stock = k_rows[peer == WRI_ENTITY_MON ? 2 : 1]; /* [secure, crc] to a monitor, [crc, secure] to an OSD */
		stock->policy = WR_MODE_STOCK;
		return stock;
	}
	for (i = 0; i < NROWS; i++)
		if (k_rows[i].policy == policy)
			return &k_rows[i];
	return NULL;
}

static void check_offer(uint8_t mask, size_t n, const uint32_t *want)
{
	uint32_t got[2] = {0xdeadbeefu, 0xdeadbeefu};
	size_t i;

	WRT_CHECK_U64(wri_m2_offer_list(mask, got), n);
	for (i = 0; i < n; i++)
		WRT_CHECK_U64(got[i], want[i]);
	if (n == 1u)
		WRT_CHECK_U64(got[1], 0xdeadbeefu); /* the second slot is not written for a one-entry list */
}

/* Every policy x peer type x override (0 and every value, valid or not) against the table. */
static void test_matrix(void)
{
	static const uint8_t peers[] = {WRI_ENTITY_MON, WRI_ENTITY_OSD};
	unsigned pol, ovr, p;

	for (pol = 1; pol <= 5; pol++) {
		for (ovr = 0; ovr <= 5; ovr++) {
			for (p = 0; p < 2; p++) {
				uint8_t peer = peers[p];
				/* the override applies to OSD connections only; 0 means the same policy */
				uint8_t eff = (peer == WRI_ENTITY_OSD && ovr != 0u) ? (uint8_t)ovr : (uint8_t)pol;
				row stock;
				const row *e = expect_row(eff, peer, &stock);
				uint8_t got = wri_m2_offer_for((uint8_t)pol, (uint8_t)ovr, peer);

				WRT_CHECK(e != NULL);
				if (e == NULL)
					continue;
				WRT_CHECK_U64(got, e->mask);
				check_offer(got, e->n, e->list);
			}
		}
	}
}

static void test_unknown(void)
{
	unsigned v;

	/* every value outside 1..5 is no policy at all: 0 for both peer types, with and without an override */
	for (v = 0; v <= 255; v++) {
		if (v >= 1u && v <= 5u)
			continue;
		WRT_CHECK_U64(wri_m2_offer_for((uint8_t)v, 0, WRI_ENTITY_MON), 0);
		WRT_CHECK_U64(wri_m2_offer_for((uint8_t)v, 0, WRI_ENTITY_OSD), 0);
		WRT_CHECK_U64(wri_m2_offer_for((uint8_t)v, (uint8_t)v, WRI_ENTITY_OSD), 0);
		/* a bad override only matters to the OSD offer; a monitor keeps the policy */
		WRT_CHECK_U64(wri_m2_offer_for(WR_MODE_CRC_FIRST, (uint8_t)v, WRI_ENTITY_OSD), v == 0u ? (WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE) : 0u);
		WRT_CHECK_U64(wri_m2_offer_for(WR_MODE_CRC_FIRST, (uint8_t)v, WRI_ENTITY_MON), WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE);
	}
	/* a peer type that is neither monitor nor OSD has no offer */
	WRT_CHECK_U64(wri_m2_offer_for(WR_MODE_CRC_ONLY, 0, WRI_ENTITY_CLIENT), 0);
	WRT_CHECK_U64(wri_m2_offer_for(WR_MODE_STOCK, WR_MODE_STOCK, 0), 0);
	WRT_CHECK_U64(wri_m2_offer_for(WR_MODE_SECURE_ONLY, 0, 0xffu), 0);
}

static void test_list_and_has(void)
{
	static const uint32_t c[1] = {CRC}, s[1] = {SEC}, cs[2] = {CRC, SEC}, sc[2] = {SEC, CRC};
	unsigned m;

	check_offer(0, 1, c); /* empty mask: crc only */
	check_offer(WRI_M2_OFFER_SECURE_FIRST, 1, c); /* the order bit alone offers nothing */
	check_offer(WRI_M2_OFFER_CRC, 1, c);
	check_offer(WRI_M2_OFFER_SECURE, 1, s);
	check_offer(WRI_M2_OFFER_SECURE | WRI_M2_OFFER_SECURE_FIRST, 1, s); /* the order bit means nothing with one mode */
	check_offer(WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE_FIRST, 1, c);
	check_offer(WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE, 2, cs);
	check_offer(WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE | WRI_M2_OFFER_SECURE_FIRST, 2, sc);

	/* unknown high bits are ignored: all 256 masks agree with their low three bits */
	for (m = 0; m < 256u; m++) {
		uint32_t a[2] = {0, 0}, b[2] = {0, 0};
		size_t na = wri_m2_offer_list((uint8_t)m, a), nb = wri_m2_offer_list((uint8_t)(m & 7u), b);

		WRT_CHECK_U64(na, nb);
		WRT_CHECK(a[0] == b[0] && (na < 2u || a[1] == b[1]));
		WRT_CHECK(na == 1u || na == 2u);
		/* has() agrees with the list for both modes and is 0 for anything else */
		WRT_CHECK_U64(wri_m2_offer_has((uint8_t)m, CRC), a[0] == CRC || (na == 2u && a[1] == CRC));
		WRT_CHECK_U64(wri_m2_offer_has((uint8_t)m, SEC), a[0] == SEC || (na == 2u && a[1] == SEC));
		WRT_CHECK_U64(wri_m2_offer_has((uint8_t)m, 0), 0);
		WRT_CHECK_U64(wri_m2_offer_has((uint8_t)m, 3), 0);
		WRT_CHECK_U64(wri_m2_offer_has((uint8_t)m, 0x80000001u), 0);
	}
	WRT_CHECK(wri_m2_offer_has(0, CRC) == 1 && wri_m2_offer_has(0, SEC) == 0);
	WRT_CHECK(wri_m2_offer_has(WRI_M2_OFFER_SECURE, CRC) == 0 && wri_m2_offer_has(WRI_M2_OFFER_SECURE, SEC) == 1);
}

/* The offer of STOCK against what the stock client sends: the option strings of secure-mode spec 2.9 parsed the way the reference
 * client parses them (whitespace or comma separated tokens, `crc` and `secure`, the first listed is the first preferred). */
static size_t parse_modes(const char *s, uint32_t out[2])
{
	size_t n = 0;

	while (*s != '\0') {
		const char *t = s;
		size_t len;

		while (*s != '\0' && *s != ' ' && *s != ',')
			s++;
		len = (size_t)(s - t);
		if (len == 3u && memcmp(t, "crc", 3) == 0 && n < 2u)
			out[n++] = CRC;
		else if (len == 6u && memcmp(t, "secure", 6) == 0 && n < 2u)
			out[n++] = SEC;
		while (*s == ' ' || *s == ',')
			s++;
	}
	return n;
}

static void test_stock(void)
{
	static const char k_ms_mon_client_mode[] = "secure crc"; /* a client's offer to a monitor (spec 2.9) */
	static const char k_ms_client_mode[] = "crc secure";     /* a client's offer to an OSD */
	uint32_t want_mon[2] = {0, 0}, want_osd[2] = {0, 0};
	size_t nm = parse_modes(k_ms_mon_client_mode, want_mon), no = parse_modes(k_ms_client_mode, want_osd);
	uint8_t mon = wri_m2_offer_for(WR_MODE_STOCK, 0, WRI_ENTITY_MON);
	uint8_t osd = wri_m2_offer_for(WR_MODE_STOCK, 0, WRI_ENTITY_OSD);

	WRT_CHECK_U64(nm, 2);
	WRT_CHECK_U64(no, 2);
	check_offer(mon, nm, want_mon);
	check_offer(osd, no, want_osd);
	/* spelled out once, so a mistake in the table above cannot cancel against a mistake here */
	WRT_CHECK_U64(want_mon[0], SEC);
	WRT_CHECK_U64(want_mon[1], CRC);
	WRT_CHECK_U64(want_osd[0], CRC);
	WRT_CHECK_U64(want_osd[1], SEC);
	/* STOCK as the OSD override: a monitor still follows mode_policy */
	WRT_CHECK_U64(wri_m2_offer_for(WR_MODE_CRC_ONLY, WR_MODE_STOCK, WRI_ENTITY_OSD), osd);
	WRT_CHECK_U64(wri_m2_offer_for(WR_MODE_CRC_ONLY, WR_MODE_STOCK, WRI_ENTITY_MON), WRI_M2_OFFER_CRC);
	/* STOCK as the base policy with an override on the OSD side */
	WRT_CHECK_U64(wri_m2_offer_for(WR_MODE_STOCK, WR_MODE_CRC_ONLY, WRI_ENTITY_OSD), WRI_M2_OFFER_CRC);
	WRT_CHECK_U64(wri_m2_offer_for(WR_MODE_STOCK, WR_MODE_CRC_ONLY, WRI_ENTITY_MON), mon);
	/* a stock client with both modes offered is accepted by a default cluster whose servers allow both; and it differs by peer */
	WRT_CHECK(mon != osd);
}

static void test_may_secure(void)
{
	unsigned pol, ovr;

	for (pol = 0; pol <= 8; pol++) {
		for (ovr = 0; ovr <= 8; ovr++) {
			int want = ((wri_m2_offer_for((uint8_t)pol, (uint8_t)ovr, WRI_ENTITY_MON) |
				     wri_m2_offer_for((uint8_t)pol, (uint8_t)ovr, WRI_ENTITY_OSD)) &
				    WRI_M2_OFFER_SECURE) != 0u;

			WRT_CHECK_U64(wri_m2_policy_may_secure((uint8_t)pol, (uint8_t)ovr), want);
		}
	}
	/* the defaults and the explicit cases */
	WRT_CHECK(wri_m2_policy_may_secure(WR_MODE_CRC_ONLY, 0) == 0);
	WRT_CHECK(wri_m2_policy_may_secure(WR_MODE_CRC_ONLY, WR_MODE_CRC_ONLY) == 0);
	WRT_CHECK(wri_m2_policy_may_secure(WR_MODE_CRC_FIRST, 0) == 1);
	WRT_CHECK(wri_m2_policy_may_secure(WR_MODE_SECURE_FIRST, 0) == 1);
	WRT_CHECK(wri_m2_policy_may_secure(WR_MODE_SECURE_ONLY, 0) == 1);
	WRT_CHECK(wri_m2_policy_may_secure(WR_MODE_STOCK, 0) == 1);
	/* crc for the monitor but secure for OSDs, and the other way round: still "may" */
	WRT_CHECK(wri_m2_policy_may_secure(WR_MODE_CRC_ONLY, WR_MODE_SECURE_ONLY) == 1);
	WRT_CHECK(wri_m2_policy_may_secure(WR_MODE_SECURE_ONLY, WR_MODE_CRC_ONLY) == 1);
	/* unknown values offer nothing, so they never reserve secure memory (the configuration is refused before this matters) */
	WRT_CHECK(wri_m2_policy_may_secure(0, 0) == 0);
	WRT_CHECK(wri_m2_policy_may_secure(6, 0) == 0);
	WRT_CHECK(wri_m2_policy_may_secure(255, 255) == 0);
}

/* The validity rule: policy 1..5, override 0..5, nothing else; and a valid pair never offers nothing to either peer type. */
static void test_valid(void)
{
	unsigned pol, ovr;

	for (pol = 0; pol <= 255; pol++) {
		for (ovr = 0; ovr <= 255; ovr++) {
			int want = pol >= 1u && pol <= 5u && ovr <= 5u;
			int got = wri_m2_policy_valid((uint8_t)pol, (uint8_t)ovr);

			WRT_CHECK_U64(got, want);
			if (got) {
				WRT_CHECK(wri_m2_offer_for((uint8_t)pol, (uint8_t)ovr, WRI_ENTITY_MON) != 0u);
				WRT_CHECK(wri_m2_offer_for((uint8_t)pol, (uint8_t)ovr, WRI_ENTITY_OSD) != 0u);
			}
		}
	}
	/* the hazard it exists for: secure only to the monitor, a garbage OSD override gives an empty (= crc) OSD offer */
	WRT_CHECK(wri_m2_policy_valid(WR_MODE_SECURE_ONLY, 9) == 0);
	WRT_CHECK_U64(wri_m2_offer_for(WR_MODE_SECURE_ONLY, 9, WRI_ENTITY_OSD), 0);
}

/* A policy that says secure only never produces a mask or `has` answer that lets crc through, for either peer type. */
static void test_secure_only_never_crc(void)
{
	static const uint8_t peers[] = {WRI_ENTITY_MON, WRI_ENTITY_OSD};
	static const uint8_t overrides[] = {0, WR_MODE_SECURE_ONLY}; /* same as the policy, or explicitly secure only */
	unsigned o, p;

	for (o = 0; o < 2; o++) {
		for (p = 0; p < 2; p++) {
			uint8_t m = wri_m2_offer_for(WR_MODE_SECURE_ONLY, overrides[o], peers[p]);

			WRT_CHECK_U64(m, WRI_M2_OFFER_SECURE);
			WRT_CHECK(wri_m2_offer_has(m, SEC) == 1 && wri_m2_offer_has(m, CRC) == 0);
		}
	}
}

int main(void)
{
	test_matrix();
	test_unknown();
	test_list_and_has();
	test_stock();
	test_may_secure();
	test_valid();
	test_secure_only_never_crc();
	return wrt_finish();
}
