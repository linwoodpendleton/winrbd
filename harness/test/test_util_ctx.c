/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of core/src/util/wri_ctx.c: random with a failing or missing source, log emission
 * (null sink, level filtering, record contents) and the first-failure-wins errinfo.
 */
#include "wrt.h"

/* Lower the compile-time ceiling in this translation unit only, to test that WRI_LOG compiles away
 * above it. wri_log_emit itself is compiled into the library with the default ceiling. */
#define WR_LOG_MAX_LEVEL 3
#include "wri_ctx.h"

/* ---- fake host ---------------------------------------------------------------------------- */

struct fake {
	unsigned random_calls;
	size_t last_n;
	int fail_random;     /* return an error after writing garbage */
	int fail_with;       /* the error to return (0 = WR_E_HOST_RANDOM) */
	unsigned log_calls;
	wr_log_rec last;
	void *last_ctx;
};

static wr_status fake_random(void *ctx, uint8_t *out, size_t n)
{
	struct fake *f = (struct fake *)ctx;
	size_t i;

	f->random_calls++;
	f->last_n = n;
	for (i = 0; i < n; i++)
		out[i] = (uint8_t)(0xA0 + i);
	if (f->fail_random)
		return f->fail_with ? (wr_status)f->fail_with : WR_E_HOST_RANDOM;
	return WR_OK;
}

static void fake_log(void *ctx, const wr_log_rec *rec)
{
	struct fake *f = (struct fake *)ctx;

	f->log_calls++;
	f->last = *rec;
	f->last_ctx = ctx;
}

static void ctx_init(wri_ctx *x, struct fake *f, int with_random, int with_log)
{
	memset(x, 0, sizeof(*x));
	memset(f, 0, sizeof(*f));
	x->host.size = (uint32_t)sizeof(x->host);
	x->host.ctx = f;
	x->host.random = with_random ? fake_random : NULL;
	x->host.log = with_log ? fake_log : NULL;
}

/* ---- random ------------------------------------------------------------------------------- */

static void test_random(void)
{
	wri_ctx x;
	struct fake f;
	uint8_t buf[16];
	static const uint8_t zero16[16] = {0};

	ctx_init(&x, &f, 1, 0);
	memset(buf, 0, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wri_random(&x, buf, 16));
	WRT_CHECK_U64(f.random_calls, 1);
	WRT_CHECK_U64(f.last_n, 16);
	WRT_CHECK_U64(buf[0], 0xA0);
	WRT_CHECK_U64(buf[15], 0xAF);

	/* zero length: success without bothering the host, as long as there is a source */
	WRT_CHECK_STATUS(WR_OK, wri_random(&x, buf, 0));
	WRT_CHECK_STATUS(WR_OK, wri_random(&x, NULL, 0));
	WRT_CHECK_U64(f.random_calls, 1);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_random(&x, NULL, 4)); /* nowhere to put the bytes */

	/* the host fails: the error is WR_E_HOST_RANDOM whatever it returned, and partial bytes are wiped */
	f.fail_random = 1;
	memset(buf, 0xEE, sizeof(buf));
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wri_random(&x, buf, 16));
	WRT_CHECK_MEM(buf, zero16, 16);
	f.fail_with = WR_E_BUSY;
	memset(buf, 0xEE, sizeof(buf));
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wri_random(&x, buf, 8));
	WRT_CHECK_U64(buf[0] | buf[7], 0);
	WRT_CHECK_U64(buf[8], 0xEE); /* only the requested range is touched */

	/* no source at all: an error, never a silent weak fallback (also for zero length) */
	ctx_init(&x, &f, 0, 0);
	memset(buf, 0xEE, sizeof(buf));
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wri_random(&x, buf, 16));
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wri_random(&x, buf, 0));
	WRT_CHECK_U64(buf[0], 0xEE); /* untouched: nothing was produced */
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wri_random(NULL, buf, 16));
}

/* ---- log ---------------------------------------------------------------------------------- */

static void test_log_basic(void)
{
	wri_ctx x;
	struct fake f;

	ctx_init(&x, &f, 0, 1);
	wri_log_emit(&x, WR_LOG_ERR, WR_MOD_M2, 7, WR_E_M2_FRAME_CRC, "bad crc", 1, 2, 3, 0xFFFFFFFFFFFFFFFFull);
	WRT_CHECK_U64(f.log_calls, 1);
	WRT_CHECK_U64(f.last.level, WR_LOG_ERR);
	WRT_CHECK_U64(f.last.module, WR_MOD_M2);
	WRT_CHECK_U64(f.last.conn, 7);
	WRT_CHECK_STATUS(WR_E_M2_FRAME_CRC, f.last.status);
	WRT_CHECK(f.last.msg != NULL && strcmp(f.last.msg, "bad crc") == 0);
	WRT_CHECK_U64(f.last.a0, 1);
	WRT_CHECK_U64(f.last.a1, 2);
	WRT_CHECK_U64(f.last.a2, 3);
	WRT_CHECK_U64(f.last.a3, 0xFFFFFFFFFFFFFFFFull);
	WRT_CHECK_U64(f.last.reserved16, 0);
	WRT_CHECK(f.last_ctx == &f); /* the host's ctx is passed back */

	/* all legal levels reach the sink through the function (the library ceiling is the default 5) */
	f.log_calls = 0;
	wri_log_emit(&x, WR_LOG_WARN, 1, 0, WR_OK, "w", 0, 0, 0, 0);
	wri_log_emit(&x, WR_LOG_INFO, 1, 0, WR_OK, "i", 0, 0, 0, 0);
	wri_log_emit(&x, WR_LOG_DEBUG, 1, 0, WR_OK, "d", 0, 0, 0, 0);
	wri_log_emit(&x, WR_LOG_TRACE, 1, 0, WR_OK, "t", 0, 0, 0, 0);
	WRT_CHECK_U64(f.log_calls, 4);
	/* out-of-range levels are dropped: 0, 6, huge */
	wri_log_emit(&x, 0, 1, 0, WR_OK, "zero", 0, 0, 0, 0);
	wri_log_emit(&x, 6, 1, 0, WR_OK, "six", 0, 0, 0, 0);
	wri_log_emit(&x, 0xFFFFFFFFu, 1, 0, WR_OK, "huge", 0, 0, 0, 0);
	WRT_CHECK_U64(f.log_calls, 4);
	/* module ids are narrowed, not trusted */
	wri_log_emit(&x, WR_LOG_ERR, 0x1FFu, 0, WR_OK, "m", 0, 0, 0, 0);
	WRT_CHECK_U64(f.last.module, 0xFF);
}

static void test_log_null_sink(void)
{
	wri_ctx x;
	struct fake f;

	ctx_init(&x, &f, 0, 0); /* no log callback */
	wri_log_emit(&x, WR_LOG_ERR, WR_MOD_UTIL, 0, WR_E_INVAL, "nobody listens", 0, 0, 0, 0);
	WRT_CHECK_U64(f.log_calls, 0);
	wri_log_emit(NULL, WR_LOG_ERR, WR_MOD_UTIL, 0, WR_E_INVAL, "no ctx", 0, 0, 0, 0); /* must not crash */
	WRT_CHECK_U64(f.log_calls, 0);
}

static void test_log_macro_ceiling(void)
{
	wri_ctx x;
	struct fake f;

	WRT_CHECK_U64(WR_LOG_MAX_LEVEL, 3);
	ctx_init(&x, &f, 0, 1);
	WRI_LOG(&x, WR_LOG_ERR, WR_MOD_UTIL, 0, WR_OK, "e", 1, 2, 3, 4);
	WRI_LOG(&x, WR_LOG_WARN, WR_MOD_UTIL, 0, WR_OK, "w", 0, 0, 0, 0);
	WRI_LOG(&x, WR_LOG_INFO, WR_MOD_UTIL, 0, WR_OK, "i", 0, 0, 0, 0);
	WRT_CHECK_U64(f.log_calls, 3);
	WRI_LOG(&x, WR_LOG_DEBUG, WR_MOD_UTIL, 0, WR_OK, "d", 0, 0, 0, 0); /* above the ceiling: nothing */
	WRI_LOG(&x, WR_LOG_TRACE, WR_MOD_UTIL, 0, WR_OK, "t", 0, 0, 0, 0);
	WRT_CHECK_U64(f.log_calls, 3);
	WRT_CHECK(strcmp(f.last.msg, "i") == 0);
	/* arguments are widened to u64 without sign trouble */
	WRI_LOG(&x, WR_LOG_ERR, WR_MOD_UTIL, 0, WR_OK, "neg", (uint32_t)0xFFFFFFFFu, 'x', (size_t)5, (uint8_t)9);
	WRT_CHECK_U64(f.last.a0, 0xFFFFFFFFu);
	WRT_CHECK_U64(f.last.a1, 'x');
	WRT_CHECK_U64(f.last.a2, 5);
	WRT_CHECK_U64(f.last.a3, 9);
}

/* ---- errinfo ------------------------------------------------------------------------------ */

static void test_errinfo(void)
{
	wr_errinfo e;
	static const char what1[] = "first check";
	static const char what2[] = "second check";

	memset(&e, 0, sizeof(e));
	WRT_CHECK_STATUS(WR_OK, e.status);

	wri_errinfo_set(&e, WR_E_M2_FRAME_CRC, WR_MOD_M2, 321, what1, 11, 22, 33);
	WRT_CHECK_STATUS(WR_E_M2_FRAME_CRC, e.status);
	WRT_CHECK_U64(e.module, WR_MOD_M2);
	WRT_CHECK_U64(e.line, 321);
	WRT_CHECK(e.what == what1);
	WRT_CHECK_U64(e.a0, 11);
	WRT_CHECK_U64(e.a1, 22);
	WRT_CHECK_U64(e.a2, 33);

	/* a later failure (the fallout) does not overwrite the root cause, in any field */
	wri_errinfo_set(&e, WR_E_NET_CLOSED, WR_MOD_CLIENT, 999, what2, 1, 2, 3);
	WRT_CHECK_STATUS(WR_E_M2_FRAME_CRC, e.status);
	WRT_CHECK_U64(e.module, WR_MOD_M2);
	WRT_CHECK_U64(e.line, 321);
	WRT_CHECK(e.what == what1);
	WRT_CHECK_U64(e.a0, 11);
	WRT_CHECK_U64(e.a2, 33);

	/* recording "success" is not a failure and does not claim the slot */
	memset(&e, 0, sizeof(e));
	wri_errinfo_set(&e, WR_OK, WR_MOD_M2, 1, what1, 1, 1, 1);
	WRT_CHECK_STATUS(WR_OK, e.status);
	WRT_CHECK(e.what == NULL);
	wri_errinfo_set(&e, WR_E_AUTH_DENIED, WR_MOD_AUTH, 5, NULL, 0, 0, 0); /* what may be NULL */
	WRT_CHECK_STATUS(WR_E_AUTH_DENIED, e.status);
	WRT_CHECK(e.what == NULL);

	/* caller-set peer_result and conn survive the record */
	memset(&e, 0, sizeof(e));
	e.peer_result = -13;
	e.conn = 4;
	wri_errinfo_set(&e, WR_E_AUTH_RESULT, WR_MOD_AUTH, 5, what1, 0, 0, 0);
	WRT_CHECK(e.peer_result == -13);
	WRT_CHECK_U64(e.conn, 4);

	/* narrowing: huge line and module values are clamped / masked rather than wrapped to a wrong value */
	memset(&e, 0, sizeof(e));
	wri_errinfo_set(&e, WR_E_INVAL, 0x105u, 70000u, what1, 0, 0, 0);
	WRT_CHECK_U64(e.line, 0xFFFF);
	WRT_CHECK_U64(e.module, 5);

	/* NULL target is ignored; the macro supplies the source line */
	wri_errinfo_set(NULL, WR_E_INVAL, 0, 0, NULL, 0, 0, 0);
	memset(&e, 0, sizeof(e));
	WRI_ERRINFO(&e, WR_E_RANGE, WR_MOD_UTIL, "range check", -1, 'a', 3);
	WRT_CHECK_STATUS(WR_E_RANGE, e.status);
	WRT_CHECK(e.line > 0);
	WRT_CHECK(e.what != NULL && strcmp(e.what, "range check") == 0);
	WRT_CHECK_U64(e.a0, 0xFFFFFFFFFFFFFFFFull); /* (uint64_t)-1 */
	WRT_CHECK_U64(e.a1, 'a');
	WRI_ERRINFO(&e, WR_E_INVAL, WR_MOD_UTIL, "later", 0, 0, 0);
	WRT_CHECK_STATUS(WR_E_RANGE, e.status);

	/* a reset (status back to 0) re-arms it */
	e.status = WR_OK;
	WRI_ERRINFO(&e, WR_E_INVAL, WR_MOD_UTIL, "after reset", 0, 0, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, e.status);
}

int main(void)
{
	test_random();
	test_log_basic();
	test_log_null_sink();
	test_log_macro_ceiling();
	test_errinfo();
	return wrt_finish();
}
