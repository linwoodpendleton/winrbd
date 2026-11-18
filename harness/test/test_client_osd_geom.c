/* SPDX-License-Identifier: MIT */
/*
 * test_client_osd_geom.c - which object and which byte of it a byte of the image lands on, on the whole engine (module client-glue-osd; client_osd_rig.h):
 * the object names, the in-object offsets and the sizes of the object operations are checked in the object store, not through the engine's own reads.
 *
 *   huge images       sizes above 4 GiB, 1 TiB and 8 TiB (object numbers above 2^31 and 2^32 at order 12): a write that ends the last byte of an object
 *                     and starts the next one lands in the two objects named by the 16 hex digit number; a read of the same range returns it
 *   partial last      an image size that is no multiple of the object size: the last object is only as long as the image says; the last byte reads and
 *                     writes, one byte more is WR_E_RANGE (nothing is queued), a request that ends at the size works, a zero-length request at the size
 *                     works, one byte beyond it is WR_E_RANGE
 *   object sizes      the smallest (4 KiB) and the largest (32 MiB) object order the open accepts: a request over several objects is cut at every boundary
 *   missing objects   a read over objects that were never written is all zeros (ENOENT is not an error), partial objects read as zeros past their end
 */
#include "client_osd_rig.h"

static int objname(char *out, size_t cap, const wr_image_info *info, uint64_t objno)
{
	return snprintf(out, cap, "%s.%016" PRIx64, info->object_prefix, objno);
}

static wr_image *open_img(cw *w, wr_image_info *info)
{
	wr_image_params p = cw_params("img", 1);
	wr_image_state fin = WR_IMG_FREE;
	wr_image *img = cw_open_image(w, &p, &fin);

	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN)
		return NULL;
	WRT_CHECK_STATUS(WR_OK, wr_image_get_info(img, info));
	return img;
}

/* Write n bytes of the pattern at `off`, read them back through the engine and look at the two object names the bytes must be in. */
static void write_read_check(cw *w, wr_image *img, const wr_image_info *info, uint64_t off, size_t n, uint32_t seed)
{
	uint8_t *buf = (uint8_t *)malloc(n), *back = (uint8_t *)malloc(n), *obj = (uint8_t *)malloc(n);
	wr_io_req r;
	uint64_t os = info->object_size, o, done = 0;

	if (buf == NULL || back == NULL || obj == NULL) {
		WRT_CHECK(0);
		free(buf);
		free(back);
		free(obj);
		return;
	}
	cw_fill(buf, seed, off, n);
	r = cw_req(WR_IO_WRITE, off, n, buf);
	WRT_CHECK_STATUS(WR_OK, cw_do(w, img, &r, 60000));
	memset(back, 0xee, n);
	r = cw_req(WR_IO_READ, off, n, back);
	WRT_CHECK_STATUS(WR_OK, cw_do(w, img, &r, 60000));
	WRT_CHECK_MEM(back, buf, n);
	for (o = off / os; done < n; o++) {
		char name[160];
		int exists = 0;
		uint64_t in = o == off / os ? off % os : 0, len = os - in < n - done ? os - in : n - done;

		objname(name, sizeof(name), info, o);
		memset(obj, 0xee, (size_t)len);
		WRT_CHECK_STATUS(WR_OK, sim_store_read(w->store, info->data_pool_id, name, in, obj, (size_t)len, &exists));
		WRT_CHECK(exists);
		WRT_CHECK_MEM(obj, buf + done, (size_t)len);
		done += len;
	}
	free(buf);
	free(back);
	free(obj);
}

/* ---- huge images --------------------------------------------------------------------------------------------------------------- */

static void huge_one(uint64_t size, uint8_t order)
{
	cw w;
	wr_image *img;
	wr_image_info info;
	uint64_t os = 1ull << order, pts[8], last;
	unsigned i;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "big", size, order, 0x21, -1) == 0);
	img = open_img(&w, &info);
	if (img == NULL) {
		cw_free(&w);
		return;
	}
	WRT_CHECK_U64(info.size_bytes, size);
	WRT_CHECK_U64(info.order, order);
	WRT_CHECK_U64(info.object_size, os);
	last = size - 1u;
	pts[0] = os - 4u;                                  /* across the first boundary */
	pts[1] = (1ull << 31) - 4u;                        /* across 2^31 (a multiple of every object size) */
	pts[2] = (1ull << 32) - 4u;                        /* across 2^32 */
	pts[3] = (1ull << 33) + os - 5u;                   /* an object boundary that is no power of two of the byte count */
	pts[4] = (size / 2u / os) * os - 3u;               /* about the middle of the image */
	pts[5] = ((size - 1u) / os) * os - 6u;             /* across the start of the last object */
	pts[6] = size - 9u;                                /* the last 9 bytes */
	pts[7] = last;                                     /* the very last byte */
	for (i = 0; i < 8u; i++) {
		size_t n = i == 7u ? 1u : 8u;

		if (pts[i] + n > size)
			continue; /* the small images do not reach the larger points */
		write_read_check(&w, img, &info, pts[i], n, 100u + i);
	}
	{
		uint8_t b[4];
		wr_io_req r = cw_req(WR_IO_WRITE, size - 3u, 4, b);

		memset(b, 1, sizeof(b));
		WRT_CHECK_STATUS(WR_E_RANGE, cw_submit(img, &r)); /* one byte beyond the image */
		r = cw_req(WR_IO_READ, size, 1, b);
		WRT_CHECK_STATUS(WR_E_RANGE, cw_submit(img, &r));
		r = cw_req(WR_IO_READ, size + 1u, 0, b);
		WRT_CHECK_STATUS(WR_E_RANGE, cw_submit(img, &r));
		r = cw_req(WR_IO_READ, size, 0, b); /* a zero-length request at the size is fine */
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 5000));
	}
	cw_free(&w);
}

static void test_huge(void)
{
	huge_one((1ull << 33) + 12345u, 22);          /* 8 GiB and a bit, 4 MiB objects */
	huge_one((1ull << 40) + 1000u, 22);           /* 1 TiB */
	huge_one((1ull << 43) + 1000u, 22);           /* 8 TiB, object number 2^21 for the last one */
	huge_one((1ull << 40) + 5u, 12);              /* order 12: object numbers up to 2^28 (the 16 hex digits carry them) */
	huge_one((1ull << 44) + 4096u * 3u + 17u, 12); /* object numbers above 2^32 */
}

/* ---- partial last object, the two ends of the order range ------------------------------------------------------------------------- */

static void test_orders(void)
{
	static const uint8_t orders[] = {12, 13, 16, 20, 22, 25};
	unsigned k;

	for (k = 0; k < sizeof(orders); k++) {
		uint64_t os = 1ull << orders[k], size = 3u * os + 777u;
		size_t whole = (size_t)(os + 777u + 3000u); /* the tail of the image: the end of object 1, all of object 2, the partial object 3 */
		uint64_t base = size - whole;
		cw w;
		wr_image *img;
		wr_image_info info;
		uint8_t *buf, *back;
		wr_io_req r;

		buf = (uint8_t *)malloc(whole);
		back = (uint8_t *)malloc(whole);
		WRT_CHECK(buf != NULL && back != NULL);
		WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
		WRT_CHECK(cw_image(&w, "img", "geo", size, orders[k], 0x21, -1) == 0);
		img = open_img(&w, &info);
		if (img == NULL || buf == NULL || back == NULL) {
			cw_free(&w);
			free(buf);
			free(back);
			continue;
		}
		/* the tail in one request (several objects, the last one partial) */
		cw_fill(buf, 55u + k, base, whole);
		r = cw_req(WR_IO_WRITE, base, whole, buf);
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 600000));
		memset(back, 0xee, whole);
		r = cw_req(WR_IO_READ, base, whole, back);
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 600000));
		WRT_CHECK_MEM(back, buf, whole);
		{
			char name[160];
			uint64_t len = 0;

			objname(name, sizeof(name), &info, 3);
			WRT_CHECK_STATUS(WR_OK, sim_store_size(w.store, info.data_pool_id, name, &len)); /* the last object holds the 777 bytes and no more */
			WRT_CHECK_U64(len, 777);
			objname(name, sizeof(name), &info, 4);
			WRT_CHECK(!sim_store_exists(w.store, info.data_pool_id, name)); /* nothing past the image */
		}
		/* discard the tail: whole objects go, the partial last object is truncated or zeroed, never extended */
		r = cw_req(WR_IO_DISCARD, base, whole, NULL);
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 600000));
		memset(back, 0xee, whole);
		r = cw_req(WR_IO_READ, base, whole, back);
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 600000));
		{
			size_t i, nz = 0;

			for (i = 0; i < whole; i++)
				nz += back[i] != 0;
			WRT_CHECK_U64(nz, 0);
		}
		{
			char name[160];
			uint64_t len = 0;

			objname(name, sizeof(name), &info, 3);
			if (sim_store_exists(w.store, info.data_pool_id, name)) {
				WRT_CHECK_STATUS(WR_OK, sim_store_size(w.store, info.data_pool_id, name, &len));
				WRT_CHECK(len <= 777u);
			}
		}
		/* write-zeroes over the last 782 bytes (the partial object and 5 bytes before it) after a full write */
		cw_fill(buf, 9u, base, whole);
		r = cw_req(WR_IO_WRITE, base, whole, buf);
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 600000));
		r = cw_req(WR_IO_WRITE_ZEROES, size - 782u, 782, NULL);
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 600000));
		memset(back, 0xee, whole);
		r = cw_req(WR_IO_READ, base, whole, back);
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 600000));
		{
			size_t i, bad = 0;

			for (i = 0; i < whole; i++)
				bad += back[i] != (i >= whole - 782u ? 0u : buf[i]);
			WRT_CHECK_U64(bad, 0);
		}
		cw_free(&w);
		free(buf);
		free(back);
	}
}

/* ---- missing objects --------------------------------------------------------------------------------------------------------------- */

static void test_missing(void)
{
	cw w;
	wr_image *img;
	wr_image_info info;
	uint64_t os, size;
	uint8_t *back;
	wr_io_req r;
	size_t i, nz = 0;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	size = (1ull << 36) + 3000u;
	WRT_CHECK(cw_image(&w, "img", "sparse", size, 16, 0x21, -1) == 0);
	img = open_img(&w, &info);
	back = (uint8_t *)malloc(200000);
	if (img == NULL || back == NULL) {
		cw_free(&w);
		free(back);
		return;
	}
	os = info.object_size;
	memset(back, 0xee, 200000);
	r = cw_req(WR_IO_READ, (1ull << 35) + 5u, 200000, back); /* three objects that never existed */
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 60000));
	for (i = 0; i < 200000; i++)
		nz += back[i] != 0;
	WRT_CHECK_U64(nz, 0);
	/* one short object in the middle of the range: it reads as itself, then zeros */
	{
		uint8_t small[10];
		uint64_t base = (1ull << 35) + 3u * os, start = base - 50u;

		cw_fill(small, 3u, base + 100u, sizeof(small));
		r = cw_req(WR_IO_WRITE, base + 100u, sizeof(small), small);
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 60000));
		memset(back, 0xee, 3000);
		r = cw_req(WR_IO_READ, start, 3000, back);
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 60000));
		for (i = 0; i < 3000; i++) {
			uint64_t at = start + i;
			uint8_t want = at >= base + 100u && at < base + 110u ? cw_pat(3u, at) : 0u;

			if (back[i] != want) {
				WRT_CHECK(back[i] == want);
				break;
			}
		}
	}
	cw_free(&w);
	free(back);
}

int main(void)
{
	test_huge();
	test_orders();
	test_missing();
	return wrt_finish();
}
