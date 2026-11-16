/* SPDX-License-Identifier: MIT */
#include "wrt.h"

#include "wr_err.h"

unsigned long wrt_checks;
unsigned long wrt_failures;

const char *wrt_status_name_(int32_t st)
{
	return wr_status_name(st);
}

void wrt_check_mem_(const char *file, int line, const char *what, const void *got, const void *want, size_t n)
{
	const uint8_t *a = (const uint8_t *)got, *b = (const uint8_t *)want;
	size_t i;

	wrt_checks++;
	for (i = 0; i < n; i++) {
		if (a[i] != b[i]) {
			wrt_failures++;
			fprintf(stderr, "%s:%d: %s differs at offset %zu of %zu: got %02x, want %02x\n", file, line,
				what, i, n, a[i], b[i]);
			return;
		}
	}
}

int wrt_finish(void)
{
	if (wrt_failures) {
		fprintf(stderr, "FAILED: %lu of %lu checks\n", wrt_failures, wrt_checks);
		return 1;
	}
	printf("ok: %lu checks\n", wrt_checks);
	return 0;
}

int wrt_read_file(const char *path, uint8_t **buf, size_t *n)
{
	FILE *f = fopen(path, "rb");
	long len;
	uint8_t *b;

	if (!f) {
		fprintf(stderr, "cannot open %s\n", path);
		return -1;
	}
	if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		fprintf(stderr, "cannot size %s\n", path);
		return -1;
	}
	b = (uint8_t *)malloc((size_t)len + 1);
	if (!b || fread(b, 1, (size_t)len, f) != (size_t)len) {
		free(b);
		fclose(f);
		fprintf(stderr, "cannot read %s\n", path);
		return -1;
	}
	fclose(f);
	b[len] = 0;
	*buf = b;
	*n = (size_t)len;
	return 0;
}

const char *wrt_vec_path(const char *rel)
{
	static char path[1024];
	const char *dir = getenv("WRT_VECTOR_DIR");

	if (!dir || !*dir)
		dir = WRT_VECTOR_DIR;
	snprintf(path, sizeof(path), "%s/%s", dir, rel);
	return path;
}

static int wrt_hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int wrt_hex_decode(const char *hex, size_t len, uint8_t **out, size_t *n)
{
	uint8_t *b = (uint8_t *)malloc(len / 2 + 1);
	size_t i, k = 0;
	int hi = -1;

	if (!b)
		return -1;
	for (i = 0; i < len; i++) {
		int v;

		if (hex[i] == ' ' || hex[i] == '\n' || hex[i] == '\r' || hex[i] == '\t')
			continue;
		v = wrt_hexval((unsigned char)hex[i]);
		if (v < 0) {
			free(b);
			return -1;
		}
		if (hi < 0) {
			hi = v;
		} else {
			b[k++] = (uint8_t)((hi << 4) | v);
			hi = -1;
		}
	}
	if (hi >= 0) {
		free(b);
		return -1;
	}
	*out = b;
	*n = k;
	return 0;
}

void wrt_hex_encode(const uint8_t *p, size_t n, char *out)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) {
		out[2 * i] = digits[p[i] >> 4];
		out[2 * i + 1] = digits[p[i] & 15];
	}
	out[2 * n] = 0;
}
