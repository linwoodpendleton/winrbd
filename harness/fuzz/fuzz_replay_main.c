/* SPDX-License-Identifier: MIT */
/*
 * Replay driver for fuzz targets in builds without libFuzzer: feeds every regular file of the given
 * directories (or the given files) to LLVMFuzzerTestOneInput once. Lets the committed seed corpus run
 * as an ordinary ctest regression test. A missing directory is an empty corpus (exit 0).
 */
#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static unsigned long replayed;

static int replay_file(const char *path)
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
		return -1;
	}
	b = (uint8_t *)malloc((size_t)len + 1);
	if (!b || fread(b, 1, (size_t)len, f) != (size_t)len) {
		free(b);
		fclose(f);
		return -1;
	}
	fclose(f);
	(void)LLVMFuzzerTestOneInput(b, (size_t)len);
	free(b);
	replayed++;
	return 0;
}

static int replay_path(const char *path)
{
	struct stat st;
	DIR *d;
	struct dirent *e;
	int rc = 0;

	if (stat(path, &st) != 0)
		return 0; /* missing = empty corpus */
	if (!S_ISDIR(st.st_mode))
		return replay_file(path);
	d = opendir(path);
	if (!d)
		return -1;
	while ((e = readdir(d)) != NULL) {
		char full[4096];

		if (e->d_name[0] == '.')
			continue;
		snprintf(full, sizeof(full), "%s/%s", path, e->d_name);
		if (replay_path(full) != 0)
			rc = -1;
	}
	closedir(d);
	return rc;
}

int main(int argc, char **argv)
{
	int i, rc = 0;

	for (i = 1; i < argc; i++)
		if (replay_path(argv[i]) != 0)
			rc = 1;
	printf("replayed %lu inputs\n", replayed);
	return rc;
}
