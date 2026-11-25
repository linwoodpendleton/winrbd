/* SPDX-License-Identifier: MIT */
/*
 * rbft-check - find the "rBFT" handoff table in a booted Linux guest, check EVERY field of it against the
 * values the test expects, print one PASS / FAIL / SKIP line per field, and (for the boot hook) write out
 * what the hook needs to bring the NIC up and to map the image with the kernel client.
 *
 * This is the guest side of the proof "the table matches the design" (docs/design/ipxe-driver.md, 14.3). It
 * is a THIRD implementation of the layout of docs/design/handoff-table.md, written from that document and
 * sharing no code with core/src/handoff/ (the codec the iPXE driver uses) nor with the Python generator of the
 * golden vectors: if the codec and this tool agree on what the firmware built, the table is right.
 *
 * Where the table comes from (exactly one):
 *   --sysfs [PATH]     the firmware table as Linux exposes it (UEFI; default /sys/firmware/acpi/tables/rBFT)
 *   --file PATH        a file holding the table (tests; also /sys/firmware/qemu_fw_cfg/by_name/<name>/raw)
 *   --scan             BIOS: scan physical memory through /dev/mem (iomem=relaxed on the kernel command line)
 *                      for the signature with a valid checksum, 16-byte aligned; default range 0 .. 0x100000,
 *                      --range LO-HI (hex or decimal, repeatable) to scan others
 *   --scan-file PATH   the same scan over a file taken as a memory image whose first byte is address 0
 *                      (--base ADDR shifts that); used by the unit test
 *
 * What it is checked against: "expectations", name=value pairs written as rbft.<name>=<value> on the kernel
 * command line (--cmdline), in a file (--params FILE, same syntax, whitespace separated) or as --param
 * name=value. The first source that names a field wins (--param, then the command line, then the files).
 * A field without an expectation is SKIP, or FAIL with --strict (so a test configuration cannot pass by
 * leaving things out). "-" means: expected absent / zero. Names:
 *   mons=ip:port[,ip:port...]  ([v6]:port for IPv6)   entity pool image imageid snap   ("-" = absent)
 *   auth=none|cephx   mode=crc|crc-first|secure-first|secure   flags=ro,key,static,vlan,fsid,secure|none|NUMBER
 *   keytype=none|aes|aes256k   keylen=N   fsid=UUID|-   mac=aa:bb:cc:dd:ee:ff   vlan=N   mtu=N
 *   ip=ADDR/PREFIX|-   gw=ADDR|-   dns=ADDR|-
 * Fields that need no expectation (they are fixed by the design) are always checked: signature, length,
 * revision, checksum, magic, version, header_len, the reserved bytes, the canonical layout and every rule of
 * the field table, the namespace (absent in version 1). The OEM and creator fields are not interpreted (iPXE
 * overwrites them): they are printed as INFO.
 *
 * Output: one line per field, "RBFT PASS|FAIL|SKIP|INFO <field>: <detail>", then
 * "RBFT-RESULT PASS|FAIL pass=N fail=N skip=N". The key is never printed (only its type and length).
 *
 * For the boot hook:
 *   --emit-env FILE    shell variables RBFT_* (monitors, entity, pool, image, NIC ...), written only when
 *                      the table is structurally sound and its names are safe to hand to a shell and to the
 *                      kernel client (only A-Z a-z 0-9 . _ - + : in entity, pool, image, snapshot and image id; a snapshot named "-" is
 *                      refused too, the hook reads that as "none"). Any file of an earlier run at that path is removed first.
 *   --emit-secret FILE the table's key in the armoured base64 form the kernel client's secret= option takes
 *                      (mode 0600, created exclusively); only for an "aes" key (the kernel client rejects
 *                      the 32-byte "aes256k" keys); nothing is written otherwise
 *   --supplied-key FILE a key from another channel (armoured base64, as "ceph auth get-key" prints it):
 *                      when the table also carries one, they must be equal (PASS/FAIL "key_value")
 *   --check-nic        also require a network interface with the table's MAC (reads /sys/class/net; --net-dir DIR reads DIR instead)
 *   --cmdline-file F   read the command line from F instead of /proc/cmdline (with --cmdline)
 *   --hexdump          print the table as "RBFT DUMP <offset>: <16 bytes>" lines (an acpidump-style record for the run's log); the
 *                      bytes of the key are replaced by ".." (a table that cannot be decoded is shown up to the end of the fixed part
 *                      only, because the place of the key is not known)
 *
 * Every line is printed through one sanitiser (bytes outside 0x20..0x7e become '?'): a name in the table cannot add a line, not even a
 * forged RBFT-RESULT, to the output the run is judged on.
 *
 * Exit status: 0 every line PASS or SKIP, 1 at least one FAIL, 2 no table, unreadable input or bad usage.
 *
 * Portable C99 + POSIX, no allocation beyond a table-sized buffer, builds static (-static) so that it can
 * sit in an initramfs.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ACPI_HDR 36u
#define FIXED_LEN 116u
#define MAX_TABLE 1024u
#define MAX_BODY (MAX_TABLE - ACPI_HDR)
#define ABSENT 0xffffu
#define MON_REC 20u
#define MAX_MONS 8u

#define F_RO 0x01u
#define F_KEY 0x02u
#define F_STATIC 0x04u
#define F_VLAN 0x08u
#define F_FSID 0x10u
#define F_SECREQ 0x20u
#define F_ALL 0x3fu

/* ------------------------------------------------------------------------------------------------ */
/* output and bookkeeping                                                                            */
/* ------------------------------------------------------------------------------------------------ */

static int n_pass, n_fail, n_skip;
static int g_strict;
static const char *g_netdir = "/sys/class/net";

static void emit(const char *verdict, const char *field, const char *fmt, va_list ap)
{
	char buf[512];
	size_t i;
	(void)vsnprintf(buf, sizeof buf, fmt, ap);
	/* the detail may carry bytes from the table: keep the console line printable */
	for (i = 0; buf[i]; i++)
		if ((unsigned char)buf[i] < 0x20 || (unsigned char)buf[i] >= 0x7f)
			buf[i] = '?';
	printf("RBFT %s %s: %s\n", verdict, field, buf);
}
static void say_pass(const char *field, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	emit("PASS", field, fmt, ap);
	va_end(ap);
	n_pass++;
}
static void say_fail(const char *field, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	emit("FAIL", field, fmt, ap);
	va_end(ap);
	n_fail++;
}
static void say_info(const char *field, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	emit("INFO", field, fmt, ap);
	va_end(ap);
}
static void say_skip(const char *field, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	emit("SKIP", field, fmt, ap);
	va_end(ap);
	n_skip++;
}
/* no expectation for a field: SKIP, or FAIL under --strict. "got" may hold bytes of the table (a name): it goes through emit() like every
 * other line, so that a name with a line break cannot forge an "RBFT-RESULT" or "RBFT PASS" line on the console. */
static void say_noexp(const char *field, const char *got)
{
	if (g_strict)
		say_fail(field, "no expected value was supplied (strict), table has %s", got);
	else
		say_skip(field, "no expected value (table has %s)", got);
}

/* ------------------------------------------------------------------------------------------------ */
/* expectations                                                                                      */
/* ------------------------------------------------------------------------------------------------ */

#define MAX_EXP 64
static struct {
	char name[24];
	char *val;
} g_exp[MAX_EXP];
static int g_nexp;

static void exp_add(const char *name, const char *val)
{
	int i;
	char *c;
	if (strlen(name) >= sizeof g_exp[0].name)
		return;
	if (!strcmp(name, "key"))
		return; /* rbft.key= on the command line is a secret, not an expectation: never keep it, never print it */
	for (i = 0; i < g_nexp; i++)
		if (!strcmp(g_exp[i].name, name))
			return; /* first source wins */
	if (g_nexp == MAX_EXP)
		return;
	c = strdup(val);
	if (!c)
		return;
	strcpy(g_exp[g_nexp].name, name);
	g_exp[g_nexp].val = c;
	g_nexp++;
}
static const char *exp_get(const char *name)
{
	int i;
	for (i = 0; i < g_nexp; i++)
		if (!strcmp(g_exp[i].name, name))
			return g_exp[i].val;
	return NULL;
}
/* feed one "rbft.name=value" or "name=value" token */
static void exp_token(char *tok, int need_prefix)
{
	char *eq;
	if (!strncmp(tok, "rbft.", 5))
		tok += 5;
	else if (need_prefix)
		return;
	eq = strchr(tok, '=');
	if (!eq)
		return;
	*eq = 0;
	exp_add(tok, eq + 1);
}
static int exp_text(const char *text, int need_prefix)
{
	char *copy = strdup(text), *p, *save = NULL;
	if (!copy)
		return -1;
	for (p = strtok_r(copy, " \t\r\n", &save); p; p = strtok_r(NULL, " \t\r\n", &save))
		exp_token(p, need_prefix);
	free(copy);
	return 0;
}
/* 0 ok, -1 cannot read, -2 the file does not fit the buffer (a cut file could drop or change an expectation: refused, not used) */
static int exp_file(const char *path, int need_prefix)
{
	FILE *f = fopen(path, "r");
	char buf[4096];
	size_t n;
	int bad;
	if (!f)
		return -1;
	n = fread(buf, 1, sizeof buf - 1, f);
	bad = ferror(f) ? -1 : (n == sizeof buf - 1 && fgetc(f) != EOF) ? -2 : 0;
	fclose(f);
	if (bad)
		return bad;
	buf[n] = 0;
	return exp_text(buf, need_prefix);
}

/* ------------------------------------------------------------------------------------------------ */
/* small parsers                                                                                     */
/* ------------------------------------------------------------------------------------------------ */

/* clear a buffer that held (or may hold) the key; the volatile stores cannot be dropped as dead stores the way a memset before a return can */
static void wipe_mem(void *p, size_t n)
{
	volatile unsigned char *v = p;
	while (n--)
		*v++ = 0;
}

static unsigned le16(const uint8_t *p) { return (unsigned)p[0] | ((unsigned)p[1] << 8); }
static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int parse_uint(const char *s, unsigned long max, unsigned long *out)
{
	char *end;
	unsigned long v;
	if (!s || !*s || !(isdigit((unsigned char)*s)))
		return -1;
	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno || *end || v > max)
		return -1;
	*out = v;
	return 0;
}

/* an address text into the 16 bytes of the table; family 4 or 6 on success, 0 on failure */
static int parse_addr(const char *s, uint8_t ip[16])
{
	struct in_addr a4;
	struct in6_addr a6;
	memset(ip, 0, 16);
	if (inet_pton(AF_INET, s, &a4) == 1) {
		memcpy(ip, &a4, 4);
		return 4;
	}
	if (inet_pton(AF_INET6, s, &a6) == 1) {
		memcpy(ip, &a6, 16);
		return 6;
	}
	return 0;
}
static void fmt_addr(char *out, size_t cap, unsigned family, const uint8_t ip[16])
{
	out[0] = 0;
	if (family == 4)
		(void)inet_ntop(AF_INET, ip, out, (socklen_t)cap);
	else if (family == 6)
		(void)inet_ntop(AF_INET6, ip, out, (socklen_t)cap);
	else
		snprintf(out, cap, "-");
}
static int all_zero(const uint8_t *p, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		if (p[i])
			return 0;
	return 1;
}

static int b64v(int c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}
/* base64 text (padding and trailing white space allowed) to bytes; returns the length or -1 */
static int b64_decode(const char *s, uint8_t *out, size_t cap)
{
	uint32_t acc = 0;
	int bits = 0;
	size_t n = 0;
	for (; *s && *s != '='; s++) {
		int v;
		if (*s == '\n' || *s == '\r' || *s == ' ' || *s == '\t')
			continue;
		v = b64v((unsigned char)*s);
		if (v < 0)
			return -1;
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (n == cap)
				return -1;
			out[n++] = (uint8_t)(acc >> bits);
		}
	}
	return (int)n;
}
static void b64_encode(const uint8_t *in, size_t n, char *out)
{
	static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i, o = 0;
	for (i = 0; i + 2 < n; i += 3) {
		out[o++] = t[in[i] >> 2];
		out[o++] = t[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
		out[o++] = t[((in[i + 1] & 15) << 2) | (in[i + 2] >> 6)];
		out[o++] = t[in[i + 2] & 63];
	}
	if (i + 1 == n) {
		out[o++] = t[in[i] >> 2];
		out[o++] = t[(in[i] & 3) << 4];
		out[o++] = '=';
		out[o++] = '=';
	} else if (i + 2 == n) {
		out[o++] = t[in[i] >> 2];
		out[o++] = t[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
		out[o++] = t[(in[i + 1] & 15) << 2];
		out[o++] = '=';
	}
	out[o] = 0;
}

/* ------------------------------------------------------------------------------------------------ */
/* the decoded table                                                                                 */
/* ------------------------------------------------------------------------------------------------ */

struct mon {
	unsigned family;
	unsigned port;
	uint8_t ip[16];
};
struct tbl {
	uint8_t raw[MAX_TABLE]; /* private copy of the table (never the live firmware bytes) */
	size_t len;
	uint32_t flags;
	unsigned auth, mode, key_type, key_len, mon_count, nic_family, nic_prefix, nic_vlan, nic_mtu;
	uint8_t fsid[16], mac[6], ip[16], gw[16], dns[16];
	const char *entity, *pool, *ns, *image, *image_id, *snap; /* NULL = absent; into raw */
	struct mon mons[MAX_MONS];
	const uint8_t *key; /* into raw, or NULL */
	int safe_names;     /* the names may be handed to a shell and to the kernel client */
	int sound;          /* no structural FAIL at all (the checksum counts) */
};

static const char *const field_names[6] = {"entity", "pool", "namespace", "image", "image_id", "snapshot"};

/*
 * Validate and decode one candidate. The structural checks print their own lines; the return value is 0 when
 * the fields could be read (offsets in bounds), -1 when they could not (then no field line is printed).
 */
static int decode(const uint8_t *src, size_t avail, struct tbl *t)
{
	const uint8_t *b; /* body */
	size_t blen, var_len, pos, idx;
	const uint8_t *var;
	unsigned off[6], off_mons, off_key;
	int bad_before = n_fail, cs;
	uint32_t length;
	size_t i;

	memset(t, 0, sizeof *t);
	if (avail < ACPI_HDR) {
		say_fail("length", "only %zu bytes available, an ACPI header is %u", avail, ACPI_HDR);
		return -1;
	}
	if (memcmp(src, "rBFT", 4)) {
		say_fail("signature", "not rBFT");
		return -1;
	}
	say_pass("signature", "rBFT");
	length = le32(src + 4);
	if (length < ACPI_HDR + FIXED_LEN || length > MAX_TABLE || length > avail) {
		say_fail("length", "header says %u bytes (valid %u..%u, %zu available)", (unsigned)length,
			 ACPI_HDR + FIXED_LEN, MAX_TABLE, avail);
		return -1;
	}
	say_pass("length", "%u bytes", (unsigned)length);
	memcpy(t->raw, src, length);
	t->len = length;
	if (t->raw[8] == 1)
		say_pass("acpi_revision", "1");
	else
		say_fail("acpi_revision", "%u, expected 1", t->raw[8]);
	for (cs = 0, i = 0; i < length; i++)
		cs += t->raw[i];
	if ((cs & 0xff) == 0)
		say_pass("checksum", "all %u bytes sum to 0", (unsigned)length);
	else
		say_fail("checksum", "bytes sum to 0x%02x, not 0 (checksum byte 0x%02x)", cs & 0xff, t->raw[9]);
	say_info("oem", "not interpreted (iPXE writes its own): id '%.6s' table id '%.8s' creator '%.4s'", t->raw + 10,
		 t->raw + 16, t->raw + 28);

	b = t->raw + ACPI_HDR;
	blen = length - ACPI_HDR;
	if (!memcmp(b, "WRBT", 4))
		say_pass("magic", "WRBT");
	else {
		say_fail("magic", "body does not start with WRBT");
		return -1;
	}
	if (le16(b + 4) == 1)
		say_pass("version", "1");
	else {
		say_fail("version", "%u, this tool reads version 1", le16(b + 4));
		return -1;
	}
	if (le16(b + 6) == FIXED_LEN)
		say_pass("header_len", "%u", FIXED_LEN);
	else {
		say_fail("header_len", "%u, version 1 has %u", le16(b + 6), FIXED_LEN);
		return -1;
	}

	t->flags = le32(b + 8);
	t->auth = b[12];
	t->mode = b[13];
	t->key_type = b[14];
	t->key_len = b[15];
	t->mon_count = b[16];
	t->nic_family = b[17];
	t->nic_prefix = b[18];
	memcpy(t->fsid, b + 20, 16);
	memcpy(t->mac, b + 36, 6);
	t->nic_vlan = le16(b + 42);
	t->nic_mtu = le16(b + 44);
	memcpy(t->ip, b + 48, 16);
	memcpy(t->gw, b + 64, 16);
	memcpy(t->dns, b + 80, 16);
	for (i = 0; i < 6; i++)
		off[i] = le16(b + 96 + 2 * i);
	off_mons = le16(b + 108);
	off_key = le16(b + 110);

	/* reserved bytes: 19, 46..47, 112..115 */
	if (b[19] == 0 && all_zero(b + 46, 2) && all_zero(b + 112, 4))
		say_pass("reserved", "all reserved bytes are zero");
	else
		say_fail("reserved", "a reserved byte is not zero (a later layout version?)");
	if (t->flags & ~F_ALL)
		say_fail("flags_reserved", "unknown flag bits 0x%x", (unsigned)(t->flags & ~F_ALL));
	else
		say_pass("flags_reserved", "only bits 0..5 are set (0x%x)", (unsigned)t->flags);

	/* the variable area: canonical layout, no gaps, no padding, nothing after the key */
	var = b + FIXED_LEN;
	var_len = blen - FIXED_LEN;
	pos = 0;
	{
		const char **dst[6];
		int layout_ok = 1;
		dst[0] = &t->entity;
		dst[1] = &t->pool;
		dst[2] = &t->ns;
		dst[3] = &t->image;
		dst[4] = &t->image_id;
		dst[5] = &t->snap;
		for (idx = 0; idx < 6; idx++) {
			size_t n;
			if (off[idx] == ABSENT)
				continue;
			if (off[idx] != pos || off[idx] >= var_len) {
				say_fail("layout", "%s at offset %u, canonical layout has it at %zu", field_names[idx], off[idx], pos);
				layout_ok = 0;
				break;
			}
			n = strnlen((const char *)var + off[idx], var_len - off[idx]);
			if (off[idx] + n >= var_len) {
				say_fail("layout", "%s has no terminating NUL inside the table", field_names[idx]);
				layout_ok = 0;
				break;
			}
			if (n == 0 || n > 255) {
				say_fail("layout", "%s is %zu bytes (1..255 allowed, an absent string takes no space)",
					 field_names[idx], n);
				layout_ok = 0;
				break;
			}
			*dst[idx] = (const char *)var + off[idx];
			pos += n + 1;
		}
		if (layout_ok) {
			if (t->mon_count < 1 || t->mon_count > MAX_MONS) {
				say_fail("layout", "mon_count %u (1..8)", t->mon_count);
				layout_ok = 0;
			} else if (off_mons != pos || pos + (size_t)t->mon_count * MON_REC > var_len) {
				say_fail("layout", "monitor records at %u (%zu expected, %zu bytes of area)", off_mons, pos, var_len);
				layout_ok = 0;
			}
		}
		if (layout_ok) {
			unsigned m;
			for (m = 0; m < t->mon_count; m++) {
				const uint8_t *r = var + pos + (size_t)m * MON_REC;
				t->mons[m].family = r[0];
				t->mons[m].port = le16(r + 2);
				memcpy(t->mons[m].ip, r + 4, 16);
				if ((r[0] != 4 && r[0] != 6) || r[1] != 0 || t->mons[m].port == 0 ||
				    (r[0] == 4 && !all_zero(r + 8, 12))) {
					say_fail("layout", "monitor %u: family %u reserved %u port %u (family 4 or 6, reserved 0, port not 0, "
						 "IPv4 address padded with zeros)", m, r[0], r[1], t->mons[m].port);
					layout_ok = 0;
					break;
				}
			}
			pos += (size_t)t->mon_count * MON_REC;
		}
		if (layout_ok) {
			if (t->flags & F_KEY) {
				if (off_key != pos || t->key_len == 0 || pos + t->key_len > var_len) {
					say_fail("layout", "key at %u (%zu expected) length %u, %zu bytes of area", off_key, pos, t->key_len,
						 var_len);
					layout_ok = 0;
				} else {
					t->key = var + pos;
					pos += t->key_len;
				}
			} else if (off_key != ABSENT || t->key_len != 0 || t->key_type != 0) {
				say_fail("layout", "no key flag but key offset %u, key_len %u, key_type %u", off_key, t->key_len, t->key_type);
				layout_ok = 0;
			}
		}
		if (layout_ok && pos != var_len) {
			say_fail("layout", "%zu bytes after the canonical end of the variable area", var_len - pos);
			layout_ok = 0;
		}
		if (layout_ok)
			say_pass("layout", "canonical: strings, %u monitor records%s, nothing else (%zu bytes of area)", t->mon_count,
				 t->key ? ", key" : "", var_len);
		else
			return -1; /* offsets cannot be trusted: no field lines */
	}

	/* the rules of the field table */
	{
		int ok = 1;
		if (t->auth > 1) { say_fail("rules", "auth %u (0 none, 1 cephx)", t->auth); ok = 0; }
		if (t->auth == 1 && !t->entity) { say_fail("rules", "cephx without an entity"); ok = 0; }
		if (!t->pool || !t->image) { say_fail("rules", "pool and image are required"); ok = 0; }
		if (t->ns) { say_fail("namespace", "present, but absent in version 1"); ok = 0; }
		else say_pass("namespace", "absent (as in version 1)");
		if (t->mode < 1 || t->mode > 4) { say_fail("rules", "msgr_mode %u (1..4)", t->mode); ok = 0; }
		if ((t->flags & F_SECREQ) && t->mode != 4) { say_fail("rules", "secure-required flag needs msgr_mode 4"); ok = 0; }
		if (t->nic_family != 0 && t->nic_family != 4 && t->nic_family != 6) { say_fail("rules", "nic_family %u", t->nic_family); ok = 0; }
		if ((t->flags & F_STATIC) && !t->nic_family) { say_fail("rules", "static flag without a NIC family"); ok = 0; }
		if (t->nic_family == 0 && (t->nic_prefix || !all_zero(t->ip, 16) || !all_zero(t->gw, 16) || !all_zero(t->dns, 16))) {
			say_fail("rules", "NIC family 0 but prefix or addresses are not zero"); ok = 0;
		}
		if (t->nic_family == 4 && (t->nic_prefix > 32 || !all_zero(t->ip + 4, 12) || !all_zero(t->gw + 4, 12) || !all_zero(t->dns + 4, 12))) {
			say_fail("rules", "IPv4 NIC with prefix %u or addresses not padded with zeros", t->nic_prefix); ok = 0;
		}
		if (t->nic_family == 6 && t->nic_prefix > 128) { say_fail("rules", "IPv6 prefix %u", t->nic_prefix); ok = 0; }
		if (t->flags & F_VLAN) {
			if (t->nic_vlan < 1 || t->nic_vlan > 4094) { say_fail("rules", "VLAN flag with id %u", t->nic_vlan); ok = 0; }
		} else if (t->nic_vlan) { say_fail("rules", "VLAN id %u without the flag", t->nic_vlan); ok = 0; }
		if (!(t->flags & F_FSID) && !all_zero(t->fsid, 16)) { say_fail("rules", "fsid set without the flag"); ok = 0; }
		if (t->flags & F_KEY) {
			if (t->auth != 1) { say_fail("rules", "key without cephx"); ok = 0; }
			if (t->key_type == 1 ? (t->key_len < 16 || t->key_len > 64) : t->key_type == 2 ? (t->key_len < 32 || t->key_len > 64) : 1) {
				say_fail("rules", "key_type %u with key_len %u", t->key_type, t->key_len); ok = 0;
			}
		}
		if (ok)
			say_pass("rules", "every rule of the field table holds");
	}
	/* may the names go into a shell and into the kernel client's "add" string? */
	{
		const char *s[5];
		size_t k;
		t->safe_names = 1;
		s[0] = t->entity; s[1] = t->pool; s[2] = t->image; s[3] = t->snap; s[4] = t->image_id;
		for (k = 0; k < 5; k++) {
			const char *p;
			/* an allow-list: these words go into a shell variable file, the kernel client's add string and the result file the marker
			 * reads; a table is not trusted to leave out ; | & ( ) < > * ? # { } and the like */
			for (p = s[k]; p && *p; p++)
				if (!isalnum((unsigned char)*p) && !strchr("._-+:", *p))
					t->safe_names = 0;
			if (s[k] && !strcmp(s[k], "-") && k == 3)
				t->safe_names = 0; /* the hook reads snapshot "-" as "none": a snapshot named so would map the head instead */
		}
		if (!t->safe_names)
			say_info("names", "a name has a character outside A-Z a-z 0-9 . _ - + : (or a snapshot named \"-\"): the table will not be used for mapping");
	}
	t->sound = (n_fail == bad_before);
	return 0;
}

/* ------------------------------------------------------------------------------------------------ */
/* the field checks against the expectations                                                         */
/* ------------------------------------------------------------------------------------------------ */

static const char *mode_name(unsigned m)
{
	return m == 1 ? "crc" : m == 2 ? "crc-first" : m == 3 ? "secure-first" : m == 4 ? "secure" : "?";
}
static const char *key_name(unsigned k) { return k == 0 ? "none" : k == 1 ? "aes" : k == 2 ? "aes256k" : "?"; }
static void flags_text(uint32_t f, char *out, size_t cap)
{
	snprintf(out, cap, "%s%s%s%s%s%s%s", (f & F_RO) ? "ro," : "", (f & F_KEY) ? "key," : "", (f & F_STATIC) ? "static," : "",
		 (f & F_VLAN) ? "vlan," : "", (f & F_FSID) ? "fsid," : "", (f & F_SECREQ) ? "secure," : "", f ? "" : "none");
	{
		size_t n = strlen(out);
		if (n && out[n - 1] == ',')
			out[n - 1] = 0;
	}
}
/* the expected flags: a number, "none", or a comma list of names; -1 on syntax error */
static long parse_flags(const char *s)
{
	char *c = strdup(s), *p, *save = NULL;
	long v = 0;
	unsigned long n;
	if (!c || !*s) { /* "rbft.flags=" with nothing after it is not "none" */
		free(c);
		return -1;
	}
	if (!parse_uint(s, 0xffffffffUL, &n)) {
		free(c);
		return (long)n;
	}
	for (p = strtok_r(c, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
		if (!strcmp(p, "none")) continue;
		else if (!strcmp(p, "ro")) v |= F_RO;
		else if (!strcmp(p, "key")) v |= F_KEY;
		else if (!strcmp(p, "static")) v |= F_STATIC;
		else if (!strcmp(p, "vlan")) v |= F_VLAN;
		else if (!strcmp(p, "fsid")) v |= F_FSID;
		else if (!strcmp(p, "secure")) v |= F_SECREQ;
		else { v = -1; break; }
	}
	free(c);
	return v;
}

static void chk_str(const char *field, const char *key, const char *got)
{
	const char *e = exp_get(key);
	if (!e) {
		say_noexp(field, got ? got : "(absent)");
		return;
	}
	if (!strcmp(e, "-")) {
		if (!got)
			say_pass(field, "absent, as expected");
		else
			say_fail(field, "expected absent, got '%s'", got);
		return;
	}
	if (got && !strcmp(e, got))
		say_pass(field, "%s", got);
	else
		say_fail(field, "expected '%s', got '%s'", e, got ? got : "(absent)");
}
static void chk_num(const char *field, const char *key, unsigned long got)
{
	const char *e = exp_get(key);
	unsigned long want;
	char g[32];
	snprintf(g, sizeof g, "%lu", got);
	if (!e) {
		say_noexp(field, g);
		return;
	}
	if (!strcmp(e, "-"))
		want = 0;
	else if (parse_uint(e, 0xffffffffUL, &want)) {
		say_fail(field, "the expected value '%s' is not a number", e);
		return;
	}
	if (want == got)
		say_pass(field, "%lu", got);
	else
		say_fail(field, "expected %lu, got %lu", want, got);
}
static void chk_addr(const char *field, const char *key, unsigned family, const uint8_t ip[16])
{
	const char *e = exp_get(key);
	char got[64];
	uint8_t want[16];
	int wf;
	fmt_addr(got, sizeof got, family, ip);
	if (!e) {
		say_noexp(field, got);
		return;
	}
	if (!strcmp(e, "-")) {
		if (family == 0 || all_zero(ip, 16))
			say_pass(field, "zero, as expected");
		else
			say_fail(field, "expected none, got %s", got);
		return;
	}
	wf = parse_addr(e, want);
	if (!wf)
		say_fail(field, "the expected value '%s' is not an address", e);
	else if (!memcmp(want, ip, 16) && (unsigned)wf == family)
		say_pass(field, "%s", got);
	else
		say_fail(field, "expected %s, got %s", e, got);
}

static void fmt_mon(char *out, size_t cap, const struct mon *m)
{
	char a[64];
	fmt_addr(a, sizeof a, m->family, m->ip);
	if (m->family == 6)
		snprintf(out, cap, "[%s]:%u", a, m->port);
	else
		snprintf(out, cap, "%s:%u", a, m->port);
}
static int parse_mon(const char *s, struct mon *m)
{
	char buf[96], *colon;
	unsigned long port;
	size_t n = strlen(s);
	if (n == 0 || n >= sizeof buf)
		return -1;
	memcpy(buf, s, n + 1);
	if (buf[0] == '[') {
		char *rb = strchr(buf, ']');
		if (!rb || rb[1] != ':')
			return -1;
		*rb = 0;
		if (parse_uint(rb + 2, 65535, &port) || parse_addr(buf + 1, m->ip) != 6)
			return -1;
		m->family = 6;
	} else {
		colon = strrchr(buf, ':');
		if (!colon)
			return -1;
		*colon = 0;
		if (parse_uint(colon + 1, 65535, &port) || parse_addr(buf, m->ip) != 4)
			return -1;
		m->family = 4;
	}
	m->port = (unsigned)port;
	return 0;
}

static void chk_fields(const struct tbl *t, const char *supplied_key_file, int check_nic)
{
	const char *e;
	char got[160], gb[64];
	unsigned i;

	chk_str("entity", "entity", t->entity);
	chk_str("pool", "pool", t->pool);
	chk_str("image", "image", t->image);
	chk_str("image_id", "imageid", t->image_id);
	chk_str("snapshot", "snap", t->snap);

	/* auth */
	e = exp_get("auth");
	if (!e) say_noexp("auth", t->auth ? "cephx" : "none");
	else if ((!strcmp(e, "none") && t->auth == 0) || (!strcmp(e, "cephx") && t->auth == 1)) say_pass("auth", "%s", e);
	else say_fail("auth", "expected %s, got %s", e, t->auth ? "cephx" : "none");

	/* msgr_mode */
	e = exp_get("mode");
	if (!e) say_noexp("msgr_mode", mode_name(t->mode));
	else if (!strcmp(e, mode_name(t->mode))) say_pass("msgr_mode", "%s", e);
	else say_fail("msgr_mode", "expected %s, got %s", e, mode_name(t->mode));

	/* flags: the whole word, then each bit on its own line so a failure names the flag */
	e = exp_get("flags");
	flags_text(t->flags, got, sizeof got);
	if (!e) say_noexp("flags", got);
	else {
		long w = parse_flags(e);
		if (w < 0) say_fail("flags", "the expected value '%s' does not parse", e);
		else {
			static const struct { uint32_t bit; const char *name; } bits[] = {
				{F_RO, "flag_readonly"}, {F_KEY, "flag_key"}, {F_STATIC, "flag_nic_static"}, {F_VLAN, "flag_vlan"},
				{F_FSID, "flag_fsid"}, {F_SECREQ, "flag_secure_required"}};
			unsigned k;
			char wt[64];
			flags_text((uint32_t)w, wt, sizeof wt);
			if ((uint32_t)w == t->flags) say_pass("flags", "%s (0x%x)", got, (unsigned)t->flags);
			else say_fail("flags", "expected %s (0x%x), got %s (0x%x)", wt, (unsigned)w, got, (unsigned)t->flags);
			for (k = 0; k < 6; k++) {
				int want = ((uint32_t)w & bits[k].bit) != 0, have = (t->flags & bits[k].bit) != 0;
				if (want == have) say_pass(bits[k].name, "%s", have ? "set" : "clear");
				else say_fail(bits[k].name, "expected %s, got %s", want ? "set" : "clear", have ? "set" : "clear");
			}
		}
	}

	/* key */
	e = exp_get("keytype");
	if (!e) say_noexp("key_type", key_name(t->key_type));
	else if (!strcmp(e, key_name(t->key_type))) say_pass("key_type", "%s", e);
	else say_fail("key_type", "expected %s, got %s", e, key_name(t->key_type));
	chk_num("key_len", "keylen", t->key_len);
	if (t->key)
		say_info("key", "present in the table (%s, %u bytes), not printed", key_name(t->key_type), t->key_len);
	else
		say_info("key", "not in the table");
	if (supplied_key_file) {
		FILE *f = fopen(supplied_key_file, "r");
		char txt[256];
		uint8_t blob[128];
		int n = -1;
		size_t r = 0;
		if (f) {
			r = fread(txt, 1, sizeof txt - 1, f);
			fclose(f);
			txt[r] = 0;
			n = b64_decode(txt, blob, sizeof blob);
		}
		wipe_mem(txt, sizeof txt);
		if (n < 14 || (size_t)n != 12u + le16(blob + 10)) {
			say_fail("key_value", "the supplied key is not an armoured cephx secret");
		} else if (!t->key) {
			say_info("key_value", "the table carries no key: the supplied one (%s, %u bytes) will be used", blob[0] == 1 ? "aes" : "other", le16(blob + 10));
		} else if (blob[0] == t->key_type && le16(blob + 10) == t->key_len && !memcmp(blob + 12, t->key, t->key_len)) {
			say_pass("key_value", "the key in the table equals the supplied key (not printed)");
		} else {
			say_fail("key_value", "the key in the table differs from the supplied key (not printed)");
		}
		wipe_mem(blob, sizeof blob);
	}

	/* monitors */
	e = exp_get("mons");
	if (!e) {
		say_noexp("mon_count", (snprintf(gb, sizeof gb, "%u", t->mon_count), gb));
		for (i = 0; i < t->mon_count; i++) {
			char n[16], m[80];
			snprintf(n, sizeof n, "mon%u", i);
			fmt_mon(m, sizeof m, &t->mons[i]);
			say_noexp(n, m);
		}
	} else {
		char *c = strdup(e), *p, *save = NULL;
		struct mon want[MAX_MONS + 1];
		unsigned nw = 0;
		int syntax = 0;
		if (!c) { say_fail("mons", "out of memory"); }
		else {
			for (p = strtok_r(c, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
				if (nw == MAX_MONS + 1 || parse_mon(p, &want[nw])) { syntax = 1; break; }
				nw++;
			}
			free(c);
			if (syntax || nw == 0) say_fail("mons", "the expected list '%s' does not parse", e);
			else {
				if (nw == t->mon_count) say_pass("mon_count", "%u", nw);
				else say_fail("mon_count", "expected %u, got %u", nw, t->mon_count);
				for (i = 0; i < t->mon_count; i++) {
					char n[16], m[80], w2[80];
					snprintf(n, sizeof n, "mon%u", i);
					fmt_mon(m, sizeof m, &t->mons[i]);
					if (i >= nw) { say_fail(n, "%s is not in the expected list", m); continue; }
					fmt_mon(w2, sizeof w2, &want[i]);
					if (want[i].family == t->mons[i].family && want[i].port == t->mons[i].port && !memcmp(want[i].ip, t->mons[i].ip, 16))
						say_pass(n, "%s", m);
					else say_fail(n, "expected %s, got %s", w2, m);
				}
			}
		}
	}

	/* fsid */
	e = exp_get("fsid");
	{
		char f[40];
		snprintf(f, sizeof f, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", t->fsid[0], t->fsid[1], t->fsid[2],
			 t->fsid[3], t->fsid[4], t->fsid[5], t->fsid[6], t->fsid[7], t->fsid[8], t->fsid[9], t->fsid[10], t->fsid[11],
			 t->fsid[12], t->fsid[13], t->fsid[14], t->fsid[15]);
		if (!e) say_noexp("fsid", (t->flags & F_FSID) ? f : "(none)");
		else if (!strcmp(e, "-")) {
			if (!(t->flags & F_FSID)) say_pass("fsid", "none, as expected");
			else say_fail("fsid", "expected none, got %s", f);
		} else {
			char w[40];
			size_t k, o = 0;
			for (k = 0; e[k] && o < 32; k++) if (e[k] != '-') w[o++] = (char)tolower((unsigned char)e[k]);
			w[o] = 0;
			{
				char h[33];
				size_t q, ho = 0;
				for (q = 0; f[q]; q++) if (f[q] != '-') h[ho++] = f[q];
				h[ho] = 0;
				if ((t->flags & F_FSID) && !strcmp(h, w)) say_pass("fsid", "%s", f);
				else say_fail("fsid", "expected %s, got %s", e, (t->flags & F_FSID) ? f : "(none)");
			}
		}
	}

	/* NIC */
	{
		char mac[24];
		snprintf(mac, sizeof mac, "%02x:%02x:%02x:%02x:%02x:%02x", t->mac[0], t->mac[1], t->mac[2], t->mac[3], t->mac[4], t->mac[5]);
		e = exp_get("mac");
		if (!e) say_noexp("nic_mac", mac);
		else {
			char w[24];
			size_t k;
			for (k = 0; e[k] && k < sizeof w - 1; k++) w[k] = (char)tolower((unsigned char)e[k]);
			w[k] = 0;
			if (!strcmp(w, mac)) say_pass("nic_mac", "%s", mac);
			else say_fail("nic_mac", "expected %s, got %s", e, mac);
		}
		if (check_nic) {
			DIR *d = opendir(g_netdir);
			struct dirent *de;
			int found = 0;
			if (d) {
				while ((de = readdir(d)) != NULL) {
					char path[300], a[64];
					FILE *f;
					if (de->d_name[0] == '.') continue;
					snprintf(path, sizeof path, "%s/%s/address", g_netdir, de->d_name);
					f = fopen(path, "r");
					if (!f) continue;
					if (fgets(a, sizeof a, f)) {
						size_t l = strlen(a);
						while (l && (a[l - 1] == '\n' || a[l - 1] == ' ')) a[--l] = 0;
						if (!strcmp(a, mac)) found = 1;
					}
					fclose(f);
				}
				closedir(d);
			}
			if (found) say_pass("nic_present", "an interface with MAC %s exists in this guest", mac);
			else say_fail("nic_present", "no interface with MAC %s in this guest", mac);
		}
	}
	chk_num("nic_vlan", "vlan", t->nic_vlan);
	chk_num("nic_mtu", "mtu", t->nic_mtu);
	/* ip=ADDR/PREFIX covers three table fields */
	e = exp_get("ip");
	{
		char a[64], line[96];
		fmt_addr(a, sizeof a, t->nic_family, t->ip);
		snprintf(line, sizeof line, "%s/%u family %u", a, t->nic_prefix, t->nic_family);
		if (!e) {
			say_noexp("nic_family", (snprintf(gb, sizeof gb, "%u", t->nic_family), gb));
			say_noexp("nic_ip", a);
			say_noexp("nic_prefix", (snprintf(gb, sizeof gb, "%u", t->nic_prefix), gb));
		} else if (!strcmp(e, "-")) {
			if (t->nic_family == 0) say_pass("nic_family", "0 (unknown), as expected"); else say_fail("nic_family", "expected 0, got %u", t->nic_family);
			if (all_zero(t->ip, 16)) say_pass("nic_ip", "zero, as expected"); else say_fail("nic_ip", "expected none, got %s", a);
			if (t->nic_prefix == 0) say_pass("nic_prefix", "0"); else say_fail("nic_prefix", "expected 0, got %u", t->nic_prefix);
		} else {
			char *c = strdup(e), *slash;
			uint8_t w[16];
			int wf;
			unsigned long wp = 0;
			if (!c) say_fail("nic_ip", "out of memory");
			else {
				slash = strchr(c, '/');
				if (!slash) { say_fail("nic_ip", "the expected value '%s' is not ADDR/PREFIX", e); }
				else {
					*slash = 0;
					wf = parse_addr(c, w);
					if (!wf || parse_uint(slash + 1, 128, &wp)) say_fail("nic_ip", "the expected value '%s' does not parse", e);
					else {
						if ((unsigned)wf == t->nic_family) say_pass("nic_family", "%u", t->nic_family);
						else say_fail("nic_family", "expected %d, got %u", wf, t->nic_family);
						if (!memcmp(w, t->ip, 16)) say_pass("nic_ip", "%s", a); else say_fail("nic_ip", "expected %s, got %s", c, a);
						if (wp == t->nic_prefix) say_pass("nic_prefix", "%u", t->nic_prefix);
						else say_fail("nic_prefix", "expected %lu, got %u", wp, t->nic_prefix);
					}
				}
				free(c);
			}
		}
		(void)line;
	}
	chk_addr("nic_gateway", "gw", t->nic_family, t->gw);
	chk_addr("nic_dns", "dns", t->nic_family, t->dns);
	if (check_nic && !(t->flags & F_STATIC))
		say_info("nic_config", "DHCP flag state: the address in the table is what the loader had; the hook applies it statically");
}

/* ------------------------------------------------------------------------------------------------ */
/* outputs for the hook                                                                              */
/* ------------------------------------------------------------------------------------------------ */

static void shq(FILE *f, const char *name, const char *val)
{
	fprintf(f, "%s='", name);
	for (; val && *val; val++) {
		if (*val == '\'')
			fputs("'\\''", f);
		else
			fputc(*val, f);
	}
	fputs("'\n", f);
}

static int write_env(const struct tbl *t, const char *path)
{
	FILE *f;
	char buf[1024], m[80], a[64];
	unsigned i;
	size_t o = 0;
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	if (!(f = fdopen(fd, "w"))) {
		close(fd);
		return -1;
	}
	buf[0] = 0;
	for (i = 0; i < t->mon_count; i++) {
		int n;
		fmt_mon(m, sizeof m, &t->mons[i]);
		n = snprintf(buf + o, sizeof buf - o, "%s%s", i ? " " : "", m);
		if (n < 0 || (size_t)n >= sizeof buf - o)
			break;
		o += (size_t)n;
	}
	shq(f, "RBFT_MONS", buf);
	shq(f, "RBFT_ENTITY", t->entity ? t->entity : "");
	shq(f, "RBFT_POOL", t->pool);
	shq(f, "RBFT_IMAGE", t->image);
	shq(f, "RBFT_SNAP", t->snap ? t->snap : "-");
	fprintf(f, "RBFT_MODE=%u\nRBFT_AUTH=%u\nRBFT_FLAGS=%u\nRBFT_RO=%u\nRBFT_SECREQ=%u\nRBFT_STATIC=%u\n", t->mode, t->auth,
		(unsigned)t->flags, (t->flags & F_RO) ? 1u : 0u, (t->flags & F_SECREQ) ? 1u : 0u, (t->flags & F_STATIC) ? 1u : 0u);
	fprintf(f, "RBFT_KEYTYPE=%u\nRBFT_KEY_IN_TABLE=%u\n", t->key_type, t->key ? 1u : 0u);
	fprintf(f, "RBFT_MAC='%02x:%02x:%02x:%02x:%02x:%02x'\nRBFT_VLAN=%u\nRBFT_MTU=%u\nRBFT_FAMILY=%u\nRBFT_PREFIX=%u\n", t->mac[0], t->mac[1],
		t->mac[2], t->mac[3], t->mac[4], t->mac[5], t->nic_vlan, t->nic_mtu, t->nic_family, t->nic_prefix);
	fmt_addr(a, sizeof a, t->nic_family, t->ip);
	shq(f, "RBFT_IP", t->nic_family ? a : "");
	fmt_addr(a, sizeof a, t->nic_family, t->gw);
	shq(f, "RBFT_GW", (t->nic_family && !all_zero(t->gw, 16)) ? a : "");
	fmt_addr(a, sizeof a, t->nic_family, t->dns);
	shq(f, "RBFT_DNS", (t->nic_family && !all_zero(t->dns, 16)) ? a : "");
	return fclose(f);
}

/* the kernel client's secret= option takes base64 of: u16 type, u32 sec, u32 nsec, u16 len, secret */
static int write_secret(const struct tbl *t, const char *path)
{
	uint8_t blob[12 + 64];
	char txt[4 * (sizeof blob / 3 + 2) + 1];
	int fd, rc = 0;
	FILE *f;
	if (!t->key || t->key_type != 1)
		return 1;
	memset(blob, 0, sizeof blob);
	blob[0] = 1; /* CEPH_CRYPTO_AES */
	blob[10] = (uint8_t)(t->key_len & 0xff);
	blob[11] = (uint8_t)(t->key_len >> 8);
	memcpy(blob + 12, t->key, t->key_len);
	b64_encode(blob, 12u + t->key_len, txt);
	wipe_mem(blob, sizeof blob);
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		rc = -1;
	} else if (!(f = fdopen(fd, "w"))) {
		close(fd);
		rc = -1;
	} else {
		/* a short write is a failure, and a file with half a key is removed */
		if (fputs(txt, f) < 0)
			rc = -1;
		if (fclose(f) != 0)
			rc = -1;
		if (rc)
			(void)unlink(path);
	}
	wipe_mem(txt, sizeof txt);
	return rc;
}

/* ------------------------------------------------------------------------------------------------ */
/* finding the table                                                                                 */
/* ------------------------------------------------------------------------------------------------ */

static int read_all(const char *path, uint8_t *buf, size_t cap, size_t *n)
{
	int fd = open(path, O_RDONLY);
	size_t got = 0;
	if (fd < 0)
		return -1;
	while (got < cap) {
		size_t left = cap - got;
		ssize_t r = read(fd, buf + got, left);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		if (r == 0 || (size_t)r > left)
			break;
		got += (size_t)r;
	}
	close(fd);
	*n = got;
	return 0;
}

/* a candidate at buf[0..avail): signature, sane length, checksum 0 */
static int candidate_ok(const uint8_t *buf, size_t avail)
{
	uint32_t len;
	size_t i;
	unsigned s = 0;
	if (avail < ACPI_HDR || memcmp(buf, "rBFT", 4))
		return 0;
	len = le32(buf + 4);
	if (len < ACPI_HDR + FIXED_LEN || len > MAX_TABLE || len > avail)
		return 0;
	for (i = 0; i < len; i++)
		s += buf[i];
	return (s & 0xff) == 0;
}

struct found {
	uint8_t raw[MAX_TABLE];
	size_t len;
	unsigned long addr;
	int count, differ, badsum;
};

/* scan img[0..n) in steps of 16 for hits that START below limit (address of img[0] is base); a table may run on to n */
static void scan_window(const uint8_t *img, size_t n, size_t limit, unsigned long base, struct found *fd)
{
	size_t off;
	for (off = 0; off < limit && off + 4 <= n; off += 16) {
		if (memcmp(img + off, "rBFT", 4))
			continue;
		if (candidate_ok(img + off, n - off)) {
			size_t len = le32(img + off + 4);
			if (!fd->count) {
				memcpy(fd->raw, img + off, len);
				fd->len = len;
				fd->addr = base + off;
			} else if (len != fd->len || memcmp(fd->raw, img + off, len)) {
				fd->differ = 1;
			}
			fd->count++;
		} else {
			fd->badsum++;
			say_info("scan", "signature at 0x%lx but no valid length and checksum: ignored", base + off);
		}
	}
}

/* read up to n bytes at offset off, as many as there are (a short read ends it; EINTR is retried); returns the count */
static size_t pread_upto(int fd, uint8_t *buf, size_t n, off_t off)
{
	size_t got = 0;
	while (got < n) {
		ssize_t r = pread(fd, buf + got, n - got, off + (off_t)got);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			break;
		got += (size_t)r;
		if (got > n) /* cannot happen; keeps the count inside the buffer whatever the kernel says */
			return n;
	}
	return got;
}

/* read the addresses [lo, hi) of an address space that file descriptor fdm shows from address `base` on (/dev/mem: base 0; a memory image
 * taken as a file: --base) in 64 KiB steps, each read MAX_TABLE bytes longer so that a table that starts near the end of a step is whole;
 * a region the kernel refuses (RAM under a strict /dev/mem) reads as nothing. -1 when nothing could be read at all. */
static int scan_fd(int fdm, unsigned long base, unsigned long lo, unsigned long hi, struct found *fd)
{
	const size_t chunk = 1u << 16;
	unsigned long a;
	uint8_t *win;
	int any = 0;
	if (lo < base)
		lo = base;
	win = malloc(chunk + MAX_TABLE);
	if (!win)
		return -1;
	for (a = lo & ~15ul; a < hi;) {
		size_t want = chunk + MAX_TABLE, got;
		if (a >= base) {
			if (hi - a < want)
				want = (size_t)(hi - a);
			got = pread_upto(fdm, win, want, (off_t)(a - base));
			if (got) {
				any = 1;
				scan_window(win, got, got < chunk ? got : chunk, a, fd);
			}
		}
		if (hi - a <= chunk) /* the last window; also keeps a + chunk from wrapping round for a range that ends near the top */
			break;
		a += chunk;
	}
	free(win);
	return any ? 0 : -1;
}

static int scan_devmem(unsigned long lo, unsigned long hi, struct found *fd)
{
	int fdm = open("/dev/mem", O_RDONLY);
	int rc;
	if (fdm < 0) {
		say_info("scan", "cannot open /dev/mem: %s (is iomem=relaxed on the kernel command line, and CONFIG_DEVMEM set?)", strerror(errno));
		return -1;
	}
	rc = scan_fd(fdm, 0, lo, hi, fd);
	close(fdm);
	return rc;
}

/* ------------------------------------------------------------------------------------------------ */

/* the table for the log, key bytes masked; rc is the result of decode(): -1 means the layout could not be trusted */
static void hexdump_table(const uint8_t *raw, size_t len, const uint8_t *key, size_t key_len, int decoded)
{
	size_t off, i, shown = len;
	if (!decoded && shown > ACPI_HDR + FIXED_LEN)
		shown = ACPI_HDR + FIXED_LEN;
	for (off = 0; off < shown; off += 16) {
		char line[16 * 3 + 1];
		size_t o = 0;
		for (i = off; i < off + 16 && i < shown; i++) {
			int masked = key && key_len && raw + i >= key && raw + i < key + key_len;
			if (masked)
				o += (size_t)snprintf(line + o, sizeof line - o, "..%s", i + 1 < off + 16 && i + 1 < shown ? " " : "");
			else
				o += (size_t)snprintf(line + o, sizeof line - o, "%02x%s", raw[i], i + 1 < off + 16 && i + 1 < shown ? " " : "");
		}
		printf("RBFT DUMP %04zx: %s\n", off, line);
	}
	if (shown < len)
		printf("RBFT DUMP ....: (%zu more bytes not shown: the table could not be decoded)\n", len - shown);
}

static void usage(void)
{
	fputs("usage: rbft-check (--sysfs [PATH] | --file PATH | --scan [--range LO-HI]... | --scan-file PATH [--base ADDR])\n"
	      "                  [--cmdline] [--params FILE]... [--param NAME=VALUE]... [--strict] [--check-nic]\n"
	      "                  [--supplied-key FILE] [--emit-env FILE] [--emit-secret FILE] [--hexdump] [--net-dir DIR] [--cmdline-file F]\n"
	      "see the comment at the top of rbft-check.c\n", stderr);
}

int main(int argc, char **argv)
{
	enum { SRC_NONE, SRC_SYSFS, SRC_FILE, SRC_SCAN, SRC_SCANFILE } src = SRC_NONE;
	const char *path = "/sys/firmware/acpi/tables/rBFT", *emit_env = NULL, *emit_secret = NULL, *supplied = NULL;
	const char *params[8], *cmdline_file = "/proc/cmdline";
	int nparams = 0, use_cmdline = 0, check_nic = 0, hexdump = 0, i;
	unsigned long ranges[8][2], base = 0;
	int nranges = 0;
	static struct found fdz;
	static struct tbl t;
	static uint8_t srcbuf[MAX_TABLE + 4096];
	size_t srclen = 0;
	const uint8_t *tab = NULL;
	size_t tablen = 0;
	int rc;

	setvbuf(stdout, NULL, _IOLBF, 0);
	for (i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "--sysfs")) {
			src = SRC_SYSFS;
			if (i + 1 < argc && argv[i + 1][0] == '/')
				path = argv[++i];
		} else if (!strcmp(a, "--file") && i + 1 < argc) {
			src = SRC_FILE;
			path = argv[++i];
		} else if (!strcmp(a, "--scan")) {
			src = SRC_SCAN;
		} else if (!strcmp(a, "--scan-file") && i + 1 < argc) {
			src = SRC_SCANFILE;
			path = argv[++i];
		} else if (!strcmp(a, "--base") && i + 1 < argc) {
			if (parse_uint(argv[++i], ~0ul, &base)) { usage(); return 2; }
		} else if (!strcmp(a, "--range") && i + 1 < argc && nranges < 8) {
			char *dash = strchr(argv[++i], '-');
			unsigned long lo, hi;
			if (!dash) { usage(); return 2; }
			*dash = 0;
			if (parse_uint(argv[i], ~0ul, &lo) || parse_uint(dash + 1, ~0ul, &hi) || hi <= lo) { usage(); return 2; }
			ranges[nranges][0] = lo;
			ranges[nranges][1] = hi;
			nranges++;
		} else if (!strcmp(a, "--cmdline")) {
			use_cmdline = 1;
		} else if (!strcmp(a, "--cmdline-file") && i + 1 < argc) {
			cmdline_file = argv[++i];
			use_cmdline = 1;
		} else if (!strcmp(a, "--params") && i + 1 < argc && nparams < 8) {
			params[nparams++] = argv[++i];
		} else if (!strcmp(a, "--param") && i + 1 < argc) {
			exp_token(argv[++i], 0);
		} else if (!strcmp(a, "--strict")) {
			g_strict = 1;
		} else if (!strcmp(a, "--check-nic")) {
			check_nic = 1;
		} else if (!strcmp(a, "--net-dir") && i + 1 < argc) {
			g_netdir = argv[++i];
		} else if (!strcmp(a, "--hexdump")) {
			hexdump = 1;
		} else if (!strcmp(a, "--supplied-key") && i + 1 < argc) {
			supplied = argv[++i];
		} else if (!strcmp(a, "--emit-env") && i + 1 < argc) {
			emit_env = argv[++i];
		} else if (!strcmp(a, "--emit-secret") && i + 1 < argc) {
			emit_secret = argv[++i];
		} else {
			usage();
			return 2;
		}
	}
	if (src == SRC_NONE) {
		usage();
		return 2;
	}
	/* a file from an earlier run must not stand in for this run's verdict (also when no table can be read at all): it is there only if
	 * this run's table is sound */
	if (emit_env)
		(void)unlink(emit_env);
	if (use_cmdline) {
		char cl[4096];
		FILE *f = fopen(cmdline_file, "r");
		if (f) {
			size_t n = fread(cl, 1, sizeof cl - 1, f);
			fclose(f);
			cl[n] = 0;
			(void)exp_text(cl, 1);
		}
	}
	for (i = 0; i < nparams; i++) {
		int pr = exp_file(params[i], 0);
		if (pr == -2)
			say_fail("params", "%s is longer than 4095 bytes: not used", params[i]);
		else if (pr != 0)
			say_info("params", "cannot read %s", params[i]);
	}
	{
		const char *s = exp_get("strict");
		if (s && !strcmp(s, "1"))
			g_strict = 1;
	}

	switch (src) {
	case SRC_SYSFS:
	case SRC_FILE:
		if (read_all(path, srcbuf, sizeof srcbuf, &srclen)) {
			printf("RBFT-RESULT NOTABLE cannot read %s: %s\n", path, strerror(errno));
			return 2;
		}
		say_info("source", "%s %s (%zu bytes read)", src == SRC_SYSFS ? "sysfs" : "file", path, srclen);
		tab = srcbuf;
		tablen = srclen;
		break;
	case SRC_SCAN:
	case SRC_SCANFILE:
		if (src == SRC_SCAN) {
			if (!nranges) {
				ranges[0][0] = 0;
				ranges[0][1] = 0x100000;
				nranges = 1;
			}
			{
				int ok = 0;
				for (i = 0; i < nranges; i++)
					if (scan_devmem(ranges[i][0], ranges[i][1], &fdz) == 0)
						ok = 1;
				if (!ok) {
					printf("RBFT-RESULT NOTABLE /dev/mem could not be read\n");
					return 2;
				}
			}
		} else {
			struct stat st;
			int fdi = open(path, O_RDONLY);
			int ok = 0;
			if (fdi < 0 || fstat(fdi, &st) != 0) {
				printf("RBFT-RESULT NOTABLE cannot read %s: %s\n", path, strerror(errno));
				return 2;
			}
			if (!nranges) {
				ranges[0][0] = base;
				ranges[0][1] = base + (unsigned long)st.st_size;
				nranges = 1;
			}
			for (i = 0; i < nranges; i++)
				if (scan_fd(fdi, base, ranges[i][0], ranges[i][1], &fdz) == 0)
					ok = 1;
			close(fdi);
			if (!ok) {
				printf("RBFT-RESULT NOTABLE nothing could be read from %s in the range\n", path);
				return 2;
			}
		}
		if (!fdz.count) {
			printf("RBFT-RESULT NOTABLE no rBFT table with a valid checksum found (%d signature hit(s) with a bad checksum)\n", fdz.badsum);
			return 2;
		}
		say_info("source", "scan: found at physical address 0x%lx (%d valid copy/copies)", fdz.addr, fdz.count);
		if (fdz.differ)
			say_fail("scan", "%d valid tables that differ from each other: ambiguous", fdz.count);
		tab = fdz.raw;
		tablen = fdz.len;
		break;
	default:
		return 2;
	}

	rc = decode(tab, tablen, &t);
	if (rc == 0) {
		chk_fields(&t, supplied, check_nic);
		if (check_nic && !t.sound)
			say_info("hook", "table is not sound: not used for NIC or mapping");
		if (emit_env && t.sound && t.safe_names) {
			if (write_env(&t, emit_env) != 0) {
				say_fail("emit-env", "cannot write %s: %s", emit_env, strerror(errno));
				(void)unlink(emit_env); /* never leave half a file for the hook to read */
			}
		}
		if (emit_secret && t.sound && t.safe_names) {
			int w = write_secret(&t, emit_secret);
			if (w < 0)
				say_fail("emit-secret", "cannot write %s: %s", emit_secret, strerror(errno));
			else if (w > 0 && t.key)
				say_info("emit-secret", "the key type %s cannot be used by the kernel client; no secret written", key_name(t.key_type));
		}
	}
	if (hexdump)
		hexdump_table(t.len ? t.raw : tab, t.len ? t.len : tablen, t.key, t.key_len, rc == 0);
	wipe_mem(t.raw, sizeof t.raw);
	wipe_mem(srcbuf, sizeof srcbuf);
	wipe_mem(fdz.raw, sizeof fdz.raw);
	printf("RBFT-RESULT %s pass=%d fail=%d skip=%d\n", n_fail ? "FAIL" : "PASS", n_pass, n_fail, n_skip);
	return n_fail ? 1 : 0;
}
