# SPDX-License-Identifier: MIT
#
# bench.S - a BIOS boot sector that times INT 13h commands through the SAN layer (the exit measurements of docs/design/ipxe-driver.md 14.4).
#
# It is the "loader" of the measurements, like robust/tools/reader.S (whose console routines it follows; the program is new): after "sanboot"
# there is no iPXE shell, and iPXE for BIOS has no command that reads raw sectors with a chosen command size, so the caller has to be a boot
# sector. It runs a PLAN, a list of records patched into the second stage by mkbench.py, and prints one line per step on COM1.
#
# Time: the TSC (RDTSC works in real mode), because the BIOS tick (18.2 Hz) is too coarse for one command. The plan starts with a calibration step
# (Z) that prints the TSC at two edges of the BIOS tick counter, 91 ticks (5 s) apart; mkbench's analyser turns a TSC delta into seconds with that.
#
# Steps (a record is 32 bytes, see mkbench.py; all numbers are sectors of 512 bytes):
#   Z  calibrate the TSC against the BIOS tick                                  WRMS-CAL id= tsc0= tsc1= ticks=
#   R  read TOTAL sectors from LBA in commands of CMD sectors                   WRMS-STEP id= type=R cmd= sectors= errs= ...
#   C  copy: read a command's worth from LBA, write it to DST, repeat (the read is checked like R's, the write is checked from outside:
#      "rbd export" of the destination against the source)
#   L  latency series: K reads of CMD sectors at LBA + k * DST (a stride, so the sequence is not sequential and no readahead window opens),
#      after waiting GAP seconds (HLT loop, the BIOS tick counter is the clock). One line per read.   WRMS-LAT / WRMS-LATR
#
# A command of up to 127 sectors is issued as the classic form (segment:offset, a 16-byte packet) into the buffer at 0x10000, like a boot
# loader does. A larger command is the EDD 3.0/4.0 form (packet of 32 bytes, count 0xff + a 32-bit count, a 64-bit buffer address), into the
# buffer at physical 0x00800000 (an extended-memory buffer, the loader's own choice: real mode cannot address 4 MiB).
#
# The data check: after a step, the first and the last 64 KiB (or the whole command when it is smaller) of the last command's buffer are summed
# as dwords (extended memory is read through INT 15h AH=87h): "sumA" and "sumB". The analyser compares them with the sums of the same bytes in
# the image it built. A buffer that was not filled would not have the sum.
#
# Output (CR LF lines, 64-bit values as 16 hex digits):
#   WRMS-START drive=80 steps=N
#   WRMS-CAL id=I tsc0=H tsc1=H ticks=D
#   WRMS-STEP id=I type=R|C cmd=C sectors=S errs=E rdn=N rdtsc=H wrn=N wrtsc=H walltsc=H ticks=D sumA=X sumB=X lastcnt=K
#   WRMS-LAT id=I gap=G cmd=C n=K
#   WRMS-LATR id=I k=K lba=L tsc=H ah=XX
#   WRMS-ERR id=I ah=XX lba=L op=XX
#   WRMS-DONE errs=E
# then INT 18h: iPXE gets control back in the script (rbd-info and the heap line follow).
#
# Build:  as --32 -o bench.o bench.S && ld -m elf_i386 -Ttext 0x7c00 --oformat binary -o bench.bin bench.o     (mkbench.py does it and appends the data)
# Layout: sector 0 = stage 1 (loads stage 2), sectors 1..15 = stage 2 (header "WRMB" + nrec, the records at +0x20, the code), data from sector 16.

	.code16
	.intel_syntax noprefix
	.text
	.globl _start

	.equ V,        0xb000
	.equ V_DRIVE,  V+0x00		# byte
	.equ V_OP,     V+0x01		# byte: 0x42 read, 0x43 write
	.equ V_TYPE,   V+0x02		# byte: the step's type letter
	.equ V_LASTERR,V+0x03		# byte
	.equ V_STEP,   V+0x04		# dword: index of the current record
	.equ V_NREC,   V+0x08
	.equ V_REC,    V+0x0c		# word: pointer to the current record
	.equ V_ERRS,   V+0x10		# dword: errors of the whole run
	.equ V_SERR,   V+0x14		# dword: errors of the step
	.equ V_RDN,    V+0x18
	.equ V_WRN,    V+0x1c
	.equ V_RDT,    V+0x20		# qword: sum of the TSC deltas of the read calls
	.equ V_WRT,    V+0x28		# qword: the same for writes
	.equ V_T0,     V+0x30		# qword: TSC at the start of the step
	.equ V_TK0,    V+0x38		# dword: BIOS ticks at the start of the step
	.equ V_LBA,    V+0x3c		# dword
	.equ V_DLBA,   V+0x40
	.equ V_LEFT,   V+0x44
	.equ V_CNT,    V+0x48		# dword: sectors of the current command
	.equ V_CMD,    V+0x4c		# dword: sectors per command of the step
	.equ V_SUMA,   V+0x50
	.equ V_SUMB,   V+0x54
	.equ V_DONE,   V+0x58
	.equ V_TSCL,   V+0x5c		# qword: scratch
	.equ V_LAST,   V+0x64		# qword: TSC delta of the last call
	.equ V_IOLBA,  V+0x6c		# dword: LBA of the next call
	.equ V_SRC,    V+0x70		# dword: source of the extended-memory copy
	.equ V_WORDS,  V+0x74		# word: words to copy
	.equ V_NB,     V+0x78		# dword
	.equ V_BASE,   V+0x7c		# dword: base of the buffer
	.equ V_K,      V+0x80		# dword: index in a latency series
	.equ V_GAP,    V+0x84		# dword
	.equ V_DAP,    V+0xa0		# 32 bytes
	.equ V_GDT,    V+0xe0		# 48 bytes
	.equ HDR,      0x7e00
	.equ RECS,     HDR+0x20
	.equ BUF_PHYS, 0x00800000
	.equ BUF_SEG,  0x1000
	.equ CHK_PHYS, 0x00020000	# where the check copies to (segment 0x2000)
	.equ CHK_SEG,  0x2000
	.equ DATA_FIRST, 16

# ------------------------------------------------------------------------------------------------------------ stage 1 (sector 0)
_start:
	cli
	xor	ax, ax
	mov	ds, ax
	mov	es, ax
	mov	ss, ax
	mov	sp, 0x7a00
	sti
	cld
	mov	byte ptr [V_DRIVE], dl
	mov	si, offset dap1
	mov	ah, 0x42
	int	0x13
	jc	fail1
	jmp	stage2
fail1:
	mov	al, '!'
	call	putc
	int	0x18
dap1:	.byte	0x10, 0
	.word	15
	.word	0x7e00, 0
	.quad	1
	.org	510
	.word	0xaa55

# ------------------------------------------------------------------------------------------------------------ stage 2 (sectors 1-15)
	.org	512
hdr:	.ascii	"WRMB"
hdr_n:	.long	0			# number of records (patched by mkbench.py)
	.org	512+0x20
recs:	.fill	32*64, 1, 0		# up to 64 records (patched by mkbench.py)

stage2:
	mov	bl, byte ptr [V_DRIVE]
	mov	di, V
	mov	cx, 0x100
	xor	al, al
	rep	stosb
	mov	byte ptr [V_DRIVE], bl
	mov	eax, dword ptr [hdr_n]
	mov	dword ptr [V_NREC], eax
	mov	si, offset s_start
	call	puts
	mov	al, byte ptr [V_DRIVE]
	call	puthex8
	mov	si, offset s_steps
	call	puts
	mov	eax, dword ptr [V_NREC]
	call	putdec
	call	putcrlf
	mov	word ptr [V_REC], offset recs

nextstep:
	mov	eax, dword ptr [V_STEP]
	cmp	eax, dword ptr [V_NREC]
	jae	alldone
	mov	bx, word ptr [V_REC]
	mov	al, byte ptr [bx]
	mov	byte ptr [V_TYPE], al
	cmp	al, 'Z'
	je	do_cal
	cmp	al, 'L'
	je	do_lat
	jmp	do_rc			# R and C (anything else is a plan error: it is run as R)

stepend:
	inc	dword ptr [V_STEP]
	add	word ptr [V_REC], 32
	jmp	nextstep

alldone:
	mov	si, offset s_done
	call	puts
	mov	eax, dword ptr [V_ERRS]
	call	putdec
	call	putcrlf
	int	0x18
hang:	hlt
	jmp	hang

# ------------------------------------------------------------------------------------------------------------ Z: calibration
do_cal:
	call	ticks
	mov	ebp, eax
1:	call	ticks			# the edge: the counter changes
	cmp	eax, ebp
	je	1b
	mov	ebp, eax
	rdtsc
	mov	dword ptr [V_T0], eax
	mov	dword ptr [V_T0+4], edx
	add	ebp, 91
2:	call	ticks
	cmp	eax, ebp
	jb	2b
	rdtsc
	mov	dword ptr [V_TSCL], eax
	mov	dword ptr [V_TSCL+4], edx
	mov	si, offset s_cal
	call	puts
	call	putid
	mov	si, offset s_tsc0
	call	puts
	mov	edx, dword ptr [V_T0+4]
	mov	eax, dword ptr [V_T0]
	call	puthex64
	mov	si, offset s_tsc1
	call	puts
	mov	edx, dword ptr [V_TSCL+4]
	mov	eax, dword ptr [V_TSCL]
	call	puthex64
	mov	si, offset s_ticks
	call	puts
	mov	eax, 91
	call	putdec
	call	putcrlf
	jmp	stepend

# ------------------------------------------------------------------------------------------------------------ R and C
do_rc:
	mov	bx, word ptr [V_REC]
	mov	eax, dword ptr [bx+4]
	mov	dword ptr [V_CMD], eax
	mov	eax, dword ptr [bx+8]
	mov	dword ptr [V_LEFT], eax
	mov	eax, dword ptr [bx+12]
	mov	dword ptr [V_LBA], eax
	mov	eax, dword ptr [bx+16]
	mov	dword ptr [V_DLBA], eax
	xor	eax, eax
	mov	dword ptr [V_SERR], eax
	mov	dword ptr [V_RDN], eax
	mov	dword ptr [V_WRN], eax
	mov	dword ptr [V_RDT], eax
	mov	dword ptr [V_RDT+4], eax
	mov	dword ptr [V_WRT], eax
	mov	dword ptr [V_WRT+4], eax
	mov	dword ptr [V_DONE], eax
	mov	dword ptr [V_CNT], eax
	call	ticks
	mov	dword ptr [V_TK0], eax
	rdtsc
	mov	dword ptr [V_T0], eax
	mov	dword ptr [V_T0+4], edx
rc_loop:
	cmp	dword ptr [V_LEFT], 0
	je	rc_end
	mov	eax, dword ptr [V_CMD]
	cmp	eax, dword ptr [V_LEFT]
	jbe	1f
	mov	eax, dword ptr [V_LEFT]
1:	mov	dword ptr [V_CNT], eax
	mov	byte ptr [V_OP], 0x42
	mov	eax, dword ptr [V_LBA]
	mov	dword ptr [V_IOLBA], eax
	call	io_cmd
	jc	rc_err
	cmp	byte ptr [V_TYPE], 'C'
	jne	2f
	mov	byte ptr [V_OP], 0x43
	mov	eax, dword ptr [V_DLBA]
	mov	dword ptr [V_IOLBA], eax
	call	io_cmd
	jc	rc_err
2:	mov	eax, dword ptr [V_CNT]
	add	dword ptr [V_LBA], eax
	add	dword ptr [V_DLBA], eax
	sub	dword ptr [V_LEFT], eax
	add	dword ptr [V_DONE], eax
	jmp	rc_loop
rc_err:
	call	errline
	jmp	rc_fin
rc_end:
rc_fin:
	rdtsc
	sub	eax, dword ptr [V_T0]
	sbb	edx, dword ptr [V_T0+4]
	mov	dword ptr [V_T0], eax		# the wall TSC delta
	mov	dword ptr [V_T0+4], edx
	call	ticks
	sub	eax, dword ptr [V_TK0]
	mov	dword ptr [V_TK0], eax
	mov	dword ptr [V_SUMA], 0
	mov	dword ptr [V_SUMB], 0
	cmp	dword ptr [V_DONE], 0
	je	1f
	cmp	dword ptr [V_SERR], 0
	jne	1f
	call	checksums
1:	mov	si, offset s_step
	call	puts
	call	putid
	mov	si, offset s_type
	call	puts
	mov	al, byte ptr [V_TYPE]
	call	putc
	mov	si, offset s_cmd
	call	puts
	mov	eax, dword ptr [V_CMD]
	call	putdec
	mov	si, offset s_sectors
	call	puts
	mov	eax, dword ptr [V_DONE]
	call	putdec
	mov	si, offset s_errs
	call	puts
	mov	eax, dword ptr [V_SERR]
	call	putdec
	mov	si, offset s_rdn
	call	puts
	mov	eax, dword ptr [V_RDN]
	call	putdec
	mov	si, offset s_rdtsc
	call	puts
	mov	edx, dword ptr [V_RDT+4]
	mov	eax, dword ptr [V_RDT]
	call	puthex64
	mov	si, offset s_wrn
	call	puts
	mov	eax, dword ptr [V_WRN]
	call	putdec
	mov	si, offset s_wrtsc
	call	puts
	mov	edx, dword ptr [V_WRT+4]
	mov	eax, dword ptr [V_WRT]
	call	puthex64
	mov	si, offset s_wall
	call	puts
	mov	edx, dword ptr [V_T0+4]
	mov	eax, dword ptr [V_T0]
	call	puthex64
	mov	si, offset s_ticks
	call	puts
	mov	eax, dword ptr [V_TK0]
	call	putdec
	mov	si, offset s_suma
	call	puts
	mov	eax, dword ptr [V_SUMA]
	call	puthex32
	mov	si, offset s_sumb
	call	puts
	mov	eax, dword ptr [V_SUMB]
	call	puthex32
	mov	si, offset s_last
	call	puts
	mov	eax, dword ptr [V_CNT]
	call	putdec
	call	putcrlf
	jmp	stepend

# ------------------------------------------------------------------------------------------------------------ L: latency series
do_lat:
	mov	bx, word ptr [V_REC]
	mov	eax, dword ptr [bx+4]
	mov	dword ptr [V_CMD], eax
	mov	eax, dword ptr [bx+12]
	mov	dword ptr [V_LBA], eax
	mov	eax, dword ptr [bx+20]
	mov	dword ptr [V_GAP], eax
	mov	si, offset s_lat
	call	puts
	call	putid
	mov	si, offset s_gap
	call	puts
	mov	eax, dword ptr [V_GAP]
	call	putdec
	mov	si, offset s_cmd
	call	puts
	mov	eax, dword ptr [V_CMD]
	call	putdec
	mov	si, offset s_n
	call	puts
	mov	bx, word ptr [V_REC]
	mov	eax, dword ptr [bx+8]
	call	putdec
	call	putcrlf
	# the gap: HLT until the BIOS tick counter has moved by GAP * 18.2065 ticks
	mov	eax, dword ptr [V_GAP]
	test	eax, eax
	jz	lat_go
	mov	ecx, 18207
	mul	ecx
	mov	ecx, 1000
	div	ecx
	mov	ebp, eax
	call	ticks
	add	ebp, eax			# the tick count to wait for
3:	sti
	hlt
	call	ticks
	cmp	eax, ebp
	jb	3b
lat_go:
	mov	dword ptr [V_K], 0
lat_loop:
	mov	bx, word ptr [V_REC]
	mov	eax, dword ptr [V_K]
	cmp	eax, dword ptr [bx+8]
	jae	lat_end
	mov	eax, dword ptr [V_CMD]
	mov	dword ptr [V_CNT], eax
	mov	byte ptr [V_OP], 0x42
	mov	eax, dword ptr [V_K]
	mul	dword ptr [bx+16]
	add	eax, dword ptr [V_LBA]
	mov	dword ptr [V_IOLBA], eax
	call	io_cmd
	pushf
	mov	si, offset s_latr
	call	puts
	call	putid
	mov	si, offset s_k
	call	puts
	mov	eax, dword ptr [V_K]
	call	putdec
	mov	si, offset s_lba
	call	puts
	mov	eax, dword ptr [V_IOLBA]
	call	putdec
	mov	si, offset s_tsc
	call	puts
	mov	edx, dword ptr [V_LAST+4]
	mov	eax, dword ptr [V_LAST]
	call	puthex64
	mov	si, offset s_ah
	call	puts
	popf
	pushf
	mov	al, 0
	jnc	4f
	mov	al, byte ptr [V_LASTERR]
	inc	dword ptr [V_ERRS]
4:	call	puthex8
	popf
	call	putcrlf
	inc	dword ptr [V_K]
	jmp	lat_loop
lat_end:
	jmp	stepend

# ------------------------------------------------------------------------------------------------------------ one INT 13h call
# in: V_OP (0x42 / 0x43), V_IOLBA, V_CNT, V_CMD (decides the form); out: CF as the BIOS left it; the TSC delta is added to the read or write sum and
# is in V_LAST
io_cmd:
	push	ebx
	push	esi
	push	edi
	mov	di, V_DAP
	cmp	dword ptr [V_CMD], 127
	ja	io_big
	mov	byte ptr [di], 0x10
	mov	byte ptr [di+1], 0
	mov	ax, word ptr [V_CNT]
	mov	word ptr [di+2], ax
	mov	word ptr [di+4], 0
	mov	word ptr [di+6], BUF_SEG
	jmp	io_lba
io_big:
	mov	byte ptr [di], 0x20
	mov	byte ptr [di+1], 0
	mov	word ptr [di+2], 0x00ff		# count 0xff: the real count is the 32-bit one
	mov	word ptr [di+4], 0xffff		# segment:offset ffff:ffff: the buffer is the 64-bit address
	mov	word ptr [di+6], 0xffff
	mov	dword ptr [di+16], BUF_PHYS
	mov	dword ptr [di+20], 0
	mov	eax, dword ptr [V_CNT]
	mov	dword ptr [di+24], eax
	mov	dword ptr [di+28], 0
io_lba:
	mov	eax, dword ptr [V_IOLBA]
	mov	dword ptr [di+8], eax
	mov	dword ptr [di+12], 0
	rdtsc
	mov	dword ptr [V_TSCL], eax
	mov	dword ptr [V_TSCL+4], edx
	mov	si, V_DAP
	mov	dl, byte ptr [V_DRIVE]
	mov	ah, byte ptr [V_OP]
	xor	al, al
	int	0x13
	mov	byte ptr [V_LASTERR], ah
	pushf
	rdtsc
	sub	eax, dword ptr [V_TSCL]
	sbb	edx, dword ptr [V_TSCL+4]
	mov	dword ptr [V_LAST], eax
	mov	dword ptr [V_LAST+4], edx
	cmp	byte ptr [V_OP], 0x42
	jne	io_w
	add	dword ptr [V_RDT], eax
	adc	dword ptr [V_RDT+4], edx
	inc	dword ptr [V_RDN]
	jmp	io_x
io_w:
	add	dword ptr [V_WRT], eax
	adc	dword ptr [V_WRT+4], edx
	inc	dword ptr [V_WRN]
io_x:
	popf
	pop	edi
	pop	esi
	pop	ebx
	ret

errline:
	inc	dword ptr [V_ERRS]
	inc	dword ptr [V_SERR]
	mov	si, offset s_err
	call	puts
	call	putid
	mov	si, offset s_ah
	call	puts
	mov	al, byte ptr [V_LASTERR]
	call	puthex8
	mov	si, offset s_lba
	call	puts
	mov	eax, dword ptr [V_IOLBA]
	call	putdec
	mov	si, offset s_op
	call	puts
	mov	al, byte ptr [V_OP]
	call	puthex8
	call	putcrlf
	ret

# ------------------------------------------------------------------------------------------------------------ the data check
# sums (as dwords) the first and the last min(bytes of the last command, 64 KiB) of the buffer into V_SUMA / V_SUMB
checksums:
	mov	eax, dword ptr [V_CNT]
	shl	eax, 9
	mov	dword ptr [V_NB], eax		# bytes of the last command
	mov	edx, 65536
	cmp	eax, edx
	jbe	1f
	mov	eax, edx
1:	mov	edx, dword ptr [V_NB]		# edx = bytes, eax = bytes to sum
	mov	ebx, 0x10000
	cmp	dword ptr [V_CMD], 127
	jbe	2f
	mov	ebx, BUF_PHYS
2:	mov	dword ptr [V_BASE], ebx
	push	eax				# bytes to sum
	mov	dword ptr [V_SRC], ebx
	call	chk_one
	mov	dword ptr [V_SUMA], edx
	pop	eax
	mov	ecx, dword ptr [V_NB]
	sub	ecx, eax			# offset of the last piece
	add	ecx, dword ptr [V_BASE]
	mov	dword ptr [V_SRC], ecx
	call	chk_one
	mov	dword ptr [V_SUMB], edx
	ret

# eax = bytes, V_SRC = the physical source: copies to CHK_PHYS (INT 15h AH=87h) and returns the dword sum in edx (eax is kept)
chk_one:
	push	eax
	push	ecx
	push	esi
	push	edi
	push	ds
	push	es
	xor	cx, cx
	mov	ds, cx
	mov	es, cx
	mov	edx, eax
	shr	edx, 1
	mov	word ptr [V_WORDS], dx		# words
	mov	di, V_GDT
	xor	eax, eax
	mov	cx, 12
	rep	stosd
	mov	di, V_GDT+16			# descriptor 2: the source
	mov	word ptr [di], 0xffff
	mov	eax, dword ptr [V_SRC]
	mov	word ptr [di+2], ax
	shr	eax, 16
	mov	byte ptr [di+4], al
	mov	byte ptr [di+5], 0x93
	mov	byte ptr [di+6], 0
	mov	byte ptr [di+7], ah
	mov	di, V_GDT+24			# descriptor 3: the destination
	mov	word ptr [di], 0xffff
	mov	eax, CHK_PHYS
	mov	word ptr [di+2], ax
	shr	eax, 16
	mov	byte ptr [di+4], al
	mov	byte ptr [di+5], 0x93
	mov	byte ptr [di+6], 0
	mov	byte ptr [di+7], ah
	mov	si, V_GDT
	mov	cx, word ptr [V_WORDS]
	mov	ah, 0x87
	int	0x15
	jc	chk_bad
	xor	ax, ax
	mov	ds, ax
	movzx	ecx, word ptr [V_WORDS]
	mov	ax, CHK_SEG
	mov	ds, ax
	xor	si, si
	xor	edx, edx
	shr	cx, 1				# dwords
	jz	chk_x
3:	lodsd
	add	edx, eax
	loop	3b
	jmp	chk_x
chk_bad:
	mov	edx, 0xdead0000
chk_x:
	pop	es
	pop	ds
	pop	edi
	pop	esi
	pop	ecx
	pop	eax
	ret

# ------------------------------------------------------------------------------------------------------------ helpers
# eax = BIOS tick count (18.2 Hz)
ticks:
	push	cx
	push	dx
	xor	ah, ah
	int	0x1a
	mov	ax, cx
	shl	eax, 16
	mov	ax, dx
	pop	dx
	pop	cx
	ret

# " id=N" of the current record
putid:
	push	eax
	push	si
	mov	si, offset s_id
	call	puts
	mov	bx, word ptr [V_REC]
	mov	eax, dword ptr [bx+24]
	call	putdec
	pop	si
	pop	eax
	ret

putcrlf:
	mov	al, 13
	call	putc
	mov	al, 10
	call	putc
	ret

# the serial port COM1 (iPXE has set it up; QEMU's file backend takes whatever is written)
putc:
	push	dx
	push	ax
	mov	dx, 0x3fd
1:	in	al, dx
	test	al, 0x20
	jz	1b
	pop	ax
	mov	dx, 0x3f8
	out	dx, al
	pop	dx
	ret

puts:
	push	ax
1:	lodsb
	test	al, al
	jz	2f
	call	putc
	jmp	1b
2:	pop	ax
	ret

puthex8:
	push	ax
	push	ax
	shr	al, 4
	call	nib
	pop	ax
	and	al, 15
	call	nib
	pop	ax
	ret
nib:	add	al, '0'
	cmp	al, '9'
	jbe	1f
	add	al, 39				# lower case: 'a' - '9' - 1
1:	call	putc
	ret

puthex32:
	push	eax
	rol	eax, 8
	call	puthex8
	rol	eax, 8
	call	puthex8
	rol	eax, 8
	call	puthex8
	rol	eax, 8
	call	puthex8
	pop	eax
	ret

# edx:eax in hex
puthex64:
	push	eax
	mov	eax, edx
	call	puthex32
	pop	eax
	call	puthex32
	ret

# eax in decimal
putdec:
	push	eax
	push	ebx
	push	ecx
	push	edx
	xor	cx, cx
	mov	ebx, 10
1:	xor	edx, edx
	div	ebx
	push	dx
	inc	cx
	test	eax, eax
	jnz	1b
2:	pop	ax
	add	al, '0'
	call	putc
	loop	2b
	pop	edx
	pop	ecx
	pop	ebx
	pop	eax
	ret

s_start:	.asciz	"WRMS-START drive="
s_steps:	.asciz	" steps="
s_cal:		.asciz	"WRMS-CAL"
s_step:		.asciz	"WRMS-STEP"
s_lat:		.asciz	"WRMS-LAT"
s_latr:		.asciz	"WRMS-LATR"
s_err:		.asciz	"WRMS-ERR"
s_done:		.asciz	"WRMS-DONE errs="
s_id:		.asciz	" id="
s_type:		.asciz	" type="
s_cmd:		.asciz	" cmd="
s_sectors:	.asciz	" sectors="
s_errs:		.asciz	" errs="
s_rdn:		.asciz	" rdn="
s_rdtsc:	.asciz	" rdtsc="
s_wrn:		.asciz	" wrn="
s_wrtsc:	.asciz	" wrtsc="
s_wall:		.asciz	" walltsc="
s_ticks:	.asciz	" ticks="
s_suma:		.asciz	" sumA="
s_sumb:		.asciz	" sumB="
s_last:		.asciz	" lastcnt="
s_tsc0:		.asciz	" tsc0="
s_tsc1:		.asciz	" tsc1="
s_gap:		.asciz	" gap="
s_n:		.asciz	" n="
s_k:		.asciz	" k="
s_lba:		.asciz	" lba="
s_tsc:		.asciz	" tsc="
s_ah:		.asciz	" ah="
s_op:		.asciz	" op="

	.org	8192
