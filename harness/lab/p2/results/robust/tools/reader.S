# SPDX-License-Identifier: MIT
#
# reader.S - a BIOS boot sector that reads a disk through INT 13h and says what it read (rows of qemu-robust, BIOS family).
#
# Why it exists: after "sanboot" there is no iPXE shell, and iPXE for BIOS has no command that reads raw sectors, so the bytes that the
# driver delivers to an INT 13h caller cannot be digested from the script. This program is the caller. It is the "loader" of
# docs/design/ipxe-driver.md 14.3: it reads sectors DATA_FIRST ... DATA_FIRST+N-1 with INT 13h AH=42h in commands of changing size
# (127, 64, 33, 8, 1, 100, 17, 127 sectors, repeating: what GRUB and the Windows boot manager mix), folds every dword into a hash, and prints
# progress and the verdict on COM1 (the serial console of the run script). Then it returns to iPXE with INT 18h (iPXE hooks INT 18/19: a boot
# sector that "fails" gets control back in the script, which prints rbd-info).
#
# The hash is order dependent:  h = 0;  for every little-endian dword w of the data, in disk order:  h = rol32(h, 5) ^ w;  h = (h * 0x9E3779B1) mod 2^32.
# tools/reader-hash.py computes the same over a file (the oracle's side: "rbd export" of the same image).
#
# The canary (design 14.3, "no byte lands in a released buffer"): three buffers of 64 KiB rotate. When a read has completed, the program
#   - hashes the new buffer and remembers its dword sum,
#   - looks at the two others: a buffer that holds data must still have its sum (a late write by a cancelled command would change it), then it is
#     overwritten with 0xA5A5A5A5; a buffer that holds the canary must still be all canary (a late write would break it).
# A mismatch is a "WRRB-STALE" line. After the last read it waits about a second and checks again. A command of the SAN layer that the driver cancelled
# (15 s timeout) and the SAN layer re-issued writes into the SAME buffer, with the same data: that is not stale and the program sees nothing; what it
# sees is a write into a buffer the loader has already moved on from.
#
# Output (one line each, CR LF):
#   WRRB-START drive=80 first=8 sectors=N rtc=HHMMSS
#   WRRB-PROG lba=L h=XXXXXXXX maxticks=T@LBA rtc=HHMMSS errs=E stale=S       every 4096 sectors; h = the hash of everything read so far
#   WRRB-ERR ah=XX lba=L try=K                                             a read failed (up to 3 tries per command, then the run ends)
#   WRRB-STALE slot=I lba=L what=sum|canary
#   WRRB-DONE sectors=N h=XXXXXXXX errs=E stale=S maxticks=T@LBA rtc=HHMMSS end=ok|err
# (ticks are the BIOS's 18.2 per second; rtc is the CMOS clock in BCD, which follows the host's clock when QEMU runs with -rtc clock=host.)
#
# Build:  as --32 -o reader.o reader.S && ld -m elf_i386 -Ttext 0x7c00 --oformat binary -o reader.bin reader.o     (tools/mkreader.py does it and appends the data)
# Layout: sector 0 = stage 1 (loads stage 2), sectors 1..7 = stage 2, data from sector 8.

	.code16
	.intel_syntax noprefix
	.text
	.globl _start

	.equ V,        0xa000		# variables (above the 7 sectors of code, below the buffers at 0x10000)
	.equ V_DRIVE,  V+0x00		# byte
	.equ V_LBA,    V+0x04		# dword
	.equ V_LEFT,   V+0x08		# dword sectors left
	.equ V_H,      V+0x0c		# dword hash
	.equ V_STALE,  V+0x10
	.equ V_ERRS,   V+0x14
	.equ V_MAXT,   V+0x18
	.equ V_MAXLBA, V+0x1c
	.equ V_CHUNK,  V+0x20		# dword chunk index
	.equ V_CUR,    V+0x24		# dword current slot
	.equ V_NEXTP,  V+0x28		# dword next progress at this many sectors done
	.equ V_DONE,   V+0x2c		# dword sectors done
	.equ V_CNT,    V+0x30		# dword count of the current command
	.equ V_SLOTS,  V+0x40		# 3 slots of 16 bytes: len (dwords), sum, state (0 empty, 1 data, 2 canary), lba
	.equ V_DAP,    V+0x80		# the disk address packet
	.equ SLOT0_SEG, 0x1000
	.equ DATA_FIRST, 8
	.equ CANARY,   0xA5A5A5A5
	.equ PROG_STEP, 4096

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
	.word	7
	.word	0x7e00, 0
	.quad	1
	.org	510
	.word	0xaa55

# ------------------------------------------------------------------------------------------------------------ stage 2 (sectors 1-7)
	.org	512
hdr:	.ascii	"WRRD"
hdr_n:	.long	0			# sectors of data (patched by mkreader.py)
	.long	0
	.long	0

stage2:
	# clear the variables (the drive number, kept by stage 1, survives)
	mov	bl, byte ptr [V_DRIVE]
	mov	di, V
	mov	cx, 0x100
	xor	al, al
	rep	stosb
	mov	byte ptr [V_DRIVE], bl
	mov	eax, dword ptr [hdr_n]
	mov	dword ptr [V_LEFT], eax
	mov	dword ptr [V_LBA], DATA_FIRST
	mov	dword ptr [V_NEXTP], PROG_STEP
	# fill the three buffers with the canary
	mov	bx, SLOT0_SEG
	mov	cx, 3
1:	push	cx
	mov	es, bx
	xor	di, di
	mov	ecx, 16384
	mov	eax, CANARY
	rep	stosd
	xor	ax, ax
	mov	es, ax
	add	bx, 0x1000
	pop	cx
	loop	1b
	mov	si, offset s_start
	call	puts
	mov	al, byte ptr [V_DRIVE]
	call	puthex8
	mov	si, offset s_first
	call	puts
	mov	eax, DATA_FIRST
	call	putdec
	mov	si, offset s_sectors
	call	puts
	mov	eax, dword ptr [hdr_n]
	call	putdec
	call	putrtc
	call	putcrlf
	mov	dword ptr [V_CUR], 2		# the first slot used is 0

mainloop:
	cmp	dword ptr [V_LEFT], 0
	je	finished
	# size of the next command
	mov	eax, dword ptr [V_CHUNK]
	and	eax, 7
	movzx	eax, byte ptr [chunks + eax]
	inc	dword ptr [V_CHUNK]
	cmp	eax, dword ptr [V_LEFT]
	jbe	1f
	mov	eax, dword ptr [V_LEFT]
1:	mov	dword ptr [V_CNT], eax
	mov	byte ptr [tries], 0
issue:
	# the slot (a command that failed and is tried again gets the next buffer: the failed one is a buffer the SAN layer has given back)
	mov	eax, dword ptr [V_CUR]
	inc	eax
	cmp	eax, 3
	jb	2f
	xor	eax, eax
2:	mov	dword ptr [V_CUR], eax
	# the packet
	mov	di, V_DAP
	mov	byte ptr [di], 0x10
	mov	byte ptr [di+1], 0
	mov	ax, word ptr [V_CNT]
	mov	word ptr [di+2], ax
	mov	word ptr [di+4], 0
	mov	eax, dword ptr [V_CUR]
	inc	eax
	shl	ax, 12				# segment = 0x1000 * (slot + 1)
	mov	word ptr [di+6], ax
	mov	eax, dword ptr [V_LBA]
	mov	dword ptr [di+8], eax
	mov	dword ptr [di+12], 0
	call	ticks
	mov	ebp, eax
	mov	si, V_DAP
	mov	dl, byte ptr [V_DRIVE]
	mov	ah, 0x42
	int	0x13
	jnc	readok
	# a failed read: the SAN layer has given up on the command and handed the buffer back. Overwrite it with the canary at once; a byte that still lands in it
	# later (a command the driver did not really cancel) breaks the canary and is reported by the next check as WRRB-STALE.
	mov	byte ptr [lasterr], ah
	inc	dword ptr [V_ERRS]
	inc	byte ptr [tries]
	mov	ebx, dword ptr [V_CUR]
	mov	eax, ebx
	shl	eax, 4
	mov	di, ax
	mov	eax, dword ptr [V_CNT]
	shl	eax, 7
	mov	dword ptr [V_SLOTS + di], eax
	mov	dword ptr [V_SLOTS + di + 4], 0
	mov	eax, dword ptr [V_LBA]
	mov	dword ptr [V_SLOTS + di + 12], eax
	call	poison_slot
	mov	dword ptr [V_SLOTS + di + 8], 2
	mov	si, offset s_err
	call	puts
	mov	al, byte ptr [lasterr]
	call	puthex8
	mov	si, offset s_errlba
	call	puts
	mov	eax, dword ptr [V_LBA]
	call	putdec
	mov	si, offset s_errtry
	call	puts
	movzx	eax, byte ptr [tries]
	call	putdec
	call	putcrlf
	cmp	byte ptr [tries], 3
	jb	issue
	mov	byte ptr [endflag], 1
	jmp	finished
readok:
	call	ticks
	sub	eax, ebp
	cmp	eax, dword ptr [V_MAXT]
	jbe	1f
	mov	dword ptr [V_MAXT], eax
	mov	eax, dword ptr [V_LBA]
	mov	dword ptr [V_MAXLBA], eax
1:
	# hash and sum the new buffer (everything the loop needs is loaded before DS moves)
	mov	ecx, dword ptr [V_CNT]
	shl	ecx, 7				# dwords
	mov	ebx, dword ptr [V_H]
	mov	eax, dword ptr [V_CUR]
	call	slotseg				# ax = segment of slot eax
	push	ds
	mov	ds, ax
	xor	si, si
	xor	edx, edx
2:	lodsd
	add	edx, eax
	rol	ebx, 5
	xor	ebx, eax
	imul	ebx, ebx, 0x9E3779B1
	loop	2b
	pop	ds
	mov	dword ptr [V_H], ebx
	# remember it in the slot table
	mov	eax, dword ptr [V_CUR]
	shl	eax, 4
	mov	di, ax
	mov	eax, dword ptr [V_CNT]
	shl	eax, 7
	mov	dword ptr [V_SLOTS + di], eax
	mov	dword ptr [V_SLOTS + di + 4], edx
	mov	dword ptr [V_SLOTS + di + 8], 1
	mov	eax, dword ptr [V_LBA]
	mov	dword ptr [V_SLOTS + di + 12], eax
	# look at the other two buffers
	call	checkothers
	# bookkeeping
	mov	eax, dword ptr [V_CNT]
	add	dword ptr [V_LBA], eax
	sub	dword ptr [V_LEFT], eax
	add	dword ptr [V_DONE], eax
	mov	eax, dword ptr [V_DONE]
	cmp	eax, dword ptr [V_NEXTP]
	jb	mainloop
	add	dword ptr [V_NEXTP], PROG_STEP
	call	progress
	jmp	mainloop

finished:
	# wait about a second, then look at all three buffers once more (a late write would land now)
	call	ticks
	add	eax, 20
	mov	ebp, eax
1:	call	ticks
	cmp	eax, ebp
	jb	1b
	mov	dword ptr [V_CUR], 3		# no slot is "current": every buffer is looked at
	call	checkothers
	mov	si, offset s_done
	call	puts
	mov	eax, dword ptr [V_DONE]
	call	putdec
	mov	si, offset s_h
	call	puts
	mov	eax, dword ptr [V_H]
	call	puthex32
	mov	si, offset s_errs
	call	puts
	mov	eax, dword ptr [V_ERRS]
	call	putdec
	mov	si, offset s_stale
	call	puts
	mov	eax, dword ptr [V_STALE]
	call	putdec
	call	putmax
	call	putrtc
	mov	si, offset s_end
	call	puts
	mov	si, offset s_ok
	cmp	byte ptr [endflag], 0
	je	2f
	mov	si, offset s_bad
2:	call	puts
	call	putcrlf
	int	0x18
hang:	hlt
	jmp	hang

# ax = segment of slot number eax
slotseg:
	inc	ax
	shl	ax, 12
	ret

# examine the slots other than V_CUR: data must be unchanged (then it becomes canary), canary must be intact
checkothers:
	xor	ebx, ebx			# slot number
chk_next:
	cmp	ebx, dword ptr [V_CUR]
	je	chk_skip
	mov	eax, ebx
	shl	eax, 4
	mov	di, ax				# di = offset of the slot's entry in the table
	mov	eax, dword ptr [V_SLOTS + di + 8]
	test	eax, eax
	jz	chk_skip
	cmp	eax, 1
	jne	chk_canary
	call	sumslot				# edx = the dword sum of the buffer now
	cmp	edx, dword ptr [V_SLOTS + di + 4]
	je	chk_poison
	mov	si, offset s_what_sum
	call	stalemsg
chk_poison:
	call	poison_slot
	mov	dword ptr [V_SLOTS + di + 8], 2
	jmp	chk_skip
chk_canary:
	call	canary_ok			# ZF set: all canary
	je	chk_skip
	mov	si, offset s_what_canary
	call	stalemsg
	call	poison_slot			# one report per late write
chk_skip:
	inc	ebx
	cmp	ebx, 3
	jb	chk_next
	ret

# ebx = slot, di = table offset: edx = the dword sum of the slot's buffer
sumslot:
	push	ds
	push	si
	push	ecx
	push	eax
	mov	ecx, dword ptr [V_SLOTS + di]
	mov	eax, ebx
	call	slotseg
	mov	ds, ax
	xor	si, si
	xor	edx, edx
1:	lodsd
	add	edx, eax
	loop	1b
	pop	eax
	pop	ecx
	pop	si
	pop	ds
	ret

# ebx = slot, di = table offset: overwrite the buffer with the canary
poison_slot:
	push	es
	push	di
	push	ecx
	push	eax
	mov	ecx, dword ptr [V_SLOTS + di]
	mov	eax, ebx
	call	slotseg
	mov	es, ax
	xor	di, di
	mov	eax, CANARY
	rep	stosd
	pop	eax
	pop	ecx
	pop	di
	pop	es
	ret

# ebx = slot, di = table offset: ZF set when the whole buffer is still canary
canary_ok:
	push	es
	push	di
	push	ecx
	push	eax
	mov	ecx, dword ptr [V_SLOTS + di]
	mov	eax, ebx
	call	slotseg
	mov	es, ax
	xor	di, di
	mov	eax, CANARY
	repe	scasd
	pop	eax
	pop	ecx
	pop	di
	pop	es
	ret

# a stale-buffer line: ebx = slot, di = table offset, si = what
stalemsg:
	push	si
	inc	dword ptr [V_STALE]
	mov	si, offset s_stale_l
	call	puts
	mov	eax, ebx
	call	putdec
	mov	si, offset s_lba
	call	puts
	mov	eax, dword ptr [V_SLOTS + di + 12]
	call	putdec
	mov	si, offset s_what
	call	puts
	pop	si
	call	puts
	call	putcrlf
	ret

progress:
	mov	si, offset s_prog
	call	puts
	mov	eax, dword ptr [V_LBA]
	call	putdec
	mov	si, offset s_h
	call	puts
	mov	eax, dword ptr [V_H]
	call	puthex32
	call	putmax
	call	putrtc
	mov	si, offset s_errs
	call	puts
	mov	eax, dword ptr [V_ERRS]
	call	putdec
	mov	si, offset s_stale
	call	puts
	mov	eax, dword ptr [V_STALE]
	call	putdec
	call	putcrlf
	ret

putmax:
	mov	si, offset s_maxt
	call	puts
	mov	eax, dword ptr [V_MAXT]
	call	putdec
	mov	al, '@'
	call	putc
	mov	eax, dword ptr [V_MAXLBA]
	call	putdec
	ret

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

# " rtc=HHMMSS" from the CMOS clock (BCD)
putrtc:
	push	ax
	mov	si, offset s_rtc
	call	puts
	mov	al, 4
	out	0x70, al
	in	al, 0x71
	call	puthex8
	mov	al, 2
	out	0x70, al
	in	al, 0x71
	call	puthex8
	mov	al, 0
	out	0x70, al
	in	al, 0x71
	call	puthex8
	pop	ax
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
	add	al, 7
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

chunks:		.byte	127, 64, 33, 8, 1, 100, 17, 127
tries:		.byte	0
lasterr:	.byte	0
endflag:	.byte	0

s_start:	.asciz	"WRRB-START drive="
s_first:	.asciz	" first="
s_sectors:	.asciz	" sectors="
s_prog:		.asciz	"WRRB-PROG lba="
s_h:		.asciz	" h="
s_maxt:		.asciz	" maxticks="
s_rtc:		.asciz	" rtc="
s_errs:		.asciz	" errs="
s_stale:	.asciz	" stale="
s_err:		.asciz	"WRRB-ERR ah="
s_errlba:	.asciz	" lba="
s_errtry:	.asciz	" try="
s_stale_l:	.asciz	"WRRB-STALE slot="
s_lba:		.asciz	" lba="
s_what:		.asciz	" what="
s_what_sum:	.asciz	"sum"
s_what_canary:	.asciz	"canary"
s_done:		.asciz	"WRRB-DONE sectors="
s_end:		.asciz	" end="
s_ok:		.asciz	"ok"
s_bad:		.asciz	"err"

	.org	4096
