# tailts start epoch=1795464121.652
8.704 iPXE initialising devices...
8.766 
8.766 
8.786 
8.828 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.849 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.869 WRRUN-STUB
12.483 Configuring (net0 52:54:00:77:12:cb)...... ok
12.903 tftp://10.77.0.10/autoexec.ipxe... ok
12.924 WRRUN-BEGIN row=B1-NEG
12.965 Waiting for link-up on net0... ok
13.007 WRRUN-NET-OK
13.048 WRRUN-SAN-START sanboot
13.239 rbd: stack monitor: the stack is not iPXE's own (frame 0x7fe8edd8, internal stack 0xffffffffeb464660 to 0xffffffffeb466660): not painted
14.019 rbd: DIAG esp 7fe8edd0 frame 7fe8edd8 _stack ffffffffeb464660 _estack ffffffffeb466660 phys(frame) 7fe8edd8 phys(_stack) 7fe8d660 phys(_estack) 7fe8f660 virt_offset 0
34.249 rbd: open failed: server refused the offered authentication method or mode (WR_E_M2_BAD_METHOD)
34.290 Could not open SAN device: Error 0x43766001 (https://ipxe.org/43766001)
34.311 WRRUN-SAN-FAILED 0x43766001
34.332 WRRUN-FAIL
34.352 WRRUN-END
