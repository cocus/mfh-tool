# mfh-tool
Tool to read and hopefully modify the mfh block on Intel CE SoCs, like the CE2600.

Ideally it could be compiled statically so it can be executed under the original SoC firmware, allowing users to change the "user script", or changing the "boot delay" of the bootloader.

Because only the "header" blocks are signed (but not its contets, *facepalm*), it's certainly possible to change what's stored on them.

This is important because if it's set to a 0s delay (as I've seen in at least ONE firmware), it won't let you stop the auto-boot process, even if constantly sending characters through the serial port.


# How to use
This requires gcc and make (and optionally openssl).

Run `make` to compile.

Extract a full memory dump (or at least, the region that contains the full MFH) from your device.

> **_NOTE:_** Only eMMC has been validated, where the MFH block starts at `0x8000`. SPI could be supported given a full dump is available to inspect.

Run the app as follows: `./mfh-tool your-dump.bin`.

# What it can extract as of now
Right now, it can parse the MFH block headers, validate the signature, iterate through every flash item struct, and extract the "user script" from it.

# Example
This comes from a memory dump of a device I currently use to debug my ongoing OpenWRT port, so the "user script" is different than what it came with originally.


```
$ ./mfh-tool dpc3848.bin
MFH Blocks, items = 4:
   Version      Flags NextHdrBlk FI BP Sign
0x00000001 0x00000000 0x00280200 11 01 OK 
0x00000001 0x00000000 0x00280400 00 00 OK 
0x00000001 0x00000000 0x00280600 00 00 OK 
0x00000001 0x00000000 0x00000000 00 00 OK 
===========
Now going to process each block's contents:
===========
MFH Block 0, boot priority items = 1
MFH Block 0, boot priority item 0, value = 0x00000000
===========
MFH Block 0, items = 11
Type Label                 Type ID      Flags     Offset       Size
cefdk_s1             0x00000000 00 0x80000000 0x00280800 0x00010000
cefdk_s1h            0x00000001 00 0x80000000 0x002ff800 0x00000800
user flash           0xffffffff 00 0x00000000 0x00400000 0x00000000
cefdk_s2             0x00000002 00 0x80000000 0x00290800 0x00009400
cefdk_s3             0x00000016 00 0x80000000 0x00299c00 0x00065400
cefdk_s3h            0x00000017 00 0x80000000 0x002ff000 0x00000800
cefdk_s2h            0x00000003 00 0x80000000 0x00300000 0x00000800
plat_params          0x00000005 00 0x80000000 0x00300800 0x00010000
ip_params            0x00000012 00 0x80000000 0x00310800 0x00000010
script               0x00000015 00 0x80000000 0x00310c70 0x00000800
===========
MFH Block 0, 'script':
 line 0 => 'tftp get 192.168.100.8 0x200000 bzImage' (len = 39)
 line 1 => 'bootkernel -b 0x200000 "earlyprintk=intelce console=uart,mmio32,0xdffe0200 panic=2 rootdelay=2 pci=nocrs root=/dev/sda1"' (len = 120)
 line 2 => 'load -m 0x200000 -s 0x6B00000 -l 0x560000 -t emmc' (len = 49)
 line 3 => 'bootkernel -b 0x200000 "earlyprintk=intelce console=uart,mmio32,0xdffe0200 panic=2 rootdelay=2 pci=nocrs root=/dev/sda1"' (len = 120)
 script uses 332 bytes out of 2048
===========
cefdk_params         0x00000004 00 0x80000000 0x00311600 0x00000465
```
