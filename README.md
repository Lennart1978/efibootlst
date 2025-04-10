# efibootlst
### List all UEFI Boot entries

Compile: (needs efivar devel package)
```bash
gcc -s -O3 efibootlst.c -o efibootlst -lefivar
```
Run:
```bash
./efibootlst
```
**There is a compiled binary for Linux x86_64 (efibootlst)**


Example output:(I only have one boot entry)

```bash
EFI Boot Entries:

Boot Order: 0000

=== Boot Entry: Boot0000 ===
Status: Active
Name: Systemd-boot
Device path: 
Raw Device Path Data (Size: 116 Bytes):
04 01 2a 00 01 00 00 00 00 08 00 00 00 00 00 00 
00 00 10 00 00 00 00 00 f8 48 1f ef 82 0f 24 49 
a3 1f bf 79 d8 bc 4c 7b 02 02 04 04 46 00 5c 00 
45 00 46 00 49 00 5c 00 53 00 59 00 53 00 54 00 
45 00 4d 00 44 00 5c 00 53 00 59 00 53 00 54 00 
45 00 4d 00 44 00 2d 00 42 00 4f 00 4f 00 54 00 
58 00 36 00 34 00 2e 00 45 00 46 00 49 00 00 00 
7f ff 04 00 
Parsed: HD(Part=1,SigType=2,Sig=ef1f48f8-0f82-4924-a31f-bf79d8bc4c7b,Format=GPT)/File(\EFI\SYSTEMD\SYSTEMD-BOOTX64.EFI)/End(Entire)
```

