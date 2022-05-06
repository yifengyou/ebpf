# elf-ebpf解析


## 帮助信息

```
OVERVIEW: llvm object file dumper

USAGE: llvm-objdump [options] <input object files>

OPTIONS:

Generic Options:

  --help                           - Display available options (--help-hidden for more)
  --help-list                      - Display list of available options (--help-list-hidden for more)
  --version                        - Display the version of this program

llvm-objdump MachO Specific Options:

  --arch=<string>                  - architecture(s) from a Mach-O file to dump
  --archive-member-offsets         - Print the offset to each archive member for Mach-O archives (requires --macho and --archive-headers)
  --bind                           - Display mach-o binding info
  --data-in-code                   - Print the data in code table for Mach-O objects (requires --macho)
  --dis-symname=<string>           - disassemble just this symbol's instructions (requires --macho)
  --dsym=<string>                  - Use .dSYM file for debug info
  --dylib-id                       - Print the shared library's id for the dylib Mach-O file (requires --macho)
  --dylibs-used                    - Print the shared libraries used for linked Mach-O files (requires --macho)
  --exports-trie                   - Display mach-o exported symbols
  --full-leading-addr              - Print full leading address
  -g                               - Print line information from debug info if available
  --indirect-symbols               - Print indirect symbol table for Mach-O objects (requires --macho)
  --info-plist                     - Print the info plist section as strings for Mach-O objects (requires --macho)
  --lazy-bind                      - Display mach-o lazy binding info
  --link-opt-hints                 - Print the linker optimization hints for Mach-O objects (requires --macho)
  --no-leading-headers             - Print no leading headers
  --no-symbolic-operands           - do not symbolic operands when disassembling (requires --macho)
  --non-verbose                    - Print the info for Mach-O objects in non-verbose or numeric form (requires --macho)
  --objc-meta-data                 - Print the Objective-C runtime meta data for Mach-O files (requires --macho)
  --private-header                 - Display only the first format specific file header
  --rebase                         - Display mach-o rebasing info
  --universal-headers              - Print Mach-O universal headers (requires --macho)
  --weak-bind                      - Display mach-o weak binding info

llvm-objdump Options:

  -C                               - Alias for --demangle # Demangle解构，还原函数
  -D                               - Alias for --disassemble-all
  -M                               - Alias for --disassembler-options
  -R                               - Alias for --dynamic-reloc
  -S                               - Alias for --source
  -T                               - Alias for --dynamic-syms
  -a                               - Alias for --archive-headers
  --adjust-vma=<offset>            - Increase the displayed address by the specified offset
  --all-headers                    - Display all available header information
  --arch-name=<string>             - Target arch to disassemble for, see --version for available targets
  --archive-headers                - Display archive header information
  -d                               - Alias for --disassemble
  --debug-vars                     - Print the locations (in registers or memory) of source-level variables alongside disassembly
  --debug-vars=<value>             - Print the locations (in registers or memory) of source-level variables alongside disassembly
    =<empty>                       -   unicode
    =unicode                       -   unicode
    =ascii                         -   unicode
  --debug-vars-indent=<int>        - Distance to indent the source-level variable display, relative to the start of the disassembly
  --demangle                       - Demangle symbols names # Demangle解构，还原函数
  --disassemble                    - Display assembler mnemonics for the machine instructions
  --disassemble-all                - Display assembler mnemonics for the machine instructions
  --disassemble-symbols=<string>   - List of symbols to disassemble. Accept demangled names when --demangle is specified, otherwise accept mangled names
  --disassemble-zeroes             - Do not skip blocks of zeroes when disassembling
  --disassembler-options=<options> - Pass target specific disassembler options
  --dwarf=<value>                  - Dump of dwarf debug sections:
    =frames                        -   .debug_frame
  --dynamic-reloc                  - Display the dynamic relocation entries in the file
  --dynamic-syms                   - Display the contents of the dynamic symbol table
  -f                               - Alias for --file-headers
  --fault-map-section              - Display contents of faultmap section
  --file-headers                   - Display the contents of the overall file header
  --full-contents                  - Display the content of each section
  -h                               - Alias for --section-headers
  --headers                        - Alias for --section-headers
  -j                               - Alias for --section
  -l                               - Alias for --line-numbers
  --line-numbers                   - Display source line numbers with disassembly. Implies disassemble object
  -m                               - Alias for --macho
  --macho                          - Use MachO specific object file parser
  --mattr=<a1,+a2,-a3,...>         - Target specific attributes (--mattr=help for details)
  --mcpu=<cpu-name>                - Target a specific cpu type (--mcpu=help for details)
  --no-leading-addr                - Print no leading address
  --no-show-raw-insn               - When disassembling instructions, do not print the instruction bytes.
  -p                               - Alias for --private-headers
  --prefix=<string>                - Add prefix to absolute paths
  --print-imm-hex                  - Use hex format for immediate values
  --private-headers                - Display format specific file headers
  -r                               - Alias for --reloc
  --raw-clang-ast                  - Dump the raw binary contents of the clang AST section
  --reloc                          - Display the relocation entries in the file
  -s                               - Alias for --full-contents
  --section=<string>               - Operate on the specified sections only. With --macho dump segment,section
  --section-headers                - Display summaries of the headers for each section.
  --show-lma                       - Display LMA column when dumping ELF section headers
  --source                         - Display source inlined with disassembly. Implies disassemble object
  --start-address=<address>        - Disassemble beginning at address
  --stop-address=<address>         - Stop disassembly at address
  --symbol-description             - Add symbol description for disassembly. This option is for XCOFF files only
  --symbolize-operands             - Symbolize instruction operands when disassembling
  --syms                           - Display the symbol table
  -t                               - Alias for --syms
  --triple=<string>                - Target triple to disassemble for, see --version for available targets
  -u                               - Alias for --unwind-info
  --unwind-info                    - Display unwind information
  --wide                           - Ignored for compatibility with GNU objdump
  -x                               - Alias for --all-headers
  -z                               - Alias for --disassemble-zeroes

Pass @FILE as argument to read options from FILE.
```





















## 获取所有节信息

```
[root@rockylinux-ebpf ~/goebpf.git/examples/xdp/basic_firewall/ebpf_prog]# llvm-objdump -D -C xdp_fw.elf

xdp_fw.elf:	file format elf64-bpf


Disassembly of section .strtab:

0000000000000000 <.strtab>:
       0:	00 2e 74 65 78 74 00 62	<unknown>
       1:	6c 61 63 6b 6c 69 73 74	w1 <<= w6
       2:	00 6d 61 70 73 00 6d 61	<unknown>
       3:	74 63 68 65 73 00 2e 72	w3 >>= 1915617395
       4:	65 6c 78 64 70 00 66 69	<unknown>
       5:	72 65 77 61 6c 6c 00 2e	<unknown>
       6:	6c 6c 76 6d 5f 61 64 64	<unknown>
       7:	72 73 69 67 00 5f 6c 69	<unknown>
       8:	63 65 6e 73 65 00 78 64	*(u32 *)(r5 + 29550) = r6
       9:	70 5f 66 77 2e 63 00 2e	<unknown>
      10:	73 74 72 74 61 62 00 2e	*(u8 *)(r4 + 29810) = r7
      11:	73 79 6d 74 61 62 00 4c	*(u8 *)(r9 + 29805) = r7
      12:	42 42 30 5f 37 00 4c 42	<unknown>
      13:	42	<unknown>
      13:	30	<unknown>
      13:	5f	<unknown>
      13:	36	<unknown>
      13:	00	<unknown>

Disassembly of section xdp:

0000000000000000 <firewall>:
       0:	b7 00 00 00 00 00 00 00	r0 = 0
       1:	61 12 04 00 00 00 00 00	r2 = *(u32 *)(r1 + 4)
       2:	61 11 00 00 00 00 00 00	r1 = *(u32 *)(r1 + 0)
       3:	bf 13 00 00 00 00 00 00	r3 = r1
       4:	07 03 00 00 0e 00 00 00	r3 += 14
       5:	2d 23 2b 00 00 00 00 00	if r3 > r2 goto +43 <LBB0_7>
       6:	71 13 0c 00 00 00 00 00	r3 = *(u8 *)(r1 + 12)
       7:	71 14 0d 00 00 00 00 00	r4 = *(u8 *)(r1 + 13)
       8:	67 04 00 00 08 00 00 00	r4 <<= 8
       9:	4f 34 00 00 00 00 00 00	r4 |= r3
      10:	b7 00 00 00 02 00 00 00	r0 = 2
      11:	55 04 25 00 08 00 00 00	if r4 != 8 goto +37 <LBB0_7>
      12:	bf 13 00 00 00 00 00 00	r3 = r1
      13:	07 03 00 00 22 00 00 00	r3 += 34
      14:	b7 00 00 00 00 00 00 00	r0 = 0
      15:	2d 23 21 00 00 00 00 00	if r3 > r2 goto +33 <LBB0_7>
      16:	b7 02 00 00 20 00 00 00	r2 = 32
      17:	63 2a f8 ff 00 00 00 00	*(u32 *)(r10 - 8) = r2
      18:	71 12 1b 00 00 00 00 00	r2 = *(u8 *)(r1 + 27)
      19:	67 02 00 00 08 00 00 00	r2 <<= 8
      20:	71 13 1a 00 00 00 00 00	r3 = *(u8 *)(r1 + 26)
      21:	4f 32 00 00 00 00 00 00	r2 |= r3
      22:	71 13 1c 00 00 00 00 00	r3 = *(u8 *)(r1 + 28)
      23:	71 11 1d 00 00 00 00 00	r1 = *(u8 *)(r1 + 29)
      24:	67 01 00 00 08 00 00 00	r1 <<= 8
      25:	4f 31 00 00 00 00 00 00	r1 |= r3
      26:	67 01 00 00 10 00 00 00	r1 <<= 16
      27:	4f 21 00 00 00 00 00 00	r1 |= r2
      28:	63 1a fc ff 00 00 00 00	*(u32 *)(r10 - 4) = r1
      29:	bf a2 00 00 00 00 00 00	r2 = r10
      30:	07 02 00 00 f8 ff ff ff	r2 += -8
      31:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0 ll
      33:	85 00 00 00 01 00 00 00	call 1
      34:	bf 01 00 00 00 00 00 00	r1 = r0
      35:	b7 00 00 00 02 00 00 00	r0 = 2
      36:	15 01 0c 00 00 00 00 00	if r1 == 0 goto +12 <LBB0_7>
      37:	61 11 00 00 00 00 00 00	r1 = *(u32 *)(r1 + 0)
      38:	63 1a f4 ff 00 00 00 00	*(u32 *)(r10 - 12) = r1
      39:	bf a2 00 00 00 00 00 00	r2 = r10
      40:	07 02 00 00 f4 ff ff ff	r2 += -12
      41:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0 ll
      43:	85 00 00 00 01 00 00 00	call 1
      44:	15 00 03 00 00 00 00 00	if r0 == 0 goto +3 <LBB0_6>
      45:	79 01 00 00 00 00 00 00	r1 = *(u64 *)(r0 + 0)
      46:	07 01 00 00 01 00 00 00	r1 += 1
      47:	7b 10 00 00 00 00 00 00	*(u64 *)(r0 + 0) = r1

0000000000000180 <LBB0_6>:
      48:	b7 00 00 00 01 00 00 00	r0 = 1

0000000000000188 <LBB0_7>:
      49:	95 00 00 00 00 00 00 00	exit

Disassembly of section .relxdp:

0000000000000000 <.relxdp>:
       0:	f8 00 00 00 00 00 00 00	<unknown>
       1:	01 00 00 00 05 00 00 00	<unknown>
       2:	48 01 00 00 00 00 00 00	r0 = *(u16 *)skb[r0]
       3:	01 00 00 00 07 00 00 00	<unknown>

Disassembly of section maps:

0000000000000000 <matches>:
       0:	06 00 00 00 04 00 00 00	<unknown>
       1:	08 00 00 00 10 00 00 00	<unknown>
		...

0000000000000028 <blacklist>:
       5:	0b 00 00 00 08 00 00 00	<unknown>
       6:	04 00 00 00 10 00 00 00	w0 += 16
		...

Disassembly of section license:

0000000000000000 <_license>:
       0:	47	<unknown>
       0:	50	<unknown>
       0:	4c	<unknown>
       0:	76	<unknown>
       0:	32	<unknown>
       0:	00	<unknown>

Disassembly of section .llvm_addrsig:

0000000000000000 <.llvm_addrsig>:
       0:	06	<unknown>
       0:	07	<unknown>
       0:	05	<unknown>
       0:	04	<unknown>

Disassembly of section .symtab:

0000000000000000 <.symtab>:
		...
       3:	46 00 00 00 04 00 f1 ff	<unknown>
		...
       6:	66 00 00 00 00 00 03 00	if w0 s> 196608 goto +0 <.symtab+0x38>
       7:	80 01 00 00 00 00 00 00	<unknown>
		...
       9:	5f 00 00 00 00 00 03 00	r0 &= r0
      10:	88 01 00 00 00 00 00 00	<unknown>
		...
      12:	3d 00 00 00 11 00 06 00	if r0 >= r0 goto +0 <.symtab+0x68>
		...
      14:	06 00 00 00 00 00 00 00	<unknown>
      15:	07 00 00 00 11 00 05 00	r0 += 327697
      16:	28 00 00 00 00 00 00 00	r0 = *(u16 *)skb[0]
      17:	28 00 00 00 00 00 00 00	r0 = *(u16 *)skb[0]
      18:	26 00 00 00 12 00 03 00	if w0 > 196626 goto +0 <.symtab+0x98>
		...
      20:	90 01 00 00 00 00 00 00	<unknown>
      21:	16 00 00 00 11 00 05 00	if w0 == 327697 goto +0 <.symtab+0xb0>
		...
      23:	28 00 00 00 00 00 00 00	r0 = *(u16 *)skb[0]

```


---
