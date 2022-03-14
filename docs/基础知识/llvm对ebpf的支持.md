# llvm对ebpf的支持

* BPF 的编译离不开 LLVM，LLVM 分为前端和后端
* 可以使用 clang 将 BPF 编译为 LLVM IR 文件，LLVM 当前已经支持 BPF 作为目标文件，因此我们可以将任何的 LLVM IR 编译为 BPF 目标文件
* 默认情况下，代码位于 ELF 的```.text```区域section
* 默认只是生成了bpf代码，少不了一个loader，loader负责加载bpf code到内核中，此处毫无疑问就是用户态拷贝数据到内核态

## 举栗子


### 最简单例子

```
cat bpf.c
int func() {
    return 0;
}
```

```
clang -target bpf -Wall -O2 -o bpf.o -c bpf.c
```


```
[root@rockylinux ~/cilium_ebpf.git/examples/test2]# llvm-objdump -d -a bpf.o

bpf.o:	file format elf64-bpf


Disassembly of section .text:

0000000000000000 <func>:
       0:	b7 00 00 00 00 00 00 00	r0 = 0
       1:	95 00 00 00 00 00 00 00	exit

```


### 统计sys_execve执行次数

```
// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};

SEC("kprobe/sys_execve")
int kprobe_execve() {
    u32 key = 0;
    u64 initval = 1, *valp;

    valp = bpf_map_lookup_elem(&kprobe_map, &key);
    if (!valp) {
        bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);

    return 0;
}
```

```
[root@rockylinux ~/cilium_ebpf.git/examples/test/kprobe]# llvm-objdump -d -a bpf_bpfel.o

bpf_bpfel.o:	file format elf64-bpf


Disassembly of section kprobe/sys_execve:

0000000000000000 <kprobe_execve>:
       0:	b7 01 00 00 00 00 00 00	r1 = 0
       1:	63 1a fc ff 00 00 00 00	*(u32 *)(r10 - 4) = r1
       2:	b7 06 00 00 01 00 00 00	r6 = 1
       3:	7b 6a f0 ff 00 00 00 00	*(u64 *)(r10 - 16) = r6
       4:	bf a2 00 00 00 00 00 00	r2 = r10
       5:	07 02 00 00 fc ff ff ff	r2 += -4
       6:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0 ll
       8:	85 00 00 00 01 00 00 00	call 1
       9:	55 00 09 00 00 00 00 00	if r0 != 0 goto +9 <LBB0_2>
      10:	bf a2 00 00 00 00 00 00	r2 = r10
      11:	07 02 00 00 fc ff ff ff	r2 += -4
      12:	bf a3 00 00 00 00 00 00	r3 = r10
      13:	07 03 00 00 f0 ff ff ff	r3 += -16
      14:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0 ll
      16:	b7 04 00 00 00 00 00 00	r4 = 0
      17:	85 00 00 00 02 00 00 00	call 2
      18:	05 00 01 00 00 00 00 00	goto +1 <LBB0_3>

0000000000000098 <LBB0_2>:
      19:	db 60 00 00 00 00 00 00	lock *(u64 *)(r0 + 0) += r6

00000000000000a0 <LBB0_3>:
      20:	b7 00 00 00 00 00 00 00	r0 = 0
      21:	95 00 00 00 00 00 00 00	exit
```









## 参考

* <https://www.kernel.org/doc/Documentation/networking/filter.txt>
* <https://github.com/iovisor/bpf-docs/blob/master/eBPF.md>
* <https://arthurchiao.art/blog/ebpf-assembly-with-llvm-zh/>










---
