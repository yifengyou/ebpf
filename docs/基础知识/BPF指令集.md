<!-- TOC -->

- [BPF指令集](#bpf指令集)
  - [基本内容](#基本内容)
  - [BPF_LD加载指令](#bpf_ld加载指令)
  - [BPF_LDX 加载指令](#bpf_ldx-加载指令)
  - [BPF_ST存储指令](#bpf_st存储指令)
  - [BPF_STX存储指令](#bpf_stx存储指令)
  - [BPF_ALU计算指令](#bpf_alu计算指令)
  - [BPF_JMP跳转指令](#bpf_jmp跳转指令)
  - [BPF_RET返回指令](#bpf_ret返回指令)
  - [BPF_MISC其他指令](#bpf_misc其他指令)
  - [参考](#参考)

<!-- /TOC -->
# BPF指令集

## 基本内容

* BPF 是一个通用目的 RISC 指令集，其最初的设计目标是：
* 用 C 语言的一个子集编写程序，然后用一个编译器后端（例如 LLVM）将其编译成 BPF 指令，
* 内核再通过一个位于内核中的（in-kernel）即时编译器（JIT Compiler） 将 BPF 指令映射成处理器的原生指令（opcode ），以获得在内核中的最佳执行性能。
* BPF一共有8种类型的指令，分别是 BPF_LD, BPF_LDX, BPF_ST, BPF_STX, BPF_ALU, BPF_JMP, BPF_RET, BPF_MISC
* 一条bpf的指令包括：8字节长

```
struct bpf_insn {
    __u8    code;       /* opcode */
    __u8    dst_reg:4;  /* dest register */
    __u8    src_reg:4;  /* source register */
    __s16   off;        /* signed offset */
    __s32   imm;        /* signed immediate constant */
};
```
* 所有的eBPF汇编在内核中定义为一个```struct bpf_insn```，一般将连续的指令布置成一个结构体数组```struct bpf_insn insn[]={}```
* 其中操作码共8位，开头0,1,2这三位表示的是该操作的大类别

| 7   | 6   | 5   | 4   | 3   | 2   | 1   | 0   |
| --- | --- | --- | --- | --- | --- | --- | --- |
|     |     |     |     |     | X   | X   | X   |

* BPF_LD(0x00) / BPF_LDX(0x01) / BPF_ST(0x02) /BPF_STX(0x03) / BPF_ALU(0x04) / BPF_JMP(0x05) / BPF_RET(0x06) / BPT_MISC(0x07)
* BPF 程序在内核中的执行总是事件驱动的
* LLVM 是唯一提供 BPF 后端的编译器套件。gcc 目前还不支持
* BPF虚拟机组成：11个64位寄存器，PC指令指针寄存器，BPF栈空间512字节
* 寄存器的名字从 r0 到 r10。默认的运行模式是 64 位，32 位子寄存器只能 通过特殊的 ALU（arithmetic logic unit）访问。向 32 位子寄存器写入时，会用 0 填充 到 64 位。
* BPF 程序可以调用核心内核（而不是内核模块）预定义的一些辅助函数。BPF 调用约定 定义如下：

```
r0 存放被调用的辅助函数的返回值
r1 - r5 存放 BPF 调用内核辅助函数时传递的参数
r6 - r9 由被调用方（callee）保存，在函数返回之后调用方（caller）可以读取
```

* eBPF汇编中有r0至r10一共11个寄存器，作用如下：

```
R0（rax），函数返回值
R1（rdi），arg1
R2（rsi），arg2
R3（rdx），arg3
R4（rcx），arg4
R5（r8），arg5
R6（rbx），callee保存
R7（r13），callee保存
R8（r14），callee保存
R9（r15），callee保存
R10（rbp），栈帧寄存器
```

* BPF 调用约定足够通用，能够直接映射到 x86_64、arm64 和其他 ABI，因此所有 的 BPF 寄存器可以一一映射到硬件 CPU 寄存器
* 每个 BPF 程序的最大指令数限制在 4096 条以内，这意味着从设计上就可以保证每 个程序都会很快结束。对于内核 5.1+，这个限制放大到了 100 万条。
* BPF指令格式

```
op:8, dst_reg:4, src_reg:4, off:16, imm:32
```

* r0 寄存器还用于保存 BPF 程序的退出值。退出值的语义由程序类型决定。另外， 当将执行权交回内核时，退出值是以 32 位传递的。
* r1 - r5 寄存器是 scratch registers，意思是说，如果要在多次辅助函数调用之 间重用这些寄存器内的值，那 BPF 程序需要负责将这些值临时转储（spill）到 BPF 栈上 ，或者保存到被调用方（callee）保存的寄存器中。
* r1 寄存器中存放的是程序的上下文（context）。上下文就是 程序的输入参数（和典型 C 程序的 argc/argv 类似）
* BPF 基于寄存器的虚拟机，区别于基于栈的虚拟机




## BPF_LD加载指令

将值复制到累加器

```
BPF_STMT(BPF_LD | BPF_W | BPF_ABS, k)   A <- P[k:4]     // 将k字节偏移处往后4个字节存入A中
BPF_STMT(BPF_LD | BPF_H | BPF_ABS, k)   A <- P[k:2]     // 将k字节偏移处往后2个字节存入A中
BPF_STMT(BPF_LD | BPF_B | BPF_ABS, k)   A <- P[k:1]     // 将k字节偏移处往后1个字节存入A中
BPF_STMT(BPF_LD | BPF_W | BPF_IND, k)   A <- P[X+k:4]   // 将(X寄存器值与k的和)偏移处往后4个字节存入A中
BPF_STMT(BPF_LD | BPF_H | BPF_IND, k)   A <- P[X+k:2]   // 将(X寄存器值与k的和)偏移处往后2个字节存入A中
BPF_STMT(BPF_LD | BPF_B | BPF_IND, k)   A <- P[X+k:1]   // 将(X寄存器值与k的和)偏移处往后1个字节存入A中
BPF_STMT(BPF_LD | BPF_W | BPF_LEN)      A <- len        // 将包长度存存入A中
BPF_STMT(BPF_LD | BPF_IMM, k)           A <- k          // 将k值存入A中
BPF_STMT(BPF_LD | BPF_MEM, k)           A <- M[k]       // 将k地址内存的值存入A中
```

## BPF_LDX 加载指令

将值复制到寄存器

```
BPF_STMT(BPF_LDX | BPF_W | BPF_IMM, k)  X <- k              // 将k值存入X中
BPF_STMT(BPF_LDX | BPF_W | BPF_MEM, k)  X <- M[k]           // 将k地址内存的值存入X中
BPF_STMT(BPF_LDX | BPF_W | BPF_LEN, k)  X <- len            // 将包长度存入X中
BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, k)  X <- 4*(P[k:1]&0xf) // 用于计算ip头的长度 --->
                                        // ---> 将偏移k处一个字节后4位转换成十进制乘以4
```

## BPF_ST存储指令

将A累加器中的值存入存储器中

```
BPF_STMT(BPF_ST, k)                     M[k] <- X       // 将A中的值存入存储器中
```


## BPF_STX存储指令

将X寄存器中的值存入存储器中

```
BPF_STMT(BPF_ST, k)                     M[k] <- X       // 将X中的值存入存储器中
```


## BPF_ALU计算指令

将A累加器中的值进行不同方式的计算并存入A中

```
BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, k)  A <- A + k      // A + k 后存入A中
BPF_STMT(BPF_ALU | BPF_SUB | BPF_K, k)  A <- A - k      // ..
BPF_STMT(BPF_ALU | BPF_MUL | BPF_K, k)  A <- A * k      
BPF_STMT(BPF_ALU | BPF_DIV | BPF_K, k)  A <- A / k
BPF_STMT(BPF_ALU | BPF_AND | BPF_K, k)  A <- A & k
BPF_STMT(BPF_ALU | BPF_OR | BPF_K, k)   A <- A | k
BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, k)  A <- A << k
BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, k)  A <- A >> k
BPF_STMT(BPF_ALU | BPF_ADD | BPF_X)     A <- A + X
BPF_STMT(BPF_ALU | BPF_SUB | BPF_X)     A <- A - X
BPF_STMT(BPF_ALU | BPF_MUL | BPF_X)     A <- A * X
BPF_STMT(BPF_ALU | BPF_DIV | BPF_X)     A <- A / X
BPF_STMT(BPF_ALU | BPF_AND | BPF_X)     A <- A & X
BPF_STMT(BPF_ALU | BPF_OR | BPF_X)      A <- A | X
BPF_STMT(BPF_ALU | BPF_LSH | BPF_X)     A <- A << X
BPF_STMT(BPF_ALU | BPF_RSH | BPF_X)     A <- A >> X
BPF_STMT(BPF_ALU | BPF_NEG)             A <- -A
```

## BPF_JMP跳转指令

条件跳转，根据条件跳转到不同偏移的命令

```
BPF_JUMP(BPF_JMP | BPF_JA, k)           pc += k         // 永远跳转到这条命令后偏移k的命令
// 如果A>k，则跳转到偏移jt的命令，否则跳转到偏移为jf的命令  
BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, k)  pc += (A > k) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, k)  pc += (A >= k) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, k)  pc += (A == k) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, k) pc += (A & k) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JGT | BPF_X)     pc += (A > X) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X)     pc += (A >= X) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_X)     pc += (A == X) ? jt : jf
BPF_JUMP(BPF_JMP | BPF_JSET | BPF_X)    pc += (A & X) ? jt : jf
```

## BPF_RET返回指令

结束指令，设定接收的包的长度

```
BPF_STMT(BPF_RET | BPF_A),                          // 接收长度为A累加器值的包
BPF_STMT(BPF_RET | BPF_K, k)                        // 接收长度为k的包
```

## BPF_MISC其他指令

将A中的值存入X中，或将X中的值存入A中

```
BPF_STMT(BPF_MISC | BPF_TAX)                X <- A      // 将A中的值存入X中
BPF_STMT(BPF_MISC | BPF_TXA)                A <- X      // 将X中的值存入A中
```

使用BPF_LD和BPF_LDX将k值存入A或者X中，使用BPF_JUMP将A中的值与k或者X进行比较，实现指令跳转，
可以跳转到下一步的过滤指令，或者跳转到BPF_RET进行截取包长度的限定，如果截取包的长度为0，则代表未匹配。



## 参考

* <https://arthurchiao.art/blog/cilium-bpf-xdp-reference-guide-zh/#111-%E6%8C%87%E4%BB%A4%E9%9B%86>
* <https://www.kernel.org/doc/Documentation/networking/filter.txt>
* <https://github.com/iovisor/bpf-docs/blob/master/eBPF.md>





---
