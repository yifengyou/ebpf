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

* 其中操作码共8位，开头0,1,2这三位表示的是该操作的大类别

| 7   | 6   | 5   | 4   | 3   | 2   | 1   | 0   |
| --- | --- | --- | --- | --- | --- | --- | --- |
|     |     |     |     |     | X   | X   | X   |

* BPF_LD(0x00) / BPF_LDX(0x01) / BPF_ST(0x02) /BPF_STX(0x03) / BPF_ALU(0x04) / BPF_JMP(0x05) / BPF_RET(0x06) / BPT_MISC(0x07)
* BPF 程序在内核中的执行总是事件驱动的
* LLVM 是唯一提供 BPF 后端的编译器套件。gcc 目前还不支持


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





---
