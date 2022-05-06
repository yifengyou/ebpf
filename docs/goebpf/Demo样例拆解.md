# Demo样例拆解

## 先甩一堆源码

```
// Copyright (c) 2020 Dropbox, Inc.
// Full license can be found in the LICENSE file.

#include "bpf_helpers.h"

#define BUFSIZE_PADDED (2 << 13)
#define BUFSIZE ((BUFSIZE_PADDED - 1) >> 1)
#define MAX_ARGLEN 256
#define MAX_ARGS 20
#define NARGS 6
#define NULL ((void *)0)
#define TASK_COMM_LEN 32

typedef unsigned long args_t;

typedef struct event {
  __u64 ktime_ns;
  __u32 pid;
  __u32 uid;
  __u32 gid;
  __s32 type;
  char comm[TASK_COMM_LEN];
} event_t;

typedef struct buf {
  __u32 off;
  __u8 data[BUFSIZE_PADDED];
} buf_t;

BPF_MAP_DEF(events) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 1024,
};
BPF_MAP_ADD(events);

BPF_MAP_DEF(buffer) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = BUFSIZE_PADDED,
    .max_entries = 1,
};
BPF_MAP_ADD(buffer);

static inline void get_args(struct pt_regs *ctx, unsigned long *args) {
  // if registers are valid then use them directly (kernel version < 4.17)
  if (ctx->orig_ax || ctx->bx || ctx->cx || ctx->dx) {
    args[0] = PT_REGS_PARM1(ctx);
    args[1] = PT_REGS_PARM2(ctx);
    args[2] = PT_REGS_PARM3(ctx);
    args[3] = PT_REGS_PARM4(ctx);
    args[4] = PT_REGS_PARM5(ctx);
    args[5] = PT_REGS_PARM6(ctx);
  } else {
    // otherwise it's a later kernel version so load register values from
    // ctx->di.
    struct pt_regs *regs = (struct pt_regs *)ctx->di;
    bpf_probe_read(&args[0], sizeof(*args), &regs->di);
    bpf_probe_read(&args[1], sizeof(*args), &regs->si);
    bpf_probe_read(&args[2], sizeof(*args), &regs->dx);
    bpf_probe_read(&args[3], sizeof(*args), &regs->r10);
    bpf_probe_read(&args[4], sizeof(*args), &regs->r8);
    bpf_probe_read(&args[5], sizeof(*args), &regs->r9);
  }
}

static inline buf_t *get_buf() {
  __u32 key = 0;
  return (buf_t *)bpf_map_lookup_elem(&buffer, &key);
}

static inline int buf_perf_output(struct pt_regs *ctx) {
  buf_t *buf = get_buf();
  if (buf == NULL) {
    return -1;
  }
  int size = buf->off & BUFSIZE;
  buf->off = 0;
  return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                               (void *)buf->data, size);
}

static inline int buf_write(buf_t *buf, void *ptr, int size) {
  if (buf->off >= BUFSIZE) {
    return 0;
  }

  if (bpf_probe_read(&(buf->data[buf->off]), size, ptr) == 0) {
    buf->off += size;
    return size;
  }

  return -1;
}

static inline int buf_strcat(buf_t *buf, void *ptr) {
  if (buf->off >= BUFSIZE) {
    return 0;
  }

  int n = bpf_probe_read_str(&(buf->data[buf->off]), MAX_ARGLEN, ptr);
  if (n > 0) {
    buf->off += n;
  }

  return n;
}

static inline int buf_strcat_argp(buf_t *buf, void *ptr) {
  const char *argp = NULL;
  bpf_probe_read(&argp, sizeof(argp), ptr);
  if (argp) {
    return buf_strcat(buf, (void *)(argp));
  }
  return 0;
}

static inline int buf_strcat_argv(buf_t *buf, void **ptr) {
#pragma unroll
  for (int i = 0; i < MAX_ARGS; i++) {
    if (buf_strcat_argp(buf, &ptr[i]) == 0) {
      return 0;
    }
  }
  return 0;
}

SEC("kprobe/guess_execve")
int execve_entry(struct pt_regs *ctx) {
  buf_t *buf = get_buf();
  if (buf == NULL) {
    return 0;
  }

  args_t args[NARGS] = {};
  get_args(ctx, args);

  event_t e = {0};
  e.ktime_ns = bpf_ktime_get_ns();
  e.pid = bpf_get_current_pid_tgid() >> 32;
  e.uid = bpf_get_current_uid_gid() >> 32;
  e.gid = bpf_get_current_uid_gid();
  bpf_get_current_comm(&e.comm, sizeof(e.comm));

  buf_write(buf, (void *)&e, sizeof(e));
  buf_strcat(buf, (void *)args[0]);
  buf_strcat_argv(buf, (void *)args[1]);
  buf_perf_output(ctx);

  return 0;
}

char _license[] SEC("license") = "GPL";

```

```
// Copyright (c) 2020 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/dropbox/goebpf"
)

var (
	ErrProgramNotFound = errors.New("program not found")
	ErrMapNotFound     = errors.New("map not found")
)

type Event_t struct {
	KtimeNs uint64
	Pid     uint32
	Uid     uint32
	Gid     uint32
	Type    int32
	Comm    [32]byte
}

type Program struct {
	bpf goebpf.System
	pe  *goebpf.PerfEvents
	wg  sync.WaitGroup
}

func main() {

	// cleanup old probes
	if err := goebpf.CleanupProbes(); err != nil {
		log.Println(err)
	}

	// load ebpf program
	p, err := LoadProgram("ebpf_prog/kprobe.elf")
	if err != nil {
		log.Fatalf("LoadProgram() failed: %v", err)
	}
	p.ShowInfo()

	// attach ebpf kprobes
	if err := p.AttachProbes(); err != nil {
		log.Fatalf("AttachProbes() failed: %v", err)
	}
	defer p.DetachProbes()

	// wait until Ctrl+C pressed
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	<-ctrlC

	// display some stats
	fmt.Println()
	fmt.Printf("%d Event(s) Received\n", p.pe.EventsReceived)
	fmt.Printf("%d Event(s) lost (e.g. small buffer, delays in processing)\n", p.pe.EventsLost)
}

func LoadProgram(filename string) (*Program, error) {

	// create system
	bpf := goebpf.NewDefaultEbpfSystem()

	// load compiled ebpf elf file
	if err := bpf.LoadElf(filename); err != nil {
		return nil, err
	}

	// load programs
	for _, prog := range bpf.GetPrograms() {
		if err := prog.Load(); err != nil {
			return nil, err
		}
	}

	return &Program{bpf: bpf}, nil
}

func (p *Program) startPerfEvents(events <-chan []byte) {
	p.wg.Add(1)
	go func(events <-chan []byte) {
		defer p.wg.Done()

		// print header
		fmt.Printf("\nTIME          PCOMM             PID    UID    GID    DESC\n\n")
		for {

			// receive exec events
			if b, ok := <-events; ok {

				// parse proc info
				var ev Event_t
				buf := bytes.NewBuffer(b)
				if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
					fmt.Printf("error: %v\n", err)
					continue
				}

				// parse args
				tokens := bytes.Split(buf.Bytes(), []byte{0x00})
				var args []string
				for _, arg := range tokens {
					if len(arg) > 0 {
						args = append(args, string(arg))
					}
				}

				// build display strings
				var desc string
				if len(args) > 0 {
					desc = args[0]
				}
				if len(args) > 2 {
					desc += " " + strings.Join(args[2:], " ")
				}

				// display process execution event
				ts := goebpf.KtimeToTime(ev.KtimeNs)
				fmt.Printf("%s  %-16s  %-6d %-6d %-6d %s\n",
					ts.Format("15:04:05.000"),
					goebpf.NullTerminatedStringToString(ev.Comm[:]),
					ev.Pid, ev.Uid, ev.Gid, desc)

			} else {
				break
			}
		}
	}(events)
}

func (p *Program) stopPerfEvents() {
	p.pe.Stop()
	p.wg.Wait()
}

func (p *Program) AttachProbes() error {

	// attach all probe programs
	for _, prog := range p.bpf.GetPrograms() {
		if err := prog.Attach(nil); err != nil {
			return err
		}
	}

	// get handles to perf event map
	m := p.bpf.GetMapByName("events")
	if m == nil {
		return ErrMapNotFound
	}

	// create perf events
	var err error
	p.pe, err = goebpf.NewPerfEvents(m)
	if err != nil {
		return err
	}
	events, err := p.pe.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		return err
	}

	// start event listeners
	p.wg = sync.WaitGroup{}
	p.startPerfEvents(events)

	return nil
}

func (p *Program) DetachProbes() error {
	p.stopPerfEvents()
	for _, prog := range p.bpf.GetPrograms() {
		prog.Detach()
		prog.Close()
	}
	return nil
}

func (p *Program) ShowInfo() {
	fmt.Println()
	fmt.Println("Maps:")
	for _, item := range p.bpf.GetMaps() {
		m := item.(*goebpf.EbpfMap)
		fmt.Printf("\t%s: %v, Fd %v\n", m.Name, m.Type, m.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range p.bpf.GetPrograms() {
		fmt.Printf("\t%s: %v (%s), size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSection(), prog.GetSize(), prog.GetLicense(),
		)
	}
}

```



## 看看怎么搞的


* 首先明确一点，肯定是要分成两部分，一部分是内核中加载ebpf程序，需要用clang编译，另一部分是用户态程序，加载ebpf程序，并且实现后续执行结果提取，不管是否把句柄放到文件系统中
* 那么逃不开需要一个c代码，clang编译成ebpf
* go程序其实就是底层要调用syscall ebpf来实现程序加载，执行结果获取功能

带着这万变不离其宗的基本原理，来看看怎么玩的


## main函数调用关系

```
main
  ->  if err := goebpf.CleanupProbes(); err != nil {}  # 清理已有探测点
    -> probes, err := ListProbes() # 清理过程，先罗列
      -> data, err := ioutil.ReadFile("/sys/kernel/debug/tracing/kprobe_events")
    -> for _, p := range probes { _, err = f.Write([]byte("-:" + event)) } # 借助vfs，写入sysfs关闭探测点
  ->  p, err := LoadProgram("ebpf_prog/kprobe.elf") # 加载clang编译的ebpf程序
    -> bpf := goebpf.NewDefaultEbpfSystem() # 实例化EbpfSystem
    -> if err := bpf.LoadElf(filename); err != nil {} # 读取，加载ebpf程序
      -> f, err := os.Open(path)
      -> return s.Load(f)
        -> elfFile, err := elf.NewFile(r) # 读取ebpf elf头信息
        -> s.Maps, err = loadAndCreateMaps(elfFile) # 从elf头信息获取节信息，检索maps节，解析创建内核ebpf map，返回文件引用
          -> symbols, err := elfFile.Symbols() # 读取elf符号表
          -> for index, section := range elfFile.Sections { if section.Name == MapSectionName {} } # 获取“maps”节
          -> if mapSection == nil { return map[string]Map{}, nil } # 可以没有map节
          -> for _, item := range mapsByIndex { err := item.Create() } # 遍历所有节，创建map
            -> C.ebpf_map_create()
              -> int res = SYSCALL_BPF(BPF_MAP_CREATE); # cgo代码ebpf_map_create中调用syscall
        -> s.Programs, err = loadPrograms(elfFile, s.Maps)
    -> for _, prog := range bpf.GetPrograms() { if err := prog.Load(); err != nil {} }
  ->  if err := p.AttachProbes(); err != nil {}
  ->  defer p.DetachProbes()
```













---
