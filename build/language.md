<!--
This file originates from https://github.com/bpftrace/bpftrace
It is licensed under the Apache License, Version 2.0
See the LICENSE file of that project or https://www.apache.org/licenses/LICENSE-2.0
-->
## Probes

bpftrace supports various probe types which allow the user to attach BPF programs to different types of events.
Each probe starts with a provider (e.g. `kprobe`) followed by a colon (`:`) separated list of options.
An optional name may precede the provider with an equals sign (e.g. `name=`), which is reserved for internal use and future features.
The amount of options and their meaning depend on the provider and are detailed below.
The valid values for options can depend on the system or binary being traced, e.g. for uprobes it depends on the binary.
Also see [Listing Probes](../man/adoc/bpftrace.adoc#listing-probes).

It is possible to associate multiple probes with a single action as long as the action is valid for all specified probes.
Multiple probes can be specified as a comma (`,`) separated list:

```
kprobe:tcp_reset,kprobe:tcp_v4_rcv {
  printf("Entered: %s\n", probe);
}
```

Wildcards are supported too:

```
kprobe:tcp_* {
  printf("Entered: %s\n", probe);
}
```

Both can be combined:

```
kprobe:tcp_reset,kprobe:*socket* {
  printf("Entered: %s\n", probe);
}
```

By default, bpftrace requires all probes to attach successfully or else an error is returned. However this can be changed using the `missing_probes` config variable.

Most providers also support a short name which can be used instead of the full name, e.g. `kprobe:f` and `k:f` are identical.

|     |     |     |
| --- | --- | --- |
| **Probe Name** | **Short Name** | **Description** |
| [`begin/end`](#beginend) | - | Built-in events |
| [`bench`](#bench) | - | Micro benchmarks |
| [`self`](#self) | - | Built-in events |
| [`test`](#test) | - | Script tests |
| [`hardware`](#hardware) | `h` | Processor-level events |
| [`interval`](#interval) | `i` | Timed output |
| [`iter`](#iterator) | `it` | Iterators tracing |
| [`fentry/fexit`](#fentry-and-fexit) | `f`/`fr` | Kernel functions tracing with BTF support |
| [`kprobe/kretprobe`](#kprobe-and-kretprobe) | `k`/`kr` | Kernel function start/return |
| [`profile`](#profile) | `p` | Timed sampling |
| [`rawtracepoint`](#rawtracepoint) | `rt` | Kernel static tracepoints with raw arguments |
| [`software`](#software) | `s` | Kernel software events |
| [`tracepoint`](#tracepoint) | `t` | Kernel static tracepoints |
| [`uprobe/uretprobe`](#uprobe-uretprobe) | `u`/`ur` | User-level function start/return |
| [`usdt`](#usdt) | `U` | User-level static tracepoints |
| [`watchpoint/asyncwatchpoint`](#watchpoint-and-asyncwatchpoint) | `w`/`aw` | Memory watchpoints |

### BEGIN [..]
Built-in event before other probes are attached.

**variants**
* `BEGIN`

Special built-in event provided by the bpftrace runtime.
`BEGIN` is triggered before all other probes are attached.

### END [..]
Built-in event after all other probes are detached.

**variants**
* `END`

Special built-in event provided by the bpftrace runtime.
`END` is triggered after all other probes are detached.

#### Notes
Specifying an `END` probe doesn’t override the printing of 'non-empty' maps at exit.
To prevent printing all used maps need be cleared in the `END` probe:

#### Example
```
end {
    clear(@map1);
    clear(@map2);
}
```

### test [0.25..]
Built-in probe for testing bpftrace scripts.

**variants**
* `test:name`

`test` is a special built-in probe type for creating tests.
bpftrace executes each `test` probe and checks the return value, error count and possible exit calls to determine a pass.
If multiple `test` probes exist in a script, bpftrace executes them sequentially in the order they are specified.
To run `test` probes, you must run bpftrace in test mode: `bpftrace --test ...`; otherwise `test` probes will be ignored.

**Availability**
Since bpftrace v0.25

```
test:okay {
  print("I'm okay! This output will be suppressed.");
}

test:failure {
  print("This is a failure! This output will be shown");
  return 1;
}
```

### bench [0.24..]
Microbenchmark probe for measuring execution time.

**variants**
* `bench:name`

`bench` is a special built-in probe type for creating micro benchmarks.
bpftrace executes each `bench` probe repeatedly to measure the average execution time of the contained code.
If multiple `bench` probes exist in a script, bpftrace executes them sequentially in the order they are specified.
To run `bench` probes, you must run bpftrace in bench mode: `bpftrace --bench ...`; otherwise, `bench` probes will be ignored.

**Availability**
Since bpftrace v0.24

```
bench:lhist {
    @a = lhist(rand % 10, 1, 10, 1);
}

bench:count {
    @b = count();
}

bench:my_loop {
    $a = 0;
    for ($i : 0..10) {
        $a++;
    }
}
```

```
Attached 3 probes


+-----------+-------------+
| BENCHMARK | NANOSECONDS |
+-----------+-------------+
| count     | 40          |
| lhist     | 88          |
| my_loop   | 124         |
+-----------+-------------+
```

### self [0.22..]
Signal event for the bpftrace process.

**variants**
* `self:signal:SIGUSR1`

These are special built-in events provided by the bpftrace runtime.
The trigger function is called by the bpftrace runtime when the bpftrace process receives specific events, such as a `SIGUSR1` signal.

```
self:signal:SIGUSR1 {
  print("abc");
}
```

**Availability**
Since bpftrace v0.22

### hardware [..]
Processor hardware performance event. Short name `h`.

**variants**

* `hardware:event_name[:count]`

These are the pre-defined hardware events provided by the Linux kernel, as commonly traced by the perf utility.
They are implemented using performance monitoring counters (PMCs): hardware resources on the processor.
There are about ten of these, and they are documented in the perf_event_open(2) man page.
The event names are:

* `cpu-cycles` or `cycles`
* `instructions`
* `cache-references`
* `cache-misses`
* `branch-instructions` or `branches`
* `branch-misses`
* `bus-cycles`
* `frontend-stalls`
* `backend-stalls`
* `ref-cycles`

The `count` option specifies how many events must happen before the probe fires (sampling interval).
If `count` is left unspecified a default value is used.

This will fire once for every 1,000,000 cache misses.

```
hardware:cache-misses:1e6 { @[pid] = count(); }
```

### interval [..]
Periodic event at a specified time interval. Short name `i`.

**variants**

* `interval[:time_unit]:count`
* `interval:hz:rate`

The interval probe fires at a fixed interval as specified by its time spec.
Interval fires on one CPU at a time, unlike [profile](#profile) probes.
If a unit of time is not specified in the second position, the number is interpreted as nanoseconds; e.g., `interval:1s`, `interval:1000000000`, and `interval:s:1` are all equivalent.

This prints the rate of syscalls per second.

```
tracepoint:raw_syscalls:sys_enter { @syscalls = count(); }
interval:1s { print(@syscalls); clear(@syscalls); }
```

### iter [..]
Kernel object iterator. Short name `it`.

**variants**
* `iter:object[:pin]`

***Warning*** this feature is experimental and may be subject to interface changes.

These are eBPF iterator probes that allow iteration over kernel objects.
Iterator probe can’t be mixed with any other probe, not even another iterator.
Each iterator probe provides a set of fields that could be accessed with the
ctx pointer. Users can display the set of available fields for each iterator via
-lv options as described below.

```
iter:task { printf("%s:%d\n", ctx.task.comm, ctx.task.pid); }

/*
 * Sample output:
 * systemd:1
 * kthreadd:2
 * rcu_gp:3
 * rcu_par_gp:4
 * kworker/0:0H:6
 * mm_percpu_wq:8
 */
```

```
iter:task_file {
  printf("%s:%d %d:%s\n", ctx.task.comm, ctx.task.pid, ctx.fd, path(ctx.file.f_path));
}

/*
 * Sample output:
 * systemd:1 1:/dev/null
 * systemd:1 3:/dev/kmsg
 * ...
 * su:1622 2:/dev/pts/1
 * ...
 * bpftrace:1892 2:/dev/pts/1
 * bpftrace:1892 6:anon_inode:bpf-prog
 */
```

```
iter:task_vma {
  printf("%s %d %lx-%lx\n", comm, pid, ctx.vma.vm_start, ctx.vma.vm_end);
}

/*
 * Sample output:
 * bpftrace 119480 55b92c380000-55b92c386000
 * ...
 * bpftrace 119480 7ffd55dde000-7ffd55de2000
 */
```

It’s possible to pin an iterator by specifying the optional probe ':pin' part, that defines the pin file.
It can be specified as an absolute or relative path to /sys/fs/bpf.

**relative pin**

```
iter:task:list { printf("%s:%d\n", ctx.task.comm, ctx.task.pid); }

/*
 * Sample output:
 * Program pinned to /sys/fs/bpf/list
 */
```

**absolute pin**

```
iter:task_file:/sys/fs/bpf/files {
  printf("%s:%d %s\n", ctx.task.comm, ctx.task.pid, path(ctx.file.f_path));
}

/*
 * Sample output:
 * Program pinned to /sys/fs/bpf/files
 */
```

### fentry [0.20..]
Kernel function entry probe using BTF. Short name `f`.

**variants**
* `fentry[:module]:function`
* `fentry:bpf[:prog_id]:prog_name`

`fentry` attaches when a kernel function starts. It uses BTF and eBPF
trampolines, and exposes typed function arguments through `args`.

The name `fentry` was introduced in bpftrace v0.20 as an alias for `kfunc` and
became the preferred name in v0.22. `kfunc` remains supported as an alias.

The `bpf` variants attach to running BPF programs and subprograms. A program
name matches all programs and subprograms with that name. Add a program ID to
restrict the match to that program and its subprograms. Use `probe` to identify
the matched program. Run `bpftrace -l 'fentry:bpf:*'` to list attachable
programs. Only programs with a BTF ID can be attached, and the `args` builtin is
unavailable for these variants.

**Example**
```
fentry:vmlinux:x86_pmu_stop {
  printf("pmu %s stop\n", str(args.event.pmu.name));
}
```

**Availability**
Since bpftrace v0.20; preferred name since v0.22

### fexit [0.20..]
Kernel function exit probe using BTF. Short name `fr`.

**variants**
* `fexit[:module]:function`
* `fexit:bpf[:prog_id]:prog_name`

`fexit` attaches when a kernel function returns. It uses BTF and eBPF
trampolines. The function arguments are available through `args`, and the
return value through `retval`.

The name `fexit` was introduced in bpftrace v0.20 as an alias for `kretfunc`
and became the preferred name in v0.22. `kretfunc` remains supported as an
alias.

The `bpf` variant attaches to a running BPF program or its subprograms by name.
An optional program ID restricts the match to a specific program. The `args`
builtin is unavailable for this variant.

**Example**
```
fexit:vmlinux:fget {
  printf("fd %d name %s\n", args.fd, str(retval.f_path.dentry.d_name.name));
}
/*
 * Sample output:
 * fd 3 name ld.so.cache
 * fd 3 name libselinux.so.1
 */

```

**Availability**
Since bpftrace v0.20; preferred name since v0.22

### kfunc [..]
Deprecated alias for `fentry`.

**variants**
* `kfunc[:module]:function`

### kretfunc [..]
Deprecated alias for `fexit`.

**variants**
* `kretfunc[:module:]function`

### kprobe [..]
Kernel function entry or instruction probe. Short name `k`.

**variants**
* `kprobe[:module]:function[+offset]`

`kprobe` attaches at kernel function entry. The optional `:module` qualifier
selects a kernel module. The `+offset` suffix selects an instruction relative
to the function start.

Register arguments are available through `argN`. On x86_64, the first six
function arguments are passed in registers, additional arguments are passed on
the stack. Stack-passed arguments are accessed through the stack pointer. Their
locations depend on the architecture and calling convention. At x86_64 function
entry, the first stack-passed argument is at `sp + 8`, for example:
`$stack_arg0 = *(uint64*)(reg("sp") + 8)`.

If kernel BTF is available, its types can be used without manually defining
structs.

**Examples**
```
kprobe:tcp_reset {
  @tcp_resets = count()
}
```

This probe reads the path passed to `vfs_open` using kernel BTF types:
```
kprobe:vfs_open {
  printf("open path: %s\n", str(((struct path *)arg0).dentry.d_name.name));
}
```

### kretprobe [..]
Kernel function return probe. Short name `kr`.

**variants**
* `kretprobe[:module]:function`

`kretprobe` attaches when a kernel function returns. Function arguments are
unavailable; the return value is available through `retval`.

### profile [..]
Per-CPU sampling probe at a specified interval. Short name `p`.

**variants**
* `profile[:time_unit]:count`
* `profile:hz:rate`

Profile probes fire on each CPU on the specified interval.
These operate using perf_events (a Linux kernel facility, which is also used by the perf command).
If a unit of time is not specified in the second position, the number is interpreted as nanoseconds; e.g., `interval:1s`, `interval:1000000000`, and `interval:s:1` are all equivalent.

```
profile:hz:99 { @[tid] = count(); }
```

### rawtracepoint [..]
Kernel static tracepoint probe with raw arguments. Short name `rt`.

**variants**
* `rawtracepoint[:module]:event`

`rawtracepoint` attaches to the raw form of a kernel tracepoint and can have
lower overhead. Raw arguments are available through `argN`; when BTF is
available, typed arguments are also available through `args`.

**Example**
```
rawtracepoint:vmlinux:kfree_skb {
  printf("%llx %llx\n", arg0, args.skb);
}
```
In this example, `arg0` and `args.skb` refer to the same argument.

### software [..]
Kernel software performance event. Short name `s`.

**variants**
* `software:event[:count]`

These are the pre-defined software events provided by the Linux kernel, as commonly traced via the perf utility.
They are similar to tracepoints, but there is only about a dozen of these, and they are documented in the perf_event_open(2) man page.
If the count is not provided, a default is used.

The event names are:

* `cpu-clock` or `cpu`
* `task-clock`
* `page-faults` or `faults`
* `context-switches` or `cs`
* `cpu-migrations`
* `minor-faults`
* `major-faults`
* `alignment-faults`
* `emulation-faults`
* `dummy`
* `bpf-output`

```
software:faults:100 { @[comm] = count(); }
```

This roughly counts who is causing page faults, by sampling the process name for every one in one hundred faults.

### tracepoint [..]
Kernel static tracepoint probe. Short name `t`.

**variants**

* `tracepoint:subsys:event`

`tracepoint` attaches to a statically defined kernel event. Event fields are
available through the `args` struct. Tracepoints are defined in the kernel
source and generally provide a stable interface.

**Example**
```
tracepoint:syscalls:sys_enter_openat {
  printf("%s %s\n", comm, str(args.filename));
}
```

### uprobe [..]
User-space function entry probe. Short name `u`.

**variants**
* `uprobe:binary:function`
* `uprobe:binary:function+offset`
* `uprobe:binary:offset`

`uprobe` s or user-space probes are the user-space equivalent of `kprobe` s.
The same limitations that apply [kprobe and kretprobe](#kprobe-and-kretprobe) also apply to `uprobe` s and `uretprobe` s, namely: arguments are available via the `argN` builtins and can only be accessed with a uprobe.
retval is the return value for the instrumented function and can only be accessed with a uretprobe.
**Note**: When tracing some languages, like C++, `arg0` and even `arg1` may refer to runtime internals such as the current object instance (`this`) and/or the eventual return value for large returned objects where copy elision is used.
This will push the actual function arguments to possibly start at `arg1` or `arg2` - the only way to know is to experiment.

```
uprobe:/bin/bash:readline { printf("arg0: %d\n", arg0); }
```

What does arg0 of readline() in /bin/bash contain?
I don’t know, so I’ll need to look at the bash source code to find out what its arguments are.

When tracing libraries, it is sufficient to specify the library name instead of
a full path. The path will be then automatically resolved using `/etc/ld.so.cache`:

```
uprobe:libc:malloc { printf("Allocated %d bytes\n", arg0); }
```

If multiple versions of the same shared library exist (e.g. `libssl.so.3` and
`libssl.so.59`), bpftrace may resolve the wrong one. To fix this, you can specify
a versioned SONAME to ensure the correct library is traced:

```
uprobe:libssl.so.3:SSL_write { ... }
```

If the traced binary has DWARF included, function arguments are available in the `args` struct which can be inspected with verbose listing, see the [Listing Probes](../man/adoc/bpftrace.adoc#listing-probes) section for more details.

```
# bpftrace -lv 'uprobe:/bin/bash:rl_set_prompt'

uprobe:/bin/bash:rl_set_prompt
    const char* prompt
```

When tracing C++ programs, it’s possible to turn on automatic symbol demangling by using the `:cpp` prefix:

```
# bpftrace:cpp:"bpftrace::BPFtrace::add_probe" { ... }
```

It is important to note that for `uretprobe` s to work the kernel runs a special helper on user-space function entry which overrides the return address on the stack.
This can cause issues with languages that have their own runtime like Golang:

**example.go**

```
func myprint(s string) {
  fmt.Printf("Input: %s\n", s)
}

func main() {
  ss := []string{"a", "b", "c"}
  for _, s := range ss {
    go myprint(s)
  }
  time.Sleep(1*time.Second)
}
```

**bpftrace**

```
# bpftrace -e 'uretprobe:./test:main.myprint { @=count(); }' -c ./test
runtime: unexpected return pc for main.myprint called from 0x7fffffffe000
stack: frame={sp:0xc00008cf60, fp:0xc00008cfd0} stack=[0xc00008c000,0xc00008d000)
fatal error: unknown caller pc
```

### uretprobe [..]
User-space function return probe. Short name `ur`.

**variants**
* `uretprobe:binary:function`

### usdt [..]
User-space statically defined tracepoint. Short name `U`.

**variants**

* `usdt:binary_path[:probe_namespace]:probe_name`
* `usdt:library_path[:probe_namespace]:probe_name`

Where probe_namespace is optional if probe_name is unique within the binary.

You can target the entire host (or an entire process’s address space by using the `-p` arg) by using a single wildcard in place of the binary_path/library_path:

```
usdt:*:loop { printf("hi\n"); }
```

Please note that if you use wildcards for the probe_name or probe_namespace and end up targeting multiple USDTs for the same probe you might get errors if you also utilize the USDT argument builtin (e.g. arg0) as they could be of different types.

Arguments are available via the `argN` builtins:

```
usdt:/root/tick:loop { printf("%s: %d\n", str(arg0), arg1); }
```

bpftrace also supports USDT semaphores.
If both your environment and bpftrace support uprobe refcounts, then USDT semaphores are automatically activated for all processes upon probe attachment (and --usdt-file-activation becomes a noop).
You can check if your system supports uprobe refcounts by running:

```
# bpftrace --info 2>&1 | grep "uprobe refcount"
bcc bpf_attach_uprobe refcount: yes
  uprobe refcount (depends on Build:bcc bpf_attach_uprobe refcount): yes
```

If your system does not support uprobe refcounts, you may activate semaphores by passing in -p $PID or --usdt-file-activation.
--usdt-file-activation looks through /proc to find processes that have your probe’s binary mapped with executable permissions into their address space and then tries to attach your probe.
Note that file activation occurs only once (during attach time).
In other words, if later during your tracing session a new process with your executable is spawned, your current tracing session will not activate the new process.
Also note that --usdt-file-activation matches based on file path.
This means that if bpftrace runs from the root host, things may not work as expected if there are processes execved from private mount namespaces or bind mounted directories.
One workaround is to run bpftrace inside the appropriate namespaces (i.e. the container).

### watchpoint [..]
Synchronous memory access watchpoint. Short name `w`.

**variants**
* `watchpoint:absolute_address:length:mode`
* `watchpoint:function+argN:length:mode`

These are memory watchpoints provided by the kernel.
Whenever a memory address is written to (`w`), read
from (`r`), or executed (`x`), the kernel can generate an event.

### asyncwatchpoint [..0.24]
Asynchronous memory access watchpoint. Short name `aw`.

**variants**

* `asyncwatchpoint:absolute_address:length:mode`
* `asyncwatchpoint:function+argN:length:mode`

This feature is experimental and may be subject to interface changes.
Memory watchpoints are also architecture dependent.

These are memory watchpoints provided by the kernel.
Whenever a memory address is written to (`w`), read
from (`r`), or executed (`x`), the kernel can generate an event.

In the first form, an absolute address is monitored.
If a pid (`-p`) or a command (`-c`) is provided, bpftrace takes the address as a userspace address and monitors the appropriate process.
If not, bpftrace takes the address as a kernel space address.

In the second form, the address present in `argN` when `function` is entered is
monitored.
A pid or command must be provided for this form.
If synchronous (`watchpoint`), a `SIGSTOP` is sent to the tracee upon function entry.
The tracee will be ``SIGCONT``ed after the watchpoint is attached.
This is to ensure events are not missed.
If you want to avoid the `SIGSTOP` + `SIGCONT` use `asyncwatchpoint`.

**Availability**
Available through bpftrace v0.24.

Note that on most architectures you may not monitor for execution while monitoring read or write.

```
# bpftrace -e 'watchpoint:0x10000000:8:rw { printf("hit!\n"); }' -c ./testprogs/watchpoint
```

Print the call stack every time the `jiffies` variable is updated:

```
watchpoint:0x$(awk '$3 == "jiffies" {print $1}' /proc/kallsyms):8:w {
  @[kstack] = count();
}
```

"hit" and exit when the memory pointed to by `arg1` of `increment` is written to:

```C
# cat wpfunc.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline))
void increment(__attribute__((unused)) int _, int *i)
{
  (*i)++;
}

int main()
{
  int *i = malloc(sizeof(int));
  while (1)
  {
    increment(0, i);
    (*i)++;
    usleep(1000);
  }
}
```

```
# bpftrace -e 'watchpoint:increment+arg1:4:w { printf("hit!\n"); exit() }' -c ./wpfunc
```

Note that threads are monitored, but only for threads created after watchpoint attachment.
The is a limitation from the kernel.
Additionally, because of how watchpoints are implemented in bpftrace the specified function must be called at least once in the main thread in order to observe future calls to this function in child threads.

