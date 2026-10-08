<!--
This file originates from https://github.com/bpftrace/bpftrace
It is licensed under the Apache License, Version 2.0
See the LICENSE file of that project or https://www.apache.org/licenses/LICENSE-2.0
-->

# bpftrace Standard Library

This includes builtins, functions, macros, and [map value functions](#map-value-functions).
The boundaries for the first three are blurred, by design, to allow for more flexible usage and are grouped below as "Helpers".
For example `pid` and `pid()` are equivalent; both yielding the process id.
Basically all functions or macros that don't have arguments or have default arguments can be invoked with or without the call syntax.

**async** helpers are asynchronous, which can lead to unexpected behaviour. See the [Invocation Mode](#invocation-mode) section for more information.

**compile time** helpers are evaluated at compile time, a static value will be compiled into the program.

**unsafe** helpers can have dangerous side effects and should be used with care, the `--unsafe` flag is required for use.

## Helpers

### config
- `Record config()`
- `Record config`

Returns a `Record` containing the current `bpftrace` configuration settings. [List of config variables](./language.md#config-variables)

```
printf("max_strlen: %d, stack_mode: %s\n", config.max_strlen, config.stack_mode);
}
```


### container_of
- `Container* container_of(Member* ptr, Type type, Identifier member)`

Returns a pointer to an object of the passed `type` given a pointer to the `member` of that object.


### default_str_length

Returns the default unbounded length.


### dw_ustack
- `ustack_t dw_ustack([StackMode mode, ][int limit])`

DWARF-based user-space stack unwinding. Unlike [ustack](#ustack), which
relies on frame pointers, `dw_ustack` uses DWARF `.eh_frame` debug
information to unwind the stack. This makes it possible to collect complete
user-space stack traces from programs compiled without frame pointers.

The signature and output format are the same as `ustack`.

Bpftrace needs to read the DWARF information for the target processes at startup.
For this, one or more pids have to be specified. This can either be done via
`-p`, `-c` (implicitly) or `--dwarf-pid`. If `dw_ustack` cannot find unwind
information for a process, a runtime warning is emitted.

`dw_ustack` is currently only available on x86_64.

**Unstable feature**

`dw_ustack` is an unstable feature. By default a warning is printed when it
is used. Set the config flag to suppress the warning or to make it an error:

```
config = { unstable_dw_ustack=enable }
```

For usage examples see [ustack](#ustack).


### errorf
- `void errorf(const string fmt, args...)`

**async**

`errorf()` formats and prints data (similar to [`printf`](#printf)) as an error message with the source location.

```
BEGIN { errorf("Something bad with args: %d, %s", 10, "arg2"); }
```

Prints:

```
EXPECT stdin:1:9-62: ERROR: Something bad with args: 10, arg2
```


### fail
- `void fail(const string fmt, args...)`

`fail()` formats and prints data (similar to [`printf`](#printf)) as an error message with the source location but, as opposed to [`errorf`](#errorf), is treated like a static assert and halts compilation if it is visited. All args have to be literals since they are evaluated at compile time.

```
BEGIN { if ($1 < 2) { fail("Expected the first positional param to be greater than 1. Got %d", $1); } }
```



### find
- `boolean find(map m, mapkey k, mapvalue result)`

Return `true` if the key exists in this map and sets the passed scratch variable (result) to the value of that map key.
Otherwise return `false` and don't mutate result.
Use this instead of `has_key` and a map access to avoid an additional map lookup.
Error if called with a map that has no keys (aka scalar map).

```
kprobe:dummy {
  @map[2] = (1, "hello");
  let $val;
  if (find(@map, 2, $val)) {
    print($val); // prints (1, "hello")
  }
}
```


### getopt
- `bool getopt(string arg_name)`
- `bool getopt(string arg_name, bool default_value, [string description])`
- `int getopt(string arg_name, int default_value, [string description])`
- `string getopt(string arg_name, string default_value, [string description])`

Get the named command line argument/option e.g.
```
# bpftrace -e 'BEGIN { print(getopt("hello", 1, "Description of hello")); }' -- --hello=5

```

`getopt` defines the type of the argument by the default value’s type.
If no default type is provided, the option is treated like a boolean arg e.g. `getopt("hello")` would evaluate to `false` if `--hello` is not specified on the command line or `true` if `--hello` is passed or set to one of the following values: `true`, `1`.
Additionally, boolean args accept the following false values: `0`, `false` e.g. `--hello=false`.
If the arg is not set on the command line, the default value is used.
`getopt` calls may optionally specify a string with the argument description (except for a boolean arg without a default value).

You can use `--help` to see all named arguments/options.

```
# bpftrace -e 'BEGIN { print((getopt("aa", 10, "Description of aa"), getopt("bb", "hello"), getopt("cc"), getopt("dd", false))); }' -- --cc --bb=bye

```


### has_cpid
- `bool has_cpid()`
- `bool has_cpid`

Returns true iff cpid is available.


### is_array
- `bool is_array(any expression)`

Determine whether the given expression is an array.


### is_err
- `bool is_err(void * ptr)`

Returns true if the pointer is an ERR_PTR, i.e. it encodes a kernel error code.

In the Linux kernel, some functions return error codes encoded as pointers
using the `ERR_PTR` macro. These are pointer values in the range
`(unsigned long)(-4095)` to `(unsigned long)(-1)`.

This is equivalent to the kernel's `IS_ERR()` macro.

```
fexit:do_filp_open {
  if (is_err(retval)) {
    printf("error: %ld\n", (int64)retval);
  }
}
```


### is_integer
- `bool is_integer(any expression)`

Determine whether the given expression is an integer.


### is_literal
- `bool is_literal(Expression expr)`

Returns true if the passed expression is a literal, e.g. 1, true, "hello"


### is_ptr
- `bool is_ptr(any expression)`

Determine whether the given expression is a pointer.


### is_str
- `bool is_str(any expression)`

Determine whether the given expression is a string.


### is_unsigned_integer
- `bool is_unsigned_integer(any expression)`

Determine whether the given expression is an unsigned integer.


### kfunc_allowed
- `boolean kfunc_allowed(const string kfunc)`

Determine if a kfunc is supported for particular probe types.

Argument kfunc must be string literal.


### kfunc_exist
- `boolean kfunc_exist(const string kfunc)`

Determine if a kfunc exists using BTF.

Argument kfunc must be string literal.


### leader_comm
- `string leader_comm()`
- `string leader_comm`
- `string leader_comm(struct task_struct * task)`

Get the thread name of the thread group leader for the passed task or the current task if called without arguments.
This is an alias for `task.group_leader.comm`, which is different than `task.real_parent.comm`, which you can get from calling `pcomm()`.
See `pcomm()` for more details.


### leader_tid
- `string leader_tid()`
- `string leader_tid`
- `string leader_tid(struct task_struct * task)`

Get the thread id of the thread group leader for the passed task or the current task if called without arguments.
This is an alias for `task.group_leader.pid`, which is different than `task.real_parent.pid`, which you can get from calling `ppid()`.
See `ppid()` for more details.


### memcmp
- `int memcmp(left, right, uint64 count)`

Compares the first 'count' bytes of two expressions.
0 is returned if they are the same.
negative value if the first differing byte in left is less
than the corresponding byte in right.



### ncpus
- `uint64 ncpus()`
- `uint64 ncpus`

Number of CPUs


### pcomm
- `string pcomm()`
- `string pcomm`
- `string pcomm(struct task_struct * task)`

Get the name of the parent process for the passed task or the current task if called without arguments.
This is an alias for `task.real_parent.comm`, which is different than `task.group_leader.comm`, which you can get from calling `leader_comm()`.


### ppid
- `uint32 ppid()`
- `uint32 ppid`
- `uint32 ppid(struct task_struct * task)`

Get the pid of the parent process for the passed task or the current task if called without arguments.
This is an alias for `task.real_parent.pid`, which is different than `task.group_leader.pid`, which you can get from calling `leader_tid()`.


### probetype
- `string probetype()`
- `string probetype`

Name of the probe type.
Note: `begin` and `end` probes are of type `special`.

For example: `kprobe`, `special`, `tracepoint`


### rand
- `uint32 rand()`
- `uint32 rand`

Get a pseudo random number

This utilizes the BPF helper `get_prandom_u32`


### reg
- `uint64 reg(const string name)`

**Supported probes**

* kprobe
* uprobe

Get the contents of the register identified by `name`.
Valid names depend on the CPU architecture.


### signal
- `void signal(const string sig)`
- `void signal(uint32 signum)`

**unsafe**

This utilizes the BPF helper `bpf_send_signal`.

Probe types: k(ret)probe, u(ret)probe, USDT, profile

Send a signal to the process being traced (any thread).
Use `signal_thread` to send to the thread being traced.
The signal can either be identified by name, e.g. `SIGSTOP` or by ID, e.g. `19` as found in `kill -l`.

```
kprobe:__x64_sys_execve
/comm == "bash"/ {
  signal(5);
}
```
```
$ ls
Trace/breakpoint trap (core dumped)
```


### signal_name
- `string signal_name(int sig)`

Convert signal code to string.

```
#include <signal.h>
begin {
  print(signal_name(SIGINT));
}
```


### signal_thread
- `void signal_thread(const string sig)`
- `void signal_thread(uint32 signum)`

**unsafe**

This utilizes the BPF helper `bpf_send_signal_thread`.

Probe types: k(ret)probe, u(ret)probe, USDT, profile

Send a signal to the thread being traced.
Use `signal` to send to the process being traced (any thread).
The signal can either be identified by name, e.g. `SIGSTOP` or by ID, e.g. `19` as found in `kill -l`.


### sizeof
- `uint64 sizeof(TYPE)`
- `uint64 sizeof(EXPRESSION)`

**compile time**

Returns size of the argument in bytes.
Similar to C/C++ `sizeof` operator.
Note that the expression does not get evaluated.


### skboutput
- `uint32 skboutput(const string path, struct sk_buff *skb, uint64 length, const uint64 offset)`

**Kernel** 5.5

This utilizes the BPF helper `bpf_skb_output`

Write sk_buff `skb` 's data section to a PCAP file in the `path`, starting from `offset` to `offset` + `length`.

The PCAP file is encapsulated in RAW IP, so no ethernet header is included.
The `data` section in the struct `skb` may contain ethernet header in some kernel contexts, you may set `offset` to 14 bytes to exclude ethernet header.

Each packet’s timestamp is determined by adding `nsecs` and boot time, the accuracy varies on different kernels, see `nsecs`.

This function returns 0 on success, or a negative error in case of failure.

Environment variable `BPFTRACE_PERF_RB_PAGES` should be increased in order to capture large packets, or else these packets will be dropped.

Usage

```
# cat dump.bt
fentry:napi_gro_receive {
  $ret = skboutput("receive.pcap", args.skb, args.skb.len, 0);
}

fentry:dev_queue_xmit {
  // setting offset to 14, to exclude ethernet header
  $ret = skboutput("output.pcap", args.skb, args.skb.len, 14);
  printf("skboutput returns %d\n", $ret);
}

# export BPFTRACE_PERF_RB_PAGES=1024
# bpftrace dump.bt
...

# tcpdump -n -r ./receive.pcap  | head -3
reading from file ./receive.pcap, link-type RAW (Raw IP)
dropped privs to tcpdump
10:23:44.674087 IP 22.128.74.231.63175 > 192.168.0.23.22: Flags [.], ack 3513221061, win 14009, options [nop,nop,TS val 721277750 ecr 3115333619], length 0
10:23:45.823194 IP 100.101.2.146.53 > 192.168.0.23.46619: 17273 0/1/0 (130)
10:23:45.823229 IP 100.101.2.146.53 > 192.168.0.23.46158: 45799 1/0/0 A 100.100.45.106 (60)
```


### socket_cookie
- `uint64 socket_cookie(struct sock *sk)`

This utilizes the BPF helper `bpf_get_socket_cookie`

Retrieve the cookie (generated by the kernel) of the socket.
If no cookie has been set yet, generate a new cookie. Once generated, the socket cookie remains stable for the life of the socket.

This function returns a `uint64` unique number on success, or 0 if **sk** is NULL.

```
fentry:tcp_rcv_established
{
  $cookie = socket_cookie(args.sk);
  @psize[$cookie] = hist(args.skb.len);
}
```

Prints:

```
@psize[65551]:
[32, 64)               4 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

@psize[504]:
[32, 64)               4 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[64, 128)              1 |@@@@@@@@@@@@@                                       |
[128, 256)             0 |                                                    |
[256, 512)             1 |@@@@@@@@@@@@@                                       |
[512, 1K)              0 |                                                    |
[1K, 2K)               0 |                                                    |
[2K, 4K)               1 |@@@@@@@@@@@@@                                       |
```


### static_assert
- `void static_assert(bool condition, string msg)`

Assert something is true or fail the build.


### str
- `string str(char * data [, uint32 length)`

This utilizes the BPF helpers `probe_read_str, probe_read_{kernel,user}_str`

`str` reads a NULL terminated (`\0`) string from `data`.
The maximum string length is limited by the `BPFTRACE_MAX_STRLEN` env variable, unless `length` is specified and shorter than the maximum.
In case the string is longer than the specified length only `length - 1` bytes are copied and a NULL byte is appended at the end.

bpftrace will automatically use the `kernel` or `user` variant of `probe_read_{kernel,user}_str` based on the address space of `data`, see [Address-spaces](./language.md#address-spaces) for more information.


### str_concat
- `string str_concat(string s1, string s2)`

Concatenate two strings into a new string.
Returns the new string.



### strcap
- `int64 strcap(string exp)`
- `int64 strcap(int8 exp[])`
- `int64 strcap(int8 *exp)`

Returns the "capacity" of a string-like object.

In most cases this is the same as the length, but for bpftrace-native
strings and arrays, this is the underlying object capacity. This is used to
bound searches and lookups without needing to scan the string itself.


### strcontains
- `bool strcontains(string haystack, string needle)`

Compares whether the string haystack contains the string needle.

If needle is contained then true is returned, else false is returned.


### strerror
- `string strerror(int error)`

Convert errno code to string.

```
#include <errno.h>
begin {
  print(strerror(EPERM));
}
```


### strftime
- `timestamp strftime(const string fmt, uint64 timestamp_ns)`

**async**

Format the nanoseconds since boot timestamp `timestamp_ns` according to the format specified by `fmt`.
The time conversion and formatting happens in user space, therefore  the `timestamp` value returned can only be used for printing using the `%s` format specifier.
**Note:** `timestamp_ns` must be non-negative. Negative timestamp literals are rejected.

bpftrace uses the `strftime(3)` function for formatting time and supports the same format specifiers.

```
interval:s:1 {
  printf("%s\n", strftime("%H:%M:%S", nsecs));
}
```

bpftrace also supports the following format string extensions:

| Specifier | Description |
| --- | --- |
| `%f` | Microsecond as a decimal number, zero-padded on the left |


### strlen
- `uint64 strlen(string exp)`
- `uint64 strlen(int8 exp[])`
- `uint64 strlen(int8 *exp)`

Returns the length of a string-like object.


### strncmp
- `int64 strncmp(char * s1, char * s2, int64 n)`

`strncmp` compares up to `n` characters string `s1` and string `s2`.
If they’re equal `0` is returned, else a non-zero value is returned.

bpftrace doesn’t read past the length of the shortest string.

The use of the `==` and `!=` operators is recommended over calling `strncmp` directly.


### strstr
- `int64 strstr(string haystack, string needle)`

Returns the index of the first occurrence of the string needle in the string haystack. If needle is not in haystack then -1 is returned.


### syscall_name
- `string syscall_name(int nr_syscall)`

Convert syscall number to string.

```
#include <syscall.h>
begin {
  print(syscall_name(__NR_read)); // outputs "read"
}
```


### system
- `void system(string namefmt [, ...args])`

**unsafe**
**async**

`system` lets bpftrace run the specified command (`fork` and `exec`) until it completes and print its stdout.
The `command` is run with the same privileges as bpftrace and it blocks execution of the processing threads which can lead to missed events and delays processing of async events.

```
interval:s:1 {
  time("%H:%M:%S: ");
  printf("%d\n", @++);
}
interval:s:10 {
  system("/bin/sleep 10");
}
interval:s:30 {
  exit();
}
```

Note how the async `time` and `printf` first print every second until the `interval:s:10` probe hits, then they print every 10 seconds due to bpftrace blocking on `sleep`.

```
Attached 3 probes
08:50:37: 0
08:50:38: 1
08:50:39: 2
08:50:40: 3
08:50:41: 4
08:50:42: 5
08:50:43: 6
08:50:44: 7
08:50:45: 8
08:50:46: 9
08:50:56: 10
08:50:56: 11
08:50:56: 12
08:50:56: 13
08:50:56: 14
08:50:56: 15
08:50:56: 16
08:50:56: 17
08:50:56: 18
08:50:56: 19
```

`system` supports the same format string and arguments that `printf` does.

```
tracepoint:syscalls:sys_enter_execve {
  system("/bin/grep %s /proc/%d/status", "vmswap", pid);
}
```


### tid
- `uint32 tid([curr_ns|init])`
- `uint32 tid`

Returns the thread ID of the current thread.
Defaults to `curr_ns`.

* `tid(curr_ns)` - The thread ID as seen from the PID namespace of bpftrace.
* `tid(init)` - The thread ID as seen from the initial PID namespace.


### time
- `void time(const string fmt)`

**async**

Format the current wall time according to the format specifier `fmt` and print it to stdout.
Unlike `strftime()` `time()` doesn’t send a timestamp from the probe, instead it is the time at which user-space processes the event.

bpftrace uses the `strftime(3)` function for formatting time and supports the same format specifiers.


### typeof
- `TYPE typeof(TYPE)`
- `TYPE typeof(EXPRESSION)`

This is a special builtin that can only be used in the following contexts:
- variable declarations e.g. `let $a: typeof($b);`
- cast expressions e.g. `$a = (typeof($b))2;`
- macro expansion calls to pass a type parameter e.g. `my_macro(typeof(uint64 *));`
- type accepting builtins: `sizeof`, `offsetof`, `typeinfo`

This builtin evaluates to the static type of either the parsed TYPE or the raw EXPRESSION parameter.


### uaddr
- `T * uaddr(const string sym)`

**Supported probes**

* uprobes
* uretprobes
* USDT

If kernel supports task_vma open-coded iterator kfuncs (linux >= 6.7), uaddr() will correct the symbol addresses of PIE and dynamic libraries instead of directly using the symbol addresses in the ELF file, see https://github.com/torvalds/linux/commit/4ac454682158.

The `uaddr` function returns the address of the specified symbol.
This lookup happens during program compilation and cannot be used dynamically.

The default return type is `uint64*`.
If the ELF object size matches a known integer size (1, 2, 4 or 8 bytes) the return type is modified to match the width (`uint8*`, `uint16*`, `uint32*` or `uint64*` resp.).
As ELF does not contain type info the type is always assumed to be unsigned.

```
uprobe:/bin/bash:readline {
  printf("PS1: %s\n", str(*uaddr("ps1_prompt")));
}
```


### uid
- `uint64 uid()`
- `uint64 uid`

User ID of the current thread, as seen from the init namespace

This utilizes the BPF helper `get_current_uid_gid`


### unwatch
- `void unwatch(void * addr)`

**async**

Removes a watchpoint


### uptr
- `T * uptr(T * ptr)`

Marks `ptr` as a user address space pointer.
See the address-spaces section for more information on address-spaces.
The pointer type is left unchanged.


### usermode
- `uint8 usermode()`
- `uint8 usermode`

Returns 1 if the current process is in user mode, 0 otherwise

Currently only available on x86_64.


### username
- `string username()`
- `string username`

Get the current username

Often this is just "root"


### ustack
- `ustack_t ustack([StackMode mode, ][int limit])`

There are several [formatting/StackMode options](./language.md#stack_mode).

```
kprobe:do_sys_open /comm == "bash"/ { @[ustack()] = count(); }

/*
 * Sample output:
 * @[
 *  __open_nocancel+65
 *  command_word_completion_function+3604
 *  rl_completion_matches+370
 *  bash_default_completion+540
 *  attempt_shell_completion+2092
 *  gen_completion_matches+82
 *  rl_complete_internal+288
 *  rl_complete+145
 *  _rl_dispatch_subseq+647
 *  _rl_dispatch+44
 *  readline_internal_char+479
 *  readline_internal_charloop+22
 *  readline_internal+23
 *  readline+91
 *  yy_readline_get+152
 *  yy_readline_get+429
 *  yy_getc+13
 *  shell_getc+469
 *  read_token+251
 *  yylex+192
 *  yyparse+777
 *  parse_command+126
 *  read_command+207
 *  reader_loop+391
 *  main+2409
 *  __libc_start_main+231
 *  0x61ce258d4c544155
 * ]: 9
 */
```

Sampling only three frames from the stack (limit = 3):

```
kprobe:ip_output { @[ustack(3)] = count(); }

/*
 * Sample output:
 * @[
 *  __open_nocancel+65
 *  command_word_completion_function+3604
 *  rl_completion_matches+370
 * ]: 20
 */
```

Note: If a limit is used and `show_debug_info` is enabled then the number of symbolized frames might exceed that limit in the output as `limit` refers to instruction pointers, which can translate to multiple inlined symbols.

Example using `perf` StackMode:

```
kprobe:ip_output { @[ustack(perf, 3)] = count(); }

/*
 * Sample output:
 * @[
 *  5649feec4090 readline+0 (/home/mmarchini/bash/bash/bash)
 *  5649fee2bfa6 yy_readline_get+451 (/home/mmarchini/bash/bash/bash)
 *  5649fee2bdc6 yy_getc+13 (/home/mmarchini/bash/bash/bash)
 * ]: 20
 */
```

Note that for these examples to work, bash had to be recompiled with frame pointers.


### usym
- `usym_t usym(uint64 * addr)`

**async**

**Supported probes**

* uprobes
* uretprobes

Equal to [ksym](#ksym) but resolves user space symbols.

If ASLR is enabled, user space symbolication only works when the process is running at either the time of the symbol resolution or the time of the probe attachment. The latter requires `BPFTRACE_CACHE_USER_SYMBOLS` to be set to `PER_PID`, and might not work with older versions of BCC. A similar limitation also applies to dynamically loaded symbols.

```
uprobe:/bin/bash:readline
{
  printf("%s\n", usym(reg("ip")));
}

/*
 * Sample output:
 * readline
 */
```


### warnf
- `void warnf(const string fmt, args...)`

**async**

`warnf()` formats and prints data (similar to [`printf`](#printf)) as an warning message with the source location. This respects the "--no-warnings" flag and will be silent if that is used.

```
BEGIN { warnf("Something kinda bad with args: %d, %s", 10, "arg2"); }
```

Prints:

```
EXPECT stdin:1:9-62: WARNING: Something kinda bad with args: 10, arg2
```


### write_user
- `bool write_user(T * dst, T * src, uint32 len)`

**unsafe**

Writes `len` bytes from BPF program memory at `src` to user-space address
`dst` using the BPF helper `bpf_probe_write_user`.

Returns true on success, or false on failure.

**Warning**: This can crash or corrupt the target process if used incorrectly.
Only use on user-space memory addresses belonging to the current task.
The kernel will print a warning to dmesg when this helper is used.

```
tracepoint:syscalls:sys_enter_openat
/comm == "myapp"/ {
  $new_path = "/tmp/redirected\0";
  if (write_user(args.filename, $new_path, 16)) {
    printf("redirected open for pid %d\n", pid);
  }
}
```


### zero
- `void zero(map m)`

**async**

Set all values (for all keys) in the map to zero.

### avg

* `avg_t avg(int64 n)`

Calculate the running average of `n` between consecutive calls.

```
interval:s:1 {
  @x++;
  @y = avg(@x);
  print(@x);
  print(@y);
}
```

Internally this keeps two values in the map: value count and running total.
The average is computed in user-space when printing by dividing the total by the
count. However, you can get the average in kernel space in expressions like
`if (@y == 5)` but this is expensive as bpftrace needs to iterate over all the
cpus to collect and sum BOTH count and total.

### count

* `count_t count()`

Count how often this function is called.

Using `@=count()` is conceptually similar to `@++`.
The difference is that the `count()` function uses a map type optimized for
performance and correctness using cheap, thread-safe writes ([PERCPU](./language.md#percpu-types)). However, sync reads
can be expensive as bpftrace needs to iterate over all the cpus to collect and
sum these values.

Note: This differs from "raw" writes (e.g. `@++`) where multiple writers to a
shared location might lose updates, as bpftrace does not generate any atomic instructions
for `++`.

Example one:
```
BEGIN {
  @ = count();
  @ = count();
  printf("%d\n", (int64)@);   // prints 2
  exit();
}
```

Example two:
```
interval:ms:100 {
  @ = count();
}

interval:s:10 {
  // async read
  print(@);
  // sync read
  if (@ > 10) {
    print(("hello"));
  }
  clear(@);
}
```

### hist

* `hist_t hist(int64 n[, int k])`

Create a log2 histogram of `n` using $2^k$ buckets per power of 2,
0 &lt;= k &lt;= 5, defaults to 0.

```
kretprobe:vfs_read {
  @bytes = hist(retval);
}
```

Prints:

```
@:
[1M, 2M)               3 |                                                    |
[2M, 4M)               2 |                                                    |
[4M, 8M)               2 |                                                    |
[8M, 16M)              6 |                                                    |
[16M, 32M)            16 |                                                    |
[32M, 64M)            27 |                                                    |
[64M, 128M)           48 |@                                                   |
[128M, 256M)          98 |@@@                                                 |
[256M, 512M)         191 |@@@@@@                                              |
[512M, 1G)           394 |@@@@@@@@@@@@@                                       |
[1G, 2G)             820 |@@@@@@@@@@@@@@@@@@@@@@@@@@@                         |
```

### lhist

* `lhist_t lhist(int64 n, int64 min, int64 max, int64 step)`

Create a linear histogram of `n`.
`lhist` creates `M` (`(max - min) / step`) buckets in the range `[min,max)` where each bucket is `step` in size.
Values in the range `(-inf, min)` and `(max, inf)` get their get their own bucket too, bringing the total amount of buckets created to `M+2`.

```
interval:ms:1 {
  @ = lhist(rand %10, 0, 10, 1);
}

interval:s:5 {
  exit();
}
```

Prints:

```
@:
[0, 1)               306 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         |
[1, 2)               284 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@            |
[2, 3)               294 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@          |
[3, 4)               318 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       |
[4, 5)               311 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        |
[5, 6)               362 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[6, 7)               336 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    |
[7, 8)               326 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      |
[8, 9)               328 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     |
[9, 10)              318 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       |
```

### max

* `max_t max(int64 n)`

Update the map with `n` if `n` is bigger than the current value held.
Similar to `count` this uses a [PERCPU](./language.md#percpu-types) map (thread-safe, fast writes, slow reads).

Note: this is different than the typical userspace `max()` in that bpftrace’s `max()`
only takes a single argument. The logical "other" argument to compare to is the value
in the map the "result" is being assigned to.

For example, compare the two logically equivalent samples (C++ vs bpftrace):

In C++:
```
int x = std::max(3, 33);  // x contains 33
```

In bpftrace:
```
@x = max(3);
@x = max(33);   // @x contains 33
```

Also note that bpftrace takes care to handle the unset case. In other words,
there is no default value. The first value you pass to `max()` will always
be returned.

### min

* `min_t min(int64 n)`

Update the map with `n` if `n` is smaller than the current value held.
Similar to `count` this uses a [PERCPU](./language.md#percpu-types) map (thread-safe, fast writes, slow reads).

See `max()` above for how this differs from the typical userspace `min()`.

### stats

* `stats_t stats(int64 n)`

`stats` combines the `count`, `avg` and `sum` calls into one.

```
kprobe:vfs_read {
  @bytes[comm] = stats(arg2);
}
```

```
@bytes[bash]: count 7, average 1, total 7
@bytes[sleep]: count 5, average 832, total 4160
@bytes[ls]: count 7, average 886, total 6208
@
```

### sum

* `sum_t sum(int64 n)`

Calculate the sum of all `n` passed.

Using `@=sum(5)` is conceptually similar to `@+=5`.
The difference is that the `sum()` function uses a map type optimized for
performance and correctness using cheap, thread-safe writes ([PERCPU](./language.md#percpu-types)). However, sync reads
can be expensive as bpftrace needs to iterate over all the cpus to collect and
sum these values.

Note: This differs from "raw" writes (e.g. `@+=5`) where multiple writers to a
shared location might lose updates, as bpftrace does not generate any implicit
atomic operations.

Example one:
```
BEGIN {
  @ = sum(5);
  @ = sum(6);
  printf("%d\n", (int64)@);   // prints 11
  clear(@);
  exit();
}
```

Example two:
```
interval:ms:100 {
  @ = sum(5);
}

interval:s:10 {
  // async read
  print(@);
  // sync read
  if (@ > 10) {
    print(("hello"));
  }
  clear(@);
}
```

### tseries

* `tseries_t tseries(int64 n, int64 interval_ns, int64 num_intervals)`
* `tseries_t tseries(int64 n, int64 interval_ns, int64 num_intervals, const string agg)`

Create a time series that tracks an integer value. `tseries` records up to
`num_intervals` intervals representing `interval_ns` nanoseconds.

#### Durations

`interval_ns` is an unsigned integer that specifies the interval duration. You
may use numbers with duration suffixes to improve readability:

```
@a = tseries(1, 100ns, 5); // 100 nanoseconds
@b = tseries(1, 100us, 5); // 100 microseconds
@c = tseries(1, 100ms, 5); // 100 milliseconds
@d = tseries(1, 1s, 5);    // 1 second
```

#### Aggregation Functions

By default, each interval in `tseries` contains the last value recorded in that
interval. The optional `agg` parameter specifies how values in the same interval
are aggregated.

| Aggregation Function | Example | Description |
| --- | --- | --- |
| `avg` | `@ = tseries(@v, 1s, 5, "avg")` | Calculate the running average of all the values in each interval. |
| `max` | `@ = tseries(@v, 1s, 5, "max")` | Calculate the maximum of all values in each interval. |
| `min` | `@ = tseries(@v, 1s, 5, "min")` | Calculate the minimum of all values in each interval. |
| `sum` | `@ = tseries(@v, 1s, 5, "sum")` | Calculate the sum of all values in each interval. |

#### Examples

Example one:

```
// Record the minimum of ten random values generated during each 100ms interval.
i:ms:10 {
  @ = tseries(rand % 10, 100ms, 20, "min");
}
```

```
Attached 2 probes


@:
             0                                                   2
hh:mm:ss.ms  |___________________________________________________|
10:41:46.700 *                                                   | 0
10:41:46.800 *                                                   | 0
10:41:46.900 |                         *                         | 1
10:41:47.000 |                                                   * 2
10:41:47.100 |                         *                         | 1
10:41:47.200 *                                                   | 0
10:41:47.300 |                         *                         | 1
10:41:47.400 *                                                   | 0
10:41:47.500 |                         *                         | 1
10:41:47.600 *                                                   | 0
10:41:47.700 |                                                   * 2
10:41:47.800 *                                                   | 0
10:41:47.900 *                                                   | 0
10:41:48.000 |                         *                         | 1
10:41:48.100 |                         *                         | 1
10:41:48.200 |                         *                         | 1
10:41:48.300 *                                                   | 0
10:41:48.400 |                                                   * 2
10:41:48.500 |                         *                         | 1
10:41:48.600 |                         *                         | 1
             v___________________________________________________v
             0                                                   2
```

Example two:

```
// Create a zigzag pattern
BEGIN {
  @dir = 1;
  @c = -5;
}

i:ms:100 {
  @ = tseries(@c, 100ms, 20);
  @c += @dir;

  if (@c > 5) {
    @dir = -1;
    @c = 4
  } else if (@c < -5) {
    @dir = 1;
    @c = -4;
  }
}
```

```
Attached 2 probes


@:
             -5                                                  5
hh:mm:ss.ms  |___________________________________________________|
10:39:49.300 *                         .                         | -5
10:39:49.400 |    *                    .                         | -4
10:39:49.500 |         *               .                         | -3
10:39:49.600 |              *          .                         | -2
10:39:49.700 |                   *     .                         | -1
10:39:49.800 |                         *                         | 0
10:39:49.900 |                         .    *                    | 1
10:39:50.000 |                         .         *               | 2
10:39:50.100 |                         .              *          | 3
10:39:50.200 |                         .                   *     | 4
10:39:50.300 |                         .                         * 5
10:39:50.400 |                         .                   *     | 4
10:39:50.500 |                         .              *          | 3
10:39:50.600 |                         .         *               | 2
10:39:50.700 |                         .    *                    | 1
10:39:50.800 |                         *                         | 0
10:39:50.900 |                   *     .                         | -1
10:39:51.000 |              *          .                         | -2
10:39:51.100 |         *               .                         | -3
10:39:51.200 |    *                    .                         | -4
             v___________________________________________________v
             -5                                                  5
```

### END
