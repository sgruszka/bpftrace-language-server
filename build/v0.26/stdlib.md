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

### memcmp
- `int memcmp(left, right, uint64 count)`

Compares the first 'count' bytes of two expressions.
0 is returned if they are the same.
negative value if the first differing byte in left is less
than the corresponding byte in right.



### pcomm
- `string pcomm()`
- `string pcomm`
- `string pcomm(struct task_struct * task)`

Get the name of the parent process for the passed task or the current task if called without arguments.
This is an alias for `task.real_parent.comm`, which is different than `task.group_leader.comm`, which you can get from calling `leader_comm()`.


### probetype
- `string probetype()`
- `string probetype`

Name of the probe type.
Note: `begin` and `end` probes are of type `special`.

For example: `kprobe`, `special`, `tracepoint`


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


### static_assert
- `void static_assert(bool condition, string msg)`

Assert something is true or fail the build.


### strcap
- `int64 strcap(string exp)`
- `int64 strcap(int8 exp[])`
- `int64 strcap(int8 *exp)`

Returns the "capacity" of a string-like object.

In most cases this is the same as the length, but for bpftrace-native
strings and arrays, this is the underlying object capacity. This is used to
bound searches and lookups without needing to scan the string itself.


### strlen
- `uint64 strlen(string exp)`
- `uint64 strlen(int8 exp[])`
- `uint64 strlen(int8 *exp)`

Returns the length of a string-like object.


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


### END
