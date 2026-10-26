<!--
This file originates from https://github.com/bpftrace/bpftrace
It is licensed under the Apache License, Version 2.0
See the LICENSE file of that project or https://www.apache.org/licenses/LICENSE-2.0
-->

### abs_path [0.28..]
Resolves a relative path or filename to an absolute path.

- `string abs_path(string path, uint64 max_path_depth)`

If `path` is empty, the returned string is empty.

**Example**
```
tracepoint:syscalls:sys_enter_openat {
  print(abs_path(str(args.filename), 32));
}
```

See also `cwd`.

**Availability**
Since bpftrace v0.28

### arch [0.28..]
Returns the architecture bpftrace was built for.

- `string arch()`
- `string arch`

**compile time**

The result is one of: `x86_64`, `arm64`, `arm`, `s390x`, `ppc64le`, `ppc64`,
`mips64`, `riscv64`, or `loongarch64`.

This describes the architecture of the bpftrace binary, which may differ from
the architecture reported by `uname -m`. For example, a 32-bit ARM build on an
arm64 kernel returns `arm`.

**Availability**
Since bpftrace v0.28

### assert [0.24..]
Terminates the script with an error code if a condition is false.

- `void assert(bool condition, string message)`

**Availability**
Since bpftrace v0.24

### assert_str [0.25..]
Checks that this value is string-like.

- `void assert_str(any expression)`

**Availability**
Since bpftrace v0.25

### bswap [0.15..]
Reverses the byte order of an integer.

- `uint8 bswap(uint8 n)`
- `uint16 bswap(uint16 n)`
- `uint32 bswap(uint32 n)`
- `uint64 bswap(uint64 n)`

In case of 8 bit integers, `n` is returned without being modified. The return
type is an unsigned integer of the same width as `n`.

**Availability**
Since bpftrace v0.15

### buf [0.11..]
Reads bytes from an address into a buffer.

- `buffer buf(void * data, [int64 length])`

`buf` reads `length` amount of bytes from address `data`. The maximum value of
`length` is limited to the `BPFTRACE_MAX_STRLEN` variable. For arrays the
`length` is optional, it is automatically inferred from the signature.

`buf` is address space aware and will call the correct helper based on the
address space associated with `data`.

The `buffer` object returned by `buf` can safely be printed as a hex encoded
string with the `%r` format specifier.

Bytes with values >=32 and <=126 are printed using their ASCII character, other
bytes are printed in hex form (e.g. `\x00`). The `%rx` format specifier can be
used to print everything in hex form, including ASCII characters. The similar
`%rh` format specifier prints everything in hex form without `\x` and with
spaces between bytes (e.g. `0a fe`).

**Example**
```
interval:s:1 {
  printf("%r\n", buf(kaddr("avenrun"), 8));
  // Example output:
  // \x00\x03\x00\x00\x00\x00\x00\x00
  // \xc2\x02\x00\x00\x00\x00\x00\x00
}
```

**Availability**
Since bpftrace v0.11

### cat [..]
Prints the contents of a file to standard output.

- `void cat(string namefmt, [...args])`

**async**

Dump the contents of the named file to stdout. `cat` supports the same format
string and arguments that `printf` does. If the file cannot be opened or read an
error is printed to stderr.

**Example**
```
tracepoint:syscalls:sys_enter_execve {
  cat("/proc/%d/maps", pid);
  // Sample output:
  // 55f683ebd000-55f683ec1000 r--p 00000000 08:01 1843399     /usr/bin/ls
  // 55f683ec1000-55f683ed6000 r-xp 00004000 08:01 1843399     /usr/bin/ls
  // 55f683ed6000-55f683edf000 r--p 00019000 08:01 1843399     /usr/bin/ls
  // 55f683edf000-55f683ee2000 rw-p 00021000 08:01 1843399     /usr/bin/ls
  // 55f683ee2000-55f683ee3000 rw-p 00000000 00:00 0
}
```

### cgroup [..]
Returns the current process's cgroup ID.

- `uint64 cgroup()`
- `uint64 cgroup`

Only works with cgroupv2. This utilizes the BPF helper
`bpf_get_current_cgroup_id`.

### cgroup_path [0.15..]
Converts a cgroup ID to its path.

- `cgroup_path_t cgroup_path(int cgroupid, string filter)`

This is done asynchronously in userspace when the `cgroup_path` value is
printed, therefore it can resolve to a different value if the cgroup id gets
reassigned. This also means that the returned value can only be used for
printing.

A string literal may be passed as an optional second argument to filter cgroup
hierarchies in which the cgroup id is looked up by a wildcard expression
(cgroup2 is always represented by "unified", regardless of where it is mounted).

The currently mounted hierarchy at /sys/fs/cgroup is used to do the lookup. If
the cgroup with the given id isn’t present here (e.g. when running in a Docker
container), the cgroup path won’t be found (unlike when looking up the cgroup
path of a process via /proc/.../cgroup).

```
BEGIN {
  $cgroup_path = cgroup_path(3436);
  print($cgroup_path);
  print($cgroup_path); /* This may print a different path */
  printf("%s %s", $cgroup_path, $cgroup_path); /* This may print two different paths */
}
```

**Availability**
Since bpftrace v0.15

### cgroupid [0.10..]
Returns the cgroup v2 ID for a cgroup path.

- `uint64 cgroupid(const string path)`

**compile time**

```
BEGIN {
  print(cgroupid("/sys/fs/cgroup/system.slice"));
}
```

**Availability**
Since bpftrace v0.10

### clear [..]
Clear all keys/values from a map.

- `void clear(map m)`

**async**

**Example**
```
interval:ms:100 {
  @[rand % 10] = count();
}

interval:s:10 {
  print(@);
  clear(@);
}
```

### comm [..0.23]
Name of the current thread.

- `string comm`

This utilizes the BPF helper `bpf_get_current_comm`.

### comm [0.24..0.24]
Returns the name of the current thread.

- `string comm()`
- `string comm`

This utilizes the BPF helper `bpf_get_current_comm`.

### comm [0.25..]
Returns the name of the current thread or a specified process.

- `string comm()`
- `string comm`
- `string comm(uint32 pid)`

This uses the BPF helper `bpf_get_current_comm` for `comm()` or the kfunc
`bpf_task_from_pid` for `comm(pid)`.

### config [0.27..]
Returns the current bpftrace configuration.

- `Record config()`
- `Record config`

Returns a `Record` containing the current `bpftrace` configuration settings.
[List of config variables][doc1]

[doc1]: https://bpftrace.org/docs/release_027/language#config-variables

**Example**
```bpftrace
begin {
  printf("max_strlen: %d, stack_mode: %s\n", config.max_strlen, config.stack_mode);
}
```

**Availability**
Since bpftrace v0.27

### container_of [0.27..]
Finds the containing object from a pointer to one of its members.

- `Container* container_of(Member* ptr, Type type, Identifier member)`

**Availability**
Since bpftrace v0.27

### cpid [..0.23]
Child process ID when bpftrace was started with `-c`.

- `uint32 cpid`

### cpid [0.24..]
Returns the child process ID when bpftrace was started with `-c`.

- `uint32 cpid()`
- `uint32 cpid`

If there is no child process, a runtime warning will be issued and the return
value will be zero. This warning can be avoided by using `has_cpid` to check if
`cpid` has a value, prior to referencing `cpid`.

### cpu [..0.23]
ID of the CPU running the current BPF program.

- `uint32 cpu`

The BPF program corresponds to the probe's action body. This utilizes the BPF
helper `bpf_get_smp_processor_id`.

### cpu [0.24..]
Returns the ID of the CPU running the current BPF program.

- `uint32 cpu()`
- `uint32 cpu`

The BPF program corresponds to the probe's action body. This utilizes the BPF
helper `bpf_get_smp_processor_id`.

### curtask [0.22..0.23]
Pointer to the current task's `task_struct`.

- `uint64 curtask`

This utilizes the BPF helper `get_current_task`.

**Availability**
Since bpftrace v0.22

### curtask [0.24..0.27]
Returns a pointer to the current task's `task_struct`.

- `uint64 curtask()`
- `uint64 curtask`

This utilizes the BPF helper `get_current_task`.

**Availability**
Since bpftrace v0.22

### curtask [0.28..]
Returns a pointer to the current task's `task_struct`.

- `struct task_struct * curtask()`
- `struct task_struct * curtask`

This utilizes the BPF helper `bpf_get_current_task_btf`.

**Availability**
Since bpftrace v0.22

### cwd [0.28..]
Get the current working directory.

- `string cwd()`
- `string cwd`
- `string cwd(max_path_depth)`

**Availability**
Since bpftrace v0.28

### default_str_length [0.25..]
Returns the default unbounded length.

- `uint64 default_str_length()`
- `uint64 default_str_length`

**Availability**
Since bpftrace v0.25

### delete [..]
Removes one key and its value from a map.

- `bool delete(map m, mapkey k)`
- deprecated `bool delete(mapkey k)`

For scalar maps (e.g. no explicit keys), the key is omitted and is equivalent to
calling `clear`. For map keys that are composed of multiple values (e.g.
`@mymap[3, "hello"] = 1` - remember these values are represented as a tuple) the
syntax would be: `delete(@mymap, (3, "hello"));`.

If deletion fails (e.g. the key doesn’t exist) the function returns false (0).
If the return value of `delete` isn't used, you will get a compile-time warning,
whether or not the deletion succeeds. Use `_ = delete(...)` to discard it without
a warning.

**Examples**
```
@a[1] = 1;
delete(@a, 1); // warning (return value is discarded)
if (delete(@a, 2)) { // no warning (return value is used)
  // ...
}
$did_delete = delete(@a, 2); // no warning (return value is used)
_ = delete(@a, 2); // no warning (return value is explicitly discarded)
```

The, now deprecated, API (supported in version &lt;= 0.21.x) of passing map
arguments with the key is still supported: e.g. `delete(@mymap[3, "hello"]);`.

```
kprobe:dummy {
  @scalar = 1;
  delete(@scalar); // ok
  @single["hello"] = 1;
  delete(@single, "hello"); // ok
  @associative[1,2] = 1;
  delete(@associative, (1,2)); // ok
  delete(@associative); // error
  delete(@associative, 1); // error

  // deprecated but ok
  delete(@single["hello"]);
  delete(@associative[1, 2]);
}
```

### dw_ustack [0.26..]
Unwinds and returns a user-space stack using DWARF debug information.

- `ustack_t dw_ustack([StackMode mode, ][int limit])`

DWARF-based user-space stack unwinding. Unlike `ustack` which relies on frame
pointers, `dw_ustack` uses DWARF `.eh_frame` debug information to unwind the
stack. This makes it possible to collect complete user-space stack traces from
programs compiled without frame pointers.

The signature and output format are the same as `ustack`.

Bpftrace needs to read the DWARF information for the target processes at
startup. For this, one or more pids have to be specified. This can either be
done via `-p`, `-c` (implicitly) or `--dwarf-pid`. If `dw_ustack` cannot find
unwind information for a process, a runtime warning is emitted.

`dw_ustack` is currently only available on `x86_64`.

**Unstable feature**

`dw_ustack` is an unstable feature. By default a warning is printed when it is
used. Set the config flag to suppress the warning or to make it an error:

```
config = { unstable_dw_ustack=enable }
```

For usage examples see
[ustack](https://bpftrace.org/docs/release_026/stdlib#ustack).

**Availability**
Since bpftrace v0.26

### elapsed [..]
Returns nanoseconds since bpftrace initialization.

- `uint64 elapsed()`
- `uint64 elapsed`

### errorf [0.24..]
Formats and prints an error message with its source location.

- `void errorf(const string fmt, args...)`

**async**

`errorf()` formats and prints data (similar to `printf`) as an error message
with the source location.

**Example**
```
BEGIN { errorf("Something bad with args: %d, %s", 10, "arg2"); }
// Prints:
// stdin:1:9-62: ERROR: Something bad with args: 10, arg2
```

**Availability**
Since bpftrace v0.24

### exit [..]
Terminates bpftrace with an optional exit code.

- `void exit([int code])`

**async**

Terminate bpftrace, as if a `SIGTERM` was received. The `END` probe will still
trigger (if specified) and maps will be printed. An optional exit code can be
provided.

**Example**
```
BEGIN {
  exit(1);
}
```

### fail [0.25..]
Reports a compile-time error and halts compilation when reached.

- `void fail(const string fmt, args...)`

**compile time**

`fail()` formats and prints data (similar to `printf`) as an error message with
the source location but, as opposed to `errorf`, is treated like a static assert
and halts compilation if it is visited. All args have to be literals since they
are evaluated at compile time.

**Example**
```
BEGIN {
  if ($1 < 2) {
    fail("Expected the first positional param to be greater than 1. Got %d", $1);
  }
}
```

**Availability**
Since bpftrace v0.25

### find [0.25..]
Looks up a map key and stores its value in a scratch variable if found.

- `boolean find(map m, mapkey k, mapvalue result)`

Return `true` if the key exists in this map and sets the passed scratch variable
(result) to the value of that map key. Otherwise return `false` and don't mutate
result. Use this instead of `has_key` and a map access to avoid an additional
map lookup. Error if called with a map that has no keys (aka scalar map).

**Example**
```
kprobe:dummy_probe {
  @map[2] = (1, "hello");
  let $val;
  if (find(@map, 2, $val)) {
    print($val); // prints (1, "hello")
  }
}
```

**Availability**
Since bpftrace v0.25

### func [..0.23]
Name of the current function being traced (kprobes,uprobes,fentry).

- `string func`

**Supported probes**
* kprobe
* kretprobe
* uprobe
* uretprobe
* fentry
* fexit

### func [0.24..0.26]
Name of the current function being traced (kprobes,uprobes,fentry).

- `string func()`
- `string func`

**Supported probes**
* kprobe
* kretprobe
* uprobe
* uretprobe
* fentry
* fexit

### func [0.27..]
Name of the current function being traced (kprobes,uprobes,fentry).

- `ksym_t func()`
- `ksym_t func`
- `usym_t func()`
- `usym_t func`

**Supported probes**
* kprobe
* kretprobe
* uprobe
* uretprobe
* fentry
* fexit

### getopt [0.24..0.24]
Reads a named command-line option.

- `bool getopt(string arg_name)`
- `string getopt(string arg_name, string default_value)`
- `int getopt(string arg_name, int default_value)`
- `bool getopt(string arg_name, bool default_value)`

Get the named command line argument/option e.g.

`getopt` defines the type of the argument by the default value’s type. If no
default type is provided, the option is treated like a boolean arg e.g.
`getopt("hello")` would evaluate to `false` if `--hello` is not specified on the
command line or `true` if `--hello` is passed or set to one of the following
values: `true`, `1`. Additionally, boolean args accept the following false
values: `0`, `false` e.g. `--hello=false`. If the arg is not set on the command
line, the default value is used.

**Example**
```sh
# bpftrace -e 'BEGIN { print(getopt("hello", 1)); }' -- --hello=5
```

```sh
# bpftrace -e 'BEGIN { print((getopt("aa", 10), getopt("bb", "hello"), getopt("cc"), getopt("dd", false))); }' -- --cc --bb=bye

```

**Availability**
Since bpftrace v0.24

### getopt [0.25..]
Reads a named command-line option.

- `bool getopt(string arg_name)`
- `bool getopt(string arg_name, bool default_value, [string description])`
- `int getopt(string arg_name, int default_value, [string description])`
- `string getopt(string arg_name, string default_value, [string description])`

Get the named command line argument/option e.g.

`getopt` defines the type of the argument by the default value’s type. If no
default type is provided, the option is treated like a boolean arg e.g.
`getopt("hello")` would evaluate to `false` if `--hello` is not specified on the
command line or `true` if `--hello` is passed or set to one of the following
values: `true`, `1`.

Additionally, boolean args accept the following false values: `0`, `false` e.g.
`--hello=false`. If the arg is not set on the command line, the default value is
used. `getopt` calls may optionally specify a string with the argument
description (except for a boolean arg without a default value).

You can use `--help` to see all named arguments/options.

**Examples**
```
# bpftrace -e 'BEGIN { print(getopt("hello", 1, "Description of hello")); }' -- --hello=5

```
```
# bpftrace -e 'BEGIN { print((getopt("aa", 10, "Description of aa"), getopt("bb", "hello"), getopt("cc"), getopt("dd", false))); }' -- --cc --bb=bye

```

**Availability**
Since bpftrace v0.24

### gid [..0.23]
Group ID of the current thread in the initial namespace.

- `uint64 gid`

This utilizes the BPF helper `bpf_get_current_uid_gid`.

### gid [0.24..]
Returns the current thread's group ID in the initial namespace.

- `uint64 gid()`
- `uint64 gid`

This utilizes the BPF helper `bpf_get_current_uid_gid`.

### has_cpid [0.25..]
Returns whether a child process ID is available.

- `bool has_cpid()`
- `bool has_cpid`

**Availability**
Since bpftrace v0.25

### has_key [0.22..0.24]
Returns whether a map contains a specified key.

- `boolean has_key(map m, mapkey k)`

Return true (1) if the key exists in this map. Otherwise return false (0). Error
if called with a map that has no keys (aka scalar map). Return value can also be
used for scratch variables and map keys/values.

**Example**
```
kprobe:dummy {
  @associative[1,2] = 1;
  if (!has_key(@associative, (1,3))) { // ok
    print(("bye"));
  }

  @scalar = 1;
  if (has_key(@scalar)) { // error
    print(("hello"));
  }

  $a = has_key(@associative, (1,2)); // ok
  @b[has_key(@associative, (1,2))] = has_key(@associative, (1,2)); // ok
}
```

**Availability**
Since bpftrace v0.22

### has_key [0.25..]
Returns whether a map contains a specified key.

- `boolean has_key(map m, mapkey k)`

Return `true` if the key exists in this map. Otherwise return `false`. Error if
called with a map that has no keys (aka scalar map).

**Example**
```
kprobe:dummy {
  @associative[1,2] = 1;
  if (!has_key(@associative, (1,3))) { // ok
    print(("bye"));
  }

  @scalar = 1;
  if (has_key(@scalar)) { // error
    print(("hello"));
  }
}
```

**Availability**
Since bpftrace v0.22

### is_array [0.25..]
Determine whether the given expression is an array.

- `bool is_array(any expression)`

**Availability**
Since bpftrace v0.25

### is_err [0.26..]
Checks whether a pointer encodes a kernel error.

- `bool is_err(void * ptr)`

Returns true if the pointer is an `ERR_PTR`, i.e. it encodes a kernel error code.

In the Linux kernel, some functions return error codes encoded as pointers using
the `ERR_PTR` macro. These are pointer values in the range
`(unsigned long)(-4095)` to `(unsigned long)(-1)`.

This is equivalent to the kernel's `IS_ERR()` macro.

**Example**
```
fexit:do_filp_open {
  if (is_err(retval)) {
    printf("error: %ld\n", (int64)retval);
  }
}
```

**Availability**
Since bpftrace v0.26

### is_integer [0.25..]
Determine whether the given expression is an integer.

- `bool is_integer(any expression)`

**Availability**
Since bpftrace v0.25

### is_literal [0.25..]
Returns true if the passed expression is a literal, e.g. `1`, `true`, `"hello"`.

- `bool is_literal(Expression expr)`

**Availability**
Since bpftrace v0.25

### is_ptr [0.25..]
Determine whether the given expression is a pointer.

- `bool is_ptr(any expression)`

**Availability**
Since bpftrace v0.25

### is_str [0.25..]
Determine whether the given expression is a string.

- `bool is_str(any expression)`

**Availability**
Since bpftrace v0.25

### is_unsigned_integer [0.25..]
Determine whether the given expression is an unsigned integer.

- `bool is_unsigned_integer(any expression)`

**Availability**
Since bpftrace v0.25

### jiffies [0.20..0.23]
Kernel jiffies counter.

- `uint64 jiffies`

On 32-bit systems, using this builtin might be slower. This utilizes the BPF
helper `bpf_jiffies64`.

**Availability**
Since bpftrace v0.20

### jiffies [0.24..]
Returns the kernel jiffies counter.

- `uint64 jiffies()`
- `uint64 jiffies`

On 32-bit systems, using this builtin might be slower. This utilizes the BPF
helper `bpf_jiffies64`.

**Availability**
Since bpftrace v0.20

### join [..]
Joins an array of strings with a separator and prints the result.

- `void join(char *arr[], [char * sep = ' '])`

**async**

`join` joins a `arr` with `sep` as separator into one string. This string will
be printed to stdout directly, it cannot be used as string value.

The concatenation of the array members is done in BPF and the printing happens
in userspace.

**Example**
```
tracepoint:syscalls:sys_enter_execve {
  join(args.argv);
}
```

### kaddr [..]
Returns the address of a kernel symbol.

- `uint64 kaddr(const string name)`

**compile time**

**Example**
```
interval:s:1 {
  $avenrun = kaddr("avenrun");
  $load1 = *$avenrun;
}
```

You can find all kernel symbols at `/proc/kallsyms`.

### kfunc_allowed [0.25..]
Determine if a kfunc is supported for particular probe types.

- `boolean kfunc_allowed(const string kfunc)`

Argument kfunc must be string literal.

**Availability**
Since bpftrace v0.25

### kfunc_exist [0.25..]
Determine if a kfunc exists using BTF.

- `boolean kfunc_exist(const string kfunc)`

Argument kfunc must be string literal.

**Availability**
Since bpftrace v0.25

### kptr [0.12..]
Marks a pointer as pointing to kernel address space.

- `T * kptr(T * ptr)`

The pointer type is left unchanged.

For more information see
[Address Spaces](https://bpftrace.org/docs/release_026/language#address-spaces).

**Availability**
Since bpftrace v0.12

### kstack [..0.24]
Returns a kernel stack trace.

- `kstack_t kstack([StackMode mode, ][int limit])`

These are implemented using BPF stack maps.

**Examples**
```
kprobe:ip_output { @[kstack()] = count(); }
/*
 * Sample output:
 * @[
 *  ip_output+1
 *  tcp_transmit_skb+1308
 *  tcp_write_xmit+482
 *  tcp_release_cb+225
 *  release_sock+64
 *  tcp_sendmsg+49
 *  sock_sendmsg+48
 *  sock_write_iter+135
 *   __vfs_write+247
 *  vfs_write+179
 *  sys_write+82
 *   entry_SYSCALL_64_fastpath+30
 * ]: 1708
 */
```

Sampling only three frames from the stack (limit = 3):

```
kprobe:ip_output { @[kstack(3)] = count(); }
/*
 * Sample output:
 * @[
 *  ip_output+1
 *  tcp_transmit_skb+1308
 *  tcp_write_xmit+482
 * ]: 1708
 */
```

You can also choose a different output format. Available formats are `bpftrace`,
`perf`, and `raw` (no symbolication):

```
kprobe:ip_output { @[kstack(perf, 3)] = count(); }
/*
 * Sample output:
 * @[
 *  ffffffffb4019501 do_mmap+1
 *  ffffffffb401700a sys_mmap_pgoff+266
 *  ffffffffb3e334eb sys_mmap+27
 * ]: 1708
 */
```

### kstack [0.25..0.26]
Returns a kernel stack trace.

- `kstack_t kstack([StackMode mode, ][int limit])`

These are implemented using BPF stack maps.

**Examples**
```
kprobe:ip_output { @[kstack()] = count(); }
/*
 * Sample output:
 * @[
 *  ip_output+1
 *  tcp_transmit_skb+1308
 *  tcp_write_xmit+482
 *  tcp_release_cb+225
 *  release_sock+64
 *  tcp_sendmsg+49
 *  sock_sendmsg+48
 *  sock_write_iter+135
 *   __vfs_write+247
 *  vfs_write+179
 *  sys_write+82
 *   entry_SYSCALL_64_fastpath+30
 * ]: 1708
 */
```

Sampling only three frames from the stack (limit = 3):

```
kprobe:ip_output { @[kstack(3)] = count(); }

/*
 * Sample output:
 * @[
 *  ip_output+1
 *  tcp_transmit_skb+1308
 *  tcp_write_xmit+482
 * ]: 1708
 */
```

Note: If a limit is used and `show_debug_info` is enabled then the number of
symbolized frames might exceed that limit in the output as `limit` refers to
instruction pointers, which can translate to multiple inlined symbols.

You can also choose a different output format. Available formats are `bpftrace`,
`perf`, and `raw` (no symbolication):

```
kprobe:ip_output { @[kstack(perf, 3)] = count(); }
/*
 * Sample output:
 * @[
 *  ffffffffb4019501 do_mmap+1
 *  ffffffffb401700a sys_mmap_pgoff+266
 *  ffffffffb3e334eb sys_mmap+27
 * ]: 1708
 */
```

### kstack [0.27..]
Returns a kernel stack trace.

- `kstack_t kstack([StackMode mode, ][int limit])`

There are several [formatting/StackMode options][doc2].

[doc2]: https://bpftrace.org/docs/release_026/language#stack_mode

**Examples**
```
kprobe:ip_output { @[kstack()] = count(); }

/*
 * Sample output:
 * @[
 *  ip_output+1
 *  tcp_transmit_skb+1308
 *  tcp_write_xmit+482
 *  tcp_release_cb+225
 *  release_sock+64
 *  tcp_sendmsg+49
 *  sock_sendmsg+48
 *  sock_write_iter+135
 *   __vfs_write+247
 *  vfs_write+179
 *  sys_write+82
 *   entry_SYSCALL_64_fastpath+30
 * ]: 1708
 */
```

Sampling only three frames from the stack (limit = 3):

```
kprobe:ip_output { @[kstack(3)] = count(); }

/*
 * Sample output:
 * @[
 *  ip_output+1
 *  tcp_transmit_skb+1308
 *  tcp_write_xmit+482
 * ]: 1708
 */
```

Note: If a limit is used and `show_debug_info` is enabled then the number of
symbolized frames might exceed that limit in the output as `limit` refers to
instruction pointers, which can translate to multiple inlined symbols.

Example using `perf` StackMode:
```
kprobe:ip_output { @[kstack(perf, 3)] = count(); }

/*
 * Sample output:
 * @[
 *  ffffffffb4019501 do_mmap+1
 *  ffffffffb401700a sys_mmap_pgoff+266
 *  ffffffffb3e334eb sys_mmap+27
 * ]: 1708
 */
```

### ksym [..]
Resolves a kernel address to the name of its containing function.

- `ksym_t ksym(uint64 addr)`

**async**

Retrieve the name of the function that contains address `addr`. The address to
name mapping happens in user-space.

The `ksym_t` type can be printed with the `%s` format specifier.

**Example**
```
kprobe:do_nanosleep
{
  printf("%s\n", ksym(reg("ip"))); // Prints: do_nanosleep
}
```

### leader_comm [0.26..]
Returns the name of the thread group leader.

- `string leader_comm()`
- `string leader_comm`
- `string leader_comm(struct task_struct * task)`

Get the thread name of the thread group leader for the passed task or the
current task if called without arguments. This is an alias for
`task.group_leader.comm`, which is different than `task.real_parent.comm`, which
you can get from calling `pcomm()`. See `pcomm()` for more details.

**Availability**
Since bpftrace v0.26

### leader_tid [0.26..]
Returns the thread ID of the thread group leader.

- `string leader_tid()`
- `string leader_tid`
- `string leader_tid(struct task_struct * task)`

Get the thread id of the thread group leader for the passed task or the current
task if called without arguments. This is an alias for `task.group_leader.pid`,
which is different than `task.real_parent.pid`, which you can get from calling
`ppid()`. See `ppid()` for more details.

**Availability**
Since bpftrace v0.26

### len [0.20..]
Returns the number of map entries or the depth of a stack trace.

- `int64 len(map m)`
- `int64 len(ustack stack)`
- `int64 len(kstack stack)`

For maps, return the number of elements in the map. For kstack/ustack, return
the depth (measured in # of frames) of the call stack.

**Availability**
Since bpftrace v0.20

### macaddr [0.12..]
Creates a printable buffer from a MAC address.

- `macaddr_t macaddr(char [6] mac)`

This buffer can be printed in the canonical string format using the `%s` format
specifier.

**Example**
```
kprobe:arp_create {
  $stack_arg0 = *(uint8*)(reg("sp") + 8);
  $stack_arg1 = *(uint8*)(reg("sp") + 16);
  printf("SRC %s, DST %s\n", macaddr($stack_arg0), macaddr($stack_arg1));
}
/*
 * Sample output:
 * SRC 18:C0:4D:08:2E:BB, DST 74:83:C2:7F:8C:FF
 */
```

**Availability**
Since bpftrace v0.12

### memcmp [0.25..]
Compares a specified number of bytes.

- `int memcmp(left, right, uint64 count)`

Compares the first `count` bytes of `left` and `right`. Returns zero if they
match. Otherwise, returns a negative value if the first differing byte in `left`
is smaller, or a positive value if it is larger.

**Availability**
Since bpftrace v0.25

### ncpus [0.24..]
Number of CPUs.

- `uint64 ncpus()`
- `uint64 ncpus`

**Availability**
Since bpftrace v0.24

### nsecs [..]
Returns a timestamp in nanoseconds.

- `timestamp nsecs([TimestampMode mode])`
- `timestamp nsecs`

Timestamp modes: `monotonic`, `boot`, `tai`, `sw_tai`.

Returns a timestamp in nanoseconds, as given by the requested kernel clock.
Defaults to `boot` if no clock is explicitly requested.


**Example**
```
interval:s:1 {
  $sw_tai1 = nsecs(sw_tai);
  $tai = nsecs(tai);
  $sw_tai2 = nsecs(sw_tai);
  printf("sw_tai precision: %lldns\n", ($sw_tai1 + $sw_tai2)/2 - $tai);
}
/*
 * Sample output:
 * sw_tai precision: -98ns
 * sw_tai precision: -99ns
 * ...
 */
```

### ntop [0.12..]
Converts an IPv4 or IPv6 address to its text representation.

- `inet ntop([int64 af, ] int addr)`
- `inet ntop([int64 af, ] char addr[4])`
- `inet ntop([int64 af, ] char addr[16])`

`ntop` will infer the address type (IPv4 or IPv6) based on the `addr` type and
size. If an integer or `char[4]` is given, ntop assumes IPv4, if a `char[16]` is
given, ntop assumes IPv6. You can also pass the address type (e.g. `AF_INET`)
explicitly as the first parameter.

**Availability**
Since bpftrace v0.12

### numaid [0.16..0.23]
ID of the NUMA node running the current BPF program.

- `uint32 numaid`

This utilizes the BPF helper `bpf_get_numa_node_id`.

**Availability**
Since bpftrace v0.16

### numaid [0.24..]
Returns the ID of the NUMA node running the current BPF program.

- `uint32 numaid()`
- `uint32 numaid`

This utilizes the BPF helper `bpf_get_numa_node_id`.

**Availability**
Since bpftrace v0.16

### offsetof [0.18..]
Returns the byte offset of a field within a type.

- `uint64 offsetof(STRUCT, FIELD[.SUBFIELD])`
- `uint64 offsetof(EXPRESSION, FIELD[.SUBFIELD])`

**compile time**

Returns the offset, in bytes, of a field within a struct. Like the kernel's
`offsetof` operator, it supports any number of nested fields.

**Example**
```
struct Foo {
  struct {
    struct {
      struct {
        int d;
      } c;
    } b;
  } a;
}
BEGIN {
  @x = offsetof(struct Foo, a.b.c.d);
  exit();
}
```

**Availability**
Since bpftrace v0.18

### override [..]
Prevents a probed function from running and supplies its return value.

- `void override(uint64 rc)`

**unsafe**

When using `override` the probed function will not be executed and instead `rc`
will be returned. This utilizes the BPF helper `bpf_override_return`.

**Supported probes**
* kprobe

This feature only works on kernels compiled with `CONFIG_BPF_KPROBE_OVERRIDE`
and only works on functions tagged `ALLOW_ERROR_INJECTION`.

bpftrace does not test whether error injection is allowed for the probed
function, instead it will fail to load the program into the kernel:

```
ioctl(PERF_EVENT_IOC_SET_BPF): Invalid argument
Error attaching probe: 'kprobe:vfs_read'
```

**Example**
```
kprobe:__x64_sys_getuid /comm == "id"/ {
  override(2<<21);
}
// uid=4194304 gid=0(root) euid=0(root) groups=0(root)
```

**Availability**
Since kernel v4.16

### path [0.12..]
Resolves a kernel path to a string.

- `char * path(struct path * path [, int32 size])`

This utilizes the BPF helper `bpf_d_path`.

Return full path referenced by struct path pointer in argument. If `size` is
set, the path will be clamped by `size` otherwise `BPFTRACE_MAX_STRLEN` is used.

If `size` is smaller than the resolved path, the resulting string will be
truncated at the front rather than at the end.

This function can only be used by functions that are allowed to, these functions
are contained in the `btf_allowlist_d_path` set in the kernel.

**Availability**
Since bpftrace v0.12
Since kernel v5.10

### pcomm [0.25..0.25]
Returns the name of the thread group leader.

- `string pcomm()`
- `string pcomm`
- `string pcomm(struct task_struct * task)`

Uses the supplied task, or the current task when called without arguments. This
is an alias for `task.group_leader.comm`.

**Availability**
Since bpftrace v0.25

### pcomm [0.26..]
Returns the name of the parent process.

- `string pcomm()`
- `string pcomm`
- `string pcomm(struct task_struct * task)`

Get the name of the parent process for the passed task or the current task if
called without arguments. This is an alias for `task.real_parent.comm`, which is
different than `task.group_leader.comm`, which you can get from calling
`leader_comm()`.

**Availability**
Since bpftrace v0.26

### percpu_kaddr [0.22..0.24]
Returns the address of a per-CPU kernel symbol.

- `uint64 *percpu_kaddr(const string name)`
- `uint64 *percpu_kaddr(const string name, int cpu)`

**sync**

Get the address of the percpu kernel symbol `name` for CPU `cpu`. When `cpu` is
omitted, the current CPU is used.

**Examples**
```
interval:s:1 {
  $proc_cnt = percpu_kaddr("process_counts");
  printf("%d processes are running on CPU %d\n", *$proc_cnt, cpu);
}
```

The second variant may return NULL if `cpu` is higher than the number of
available CPUs. Therefore, it is necessary to perform a NULL-check on the result
when accessing fields of the pointed structure, otherwise the BPF program will
be rejected.

```
interval:s:1 {
  $runqueues = (struct rq *)percpu_kaddr("runqueues", 0);
  if ($runqueues != 0) {         // The check is mandatory here
    print($runqueues->nr_running);
  }
}
```

**Availability**
Since bpftrace v0.22

### percpu_kaddr [0.25..]
Returns the address of a per-CPU kernel symbol.

- `uint64 *percpu_kaddr(const string name)`
- `uint64 *percpu_kaddr(const string name, int cpu)`

**sync**

Get the address of the percpu kernel symbol `name` for CPU `cpu`. When `cpu` is
omitted, the current CPU is used.

**Examples**
```
interval:s:1 {
  $proc_cnt = percpu_kaddr("process_counts");
  printf("%d processes are running on CPU %d\n", *$proc_cnt, cpu);
}
```

The second variant may return NULL if `cpu` is higher than the number of
available CPUs. Therefore, it is necessary to perform a NULL-check on the result
when accessing fields of the pointed structure, otherwise the BPF program will
be rejected.

```
interval:s:1 {
  $runqueues = (struct rq *)percpu_kaddr("runqueues", 0);
  if ($runqueues != 0) {         // The check is mandatory here
    print($runqueues.nr_running);
  }
}
```

**Availability**
Since bpftrace v0.22

### pid [..0.23]
Process ID of the current thread.

- `uint32 pid`

### pid [0.24..]
Returns the process ID of the current thread.

- `uint32 pid([curr_ns|init])`
- `uint32 pid`

Defaults to `curr_ns`.

* `pid(curr_ns)` - The process ID as seen from the PID namespace of bpftrace.
* `pid(init)` - The process ID as seen from the initial PID namespace.

### ppid [0.24..0.24]
Returns the process ID of the parent process.

- `uint32 ppid(struct task_struct * task)`

**Availability**
Since bpftrace v0.24

### ppid [0.25..0.25]
Returns the process ID of the parent process.

- `uint32 ppid()`
- `uint32 ppid`
- `uint32 ppid(struct task_struct * task)`

Get the pid of the parent process for the passed task or the current task if
called without arguments.

**Availability**
Since bpftrace v0.24

### ppid [0.26..]
Returns the process ID of the parent process.

- `uint32 ppid()`
- `uint32 ppid`
- `uint32 ppid(struct task_struct * task)`

Get the pid of the parent process for the passed task or the current task if
called without arguments. This is an alias for `task.real_parent.pid`, which is
different than `task.group_leader.pid`, which you can get from calling
`leader_tid()`.

**Availability**
Since bpftrace v0.24

### print [..0.24]
Prints a value using its default formatting.

- `void print(T val)`

**async**

### print [0.25..]
Prints a value using its default formatting.

- `void print(T val)`
- `void print(@map [, uint64 top [, uint64 div]])`

**async**

`print` prints the value, which can be a map or a scalar value, with the default
formatting for the type.

Declared maps and histograms are automatically printed out on program
termination.

Note that maps are printed by reference while scalar values are copied. This
means that updating and printing maps in a fast loop will likely result in bogus
map values as the map will be updated before userspace gets the time to dump and
print it.

**Examples**
```
interval:s:1 {
  print(123);
  print("abc");
  exit();
  // Prints:
  // 123
  // abc
}
```

```
interval:ms:10 { @=hist(rand); }
interval:s:1 { print(@); exit(); }
// Sample output:
// @:
// [16M, 32M)             3 |@@@                                              |
// [32M, 64M)             2 |@@                                               |
// [64M, 128M)            1 |@                                                |
// [128M, 256M)           4 |@@@@                                             |
// [256M, 512M)           3 |@@@                                              |
// [512M, 1G)            14 |@@@@@@@@@@@@@@                                   |
// [1G, 2G)              22 |@@@@@@@@@@@@@@@@@@@@@@                           |
// [2G, 4G)              51 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
```

The printing of maps supports the optional `top` and `div` arguments. `top`
limits the printing to the top N entries with the highest integer values.

```
BEGIN {
  $i = 11;
  for $elem : 1..$i {
    @[$elem] = $elem - 1;
  }
  print(@, 2);
  clear(@);
  exit();
}
// Prints:
// @[9]: 8
// @[10]: 9

```

The `div` argument scales the values prior to printing them. Scaling values
before storing them can result in rounding errors. Consider the following
program:

```
kprobe:f {
  @[func] += arg0 / 10;
}
```

With the following sequence as numbers for arg0: `134, 377, 111, 99`. The total
is `721` which rounds to `72` when scaled by 10 but the program would print `70`
due to the rounding of individual values.

Changing the earlier `print(@, 2)` call to `print(@, 5, 2)` will take the top 5
values and scale them by 2:

```
@[6]: 2
@[7]: 3
@[8]: 3
@[9]: 4
@[10]: 4
```

### printf [..0.25]
Prints arguments using a format string.

- `void printf(const string fmt, args...)`

**async**

`printf()` formats and prints data. It behaves similar to `printf()` found in
`C` and many other languages.

The format string has to be a constant, it cannot be modified at runtime. The
formatting of the string happens in user space. Values are copied and passed by
value.

bpftrace supports all the typical format specifiers like `%llx` and `%hhu`. The
non-standard ones for `buf` function output can be found below:

- `r` Hex-formatted string with `\x`
- `rh` Hex-formatted string without `\x` and with spaces between bytes (e.g.
  `0a fe`)

`printf()` can also symbolize enums as strings. User defined enums as well as
enums defined in the kernel are supported. For example:

**Examples**
```
enum custom {
  CUSTOM_ENUM = 3,
};

BEGIN {
  $r = SKB_DROP_REASON_SOCKET_FILTER;
  printf("%d, %s, %s\n", $r, $r, CUSTOM_ENUM);
  exit();
  // Prints:
  // 6, SKB_DROP_REASON_SOCKET_FILTER, CUSTOM_ENUM
}
```

Colors are supported too, using standard terminal escape sequences:

```
print("\033[31mRed\t\033[33mYellow\033[0m\n")
```

### printf [0.26..]
Prints arguments using a format string.

- `void printf(const string fmt, args...)`

**async**

`printf()` formats and prints data. It behaves similar to `printf()` found in
`C` and many other languages.

The format string has to be a constant, it cannot be modified at runtime. The
formatting of the string happens in user space. Values are copied and passed by
value.

bpftrace supports all the typical format specifiers like `%llx` and `%hhu`. The
non-standard ones can be found below:

* `r` - Normal hex for a buffer. Hex-formatted string to print arbitrary binary
  content returned by the `buf`.
* `rh` - Formatted hex. Prints in hex-formatted string without `\x` and with
  spaces between bytes (e.g. `0a fe`).
* `rx` - Escaped hex. Prints in hex-formatted string with `\x` without spaces
  between bytes (e.g. `\x0a\xfe`).
* `gr` - Human-readable GFP flags. Formats GFP (Get Free Pages) flags into
  human-readable strings, similar to the Linux kernel's `%pGg` format.

`printf()` can also symbolize enums as strings. User defined enums as well as
enums defined in the kernel are supported.

**Examples**
```
enum custom {
  CUSTOM_ENUM = 3,
};

BEGIN {
  $r = SKB_DROP_REASON_SOCKET_FILTER;
  printf("%d, %s, %s\n", $r, $r, CUSTOM_ENUM);
  exit();
  // Prints
  // 6, SKB_DROP_REASON_SOCKET_FILTER, CUSTOM_ENUM
}
```

The `%gr` specifier can be used to format GFP (Get Free Pages) flags into
human-readable strings:

```
tracepoint:kmem:kmalloc {
  printf("GFP flags: %gr\n", args->gfp_flags);
  // Sample output:
  // GFP flags: GFP_KERNEL
  // GFP flags: GFP_ATOMIC|__GFP_HIGHMEM
  // GFP flags: __GFP_IO|__GFP_FS|__GFP_DIRECT_RECLAIM
}
```

Colors are supported too, using standard terminal escape sequences:

```
print("\033[31mRed\t\033[33mYellow\033[0m\n")
```

### probe [0.24..]
Returns the fully expanded name of the current probe.

- `string probe()`
- `string probe`

For example: `kprobe:do_nanosleep`.

**Availability**
Since bpftrace v0.24

### probetype [0.25..]
Returns the type of the current probe.

- `string probetype()`
- `string probetype`

Note: `begin` and `end` probes are of type `special`.

For example: `kprobe`, `special`, `tracepoint`.

**Availability**
Since bpftrace v0.25

### pton [0.16..0.26]
Converts an IPv4 or IPv6 address string to a byte array.

- `char addr[4] pton(const string *addr_v4)`
- `char addr[16] pton(const string *addr_v6)`

**compile time**

`pton` converts a text representation of an IPv4 or IPv6 address to byte array.
`pton` infers the address family based on `.` or `:` in the given argument.
`pton` comes in handy when we need to select packets with certain IP addresses.

**Availability**
Since bpftrace v0.16

### pton [0.27..]
Converts an IPv4 or IPv6 address string to a byte array.

- `char addr[4] pton(const string *addr_v4)`
- `char addr[16] pton(const string *addr_v6)`

**compile time**

`pton` converts a text representation of an IPv4 or IPv6 address to byte array.
`pton` infers the address family based on `.` or `:` in the given argument.
`pton` comes in handy when we need to select packets with certain IP addresses.

When casting the result of `pton()` to an integer (e.g.
`(uint32)pton("127.0.0.1")`), the resulting value depends on the system's
endianness. The byte array returned by `pton()` is stored in network byte order
(big-endian), and when cast to an integer, it is interpreted according to the
system's native byte order:

*Little-endian systems*: The bytes are reversed when interpreted as an integer.
For example, `(uint32)pton("127.0.0.1")` yields `0x100007f` (bytes:
`[0x7f, 0x00, 0x00, 0x01]` interpreted as little-endian).

*Big-endian systems*: The bytes maintain their network byte order. For example,
`(uint32)pton("127.0.0.1")` yields `0x7f000001` (bytes:
`[0x7f, 0x00, 0x00, 0x01]` interpreted as big-endian). This behavior is
consistent with how the underlying `inet_pton()` function works.

**Availability**
Since bpftrace v0.16

### rand [..0.23]
Pseudo-random number.

- `uint32 rand`

This utilizes the BPF helper `bpf_get_prandom_u32`.

### rand [0.24..]
Returns a pseudo-random number.

- `uint32 rand()`
- `uint32 rand`

This utilizes the BPF helper `bpf_get_prandom_u32`.

### reg [..]
Returns the value of a named CPU register.

- `uint64 reg(const string name)`

**Supported probes**

* kprobe
* uprobe

Get the contents of the register identified by `name`. Valid names depend on the
CPU architecture.

### signal [..0.24]
Sends a signal to the process being traced.

- `void signal(const string sig)`
- `void signal(uint32 signum)`

**unsafe**

This utilizes the BPF helper `bpf_send_signal`.

**Supported probes**
* kprobe
* kretprobe
* uprobe
* uretprobe
* usdt
* profile

The signal can either be identified by name, e.g. `SIGSTOP` or by ID, e.g. `19`
as found in `kill -l`.

**Example**
```
kprobe:__x64_sys_execve
/comm == "ls"/ {
  signal(5);
  // $ ls
  // Trace/breakpoint trap (core dumped)
}
```

**Availability**
Since kernel v5.3

### signal [0.25..]
Sends a signal to the process being traced.

- `void signal(const string sig)`
- `void signal(uint32 signum)`

**unsafe**

This utilizes the BPF helper `bpf_send_signal`.

**Supported probes**
* kprobe
* kretprobe
* uprobe
* uretprobe
* usdt
* profile

Use `signal_thread` to send to the thread being traced. The signal can either be
identified by name, e.g. `SIGSTOP` or by ID, e.g. `19` as found in `kill -l`.

**Example**
```
kprobe:__x64_sys_execve
/comm == "ls"/ {
  signal(5);
  // $ ls
  // Trace/breakpoint trap (core dumped)
}
```

**Availability**
Since kernel v5.3

### signal_name [0.26..]
Converts a signal number to its name.

- `string signal_name(int sig)`

**Example**
```
#include <signal.h>
begin {
  print(signal_name(SIGINT));
}
```

**Availability**
Since bpftrace v0.26

### signal_thread [0.25..]
Sends a signal to the thread being traced.

- `void signal_thread(const string sig)`
- `void signal_thread(uint32 signum)`

**unsafe**

This utilizes the BPF helper `bpf_send_signal_thread`.

**Supported probes**
* kprobe
* kretprobe
* uprobe
* uretprobe
* usdt
* profile

Use `signal` to send to the process being traced (any thread). The signal can
either be identified by name, e.g. `SIGSTOP` or by ID, e.g. `19` as found in
`kill -l`.

**Availability**
Since bpftrace v0.25

### sizeof [0.11..]
Returns the size of a type or expression in bytes.

- `uint64 sizeof(TYPE)`
- `uint64 sizeof(EXPRESSION)`

**compile time**

Similar to C/C++ `sizeof` operator. Note that the expression does not get
evaluated.

**Availability**
Since bpftrace v0.11

### skboutput [0.12..0.24]
Writes packet data from a socket buffer to a PCAP file.

- `uint32 skboutput(const string path, struct sk_buff *skb, uint64 length, const uint64 offset)`

This utilizes the BPF helper `bpf_skb_output`.

Write the data section of `skb` to a PCAP file in `path`, starting from `offset`
to `offset` + `length`.

The PCAP file is encapsulated in RAW IP, so no ethernet header is included. The
`data` section in the struct `skb` may contain ethernet header in some kernel
contexts, you may set `offset` to 14 bytes to exclude ethernet header.

Each packet’s timestamp is determined by adding `nsecs` and boot time, the
accuracy varies on different kernels, see `nsecs`.

This function returns 0 on success, or a negative error in case of failure.

Environment variable `BPFTRACE_PERF_RB_PAGES` should be increased in order to
capture large packets, or else these packets will be dropped.

**Examples**
```
# cat dump.bt
fentry:napi_gro_receive {
  $ret = skboutput("receive.pcap", args.skb, args.skb->len, 0);
}

fentry:dev_queue_xmit {
  // setting offset to 14, to exclude ethernet header
  $ret = skboutput("output.pcap", args.skb, args.skb->len, 14);
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

**Availability**
Since bpftrace v0.12
Since kernel v5.5

### skboutput [0.25..]
Writes packet data from a socket buffer to a PCAP file.

- `uint32 skboutput(const string path, struct sk_buff *skb, uint64 length, const uint64 offset)`

This utilizes the BPF helper `bpf_skb_output`.

Write the data section of `skb` to a PCAP file in `path`, starting from `offset`
to `offset` + `length`.

The PCAP file is encapsulated in RAW IP, so no ethernet header is included. The
`data` section in the struct `skb` may contain ethernet header in some kernel
contexts, you may set `offset` to 14 bytes to exclude ethernet header.

Each packet’s timestamp is determined by adding `nsecs` and boot time, the
accuracy varies on different kernels, see `nsecs`.

This function returns 0 on success, or a negative error in case of failure.

Environment variable `BPFTRACE_PERF_RB_PAGES` should be increased in order to
capture large packets, or else these packets will be dropped.

**Example**
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

**Availability**
Since bpftrace v0.12
Since kernel v5.5

### socket_cookie [0.24..0.24]
Returns the kernel-generated cookie for a socket.

- `uint64 socket_cookie(struct sock *sk)`

This utilizes the BPF helper `bpf_get_socket_cookie`.

Retrieve the cookie (generated by the kernel) of the socket. If no cookie has
been set yet, generate a new cookie. Once generated, the socket cookie remains
stable for the life of the socket.

This function returns a `uint64` unique number on success, or 0 if **sk** is
NULL.

**Example**
```
fentry:tcp_rcv_established
{
  $cookie = socket_cookie(args->sk);
  @psize[$cookie] = hist(args->skb->len);
  // Sample output:

  // @psize[65551]:
  // [32, 64)               4 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
  //
  // @psize[504]:
  // [32, 64)               4 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
  // [64, 128)              1 |@@@@@@@@@@@@                                   |
  // [128, 256)             0 |                                               |
  // [256, 512)             1 |@@@@@@@@@@@@                                   |
  // [512, 1K)              0 |                                               |
  // [1K, 2K)               0 |                                               |
  // [2K, 4K)               1 |@@@@@@@@@@@@                                   |
}
```

**Availability**
Since bpftrace v0.24

### socket_cookie [0.25..]
Returns the kernel-generated cookie for a socket.

- `uint64 socket_cookie(struct sock *sk)`

This utilizes the BPF helper `bpf_get_socket_cookie`.

Retrieve the cookie (generated by the kernel) of the socket. If no cookie has
been set yet, generate a new cookie. Once generated, the socket cookie remains
stable for the life of the socket.

This function returns a `uint64` unique number on success, or 0 if **sk** is
NULL.

**Example**
```
fentry:tcp_rcv_established
{
  $cookie = socket_cookie(args->sk);
  @psize[$cookie] = hist(args->skb->len);
  // Sample output:

  // @psize[65551]:
  // [32, 64)               4 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
  //
  // @psize[504]:
  // [32, 64)               4 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
  // [64, 128)              1 |@@@@@@@@@@@@                                   |
  // [128, 256)             0 |                                               |
  // [256, 512)             1 |@@@@@@@@@@@@                                   |
  // [512, 1K)              0 |                                               |
  // [1K, 2K)               0 |                                               |
  // [2K, 4K)               1 |@@@@@@@@@@@@                                   |
}
```

**Availability**
Since bpftrace v0.24

### static_assert [0.25..]
Assert something is true or fail the build.

- `void static_assert(bool condition, string msg)`

**compile time**

**Availability**
Since bpftrace v0.25

### str [..0.24]
Reads a null-terminated string from an address.

- `string str(char * data [, uint32 length])`

This utilizes the BPF helpers `bpf_probe_read_str`,
`bpf_probe_read_{kernel,user}_str`.

`str` reads a NULL terminated (`\0`) string from `data`. The maximum string
length is limited by the `BPFTRACE_MAX_STRLEN` env variable, unless `length` is
specified and shorter than the maximum. In case the string is longer than the
specified length only `length - 1` bytes are copied and a NULL byte is appended
at the end.

When available (starting from kernel 5.5, see the `--info` flag) bpftrace will
automatically use the `kernel` or `user` variant of
`bpf_probe_read_{kernel,user}_str` based on the address space of `data`. For more
information see:
[Address-spaces](https://bpftrace.org/docs/release_024/language#address-spaces).

### str [0.25..]
Reads a null-terminated string from an address.

- `string str(char * data [, uint32 length])`

This utilizes the BPF helpers `bpf_probe_read_str`,
`bpf_probe_read_{kernel,user}_str`.

`str` reads a NULL terminated (`\0`) string from `data`. The maximum string
length is limited by the `BPFTRACE_MAX_STRLEN` env variable, unless `length` is
specified and shorter than the maximum. In case the string is longer than the
specified length only `length - 1` bytes are copied and a NULL byte is appended
at the end.

bpftrace will automatically use the `kernel` or `user` variant of
`bpf_probe_read_{kernel,user}_str` based on the address space of `data`. For more
information see:
[Address-spaces](https://bpftrace.org/docs/release_025/language#address-spaces).

### str_concat [0.27..]
Concatenates two strings into a new string.

- `string str_concat(string s1, string s2)`

**Availability**
Since bpftrace v0.27

### strcap [0.25..]
Returns the capacity of a string-like object.

- `int64 strcap(string exp)`
- `int64 strcap(int8 exp[])`
- `int64 strcap(int8 *exp)`

In most cases this is the same as the length, but for bpftrace-native strings
and arrays, this is the underlying object capacity. This is used to bound
searches and lookups without needing to scan the string itself.

**Availability**
Since bpftrace v0.25

### strcontains [0.17..0.24]
Checks whether one string contains another.

- `int64 strcontains(const char *haystack, const char *needle)`

`strcontains` compares whether the string haystack contains the string needle.
If needle is contained `1` is returned, else zero is returned.

bpftrace doesn’t read past the length of the shortest string.

**Availability**
Since bpftrace v0.17

### strcontains [0.25..]
Checks whether one string contains another.

- `bool strcontains(string haystack, string needle)`

If needle is contained then `true` is returned, else `false` is returned.

**Availability**
Since bpftrace v0.17

### strerror [0.16..0.24]
Converts an error number to its description.

- `strerror_t strerror(int error)`

This is done asynchronously in userspace when the strerror value is printed,
hence the returned value can only be used for printing.

**Example**
```
#include <errno.h>
BEGIN {
  print(strerror(EPERM));
}
```

**Availability**
Since bpftrace v0.16

### strerror [0.25..]
Converts an error number to its description.

- `string strerror(int error)`

**Example**
```
#include <errno.h>
begin {
  print(strerror(EPERM)); // Prints: Operation not permitted
}
```

**Availability**
Since bpftrace v0.16

### strftime [0.12..0.26]
Formats a timestamp according to a time format string.

- `timestamp strftime(const string fmt, int64 timestamp_ns)`

**async**

Format the nanoseconds since boot timestamp `timestamp_ns` according to the
format specified by `fmt`. The time conversion and formatting happens in user
space, therefore the `timestamp` value returned can only be used for printing
using the `%s` format specifier.

bpftrace uses the `strftime(3)` function for formatting time and supports the
same format specifiers.

bpftrace also supports the following format string extensions:
* `%f` - Microsecond as a decimal number, zero-padded on the left.

**Example**
```
interval:s:1 {
  printf("%s\n", strftime("%H:%M:%S", nsecs));
}
```

**Availability**
Since bpftrace v0.12

### strftime [0.27..]
Formats a timestamp according to a time format string.

- `timestamp strftime(const string fmt, uint64 timestamp_ns)`

**async**

Format the nanoseconds since boot timestamp `timestamp_ns` according to the
format specified by `fmt`. The time conversion and formatting happens in user
space, therefore the `timestamp` value returned can only be used for printing
using the `%s` format specifier. **Note:** `timestamp_ns` must be non-negative.
Negative timestamp literals are rejected.

bpftrace uses the `strftime(3)` function for formatting time and supports the
same format specifiers.

bpftrace also supports the following format string extensions:
* `%f` - Microsecond as a decimal number, zero-padded on the left.

**Example**
```
interval:s:1 {
  printf("%s\n", strftime("%H:%M:%S", nsecs));
}
```

**Availability**
Since bpftrace v0.12

### strlen [0.25..]
Returns the length of a string-like object.

- `uint64 strlen(string exp)`
- `uint64 strlen(int8 exp[])`
- `uint64 strlen(int8 *exp)`

**Availability**
Since bpftrace v0.25

### strncmp [0.24..]
Compares up to a specified number of characters in two strings.

- `int64 strncmp(char * s1, char * s2, int64 n)`

`strncmp` compares up to `n` characters string `s1` and string `s2`. If they’re
equal `0` is returned, else a non-zero value is returned.

bpftrace doesn’t read past the length of the shortest string.

The use of the `==` and `!=` operators is recommended over calling `strncmp`
directly.

**Availability**
Since bpftrace v0.24

### strstr [0.25..]
Returns the index of the first occurrence of one string in another, or -1 if not
found.

- `int64 strstr(string haystack, string needle)`

**Availability**
Since bpftrace v0.25

### syscall_name [0.25..]
Converts a system call number to its name.

- `string syscall_name(int nr_syscall)`

**Example**
```
#include <syscall.h>
begin {
  print(syscall_name(__NR_read)); // Outputs "read"
}
```

**Availability**
Since bpftrace v0.25

### system [..]
Runs a command in a child process and prints its output.

- `void system(string namefmt [, ...args])`

**unsafe**
**async**

`system` lets bpftrace run the specified command (`fork` and `exec`) until it
completes and print its stdout. The `command` is run with the same privileges as
bpftrace and it blocks execution of the processing threads which can lead to
missed events and delays processing of async events.

**Examples**
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

Note how the async `time` and `printf` first print every second until the
`interval:s:10` probe hits, then they print every 10 seconds due to bpftrace
blocking on `sleep`.

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
  system("/bin/grep %s /proc/%d/status", "VmSwap", pid);
}
```

### tid [..0.23]
Thread ID of the current thread.

- `uint32 tid`

### tid [0.24..]
Returns the thread ID of the current thread.

- `uint32 tid([curr_ns|init])`
- `uint32 tid`

Defaults to `curr_ns`.

* `tid(curr_ns)` - The thread ID as seen from the PID namespace of bpftrace.
* `tid(init)` - The thread ID as seen from the initial PID namespace.

### time [..]
Formats and prints the current wall-clock time.

- `void time(const string fmt)`

**async**

Format the current wall time according to the format specifier `fmt` and print
it to stdout. Unlike `strftime()` `time()` doesn’t send a timestamp from the
probe, instead it is the time at which user-space processes the event.

bpftrace uses the `strftime(3)` function for formatting time and supports the
same format specifiers.

### typeof [0.27..]
Returns the static type of a parsed type or expression.

- `TYPE typeof(TYPE)`
- `TYPE typeof(EXPRESSION)`

This is a special builtin that can only be used in the following contexts:
* variable declarations e.g. `let $a: typeof($b);`
* cast expressions e.g. `$a = (typeof($b))2;`
* macro expansion calls to pass a type parameter e.g.
  `my_macro(typeof(uint64 *));`
* type accepting builtins: `sizeof`, `offsetof`, `typeinfo`

This builtin evaluates to the static type of either the parsed TYPE or the raw
EXPRESSION parameter.

**Availability**
Since bpftrace v0.27

### uaddr [..0.24]
Returns the address of a user-space symbol.

- `T * uaddr(const string sym)`

**Supported probes**

* uprobes
* uretprobes
* usdt

***Does not work with ASLR, see issue
[#75](https://github.com/bpftrace/bpftrace/issues/75)***

The `uaddr` function returns the address of the specified symbol. This lookup
happens during program compilation and cannot be used dynamically.

The default return type is `uint64*`. If the ELF object size matches a known
integer size (1, 2, 4 or 8 bytes) the return type is modified to match the width
(`uint8*`, `uint16*`, `uint32*` or `uint64*` resp.). As ELF does not contain
type info the type is always assumed to be unsigned.


**Example**
```
uprobe:/bin/bash:readline {
  printf("PS1: %s\n", str(*uaddr("ps1_prompt")));
}
```

### uaddr [0.25..]
Returns the address of a user-space symbol.

- `T * uaddr(const string sym)`

**Supported probes**
* uprobe
* uretprobe
* usdt

If kernel supports `task_vma` open-coded iterator kfuncs (linux >= 6.7),
`uaddr()` will correct the symbol addresses of PIE and dynamic libraries instead
of directly using the symbol addresses in the ELF file, see
[linux commit](https://github.com/torvalds/linux/commit/4ac454682158).

The `uaddr` function returns the address of the specified symbol. This lookup
happens during program compilation and cannot be used dynamically.

The default return type is `uint64*`. If the ELF object size matches a known
integer size (1, 2, 4 or 8 bytes) the return type is modified to match the width
(`uint8*`, `uint16*`, `uint32*` or `uint64*` resp.). As ELF does not contain
type info the type is always assumed to be unsigned.

**Example**
```
uprobe:/bin/bash:readline {
  printf("PS1: %s\n", str(*uaddr("ps1_prompt")));
}
```

### uid [..0.23]
User ID of the current thread in the initial namespace.

- `uint64 uid`

This utilizes the BPF helper `bpf_get_current_uid_gid`.

### uid [0.24..]
Returns the user ID of the current thread in the initial namespace.

- `uint64 uid()`
- `uint64 uid`

This utilizes the BPF helper `bpf_get_current_uid_gid`.

### unwatch [..]
Removes a watchpoint.

- `void unwatch(void * addr)`

**async**

### uptr [0.12..]
Marks a pointer as pointing to user address space.

- `T * uptr(T * ptr)`

The pointer type is left unchanged.

For more information see
[Address Spaces](https://bpftrace.org/docs/release_026/language#address-spaces).

**Availability**
Since bpftrace v0.12

### usermode [0.24..]
Returns whether execution is currently in user mode (1 or 0).

- `uint8 usermode()`
- `uint8 usermode`

Currently only available on `x86_64`.

**Availability**
Since bpftrace v0.24

### username [0.24..]
Returns the current user's name.

- `string username()`
- `string username`

Often this is just "root".

**Availability**
Since bpftrace v0.24

### ustack [..0.24]
Returns a user-space stack trace.

- `ustack_t ustack([StackMode mode, ][int limit])`

These are implemented using BPF stack maps.

**Examples**
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

You can also choose a different output format. Available formats are `bpftrace`,
`perf`, and `raw` (no symbolication):

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

Note that for these examples to work, bash had to be recompiled with frame
pointers.

### ustack [0.25..0.26]
Returns a user-space stack trace.

- `ustack_t ustack([StackMode mode, ][int limit])`

These are implemented using BPF stack maps.

**Examples**
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

Note: If a limit is used and `show_debug_info` is enabled then the number of
symbolized frames might exceed that limit in the output as `limit` refers to
instruction pointers, which can translate to multiple inlined symbols.

You can also choose a different output format. Available formats are `bpftrace`,
`perf`, and `raw` (no symbolication):

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

Note that for these examples to work, bash had to be recompiled with frame
pointers.

### ustack [0.27..]
Returns a user-space stack trace.

- `ustack_t ustack([StackMode mode, ][int limit])`

There are several [formatting/StackMode options][doc3].

[doc3]: https://bpftrace.org/docs/release_027/language#stack_mode

**Examples**
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

Note: If a limit is used and `show_debug_info` is enabled then the number of
symbolized frames might exceed that limit in the output as `limit` refers to
instruction pointers, which can translate to multiple inlined symbols.

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

Note that for these examples to work, bash had to be recompiled with frame
pointers.

### usym [..]
Resolves a user-space address to a symbol name.

- `usym_t usym(uint64 * addr)`

**async**

**Supported probes**

* uprobes
* uretprobes

Equal to `ksym` but resolves user space symbols.

If ASLR is enabled, user space symbolication only works when the process is
running at either the time of the symbol resolution or the time of the probe
attachment. The latter requires `BPFTRACE_CACHE_USER_SYMBOLS` to be set to
`PER_PID`, and might not work with older versions of BCC. A similar limitation
also applies to dynamically loaded symbols.

**Example**
```
uprobe:/bin/bash:readline
{
  printf("%s\n", usym(reg("ip"))); // Prints: readline
}
```

### warnf [0.25..]
Formats and prints a warning message with its source location.

- `void warnf(const string fmt, args...)`

**async**

`warnf()` formats and prints data similar to `printf` as a warning message with
the source location. This respects the "--no-warnings" flag and will be silent
if that is used.

**Example**
```
BEGIN { warnf("Something kinda bad with args: %d, %s", 10, "arg2"); }
// Prints:
// stdin:1:9-67: WARNING: Something kinda bad with args: 10, arg2
```

**Availability**
Since bpftrace v0.25

### write_user [0.26..]
Writes bytes from BPF memory to a user-space address.

- `bool write_user(T * dst, T * src, uint32 len)`

**unsafe**

Writes `len` bytes from BPF program memory at `src` to user-space address `dst`
using the BPF helper `bpf_probe_write_user`.

Returns `true` on success, or `false` on failure.

**Warning**: This can crash or corrupt the target process if used incorrectly.
Only use on user-space memory addresses belonging to the current task. The
kernel will print a warning to dmesg when this helper is used.

```
tracepoint:syscalls:sys_enter_openat
/comm == "myapp"/ {
  $new_path = "/tmp/redirected\0";
  if (write_user(args.filename, $new_path, 16)) {
    printf("redirected open for pid %d\n", pid);
  }
}
```

**Availability**
Since bpftrace v0.26

### zero [..]
Sets every value in a map to zero.

- `void zero(map m)`

**async**

Set all values (for all keys) in the map to zero.

## MAP VALUE FUNCTIONS

### avg [..]
Calculates the running average of values passed to the function.

* `avg_t avg(int64 n)`

**Example**
```
interval:s:1 {
  @x++;
  @y = avg(@x);
  print(@x);
  print(@y);
}
```

Internally this keeps two values in the map: value count and running total. The
average is computed in userspace when printing by dividing the total by the
count. You can also get the average in kernel space in expressions like
`if (@y == 5)`, but this is expensive because bpftrace must iterate over all
CPUs to collect and sum both the count and total.

### count [..]
Counts how many times the function is called.

* `count_t count()`

Using `@=count()` is conceptually similar to `@++`. The difference is that the
`count()` function uses a map type optimized for performance and correctness
using cheap, thread-safe writes. However, sync reads can be expensive as
bpftrace needs to iterate over all the CPUs to collect and sum these values. See
[PERCPU types](https://bpftrace.org/docs/release_027/language#percpu-types).

Note: This differs from "raw" writes (e.g. `@++`) where multiple writers to a
shared location might lose updates, as bpftrace does not generate any atomic
instructions for `++`.

**Examples**
```
BEGIN {
  @ = count();
  @ = count();
  printf("%d\n", (int64)@);   // prints 2
  exit();
}
```

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

### hist [..]
Records values in a logarithmic histogram.

* `hist_t hist(int64 n[, int k])`

Create a log2 histogram of `n` using $2^k$ buckets per power of 2, where
`0 <= k <= 5`. The default value of `k` is 0.

**Example**
```
kretprobe:vfs_read {
  @bytes = hist(retval);
  // Sample output:
  // @bytes:
  // [1M, 2M)               3 |                                                    |
  // [2M, 4M)               2 |                                                    |
  // [4M, 8M)               2 |                                                    |
  // [8M, 16M)              6 |                                                    |
  // [16M, 32M)            16 |                                                    |
  // [32M, 64M)            27 |                                                    |
  // [64M, 128M)           48 |@                                                   |
  // [128M, 256M)          98 |@@@                                                 |
  // [256M, 512M)         191 |@@@@@@                                              |
  // [512M, 1G)           394 |@@@@@@@@@@@@@                                       |
  // [1G, 2G)             820 |@@@@@@@@@@@@@@@@@@@@@@@@@@@                         |
}
```

### lhist [..]
Records values in a linear histogram.

* `lhist_t lhist(int64 n, int64 min, int64 max, int64 step)`

Create a linear histogram of `n`. `lhist` creates `M` (`(max - min) / step`)
buckets in the range `[min, max)`, each of size `step`. Values below `min` and
above or equal to `max` are placed in their own buckets, for a total of `M + 2`
buckets.

**Example**
```
interval:ms:1 {
  @ = lhist(rand % 10, 0, 10, 1);
}

interval:s:5 {
  exit();
  // Sample output:
  // @:
  // [0, 1)               306 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         |
  // [1, 2)               284 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@            |
  // [2, 3)               294 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@          |
  // [3, 4)               318 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       |
  // [4, 5)               311 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        |
  // [5, 6)               362 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
  // [6, 7)               336 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    |
  // [7, 8)               326 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      |
  // [8, 9)               328 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     |
  // [9, 10)              318 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       |
}
```

### max [..]
Tracks the largest value passed to the function.

* `max_t max(int64 n)`

Update the map with `n` if `n` is bigger than the current value held.

This function uses a
[PERCPU map](https://bpftrace.org/docs/release_027/language#percpu-types).
Writes are fast and thread-safe, but reads are slow.

Note: Unlike the typical userspace `max()`, bpftrace's `max()` takes only one
argument. The other value being compared is the current value in the map to
which the result is assigned.

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
there is no default value. The first value you pass to `max()` will always be
returned.

### min [..]
Tracks the smallest value passed to the function.

* `min_t min(int64 n)`

Update the map with `n` if `n` is smaller than the current value held.

This function uses a
[PERCPU map](https://bpftrace.org/docs/release_027/language#percpu-types).
Writes are fast and thread-safe, but reads are slow.

See `max()` above for how this differs from the typical userspace `min()`.

### stats [..0.27]
Tracks the count, average, and sum of values.

* `stats_t stats(int64 n)`

`stats` combines the `count`, `avg`, and `sum` calls into one.

**Example**
```
kprobe:vfs_read {
  @bytes[comm] = stats(arg2);
  // Sample output:
  // @bytes[bash]: count 7, average 1, total 7
  // @bytes[sleep]: count 5, average 832, total 4160
  // @bytes[ls]: count 7, average 886, total 6208
}
```

### stats [0.28..]
Tracks the count, average, and sum of values.

* `stats_t stats(int64 n)`

`stats` combines the `count`, `avg`, and `sum` calls into one.

Individual fields of a `stats_t` map can be accessed synchronously using
`.count`, `.total`, and `.avg`.

**Examples**
```
kprobe:vfs_read {
  @bytes[comm] = stats(arg2);
  // Sample output:
  // @bytes[bash]: count 7, average 1, total 7
  // @bytes[sleep]: count 5, average 832, total 4160
  // @bytes[ls]: count 7, average 886, total 6208
}
```

```
kprobe:vfs_read {
  @bytes[comm] = stats(arg2);
}

interval:s:1 {
  printf("Count: %d, Total: %d, Avg: %d\n",
         @bytes["bash"].count,
         @bytes["bash"].total,
         @bytes["bash"].avg);
}
```

### sum [..0.23]
Calculates the sum of values passed to the function.

* `sum_t sum(int64 n)`

Using `@=sum(5)` is conceptually similar to `@+=5`. The difference is that the
`sum()` function uses a map type optimized for performance and correctness using
cheap, thread-safe writes. However, sync reads can be expensive as bpftrace
needs to iterate over all CPUs to collect and sum these values. See
[PERCPU types](https://bpftrace.org/docs/release_027/language#percpu-types).

Note: This differs from "raw" writes (e.g. `@+=5`) where multiple writers to a
shared location might lose updates, as bpftrace does not generate any implicit
atomic operations.

**Examples**
```
BEGIN {
  @ = sum(5);
  @ = sum(6);
  printf("%d\n", (int64)@);   // prints 11
  clear(@);
  exit();
}
```

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

### sum [0.24..]
Calculates the sum of values passed to the function.

* `sum_t sum(int64 n)`

Using `@=sum(5)` is conceptually similar to `@+=5`. The difference is that the
`sum()` function uses a map type optimized for performance and correctness using
cheap, thread-safe writes. However, sync reads can be expensive as bpftrace
needs to iterate over all CPUs to collect and sum these values. See
[PERCPU types](https://bpftrace.org/docs/release_027/language#percpu-types).

Note: This differs from "raw" writes (e.g. `@+=5`) where multiple writers to a
shared location might lose updates, as bpftrace does not generate any implicit
atomic operations.

**Examples**
```
BEGIN {
  @ = sum(5);
  @ = sum(6);
  printf("%d\n", (int64)@);   // prints 11
  clear(@);
  exit();
}
```

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

### tseries [0.24..]
Records integer values over a series of time intervals.

* `tseries_t tseries(int64 n, int64 interval_ns, int64 num_intervals)`
* `tseries_t tseries(int64 n, int64 interval_ns, int64 num_intervals, const string agg)`

Create a time series that tracks an integer value. `tseries` records up to
`num_intervals` intervals representing `interval_ns` nanoseconds.

#### Durations

`interval_ns` is an unsigned integer that specifies the interval duration. Use
duration suffixes to improve readability:

```
@a = tseries(1, 100ns, 5); // 100 nanoseconds
@b = tseries(1, 100us, 5); // 100 microseconds
@c = tseries(1, 100ms, 5); // 100 milliseconds
@d = tseries(1, 1s, 5);    // 1 second
```

#### Aggregation functions

By default, each interval in `tseries` contains the last value recorded in that
interval. The optional `agg` parameter specifies how values in the same interval
are aggregated.

- `avg`: `@ = tseries(@v, 1s, 5, "avg")` — calculates the running average of
  values in each interval.
- `max`: `@ = tseries(@v, 1s, 5, "max")` — calculates the maximum value in each
  interval.
- `min`: `@ = tseries(@v, 1s, 5, "min")` — calculates the minimum value in each
  interval.
- `sum`: `@ = tseries(@v, 1s, 5, "sum")` — calculates the sum of values in each
  interval.

**Examples**
```
// Record the minimum of ten random values generated during each 100ms interval.
i:ms:10 {
  @ = tseries(rand % 10, 100ms, 20, "min");
  // Sample output:
  // Attached 1 probe
  //
  // @:
  //              0                                                   2
  // hh:mm:ss.ms  |___________________________________________________|
  // 10:41:46.700 *                                                   | 0
  // 10:41:46.800 *                                                   | 0
  // 10:41:46.900 |                         *                         | 1
  // 10:41:47.000 |                                                   * 2
  // 10:41:47.100 |                         *                         | 1
  // 10:41:47.200 *                                                   | 0
  // 10:41:47.300 |                         *                         | 1
  // 10:41:47.400 *                                                   | 0
  // 10:41:47.500 |                         *                         | 1
  // 10:41:47.600 *                                                   | 0
  // 10:41:47.700 |                                                   * 2
  // 10:41:47.800 *                                                   | 0
  // 10:41:47.900 *                                                   | 0
  // 10:41:48.000 |                         *                         | 1
  // 10:41:48.100 |                         *                         | 1
  // 10:41:48.200 |                         *                         | 1
  // 10:41:48.300 *                                                   | 0
  // 10:41:48.400 |                                                   * 2
  // 10:41:48.500 |                         *                         | 1
  // 10:41:48.600 |                         *                         | 1
  //              v___________________________________________________v
  //              0                                                   2
}
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
    @c = 4;
  } else if (@c < -5) {
    @dir = 1;
    @c = -4;
  }
  // Sample output:
  // Attached 2 probes
  //
  // @:
  //              -5                                                  5
  // hh:mm:ss.ms  |___________________________________________________|
  // 10:39:49.300 *                         .                         | -5
  // 10:39:49.400 |    *                    .                         | -4
  // 10:39:49.500 |         *               .                         | -3
  // 10:39:49.600 |              *          .                         | -2
  // 10:39:49.700 |                   *     .                         | -1
  // 10:39:49.800 |                         *                         | 0
  // 10:39:49.900 |                         .    *                    | 1
  // 10:39:50.000 |                         .         *               | 2
  // 10:39:50.100 |                         .              *          | 3
  // 10:39:50.200 |                         .                   *     | 4
  // 10:39:50.300 |                         .                         * 5
  // 10:39:50.400 |                         .                   *     | 4
  // 10:39:50.500 |                         .              *          | 3
  // 10:39:50.600 |                         .         *               | 2
  // 10:39:50.700 |                         .    *                    | 1
  // 10:39:50.800 |                         *                         | 0
  // 10:39:50.900 |                   *     .                         | -1
  // 10:39:51.000 |              *          .                         | -2
  // 10:39:51.100 |         *               .                         | -3
  // 10:39:51.200 |    *                    .                         | -4
  //              v___________________________________________________v
  //              -5                                                  5
}
```

**Availability**
Since bpftrace v0.24
