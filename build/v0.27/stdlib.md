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


### typeof
- `TYPE typeof(TYPE)`
- `TYPE typeof(EXPRESSION)`

This is a special builtin that can only be used in the following contexts:
- variable declarations e.g. `let $a: typeof($b);`
- cast expressions e.g. `$a = (typeof($b))2;`
- macro expansion calls to pass a type parameter e.g. `my_macro(typeof(uint64 *));`
- type accepting builtins: `sizeof`, `offsetof`, `typeinfo`

This builtin evaluates to the static type of either the parsed TYPE or the raw EXPRESSION parameter.


### username
- `string username()`
- `string username`

Get the current username

Often this is just "root"


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
