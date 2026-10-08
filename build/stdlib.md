### assert [0.24..]
- `void assert(bool condition, string message)`

Simple assertion macro that will exit the entire script with an error code if the condition is not met.

**Availability**
Since bpftrace v0.24

### assert_str [0.25..]

Checks that this value is string-like.

**Availability**
Since bpftrace v0.25

### bswap [..]
- `uint8 bswap(uint8 n)`
- `uint16 bswap(uint16 n)`
- `uint32 bswap(uint32 n)`
- `uint64 bswap(uint64 n)`

`bswap` reverses the order of the bytes in integer `n`. In case of 8 bit integers, `n` is returned without being modified.
The return type is an unsigned integer of the same width as `n`.

**Availability**
Since bpftrace v0.15.0

### buf [..]
- `buffer buf(void * data, [int64 length])`

`buf` reads `length` amount of bytes from address `data`.
The maximum value of `length` is limited to the `BPFTRACE_MAX_STRLEN` variable.
For arrays the `length` is optional, it is automatically inferred from the signature.

`buf` is address space aware and will call the correct helper based on the address space associated with `data`.

The `buffer` object returned by `buf` can safely be printed as a hex encoded string with the `%r` format specifier.

Bytes with values >=32 and \&lt;=126 are printed using their ASCII character, other bytes are printed in hex form (e.g. `\x00`). The `%rx` format specifier can be used to print everything in hex form, including ASCII characters. The similar `%rh` format specifier prints everything in hex form without `\x` and with spaces between bytes (e.g. `0a fe`).

```
interval:s:1 {
  printf("%r\n", buf(kaddr("avenrun"), 8));
}
```

```
\x00\x03\x00\x00\x00\x00\x00\x00
\xc2\x02\x00\x00\x00\x00\x00\x00
```

### cat [..]
- `void cat(string namefmt, [...args])`

**async**

Dump the contents of the named file to stdout.
`cat` supports the same format string and arguments that `printf` does.
If the file cannot be opened or read an error is printed to stderr.

```
tracepoint:syscalls:sys_enter_execve {
  cat("/proc/%d/maps", pid);
}
```

```
55f683ebd000-55f683ec1000 r--p 00000000 08:01 1843399                    /usr/bin/ls
55f683ec1000-55f683ed6000 r-xp 00004000 08:01 1843399                    /usr/bin/ls
55f683ed6000-55f683edf000 r--p 00019000 08:01 1843399                    /usr/bin/ls
55f683edf000-55f683ee2000 rw-p 00021000 08:01 1843399                    /usr/bin/ls
55f683ee2000-55f683ee3000 rw-p 00000000 00:00 0
```

### cgroup [..]
- `uint64 cgroup()`
- `uint64 cgroup`

ID of the cgroup the current process belongs to

Only works with cgroupv2

This utilizes the BPF helper `get_current_cgroup_id`

### cgroup_path [..]
- `cgroup_path_t cgroup_path(int cgroupid, string filter)`

Convert cgroup id to cgroup path.
This is done asynchronously in userspace when the cgroup_path value is printed,
therefore it can resolve to a different value if the cgroup id gets reassigned.
This also means that the returned value can only be used for printing.

A string literal may be passed as an optional second argument to filter cgroup
hierarchies in which the cgroup id is looked up by a wildcard expression (cgroup2
is always represented by "unified", regardless of where it is mounted).

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

### cgroupid [..]
- `uint64 cgroupid(const string path)`

**compile time**

`cgroupid` retrieves the cgroupv2 ID  of the cgroup available at `path`.

```
BEGIN {
  print(cgroupid("/sys/fs/cgroup/system.slice"));
}
```

### clear [..]
- `void clear(map m)`

**async**

Clear all keys/values from map `m`.

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
- `string comm`

Name of the current thread

This utilizes the BPF helper `get_current_comm`

### comm [0.24..0.24]
- `string comm()`
- `string comm`

Name of the current thread

This utilizes the BPF helper `get_current_comm`

### comm [0.25..]
- `string comm()`
- `string comm`
- `string comm(uint32 pid)`

Name of the current thread or the process with the specified PID

This utilizes the BPF helper `get_current_comm`

### cpid [..0.23]
- `uint32 cpid`

Child process ID, if bpftrace is invoked with `-c`

### cpid [0.24..0.24]
- `uint32 cpid()`
- `uint32 cpid`

Child process ID, if bpftrace is invoked with `-c`

### cpid [0.25..]
- `uint32 cpid()`
- `uint32 cpid`

Child process ID, if bpftrace is invoked with `-c`.

If there is no child process, a runtime warning will be issued and the
return value will be zero.  This warning can be avoided by using `has_cpid`
to check if `cpid` has a value, prior to referencing `cpid`.

### cpu [..0.23]
- `uint32 cpu`

ID of the processor executing the BPF program

BPF program, in this case, is the probe body

This utilizes the BPF helper `raw_smp_processor_id`

### cpu [0.24..]
- `uint32 cpu()`
- `uint32 cpu`

ID of the processor executing the BPF program

BPF program, in this case, is the probe body

This utilizes the BPF helper `raw_smp_processor_id`

### curtask [..0.23]
- `uint64 curtask`

Pointer to `struct task_struct` of the current task

This utilizes the BPF helper `get_current_task`

### curtask [0.24..]
- `uint64 curtask()`
- `uint64 curtask`

Pointer to `struct task_struct` of the current task

This utilizes the BPF helper `get_current_task`

### delete [..]
- `bool delete(map m, mapkey k)`
- deprecated `bool delete(mapkey k)`

Delete a single key from a map.
For scalar maps (e.g. no explicit keys), the key is omitted and is equivalent to calling `clear`.
For map keys that are composed of multiple values (e.g. `@mymap[3, "hello"] = 1` - remember these values are represented as a tuple) the syntax would be: `delete(@mymap, (3, "hello"));`

If deletion fails (e.g. the key doesn’t exist) the function returns false (0).
Additionally, if the return value for `delete` is discarded, and deletion fails, you will get a warning.

```
@a[1] = 1;

delete(@a, 1); // no warning (the key exists)

if (delete(@a, 2)) { // no warning (return value is used)
  ...
}

$did_delete = delete(@a, 2); // no warning (return value is used)

delete(@a, 2); // warning (return value is discarded and the key doesn’t exist)
```

The, now deprecated, API (supported in version &lt;= 0.21.x) of passing map arguments with the key is still supported:
e.g. `delete(@mymap[3, "hello"]);`.

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

### elapsed [..]
- `uint64 elapsed()`
- `uint64 elapsed`

ktime_get_ns - ktime_get_boot_ns

### exit [..]
- `void exit([int code])`

**async**

Terminate bpftrace, as if a `SIGTERM` was received.
The `END` probe will still trigger (if specified) and maps will be printed.
An optional exit code can be provided.

```
BEGIN {
  exit();
}
```

Or

```
BEGIN {
  exit(1);
}
```

### func [..0.23]
- `string func`

Name of the current function being traced (kprobes,uprobes,fentry)

### func [0.24..0.26]
- `string func()`
- `string func`

Name of the current function being traced (kprobes,uprobes,fentry)

### func [0.27..]
- `ksym_t func()`
- `ksym_t func`
- `usym_t func()`
- `usym_t func`

Name of the current function being traced (kprobes,uprobes,fentry)

### gid [..0.23]
- `uint64 gid`

Group ID of the current thread, as seen from the init namespace

This utilizes the BPF helper `get_current_uid_gid`

### gid [0.24..]
- `uint64 gid()`
- `uint64 gid`

Group ID of the current thread, as seen from the init namespace

This utilizes the BPF helper `get_current_uid_gid`

### has_key [..0.24]
- `boolean has_key(map m, mapkey k)`

Return true (1) if the key exists in this map.
Otherwise return false (0).
Error if called with a map that has no keys (aka scalar map).
Return value can also be used for scratch variables and map keys/values.

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

### has_key [0.25..]
- `boolean has_key(map m, mapkey k)`

Return `true` if the key exists in this map.
Otherwise return `false`.
Error if called with a map that has no keys (aka scalar map).

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
