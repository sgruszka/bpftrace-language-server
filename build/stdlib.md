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

