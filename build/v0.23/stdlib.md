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


### uaddr
- `T * uaddr(const string sym)`

**Supported probes**

* uprobes
* uretprobes
* USDT

***Does not work with ASLR, see issue [#75](https://github.com/bpftrace/bpftrace/issues/75)***

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


### ustack
- `ustack_t ustack([StackMode mode, ][int limit])`

These are implemented using BPF stack maps.

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

You can also choose a different output format.
Available formats are `bpftrace`, `perf`, and `raw` (no symbolication):

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
