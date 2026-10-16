<!--
This file originates from https://github.com/bpftrace/bpftrace
It is licensed under the Apache License, Version 2.0
See the LICENSE file of that project or
https://www.apache.org/licenses/LICENSE-2.0
-->
## Config Variables

Some behavior can only be controlled through config variables, which are listed
here.
These can be set in a [Config Block](#config-block) directly in a script,
before any probes, or through the equivalent environment variable. The variable
name is uppercase and prefixed with `BPFTRACE_`; for example, `stack_mode` is
set with `BPFTRACE_STACK_MODE`.

### cache_user_symbols [..]
Controls caching of user-space symbol lookups.

Default: `PER_PROGRAM` if ASLR is disabled or `-c` is given; `PER_PID`
otherwise.

* `PER_PROGRAM` - each program has its own cache. If there are more processes
with ASLR enabled for a single program, this might produce incorrect results.
* `PER_PID` - each process has its own cache. This is accurate for processes
with ASLR enabled, and enables bpftrace to preload caches for processes running
at probe attachment time. If many processes are running, this can consume a lot
of memory.
* `NONE` - caching disabled. This saves the most memory, but at the cost of
speed.

### cpp_demangle [..]
Enables or disables C++ symbol demangling in user-space stack traces.

Default: `true`

C++ symbol demangling in userspace stack traces is enabled by default.

This feature can be turned off by setting the value of this variable to
`false`.

### lazy_symbolication [..]
Controls whether user-space symbols are resolved lazily or in advance.

Default: `false`

For user space symbols, symbolicate lazily/on-demand (`true`) or symbolicate
everything ahead of time (`false`).

### license [..]
Sets the license string used when loading BPF programs.

Default: "GPL"

The license bpftrace will use to load BPF programs into the Linux kernel. Here
is the list of accepted license strings:
- GPL
- GPL v2
- GPL and additional rights
- Dual BSD/GPL
- Dual MIT/GPL
- Dual MPL/GPL

[Read more about BPF licenses][bpf-license]

[bpf-license]: https://bpftrace.org/docs/release_026/language#bpf-license

### log_size [..]
Sets the size of the bpftrace log buffer in bytes.

Default: 1000000

Log size in bytes.

### max_bpf_progs [..]
Limits the number of BPF programs that bpftrace can generate.

Default: 1024

This is the maximum number of BPF programs (functions) that bpftrace can
generate. The main purpose of this limit is to prevent bpftrace from hanging
since generating a lot of probes takes a lot of resources (and it should not
happen often).

### max_cat_bytes [..]
Limits the number of bytes read by `cat`.

Default: 10240

Maximum bytes read by cat builtin.

### max_map_keys [..]
Limits the number of keys that can be stored in a map.

Default: 4096

This is the maximum number of keys that can be stored in a map. Increasing the
value consumes more memory and increases startup time. For example, a higher
value may be useful when sampling stack traces or recording timestamps for each
page.

### max_probes [..]
Limits the number of probes that bpftrace can attach to.

Default: 1024

This is the maximum number of probes that bpftrace can attach to. Increasing the
value will consume more memory, increase startup times, and can incur high
performance overhead or even freeze/crash the system.

### max_strlen [..]
Limits the byte length of values from `str()`, `buf()`, and `path()`.

Default: 1024

The maximum length (in bytes) for values created by `str()`, `buf()` and
`path()`.

This limit is necessary because BPF requires the size of all dynamically-read
strings (and similar) to be declared up front. This is the size for all strings
(and similar) in bpftrace unless specified at the call site. There is no
artificial limit on what you can tune this to. But you may be wasting resources
(memory and cpu) if you make this too high.

### missing_probes [..]
Controls how bpftrace handles probes that cannot be attached.

Default: `error`

Controls handling of probes which cannot be attached because they do not exist
(in the kernel or in the traced binary) or there was an issue during attachment.

The possible options are:
- `error` - always fail on missing probes
- `warn` - print a warning but continue execution
- `ignore` - silently ignore missing probes

### on_stack_limit [0.22..]
Sets the maximum size of objects stored directly on the BPF stack.

Default: 32

The maximum size (in bytes) of individual objects that will be stored on the BPF
stack. If they are larger than this limit they will be stored in pre-allocated
memory.

This exists because the BPF stack is limited to 512 bytes and large objects make
it more likely that we’ll run out of space. bpftrace can store objects that are
larger than the `on_stack_limit` in pre-allocated memory to prevent this stack
error. However, storing in pre-allocated memory may be less memory efficient.
Lower this default number if you are still seeing a stack memory error or
increase it if you’re worried about memory consumption.

**Availability**
Since bpftrace v0.22

### perf_rb_pages [..]
Sets the number of pages allocated for each ring or perf buffer.

Default: Based on available system memory

Number of pages to allocate for each ring or perf buffer (bpftrace creates at
most one of each). The minimum is one page per CPU.

If you’re getting many dropped events, bpftrace may not be processing the ring
buffer (or perf buffer if you're using `skboutput`) quickly enough. Increasing
this value lets more events wait in the buffer, but uses more memory. The
default is based on available system memory; the maximum is 4096 pages (16 MB)
and the minimum is 64 pages (256 KB), assuming a 4 KB page size. If your system
uses a larger page size, the allocated memory stays the same but uses fewer
pages.

### show_debug_info [0.24..]
Controls whether stack traces include source and inline function details.

Default: `true`. Available only when bpftrace is built with `Blazesym`.

When enabled and debug information is available, bpftrace adds source file
and line details to `bpftrace` stack traces. It also labels inlined functions
in `bpftrace` and `perf` modes. Symbolication may affect performance.

**Availability**
Since bpftrace v0.24

### stack_mode [..]
Sets the output format for `ustack` and `kstack` stack traces.

Default: `bpftrace`

Output format for ustack and kstack builtins. Available modes/formats:

* `bpftrace`: symbol + offset (e.g. `do_mmap+1`)
* `perf`: Linux perf style with leading IP (e.g. `ffffffffb4019501 do_mmap+1`)
* `raw`: no symbolication (print instruction pointer)
* `build_id`: no symbolication (print build ID and file offset) (ustack only)

This can be overwritten at the call site.

When `show_debug_info` is enabled and debug information is available, bpftrace
appends the file and line in `bpftrace` or `perf` stack mode, for example:
`spin+37@/home/jordalgo/local/bpftrace/tests/testprogs/uprobe_loop.c:14`.

### str_trunc_trailer [..]
Sets the suffix appended to truncated strings.

Default: `..`

Trailer to add to strings that were truncated. Set to empty string to disable
truncation trailers.

### print_maps_on_exit [0.22..]
Controls whether bpftrace automatically prints maps on exit.

Default: `true`

Controls whether maps are printed on exit. Set to `false` in order to change the
default behavior and not automatically print maps at program exit.

**Availability**
Since bpftrace v0.22

### unstable_tseries [0.24..]
Controls whether the unstable time series map type is enabled.

Default: `warn`

Feature flag for time series map type.

The possible options are:
- `error` - fail if this feature is used
- `warn` - enable feature but print a warning
- `enable` - enable feature

**Availability**
Since bpftrace v0.24

### unstable_dw_ustack [0.26..]
Controls whether DWARF-based user-space stack unwinding is enabled.

Default: `warn`

Feature flag for DWARF-based user-space stack unwinding

The possible options are:
- `error` - fail if this feature is used
- `warn` - enable feature but print a warning
- `enable` - enable feature

**Availability**
Since bpftrace v0.26

### END
