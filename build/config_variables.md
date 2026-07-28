<!--
This file originates from https://github.com/bpftrace/bpftrace
It is licensed under the Apache License, Version 2.0
See the LICENSE file of that project or https://www.apache.org/licenses/LICENSE-2.0
-->
## Config Variables

Some behavior can only be controlled through config variables, which are listed here.
These can be set via the [Config Block](#config-block) directly in a script (before any probes) or via their environment variable equivalent, which is upper case and includes the `BPFTRACE_` prefix e.g. `stack_mode`’s environment variable would be `BPFTRACE_STACK_MODE`.

### cache_user_symbols

Default: PER_PROGRAM if ASLR disabled or `-c` option given, PER_PID otherwise.

* PER_PROGRAM - each program has its own cache. If there are more processes with enabled ASLR for a single program, this might produce incorrect results.
* PER_PID - each process has its own cache. This is accurate for processes with ASLR enabled, and enables bpftrace to preload caches for processes running at probe attachment time.
If there are many processes running, it will consume a lot of a memory.
* NONE - caching disabled. This saves the most memory, but at the cost of speed.

### cpp_demangle

Default: true

C++ symbol demangling in userspace stack traces is enabled by default.

This feature can be turned off by setting the value of this variable to `false`.

### lazy_symbolication

Default: false

For user space symbols, symbolicate lazily/on-demand (`true`) or symbolicate everything ahead of time (`false`).

### license

Default: "GPL"

The license bpftrace will use to load BPF programs into the linux kernel. Here is the list of accepted license strings:
- GPL
- GPL v2
- GPL and additional rights
- Dual BSD/GPL
- Dual MIT/GPL
- Dual MPL/GPL

[Read More about BPF licenses](#bpf-license)

### log_size

Default: 1000000

Log size in bytes.

### max_bpf_progs

Default: 1024

This is the maximum number of BPF programs (functions) that bpftrace can generate.
The main purpose of this limit is to prevent bpftrace from hanging since generating a lot of probes
takes a lot of resources (and it should not happen often).

### max_cat_bytes

Default: 10240

Maximum bytes read by cat builtin.

### max_map_keys

Default: 4096

This is the maximum number of keys that can be stored in a map.
Increasing the value will consume more memory and increase startup times.
There are some cases where you will want to, for example: sampling stack traces, recording timestamps for each page, etc.

### max_probes

Default: 1024

This is the maximum number of probes that bpftrace can attach to.
Increasing the value will consume more memory, increase startup times, and can incur high performance overhead or even freeze/crash the
system.

### max_strlen

Default: 1024

The maximum length (in bytes) for values created by `str()`, `buf()` and `path()`.

This limit is necessary because BPF requires the size of all dynamically-read strings (and similar) to be declared up front. This is the size for all strings (and similar) in bpftrace unless specified at the call site.
There is no artificial limit on what you can tune this to. But you may be wasting resources (memory and cpu) if you make this too high.

### missing_probes

Default: `error`

Controls handling of probes which cannot be attached because they do not exist (in the kernel or in the traced binary) or there was an issue during attachment.

The possible options are:
- `error` - always fail on missing probes
- `warn` - print a warning but continue execution
- `ignore` - silently ignore missing probes

### on_stack_limit

Default: 32

The maximum size (in bytes) of individual objects that will be stored on the BPF stack. If they are larger than this limit they will be stored in pre-allocated memory.

This exists because the BPF stack is limited to 512 bytes and large objects make it more likely that we’ll run out of space. bpftrace can store objects that are larger than the `on_stack_limit` in pre-allocated memory to prevent this stack error. However, storing in pre-allocated memory may be less memory efficient. Lower this default number if you are still seeing a stack memory error or increase it if you’re worried about memory consumption.

### perf_rb_pages

Default: Based on available system memory

Number of pages to allocate for each created ring or perf buffer (there is only one of each max).
The minimum is: 1 * the number of cpus on your machine.
If you’re getting a lot of dropped events bpftrace may not be processing events in the ring buffer (or perf buffer if you're using `skboutput`) fast enough.
It may be useful to bump the value higher so more events can be queued up.
The tradeoff is that bpftrace will use more memory.
The default value is based on available system memory; max is 4096 pages (16mb) and min is 64 pages (256kb), which presumes 4k page size.
If your system has a larger page size the amount of allocated memory will be the same but we'll just use fewer pages.

### show_debug_info

This is only available if the [Blazesym](https://github.com/libbpf/blazesym) library is available at build time. If it is available this defaults to `true`, meaning that when printing ustack and kstack symbols bpftrace will also show (if debug info is available) symbol file and line ('bpftrace' stack mode) and a label if the function was inlined ('bpftrace' and 'perf' stack modes).
There might be a performance difference when symbolicating, which is the only reason to disable this.

### stack_mode

Default: bpftrace

Output format for ustack and kstack builtins.
Available modes/formats:

* bpftrace: symbol + offset (e.g. `do_mmap+1`)
* perf: linux perf style with leading IP (e.g. `ffffffffb4019501 do_mmap+1`)
* raw: no symbolication (print instruction pointer)
* build_id: no symbolication (print build_id and file offset) (ustack only)

This can be overwritten at the call site.

When [debug info](#show_debug_info) is available the file and line is added at the end for `bpftrace` or `perf` stack mode e.g. `spin+37@/home/jordalgo/local/bpftrace/tests/testprogs/uprobe_loop.c:14`.

### str_trunc_trailer

Default: `..`

Trailer to add to strings that were truncated.
Set to empty string to disable truncation trailers.

### print_maps_on_exit

Default: true

Controls whether maps are printed on exit. Set to `false` in order to change the default behavior and not automatically print maps at program exit.

### unstable_tseries

Default: warn

Feature flag for time series map type.

The possible options are:
- `error` - fail if this feature is used
- `warn` - enable feature but print a warning
- `enable` - enable feature

### unstable_dw_ustack

Default: warn

Feature flag for DWARF-based user-space stack unwinding

The possible options are:
- `error` - fail if this feature is used
- `warn` - enable feature but print a warning
- `enable` - enable feature

### END

