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

### END
