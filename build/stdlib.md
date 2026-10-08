### assert [0.24..]
- `void assert(bool condition, string message)`

Simple assertion macro that will exit the entire script with an error code if the condition is not met.

**Availability**
Since bpftrace v0.24

### assert_str [0.25..]

Checks that this value is string-like.

**Availability**
Since bpftrace v0.25

### bswap [0.23..]
- `uint8 bswap(uint8 n)`
- `uint16 bswap(uint16 n)`
- `uint32 bswap(uint32 n)`
- `uint64 bswap(uint64 n)`

`bswap` reverses the order of the bytes in integer `n`. In case of 8 bit integers, `n` is returned without being modified.
The return type is an unsigned integer of the same width as `n`.

### buf [0.23..]
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
