# bpftrace-language-server

[bpftrace](https://bpftrace.org) code completion, diagnostics and more, using [Language Server Protocol](https://microsoft.github.io/language-server-protocol/)

# Configuration

## bpftrace command
The server intrnally invokes `bpftrace` directly when running with root privileges and via `sudo` otherwise.

For a non-root user, there are several ways to grant the required privileges: configure capabilities on the bpftrace binary, configure passwordless `sudo`, or start the server with `run0`.

### Option 1: Capabilities

Capabilities can be set on the system `bpftrace` binary or on a local copy. Using a separate, user-owned copy avoids granting capabilities to the system-wide `bpftrace` binary.

``` bash
cp "$(which bpftrace)" "$HOME/my_bpftrace"
sudo setcap cap_bpf,cap_perfmon,cap_dac_read_search,cap_dac_override,cap_sys_admin+ep "$HOME/my_bpftrace
```

To verify check you can invoke below commands without error:
```bash
cd
my_bpftrace --info
my_bpftrace -l | head

```
bpftrace >= 0.25 is known to work with these capabilities.

See client configuration how to use `bpftrace-language-server` with local copy.

### Option 2: sudo

Determine the username and bpftrace path:
```bash
$ whoami
thisuser

$ which bpftrace
/usr/bin/bpftrace
```

Create a dedicated sudoers configuration:
```bash
sudo visudo -f /etc/sudoers.d/bpftrace
```

Add the following entry, substituting the values obtained above:
```sudo
thisuser ALL=(root) NOPASSWD: /usr/bin/bpftrace
```

Verify that `bpftrace` can be invoked through `sudo` without a password:
```bash
sudo bpftrace --info
sudo bpftrace -l | head
```

### Option 3: run0
If `systemd` and `polkit` are available, the server can be started through `run0`. Authentication is performed when the server is started (you will be prompted for password).

For example in Neovim (see below for full config):
```lua
vim.lsp.config['bpftrace-ls'] = {
  cmd = { 'run0', 'bpftrace-ls' },
  ...
}
```


## Kernel
`bpftrace-language-server` makes extensive use of [BTF](https://docs.kernel.org/bpf/btf.html) (BPF Type Format).
Most Linux distributions enable BTF support by default. Check whether BTF is available:
```bash
ls /sys/kernel/btf/
```
If the directory does not exist or is empty, consider rebuilding the kernel with the following options enabled:
```
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
```
## Client

### Neovim LSP configuration
If the bpftrace filetype is recognized (see blow), register the language server with Neovim's LSP client. Ensure `bpftrace-ls` is in `PATH`, or specify its full path. See [Neovim LSP documentation]( https://neovim.io/doc/user/lsp.html) for details.
```lua
-- LSP config for bpftrace-ls
vim.lsp.config['bpftrace-ls'] = {
  -- Command and arguments to start the server.
  cmd = { '/PATH/TO/bpftrace-language-server/target/debug/bpftrace-ls' },

 -- Filetypes to automatically attach to
  filetypes = { 'bpftrace' },
}
-- Enable the server
vim.lsp.enable("bpftrace-ls")
```
#### Using custom command
If `bpftrace` is not available in `PATH`, or a custom build is required, specify its path with the
`--cmd` option.

For example:
```lua
local home = vim.env.HOME

vim.lsp.config['bpftrace-ls'] = {
  cmd = { home .. '/Github/bpftrace-language-server/target/debug/bpftrace-ls',
          '--cmd',
          home .. '/Github/bpftrace/build/src/bpftrace'
  },
  filetypes = { 'bpftrace' },
}
vim.lsp.enable("bpftrace-ls")
```

#### Neovim filetype detection
Neovim v0.12 and later includes built-in filetype detection for bpftrace.

For older versions, add the following to your `init.lua`:
```lua
vim.filetype.add({
  extension = {
    bt = "bpftrace"
  },
  pattern = {
    [".*"] = {
      function(path, bufnr)
        local first_line = vim.api.nvim_buf_get_lines(bufnr, 0, 1, false)[1] or ''
        if vim.regex([[^#!.*bpftrace]]):match_str(first_line) ~= nil then
          return "bpftrace"
        end
      end,
      { priority = -math.huge }
    }
  }
})
```

Verify the filetype in Neovim after opening `bpftrace` file:
```
:set filetype?
```
It should report:
```
filetype=bpftrace
```
