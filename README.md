# bpftrace-language-server

[bpftrace](https://bpftrace.org) code completion, diagnostics and more, using [Language Server Protocol](https://microsoft.github.io/language-server-protocol/)

## bpftrace configuration
The server internally invokes `bpftrace` directly when running with root permissions and via `sudo` otherwise.
For a non-root user, you need to configure passwordless `sudo` access to `bpftrace`. Alternatively, start the server with `run0`.

### sudo configuration 
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

### run0 invocation
If `systemd` and `polkit` are available, the server can be started through `run0`. Authentication is performed when the server is started (you will be prompted for password).

For example, in Neovim:
```lua
vim.lsp.config['bpftrace-ls'] = {
  cmd = { 'run0', 'bpftrace-ls' },
  filetypes = { 'bpftrace' },
}
```

### custom `bpftrace` command
If bpftrace is not available in `PATH`, or a custom build is required, specify its path with the `--cmd` option.

For example, in Neovim:
```lua
local home = vim.env.HOME

vim.lsp.config['bpftrace-ls'] = {
  cmd = { home .. '/Github/bpftrace-language-server/target/debug/bpftrace-ls' , 
          '--cmd' , 
          home .. '/Github/bpftrace/build/src/bpftrace'
  },
  filetypes = { 'bpftrace' },
}
```

## kernel
`bpftrace-ls` makes extensive use of [BTF](https://docs.kernel.org/bpf/btf.html) (BPF Type Format)] .
Most distributions enable BTF support by default. Check whether BTF is available:
```bash
ls /sys/kernel/btf/
```
If the directory does not exist or is empty, consider rebuilding the kernel with BTF support enabled:

```
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
```
## Using in Neovim

### Filetype detection
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
### Neovim LSP configuration
Once the filetype is recognized, you can register the language server.
Ensure `bpftrace-ls` is in PATH, or specify its full path
See [documentation]( https://neovim.io/doc/user/lsp.html) for details.
```lua
-- LSP config for bpftrace-ls
vim.lsp.config['bpftrace-ls'] = {
  -- Command and arguments to start the server.
  cmd = { '/PATH/TO/bpftrace-language-server/target/debug/bpftrace-ls' },
  filetypes = { 'bpftrace' },
}
-- Enable the server
vim.lsp.enable("bpftrace-ls")
```
