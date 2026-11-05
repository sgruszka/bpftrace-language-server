# bpftrace language server (bpftrace-ls)

Code completion, diagnostics, hover information, navigation, and formatting for
[bpftrace](https://bpftrace.org), using the
[Language Server Protocol (LSP)](https://microsoft.github.io/language-server-protocol/).

# Configuration

Without additional system setup, the LSP server provides parser diagnostics,
basic navigation, and completion. For detailed compiler diagnostics and richer
completion of available probes, probe arguments, and structure fields, configure
access to `bpftrace` and kernel BTF data as described below.

## bpftrace command

The `bpftrace-ls` LSP server invokes `bpftrace` to obtain compiler diagnostics
and information about available probes and their arguments. It uses:

- `bpftrace --dry-run` for diagnostics (`bpftrace -d` for versions older than 0.22).
- `bpftrace -l` to list available probes.
- `bpftrace -l -v` to obtain probe argument information (for `tracepoint`, `rawtracepoint` and `uprobe`).

Depending on the operation, `bpftrace` may require additional Linux capabilities
or root privileges. During startup, the server tries running `bpftrace`
directly, then through non-interactive `sudo -n` if the initial direct
invocation fails. It reuses the first successful method for subsequent commands.

For a non-root user, there are several ways to grant the required privileges:
configure capabilities on the `bpftrace` binary, configure passwordless
`sudo`, or start the server with `run0`, as described below.

### Option 1: Capabilities

Capabilities can be set on the system `bpftrace` binary or on a local copy.
Using a separate, user-owned copy avoids granting privileges to the
system-wide `bpftrace` binary.

```bash
cp "$(command -v bpftrace)" "$HOME/my_bpftrace"
sudo setcap cap_dac_read_search,cap_dac_override,cap_sys_admin+ep "$HOME/my_bpftrace"
```

Verify that the local copy runs without errors:

```bash
cd $HOME
./my_bpftrace --info
./my_bpftrace -l | head
```

This capability setup is known to work with bpftrace 0.25 and later.

See the [client configuration](#using-custom-command) section to configure
`bpftrace-ls` to use the local copy.

### Option 2: sudo

Determine the username and `bpftrace` path:
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

Verify that `bpftrace` can be invoked through non-interactive `sudo`:
```bash
sudo -n bpftrace --info
sudo -n bpftrace -l | head
```

### Option 3: run0
If `systemd` and `polkit` are available, the server can be invoked through
`run0`. Authentication is performed before server starts (you will be prompted
for password).

Configuring `run0` in Neovim (see below for full config):
```lua
vim.lsp.config['bpftrace-ls'] = {
  cmd = { 'run0', 'bpftrace-ls' },
  ...
}
```


## Kernel

`bpftrace-ls` uses [BTF](https://docs.kernel.org/bpf/btf.html) (BPF Type Format)
for argument and return types in kernel probes (`fentry`, `fexit`, `kprobe`,
and `kretprobe`). BTF also enables completion and hover information for
structure and union fields.

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
If the bpftrace filetype is recognized (if not, see blow), register the language server in Neovim `init.lua`. Ensure `bpftrace-ls` is in `PATH`, or specify its full path. See [documentation]( https://neovim.io/doc/user/lsp.html) for details.
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

### VS Code LSP configuration

Install the following extensions:

- [vscode-lspconfig](https://marketplace.visualstudio.com/items?itemName=whtsht.vscode-lspconfig)
  to connect VS Code to `bpftrace-ls`.
- [bpftrace](https://marketplace.visualstudio.com/items?itemName=bpfdeploy.bpftrace)
  by bpfdeploy-io for `.bt` filetype detection and syntax highlighting.

Add the following to your workspace's `.vscode/settings.json`. Ensure
`bpftrace-ls` is in `PATH`, or replace it with the full path to the executable.

```json
{
  "vscode-lspconfig.serverConfigurations": [
    {
      "name": "bpftrace-ls",
      "document_selector": [
        { "language": "bpftrace" }
      ],
      "command": ["bpftrace-ls"]
    }
  ]
}
```

For a custom `bpftrace` executable, append `"--cmd", "/path/to/bpftrace"` to
the `command` array.

Run **Developer: Reload Window** from the Command Palette, then open a `.bt`
file. The language mode in the status bar should be **bpftrace**.

#### Troubleshooting

If the server does not start or `.bt` files are not recognized, open the
Extensions view (`Ctrl+Shift+X`) and check that both **vscode-lspconfig** and
**bpftrace** are installed and enabled for the current workspace. Extensions
can be disabled globally or for an individual workspace. Use each extension's
gear menu to select **Enable** or **Enable (Workspace)** as appropriate, then
reload the window. See [VS Code's extension management documentation](https://code.visualstudio.com/docs/configure/extensions/extension-marketplace#enable-an-extension)
for details.
