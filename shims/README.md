# shims/

POSIX shell wrappers that scan packages with dep-scan before passing the
original command through to the underlying package manager.

| Shim | Wraps |
|------|-------|
| `npmds` | `npm` |
| `pipds` | `pip` |
| `cargods` | `cargo` |
| `gods` | `go` |

## Quick install

```sh
cp shims/* ~/.local/bin/
```

Make sure `~/.local/bin` is on your `PATH` (`echo $PATH`). Then use
`npmds install <pkg>` in place of `npm install <pkg>`.

## How it works

Each shim separates flag tokens (those starting with `-`) from package-name
tokens, runs `dep-scan check --registry <r> <pkgs>`, and then `exec`s the
real command if dep-scan exits 0. If dep-scan returns non-zero the shim exits
with the same code and the real install does not run.

Package names that start with `-` are rejected by dep-scan's flag-injection
guard (F-001) before reaching the registry, so they never reach `npm install`
as hidden flags.

## Customisation

If you use a private registry, edit the `dep-scan check` line in the relevant
shim and add `--config /path/to/.dep-scan.toml` pointing at a config with
`[registries]` overrides.
