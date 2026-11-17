# hatchway.config

Where hatchway keeps its configuration and its records, and how a profile is found.

Config: `$HATCHWAY_CONFIG_DIR` or `~/.config/hatchway/` (`config.toml`, the flag
files such as `allow-dispatch`, optional user profiles in `profiles/`).
Data: `$HATCHWAY_DATA_DIR` or `~/.local/share/hatchway/` (`calls.jsonl`, the
snapshot in `out/`, backups of files hatchway edited in `backups/`).

The config file is optional; every key has a default:

```default
profile = "claude-fleet"      # a bundled profile name, or a path to a .toml
path = ["/opt/bin"]           # prepended to PATH for the commands the gate runs
timeout = 120                 # seconds before a command is stopped
[roots]                       # directories file rules may serve, by name
ledger = "~/.local/share/crowsnest/ledger"
[dispatch]
roots = ["~/projects"]        # where a dispatch (spawn) may start a session
[snapshot]
to = ""                       # optional extra copy: a local dir or host:path (rsync)
```

### Functions

| `config_dir`()                                                                              |                                                                                                     |
|---------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `data_dir`()                                                                                |                                                                                                     |
| `load_profile`([name_or_path, settings])                                                    |                                                                                                     |
| [`load_settings`](#hatchway.config.load_settings)(\*[, config_file])           | Read `config.toml` (absent is fine) into [`Settings`](#hatchway.config.Settings). |
| [`profile_path`](#hatchway.config.profile_path)(name_or_path, \*[, settings]) | A profile by path, else `<config>/profiles/<name>.toml`, else a bundled one.                        |

### Classes

| [`Settings`](#hatchway.config.Settings)([profile, path, timeout, roots, ...])   | The resolved configuration the gate and the snapshot run with.   |
|---------------------------------------------------------------------------------------------------|------------------------------------------------------------------|

### *class* hatchway.config.Settings(profile='claude-fleet', path=list(), timeout=120, roots=dict(), dispatch_roots=list(), snapshot_to='', config_dir=config_dir(), data_dir=data_dir())

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

The resolved configuration the gate and the snapshot run with.

#### all_roots()

File-rule roots: `out` (the snapshot) always, plus the configured ones.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### hatchway.config.load_settings(, config_file=None, \*\*overrides)

Read `config.toml` (absent is fine) into [`Settings`](#hatchway.config.Settings).

* **Return type:**
  [`Settings`](#hatchway.config.Settings)

### hatchway.config.profile_path(name_or_path, , settings=None)

A profile by path, else `<config>/profiles/<name>.toml`, else a bundled one.

* **Return type:**
  [`Path`](https://docs.python.org/3/library/pathlib.html#pathlib.Path)
