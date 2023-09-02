# sqlelf

![example workflow](https://github.com/fzakaria/sqlelf/actions/workflows/main.yml/badge.svg)
[![built with nix](https://builtwithnix.org/badge.svg)](https://builtwithnix.org)

> Explore ELF objects through the power of SQL

A tool that utilizes SQLite's virtual table functionality to allow you to explore Linux ELF objects through SQL.

Traditionally exploring an ELF file was limited to tools such as `objdump` or `readelf`. While these tools are full featured in their parsing capability, the output format and ability to ask exploratory questions is limited.

`SQL` is the _lingua franca_ for asking questions in a declarative manner.
Let's enhance our ability to introspect binaries!

```mermaid
---
title: ELF Schema
---
erDiagram
    ELF_HEADERS ||--o{ ELF_SECTIONS : contains
    ELF_HEADERS {
        string path
        int type
        int version
        int machine
        int entry
    }
    ELF_SECTIONS {
        string path
        string name
        int offset
        int size
        int type
        blob content
    }
    ELF_HEADERS ||--o{ ELF_SYMBOLS : contains
    ELF_SECTIONS ||--o{ ELF_SYMBOLS : defined
    ELF_SYMBOLS {
        string path
        string name
        string demangled_name
        bool imported
        bool exported
        int section
        int size
    }
    ELF_HEADERS ||--o{ ELF_DYNAMIC_ENTRIES : defined
    ELF_DYNAMIC_ENTRIES {
        string path
        string tag
        string value
    }
    ELF_SECTIONS ||--o{ ELF_INSTRUCTIONS : contains
    ELF_INSTRUCTIONS {
        string path
        string section
        string mnemonic
        string address
        string operands
    }
    ELF_SECTIONS ||--o{ ELF_STRINGS : contains
    ELF_STRINGS {
        string path
        string section
        string value
    }
```

## Installation
This repository can easily be installed, you simply need to have [Nix or NixOS](https://nixos.org) installed.

```console
❯ nix run github:fzakaria/sqlelf /usr/bin/python3 -- \
--sql "select mnemonic, COUNT(*) from elf_instructions GROUP BY mnemonic ORDER BY 2 DESC LIMIT 3"

mov|223497
call|56209
jmp|48213
```

Note: I publish artifacts to [cachix](https://cachix.org/) that you can use to develop faster.

```console
> cachix use fzakaria
```

## Usage
```console
❯ sqlelf --help
usage: sqlelf [-h] FILE [FILE ...]

Analyze ELF files with the power of SQL

positional arguments:
  FILE        The ELF file to analyze

options:
  -h, --help            show this help message and exit
  -s SQL, --sql SQL     Potential SQL to execute. Omitting this enters the REPL.
  --recursive, --no-recursive
                        Load all shared libraries needed by each file using ldd
```

Note: You may provide directories for `FILE`. Avoid giving too many binaries though since they must all be parsed at startup.
## Tour

You simply have to fire up `sqlelf` and give it a list of binaries or directories and start exploring ELF via SQL.

Simple demo showing a simple `SELECT` :

```console
❯ sqlelf /usr/bin/ruby --sql "select * from elf_headers"
/usr/bin/ruby|DYNAMIC|x86_64|CURRENT|4400
```

```console
❯ sqlelf /usr/bin/ruby /bin/ls
SQLite version 3.40.1 (APSW 3.40.0.0)
Enter ".help" for instructions
Enter SQL statements terminated with a ";"
sqlite> .header ON
sqlite> select * from elf_headers;
path|type|machine|version|entry
/usr/bin/ruby|3|62|1|4400
/bin/ls|3|62|1|25040
```

A more intricate demo showing an `INNER JOIN`, `WHERE` and `GROUP BY` across two tables which each represent different portions of the ELF format.
```console
SQLite version 3.40.1 (APSW 3.40.0.0)
Enter ".help" for instructions
Enter SQL statements terminated with a ";"
sqlite> .header ON
sqlite> SELECT elf_headers.path, COUNT(*) as num_sections
    ..> FROM elf_headers
    ..> INNER JOIN elf_sections ON elf_headers.path = elf_sections.path
    ..> WHERE elf_headers.type = 3
    ..> GROUP BY elf_headers.path;
path|num_sections
/bin/ls|31
/usr/bin/pnmarith|27
/usr/bin/ruby|28
```

### Queries

#### List all symbol resolutions

```console
❯ sqlelf /usr/bin/ruby --sql "SELECT caller.path as 'caller.path',
       callee.path as 'calee.path',
       caller.name,
       caller.demangled_name
FROM ELF_SYMBOLS caller
INNER JOIN ELF_SYMBOLS callee
ON
caller.name = callee.name AND
caller.path != callee.path AND
caller.imported = TRUE AND
callee.exported = TRUE
LIMIT 25;"
┌──────────────────────────────────────────┬──────────────────────────────────────────┬──────────────────────┬──────────────────────┐
│               caller.path                │                calee.path                │         name         │    demangled_name    │
│ /usr/bin/ruby                            │ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ ruby_run_node        │ ruby_run_node        │
│ /usr/bin/ruby                            │ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ ruby_init            │ ruby_init            │
│ /usr/bin/ruby                            │ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ ruby_options         │ ruby_options         │
│ /usr/bin/ruby                            │ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ ruby_sysinit         │ ruby_sysinit         │
│ /usr/bin/ruby                            │ /lib/x86_64-linux-gnu/libc.so.6          │ __stack_chk_fail     │ __stack_chk_fail     │
│ /usr/bin/ruby                            │ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ ruby_init_stack      │ ruby_init_stack      │
│ /usr/bin/ruby                            │ /lib/x86_64-linux-gnu/libc.so.6          │ setlocale            │ setlocale            │
│ /usr/bin/ruby                            │ /lib/x86_64-linux-gnu/libc.so.6          │ __libc_start_main    │ __libc_start_main    │
│ /usr/bin/ruby                            │ /lib/x86_64-linux-gnu/libc.so.6          │ __libc_start_main    │ __libc_start_main    │
│ /usr/bin/ruby                            │ /lib/x86_64-linux-gnu/libc.so.6          │ __cxa_finalize       │ __cxa_finalize       │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libc.so.6          │ initgroups           │ initgroups           │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libm.so.6          │ log10                │ log10                │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libc.so.6          │ chmod                │ chmod                │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libgmp.so.10       │ __gmpz_mul           │ __gmpz_mul           │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libm.so.6          │ lgamma_r             │ lgamma_r             │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libc.so.6          │ symlink              │ symlink              │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libc.so.6          │ mprotect             │ mprotect             │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libc.so.6          │ pipe2                │ pipe2                │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libc.so.6          │ seteuid              │ seteuid              │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libc.so.6          │ chdir                │ chdir                │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libc.so.6          │ fileno               │ fileno               │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libc.so.6          │ dup2                 │ dup2                 │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libc.so.6          │ pthread_cond_destroy │ pthread_cond_destroy │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libc.so.6          │ pthread_cond_destroy │ pthread_cond_destroy │
│ /lib/x86_64-linux-gnu/libruby-3.1.so.3.1 │ /lib/x86_64-linux-gnu/libm.so.6          │ atan2                │ atan2                │
└──────────────────────────────────────────┴──────────────────────────────────────────┴──────────────────────┴──────────────────────┘
```

## Development

You must have [Nix](https://nixos.org) installed for development.

This package uses [poetry2nix](https://github.com/nix-community/poetry2nix) to easily setup a development environment.

```console
❯ nix develop
$ sqlelf --help
usage: sqlelf [-h] [-s SQL] FILE [FILE ...]
```

A helping `Makefile` is provided to run all the _linters_ and _formatters_.

```console
> make lint
> make fmt
```