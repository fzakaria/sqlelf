# sqlelf

![build workflow](https://github.com/fzakaria/sqlelf/actions/workflows/main.yml/badge.svg)

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
```console
❯ python3 -m venv venv
❯ source venv/bin/activate
❯ pip install .
❯ sqlelf /usr/bin/python3 -- \
--sql "select mnemonic, COUNT(*) from elf_instructions GROUP BY mnemonic ORDER BY 2 DESC LIMIT 3"

mov|223497
call|56209
jmp|48213
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

You can provide _multiple SQL_ statements to the CLI. This is useful if you want to invoke many of the special _dot_ commands. You can use `.help` to see the list of possible commands or refer to the [apsw shell documentation](https://rogerbinns.github.io/apsw/shell.html).

For instance, to have _sqelf_ emit JSON you can do the following:
```console
❯ sqlelf /usr/bin/ruby --sql ".mode json" --sql "select path,name from elf_sections LIMIT 3;"
{ "path": "\/usr\/bin\/ruby", "name": ""},
{ "path": "\/usr\/bin\/ruby", "name": ".interp"},
{ "path": "\/usr\/bin\/ruby", "name": ".note.gnu.property"},
```

### Queries

<details>
<summary>List all symbol resolutions (match import & export)</summary>

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
</details>

<details>
<summary>Find symbols that are exported by more than one library</summary>

```console
❯ sqlelf ./examples/shadowed-symbols/exe --recursive --sql "
SELECT name, version, count(*) as symbol_count, GROUP_CONCAT(path, ':') as libraries
FROM elf_symbols
WHERE exported = TRUE
GROUP BY name, version
HAVING count(*) >= 2;"
┌──────┬────────┬───────────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ name │ versio │ symbol_co │                                                                       libraries                                                                        │
│      │   n    │    unt    │                                                                                                                                                        │
├──────┼────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ foo  │ NULL   │ 2         │ /usr/local/google/home/fmzakari/code/github.com/fzakaria/sqlelf/examples/shadowed-                                                                     │
│      │        │           │ symbols/x/libx.so:/usr/local/google/home/fmzakari/code/github.com/fzakaria/sqlelf/examples/shadowed-symbols/x/libx2.so                                 │
└──────┴────────┴───────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
</details>

<details>
<summary> List contained symbols, i.e. a symbol fully within the bounds of another</summary>

```console
sqlelf ./examples/nested-symbols/exe --sql "
SELECT outer_symbol.path, 
    outer_symbol.name AS outer_symbol_name, 
    inner_symbol.name AS inner_symbol_name
FROM 
    elf_symbols AS outer_symbol, 
    elf_symbols AS inner_symbol
WHERE
    inner_symbol.section = '.text' AND
    outer_symbol.section = '.text' AND
    inner_symbol.path = outer_symbol.path AND
    inner_symbol.value > outer_symbol.value AND
    (inner_symbol.value + inner_symbol.size) < (outer_symbol.value + outer_symbol.size) AND
    inner_symbol.name != outer_symbol.name LIMIT 5;"
┌──────────────────────────────────┬───────────────────┬───────────────────┐
│               path               │ outer_symbol_name │ inner_symbol_name │
│ ./examples/nested-symbols/nested │ outer_function    │ inner_symbol      │
└──────────────────────────────────┴───────────────────┴───────────────────┘
```

</details>

## Development

You may want to install the package in _editable mode_ as well to make development easier

```console
> pip install --editable ".[dev]"
```

A helping `Makefile` is provided to run all the _linters_ and _formatters_.

```console
> make lint
> make fmt
```