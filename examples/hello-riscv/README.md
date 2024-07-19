# Hello World in RISC-V

This example shows how to assemble, link and query a simple Hello World program for RISC-V.

If you want to run this example, you will need a cross-compiling toolchain like the [RISC-V GNU Compiler Toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain) and [QEMU](https://www.qemu.org/).

## 32-bit

Assemble `hello.s` into an object file for the RISC-V 32-bit base integer instruction set (`-march rv32i`), little-endian (`-mlittle-endian`), with an ABI that follows the convention where `int`, `long` and `pointer` types are all 32-bit, with debug symbols included in the object file (`-g`):

```sh
riscv64-elf-as -march rv32i -mabi ilp32 -mlittle-endian -o hello.o hello.s -g
```

Link the object file into a RISC-V 32-bit little-endian executable (`-m elf32lriscv`), with the symbol `_start` as its entry point:

```sh
riscv64-elf-ld -e _start -m elf32lriscv -o exe --verbose hello.o
```

Execute the RISC-V ELF in QEMU:

```sh
qemu-riscv32 exe
```

Double check the disassembly:

```sh
riscv64-elf-objdump --disassemble exe
```

## 64-bit

Assemble `hello.s` into an object file for the RISC-V 64-bit base integer instruction set (`-march rv64i`), little-endian (`-mlittle-endian`), with an ABI that follows the convention where `long` and `pointer` types are all 64-bit, with debug symbols included in the object file (`-g`):

```sh
riscv64-elf-as -march rv64i -mabi lp64 -mlittle-endian -o hello.o hello.s -g
```

Link the object file into a RISC-V 64-bit little-endian executable (`-m elf64lriscv`), with the symbol `_start` as its entry point:

```sh
riscv64-elf-ld -e _start -m elf64lriscv -o exe --verbose hello.o
```

Execute the RISC-V ELF in QEMU:

```sh
qemu-riscv64 exe
```

Double check the disassembly:

```sh
riscv64-elf-objdump --disassemble exe
```
