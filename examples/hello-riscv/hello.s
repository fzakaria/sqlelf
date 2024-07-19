.section .text
.globl _start
.equ STDOUT, 1 # File descriptor 1 is standard output (stdout)
.equ WRITE, 64 # Linux write syscall
.equ EXIT, 93 # Linux exit syscall
.equ EXIT_CODE_SUCCESS, 0
  
_start:
    # In C, a list of parameters is passed to the kernel in a certain sequence.
    # For the write system call, the parameters are structured as follows:
    # ssize_t write(int fd, const void *buf, size_t count)
    # The three parameters passed are:
    # 1. a file descriptor (e.g. 1 for stdout)
    # 2. a pointer to a character buffer (i.e. a string)
    # 3. the number of characters in that string to be written. 
    li a0, STDOUT
    la a1, buf_begin
    # Load a byte from memory, zero-pad it (to a 64-bit value in RV64), and store
    # the unsigned value in the destination register a2.
    lbu a2, buf_size
    
    # Store the system call number in register a7.
    li a7, WRITE
    # Switch to RISC-V supervisor mode (the Linux kernel runs in this mode) and
    # make a request using the value stored in a7 as the system call number.
    ecall

    li a0, EXIT_CODE_SUCCESS
    li a7, EXIT
    ecall

# The .rodata section of an ELF binary contains constant values. The .rodata
# section is marked as read-only, so these values cannot change at runtime.
.section .rodata

buf_begin:
    .string "Hello World!\n"
buf_size:
    # Current address (the .) minus address of buf_begin = length of buffer.
    # We store the result in a 8-bit word using the .byte directive.
    .byte .-buf_begin
