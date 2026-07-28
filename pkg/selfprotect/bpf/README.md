# Linux BPF-LSM self-protection

Build `aftersec_selfprotect.bpf.c` as a CO-RE object and install it at
`/var/lib/aftersec/aftersec-selfprotect.bpf.o`. The host kernel must enable
`CONFIG_BPF_LSM` and include `bpf` in its active LSM list.

The daemon populates the protected inode map before attaching write, create,
unlink, and rename hooks. Only the current daemon TGID is allowed to mutate
those inodes, preserving an explicit recovery path.
