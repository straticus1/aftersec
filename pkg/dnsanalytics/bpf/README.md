# Linux DNS capture

`aftersec_dns.bpf.c` attributes outbound UDP DNS questions to the sending
process at `udp_sendmsg`. The daemon validates and normalizes every emitted
domain before detection.

Build on the target kernel architecture:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. \
  -c aftersec_dns.bpf.c -o aftersec-dns.bpf.o
install -o root -g root -m 0644 aftersec-dns.bpf.o /var/lib/aftersec/
```

Use `__TARGET_ARCH_arm64` on arm64. TCP DNS and encrypted DNS are not visible
to this UDP hook and must be covered by resolver/network policy.
