# Linux eBPF network sensor

Build `aftersec_network.bpf.c` with the target kernel's CO-RE `vmlinux.h` and
install the resulting object as `/var/lib/aftersec/aftersec-network.bpf.o`,
owned by root and not group/world writable.

The object attaches entry/return probes to `tcp_v4_connect` and
`tcp_v6_connect`, correlates the socket in a bounded LRU map, and emits only
successful connections with exact PID/UID, process, local/remote endpoints,
and TCP protocol. Incomplete records are discarded in-kernel and rejected
again by the Go validator.
