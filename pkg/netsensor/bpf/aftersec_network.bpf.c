#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

struct flow_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u16 local_port;
    __u16 remote_port;
    __u8 family;
    __u8 protocol;
    __u8 padding[2];
    char process[16];
    __u8 local_addr[16];
    __u8 remote_addr[16];
};

struct pending_socket {
    struct sock *sk;
    __u8 family;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_socket);
} pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int remember_socket(struct sock *sk, __u8 family) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_socket value = {.sk = sk, .family = family};
    return bpf_map_update_elem(&pending, &pid_tgid, &value, BPF_ANY);
}

static __always_inline int submit_connected(int result) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_socket *pending_socket = bpf_map_lookup_elem(&pending, &pid_tgid);
    if (!pending_socket)
        return 0;
    if (result != 0)
        goto cleanup;

    struct flow_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        goto cleanup;
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->family = pending_socket->family;
    event->protocol = IPPROTO_TCP;
    bpf_get_current_comm(event->process, sizeof(event->process));

    struct sock *sk = pending_socket->sk;
    event->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (event->family == AF_INET) {
        __u32 local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(event->local_addr, &local, sizeof(local));
        __builtin_memcpy(event->remote_addr, &remote, sizeof(remote));
    } else {
        BPF_CORE_READ_INTO(event->local_addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(event->remote_addr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }
    if (!event->local_port || !event->remote_port) {
        bpf_ringbuf_discard(event, 0);
        goto cleanup;
    }
    bpf_ringbuf_submit(event, 0);

cleanup:
    bpf_map_delete_elem(&pending, &pid_tgid);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(enter_tcp_v4_connect, struct sock *sk) {
    return remember_socket(sk, AF_INET);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(exit_tcp_v4_connect, int result) {
    return submit_connected(result);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(enter_tcp_v6_connect, struct sock *sk) {
    return remember_socket(sk, AF_INET6);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(exit_tcp_v6_connect, int result) {
    return submit_connected(result);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
