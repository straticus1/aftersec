#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

struct flow_event {
    __u64 timestamp_ns;
    __u64 started_ns;
    __u64 bytes_sent;
    __u64 bytes_received;
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

struct udp_flow_key {
    __u32 tgid;
    __u32 padding;
    __u64 socket_cookie;
};

struct udp_flow_state {
    __u64 started_ns;
    __u64 bytes_sent;
    __u64 bytes_received;
};

struct pending_udp_io {
    struct sock *sk;
    struct msghdr *msg;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_udp_io);
} pending_udp_send SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct pending_udp_io);
} pending_udp_receive SEC(".maps");

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
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct udp_flow_key);
    __type(value, struct udp_flow_state);
} udp_flows SEC(".maps");

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
    event->started_ns = event->timestamp_ns;
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

static __always_inline int submit_udp(struct sock *sk, struct msghdr *msg,
                                      __u64 sent, __u64 received) {
    __u16 remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    void *message_name = BPF_CORE_READ(msg, msg_name);
    __u64 now = bpf_ktime_get_ns();
    struct udp_flow_key key = {
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .socket_cookie = bpf_get_socket_cookie(sk),
    };
    struct udp_flow_state initial = {.started_ns = now, .bytes_sent = 0, .bytes_received = 0};
    struct udp_flow_state *state = bpf_map_lookup_elem(&udp_flows, &key);
    if (!state) {
        bpf_map_update_elem(&udp_flows, &key, &initial, BPF_ANY);
        state = bpf_map_lookup_elem(&udp_flows, &key);
    }
    if (!state)
        return 0;
    if (sent)
        __sync_fetch_and_add(&state->bytes_sent, sent);
    if (received)
        __sync_fetch_and_add(&state->bytes_received, received);

    struct flow_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = now;
    event->started_ns = state->started_ns;
    event->bytes_sent = state->bytes_sent;
    event->bytes_received = state->bytes_received;
    event->pid = key.tgid;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->family = family;
    event->protocol = IPPROTO_UDP;
    event->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->remote_port = remote_port;
    bpf_get_current_comm(event->process, sizeof(event->process));
    if (event->family == AF_INET) {
        __u32 local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        if (!remote_port && message_name) {
            struct sockaddr_in destination = {};
            if (bpf_probe_read_kernel(&destination, sizeof(destination), message_name) == 0) {
                remote_port = bpf_ntohs(destination.sin_port);
                remote = destination.sin_addr.s_addr;
            }
        }
        __builtin_memcpy(event->local_addr, &local, sizeof(local));
        __builtin_memcpy(event->remote_addr, &remote, sizeof(remote));
    } else if (event->family == AF_INET6) {
        struct in6_addr remote6 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
        if (!remote_port && message_name) {
            struct sockaddr_in6 destination6 = {};
            if (bpf_probe_read_kernel(&destination6, sizeof(destination6), message_name) == 0) {
                remote_port = bpf_ntohs(destination6.sin6_port);
                remote6 = destination6.sin6_addr;
            }
        }
        BPF_CORE_READ_INTO(event->local_addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        __builtin_memcpy(event->remote_addr, &remote6, sizeof(remote6));
    } else {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    event->remote_port = remote_port;
    if (!event->local_port || !event->remote_port) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(enter_udp_sendmsg, struct sock *sk, struct msghdr *msg) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_udp_io value = {.sk = sk, .msg = msg};
    return bpf_map_update_elem(&pending_udp_send, &pid_tgid, &value, BPF_ANY);
}

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(exit_udp_sendmsg, int sent) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_udp_io *io = bpf_map_lookup_elem(&pending_udp_send, &pid_tgid);
    if (!io)
        return 0;
    if (sent > 0)
        submit_udp(io->sk, io->msg, sent, 0);
    bpf_map_delete_elem(&pending_udp_send, &pid_tgid);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(enter_udp_recvmsg, struct sock *sk, struct msghdr *msg) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_udp_io value = {.sk = sk, .msg = msg};
    return bpf_map_update_elem(&pending_udp_receive, &pid_tgid, &value, BPF_ANY);
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(exit_udp_recvmsg, int received) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_udp_io *io = bpf_map_lookup_elem(&pending_udp_receive, &pid_tgid);
    if (!io)
        return 0;
    if (received > 0)
        submit_udp(io->sk, io->msg, 0, received);
    bpf_map_delete_elem(&pending_udp_receive, &pid_tgid);
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
