// SPDX-License-Identifier: GPL-2.0
// Build with a generated vmlinux.h; see README.md.
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define DNS_NAME_MAX 254

struct dns_event {
    __u32 pid;
    __u32 uid;
    __u8 protocol;
    __u8 padding[3];
    char process[16];
    char domain[DNS_NAME_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int capture_dns(struct sock *sk, struct msghdr *msg, size_t len,
                                       __u8 protocol, int dns_offset)
{
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    void *message_name = BPF_CORE_READ(msg, msg_name);
    if (protocol == IPPROTO_UDP && !dport && message_name) {
        struct sockaddr destination = {};
        if (bpf_probe_read_kernel(&destination, sizeof(destination), message_name) < 0)
            return 0;
        if (destination.sa_family == AF_INET) {
            struct sockaddr_in destination4 = {};
            if (bpf_probe_read_kernel(&destination4, sizeof(destination4), message_name) < 0)
                return 0;
            dport = destination4.sin_port;
        } else if (destination.sa_family == AF_INET6) {
            struct sockaddr_in6 destination6 = {};
            if (bpf_probe_read_kernel(&destination6, sizeof(destination6), message_name) < 0)
                return 0;
            dport = destination6.sin6_port;
        }
    }
    if (__builtin_bswap16(dport) != 53 || len < 13 + dns_offset)
        return 0;

    const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
    if (!iov)
        return 0;
    const unsigned char *payload = BPF_CORE_READ(iov, iov_base);
    if (!payload)
        return 0;

    unsigned char header[13];
    if (bpf_probe_read_user(header, sizeof(header), payload + dns_offset) < 0)
        return 0;
    if (protocol == IPPROTO_TCP) {
        __u16 frame_length = ((__u16)header[0] << 8) | header[1];
        if (frame_length < 13 || frame_length + 2 > len)
            return 0;
    }
    if ((header[2] & 0x80) || header[4] == 0 || header[12] == 0)
        return 0;

    struct dns_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    __builtin_memset(event, 0, sizeof(*event));
    __u64 id = bpf_get_current_pid_tgid();
    event->pid = id >> 32;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->protocol = protocol;
    bpf_get_current_comm(event->process, sizeof(event->process));

    int source = 12 + dns_offset;
    int target = 0;
#pragma unroll
    for (int labels = 0; labels < 64; labels++) {
        unsigned char label_len = 0;
        if (source >= len)
            goto discard;
        if (bpf_probe_read_user(&label_len, 1, payload + source) < 0)
            goto discard;
        source++;
        if (label_len == 0) {
            event->domain[target] = 0;
            bpf_ringbuf_submit(event, 0);
            return 0;
        }
        if (label_len > 63 || source + label_len > len ||
            (target && target >= DNS_NAME_MAX - 1))
            goto discard;
        if (target)
            event->domain[target++] = '.';
#pragma unroll
        for (int i = 0; i < 63; i++) {
            if (i >= label_len)
                break;
            if (target >= DNS_NAME_MAX - 1)
                goto discard;
            if (bpf_probe_read_user(&event->domain[target], 1, payload + source + i) < 0)
                goto discard;
            target++;
        }
        source += label_len;
    }

discard:
    bpf_ringbuf_discard(event, 0);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    return capture_dns(sk, msg, len, IPPROTO_UDP, 0);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    return capture_dns(sk, msg, len, IPPROTO_TCP, 2);
}

char LICENSE[] SEC("license") = "GPL";
