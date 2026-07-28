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
    char process[16];
    char domain[DNS_NAME_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (__builtin_bswap16(dport) != 53 || len < 13)
        return 0;

    const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
    if (!iov)
        return 0;
    const unsigned char *payload = BPF_CORE_READ(iov, iov_base);
    if (!payload)
        return 0;

    unsigned char header[13];
    if (bpf_probe_read_user(header, sizeof(header), payload) < 0)
        return 0;
    if ((header[2] & 0x80) || header[4] == 0 || header[12] == 0)
        return 0;

    struct dns_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    __builtin_memset(event, 0, sizeof(*event));
    __u64 id = bpf_get_current_pid_tgid();
    event->pid = id >> 32;
    event->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(event->process, sizeof(event->process));

    int source = 12;
    int target = 0;
#pragma unroll
    for (int labels = 0; labels < 64; labels++) {
        unsigned char label_len = 0;
        if (bpf_probe_read_user(&label_len, 1, payload + source) < 0)
            goto discard;
        source++;
        if (label_len == 0) {
            event->domain[target] = 0;
            bpf_ringbuf_submit(event, 0);
            return 0;
        }
        if (label_len > 63 || (target && target >= DNS_NAME_MAX - 1))
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

char LICENSE[] SEC("license") = "GPL";
