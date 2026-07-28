// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_lsm.h>
#include <bpf/bpf_tracing.h>

#define EACCES 13
#define MAY_WRITE 2

struct inode_key {
    __u64 device;
    __u64 inode;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, struct inode_key);
    __type(value, __u8);
} protected_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} agent_tgid SEC(".maps");

static __always_inline int trusted_agent(void)
{
    __u32 zero = 0;
    __u32 *allowed = bpf_map_lookup_elem(&agent_tgid, &zero);
    return allowed && *allowed == (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline int protected_inode(struct inode *inode)
{
    if (!inode)
        return 0;
    struct inode_key key = {
        .device = BPF_CORE_READ(inode, i_sb, s_dev),
        .inode = BPF_CORE_READ(inode, i_ino),
    };
    return bpf_map_lookup_elem(&protected_inodes, &key) != 0;
}

SEC("lsm/file_permission")
int BPF_PROG(protect_file_permission, struct file *file, int mask, int ret)
{
    if (ret)
        return ret;
    if ((mask & MAY_WRITE) && protected_inode(BPF_CORE_READ(file, f_inode)) && !trusted_agent())
        return -EACCES;
    return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(protect_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode, int ret)
{
    if (ret)
        return ret;
    return protected_inode(dir) && !trusted_agent() ? -EACCES : 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(protect_inode_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
    if (ret)
        return ret;
    return protected_inode(dir) && !trusted_agent() ? -EACCES : 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(protect_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, unsigned int flags, int ret)
{
    if (ret)
        return ret;
    if ((protected_inode(old_dir) || protected_inode(new_dir)) && !trusted_agent())
        return -EACCES;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
