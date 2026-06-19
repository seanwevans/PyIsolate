#define SEC(NAME) __attribute__((section(NAME), used))

/*
 * Kernel policy filter for PyIsolate sandboxes.
 *
 * The supervisor pins and updates these maps under /sys/fs/bpf/pyisolate.
 * Every decision is keyed by bpf_get_current_cgroup_id(), so enforcement follows
 * the sandbox cgroup even when guest code bypasses Python wrappers and performs
 * syscalls directly through libc or native extensions.
 */

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define EPERM 1
#define AF_INET 2
#define AF_INET6 10

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_RINGBUF 27

#define PYI_DENY_FS       (1U << 0)
#define PYI_DENY_NET      (1U << 1)
#define PYI_DENY_PROCESS  (1U << 2)
#define PYI_DENY_RISKY    (1U << 3)

#define PYI_OP_FILE_OPEN       1U
#define PYI_OP_FILE_TRUNCATE   2U
#define PYI_OP_SOCKET_CONNECT  3U
#define PYI_OP_SOCKET_CREATE   4U
#define PYI_OP_TASK_ALLOC      5U
#define PYI_OP_EXEC            6U
#define PYI_OP_PTRACE          7U
#define PYI_OP_MOUNT           8U
#define PYI_OP_BPF             9U

#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

union bpf_attr;

struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

struct pyisolate_policy {
    __u32 deny_mask;
    __u32 audit_only;
};

struct pyisolate_decision_key {
    __u64 cgroup_id;
    __u32 op;
    __u32 aux;
};

struct pyisolate_decision {
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u32 op;
    __u32 denied;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct pyisolate_policy);
} sandbox_policy SEC(".maps");

/* Optional per-operation overrides used for hot reload tests and staged rollout. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pyisolate_decision_key);
    __type(value, __u32);
} syscall_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} syscall_events SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *)130;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;

static __u32 policy_mask_for_op(__u32 op)
{
    if (op == PYI_OP_FILE_OPEN || op == PYI_OP_FILE_TRUNCATE)
        return PYI_DENY_FS;
    if (op == PYI_OP_SOCKET_CONNECT || op == PYI_OP_SOCKET_CREATE)
        return PYI_DENY_NET;
    if (op == PYI_OP_TASK_ALLOC || op == PYI_OP_EXEC)
        return PYI_DENY_PROCESS;
    return PYI_DENY_RISKY;
}

static int pyisolate_check(__u32 op, __u32 aux)
{
    __u64 cg = bpf_get_current_cgroup_id();
    struct pyisolate_policy *policy;
    struct pyisolate_decision_key key = {};
    __u32 *override;
    __u32 denied = 0;

    key.cgroup_id = cg;
    key.op = op;
    key.aux = aux;
    override = bpf_map_lookup_elem(&syscall_policy, &key);
    if (override)
        denied = *override;
    else {
        policy = bpf_map_lookup_elem(&sandbox_policy, &cg);
        if (policy && (policy->deny_mask & policy_mask_for_op(op)))
            denied = policy->audit_only ? 0 : 1;
    }

    if (denied) {
        struct pyisolate_decision event = {};
        event.cgroup_id = cg;
        event.pid_tgid = bpf_get_current_pid_tgid();
        event.op = op;
        event.denied = 1;
        bpf_ringbuf_output(&syscall_events, &event, sizeof(event), 0);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG_filter_file_open(void *file, int ret)
{
    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_FILE_OPEN, 0);
}

SEC("lsm/file_truncate")
int BPF_PROG_filter_file_truncate(void *file, int ret)
{
    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_FILE_TRUNCATE, 0);
}

SEC("lsm/socket_create")
int BPF_PROG_filter_socket_create(int family, int type, int protocol, int kern, int ret)
{
    if (ret)
        return ret;
    if (family == AF_INET || family == AF_INET6)
        return pyisolate_check(PYI_OP_SOCKET_CREATE, (__u32)family);
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG_filter_socket_connect(void *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (ret)
        return ret;
    if (address && (address->sa_family == AF_INET || address->sa_family == AF_INET6))
        return pyisolate_check(PYI_OP_SOCKET_CONNECT, (__u32)address->sa_family);
    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG_filter_task_alloc(void *task, unsigned long clone_flags, int ret)
{
    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_TASK_ALLOC, 0);
}

SEC("lsm/bprm_check_security")
int BPF_PROG_filter_exec(void *bprm, int ret)
{
    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_EXEC, 0);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG_filter_ptrace(void *child, unsigned int mode, int ret)
{
    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_PTRACE, mode);
}

SEC("lsm/sb_mount")
/* BPF programs receive at most five register arguments, so the opaque ``data``
 * blob of the sb_mount hook is omitted here; the filter only needs the prior
 * LSM decision (``ret``) and denies all mounts regardless of arguments. */
int BPF_PROG_filter_mount(const char *dev_name, const void *path, const char *type,
                          unsigned long flags, int ret)
{
    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_MOUNT, 0);
}

SEC("lsm/bpf")
int BPF_PROG_filter_bpf(int cmd, union bpf_attr *attr, unsigned int size, int ret)
{
    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_BPF, (__u32)cmd);
}

char _license[] SEC("license") = "GPL";
