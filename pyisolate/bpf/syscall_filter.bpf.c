#define SEC(NAME) __attribute__((section(NAME), used))

/*
 * Kernel policy filter for PyIsolate sandboxes.
 *
 * The supervisor pins and updates these maps under /sys/fs/bpf/pyisolate.
 * Every decision is keyed by bpf_get_current_cgroup_id(), so enforcement follows
 * the sandbox cgroup even when guest code bypasses Python wrappers and performs
 * syscalls directly through libc or native extensions.
 *
 * Calling convention
 * ------------------
 * A BPF LSM program is called with ONE argument: a pointer to an array of
 * u64 holding the hook's arguments, with the previous LSM's return value
 * appended at index <number of hook args>. libbpf's BPF_PROG macro hides this
 * by generating a wrapper that unpacks the array into typed parameters; this
 * file is built without libbpf headers, so each handler takes the context
 * array directly and unpacks it by index. Declaring the typed parameters
 * without that wrapper does NOT work: the second parameter reads r2, which an
 * LSM program never sets, and the verifier rejects the program with
 * "R2 !read_ok" before it can be attached.
 *
 * Kernel pointers in the context array are opaque here for the same reason.
 * Direct loads through a kernel pointer are only allowed for BTF-typed
 * pointers (i.e. with vmlinux.h), so fields are read with
 * bpf_probe_read_kernel instead of being dereferenced.
 */

typedef unsigned char __u8;
typedef unsigned short __u16;
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

/* Offset of the previous LSM decision within the context array, which equals
 * the arity of the hook. Naming them keeps each handler's indexing checkable
 * against include/linux/lsm_hook_defs.h. */
#define PYI_RET_file_open            1  /* (struct file *file) */
#define PYI_RET_file_truncate        1  /* (struct file *file) */
#define PYI_RET_socket_create        4  /* (family, type, protocol, kern) */
#define PYI_RET_socket_connect       3  /* (struct socket *, struct sockaddr *, int) */
#define PYI_RET_task_alloc           2  /* (struct task_struct *, unsigned long) */
#define PYI_RET_bprm_check_security  1  /* (struct linux_binprm *bprm) */
#define PYI_RET_ptrace_access_check  2  /* (struct task_struct *child, unsigned int mode) */
#define PYI_RET_sb_mount             5  /* (dev_name, path, type, flags, data) */
#define PYI_RET_bpf                  3  /* (int cmd, union bpf_attr *attr, unsigned int size) */

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
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)113;

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
int filter_file_open(__u64 *ctx)
{
    int ret = (int)ctx[PYI_RET_file_open];

    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_FILE_OPEN, 0);
}

SEC("lsm/file_truncate")
int filter_file_truncate(__u64 *ctx)
{
    int ret = (int)ctx[PYI_RET_file_truncate];

    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_FILE_TRUNCATE, 0);
}

SEC("lsm/socket_create")
int filter_socket_create(__u64 *ctx)
{
    int ret = (int)ctx[PYI_RET_socket_create];
    __u32 family = (__u32)ctx[0];

    if (ret)
        return ret;
    if (family == AF_INET || family == AF_INET6)
        return pyisolate_check(PYI_OP_SOCKET_CREATE, family);
    return 0;
}

SEC("lsm/socket_connect")
int filter_socket_connect(__u64 *ctx)
{
    int ret = (int)ctx[PYI_RET_socket_connect];
    const void *address = (const void *)ctx[1];
    __u16 family = 0;

    if (ret)
        return ret;
    if (!address)
        return 0;
    /* sa_family is the first field of struct sockaddr. The pointer is not
     * BTF-typed here, so it has to be copied rather than dereferenced. */
    if (bpf_probe_read_kernel(&family, sizeof(family), address) != 0)
        return 0;
    if (family == AF_INET || family == AF_INET6)
        return pyisolate_check(PYI_OP_SOCKET_CONNECT, family);
    return 0;
}

SEC("lsm/task_alloc")
int filter_task_alloc(__u64 *ctx)
{
    int ret = (int)ctx[PYI_RET_task_alloc];

    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_TASK_ALLOC, 0);
}

SEC("lsm/bprm_check_security")
int filter_exec(__u64 *ctx)
{
    int ret = (int)ctx[PYI_RET_bprm_check_security];

    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_EXEC, 0);
}

SEC("lsm/ptrace_access_check")
int filter_ptrace(__u64 *ctx)
{
    int ret = (int)ctx[PYI_RET_ptrace_access_check];
    __u32 mode = (__u32)ctx[1];

    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_PTRACE, mode);
}

SEC("lsm/sb_mount")
int filter_mount(__u64 *ctx)
{
    int ret = (int)ctx[PYI_RET_sb_mount];

    if (ret)
        return ret;
    /* Denies all mounts regardless of arguments, so none are unpacked. */
    return pyisolate_check(PYI_OP_MOUNT, 0);
}

SEC("lsm/bpf")
int filter_bpf(__u64 *ctx)
{
    int ret = (int)ctx[PYI_RET_bpf];
    __u32 cmd = (__u32)ctx[0];

    if (ret)
        return ret;
    return pyisolate_check(PYI_OP_BPF, cmd);
}

char _license[] SEC("license") = "GPL";
