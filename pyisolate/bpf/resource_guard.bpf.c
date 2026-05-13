#define SEC(NAME) __attribute__((section(NAME), used))

/* Per-cgroup resource accounting and quota breach events for PyIsolate. */

typedef unsigned int __u32;
typedef unsigned long long __u64;

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_HASH 5
#define BPF_MAP_TYPE_RINGBUF 27

#define PYI_RESOURCE_CPU 1U
#define PYI_RESOURCE_RSS 2U
#define PYI_RESOURCE_NET 3U

#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

struct resource_account {
    __u64 cpu_time_ns;
    __u64 rss_bytes;
    __u64 net_bytes;
    __u64 last_seen_ns;
};

struct resource_quota {
    __u64 cpu_time_ns;
    __u64 rss_bytes;
    __u64 net_bytes;
};

struct resource_event {
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u64 observed;
    __u64 quota;
    __u32 resource;
    __u32 breached;
};

struct sched_switch_args {
    unsigned long long pad;
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

struct page_fault_args {
    unsigned long long pad;
    unsigned long address;
    unsigned long ip;
    int error_code;
};

struct __sk_buff {
    __u32 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} resource_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct resource_account);
} cgroup_accounting SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct resource_quota);
} cgroup_quotas SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} task_cpu_start SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *)130;

static void emit_if_breached(__u64 cg, struct resource_account *account)
{
    struct resource_quota *quota = bpf_map_lookup_elem(&cgroup_quotas, &cg);
    struct resource_event event = {};

    if (!quota)
        return;

    event.cgroup_id = cg;
    event.pid_tgid = bpf_get_current_pid_tgid();
    if (quota->cpu_time_ns && account->cpu_time_ns > quota->cpu_time_ns) {
        event.observed = account->cpu_time_ns;
        event.quota = quota->cpu_time_ns;
        event.resource = PYI_RESOURCE_CPU;
        event.breached = 1;
        bpf_ringbuf_output(&resource_events, &event, sizeof(event), 0);
    }
    if (quota->rss_bytes && account->rss_bytes > quota->rss_bytes) {
        event.observed = account->rss_bytes;
        event.quota = quota->rss_bytes;
        event.resource = PYI_RESOURCE_RSS;
        event.breached = 1;
        bpf_ringbuf_output(&resource_events, &event, sizeof(event), 0);
    }
    if (quota->net_bytes && account->net_bytes > quota->net_bytes) {
        event.observed = account->net_bytes;
        event.quota = quota->net_bytes;
        event.resource = PYI_RESOURCE_NET;
        event.breached = 1;
        bpf_ringbuf_output(&resource_events, &event, sizeof(event), 0);
    }
}

static struct resource_account *account_for_current_cgroup(__u64 *cg_out)
{
    __u64 cg = bpf_get_current_cgroup_id();
    struct resource_account zero = {};
    struct resource_account *account;

    account = bpf_map_lookup_elem(&cgroup_accounting, &cg);
    if (!account) {
        zero.last_seen_ns = bpf_ktime_get_ns();
        bpf_map_update_elem(&cgroup_accounting, &cg, &zero, 0);
        account = bpf_map_lookup_elem(&cgroup_accounting, &cg);
    }
    *cg_out = cg;
    return account;
}

SEC("tracepoint/sched/sched_switch")
int account_sched_switch(struct sched_switch_args *ctx)
{
    __u64 cg;
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *started = bpf_map_lookup_elem(&task_cpu_start, &pid_tgid);
    struct resource_account *account = account_for_current_cgroup(&cg);

    if (account && started && now > *started) {
        account->cpu_time_ns += now - *started;
        account->last_seen_ns = now;
        emit_if_breached(cg, account);
    }

    bpf_map_update_elem(&task_cpu_start, &pid_tgid, &now, 0);
    return 0;
}

SEC("tracepoint/exceptions/page_fault_user")
int account_user_page_fault(struct page_fault_args *ctx)
{
    __u64 cg;
    struct resource_account *account = account_for_current_cgroup(&cg);

    if (account) {
        account->rss_bytes += 4096;
        account->last_seen_ns = bpf_ktime_get_ns();
        emit_if_breached(cg, account);
    }
    return 0;
}

SEC("cgroup_skb/egress")
int account_cgroup_egress(struct __sk_buff *skb)
{
    __u64 cg;
    struct resource_account *account = account_for_current_cgroup(&cg);

    if (account) {
        account->net_bytes += skb->len;
        account->last_seen_ns = bpf_ktime_get_ns();
        emit_if_breached(cg, account);
    }
    return 1;
}

char _license[] SEC("license") = "GPL";
