#define SEC(NAME) __attribute__((section(NAME), used))

/* Resource guard event consumed by pyisolate.watchdog.ResourceWatchdog.
 * The supervisor resolves cgroup_id/name to a SandboxThread and performs the
 * userspace kill/quarantine path immediately; Python tracemalloc accounting is
 * diagnostic only and is not used as the security decision point.
 */
enum breach_reason {
    BREACH_CPU = 1,
    BREACH_RSS = 2,
};

struct quota_t {
    unsigned long cpu_quota_ns;
    unsigned long rss_quota_bytes;
};

struct usage_t {
    unsigned long cpu_time_ns;
    unsigned long rss_bytes;
};

struct event_t {
    unsigned long cgroup_id;
    unsigned long cpu_time_ns;
    unsigned long rss_bytes;
    unsigned int reason;
};

/* Map placeholders. The production CO-RE object uses BPF_MAP_TYPE_HASH for
 * quota/usage keyed by cgroup id and BPF_MAP_TYPE_RINGBUF for events. Keeping
 * the declarations header-free preserves the lightweight test build while
 * documenting the kernel/userspace contract.
 */
struct {
    int dummy;
} quotas SEC(".maps");

struct {
    int dummy;
} usage SEC(".maps");

struct {
    int dummy;
} events SEC(".maps");

static __inline int emit_breach(unsigned long cgroup_id,
                                unsigned long cpu_time_ns,
                                unsigned long rss_bytes,
                                unsigned int reason)
{
    /* Real implementation reserves event_t on the ring buffer and submits it.
     * Tests inject equivalent dictionaries through BPFManager.open_ring_buffer.
     */
    (void)cgroup_id;
    (void)cpu_time_ns;
    (void)rss_bytes;
    (void)reason;
    return 0;
}

SEC("perf_event")
int on_cpu(void *ctx)
{
    /* Production path increments per-cgroup CPU usage, compares it to
     * quota_t.cpu_quota_ns, and emits BREACH_CPU before userspace can rely on
     * guest cooperation.
     */
    (void)ctx;
    return emit_breach(0, 0, 0, BREACH_CPU);
}

SEC("perf_event")
int on_rss(void *ctx)
{
    /* Production path samples cgroup RSS, compares it to
     * quota_t.rss_quota_bytes, and emits BREACH_RSS for watchdog enforcement.
     */
    (void)ctx;
    return emit_breach(0, 0, 0, BREACH_RSS);
}

char _license[] SEC("license") = "GPL";
