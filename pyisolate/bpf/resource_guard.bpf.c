#define SEC(NAME) __attribute__((section(NAME), used))

/* Event structure sent to user space via a ring buffer. */
struct event_t {
    unsigned long cgroup_id;
    unsigned long cpu_time_ns;
    unsigned long rss_bytes;
};

/* Ring buffer map placeholder. In a real implementation this would use
 * BPF_MAP_TYPE_RINGBUF and helper calls. */
struct {
    int dummy;
} events SEC(".maps");

SEC("perf_event")
int on_cpu(void *ctx)
{
    /* Track per-cgroup CPU time and emit events. Stubbed for tests. */
    return 0;
}

SEC("perf_event")
int on_rss(void *ctx)
{
    /* Track memory usage and emit events. Stubbed for tests. */
    return 0;
}

char _license[] SEC("license") = "GPL";
