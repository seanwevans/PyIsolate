#define SEC(NAME) __attribute__((section(NAME), used))

/*
 * Minimal assertion helper for demo contracts.
 * The BPF verifier ensures the branch is safe.
 */
#define BPF_ASSERT(cond)              \
    if (!(cond))                     \
        return 0

volatile const int contract_value = 1;

SEC("xdp")
int dummy_prog(void *ctx) {
    BPF_ASSERT(ctx != (void *)0);
    BPF_ASSERT(contract_value == 1);
    return 1;
}
char _license[] SEC("license") = "GPL";

