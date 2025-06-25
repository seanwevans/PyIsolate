#define SEC(NAME) __attribute__((section(NAME), used))
SEC("xdp")
int dummy_prog(void *ctx) {
    return 1;
}
char _license[] SEC("license") = "GPL";

