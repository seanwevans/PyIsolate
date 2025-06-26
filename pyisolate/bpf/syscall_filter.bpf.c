#define SEC(NAME) __attribute__((section(NAME), used))

/* Minimal syscall filter program. Returns 0 to allow all syscalls.
 * Real implementation would inspect arguments and decide.
 */

SEC("lsm/file_open")
int filter_file_open(void *ctx)
{
    return 0;
}

char _license[] SEC("license") = "GPL";
