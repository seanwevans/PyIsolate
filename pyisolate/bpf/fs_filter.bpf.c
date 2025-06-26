#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/limits.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, char[PATH_MAX]);
} allowed_paths SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(check_file_open, struct file *file, int mask)
{
    char path[PATH_MAX];
    if (bpf_d_path(&file->f_path, path, sizeof(path)) < 0)
        return 0;

    __u32 idx;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        idx = i;
        const char *allowed = bpf_map_lookup_elem(&allowed_paths, &idx);
        if (!allowed)
            break;
        int match = 1;
#pragma unroll
        for (int j = 0; j < PATH_MAX; j++) {
            char c = allowed[j];
            if (!c)
                break;
            if (c != path[j]) {
                match = 0;
                break;
            }
        }
        if (match)
            return 0;
    }
    return -13; /* -EACCES */
}

char _license[] SEC("license") = "GPL";
