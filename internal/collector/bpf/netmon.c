//go:build linux && ignore
// +build linux,ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16

struct network_event {
    __u64 timestamp;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 size;
    __u8 direction; // 0: ingress, 1: egress
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Per-process packet counter
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10240);
} process_stats SEC(".maps");

static __always_inline int parse_ip_header(struct __sk_buff *skb, struct network_event *event, __u8 direction) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;
    
    event->saddr = ip->saddr;
    event->daddr = ip->daddr;
    event->size = bpf_ntohs(ip->tot_len);
    
    // Parse transport layer
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return -1;
        
        event->sport = bpf_ntohs(tcp->source);
        event->dport = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return -1;
        
        event->sport = bpf_ntohs(udp->source);
        event->dport = bpf_ntohs(udp->dest);
    }
    
    event->direction = direction;
    event->timestamp = bpf_ktime_get_ns();
    
    // Get PID and comm
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    return 0;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    struct network_event event = {};
    
    if (parse_ip_header(skb, &event, 0) < 0)
        return TC_ACT_OK;
    
    // Update per-process stats
    __u32 pid = event.pid;
    __u64 *stats = bpf_map_lookup_elem(&process_stats, &pid);
    if (stats) {
        __sync_fetch_and_add(stats, event.size);
    } else {
        __u64 initial = event.size;
        bpf_map_update_elem(&process_stats, &pid, &initial, BPF_ANY);
    }
    
    // Send event
    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    struct network_event event = {};
    
    if (parse_ip_header(skb, &event, 1) < 0)
        return TC_ACT_OK;
    
    // Update per-process stats
    __u32 pid = event.pid;
    __u64 *stats = bpf_map_lookup_elem(&process_stats, &pid);
    if (stats) {
        __sync_fetch_and_add(stats, event.size);
    } else {
        __u64 initial = event.size;
        bpf_map_update_elem(&process_stats, &pid, &initial, BPF_ANY);
    }
    
    // Send event
    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return TC_ACT_OK;
}

// Socket-level monitoring for more accurate process tracking
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(void *ctx) {
    struct network_event event = {};
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.timestamp = bpf_ktime_get_ns();
    event.direction = 1; // egress
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Note: In real implementation, we would parse syscall args to get size
    event.size = 0; // Placeholder
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_recvfrom(void *ctx) {
    struct network_event event = {};
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.timestamp = bpf_ktime_get_ns();
    event.direction = 0; // ingress
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Note: In real implementation, we would parse syscall return value to get size
    event.size = 0; // Placeholder
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";