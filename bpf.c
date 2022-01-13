#include <stdbool.h>
#include <linux/bpf.h>
#include <netinet/ip.h>
#include "bpf_helpers.h"

#define __section(NAME)                  \
	__attribute__((section(NAME), used))

/* Map for blocking IP addresses from userspace */
struct bpf_map_def __section("maps") blocked_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u32),
        .max_entries = 10000,
};

/* Handle a packet: return whether it should be allowed or dropped */
inline bool handle_pkt(struct __sk_buff *skb) {
    struct iphdr iph;

    /* Load packet header */
    bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));

    const char fmt_str[] = "hello world from ebpf!";
    bpf_trace_printk(fmt_str, sizeof(fmt_str));
    /* Check if IPs are in "blocked" map */
    bool blocked = bpf_map_lookup_elem(&blocked_map, &iph.saddr) || bpf_map_lookup_elem(&blocked_map, &iph.daddr);
    /* Return whether it should be allowed or dropped */
    return !blocked;
}

/* Ingress hook - handle incoming packets */
__section("cgroup_skb/ingress")
int ingress(struct __sk_buff *skb) {
	return (int)handle_pkt(skb);
}


/* Egress hook - handle outgoing packets */
__section("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
	return (int)handle_pkt(skb);
}


char __license[] __section("license") = "GPL";

