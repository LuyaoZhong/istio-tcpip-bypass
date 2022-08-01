// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 Intel Corporation */
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef NULL
#define NULL ((void*)0)
#endif

#define INBOUND_ENVOY_IP 0x600007f
#define SOCKOPS_MAP_SIZE 65535

#include <bpf/bpf_endian.h>

#undef bpf_printk
// Avoiding format string array on the stack
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

static __inline__ void print_ip4(uint32_t ip) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    // eBPF does not support loop before kernel 5.3
    bpf_printk("%c%d", ' ', bytes[3]);
    bpf_printk("%c%d", ',', bytes[2]);
    bpf_printk("%c%d", ',', bytes[1]);
    bpf_printk("%c%d", ',', bytes[0]);

}

static __inline__ void log(enum sk_action action, uint32_t src_ip, uint32_t dst_ip)
{
    if (action == SK_PASS) {
        char info_fmt[] = "data redirection succeed:";
        bpf_trace_printk(info_fmt, sizeof(info_fmt));
    } else {
        char info_fmt[] = "data redirection failed:";
        bpf_trace_printk(info_fmt, sizeof(info_fmt));
    }
    print_ip4(src_ip);
    bpf_printk(" ->");
    print_ip4(dst_ip);
    bpf_printk("\n");
}

struct addr_2_tuple {
    uint32_t ip4;
    uint32_t port;
};

struct socket_4_tuple {
    struct addr_2_tuple local;
    struct addr_2_tuple remote;
};

/* when active establish, record local addr as key and remote addr as value
|--------------------------------------------------------------------|
|   key(local ip, local port)   |     Val(remote ip, remoteport)     |
|--------------------------------------------------------------------|
|        A-ip,A-app-port        |    B-cluster-ip,B-cluster-port     |
|--------------------------------------------------------------------|
|       A-ip,A-envoy-port       |              B-ip,B-port           |
|--------------------------------------------------------------------|
*/
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, SOCKOPS_MAP_SIZE);
        __type(key, struct addr_2_tuple);
        __type(value, struct addr_2_tuple);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_active_estab SEC(".maps");

/* This is a proxy map to store current socket 4-tuple and other side socket 4-tuple
|-------------------------------------------------------------------------------------------|
|          key(current socket 4-tuple)        |        Val(other side socket 4-tuple)       |
|-------------------------------------------------------------------------------------------|
| A-ip,A-app-port,B-cluster-ip,B-cluster-port |    127.0.0.1,A-outbound,A-ip:A-app-port     |
|-------------------------------------------------------------------------------------------|
|   127.0.0.1,A-outbound,A-ip:A-app-port      | A-ip:A-app-port,B-cluster-ip,B-cluster-port |
|-------------------------------------------------------------------------------------------|
*/

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, SOCKOPS_MAP_SIZE);
        __type(key, struct socket_4_tuple);
        __type(value, struct socket_4_tuple);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_proxy SEC(".maps");

/* This a sockhash map for sk_msg redirect
|------------------------------------------------------------------------|
|  key(local_ip:local_port, remote_ip:remote_port) |     Val(skops)      |
|------------------------------------------------------------------------|
|   A-ip:A-app-port, B-cluster-ip,B-cluster-port   |     A-app-skops     |    <--- A-app active_estab CB
|------------------------------------------------------------------------|
|          A-ip:A-envoy-port, B-ip:B-port          |    A-envoy-skops    |    <--- A-envoy active_estab CB
|------------------------------------------------------------------------|
|       127.0.0.1:A-outbound, A-ip:A-app-port      |   A-outbound-skops  |    <--- A-outbound passive_estab CB
|------------------------------------------------------------------------|
|        B-ip:B-inbound, A-ip:A-envoy-port         |   B-inbound-skops   |    <--- B-inbound passive_estab CB
|------------------------------------------------------------------------|
*/
struct {
        __uint(type, BPF_MAP_TYPE_SOCKHASH);
        __uint(max_entries, SOCKOPS_MAP_SIZE);
        __uint(key_size, sizeof(struct socket_4_tuple));
        __uint(value_size, sizeof(uint32_t));
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_redir SEC(".maps");

/* This a array map for debug configuration and record bypassed packet number
|-----------|------------------------------------|
|     0     |   0/1 (disable/enable debug info)  |
|-----------|------------------------------------|
|     1     |       bypassed packets number      |
|------------------------------------------------|
*/
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 2);
        __type(key, uint32_t);
        __type(value, uint32_t);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} debug_map SEC(".maps");

static __inline__ void sk_ops_extract4_key(struct bpf_sock_ops *ops,
                struct socket_4_tuple *key)
{
    key->local.ip4 = ops->local_ip4;
    key->local.port = ops->local_port;
    key->remote.ip4 = ops->remote_ip4;
    key->remote.port = bpf_ntohl(ops->remote_port);
}


static __inline__ void sk_msg_extract4_keys(struct sk_msg_md *msg,
                struct socket_4_tuple *proxy_key, struct socket_4_tuple *key)
{
    proxy_key->local.ip4 = msg->local_ip4;
    proxy_key->local.port = msg->local_port;
    proxy_key->remote.ip4 = msg->remote_ip4;
    proxy_key->remote.port = bpf_ntohl(msg->remote_port);
    key->local.ip4 = msg->remote_ip4;
    key->local.port = bpf_ntohl(msg->remote_port);
    key->remote.ip4 = msg->local_ip4;
    key->remote.port = msg->local_port;
}
