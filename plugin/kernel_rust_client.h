/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KERNEL_RUST_CLIENT_H_
#define KERNEL_RUST_CLIENT_H_
#include <daemon.h>
#include <threading/mutex.h>
#include <jansson.h>
#define KERNEL_RUST_CLIENT "kernel-rust-client"
#define KR_MAX_FRAME 131072

typedef struct { char bytes[KR_MAX_FRAME]; size_t len; } kernel_rust_frames_t;
typedef struct {
    int rpc, events;
    mutex_t *mutex;
    kernel_feature_t features;
    bool closing;
    kernel_rust_frames_t control_frames, event_frames;
} kernel_rust_client_t;
kernel_rust_client_t *kernel_rust_client_create(void);
void kernel_rust_client_destroy(kernel_rust_client_t *client);
/* Consumes parameters. Returns an owning reference to reply parameters. */
status_t kernel_rust_call(kernel_rust_client_t *client, const char *method,
                          json_t *parameters, json_t **reply);
json_t *kernel_rust_host(host_t *host);
host_t *kernel_rust_parse_host(json_t *value);
json_t *kernel_rust_ts(traffic_selector_t *ts);
traffic_selector_t *kernel_rust_parse_ts(json_t *value);
json_t *kernel_rust_mark(mark_t mark);
json_t *kernel_rust_u64(uint64_t value);
bool kernel_rust_parse_u64(json_t *value, uint64_t *out);
enumerator_t *kernel_rust_enumerator(kernel_rust_client_t *client, bool subnets, json_t *parameters);
kernel_ipsec_t *kernel_rust_ipsec_create(void);
kernel_net_t *kernel_rust_net_create(void);
#endif
