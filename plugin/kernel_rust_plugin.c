/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kernel_rust_client.h"
#include <plugins/plugin.h>
typedef struct { plugin_t public; kernel_rust_client_t *client; } private_plugin_t;
METHOD(plugin_t, get_name, char*, private_plugin_t *this) { return "kernel-rust"; }
METHOD(plugin_t, get_features, int, private_plugin_t *this, plugin_feature_t **features)
{
    static plugin_feature_t f[] = {
        PLUGIN_CALLBACK(kernel_ipsec_register, kernel_rust_ipsec_create), PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
        PLUGIN_CALLBACK(kernel_net_register, kernel_rust_net_create), PLUGIN_PROVIDE(CUSTOM, "kernel-net"),
    };
    *features = f; return countof(f);
}
METHOD(plugin_t, destroy, void, private_plugin_t *this)
{
    lib->set(lib, KERNEL_RUST_CLIENT, NULL); kernel_rust_client_destroy(this->client); free(this);
}
PLUGIN_DEFINE(kernel_rust)
{
    private_plugin_t *this; kernel_rust_client_t *c;
    if (lib->get(lib, KERNEL_RUST_CLIENT)) { return NULL; }
    c = kernel_rust_client_create(); if (!c) { return NULL; }
    INIT(this, .public = { .get_name = _get_name, .get_features = _get_features, .destroy = _destroy }, .client = c);
    lib->set(lib, KERNEL_RUST_CLIENT, c); return &this->public;
}
