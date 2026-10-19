/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kernel_rust_client.h"
typedef struct { kernel_net_t public; kernel_rust_client_t *client; } private_net_t;
METHOD(kernel_net_t, get_features, kernel_feature_t, private_net_t *this) { return 0; }
METHOD(kernel_net_t, get_source_addr, host_t*, private_net_t *this, host_t *dest, host_t *src)
{
    json_t *r; host_t *host;
    if (kernel_rust_call(this->client, "GetSourceAddress", json_pack("{s:o,s:o}", "destination", kernel_rust_host(dest), "source", kernel_rust_host(src)), &r) != SUCCESS) { return NULL; }
    host = kernel_rust_parse_host(json_object_get(r, "address")); json_decref(r); return host;
}
METHOD(kernel_net_t, get_nexthop, host_t*, private_net_t *this, host_t *dest, int prefix, host_t *src, char **iface)
{
    json_t *r; host_t *host; const char *name;
    if (iface) { *iface = NULL; }
    if (kernel_rust_call(this->client, "GetNextHop", json_pack("{s:o,s:o,s:i}", "destination", kernel_rust_host(dest), "source", kernel_rust_host(src), "prefix", prefix), &r) != SUCCESS) { return NULL; }
    host = kernel_rust_parse_host(json_object_get(r, "gateway")); name = json_string_value(json_object_get(r, "interface"));
    if (!name) { DESTROY_IF(host); host = NULL; } else if (iface) { *iface = strdup(name); }
    json_decref(r); return host;
}
METHOD(kernel_net_t, get_interface, bool, private_net_t *this, host_t *host, char **name)
{
    json_t *r; const char *iface; bool ok;
    if (name) { *name = NULL; }
    if (kernel_rust_call(this->client, "GetInterface", json_pack("{s:o}", "address", kernel_rust_host(host)), &r) != SUCCESS) { return FALSE; }
    iface = json_string_value(json_object_get(r, "interface")); ok = iface != NULL;
    if (iface && name) { *name = strdup(iface); } json_decref(r); return ok;
}
METHOD(kernel_net_t, create_address_enumerator, enumerator_t*, private_net_t *this, kernel_address_type_t which)
{
    return kernel_rust_enumerator(this->client, FALSE, json_pack("{s:i}", "which", which));
}
METHOD(kernel_net_t, create_local_subnet_enumerator, enumerator_t*, private_net_t *this)
{
    return kernel_rust_enumerator(this->client, TRUE, json_object());
}
METHOD(kernel_net_t, add_ip, status_t, private_net_t *this, host_t *vip, int prefix, char *iface) { return NOT_SUPPORTED; }
METHOD(kernel_net_t, del_ip, status_t, private_net_t *this, host_t *vip, int prefix, bool wait) { return NOT_SUPPORTED; }
METHOD(kernel_net_t, add_route, status_t, private_net_t *this, chunk_t dst, uint8_t prefix, host_t *gw, host_t *src, char *iface, bool pass) { return NOT_SUPPORTED; }
METHOD(kernel_net_t, del_route, status_t, private_net_t *this, chunk_t dst, uint8_t prefix, host_t *gw, host_t *src, char *iface, bool pass) { return NOT_SUPPORTED; }
METHOD(kernel_net_t, destroy, void, private_net_t *this) { free(this); }
kernel_net_t *kernel_rust_net_create(void)
{
    private_net_t *this; kernel_rust_client_t *c = lib->get(lib, KERNEL_RUST_CLIENT); if (!c) { return NULL; }
    INIT(this, .public = { .get_features = _get_features, .get_source_addr = _get_source_addr, .get_nexthop = _get_nexthop,
        .get_interface = _get_interface, .create_address_enumerator = _create_address_enumerator,
        .create_local_subnet_enumerator = _create_local_subnet_enumerator, .add_ip = _add_ip, .del_ip = _del_ip,
        .add_route = _add_route, .del_route = _del_route, .destroy = _destroy }, .client = c);
    return &this->public;
}
