/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kernel_rust_client.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/udp.h>

typedef struct { kernel_ipsec_t public; kernel_rust_client_t *client; } private_ipsec_t;
static bool supported_id(kernel_ipsec_sa_id_t *id) { return id->proto == IPPROTO_ESP && id->if_id; }
static json_t *sa_id(kernel_ipsec_sa_id_t *id)
{
    return json_pack("{s:o,s:o,s:I,s:o,s:I}", "src", kernel_rust_host(id->src), "dst", kernel_rust_host(id->dst),
        "spi", (json_int_t)ntohl(id->spi), "mark", kernel_rust_mark(id->mark), "interfaceId", (json_int_t)id->if_id);
}
METHOD(kernel_ipsec_t, get_features, kernel_feature_t, private_ipsec_t *this) { return this->client->features; }
METHOD(kernel_ipsec_t, get_spi, status_t, private_ipsec_t *this, host_t *src, host_t *dst, uint8_t proto, uint32_t *spi)
{
    json_t *reply, *p; status_t status; json_int_t v;
    if (proto != IPPROTO_ESP) { return NOT_SUPPORTED; }
    p = json_pack("{s:o,s:o,s:I,s:I}", "src", kernel_rust_host(src), "dst", kernel_rust_host(dst),
        "minimum", (json_int_t)(uint32_t)lib->settings->get_int(lib->settings, "%s.spi_min", KERNEL_SPI_MIN, lib->ns),
        "maximum", (json_int_t)(uint32_t)lib->settings->get_int(lib->settings, "%s.spi_max", KERNEL_SPI_MAX, lib->ns));
    status = kernel_rust_call(this->client, "AllocateSpi", p, &reply);
    if (status == SUCCESS) {
        p = json_object_get(reply, "spi"); v = json_integer_value(p);
        if (json_is_integer(p) && v >= 256 && v <= UINT32_MAX) { *spi = htonl(v); } else { status = FAILED; }
        json_decref(reply);
    }
    return status;
}
METHOD(kernel_ipsec_t, get_cpi, status_t, private_ipsec_t *this, host_t *src, host_t *dst, uint16_t *cpi) { return NOT_SUPPORTED; }
static json_t *algorithm(uint16_t id, chunk_t key, const char *name)
{
    char *hex = chunk_to_hex(key, NULL, FALSE).ptr;
    json_t *v = json_pack("{s:i,s:s,s:s}", "id", id, "name", name ? name : "", "key", hex ? hex : "");
    if (hex) { memwipe(hex, key.len*2); free(hex); } return v;
}
METHOD(kernel_ipsec_t, add_sa, status_t, private_ipsec_t *this, kernel_ipsec_sa_id_t *id, kernel_ipsec_add_sa_t *d)
{
    json_t *cfg, *lifetime; char *enc_name = NULL, *int_name = NULL;
    if (!supported_id(id) || d->mode != MODE_TUNNEL || d->ipcomp || d->cpi || d->label ||
        d->hw_offload != HW_OFFLOAD_NO || d->cpu != CPU_ID_MAX || d->forward_icmp ||
        d->enc_key.len > 8192 || d->int_key.len > 8192 || (d->interface && *d->interface)) { return NOT_SUPPORTED; }
    charon->kernel->lookup_algorithm(charon->kernel, d->enc_alg, ENCRYPTION_ALGORITHM, NULL, &enc_name);
    charon->kernel->lookup_algorithm(charon->kernel, d->int_alg, INTEGRITY_ALGORITHM, NULL, &int_name);
    lifetime = json_pack("{s:I,s:I,s:o,s:o,s:o,s:o}", "timeLife", (json_int_t)d->lifetime->time.life,
        "timeRekey", (json_int_t)d->lifetime->time.rekey, "byteLife", kernel_rust_u64(d->lifetime->bytes.life),
        "byteRekey", kernel_rust_u64(d->lifetime->bytes.rekey), "packetLife", kernel_rust_u64(d->lifetime->packets.life),
        "packetRekey", kernel_rust_u64(d->lifetime->packets.rekey));
    cfg = json_object();
#define INT(k,v) json_object_set_new(cfg, k, json_integer(v))
#define BOOL(k,v) json_object_set_new(cfg, k, json_boolean(v))
    INT("reqid", d->reqid); INT("acquireSequence", d->seq);
    INT("replayWindow", d->replay_window); INT("tfc", d->tfc); INT("copyDscp", d->copy_dscp);
    BOOL("esn", d->esn); BOOL("udpEncapsulation", d->encap); BOOL("copyDf", d->copy_df);
    BOOL("copyEcn", d->copy_ecn); BOOL("inbound", d->inbound); BOOL("update", d->update);
#undef INT
#undef BOOL
    json_object_set_new(cfg, "encryption", algorithm(d->enc_alg, d->enc_key, enc_name));
    json_object_set_new(cfg, "integrity", algorithm(d->int_alg, d->int_key, int_name));
    json_object_set_new(cfg, "lifetime", lifetime); json_object_set_new(cfg, "outputMark", kernel_rust_mark(d->mark));
    return kernel_rust_call(this->client, "InstallSa", json_pack("{s:o,s:o}", "id", sa_id(id), "config", cfg), NULL);
}
METHOD(kernel_ipsec_t, update_sa, status_t, private_ipsec_t *this, kernel_ipsec_sa_id_t *id, kernel_ipsec_update_sa_t *d) { return NOT_SUPPORTED; }
METHOD(kernel_ipsec_t, query_sa, status_t, private_ipsec_t *this, kernel_ipsec_sa_id_t *id, kernel_ipsec_query_sa_t *d, uint64_t *bytes, uint64_t *packets, time_t *time)
{
    json_t *r, *last; uint64_t b, p; status_t status;
    if (!supported_id(id) || d->cpi) { return NOT_SUPPORTED; }
    status = kernel_rust_call(this->client, "QuerySa", json_pack("{s:o}", "id", sa_id(id)), &r);
    if (status == SUCCESS) {
        last = json_object_get(r, "lastUse");
        if (kernel_rust_parse_u64(json_object_get(r, "bytes"), &b) && kernel_rust_parse_u64(json_object_get(r, "packets"), &p) && json_is_integer(last) && json_integer_value(last) >= 0) {
            if (bytes) { *bytes = b; } if (packets) { *packets = p; } if (time) { *time = json_integer_value(last); }
        } else { status = FAILED; } json_decref(r);
    } return status;
}
METHOD(kernel_ipsec_t, del_sa, status_t, private_ipsec_t *this, kernel_ipsec_sa_id_t *id, kernel_ipsec_del_sa_t *d)
{
    if (!supported_id(id) || d->cpi) { return NOT_SUPPORTED; }
    return kernel_rust_call(this->client, "RemoveSa", json_pack("{s:o}", "id", sa_id(id)), NULL);
}
METHOD(kernel_ipsec_t, flush_sas, status_t, private_ipsec_t *this) { return kernel_rust_call(this->client, "FlushSas", json_object(), NULL); }
static bool supported_policy(kernel_ipsec_policy_id_t *id)
{
    return id->if_id && !id->label && (!id->interface || !*id->interface);
}
static json_t *policy_id(kernel_ipsec_policy_id_t *id)
{
    return json_pack("{s:i,s:o,s:o,s:o,s:I}", "direction", id->dir, "src", kernel_rust_ts(id->src_ts),
        "dst", kernel_rust_ts(id->dst_ts), "mark", kernel_rust_mark(id->mark), "interfaceId", (json_int_t)id->if_id);
}
static json_t *policy_config(kernel_ipsec_manage_policy_t *d)
{
    json_t *v = json_pack("{s:i,s:i,s:I,s:o,s:o,s:I,s:I}", "kind", d->type, "priority", d->prio,
        "manualPriority", (json_int_t)d->manual_prio, "src", kernel_rust_host(d->src), "dst", kernel_rust_host(d->dst),
        "reqid", (json_int_t)d->sa->reqid, "policyCount", (json_int_t)d->sa->policy_count);
    if (d->sa->esp.use) { json_object_set_new(v, "espSpi", json_integer(ntohl(d->sa->esp.spi))); } return v;
}
static bool supported_config(kernel_ipsec_manage_policy_t *d)
{
    return d->sa && d->sa->mode == MODE_TUNNEL && !d->sa->ah.use && !d->sa->ipcomp.transform &&
        d->hw_offload == HW_OFFLOAD_NO && !d->pcpu_acquires && !d->forward_icmp;
}
METHOD(kernel_ipsec_t, add_policy, status_t, private_ipsec_t *this, kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *d)
{
    if (!supported_policy(id) || !supported_config(d)) { return NOT_SUPPORTED; }
    return kernel_rust_call(this->client, "InstallPolicy", json_pack("{s:o,s:o}", "id", policy_id(id), "config", policy_config(d)), NULL);
}
METHOD(kernel_ipsec_t, del_policy, status_t, private_ipsec_t *this, kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *d)
{
    if (!supported_policy(id) || !supported_config(d)) { return NOT_SUPPORTED; }
    return kernel_rust_call(this->client, "RemovePolicy", json_pack("{s:o,s:o}", "id", policy_id(id), "config", policy_config(d)), NULL);
}
METHOD(kernel_ipsec_t, query_policy, status_t, private_ipsec_t *this, kernel_ipsec_policy_id_t *id, kernel_ipsec_query_policy_t *d, time_t *use_time)
{
    json_t *r, *last; status_t status;
    if (!supported_policy(id)) { return NOT_SUPPORTED; }
    status = kernel_rust_call(this->client, "QueryPolicy", json_pack("{s:o}", "id", policy_id(id)), &r);
    if (status == SUCCESS) {
        last = json_object_get(r, "lastUse"); if (json_is_integer(last) && json_integer_value(last) >= 0) { *use_time = json_integer_value(last); } else { status = FAILED; }
        json_decref(r);
    } return status;
}
METHOD(kernel_ipsec_t, flush_policies, status_t, private_ipsec_t *this) { return kernel_rust_call(this->client, "FlushPolicies", json_object(), NULL); }
METHOD(kernel_ipsec_t, bypass_socket, bool, private_ipsec_t *this, int fd, int family)
{
    struct sockaddr_storage addr; socklen_t len = sizeof(addr); uint16_t port;
    if (getsockname(fd, (struct sockaddr*)&addr, &len) < 0 || addr.ss_family != family || (family != AF_INET && family != AF_INET6)) { return FALSE; }
    port = ntohs(family == AF_INET ? ((struct sockaddr_in*)&addr)->sin_port : ((struct sockaddr_in6*)&addr)->sin6_port);
    if (port < 1024) { return FALSE; }
    return kernel_rust_call(this->client, "BypassPort", json_pack("{s:i,s:i}", "family", family, "port", port), NULL) == SUCCESS;
}
METHOD(kernel_ipsec_t, enable_udp_decap, bool, private_ipsec_t *this, int fd, int family, uint16_t port)
{
    int type = UDP_ENCAP_ESPINUDP, gro = 1;
    if (setsockopt(fd, IPPROTO_UDP, UDP_ENCAP, &type, sizeof(type)) < 0) { return FALSE; }
    setsockopt(fd, IPPROTO_UDP, UDP_GRO, &gro, sizeof(gro)); return TRUE;
}
METHOD(kernel_ipsec_t, destroy, void, private_ipsec_t *this) { free(this); }
kernel_ipsec_t *kernel_rust_ipsec_create(void)
{
    private_ipsec_t *this; kernel_rust_client_t *c = lib->get(lib, KERNEL_RUST_CLIENT); if (!c) { return NULL; }
    INIT(this, .public = { .get_features = _get_features, .get_spi = _get_spi, .get_cpi = _get_cpi,
        .add_sa = _add_sa, .update_sa = _update_sa, .query_sa = _query_sa, .del_sa = _del_sa, .flush_sas = _flush_sas,
        .add_policy = _add_policy, .query_policy = _query_policy, .del_policy = _del_policy, .flush_policies = _flush_policies,
        .bypass_socket = _bypass_socket, .enable_udp_decap = _enable_udp_decap, .destroy = _destroy }, .client = c);
    return &this->public;
}
