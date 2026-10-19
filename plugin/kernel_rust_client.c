/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "kernel_rust_client.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <processing/watcher.h>

json_t *kernel_rust_host(host_t *host)
{
    char text[INET6_ADDRSTRLEN]; chunk_t address;
    if (!host) { return json_null(); }
    address = host->get_address(host);
    if (!inet_ntop(host->get_family(host), address.ptr, text, sizeof(text))) { return NULL; }
    return json_pack("{s:s,s:i}", "address", text, "port", host->get_port(host));
}
host_t *kernel_rust_parse_host(json_t *v)
{
    const char *address = json_string_value(json_object_get(v, "address"));
    json_t *port = json_object_get(v, "port");
    if (!address || !json_is_integer(port) || json_integer_value(port) < 0 || json_integer_value(port) > 65535) { return NULL; }
    return host_create_from_string((char*)address, json_integer_value(port));
}
json_t *kernel_rust_ts(traffic_selector_t *ts)
{
    char from[INET6_ADDRSTRLEN], to[INET6_ADDRSTRLEN];
    int family = ts->get_type(ts) == TS_IPV4_ADDR_RANGE ? AF_INET : AF_INET6;
    if (!inet_ntop(family, ts->get_from_address(ts).ptr, from, sizeof(from)) ||
        !inet_ntop(family, ts->get_to_address(ts).ptr, to, sizeof(to))) { return NULL; }
    return json_pack("{s:s,s:s,s:i,s:i,s:i}", "from", from, "to", to,
        "protocol", ts->get_protocol(ts), "fromPort", ts->get_from_port(ts), "toPort", ts->get_to_port(ts));
}
traffic_selector_t *kernel_rust_parse_ts(json_t *v)
{
    host_t *from, *to; traffic_selector_t *ts = NULL;
    const char *a = json_string_value(json_object_get(v, "from")), *b = json_string_value(json_object_get(v, "to"));
    json_t *proto = json_object_get(v, "protocol"), *first = json_object_get(v, "fromPort"), *last = json_object_get(v, "toPort");
    if (!a || !b || !json_is_integer(proto) || !json_is_integer(first) || !json_is_integer(last) ||
        json_integer_value(proto) < 0 || json_integer_value(proto) > 255 || json_integer_value(first) < 0 ||
        json_integer_value(last) > 65535 || json_integer_value(first) > json_integer_value(last)) { return NULL; }
    from = host_create_from_string((char*)a, 0); to = host_create_from_string((char*)b, 0);
    if (from && to && from->get_family(from) == to->get_family(to)) {
        ts = traffic_selector_create_from_bytes(json_integer_value(proto),
            from->get_family(from) == AF_INET ? TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE,
            from->get_address(from), json_integer_value(first), to->get_address(to), json_integer_value(last));
    }
    DESTROY_IF(from); DESTROY_IF(to); return ts;
}
json_t *kernel_rust_mark(mark_t mark)
{
    return json_pack("{s:I,s:I}", "value", (json_int_t)mark.value, "mask", (json_int_t)mark.mask);
}
json_t *kernel_rust_u64(uint64_t v)
{
    char text[21]; snprintf(text, sizeof(text), "%" PRIu64, v); return json_string(text);
}
bool kernel_rust_parse_u64(json_t *v, uint64_t *out)
{
    const char *s = json_string_value(v); char *end; unsigned long long n;
    if (!s || !*s || strspn(s, "0123456789") != strlen(s)) { return FALSE; }
    errno = 0; n = strtoull(s, &end, 10);
    if (errno || *end) { return FALSE; } *out = n; return TRUE;
}
static status_t status_from_errno(int err)
{
    switch (err) {
        case 0: return SUCCESS;
        case EEXIST: return ALREADY_DONE;
        case ENOENT: case ESRCH: return NOT_FOUND;
        case EOPNOTSUPP: return NOT_SUPPORTED;
        default: return FAILED;
    }
}
static bool send_request(int fd, const char *method, json_t *parameters, bool more)
{
    json_t *request; char *encoded; size_t len, done = 0; ssize_t n;
    char name[128];
    snprintf(name, sizeof(name), "io.ranet.Kernel.%s", method);
    request = json_pack("{s:s,s:O}", "method", name, "parameters", parameters);
    if (more) { json_object_set_new(request, "more", json_true()); }
    encoded = json_dumps(request, JSON_COMPACT); json_decref(request);
    if (!encoded) { return FALSE; }
    len = strlen(encoded) + 1;
    if (len > KR_MAX_FRAME) { memwipe(encoded, len); free(encoded); return FALSE; }
    while (done < len) {
        n = send(fd, encoded + done, len - done, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) { continue; }
        if (n <= 0) { break; } done += n;
    }
    memwipe(encoded, len); free(encoded); return done == len;
}
/* Read a standard Varlink frame, retaining coalesced/partial frames. */
static json_t *receive_frame(int fd, kernel_rust_frames_t *frames, int flags)
{
    char *end; size_t len; ssize_t n; json_t *reply;
    for (;;) {
        end = memchr(frames->bytes, 0, frames->len);
        if (end) {
            len = end - frames->bytes + 1;
            reply = json_loadb(frames->bytes, len - 1, JSON_REJECT_DUPLICATES, NULL);
            memmove(frames->bytes, frames->bytes + len, frames->len - len);
            frames->len -= len; memwipe(frames->bytes + frames->len, len);
            if (!reply) { errno = EPROTO; } return reply;
        }
        if (frames->len == sizeof(frames->bytes)) { errno = EMSGSIZE; return NULL; }
        n = recv(fd, frames->bytes + frames->len, sizeof(frames->bytes) - frames->len, flags);
        if (n < 0 && errno == EINTR) { continue; }
        if (n <= 0) { if (!n) { errno = ECONNRESET; } return NULL; }
        frames->len += n;
    }
}
status_t kernel_rust_call(kernel_rust_client_t *c, const char *method, json_t *parameters, json_t **out)
{
    json_t *reply = NULL, *value, *error; status_t status = FAILED;
    if (out) { *out = NULL; }
    if (!parameters) { return FAILED; }
    c->mutex->lock(c->mutex);
    if (c->rpc >= 0 && send_request(c->rpc, method, parameters, FALSE)) {
        reply = receive_frame(c->rpc, &c->control_frames, 0);
    }
    if (json_is_object(reply) && !json_is_true(json_object_get(reply, "continues"))) {
        error = json_object_get(reply, "error"); value = json_object_get(reply, "parameters");
        if (!error && (!value || json_is_object(value))) { status = SUCCESS; if (out) { *out = value ? json_incref(value) : json_object(); } }
        else if (json_is_string(error)) {
            if (streq(json_string_value(error), "io.ranet.Kernel.KernelError")) {
                int err = json_integer_value(json_object_get(value, "errno"));
                status = err ? status_from_errno(err) : FAILED;
                DBG1(DBG_KNL, "kernel-rust %s failed: %s", method, strerror(err));
            } else { DBG1(DBG_KNL, "kernel-rust %s failed: %s", method, json_string_value(error)); }
        }
    } else if (c->rpc >= 0) {
        DBG1(DBG_KNL, "kernel-rust control connection lost");
        close(c->rpc); c->rpc = -1;
    }
    c->mutex->unlock(c->mutex);
    json_decref(reply); json_decref(parameters); return status;
}
static int connect_daemon(void)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    struct ucred peer; socklen_t len = sizeof(peer); int fd;
    struct timeval timeout = { .tv_sec = 10 };
    char *path = lib->settings->get_str(lib->settings, "%s.plugins.kernel-rust.socket", IPSEC_PIDDIR "/charon-kernel.sock", lib->ns);
    uid_t uid = lib->settings->get_int(lib->settings, "%s.plugins.kernel-rust.daemon_uid", 0, lib->ns);
    if (strlen(path) >= sizeof(addr.sun_path)) { return -1; }
    strcpy(addr.sun_path, path); fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { return -1; }
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &len) < 0 || len != sizeof(peer) || peer.uid != uid) {
        DBG1(DBG_KNL, "unable to connect to kernel daemon at %s", path); close(fd); return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)); return fd;
}
static void dispatch_event(json_t *v)
{
    const char *kind = json_string_value(json_object_get(v, "kind"));
    json_t *data; host_t *dst = NULL, *remote = NULL;
    kernel_acquire_data_t acquire = { .cpu = CPU_ID_MAX };
    if (!kind) { return; }
    if (streq(kind, "expire")) {
        data = json_object_get(v, "expiry"); dst = kernel_rust_parse_host(json_object_get(data, "destination"));
        if (dst) { charon->kernel->expire(charon->kernel, json_integer_value(json_object_get(data, "protocol")),
            htonl(json_integer_value(json_object_get(data, "spi"))), dst, json_is_true(json_object_get(data, "hard"))); }
    } else if (streq(kind, "mapping")) {
        data = json_object_get(v, "mapping"); dst = kernel_rust_parse_host(json_object_get(data, "destination"));
        remote = kernel_rust_parse_host(json_object_get(data, "remote"));
        if (dst && remote) { charon->kernel->mapping(charon->kernel, IPPROTO_ESP,
            htonl(json_integer_value(json_object_get(data, "spi"))), dst, remote); }
    } else if (streq(kind, "acquire")) {
        data = json_object_get(v, "acquire"); acquire.src = kernel_rust_parse_ts(json_object_get(data, "src"));
        acquire.dst = kernel_rust_parse_ts(json_object_get(data, "dst")); acquire.seq = json_integer_value(json_object_get(data, "sequence"));
        if (acquire.src && acquire.dst) { charon->kernel->acquire(charon->kernel, json_integer_value(json_object_get(data, "reqid")), &acquire); }
    } else if (streq(kind, "roam")) { charon->kernel->roam(charon->kernel, json_is_true(json_object_get(v, "addressChanged"))); }
    DESTROY_IF(dst); DESTROY_IF(remote); DESTROY_IF(acquire.src); DESTROY_IF(acquire.dst);
}
CALLBACK(receive_events, bool, kernel_rust_client_t *c, int fd, watcher_event_t event)
{
    json_t *reply;
    for (;;) {
        reply = receive_frame(fd, &c->event_frames, MSG_DONTWAIT);
        if (!reply) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) { return TRUE; }
            break;
        }
        if (!json_is_true(json_object_get(reply, "continues")) || json_object_get(reply, "error")) { json_decref(reply); break; }
        dispatch_event(json_object_get(json_object_get(reply, "parameters"), "event")); json_decref(reply);
    }
    c->mutex->lock(c->mutex);
    if (!c->closing && c->rpc >= 0) { DBG1(DBG_KNL, "kernel-rust event connection lost"); shutdown(c->rpc, SHUT_RDWR); }
    c->mutex->unlock(c->mutex); return FALSE;
}
kernel_rust_client_t *kernel_rust_client_create(void)
{
    kernel_rust_client_t *c; json_t *reply = NULL, *parameters, *watch = NULL; const char *token;
    INIT(c, .rpc = -1, .events = -1, .mutex = mutex_create(MUTEX_TYPE_DEFAULT));
    c->rpc = connect_daemon(); if (c->rpc < 0) { goto failed; }
    parameters = json_pack("{s:s,s:s}", "interfacesUse", lib->settings->get_str(lib->settings, "%s.interfaces_use", "", lib->ns),
        "interfacesIgnore", lib->settings->get_str(lib->settings, "%s.interfaces_ignore", "", lib->ns));
    if (kernel_rust_call(c, "OpenSession", parameters, &reply) != SUCCESS) { goto failed; }
    token = json_string_value(json_object_get(reply, "token"));
    if (!token || strlen(token) != 64 || !json_is_integer(json_object_get(reply, "features"))) { goto failed; }
    c->features = json_integer_value(json_object_get(reply, "features"));
    c->events = connect_daemon(); if (c->events < 0) { goto failed; }
    parameters = json_pack("{s:s}", "token", token);
    bool sent = send_request(c->events, "WatchEvents", parameters, TRUE); json_decref(parameters);
    if (!sent) { goto failed; }
    watch = receive_frame(c->events, &c->event_frames, 0);
    const char *kind = json_string_value(json_object_get(json_object_get(json_object_get(watch, "parameters"), "event"), "kind"));
    if (!json_is_true(json_object_get(watch, "continues")) || !kind || !streq(kind, "ready")) { goto failed; }
    json_decref(reply); json_decref(watch);
    lib->watcher->add(lib->watcher, c->events, WATCHER_READ, receive_events, c); return c;
failed:
    json_decref(reply); json_decref(watch); kernel_rust_client_destroy(c); return NULL;
}
void kernel_rust_client_destroy(kernel_rust_client_t *c)
{
    c->mutex->lock(c->mutex); c->closing = TRUE; c->mutex->unlock(c->mutex);
    if (c->rpc >= 0) { kernel_rust_call(c, "CloseSession", json_object(), NULL); }
    if (c->events >= 0) { lib->watcher->remove(lib->watcher, c->events); close(c->events); }
    if (c->rpc >= 0) { close(c->rpc); }
    c->mutex->destroy(c->mutex); memwipe(c, sizeof(*c)); free(c);
}
typedef struct { host_t *host; char *name; uint8_t prefix; } item_t;
typedef struct { enumerator_t public; item_t *items; size_t count, next; bool subnets; } snapshot_t;
METHOD(enumerator_t, enumerate_snapshot, bool, snapshot_t *this, va_list args)
{
    host_t **host; item_t *item;
    if (this->next == this->count) { return FALSE; }
    item = &this->items[this->next++]; VA_ARGS_VGET(args, host); *host = item->host;
    if (this->subnets) { uint8_t *prefix; char **name; VA_ARGS_VGET(args, prefix, name); *prefix = item->prefix; *name = item->name; }
    return TRUE;
}
METHOD(enumerator_t, destroy_snapshot, void, snapshot_t *this)
{
    size_t i; for (i = 0; i < this->count; i++) { DESTROY_IF(this->items[i].host); free(this->items[i].name); }
    free(this->items); free(this);
}
enumerator_t *kernel_rust_enumerator(kernel_rust_client_t *c, bool subnets, json_t *parameters)
{
    json_t *reply, *array, *value; snapshot_t *e; size_t i, count;
    if (kernel_rust_call(c, subnets ? "ListSubnets" : "ListAddresses", parameters, &reply) != SUCCESS) { return enumerator_create_empty(); }
    array = json_object_get(reply, subnets ? "subnets" : "addresses"); count = json_array_size(array);
    if (!json_is_array(array) || count > 4096) { json_decref(reply); return enumerator_create_empty(); }
    INIT(e, .public = { .enumerate = enumerator_enumerate_default, .venumerate = _enumerate_snapshot, .destroy = _destroy_snapshot },
        .count = count, .items = calloc(count, sizeof(item_t)), .subnets = subnets);
    for (i = 0; i < count; i++) {
        value = json_array_get(array, i); e->items[i].host = kernel_rust_parse_host(subnets ? json_object_get(value, "address") : value);
        if (!e->items[i].host) { goto failed; }
        if (subnets) {
            const char *name = json_string_value(json_object_get(value, "interface")); json_t *prefix = json_object_get(value, "prefix");
            if (!name || !json_is_integer(prefix) || json_integer_value(prefix) < 0 || json_integer_value(prefix) > 128) { goto failed; }
            e->items[i].name = strdup(name); e->items[i].prefix = json_integer_value(prefix);
        }
    }
    json_decref(reply); return &e->public;
failed:
    json_decref(reply); _destroy_snapshot(e); return enumerator_create_empty();
}
