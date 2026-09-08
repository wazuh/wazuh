/*
 * Local Authd server
 * Copyright (C) 2015, Wazuh Inc.
 * May 20, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <cJSON.h>
#include <pthread.h>
#include <sys/wait.h>
#include "auth.h"
#include <openssl/crypto.h>
#include "os_err.h"
#include "authd-config.h"
#include "enrollment_token_store.h"
#include "enrollment_token_mint.h"
#include "reenroll_verify.h"
#include "wazuhdb_queries_op.h"
#include <time.h>

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

// Longest `reenroll.bearer` accepted on this socket (#38993): a wazuh-enroll+jwt is ~230 bytes, and the
// verifier has its own, tighter cap; this only keeps an absurd payload from reaching it.
#define REENROLL_BEARER_MAX_CHARS 4096

typedef enum auth_local_err {
    EINTERNAL = 0,
    EJSON,
    ENOFUNCTION,
    ENOARGUMENT,
    ENONAME,
    ENOIP,
    EDUPIP,
    EDUPNAME,
    EKEY,
    ENOID,
    ENOAGENT,
    EDUPID,
    EAGLIM,
    EINVGROUP,
    ENOMASTER,
    ENOMASTERCOMM,
    EINVALIDNAME,
    EPENDINGPURGE,
    EINVALIDKEY,
    EINVALIDID,
    EDELETEBACKLOG, // Append only: ERRORS[] below is indexed directly by these values.
    ETOKENNOTFOUND,
    ETOKENEXPIRED,
    ETOKENEXHAUSTED,
    EMINTREFUSED,
    EREENROLLUNKNOWN,
    EREENROLLINVALID,
    EREENROLLSTALE
} auth_local_err;


static const struct {
    int code;
    char *message;
} ERRORS[] = {
    { 9001, "Internal error" },
    { 9002, "Parsing JSON input" },
    { 9003, "No such function" },
    { 9004, "No such argument" },
    { 9005, "No such name" },
    { 9006, "No such IP" },
    { 9007, "Duplicate IP" },
    { 9008, "Duplicate name" },
    { 9009, "Issue generating key" },
    { 9010, "No such agent ID" },
    { 9011, "Agent ID not found" },
    { 9012, "Duplicate ID" },
    { 9013, "Maximum number of agents reached" },
    { 9014, "Invalid Group(s) Name(s)" },
    { 9015, "Cannot execute this request on a worker node" },
    { 9016, "Cannot communicate with master node" },
    // A name that IS present but not storable in client.keys (see is_storable_agent_name()), as
    // opposed to 9005 "No such name", which means the argument was missing.
    { 9017, "Invalid agent name" },
    { 9018, "Agent ID has a pending deletion" },
    // A caller-supplied key that is not 64 lowercase hex chars (the 32-byte key remoted's bearer
    // profile requires). Distinct from 9009, which is the manager failing to GENERATE a key.
    { 9019, "Invalid agent key" },
    // A caller-supplied id outside [1, INT32_MAX] -- the range OS_AddNewAgent()/wdb can actually
    // store -- or "0", which is reserved for the manager itself. See OS_IsValidAgentInsertID().
    { 9020, "Invalid agent ID" },
    // Too many deletions are already waiting to reach the indexer. Distinct from 9018, which is
    // about ONE id being unusable: this one refuses the DELETION rather than an insertion, and the
    // remedy is to wait rather than to pick a different id. 9021 rather than 9020: both features
    // appended their code independently, and 9020 was already taken by the id check above -- the
    // framework maps the two to different API errors.
    { 9021, "Too many agent deletions are pending" },
    // Enrollment tokens (#38993). One code for "unknown" and "revoked" on purpose: ids are 128 random
    // bits, so nothing is protected by telling them apart, and one answer keeps the callers' mapping
    // simple. remoted's /enroll checks these too before opening this socket; authd is the side that
    // counts uses, which is why 9024 only exists here.
    { 9022, "Enrollment token not found or revoked" },
    { 9023, "Enrollment token expired" },
    { 9024, "Enrollment token uses exhausted" },
    // A mint the running listener cannot honour. The response message carries the reason after
    // this prefix -- "Enrollment token refused: address not in certificate SAN" -- see
    // local_token_create(): the operator needs the reason, the code alone is not actionable.
    { 9025, "Enrollment token refused" },
    // Re-enrollment (#38993): the agent's own bearer, verified here on the master against the secret in its
    // global.db row. 9026 folds "no such agent" and "no secret on record" on purpose (telling them apart
    // would let a caller probe ids); remoted answers all three with its uniform 401.
    { 9026, "Unknown agent or no re-enrollment credential" },
    { 9027, "Invalid re-enrollment credential" },
    { 9028, "Re-enrollment credential outside the accepted time window" }
};

// Dispatch local request. STATIC: the unit tests drive the token verbs and `add` through it.
STATIC char* local_dispatch(const char *input);

// Per-connection thread body: recv, dispatch, send, close. See run_local_server()'s comment on
// why this now runs on its own detached thread instead of inline on the accept loop.
static void* handle_local_client(void *arg);

struct local_client_ctx {
    int peer;
};

// Ceiling on concurrent client threads, so a burst of connections can't spawn them without bound.
// 128 matches AUTH_LOCAL_SOCK's own listen backlog (OS_BindUnixDomainWithPerms, os_net.c): no point
// servicing more at once than could ever be queued.
#define MAX_LOCAL_CLIENT_THREADS 128

// Shutdown drain budget. Only has to cover a dispatch already in progress -- at worst a worker's
// cluster-forwarded "add" -- since the accept loop has exited by then.
#define LOCAL_CLIENT_DRAIN_TIMEOUT_MS 5000
#define LOCAL_CLIENT_DRAIN_POLL_MS 50

static int local_client_thread_count = 0;
static pthread_mutex_t mutex_local_client_count = PTHREAD_MUTEX_INITIALIZER;

// Returns 1 and reserves a slot if under the cap, 0 (no slot reserved) if at it.
static int try_reserve_local_client_slot(void) {
    int reserved;
    w_mutex_lock(&mutex_local_client_count);
    if (reserved = (local_client_thread_count < MAX_LOCAL_CLIENT_THREADS), reserved) {
        local_client_thread_count++;
    }
    w_mutex_unlock(&mutex_local_client_count);
    return reserved;
}

static void release_local_client_slot(void) {
    w_mutex_lock(&mutex_local_client_count);
    local_client_thread_count--;
    w_mutex_unlock(&mutex_local_client_count);
}

// Longest storable agent name. Matches both OS_IsValidName()'s own bound and the API's
// `agent_name` maxLength, so this adds no new limit of its own.
#define MAX_STORABLE_AGENT_NAME_LEN 128

// Rejects only what client.keys' `<id> <name> <ip> <key>` line cannot represent: whitespace/control
// bytes (the record is whitespace-delimited, so they shift every later column) and a leading
// '#'/'!' (the removed-entry marker, which makes readers skip the line).
//
// Deliberately NOT OS_IsValidName()'s stricter charset, which the API's own `^[\w\-.%]+$` contract
// (api/api/validator.py) has always allowed callers to violate harmlessly. The enrollment paths
// (auth.c, enrollmentEndpoint.cpp) do apply it to the names they mint.
STATIC int is_storable_agent_name(const char *name) {
    if (!name || !*name || strlen(name) > MAX_STORABLE_AGENT_NAME_LEN) {
        return 0;
    }

    if (name[0] == '#' || name[0] == '!') {
        return 0;
    }

    for (const char *c = name; *c; c++) {
        // Covers every control byte (0x00-0x1F) and the space itself in one comparison, plus DEL.
        if ((unsigned char)*c <= ' ' || (unsigned char)*c == 0x7F) {
            return 0;
        }
    }

    return 1;
}

// Reads an optional string argument. cJSON_GetObjectItem() returning non-NULL only means the KEY is
// present; valuestring is NULL for a number, bool, null or object.
//
// Absent or explicit null -> not supplied (*out stays NULL), how a client spells an unset field.
// Any other non-string type -> -1 rather than silently treated as absent: these fields select a
// specific agent identity, so dropping a malformed one would act on a different one.
STATIC int get_optional_string_arg(cJSON *arguments, const char *key, char **out) {
    cJSON *item = cJSON_GetObjectItem(arguments, key);

    *out = NULL;

    if (!item || cJSON_IsNull(item)) {
        return 0;
    }

    if (!cJSON_IsString(item)) {
        return -1;
    }

    *out = item->valuestring;
    return 0;
}

// local_add_clustered() is declared in auth.h (like local_add()) since it's genuinely
// externally linked -- see the definition below for details.

// Remove an agent
static cJSON* local_remove(const char *id, int purge);

// Get agent data
static cJSON* local_get(const char *id);

// Re-enrollment (#38993, master only): verifies `bearer` against the re-enrollment secret of the agent
// `kid` and rotates that agent's key and secret in place -- same id, no removal, no purge.
static cJSON* local_reenroll(const char *kid, const char *bearer, const char *name, const char *ip, const char *groups);

// Generates an agent info json response
// reenroll_secret may be NULL: the field is then absent (local_get(), and a clustered add whose master
// predates the secret). Only `add` ever carries it (#38993).
static cJSON* local_create_agent_response(const char *id, const char *name, const char *ip, const char *key, const char *reenroll_secret);

// Generates an agent deleted response
static cJSON* local_create_agent_delete_response(void);

// Generates an error json response
static cJSON* local_create_error_response(int code, const char *message);
// Enrollment token verbs (#38993). On failure they return NULL and set *ierror to the ERRORS[] index,
// except the 9025 refusal, which is a complete response because its message carries the detail.
static cJSON* local_token_create(cJSON *arguments, int *ierror);
static cJSON* local_token_list(void);
static cJSON* local_token_revoke(cJSON *arguments, int *ierror);
// Whether `text` has the shape of a token id: exactly ETOKEN_ID_CHARS canonical base64url chars.
static int is_token_id(const char *text);

// Services one already-accepted connection: set the recv timeout, read one request, dispatch, send
// the reply, close. Shared by the threaded path and run_local_server()'s at-the-cap inline
// fallback; only where it runs differs.
static void service_local_client(int peer) {
    char *buffer = NULL;
    char *response;
    ssize_t length;

    if (config.timeout_sec || config.timeout_usec) {
        if (OS_SetRecvTimeout(peer, config.timeout_sec, config.timeout_usec) < 0) {
            // Log-once latch, mutex-guarded because this now runs on concurrent client threads.
            static int reported = 0;
            static pthread_mutex_t mutex_reported = PTHREAD_MUTEX_INITIALIZER;
            int error = errno;
            int should_report = 0;

            w_mutex_lock(&mutex_reported);
            if (!reported) {
                reported = 1;
                should_report = 1;
            }
            w_mutex_unlock(&mutex_reported);

            if (should_report) {
                merror("Could not set timeout to internal socket: %s (%d)", strerror(error), error);
            }
        }
    }

    os_calloc(OS_MAXSTR, sizeof(char), buffer);
    switch (length = OS_RecvSecureTCP(peer, buffer,OS_MAXSTR), length) {
    case OS_SOCKTERR:
        merror("OS_RecvSecureTCP(): response size is bigger than expected");
        break;

    case -1:
        merror("OS_RecvSecureTCP(): %s", strerror(errno));
        break;

    case 0:
        mdebug2("Empty message from local client.");
        break;

    case OS_MAXLEN:
        merror("Received message > %i", MAX_DYN_STR);
        break;

    default:
        if (response = local_dispatch(buffer), response) {
            OS_SendSecureTCP(peer, strlen(response), response);
            free(response);
        }
    }

    // Closed exactly once, here, on every arm -- the "empty message" and OS_MAXLEN arms must NOT
    // close it themselves and fall through. Harmless when dispatch ran inline, but now that each
    // connection has its own thread, another thread can be handed the same descriptor number
    // between the two closes and the second would silently destroy its connection.
    close(peer);
    free(buffer);
}

// Runs on its own detached thread so one slow dispatch -- typically a worker's cluster-forwarded
// "add", which can take seconds -- never blocks other callers (manage_agents, the API, another
// /enroll request) behind it. Safe concurrently: local_add()/local_remove()/local_get() already
// serialize the `keys` keystore and write_pending/cond_pending through mutex_keys.
static void* handle_local_client(void *arg) {
    struct local_client_ctx *ctx = (struct local_client_ctx *)arg;
    int peer = ctx->peer;
    os_free(ctx);

    authd_sigblock();
    service_local_client(peer);
    release_local_client_slot();
    return NULL;
}

// Thread for internal server
void* run_local_server(__attribute__((unused)) void *arg) {
    int sock;
    int peer;
    fd_set fdset;
    struct timeval timeout;

    authd_sigblock();

    mdebug1("Local server thread ready.");

    if (sock = OS_BindUnixDomain(AUTH_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s': '%s'. Closing local server.", AUTH_LOCAL_SOCK, strerror(errno));
        return NULL;
    }

    while (running) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        switch (select(sock + 1, &fdset, NULL, NULL, &timeout)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("at run_local_server(): select(): %s", strerror(errno));
            }
            continue;
        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if ((errno == EBADF && running) || (errno != EBADF && errno != EINTR)) {
                merror("at run_local_server(): accept(): %s", strerror(errno));
            }
            continue;
        }

        if (!try_reserve_local_client_slot()) {
            // At the cap: service this one inline, before accepting the next, rather than spawning
            // past the ceiling or dropping the client. Self-limiting, as this loop always was.
            service_local_client(peer);
            continue;
        }

        struct local_client_ctx *ctx;
        os_malloc(sizeof(struct local_client_ctx), ctx);
        ctx->peer = peer;

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_local_client, ctx) != 0) {
            merror("at run_local_server(): could not create a client thread: %s", strerror(errno));
            release_local_client_slot();
            close(peer);
            os_free(ctx);
            continue;
        }
        pthread_detach(tid);
    }

    // Drain in-flight client threads: they are detached and main-server.c joins only this thread,
    // so returning while one is inside local_add() lets teardown race an OS_WriteKeys() and
    // truncate client.keys. Bounded, since a client that never sent can hold its thread
    // indefinitely (auth.timeout_seconds=0).
    for (int waited_ms = 0; waited_ms < LOCAL_CLIENT_DRAIN_TIMEOUT_MS; waited_ms += LOCAL_CLIENT_DRAIN_POLL_MS) {
        int in_flight;

        w_mutex_lock(&mutex_local_client_count);
        in_flight = local_client_thread_count;
        w_mutex_unlock(&mutex_local_client_count);

        if (in_flight == 0) {
            break;
        }

        if (waited_ms == 0) {
            mdebug1("Waiting for %d in-flight local client thread(s) to finish.", in_flight);
        }

        usleep(LOCAL_CLIENT_DRAIN_POLL_MS * 1000);
    }

    w_mutex_lock(&mutex_local_client_count);
    if (local_client_thread_count > 0) {
        mwarn("%d local client thread(s) still in flight after %d ms; proceeding with shutdown.",
              local_client_thread_count, LOCAL_CLIENT_DRAIN_TIMEOUT_MS);
    }
    w_mutex_unlock(&mutex_local_client_count);

    mdebug1("Local server thread finished");

    close(sock);
    return NULL;
}

// Dispatch local request
char* local_dispatch(const char *input) {
    cJSON *request = NULL;
    cJSON *function;
    cJSON *arguments;
    cJSON *response = NULL;
    char *output = NULL;
    int ierror;
    char *groups = NULL;

    if (input[0] == '{') {
        const char *jsonErrPtr;
        if (request = cJSON_ParseWithOpts(input, &jsonErrPtr, 0), !request) {
            ierror = EJSON;
            goto fail;
        }

        // cJSON_IsString(), not just presence: every branch below strcmp()s valuestring, so
        // {"function": 5} would segfault authd.
        if (function = cJSON_GetObjectItem(request, "function"), !cJSON_IsString(function)) {
            ierror = ENOFUNCTION;
            goto fail;
        }

        if (!strcmp(function->valuestring, "add")) {
            cJSON *item = NULL;
            cJSON *force = NULL;
            cJSON *disconnected_time = NULL;
            char *id = NULL;
            char *name = NULL;
            char *ip = NULL;
            char *key_hash = NULL;
            char *key = NULL;
            char *token_id = NULL;
            char *reenroll_kid = NULL;
            char *reenroll_bearer = NULL;
            // Borrowed from the parsed JSON. Kept separate from the enclosing `groups`, which owns
            // wstr_delete_repeated_groups()'s allocation and is what the fail path frees.
            char *groups_arg = NULL;
            authd_force_options_t force_options = {0};

            if (arguments = cJSON_GetObjectItem(request, "arguments"), !arguments) {
                ierror = ENOARGUMENT;
                goto fail;
            }

            if (get_optional_string_arg(arguments, "id", &id) < 0) {
                ierror = EJSON;
                goto fail;
            }

            if (item = cJSON_GetObjectItem(arguments, "name"), !item) {
                ierror = ENONAME;
                goto fail;
            }
            // Left untyped on purpose: a non-string value leaves this NULL, which the check below
            // reports as 9017 -- a better answer for {"name": 5} than 9005 "No such name".
            name = item->valuestring;

            // Checked for every caller, before local_add()/local_add_clustered(): this socket used
            // to trust callers to have validated the name, which was never true for /enroll, and an
            // unstorable name silently corrupts client.keys once written.
            if (!is_storable_agent_name(name)) {
                ierror = EINVALIDNAME;
                goto fail;
            }

            // cJSON_IsString(): local_add() strcmp()s this against "any", so a NULL crashes it.
            if (item = cJSON_GetObjectItem(arguments, "ip"), !cJSON_IsString(item)) {
                ierror = ENOIP;
                goto fail;
            }
            ip = item->valuestring;

            if (get_optional_string_arg(arguments, "groups", &groups_arg) < 0) {
                ierror = EINVGROUP;
                goto fail;
            }

            if (groups_arg) {
                groups = wstr_delete_repeated_groups(groups_arg);
                if (!groups) {
                    ierror = EINVGROUP;
                    goto fail;
                }
            }

            if (get_optional_string_arg(arguments, "key_hash", &key_hash) < 0 ||
                get_optional_string_arg(arguments, "key", &key) < 0 ||
                get_optional_string_arg(arguments, "token_id", &token_id) < 0) {
                ierror = EJSON;
                goto fail;
            }

            // A token id of the wrong shape is "not found" (9022), not a JSON error: the caller
            // presented a credential and the answer is that no such credential exists. Checked on
            // both roles so a worker never forwards garbage to the master.
            if (token_id && !is_token_id(token_id)) {
                ierror = ETOKENNOTFOUND;
                goto fail;
            }

            // Re-enrollment (#38993): `reenroll` = {"kid": <the agent's id>, "bearer": <its wazuh-enroll+jwt>}.
            // remoted forwards the bearer unverified -- the secret that signs it lives in the master's
            // global.db and nowhere else -- so the master judges it (local_reenroll()). Malformed, or combined
            // with another credential or a caller-chosen identity, it is 9027: the caller presented a
            // credential and that credential is not acceptable. Checked on both roles, so a worker never
            // forwards garbage to the master.
            if (item = cJSON_GetObjectItem(arguments, "reenroll"), item && !cJSON_IsNull(item)) {
                if (!cJSON_IsObject(item) || token_id || id || key ||
                    get_optional_string_arg(item, "kid", &reenroll_kid) < 0 || !reenroll_kid || !*reenroll_kid ||
                    !OS_IsValidID(reenroll_kid) ||
                    get_optional_string_arg(item, "bearer", &reenroll_bearer) < 0 || !reenroll_bearer || !*reenroll_bearer ||
                    strlen(reenroll_bearer) > REENROLL_BEARER_MAX_CHARS) {
                    ierror = EREENROLLINVALID;
                    goto fail;
                }
            }

            if (force = cJSON_GetObjectItem(arguments, "force"), force) {
                if (item = cJSON_GetObjectItem(force, "enabled"), !item) {
                    ierror = EJSON;
                    goto fail;
                }
                force_options.enabled = (bool)item->valueint;

                if (item = cJSON_GetObjectItem(force, "key_mismatch"), !item) {
                    ierror = EJSON;
                    goto fail;
                }
                force_options.key_mismatch = (bool)item->valueint;

                if (disconnected_time = cJSON_GetObjectItem(force, "disconnected_time"), !disconnected_time) {
                    ierror = EJSON;
                    goto fail;
                }

                if (item = cJSON_GetObjectItem(disconnected_time, "enabled"), !item) {
                    ierror = EJSON;
                    goto fail;
                }
                force_options.disconnected_time_enabled = (bool)item->valueint;

                item = cJSON_GetObjectItem(disconnected_time, "value");
                if(cJSON_IsNumber(item)) {
                    force_options.disconnected_time = item->valueint;
                }
                else if (!cJSON_IsString(item) || get_time_interval(item->valuestring, &force_options.disconnected_time)) {
                    ierror = EJSON;
                    goto fail;
                }

                item = cJSON_GetObjectItem(force, "after_registration_time");
                if(cJSON_IsNumber(item)) {
                    force_options.after_registration_time = item->valueint;
                }
                else if (!cJSON_IsString(item) || get_time_interval(item->valuestring, &force_options.after_registration_time)) {
                    ierror = EJSON;
                    goto fail;
                }
            }

            if (config.worker_node) {
                if (id || key) {
                    // An admin/restore-style add (manage_agents/the API; self-enrollment never
                    // sends these). No cluster RPC can honor a caller-chosen id/key on a worker,
                    // and local_add_clustered() has no parameters for them -- forwarding anyway
                    // would report success having created a DIFFERENT agent than was asked for.
                    ierror = ENOMASTER;
                    goto fail;
                }
                // Self-enrollment shape. force is ignored for workers, as on port 1515: the master
                // assigns the ID, generates the key, and decides force-replace itself.
                response = local_add_clustered(name, ip, groups, key_hash, token_id, reenroll_kid, reenroll_bearer);
            } else if (reenroll_kid) {
                // force is irrelevant here: nothing is replaced, the agent's own entry is rotated in place,
                // and the secret already proved the caller IS that agent.
                response = local_reenroll(reenroll_kid, reenroll_bearer, name, ip, groups);
            } else {
                if (token_id) {
                    // Reserve the use BEFORE the agent exists: adding first and finding the token
                    // exhausted would leave an agent to roll back. The reservation is undone below
                    // when local_add() refuses, so a duplicate name never burns a use.
                    etoken_store_reload_if_changed();
                    switch (etoken_store_consume(token_id, time(NULL))) {
                    case ETOKEN_USE_OK:
                        break;
                    case ETOKEN_USE_EXPIRED:
                        ierror = ETOKENEXPIRED;
                        goto fail;
                    case ETOKEN_USE_EXHAUSTED:
                        ierror = ETOKENEXHAUSTED;
                        goto fail;
                    case ETOKEN_USE_NOT_FOUND:
                    default:
                        ierror = ETOKENNOTFOUND;
                        goto fail;
                    }
                }
                response = local_add(id, name, ip, groups, key, key_hash, force ? &force_options : &config.force_options);
                if (token_id && response) {
                    cJSON *err = cJSON_GetObjectItem(response, "error");
                    if (cJSON_IsNumber(err) && err->valueint == 0) {
                        minfo("Enrollment token '%s' consumed by agent '%s'.", token_id, name);
                    } else {
                        etoken_store_release(token_id);
                    }
                }
            }

            os_free(groups);
        } else if (!strcmp(function->valuestring, "remove")) {
            cJSON *item;
            int purge;

            if (config.worker_node) {
                ierror = ENOMASTER;
                goto fail;
            }

            if (arguments = cJSON_GetObjectItem(request, "arguments"), !arguments) {
                ierror = ENOARGUMENT;
                goto fail;
            }

            // cJSON_IsString(): local_remove() passes this straight to OS_IsAllowedID().
            if (item = cJSON_GetObjectItem(arguments, "id"), !cJSON_IsString(item)) {
                ierror = ENOID;
                goto fail;
            }

            purge = cJSON_IsTrue(cJSON_GetObjectItem(arguments, "purge"));

            response = local_remove(item->valuestring, purge);
        } else if (!strcmp(function->valuestring, "get")) {
            cJSON *item;

            if (config.worker_node) {
                ierror = ENOMASTER;
                goto fail;
            }

            if (arguments = cJSON_GetObjectItem(request, "arguments"), !arguments) {
                ierror = ENOARGUMENT;
                goto fail;
            }

            // cJSON_IsString(): local_get() passes this straight to OS_IsAllowedID().
            if (item = cJSON_GetObjectItem(arguments, "id"), !cJSON_IsString(item)) {
                ierror = ENOID;
                goto fail;
            }

            response = local_get(item->valuestring);
        } else if (!strcmp(function->valuestring, "token_create")) {
            // Minting writes the store, and only the master writes it (T8): a worker answers the
            // same 9015 as every other write it cannot perform. Checked before parsing the
            // arguments so a worker never reads the listener certificate for nothing.
            if (config.worker_node) {
                ierror = ENOMASTER;
                goto fail;
            }
            if (arguments = cJSON_GetObjectItem(request, "arguments"), !arguments) {
                ierror = ENOARGUMENT;
                goto fail;
            }
            etoken_store_reload_if_changed();
            if (response = local_token_create(arguments, &ierror), !response) {
                goto fail;
            }
        } else if (!strcmp(function->valuestring, "token_list")) {
            // Read-only, so any node answers from its replica (a worker sees what the cluster synced).
            etoken_store_reload_if_changed();
            response = local_token_list();
        } else if (!strcmp(function->valuestring, "token_revoke")) {
            if (config.worker_node) {
                ierror = ENOMASTER;
                goto fail;
            }
            if (arguments = cJSON_GetObjectItem(request, "arguments"), !arguments) {
                ierror = ENOARGUMENT;
                goto fail;
            }
            etoken_store_reload_if_changed();
            if (response = local_token_revoke(arguments, &ierror), !response) {
                goto fail;
            }
        } else {
            // A valid string, but none of the verbs above. Without this branch no handler ran and
            // the !response check below reported 9001 "Internal error" -- blaming the manager for
            // the caller's typo.
            ierror = ENOFUNCTION;
            goto fail;
        }

        if (!response) {
            merror("at local_dispatch(): response is null.");
            ierror = EINTERNAL;
            goto fail;
        }
        else {
            output = cJSON_PrintUnformatted(response);
            cJSON_Delete(response);
        }

        cJSON_Delete(request);
    } else {
        // Read configuration commands
        authcom_dispatch(input,&output);
    }

    return output;

fail:
    merror("ERROR %d: %s.", ERRORS[ierror].code, ERRORS[ierror].message);
    response = local_create_error_response(ERRORS[ierror].code, ERRORS[ierror].message);
    output = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    cJSON_Delete(request);
    os_free(groups);
    return output;
}

cJSON* local_add(const char *id,
                 const char *name,
                 const char *ip,
                 const char *groups,
                 const char *key,
                 const char *key_hash,
                 authd_force_options_t *force_options) {
    int index;
    cJSON *response = NULL;
    int ierror;
    char* str_result = NULL;
    char _ip[IPSIZE + 1] = {0};
    char reenroll_secret[AGENT_REENROLL_SECRET_HEX_CHARS + 1] = {0};
    bool warn = false;

    mdebug2("add(%s)", name);

    /* FIRST, ahead of the purge check below and of mutex_keys: a caller-supplied id must be within
     * the range the manager can actually store it in, and rejecting a malformed one costs nothing.
     * Reaching purge_is_pending() with it would spend a wazuh-db round trip -- on the request
     * thread -- to ask whether an id that cannot exist owes a deletion.
     *
     * OS_IsValidID()'s 8-character cap is a different, unrelated convention (self-enrollment ids),
     * not the id space /agents/insert accepts.
     *
     * Returns rather than `goto fail`, like the purge check: fail: unlocks mutex_keys, which is not
     * held yet. */
    if (id && !OS_IsValidAgentInsertID(id)) {
        return local_create_error_response(ERRORS[EINVALIDID].code, ERRORS[EINVALIDID].message);
    }

    /* An explicitly chosen id is the one case where the caller can land on an id whose previous
     * owner is still being cleaned up. Both this check and the duplicate-ID one below refuse
     * instead of reassigning it, because the pending purge matches by agent id and would delete the
     * NEW agent's documents -- and nothing in a state document lets the purge tell the two owners
     * apart.
     *
     * Refusing rather than cancelling the purge is deliberate: a queued purge always runs. The
     * caller is told to come back, which for a migration script is a retry, not a data loss.
     *
     * BEFORE mutex_keys, and that placement is the point: once authd has handed a deletion off, the
     * only authority on it is the manager-task row, so this can block for up to authd.wdb_timeout.
     * mutex_keys is the lock the writer thread and every enrollment take, so holding it across that
     * query would let a slow wazuh-db stall enrollment -- the exact wedge the deletion redesign
     * exists to remove. Nothing here reads the keystore, so there is nothing to serialise. */
    if (id && purge_is_pending(id)) {
        mwarn("Agent ID '%s' still has a pending deletion, rejecting the insertion.", id);
        return local_create_error_response(ERRORS[EPENDINGPURGE].code, ERRORS[EPENDINGPURGE].message);
    }

    w_mutex_lock(&mutex_keys);

    /* The same question again, from memory only, now that the keystore is locked: a deletion of
     * this very id could have been admitted between the check above and this lock, and add_remove()
     * reserves the id under mutex_keys. The expensive half is not repeated -- a row that reached a
     * terminal status a moment ago cannot have become outstanding again. */
    if (id && purge_is_pending_locally(id)) {
        mwarn("Agent ID '%s' was deleted while the insertion was being validated, rejecting it.", id);
        ierror = EPENDINGPURGE;
        goto fail;
    }

    /* Check if groups are valid to be aggregated */
    if (groups) {
        if (OS_SUCCESS != w_auth_validate_groups(groups, NULL)) {
            ierror = EINVGROUP;
            goto fail;
        }
    }

    /* A caller-supplied key must already have the shape remoted will accept (64 lowercase hex chars
     * -> the agent's 32-byte HS256 key). Anything else would be stored fine and then rejected on
     * every request as an unusable key, which is far harder to diagnose than refusing it here. */
    if (key && !OS_IsValidAgentKey(key)) {
        ierror = EINVALIDKEY;
        goto fail;
    }

    // Check for duplicate ID
    //
    // w_auth_replace_agent() os_strdup()s a fresh message into str_result on every call, so the
    // duplicate IP and name checks below free what the previous one left -- an add matching on both
    // would otherwise leak, since only one os_free() runs at the end. The ID check does not
    // participate: it refuses instead of replacing, so it never writes str_result.
    if (id && (index = OS_IsAllowedID(&keys, id), index >= 0)) {
        /* NOT replaced, even when force would allow it: replacing by the SAME id queues a purge for
         * an id that gets a new owner in this very operation. The agent has to be deleted first,
         * and its purge has to finish, before the id can be reused.
         *
         * Nothing is freed here, unlike the IP and name checks below: this branch no longer calls
         * w_auth_replace_agent(), so it leaves nothing in str_result for them to free. */
        mwarn("Duplicate ID '%s', rejecting the insertion: delete the agent and let its deletion "
              "finish before reusing the ID.", id);
        ierror = EDUPID;
        goto fail;
    }

    /* Check for duplicate IP */
    if (strcmp(ip, "any")) {
        os_ip *aux_ip;
        os_calloc(1, sizeof(os_ip), aux_ip);

        if (!OS_IsValidIP(ip, aux_ip)) {
            mwarn("Not valid IP '%s'", ip);
            w_free_os_ip(aux_ip);
            ierror = ENOIP;
            goto fail;
        }

        strncpy(_ip, aux_ip->ip, IPSIZE);
        w_free_os_ip(aux_ip);

        if (index = OS_IsAllowedIP(&keys, _ip), index >= 0) {
            os_free(str_result); // see the note on str_result above
            if (OS_SUCCESS == w_auth_replace_agent(keys.keyentries[index], key_hash, force_options, &str_result, &warn)) {
                minfo("Duplicate IP '%s'. %s", _ip, str_result);
            } else {
                if (warn) {
                    mwarn("Duplicate IP '%s', rejecting enrollment. %s", _ip, str_result);
                } else {
                    minfo("Duplicate IP '%s', rejecting enrollment. %s", _ip, str_result);
                }
                ierror = EDUPIP;
                goto fail;
            }
        }
    } else {
        strncpy(_ip, ip, IPSIZE);
    }

    /* Check for duplicate names */
    if (index = OS_IsAllowedName(&keys, name), index >= 0) {
        os_free(str_result); // see the note on str_result above
        if(OS_SUCCESS == w_auth_replace_agent(keys.keyentries[index], key_hash, force_options, &str_result, &warn)) {
            minfo("Duplicate name. %s", str_result);
        } else {
            if (warn) {
                mwarn("Duplicate name '%s', rejecting enrollment. %s", name, str_result);
            } else {
                minfo("Duplicate name '%s', rejecting enrollment. %s", name, str_result);
            }
            ierror = EDUPNAME;
            goto fail;
        }
    }

    /* The per-agent re-enrollment secret (#38993), generated BEFORE the key so a CSPRNG failure leaves
     * nothing to undo: it never goes to client.keys -- the writer persists it in global.db and this one
     * answer hands it to the agent -- and an agent without one could never re-enroll, so the enrollment
     * is refused the same way a failed key generation is (no weaker generator to fall back to). */
    if (OS_NewReenrollSecret(reenroll_secret, sizeof(reenroll_secret)) != 0) {
        ierror = EKEY;
        goto fail;
    }

    index = OS_AddNewAgent(&keys, id, name, _ip, key, config.max_agents);
    if (index == OS_ADDAGENT_LIMIT_REACHED) {
        merror("Unable to add agent: %s. Agent limit (%u) reached.", name, config.max_agents);
        ierror = EAGLIM;
        goto fail;
    }
    if (index < 0) {
        ierror = EKEY;
        goto fail;
    }

    /* Add pending key to write */
    add_insert(keys.keyentries[index], groups, reenroll_secret);
    write_pending = 1;
    w_cond_signal(&cond_pending);

    response = local_create_agent_response(keys.keyentries[index]->id, name, _ip, keys.keyentries[index]->raw_key, reenroll_secret);
    w_mutex_unlock(&mutex_keys);
    OPENSSL_cleanse(reenroll_secret, sizeof(reenroll_secret));

    minfo("Agent key generated for agent '%s' (requested locally)", name);
    os_free(str_result);
    return response;

fail:
    w_mutex_unlock(&mutex_keys);
    OPENSSL_cleanse(reenroll_secret, sizeof(reenroll_secret));
    response = local_create_error_response(ERRORS[ierror].code, ERRORS[ierror].message);
    os_free(str_result);
    return response;
}

// Re-enrollment (#38993), master only: the agent named by `kid` keeps its id and gets a fresh key and a fresh
// re-enrollment secret, both rotated in place -- no removal, no purge, its documents survive.
static cJSON* local_reenroll(const char *kid, const char *bearer, const char *name, const char *ip, const char *groups) {
    int index;
    int other;
    int ierror;
    int verdict;
    cJSON *response = NULL;
    cJSON *agent_info = NULL;
    cJSON *j_secret = NULL;
    char _ip[IPSIZE + 1] = {0};
    char new_key[AGENT_KEY_HEX_CHARS + 1] = {0};
    char new_secret[AGENT_REENROLL_SECRET_HEX_CHARS + 1] = {0};

    mdebug2("reenroll(%s)", kid);

    /* The credential first, and BEFORE mutex_keys for the reason purge_is_pending() runs there: this is a
     * wazuh-db round trip on the request thread, and the keystore lock is the one every enrollment and the
     * writer take. The row's reenroll_secret is the only thing that can authorise the request; no row, or a
     * row without one (a worker's mirror of client.keys, an agent enrolled over 1515, a global.db rebuilt
     * from client.keys -- see wm_database), and there is nothing to verify against: 9026. */
    agent_info = wdb_get_agent_info(atoi(kid), NULL);
    if (agent_info) {
        j_secret = cJSON_GetObjectItem(agent_info->child, "reenroll_secret");
    }
    if (!cJSON_IsString(j_secret) || !OS_IsValidReenrollSecret(j_secret->valuestring)) {
        cJSON_Delete(agent_info);
        mdebug1("Re-enrollment of agent '%s' refused: unknown agent or no re-enrollment credential on record.", kid);
        return local_create_error_response(ERRORS[EREENROLLUNKNOWN].code, ERRORS[EREENROLLUNKNOWN].message);
    }

    verdict = w_reenroll_verify(bearer, kid, j_secret->valuestring, (long)time(NULL), config.jwt_max_age, config.jwt_clock_skew);
    OPENSSL_cleanse(j_secret->valuestring, strlen(j_secret->valuestring));
    cJSON_Delete(agent_info);

    if (verdict != W_REENROLL_OK) {
        /* Debug, not warn: remoted forwards these bearers unverified, so anyone who can reach /enroll can make
         * this line fire at will. remoted's remoted.enroll.reenroll.* counters are the operator's view. */
        mdebug1("Re-enrollment of agent '%s' refused: %s.", kid,
                verdict == W_REENROLL_STALE ? "credential outside the accepted time window" : "invalid credential");
        ierror = verdict == W_REENROLL_STALE ? EREENROLLSTALE : EREENROLLINVALID;
        return local_create_error_response(ERRORS[ierror].code, ERRORS[ierror].message);
    }

    w_mutex_lock(&mutex_keys);

    /* The row said yes; the keystore has the last word (the agent may have been deleted since, or the row
     * may be wazuh-db's alone). */
    if (index = OS_IsAllowedID(&keys, kid), index < 0) {
        ierror = EREENROLLUNKNOWN;
        goto fail;
    }

    if (groups && OS_SUCCESS != w_auth_validate_groups(groups, NULL)) {
        ierror = EINVGROUP;
        goto fail;
    }

    /* The body's name/ip replace the record's, checked against every OTHER agent -- the entry being rotated
     * may keep its own. No force rules: nothing is replaced, and the secret already proved this caller IS
     * the agent. */
    if (strcmp(ip, "any")) {
        os_ip *aux_ip;
        os_calloc(1, sizeof(os_ip), aux_ip);

        if (!OS_IsValidIP(ip, aux_ip)) {
            mwarn("Not valid IP '%s'", ip);
            w_free_os_ip(aux_ip);
            ierror = ENOIP;
            goto fail;
        }

        strncpy(_ip, aux_ip->ip, IPSIZE);
        w_free_os_ip(aux_ip);

        if (other = OS_IsAllowedIP(&keys, _ip), other >= 0 && other != index) {
            mdebug1("Re-enrollment of agent '%s' refused: IP '%s' belongs to agent '%s'.", kid, _ip, keys.keyentries[other]->id);
            ierror = EDUPIP;
            goto fail;
        }
    } else {
        strncpy(_ip, ip, IPSIZE);
    }

    if (other = OS_IsAllowedName(&keys, name), other >= 0 && other != index) {
        mdebug1("Re-enrollment of agent '%s' refused: name '%s' belongs to agent '%s'.", kid, name, keys.keyentries[other]->id);
        ierror = EDUPNAME;
        goto fail;
    }

    /* Both credentials BEFORE the keystore is touched: a CSPRNG failure then leaves the agent exactly as it
     * was, instead of deleted and not re-added. */
    if (OS_NewAgentKey(new_key, sizeof(new_key)) != 0 || OS_NewReenrollSecret(new_secret, sizeof(new_secret)) != 0) {
        merror("Unable to rotate the credentials of agent '%s': the CSPRNG (RAND_bytes) failed.", kid);
        ierror = EKEY;
        goto fail;
    }

    /* The rotation itself: delete + add under the same lock, so no reader ever sees the id missing. purge = 1:
     * no `!id` removal marker is kept (the id is not being retired), and add_remove() is not called -- no
     * wdb_remove_agent(), no deletion task, no indexer purge. The writer persists this as an UPDATE of the
     * agent's row (add_rotate()), never as an insert. */
    if (OS_DeleteKey(&keys, kid, 1) < 0) {
        ierror = EINTERNAL;
        goto fail;
    }
    /* max_agents 0: the count did not grow, and the limit must not refuse an agent that already counted. */
    index = OS_AddNewAgent(&keys, kid, name, _ip, new_key, 0);
    if (index < 0) {
        /* Not reachable with a validated ip and an explicit key (OS_AddKey() only fails on the ip); logged as
         * loudly as it deserves, since the entry is gone from memory until the next client.keys reload. */
        merror("Unable to re-add agent '%s' to the keystore after rotating its credentials.", kid);
        ierror = EINTERNAL;
        goto fail;
    }

    add_rotate(keys.keyentries[index], groups, new_secret);
    write_pending = 1;
    w_cond_signal(&cond_pending);

    response = local_create_agent_response(kid, name, _ip, new_key, new_secret);
    w_mutex_unlock(&mutex_keys);
    OPENSSL_cleanse(new_key, sizeof(new_key));
    OPENSSL_cleanse(new_secret, sizeof(new_secret));

    minfo("Agent '%s' (id '%s') re-enrolled: key and re-enrollment secret rotated.", name, kid);
    return response;

fail:
    w_mutex_unlock(&mutex_keys);
    OPENSSL_cleanse(new_key, sizeof(new_key));
    OPENSSL_cleanse(new_secret, sizeof(new_secret));
    return local_create_error_response(ERRORS[ierror].code, ERRORS[ierror].message);
}

// Forward an "add" request to the master node over the cluster (worker nodes only)
cJSON* local_add_clustered(const char *name, const char *ip, const char *groups, const char *key_hash, const char *token_id,
                           const char *reenroll_kid, const char *reenroll_bearer) {
    char *new_id = NULL;
    char *new_key = NULL;
    char *new_secret = NULL;
    char err_response[OS_SIZE_2048] = {0};
    int master_error_code = 0;
    int result;
    cJSON *response = NULL;

    mdebug2("add_clustered(%s)", name);
    minfo("Dispatching enrollment request to master node");

    result = w_request_agent_add_clustered(err_response, name, ip, groups, key_hash,
                                            &new_id, &new_key, &new_secret, NULL, NULL, token_id, reenroll_kid, reenroll_bearer,
                                            &master_error_code);

    if (result == 0) {
        // The master's re-enrollment secret travels through untouched (#38993); a master that predates
        // it hands back none, and this node then answers without the field, as before.
        response = local_create_agent_response(new_id, name, ip, new_key, new_secret && *new_secret ? new_secret : NULL);
    } else if (master_error_code > 0) {
        // A well-formed business rejection: surface the master's exact code so the bridge can map
        // it precisely. Drop the "ERROR: " prefix w_parse_agent_add_response() always adds -- the
        // numeric code already says as much.
        const char *message = err_response;
        if (!strncmp(message, "ERROR: ", 7)) {
            message += 7;
        }

        mwarn("Error %d: %s.", master_error_code, message);
        response = local_create_error_response(master_error_code, message);
    } else {
        // Transport failure, or an unparseable response: either way, no clean answer.
        merror("ERROR %d: %s.", ERRORS[ENOMASTERCOMM].code, ERRORS[ENOMASTERCOMM].message);
        response = local_create_error_response(ERRORS[ENOMASTERCOMM].code, ERRORS[ENOMASTERCOMM].message);
    }

    os_free(new_id);
    os_free(new_key);
    if (new_secret) {
        OPENSSL_cleanse(new_secret, strlen(new_secret));
    }
    os_free(new_secret);
    return response;
}

// Remove an agent
cJSON* local_remove(const char *id, int purge) {
    int index;
    cJSON *response = NULL;

    mdebug2("local_remove(id='%s', purge=%d)", id, purge);

    w_mutex_lock(&mutex_keys);

    if (index = OS_IsAllowedID(&keys, id), index < 0) {
        mdebug1("Error %d: %s.", ERRORS[ENOAGENT].code, ERRORS[ENOAGENT].message);
        response = local_create_error_response(ERRORS[ENOAGENT].code, ERRORS[ENOAGENT].message);
    } else if (purge_backlog_full()) {
        /* PHASE 0, and it has to be here rather than anywhere later.
         *
         * One line below, add_remove() and OS_DeleteKey() have run: the agent is out of the
         * in-memory keystore and this function is about to answer "deleted". From that point there
         * is nothing left to refuse and nobody to tell, which is why the old code -- discovering
         * the overflow in the writer -- could only choose between dropping the purge silently and
         * logging it while the documents were orphaned. Refusing the REQUEST leaves the agent
         * exactly as it was, and the caller can retry. */
        mwarn("Error %d: %s.", ERRORS[EDELETEBACKLOG].code, ERRORS[EDELETEBACKLOG].message);
        response = local_create_error_response(ERRORS[EDELETEBACKLOG].code, ERRORS[EDELETEBACKLOG].message);
    } else {
        minfo("Agent '%s' (%s) deleted (requested locally)", id, keys.keyentries[index]->name);
        /* Add pending key to write */
        add_remove(keys.keyentries[index]);
        OS_DeleteKey(&keys, id, purge);
        write_pending = 1;
        w_cond_signal(&cond_pending);
        response = local_create_agent_delete_response();
    }

    w_mutex_unlock(&mutex_keys);
    return response;
}

// Get agent data
cJSON* local_get(const char *id) {
    int index;
    cJSON *response = NULL;

    mdebug2("local_get(%s)", id);
    w_mutex_lock(&mutex_keys);

    if (index = OS_IsAllowedID(&keys, id), index < 0) {
        mdebug1("Error %d: %s.", ERRORS[ENOAGENT].code, ERRORS[ENOAGENT].message);
        response = local_create_error_response(ERRORS[ENOAGENT].code, ERRORS[ENOAGENT].message);
    }
    else {
        // Never the re-enrollment secret: `get` serves manage_agents/the API, and the secret is the
        // agent's alone (the writer only ever holds it until global.db has it).
        response = local_create_agent_response(id, keys.keyentries[index]->name, keys.keyentries[index]->ip->ip, keys.keyentries[index]->raw_key, NULL);
    }

    w_mutex_unlock(&mutex_keys);
    return response;
}

// ---------------------------------------------------------------- enrollment tokens (#38993)

static int is_token_id(const char *text) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int ok;

    if (text == NULL || strlen(text) != ETOKEN_ID_CHARS) {
        return 0;
    }

    ok = (w_b64url_decode(text, &raw, &raw_len) == 0 && raw_len == W_ETOKEN_ID_BYTES);
    free(raw);

    return ok;
}

// Optional non-negative integer argument. 0 = absent, 1 = present (*out set), -1 = wrong type/negative.
static int get_optional_long_arg(cJSON *arguments, const char *key, long *out) {
    cJSON *item = cJSON_GetObjectItem(arguments, key);

    if (item == NULL || cJSON_IsNull(item)) {
        return 0;
    }

    if (!cJSON_IsNumber(item) || item->valuedouble < 0 || item->valuedouble > (double)LONG_MAX) {
        return -1;
    }

    *out = (long)item->valuedouble;

    return 1;
}

// Optional boolean argument. 0 = absent, 1 = present (*out set), -1 = wrong type.
static int get_optional_bool_arg(cJSON *arguments, const char *key, int *out) {
    cJSON *item = cJSON_GetObjectItem(arguments, key);

    if (item == NULL || cJSON_IsNull(item)) {
        return 0;
    }

    if (!cJSON_IsBool(item)) {
        return -1;
    }

    *out = cJSON_IsTrue(item) ? 1 : 0;

    return 1;
}

static cJSON* local_token_create(cJSON *arguments, int *ierror) {
    etoken_mint_request_t req = {0};
    etoken_mint_t mint = {0};
    char detail[OS_SIZE_256] = {0};
    char *prefix = NULL;
    char *description = NULL;
    cJSON *item = NULL;
    cJSON *data = NULL;
    cJSON *response = NULL;
    long port = 0;
    long ttl = 0;
    long max_uses = 0;
    int embed_ca = 0;
    int no_credential = 0;
    int rc;

    // `address` is the one mandatory argument: the host the agents will connect to.
    if (item = cJSON_GetObjectItem(arguments, "address"), !cJSON_IsString(item) || item->valuestring[0] == '\0') {
        *ierror = ENOARGUMENT;
        return NULL;
    }
    req.address = item->valuestring;

    if (get_optional_string_arg(arguments, "prefix", &prefix) < 0 ||
        get_optional_string_arg(arguments, "description", &description) < 0 ||
        get_optional_long_arg(arguments, "port", &port) < 0 ||
        get_optional_long_arg(arguments, "ttl", &ttl) < 0 ||
        get_optional_long_arg(arguments, "max_uses", &max_uses) < 0 ||
        get_optional_bool_arg(arguments, "embed_ca", &embed_ca) < 0 ||
        get_optional_bool_arg(arguments, "no_credential", &no_credential) < 0) {
        *ierror = EJSON;
        return NULL;
    }

    if (max_uses > UINT_MAX) {
        *ierror = EJSON;
        return NULL;
    }

    req.port = port;
    req.prefix = prefix;
    req.ttl = ttl;
    req.max_uses = (unsigned int)max_uses;
    req.embed_ca = embed_ca;
    req.no_credential = no_credential;
    req.description = description;

    rc = etoken_mint_prepare(&req, &mint, detail, sizeof(detail));

    if (rc == -1) {
        // The one error whose message is built at runtime: the code says "refused", the detail
        // says why, and the operator fixes the address or the certificates accordingly.
        char message[OS_SIZE_512];

        snprintf(message, sizeof(message), "%s: %s", ERRORS[EMINTREFUSED].message, detail);
        mwarn("%s (address '%s').", message, req.address);
        return local_create_error_response(ERRORS[EMINTREFUSED].code, message);
    }

    if (rc != 0) {
        merror("Cannot prepare an enrollment token: %s.", detail);
        *ierror = EINTERNAL;
        return NULL;
    }

    if (etoken_store_create(&mint, time(NULL), &data) != 0) {
        etoken_mint_free(&mint);
        *ierror = EINTERNAL;
        return NULL;
    }

    etoken_mint_free(&mint);

    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddItemToObject(response, "data", data);

    return response;
}

static cJSON* local_token_list(void) {
    cJSON *response = cJSON_CreateObject();

    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddItemToObject(response, "data", etoken_store_list());

    return response;
}

static cJSON* local_token_revoke(cJSON *arguments, int *ierror) {
    cJSON *item = NULL;
    cJSON *response = NULL;

    if (item = cJSON_GetObjectItem(arguments, "id"), !cJSON_IsString(item)) {
        *ierror = ENOARGUMENT;
        return NULL;
    }

    // Wrong shape or unknown: the same 9022, see ERRORS[].
    if (!is_token_id(item->valuestring) || etoken_store_revoke(item->valuestring) != 0) {
        *ierror = ETOKENNOTFOUND;
        return NULL;
    }

    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddItemToObject(response, "data", cJSON_CreateObject());

    return response;
}

// Generates an agent info json response
cJSON* local_create_agent_response(const char *id, const char *name, const char *ip, const char *key, const char *reenroll_secret) {
    cJSON *response = NULL;
    cJSON *data = NULL;

    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddItemToObject(response, "data", data = cJSON_CreateObject());
    cJSON_AddStringToObject(data, "id", id);
    cJSON_AddStringToObject(data, "name", name);
    cJSON_AddStringToObject(data, "ip", ip);
    cJSON_AddStringToObject(data, "key", key);
    if (reenroll_secret) {
        cJSON_AddStringToObject(data, "reenroll_secret", reenroll_secret);
    }

    return response;
}

// Generates an agent deleted response
static cJSON* local_create_agent_delete_response(void) {
    cJSON *response = NULL;

    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddStringToObject(response, "data", "Agent deleted successfully.");

    return response;
}

// Generates an error json response
static cJSON* local_create_error_response(int code, const char *message) {
    cJSON *response = NULL;

    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", code);
    cJSON_AddStringToObject(response, "message", message);

    return response;
}
