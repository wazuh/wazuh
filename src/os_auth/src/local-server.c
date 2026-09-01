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
#include "os_err.h"
#include "authd-config.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

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
    EINVALIDKEY // Append only: ERRORS[] below is indexed directly by these values.
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
    { 9019, "Invalid agent key" }
};

// Dispatch local request
static char* local_dispatch(const char *input);

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

// Generates an agent info json response
static cJSON* local_create_agent_response(const char *id, const char *name, const char *ip, const char *key);

// Generates an agent deleted response
static cJSON* local_create_agent_delete_response(void);

// Generates an error json response
static cJSON* local_create_error_response(int code, const char *message);

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
                get_optional_string_arg(arguments, "key", &key) < 0) {
                ierror = EJSON;
                goto fail;
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
                response = local_add_clustered(name, ip, groups, key_hash);
            } else {
                response = local_add(id, name, ip, groups, key, key_hash, force ? &force_options : &config.force_options);
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
        } else {
            // A valid string, but none of the three above. Without this branch no handler ran and
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
    bool warn = false;

    mdebug2("add(%s)", name);
    w_mutex_lock(&mutex_keys);

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

    /* An explicitly chosen id is the one case where the caller can land on an id whose previous
     * owner is still being cleaned up. Both branches below refuse instead of reassigning it,
     * because the pending purge matches by agent id and would delete the NEW agent's documents --
     * and nothing in a state document lets the purge tell the two owners apart.
     *
     * Refusing rather than cancelling the purge is deliberate: a queued purge always runs. The
     * caller is told to come back, which for a migration script is a retry, not a data loss. */
    if (id && purge_is_pending(id)) {
        mwarn("Agent ID '%s' still has a pending deletion, rejecting the insertion.", id);
        ierror = EPENDINGPURGE;
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
    add_insert(keys.keyentries[index],groups);
    write_pending = 1;
    w_cond_signal(&cond_pending);

    response = local_create_agent_response(keys.keyentries[index]->id, name, _ip, keys.keyentries[index]->raw_key);
    w_mutex_unlock(&mutex_keys);

    minfo("Agent key generated for agent '%s' (requested locally)", name);
    os_free(str_result);
    return response;

fail:
    w_mutex_unlock(&mutex_keys);
    response = local_create_error_response(ERRORS[ierror].code, ERRORS[ierror].message);
    os_free(str_result);
    return response;
}

// Forward an "add" request to the master node over the cluster (worker nodes only)
cJSON* local_add_clustered(const char *name, const char *ip, const char *groups, const char *key_hash) {
    char *new_id = NULL;
    char *new_key = NULL;
    char err_response[OS_SIZE_2048] = {0};
    int master_error_code = 0;
    int result;
    cJSON *response = NULL;

    mdebug2("add_clustered(%s)", name);
    minfo("Dispatching enrollment request to master node");

    result = w_request_agent_add_clustered(err_response, name, ip, groups, key_hash,
                                            &new_id, &new_key, NULL, NULL, &master_error_code);

    if (result == 0) {
        response = local_create_agent_response(new_id, name, ip, new_key);
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
        response = local_create_agent_response(id, keys.keyentries[index]->name, keys.keyentries[index]->ip->ip, keys.keyentries[index]->raw_key);
    }

    w_mutex_unlock(&mutex_keys);
    return response;
}

// Generates an agent info json response
cJSON* local_create_agent_response(const char *id, const char *name, const char *ip, const char *key) {
    cJSON *response = NULL;
    cJSON *data = NULL;

    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddItemToObject(response, "data", data = cJSON_CreateObject());
    cJSON_AddStringToObject(data, "id", id);
    cJSON_AddStringToObject(data, "name", name);
    cJSON_AddStringToObject(data, "ip", ip);
    cJSON_AddStringToObject(data, "key", key);

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
