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
    EINVALIDNAME // Appended, not inserted: ERRORS[] below is indexed directly by this enum's
                 // value, so every existing entry must keep its current index.
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
    // Distinct from 9005 ("No such name", raised when the "name" argument is missing entirely):
    // this is a NAME THAT IS PRESENT but fails OS_IsValidName()'s charset/length/leading-dot rules
    // (e.g. contains a space). Collapsing the two under 9005 left an API/manage_agents caller
    // seeing "No such name" for a name it very much did supply, with nothing to point at the
    // actual problem.
    { 9017, "Invalid agent name" }
};

// Dispatch local request
static char* local_dispatch(const char *input);

// Per-connection thread body: recv, dispatch, send, close. See run_local_server()'s comment on
// why this now runs on its own detached thread instead of inline on the accept loop.
static void* handle_local_client(void *arg);

struct local_client_ctx {
    int peer;
};

// Caps how many connections handle_local_client() may service CONCURRENTLY via a detached
// thread. Without this, a burst of connections (e.g. many cluster workers enrolling against one
// master's authd at once, or any local caller not otherwise rate-limited) would spawn one thread
// per connection with no ceiling at all. 128 matches AUTH_LOCAL_SOCK's own listen backlog
// (OS_BindUnixDomainWithPerms, shared/os_net/os_net.c) -- there is no benefit to servicing more
// connections concurrently than that many could ever be queued at once to begin with.
#define MAX_LOCAL_CLIENT_THREADS 128

// How long run_local_server() waits, and how often it re-checks, for detached client threads to
// finish once it has been told to stop. The timeout only has to cover a dispatch already in
// progress -- the longest of which is a worker's cluster-forwarded "add" (see local_add_clustered())
// -- not a new one, since the accept loop has already exited by then.
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

// Rejects only names that would actually corrupt client.keys (or fail to round-trip back out of
// it) -- deliberately NOT the stricter agent-name charset OS_IsValidName() enforces.
//
// This socket's established callers are manage_agents and the API, and the API's own documented
// contract is `^[\w\-.%]+$` with no minimum length (api/api/validator.py). Names it has always
// accepted -- containing '%', a single character, or a leading '.' -- are all rejected by
// OS_IsValidName() yet cannot corrupt anything, so enforcing that charset here would break
// working POST /agents calls for no storage-safety gain at all.
//
// What genuinely must be refused is what the client.keys line format cannot represent:
//   - whitespace and control bytes: the record is whitespace-delimited, so a space or tab splits
//     the name into extra fields and shifts every later column (remoted's keystore reader, which
//     does `tokens >> id >> name >> ip >> key`, would then take the name's tail as the IP and the
//     IP as the key, leaving the agent with an undecodable key and a 401 on every request it ever
//     makes); '\n' or '\r' ends the record outright.
//   - a leading '#' or '!': both OS_ReadKeys() and remoted's keystore treat that as the
//     removed/disabled-entry marker and skip the line, silently dropping the agent.
//
// The two ENROLLMENT paths -- port 1515 in auth.c, and POST /enroll in enrollmentEndpoint.cpp --
// additionally apply OS_IsValidName() to the names they mint, where there is no back-compatibility
// obligation and agreeing with each other matters more than being permissive.
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

// Services one already-accepted local-socket connection: set its recv timeout, read one request,
// dispatch it, send the reply, close. Shared by both the threaded and the at-the-cap synchronous
// fallback path below (see run_local_server()) -- the logic is identical either way, only WHERE it
// runs (a detached thread vs inline on the accept loop) differs.
static void service_local_client(int peer) {
    char *buffer = NULL;
    char *response;
    ssize_t length;

    if (config.timeout_sec || config.timeout_usec) {
        if (OS_SetRecvTimeout(peer, config.timeout_sec, config.timeout_usec) < 0) {
            // Log-once latch. Guarded now that this function also runs on concurrent client
            // threads: an unsynchronized static read-modify-write is a data race even when the
            // worst visible outcome is a duplicated line.
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

    // Closed exactly once, here, on every arm. The "empty message" and OS_MAXLEN arms used to
    // close it themselves and then fall through to this close as well: harmless while dispatch ran
    // inline on the accept loop, but a genuine hazard now that each connection is serviced on its
    // own thread -- between the two closes another thread can be handed the same descriptor number
    // by accept()/open(), and the second close would silently destroy ITS connection (a truncated
    // client.keys write from the writer thread, or a dropped cluster/wdb socket, with nothing
    // logged). The empty-message arm is not a rare path either: OS_RecvSecureTCP() returns 0
    // whenever the peer closes before the length header arrives, which is exactly what remoted's
    // /enroll bridge does every time one of its own connect/response timeouts fires.
    close(peer);
    free(buffer);
}

// Runs on its own detached thread (see run_local_server()) so a single slow dispatch -- most
// notably a worker's cluster-forwarded "add", which can legitimately take several seconds, see
// local_add_clustered() -- never blocks any OTHER local-socket caller (manage_agents, the API, or
// another concurrently queued /enroll request) behind it. Safe to run concurrently:
// local_add()/local_remove()/local_get() already serialize access to the shared `keys` keystore
// (and write_pending/cond_pending) through mutex_keys. Releases the slot try_reserve_local_client_slot()
// reserved for it, so run_local_server() can admit another thread once this one finishes.
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
            // At MAX_LOCAL_CLIENT_THREADS already-in-flight connections: fall back to the
            // original synchronous behavior for this ONE connection (service it right here,
            // inline, before accepting the next) instead of either spawning past the cap or
            // dropping this client outright. Self-limiting by construction, exactly like the
            // pre-existing behavior this whole function used to have unconditionally.
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

    // Drain in-flight client threads before returning. They are DETACHED, so nobody ever joins
    // them, and main-server.c joins only this accept thread -- returning while one is still inside
    // local_add() would let process teardown (atexit cleanup, then exit()) run concurrently with an
    // OS_WriteKeys(), which is how client.keys ends up truncated on a restart. Bounded rather than
    // unconditional: a client that connected and never sent holds its thread for as long as its
    // recv timeout allows (and indefinitely if auth.timeout_seconds is set to 0), and a stuck
    // client must not be able to block shutdown forever -- wazuh-control would escalate to SIGKILL
    // anyway, which is strictly worse than proceeding deliberately.
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

        if (function = cJSON_GetObjectItem(request, "function"), !function) {
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
            authd_force_options_t force_options = {0};

            if (arguments = cJSON_GetObjectItem(request, "arguments"), !arguments) {
                ierror = ENOARGUMENT;
                goto fail;
            }

            id = (item = cJSON_GetObjectItem(arguments, "id"), item) ? item->valuestring : NULL;

            if (item = cJSON_GetObjectItem(arguments, "name"), !item) {
                ierror = ENONAME;
                goto fail;
            }
            name = item->valuestring;

            // This local socket historically trusted every caller to have already validated the
            // name -- true enough for manage_agents/the API, but not for /enroll, which bridges an
            // arbitrary remote agent-supplied string straight here. An unstorable name silently
            // corrupts client.keys once written, so it has to be refused before
            // local_add()/local_add_clustered() ever runs, for every caller alike. See
            // is_storable_agent_name() for why this is the storage-safety invariant and not
            // OS_IsValidName()'s stricter charset (which would reject names the API has always
            // accepted). EINVALIDNAME (9017), not ENONAME (9005, "No such name" -- for the
            // argument being absent, checked just above): a caller that DID supply a name, just
            // not a storable one, needs a message that says so rather than one reading as if it
            // forgot the field entirely.
            if (!is_storable_agent_name(name)) {
                ierror = EINVALIDNAME;
                goto fail;
            }

            if (item = cJSON_GetObjectItem(arguments, "ip"), !item) {
                ierror = ENOIP;
                goto fail;
            }
            ip = item->valuestring;

            if (item = cJSON_GetObjectItem(arguments, "groups"), item) {
                groups = wstr_delete_repeated_groups(item->valuestring);
                if (!groups) {
                    ierror = EINVGROUP;
                    goto fail;
                }
            }

            key_hash = (item = cJSON_GetObjectItem(arguments, "key_hash"), item) ? item->valuestring : NULL;
            key = (item = cJSON_GetObjectItem(arguments, "key"), item) ? item->valuestring : NULL;

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
                    // A caller-supplied id and/or key means this is an admin/restore-style add
                    // (manage_agents/the API can send both; self-enrollment -- /enroll included --
                    // never does), not the self-enrollment shape local_add_clustered() forwards.
                    // There is no cluster RPC to honor a caller-chosen id/key on a worker, and
                    // silently ignoring them (as local_add_clustered() itself does -- it has no
                    // id/key parameters at all) would return 200 with a DIFFERENT id/key than the
                    // one requested: a caller restoring or importing a specific agent would believe
                    // it succeeded as asked while a different agent record was actually created.
                    // Reject with the same code this request got before cluster forwarding was
                    // added for "add", rather than complete it with the wrong identity.
                    ierror = ENOMASTER;
                    goto fail;
                }
                // No id/key: a genuine self-enrollment-shaped request (the only shape /enroll ever
                // sends). The force registration settings are ignored for workers too, exactly like
                // the network (port 1515) enrollment path -- the master always assigns the ID,
                // generates the key, and decides force-replace using its own configuration.
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

            if (item = cJSON_GetObjectItem(arguments, "id"), !item) {
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

            if (item = cJSON_GetObjectItem(arguments, "id"), !item) {
                ierror = ENOID;
                goto fail;
            }

            response = local_get(item->valuestring);
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

    // Check for duplicate ID
    if (id && (index = OS_IsAllowedID(&keys, id), index >= 0)) {
        if(OS_SUCCESS == w_auth_replace_agent(keys.keyentries[index], key_hash, force_options, &str_result, &warn)) {
            minfo("Duplicate ID. %s", str_result);
        } else {
            if (warn) {
                mwarn("Duplicate ID, rejecting enrollment. %s", str_result);
            } else {
                minfo("Duplicate ID, rejecting enrollment. %s", str_result);
            }
            ierror = EDUPID;
            goto fail;
        }
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

    /* Check whether the agent name is the same as the manager */
    if (!strcmp(name, shost)) {
        ierror = EDUPNAME;
        goto fail;
    }

    /* Check for duplicate names */
    if (index = OS_IsAllowedName(&keys, name), index >= 0) {
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
        // The master responded with a well-formed business rejection; surface its exact code
        // so the bridge can map it precisely instead of a generic failure. err_response always
        // carries a "ERROR: " prefix here (see w_parse_agent_add_response) -- drop it, since the
        // numeric code already conveys the outcome.
        const char *message = err_response;
        if (!strncmp(message, "ERROR: ", 7)) {
            message += 7;
        }
        merror("ERROR %d: %s.", master_error_code, message);
        response = local_create_error_response(master_error_code, message);
    } else {
        // Transport failure, or a malformed/unparseable response from the master -- either
        // way, the cluster forward did not produce a clean answer.
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
