/*
 * Wazuh agent HTTPS client bridge
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * Wires the C++ https_client module (src/client-agent/https_client) into
 * agentd. HTTPS is the agent's transport unconditionally -- there is no
 * internal-option gate: the agent has exactly one manager address/port by
 * this point (client-agent/src/main.c already refuses to start otherwise --
 * see w_https_client_start()'s comment) and no alternative transport is
 * offered.
 *
 * The config surface (<server>/<ssl>, parsed by Read_Agent/Read_Agent_SSL
 * in src/config/src/client-config.c) and the real TLS wiring are done: the
 * module's own fail-closed validation (ModuleConfig::validateTls) now gets a
 * real verify_mode/CA/cert/key/ciphers instead of a forced HC_VERIFY_NONE.
 * on_reenroll_required is wired to the existing authd flow (try_enroll_to_server,
 * start_agent.c) and hc_set_agent_key(); on_state_change feeds the .state file
 * (client-agent/include/state.h) and, since WAIT_FILE/os_setwait() had no HTTPS
 * release path either, also clears a stale producer lock on REGISTERED.
 * on_producer_pause arms and releases that same lock while running, so a
 * sustained manager outage stops modules generating events the agent could only
 * drop. on_startup_result applies module limits and cluster-name authority, and
 * on_config_downloaded writes/applies merged.mg and releases the startup_gate.
 *
 * Since #38030 this is the agent's only transport, so every manager-visible
 * message the C side still produces goes into its /stateless accumulator.
 */

#include "https_client_bridge.h"

#include <ctype.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>

#include "agentd.h" /* pulls defs.h (__wazuh_version), sec.h (keys), client-config.h (agt) */
#include "https_client.h"
#include "sha256_op.h" /* OS_SHA256_File(): config_checksum seed, matching the module's own hash space */
#include "syscheck_op.h" /* ag_send_syscheck: the FIM leg of the sync answer */
#include "wmodules.h"    /* wmcom_send: the leg for every other module */
#include "task_registry_client.h" /* durable task_id registry client */
#include "vd_offset_client.h" /* durable VD feed offset registry client */
#include "wm_agent_upgrade_agent.h" /* wm_agent_upgrade_process_command */
#include "cJSON.h"
#include "metadata_provider.h" /* metadata_provider_get(): host metadata for the Notify */
#include "os_net.h"
#include "state.h" /* w_agentd_state_update, INCREMENT_TASK_* */

#ifdef WIN32
/* The queue os_execd pops from. Lived in receiver.c; the /control
 * active_response dispatch below is its only producer now. */
w_queue_t *winexec_queue;

/* asp_set_session_sender: registers this bridge's in-process /stateful session sender with
 * agent_sync_protocol, since Windows has no local socket for it to connect to (see
 * SyncSocketTransport's own class doc and bridge_build_config()'s comment on
 * sync_socket_path above). */
#include "agent_sync_protocol_c_interface.h"
#endif

static hc_handle *g_https_client = NULL;

/* Set once w_https_client_stop() starts tearing the client down; the re-
 * enroll thread (detached, so it can't be joined/cancelled) checks this
 * before ever touching the handle, since hc_destroy() may run concurrently
 * with a retry loop that can take minutes against a down manager.
 *
 * Guarded by g_https_client_lock, NOT a C11 _Atomic: mingw's <stdatomic.h>
 * does not declare the generic atomic_load()/atomic_store() macros, so on
 * winagent they compiled as implicit declarations and left undefined
 * references that broke the wazuh-agent.exe link as soon as anything
 * referenced this object. Every access already needed the lock for the handle
 * it guards, so the mutex is the cheaper of the two fixes.
 *
 * Not static: unit tests call bridge_reenroll_thread() directly (bypassing
 * w_https_client_start(), which is what normally resets this) and need to
 * reset it themselves between cases; they run single-threaded, so they assign
 * it without the lock. */
bool g_https_client_stopping = false;

/* Serializes the re-enroll thread's key reload against shutdown's teardown.
 * The thread's hc_set_agent_key() touches the handle; w_https_client_stop()
 * destroys it. Without this the stopping-flag check is a check-then-act race:
 * the thread could pass the check, then stop() destroys the handle, then the
 * thread calls into freed memory. Holding this across {set the flag} on the
 * stop side and {check the flag + touch the handle} on the thread side makes
 * the two mutually exclusive, so the handle is either still valid or provably
 * not touched. NOT held across hc_destroy() (which joins module threads and
 * could run long / re-enter). */
static pthread_mutex_t g_https_client_lock = PTHREAD_MUTEX_INITIALIZER;

/* Reads the stopping flag for callers that are not already holding the lock
 * (the re-enroll retry loop polls it between attempts). Callers that go on to
 * touch the handle must instead read it inside their own critical section --
 * checking here and acting later would reopen the check-then-act race. */
static bool bridge_stopping(void)
{
    w_mutex_lock(&g_https_client_lock);
    const bool stopping = g_https_client_stopping;
    w_mutex_unlock(&g_https_client_lock);
    return stopping;
}

/* Mirrors the incremental back-off already used for the initial-enrollment
 * loop (start_agent.c's w_agentd_keys_init: 5s steps up to a 60s cap). Not
 * reused directly because those constants are file-local to start_agent.c. */
#define BRIDGE_REENROLL_RETRY_DELTA_S 5
#define BRIDGE_REENROLL_RETRY_MAX_S 60

/* Runs off the dispatcher thread (spawned by bridge_on_reenroll_required):
 * the module's callback contract forbids blocking it, and enrollment can
 * take anywhere from seconds to (against a down manager) indefinitely.
 *
 * No bridge-side single-flight guard is needed: AuthGate (the module's 401
 * latch) only fires on_reenroll_required once per incident and won't re-arm
 * until hc_set_agent_key() is called, so at most one of these threads is ever
 * running at a time -- adding another lock here would just duplicate that
 * guarantee.
 *
 * Not static: unit-tested by calling it directly (synchronously, with a fake
 * handle) instead of through the real w_create_thread/CreateThread, whose
 * test double intentionally never runs the function it's given.
 */
void *bridge_reenroll_thread(void *arg)
{
    hc_handle *handle = (hc_handle *)arg;
    int enroll_result = -1;
    int delay_sleep = 0;

    while (enroll_result != 0) {
        if (bridge_stopping()) {
            mdebug1("https_client: agent shutting down; abandoning re-enrollment.");
            return NULL;
        }

        if (agt->enrollment_cfg && agt->enrollment_cfg->target_cfg &&
            agt->enrollment_cfg->target_cfg->manager_name) {
            enroll_result = try_enroll_to_server(agt->enrollment_cfg->target_cfg->manager_name,
                                                  agt->enrollment_cfg->target_cfg->network_interface);
        }
        if (enroll_result != 0 && agt->server && agt->server[0].rip) {
            enroll_result = try_enroll_to_server(agt->server[0].rip, agt->server[0].network_interface);
        }

        if (enroll_result != 0) {
            if (delay_sleep < BRIDGE_REENROLL_RETRY_MAX_S) {
                delay_sleep += BRIDGE_REENROLL_RETRY_DELTA_S;
            }
            mdebug1("https_client: re-enrollment attempt failed; retrying in %d seconds.", delay_sleep);
            sleep((unsigned int)delay_sleep);
        }
    }

    /* Under the lock: either we see the stopping flag (w_https_client_stop()
     * set it before it will destroy the handle) and abandon without touching
     * the handle, or we reload the key on a still-valid handle while stop()
     * blocks behind us -- it cannot set the flag, and so cannot reach
     * hc_destroy(), until we release. */
    w_mutex_lock(&g_https_client_lock);

    if (g_https_client_stopping) {
        w_mutex_unlock(&g_https_client_lock);
        mdebug1("https_client: agent shutting down; not reloading the signing key.");
        return NULL;
    }

    minfo("https_client: re-enrollment succeeded; reloading the signing key.");
    if (!hc_set_agent_key(handle, keys.keyentries[0]->raw_key)) {
        merror("https_client: re-enrolled, but the new key failed validation; traffic stays paused.");
    }

    w_mutex_unlock(&g_https_client_lock);
    return NULL;
}

#ifdef WIN32
/* Win32 thread entry adapting the POSIX-signature worker. Casting a cdecl
 * function to stdcall (LPTHREAD_START_ROUTINE) would corrupt the stack on the
 * 32-bit build, so wrap it instead. */
static DWORD WINAPI bridge_reenroll_thread_win(LPVOID arg)
{
    bridge_reenroll_thread(arg);
    return 0;
}
#endif

/* Startup-response parsing: applies module limits and cluster-name authority
 * from the handshake. Deliberately separate, local copies of
 * client-agent/src/start_agent.c's parse_fim_limits()/
 * parse_syscollector_limits()/parse_sca_limits()/parse_limits() logic rather
 * than calling those functions directly: they are file-static in start_agent.c
 * (legacy handshake code, out of this module's scope), and strict-required-field
 * parsing is genuinely what the "limits" sub-object needs (unlike cluster/groups
 * below). Field names/nesting confirmed against the manager's own contract and
 * the https_client module's own demo mock
 * manager (https_client/demo/mock_manager.py): {"limits":{"fim":{...},
 * "syscollector":{...},"sca":{...}},"cluster":{"name":...,"node":...},
 * "agent":{"groups":[...]}}. */

static bool bridge_get_required_int(const cJSON *parent, const char *name, int *value)
{
    cJSON *field = cJSON_GetObjectItem(parent, name);
    if (!field || !cJSON_IsNumber(field)) {
        return false;
    }
    *value = field->valueint;
    return true;
}

static bool bridge_parse_fim_limits(const cJSON *limits_obj, fim_limits_t *fim)
{
    cJSON *module = cJSON_GetObjectItem(limits_obj, "fim");
    if (!module || !cJSON_IsObject(module)) {
        return false;
    }

    return bridge_get_required_int(module, "file", &fim->file) &&
           bridge_get_required_int(module, "registry_key", &fim->registry_key) &&
           bridge_get_required_int(module, "registry_value", &fim->registry_value);
}

static bool bridge_parse_syscollector_limits(const cJSON *limits_obj, syscollector_limits_t *syscollector)
{
    cJSON *module = cJSON_GetObjectItem(limits_obj, "syscollector");
    if (!module || !cJSON_IsObject(module)) {
        return false;
    }

    return bridge_get_required_int(module, "hotfixes", &syscollector->hotfixes) &&
           bridge_get_required_int(module, "packages", &syscollector->packages) &&
           bridge_get_required_int(module, "processes", &syscollector->processes) &&
           bridge_get_required_int(module, "ports", &syscollector->ports) &&
           bridge_get_required_int(module, "network_iface", &syscollector->network_iface) &&
           bridge_get_required_int(module, "network_protocol", &syscollector->network_protocol) &&
           bridge_get_required_int(module, "network_address", &syscollector->network_address) &&
           bridge_get_required_int(module, "hardware", &syscollector->hardware) &&
           bridge_get_required_int(module, "os_info", &syscollector->os_info) &&
           bridge_get_required_int(module, "users", &syscollector->users) &&
           bridge_get_required_int(module, "groups", &syscollector->groups) &&
           bridge_get_required_int(module, "services", &syscollector->services) &&
           bridge_get_required_int(module, "browser_extensions", &syscollector->browser_extensions);
}

static bool bridge_parse_sca_limits(const cJSON *limits_obj, sca_limits_t *sca)
{
    cJSON *module = cJSON_GetObjectItem(limits_obj, "sca");
    if (!module || !cJSON_IsObject(module)) {
        return false;
    }

    return bridge_get_required_int(module, "checks", &sca->checks);
}

static bool bridge_parse_limits(const cJSON *root, module_limits_t *limits)
{
    cJSON *limits_obj = cJSON_GetObjectItem(root, "limits");
    if (!limits_obj || !cJSON_IsObject(limits_obj)) {
        return false;
    }

    if (!bridge_parse_fim_limits(limits_obj, &limits->fim) ||
        !bridge_parse_syscollector_limits(limits_obj, &limits->syscollector) ||
        !bridge_parse_sca_limits(limits_obj, &limits->sca)) {
        return false;
    }

    limits->limits_received = true;
    return true;
}

/* Cluster-name authority: the HTTPS contract nests it under "cluster":{"name"},
 * and explicitly wants an unconditional overwrite, even to empty/unknown, so a
 * manager that stops reporting identity doesn't leave a stale value behind.
 * Mirrors ControlStream::applyClusterIdentity() (the module's own internal,
 * HTTPS-side copy of this same rule) so the C side's global (which
 * agent-info/agcom and the shutdown message already read) agrees with what
 * the module itself believes. */
static void bridge_apply_cluster_identity(const cJSON *root)
{
    const cJSON *cluster = cJSON_GetObjectItem(root, "cluster");
    const char *name = NULL;

    if (cluster && cJSON_IsObject(cluster)) {
        cJSON *name_field = cJSON_GetObjectItem(cluster, "name");

        if (name_field && cJSON_IsString(name_field) && name_field->valuestring) {
            name = name_field->valuestring;
        }
    }

    snprintf(agent_cluster_name, sizeof(agent_cluster_name), "%s", name ? name : "");
    mdebug1("https_client: cluster identity -> name='%s'.", agent_cluster_name);
}

/* agent_groups: HTTPS nests the array under "agent":{"groups":[...]} (see
 * ControlStream's groupsCsv(), which reads the same object for /download's
 * resource_id) rather than start_agent.c's flat "agent_groups" array.
 * Builds the same CSV shape agent_agent_groups already holds for legacy. */
static void bridge_apply_agent_groups(const cJSON *root)
{
    const cJSON *agent = cJSON_GetObjectItem(root, "agent");
    const cJSON *groups_array = agent ? cJSON_GetObjectItem(agent, "groups") : NULL;
    cJSON *group_item = NULL;
    size_t offset = 0;

    agent_agent_groups[0] = '\0';

    if (!groups_array || !cJSON_IsArray(groups_array)) {
        return;
    }

    cJSON_ArrayForEach(group_item, groups_array) {
        if (cJSON_IsString(group_item) && group_item->valuestring && group_item->valuestring[0] != '\0') {
            size_t group_len = strlen(group_item->valuestring);
            /* Space check: group + comma + null terminator. */
            if (offset + group_len + 2 < sizeof(agent_agent_groups)) {
                if (offset > 0) {
                    agent_agent_groups[offset++] = ',';
                }
                strcpy(agent_agent_groups + offset, group_item->valuestring);
                offset += group_len;
            }
        }
    }
    agent_agent_groups[offset] = '\0';

    if (agent_agent_groups[0]) {
        mdebug1("https_client: agent groups -> %s.", agent_agent_groups);
    }
}

/* Received-work callbacks: real routing for the four /control
 * task_types (active_response/agent_restart/agent_reload/remote_upgrade),
 * durable dedup via agent-info (task_registry_client.c), and the
 * remote_upgrade download/verify/install seam. */
static void bridge_on_startup_result(bool accepted, const char *metadata_json, void *user_data)
{
    (void)user_data;
    mdebug1("https_client startup %s: %s", accepted ? "accepted" : "rejected",
            metadata_json ? metadata_json : "(no metadata)");

    if (!accepted || !metadata_json) {
        return;
    }

    cJSON *root = cJSON_Parse(metadata_json);
    if (!root) {
        mdebug2("https_client: startup metadata is not valid JSON; module limits and "
                "cluster identity are unchanged.");
        return;
    }

    /* Apply module limits into the existing exposure paths
     * (agent_module_limits, read by FIM/syscollector/SCA the same way the
     * legacy handshake feeds them) and reload under <auto_restart> only when
     * the limits actually changed -- mirrors start_agent.c's
     * agent_handshake_to_server() (previous_limits snapshot + module_limits_changed()),
     * not an unconditional reload on every accepted startup. */
    module_limits_t previous_limits = agent_module_limits;

    if (bridge_parse_limits(root, &agent_module_limits)) {
        mdebug1("https_client: module limits received from manager.");

        if (previous_limits.limits_received && module_limits_changed(&previous_limits, &agent_module_limits)) {
            if (agt->flags.auto_restart) {
                minfo("Agent is reloading due to module limits changes.");
                reloadAgent();
            } else {
                mdebug1("Module limits have been updated.");
            }
        }
    } else {
        mdebug2("https_client: no valid 'limits' object in the startup response; "
                "module limits are unchanged.");
    }

    /* agent_handshake_mutex guards these globals against the agcom "gethandshake"
     * responder, which agent-info polls periodically. The legacy connection thread
     * used to be the writer and took this lock; the control thread is now, so it
     * takes it too. Held across both calls so a reader never sees a new cluster
     * identity paired with the previous groups. */
    w_mutex_lock(&agent_handshake_mutex);
    bridge_apply_cluster_identity(root);
    bridge_apply_agent_groups(root);
    w_mutex_unlock(&agent_handshake_mutex);

    /* The cluster/groups the two calls above just wrote are what the metadata
     * carries; the legacy handshake republished it at exactly this point. */
    w_agentd_populate_metadata();

    cJSON_Delete(root);
}

static void bridge_on_reenroll_required(void *user_data)
{
    (void)user_data;
    mwarn("https_client: credential rejected (401); re-enrolling.");

    if (!agt->enrollment_cfg || !agt->enrollment_cfg->enabled) {
        merror("https_client: re-enrollment required but auto-enrollment is disabled "
               "(<enrollment><enabled>); traffic stays paused until the key is fixed manually.");
        return;
    }

#ifdef WIN32
    w_create_thread(NULL, 0, bridge_reenroll_thread_win, g_https_client, 0, NULL);
#else
    w_create_thread(bridge_reenroll_thread, g_https_client);
#endif
}

/* Maps the module's connection FSM onto the .state file's coarser 3-value
 * status (agent_state_t / w_agentd_state_get, client-agent/include/state.h):
 * the legacy path only ever sets ACTIVE/NACTIVE (PENDING is just its initial
 * value), so REGISTERED is the only "connected" state; everything else --
 * not started yet, rejected, or paused on a bad credential -- reads as
 * disconnected. STARTING is PENDING (in progress, not yet confirmed) to
 * match the .state semantics rather than prematurely reading NACTIVE. */
static agent_status_t bridge_map_agent_status(int hc_state)
{
    switch (hc_state) {
    case HC_STATE_REGISTERED:
        return GA_STATUS_ACTIVE;
    case HC_STATE_STARTING:
        return GA_STATUS_PENDING;
    case HC_STATE_STOPPED:
    case HC_STATE_REJECTED:
    case HC_STATE_AUTH_ERROR:
    default:
        return GA_STATUS_NACTIVE;
    }
}

/* Synchronous ITaskIdStore backing: fires on the CONTROL thread
 * (collectFreshTasks, controlStream.cpp), once per fresh task_id, BEFORE
 * batch planning/dispatch. The round trip to agent-info (task_registry_
 * client.c: a local socket hop to wazuh-modulesd on Linux/macOS, in-process
 * on Windows) is bounded (a few seconds at most) and judged an acceptable,
 * brief delay to the next Notify -- unlike task EXECUTION, which always
 * happens off this thread (inline for the fast AR-forward case, or a
 * dedicated worker thread for restart/reload/remote_upgrade, all below).
 * Fails closed both for a genuine duplicate and a registry error (do not
 * dispatch either way), but counts them separately -- a real registry failure
 * must never be miscounted as a duplicate. */
static int bridge_check_and_record_task(const char *task_id, void *user_data)
{
    (void)user_data;

    if (!task_id) {
        return -1;
    }

    switch (task_registry_check_and_record(task_id)) {
    case TASK_REGISTRY_RESULT_NEW:
        return 1;
    case TASK_REGISTRY_RESULT_DUPLICATE:
        w_agentd_state_update(INCREMENT_TASK_DISCARDED_DUPLICATE, NULL);
        return 0;
    case TASK_REGISTRY_RESULT_ERROR:
    default:
        w_agentd_state_update(INCREMENT_TASK_FAILED, NULL);
        return 0;
    }
}

/* Synchronous IVdOffsetStore backing (hc_vd_offset_observe_fn): fires on the
 * CONTROL thread (ControlStream::handleNotifyBody), once per accepted Notify
 * that carries a vd_feed_offset field. Same bounded-IPC-hop rationale as
 * bridge_check_and_record_task above. */
static void bridge_vd_offset_observe(uint64_t offset, int *out_changed, int *out_pending,
                                     uint64_t *out_pending_offset, void *user_data)
{
    (void)user_data;

    bool changed = false;
    bool pending = false;
    uint64_t pending_offset = 0;

    /* vd_offset_client_observe() already zero-initializes these on any error
     * path, so a failed round trip safely reports "no change, nothing
     * pending" rather than inventing a re-scan request. */
    vd_offset_client_observe(offset, &changed, &pending, &pending_offset);

    if (out_changed) {
        *out_changed = changed ? 1 : 0;
    }
    if (out_pending) {
        *out_pending = pending ? 1 : 0;
    }
    if (out_pending_offset) {
        *out_pending_offset = pending_offset;
    }
}

/* Synchronous IVdOffsetStore backing (hc_vd_offset_clear_pending_fn): called
 * only after a /scan/vd request succeeds (200 OK) -- see RescanRequester. */
static int bridge_vd_offset_clear_pending(uint64_t offset, void *user_data)
{
    (void)user_data;
    return vd_offset_client_clear_pending(offset) ? 1 : 0;
}

/* active_response: forwards the task's AR document to execd over agt->
 * execdq, mirroring the legacy path (receiver.c:~102-115) that strips the
 * EXECD_HEADER prefix and hands the remainder straight to execd -- except
 * here there is no legacy header to strip, since the task payload IS the AR
 * document. execd's ExecdRun() (os_execd/src/execd.c) parses plain JSON off
 * that queue, reading wazuh.active_response.{executable,type,
 * stateful_timeout}. The manager's own contract confirms the task payload is
 * always already the complete
 * AR document, wrapped as {"wazuh":{"active_response":{...},"agent":{...}},
 * "rule":{...},"data":{...}} -- there is no flat/unwrapped variant in the
 * real contract. So this forwards the whole parsed JSON to execd unchanged
 * (not just wazuh.active_response: execd may use sibling fields, and the
 * payload is explicitly "the complete AR document"); a payload missing
 * "wazuh" at the top level means the task is genuinely malformed, not an
 * alternate valid shape to repair. */
static void bridge_dispatch_active_response(const char *task_id, const char *payload_json)
{
    cJSON *payload = cJSON_Parse(payload_json ? payload_json : "");

    if (!payload || !cJSON_HasObjectItem(payload, "wazuh")) {
        merror("https_client: active_response task %s has a malformed payload; dropping.", task_id);
        w_agentd_state_update(INCREMENT_TASK_FAILED, NULL);
        cJSON_Delete(payload); /* No-op if NULL (parse failure). */
        return;
    }

    char *msg_str = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);

    if (!msg_str) {
        merror("https_client: active_response task %s could not be serialized; dropping.", task_id);
        w_agentd_state_update(INCREMENT_TASK_FAILED, NULL);
        return;
    }

    bool sent = false;

    if (agt->execdq >= 0) {
#ifndef WIN32
        if (OS_SendUnix(agt->execdq, msg_str, 0) < 0) {
            mdebug1("https_client: active_response task %s: error communicating with execd.", task_id);
        } else {
            sent = true;
        }
#else
        queue_push_ex(winexec_queue, strdup(msg_str));
        sent = true;
#endif
    } else {
        mdebug1("https_client: active_response task %s dropped: execd queue not available.", task_id);
    }

    os_free(msg_str);
    w_agentd_state_update(sent ? INCREMENT_TASK_DISPATCHED : INCREMENT_TASK_FAILED, NULL);
}

/* agent_restart/agent_reload: both drive wm_control's already-symmetric
 * "restart"/"reload" dispatch (src/wazuh_modules/src/wm_control.c) via
 * restartAgent()/reloadAgent() (src/client-agent/src/reload_agent.c). Their
 * POSIX path can retry the control-socket connect for up to ~30s (modulesd
 * not up yet), which must not stall the dispatcher thread (the module's
 * callback contract) or every other queued callback behind it -- so this
 * runs on its own short-lived worker thread, the same idiom already used for
 * re-enrollment (bridge_reenroll_thread). */
struct bridge_control_task_ctx {
    char *task_id;
    bool restart; /* true: agent_restart: false: agent_reload. */
};

/* Not static: unit-tested by calling it directly (synchronously), bypassing
 * w_create_thread, same convention as bridge_reenroll_thread above. */
void *bridge_control_task_thread(void *arg)
{
    struct bridge_control_task_ctx *ctx = (struct bridge_control_task_ctx *)arg;
    const char *type_name = ctx->restart ? "agent_restart" : "agent_reload";
    bool ok = ctx->restart ? restartAgent() : reloadAgent();

    if (ok) {
        minfo("https_client: task %s (%s) dispatched.", ctx->task_id, type_name);
        w_agentd_state_update(INCREMENT_TASK_DISPATCHED, NULL);
    } else {
        merror("https_client: task %s (%s) failed to dispatch.", ctx->task_id, type_name);
        w_agentd_state_update(INCREMENT_TASK_FAILED, NULL);
    }

    os_free(ctx->task_id);
    os_free(ctx);
    return NULL;
}

#ifdef WIN32
static DWORD WINAPI bridge_control_task_thread_win(LPVOID arg)
{
    bridge_control_task_thread(arg);
    return 0;
}
#endif

static void bridge_dispatch_control_task(const char *task_id, bool restart)
{
    struct bridge_control_task_ctx *ctx;
    os_malloc(sizeof(*ctx), ctx);
    os_strdup(task_id ? task_id : "", ctx->task_id);
    ctx->restart = restart;

#ifdef WIN32
    w_create_thread(NULL, 0, bridge_control_task_thread_win, ctx, 0, NULL);
#else
    w_create_thread(bridge_control_task_thread, ctx);
#endif
}

static void bridge_on_task(const char *task_id, const char *task_type, const char *payload_json,
                           void *user_data)
{
    (void)user_data;
    mdebug1("https_client task received: id=%s type=%s", task_id ? task_id : "?",
            task_type ? task_type : "?");

    if (!task_id || !task_type) {
        merror("https_client: task missing id/type; dropping.");
        w_agentd_state_update(INCREMENT_TASK_FAILED, NULL);
        return;
    }

    if (strcmp(task_type, "active_response") == 0) {
        bridge_dispatch_active_response(task_id, payload_json);
    } else if (strcmp(task_type, "agent_restart") == 0) {
        bridge_dispatch_control_task(task_id, true);
    } else if (strcmp(task_type, "agent_reload") == 0) {
        bridge_dispatch_control_task(task_id, false);
    } else {
        /* remote_upgrade is routed through on_remote_upgrade_ready instead
         * (it needs the module's own HTTP/download machinery, so ControlStream
         * intercepts it before this callback ever fires -- see controlStream.
         * cpp's dispatchPlannedTasks). Reaching this branch for "remote_upgrade"
         * would mean that interception broke; treat any other value as an
         * unknown/unsupported type either way. */
        merror("https_client: task %s has an unknown/unsupported task_type '%s'; dropping.",
               task_id, task_type);
        w_agentd_state_update(INCREMENT_TASK_FAILED, NULL);
    }
}

/* A task's durable record already happened, but ControlStream determined it will never
 * reach bridge_on_task()/bridge_on_remote_upgrade_ready() -- malformed payload, or (remote_
 * upgrade only) a WPK download/sha1 failure. Without this callback that category would go
 * uncounted, neither dispatched nor failed. */
static void bridge_on_task_failed(const char *task_id, const char *task_type, const char *reason,
                                  void *user_data)
{
    (void)user_data;
    merror("https_client: task %s (%s) failed before dispatch: %s",
           task_id ? task_id : "?", task_type ? task_type : "?", reason ? reason : "?");
    w_agentd_state_update(INCREMENT_TASK_FAILED, NULL);
}

/* remote_upgrade: the WPK is already downloaded and sha1-verified
 * by the time this fires (ControlStream::dispatchUpgradeTask); the task_id
 * is already durably recorded (bridge_check_and_record_task, before this
 * ever fires), which is what makes running the installer here idempotent
 * across the restart it triggers -- a post-restart re-delivery of the same
 * task_id is discarded upstream and never reaches this callback again.
 *
 * wpk_path is a module-owned temp file valid ONLY until this callback
 * returns (same convention as on_config_downloaded), so the file is staged
 * into INCOMING_DIR synchronously, here, before anything is deferred; only
 * the (potentially slow, installer-running) dispatch to the upgrade module
 * moves to a worker thread. */
struct bridge_upgrade_ctx {
    char *task_id;
    char *wpk_file;
    char *installer;
};

/* POSIX-only, confirmed via an actual winagent cross-compile (MinGW), not just by inspection:
 * os_execd's wcom_main() -- the COM_LOCAL_SOCK listener that dispatches "lock_restart" to
 * lock_restart(), os_execd/src/wcom.c:335-412 -- is itself wrapped in #ifndef WIN32, and is
 * absent (no such symbol at all) from the winagent build's libexecd_lib.a, so there is nothing
 * on Windows listening on COM_LOCAL_SOCK to receive this request in the first place. This
 * predates this PR: the legacy manager-driven "%.3d com lock_restart -1" request was always the
 * same OS-agnostic string regardless of agent platform, but Windows agents never had a receiver
 * for it -- so not adding a Windows path here is continuity of a pre-existing gap, not a new
 * regression. (lock_restart() itself and the pending_upg it sets, os_execd/src/wcom.c:427-429,
 * do compile cross-platform, but as of this writing nothing in the codebase reads pending_upg on
 * *any* platform: wcom_restart()/wcom_reload(), the only callers that used to check it, were
 * removed by 7217e26d24 ("Remove restart and reload command handling from wcom"). The lock is
 * currently a write-only no-op everywhere, not only on Windows -- a pre-existing dead-code
 * observation, out of scope to fix here.) */
#ifndef WIN32
/* remote_upgrade: replicates the legacy manager's first step of the old multi-step
 * upgrade protocol -- "%.3d com lock_restart -1" (wm_agent_upgrade_send_lock_restart(),
 * wm_agent_upgrade_upgrades.c, manager-side; kept only as a style/error-handling reference, not
 * touched here) -- sent to os_execd's local socket (COM_LOCAL_SOCK) before any WPK work starts,
 * so wcom_dispatch()'s "lock_restart" branch (os_execd/src/wcom.c:65) calls lock_restart(-1) and
 * blocks the agent's own auto-restart mechanism for the configured max duration while the
 * installer runs. Nothing in the new HTTPS remote_upgrade path called this before, which is a
 * real behavioral gap against the legacy flow; this restores it.
 *
 * A failed connect/send only logs a warning and the upgrade proceeds anyway: this lock is
 * best-effort (the old protocol's own manager-side sender treated it the same way -- see
 * wm_agent_upgrade_send_lock_restart()'s own error handling), so it must not abort the upgrade
 * itself. Single attempt, no retry loop: unlike reloadAgent()/restartAgent() at start-up (which
 * retry because modulesd may not be up yet), execd is already running by the time an upgrade
 * task reaches this thread, and a stuck retry loop here would only delay the installer for no
 * benefit. */
static void bridge_send_lock_restart(const char *task_id)
{
    int sock = OS_ConnectUnixDomain(COM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);

    if (sock < 0) {
        mwarn("https_client: remote_upgrade task %s: could not connect to '%s' to lock the "
              "agent's auto-restart: %s (%d). Proceeding without it.",
              task_id, COM_LOCAL_SOCK, strerror(errno), errno);
        return;
    }

    const char *lock_command = "lock_restart -1";

    if (OS_SendSecureTCP(sock, strlen(lock_command), lock_command) < 0) {
        mwarn("https_client: remote_upgrade task %s: could not send lock_restart to '%s': %s "
              "(%d). Proceeding without it.",
              task_id, COM_LOCAL_SOCK, strerror(errno), errno);
    }

    close(sock);
}
#endif

/* Not static: unit-tested by calling it directly (synchronously), bypassing
 * w_create_thread, same convention as bridge_reenroll_thread above. */
void *bridge_upgrade_thread(void *arg)
{
    struct bridge_upgrade_ctx *ctx = (struct bridge_upgrade_ctx *)arg;
    bool ok = false;

#ifndef WIN32
    bridge_send_lock_restart(ctx->task_id);
#endif

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "file", ctx->wpk_file);
    cJSON_AddStringToObject(parameters, "installer", ctx->installer);
    cJSON *command = cJSON_CreateObject();
    cJSON_AddStringToObject(command, "command", "upgrade");
    cJSON_AddItemToObject(command, "parameters", parameters);
    char *command_str = cJSON_PrintUnformatted(command);
    cJSON_Delete(command);

    if (!command_str) {
        merror("https_client: remote_upgrade task %s: could not build the upgrade command.", ctx->task_id);
        goto done;
    }

    char *output = NULL;

#ifndef WIN32
    int sock = OS_ConnectUnixDomain(AGENT_UPGRADE_SOCK, SOCK_STREAM, OS_MAXSTR);

    if (sock < 0) {
        merror("https_client: remote_upgrade task %s: could not connect to '%s': %s (%d).",
               ctx->task_id, AGENT_UPGRADE_SOCK, strerror(errno), errno);
        os_free(command_str);
        goto done;
    }

    if (OS_SendSecureTCP(sock, strlen(command_str), command_str) < 0) {
        merror("https_client: remote_upgrade task %s: OS_SendSecureTCP failed: %s (%d).",
               ctx->task_id, strerror(errno), errno);
        close(sock);
        os_free(command_str);
        goto done;
    }

    char response[OS_MAXSTR + 1] = {0};
    /* No recv timeout set on purpose: this runs on its own thread (not the
     * dispatcher), and the installer itself can legitimately take a while
     * (up to execd.request_timeout, default cap 3600s) before wm_agent_
     * upgrade_com_upgrade() replies -- unlike the dedup IPC hop, blocking
     * here has no fan-out cost on other callbacks. */
    ssize_t recv_len = OS_RecvSecureTCP(sock, response, OS_MAXSTR);
    close(sock);

    if (recv_len > 0) {
        response[recv_len < OS_MAXSTR ? recv_len : OS_MAXSTR] = '\0';
        os_strdup(response, output);
    }

#else
    wm_agent_upgrade_process_command(command_str, &output);
#endif

    os_free(command_str);

    if (!output) {
        merror("https_client: remote_upgrade task %s: no response from the upgrade module.", ctx->task_id);
        goto done;
    }

    cJSON *ack = cJSON_Parse(output);
    int error_code = -1;

    if (ack) {
        cJSON *error_item = cJSON_GetObjectItem(ack, "error");

        if (error_item && cJSON_IsNumber(error_item)) {
            error_code = error_item->valueint;
        }

        cJSON_Delete(ack);
    }

    if (error_code == 0) {
        minfo("https_client: remote_upgrade task %s dispatched to the upgrade module (installer "
              "running; the agent may restart shortly). No /control response is sent.", ctx->task_id);
        ok = true;
    } else {
        merror("https_client: remote_upgrade task %s: upgrade module rejected the command: %s",
               ctx->task_id, output);
    }

    os_free(output);

done:
    w_agentd_state_update(ok ? INCREMENT_TASK_DISPATCHED : INCREMENT_TASK_FAILED, NULL);
    os_free(ctx->task_id);
    os_free(ctx->wpk_file);
    os_free(ctx->installer);
    os_free(ctx);
    return NULL;
}

#ifdef WIN32
static DWORD WINAPI bridge_upgrade_thread_win(LPVOID arg)
{
    bridge_upgrade_thread(arg);
    return 0;
}
#endif

static void bridge_on_remote_upgrade_ready(const char *task_id, const char *wpk_file,
                                           const char *wpk_path, const char *installer,
                                           void *user_data)
{
    (void)user_data;

    if (!task_id || !wpk_file || !wpk_path || !installer) {
        merror("https_client: remote_upgrade callback missing required fields; aborting.");
        w_agentd_state_update(INCREMENT_TASK_FAILED, NULL);
        return;
    }

    if (w_ref_parent_folder(wpk_file)) {
        merror("https_client: remote_upgrade task %s: wpk_file '%s' is not a safe filename; aborting.",
               task_id, wpk_file);
        w_agentd_state_update(INCREMENT_TASK_FAILED, NULL);
        return;
    }

    char dest_path[PATH_MAX + 1];
#ifndef WIN32
    snprintf(dest_path, sizeof(dest_path), "%s/%s", INCOMING_DIR, wpk_file);
#else
    snprintf(dest_path, sizeof(dest_path), "%s\\%s", INCOMING_DIR, wpk_file);
#endif

    if (w_copy_file(wpk_path, dest_path, 'b', NULL, 0) < 0) {
        merror("https_client: remote_upgrade task %s: could not stage the WPK at '%s'; aborting.",
               task_id, dest_path);
        w_agentd_state_update(INCREMENT_TASK_FAILED, NULL);
        return;
    }

    struct bridge_upgrade_ctx *ctx;
    os_malloc(sizeof(*ctx), ctx);
    os_strdup(task_id, ctx->task_id);
    os_strdup(wpk_file, ctx->wpk_file);
    os_strdup(installer, ctx->installer);

#ifdef WIN32
    w_create_thread(NULL, 0, bridge_upgrade_thread_win, ctx, 0, NULL);
#else
    w_create_thread(bridge_upgrade_thread, ctx);
#endif
}

/* The startup hash gate (client-agent/src/startup_gate.c) holds syscheckd and
 * the other modules until the manager-validated configuration is in place.
 * Fired on every accepted Notify (whether or not it triggers a download), so
 * an agent that boots already in sync with the manager -- no download, no
 * reload, nothing else to hook a release off -- still releases the gate via
 * a direct SHA-256 comparison against the local merged.mg
 * (startup_gate_check_manager_config_hash(), which owns the real digest math;
 * this callback only forwards). */
static void bridge_on_manager_config_hash(const char *config_hash, void *user_data)
{
    (void)user_data;

    /* An accepted Notify is the agent's keepalive: it is the same event the
     * manager records as one. Taken here rather than at send time (where the
     * legacy notify.c put it, right after send_msg(), so it advanced even with
     * the network down) so the value proves a completed round trip. */
    time_t now = time(NULL);
    w_agentd_state_update(UPDATE_KEEPALIVE, &now);

    startup_gate_check_manager_config_hash(config_hash);
}

/* Notify-driven groups refresh: a group-only change never re-triggers a Startup
 * (settings_hash deliberately excludes groups; config_hash covers the group's own
 * config content, not the manager-side membership list), so without this
 * agent_agent_groups -- and everything that reads it: agcom_gethandshake(), the
 * metadata this republishes -- would go stale forever after the first Startup.
 * Unlike bridge_apply_agent_groups() (Startup-only, walks a cJSON array), this
 * takes the plain CSV the module already built (ControlStream's rawGroupsCsv())
 * -- the RAW value, not /download's "default"-substituted one: empty is
 * meaningful here (see agcom.c's own comment on an empty agent_groups falling
 * back to merged.mg) and must be preserved as empty, not turned into "default".
 * Compares before writing so an unchanged report (the module already dedupes,
 * this is defense in depth) doesn't pay for a metadata republish. */
static void bridge_on_agent_groups(const char *groups_csv, void *user_data)
{
    (void)user_data;

    if (!groups_csv) {
        return;
    }

    bool changed = false;

    w_mutex_lock(&agent_handshake_mutex);
    if (strcmp(agent_agent_groups, groups_csv) != 0) {
        snprintf(agent_agent_groups, sizeof(agent_agent_groups), "%s", groups_csv);
        changed = true;
    }
    w_mutex_unlock(&agent_handshake_mutex);

    if (changed) {
        mdebug1("https_client: agent groups -> %s.", agent_agent_groups[0] ? agent_agent_groups : "(none)");
        w_agentd_populate_metadata();
    }
}

/* Applies a downloaded merged configuration and releases the startup gate.
 *
 * file_path is a module-owned temp file valid ONLY until the callback that
 * received it returns (the module deletes it right after) -- so the very
 * first thing this does is copy it into SHAREDCFG_FILE.
 *
 * The apply chain is UnmergeFiles -> cldir_ex_ignore -> verifyRemoteConf ->
 * reloadAgent, and whether that last step runs depends on two things: a
 * blocked startup gate (modules are waiting for this very configuration to
 * start, so they must be started with it) and <auto_restart> (which governs
 * picking up a configuration change on an agent already running).
 *
 * Anti-race sequencing between reloadAgent() and the gate release: when
 * reloadAgent() dispatches, the gate is deliberately NOT released here --
 * releasing it unconditionally could let a module still blocked in
 * startup_gate_wait_for_ready() unblock and start a moment before the reload
 * chain (modulesd CONTROL_SOCK -> wazuh-control reload -> SIGUSR1) restarts
 * it anyway. client-agent/src/agentd.c's own SIGUSR1 handling
 * (needs_config_reload) calls startup_gate_release_from_https_apply()
 * once that restart has actually happened.
 *
 * When reloadAgent() cannot even dispatch (control socket unreachable) no
 * SIGUSR1 will ever arrive, and the /control contract has no handshake retry
 * to lean on, so the gate is released inline instead -- see
 * startup_gate_release_from_https_apply()'s own comment for why that is safe.
 */
static void bridge_on_config_downloaded(const char *config_hash, const char *file_path,
                                        void *user_data)
{
    (void)user_data;

    /* Callback-safe per https_client.h's own doc; read without the lock like
     * bridge_on_reenroll_required's w_create_thread(..., g_https_client, ...)
     * already does -- a callback cannot be running concurrently with the
     * hc_destroy() that would invalidate this pointer. */
    hc_handle *handle = g_https_client;

    mdebug1("https_client config downloaded (hash=%s, file=%s)",
            config_hash ? config_hash : "?", file_path ? file_path : "?");

    if (!file_path || !file_path[0]) {
        merror("https_client: config downloaded callback fired without a file path; nothing to apply.");
        return;
    }

    /* Binary mode ('b'): the module already SHA-256-verified these exact
     * bytes against the manager's config_hash before this callback fired
     * (configFetcher.cpp). A text-mode copy on Windows would silently
     * rewrite '\n' as '\r\n', corrupting the file relative to what the hash
     * was computed over -- the SHA-256 recomputed from SHAREDCFG_FILE on the
     * next fresh instance (bridge_build_config()) would then never match the
     * manager's hash, forcing an endless re-download/reload loop (observed
     * as a real, Windows-only regression during real-package validation). */
    if (w_copy_file(file_path, SHAREDCFG_FILE, 'b', NULL, 0) != 0) {
        merror("Could not copy the downloaded configuration into '%s'; "
               "keeping the previously applied one.", SHAREDCFG_FILE);
        if (handle) {
            /* What's actually on disk is still the old config, not config_hash:
             * correct the module's optimistic view so the next Notify mismatch
             * re-triggers the download instead of assuming we are in sync. */
            hc_set_config_hash(handle, "");
        }
        return;
    }

    /* SHAREDCFG_FILE now holds these exact bytes, so its SHA-256 already matches
     * the manager's config_hash -- startup_gate_check_manager_config_hash() (fired
     * independently on every accepted Notify) would otherwise race ahead and
     * release the gate with reason=https_hash_match before the reload this
     * function is about to (maybe) dispatch actually completes. Mark the download
     * pending now, before any of that can happen; only startup_gate_release_from_https_apply()
     * (below, or via reloadAgent()'s own completion) clears it. */
    startup_gate_mark_download_pending();

    char **ignore_list;
    os_calloc(2, sizeof(char *), ignore_list);
    os_strdup(SHAREDCFG_FILENAME, *ignore_list);

    if (!UnmergeFiles(SHAREDCFG_FILE, SHAREDCFG_DIR, OS_TEXT, &ignore_list)) {
        merror("Failed to unmerge the downloaded configuration "
               "('%s'); keeping the previously applied files.", SHAREDCFG_FILE);
        /* Manager-visible report, now over /stateless. */
        char unmerge_fail_msg[OS_MAXSTR];
        snprintf(unmerge_fail_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", AG_IN_UNMERGE);
        w_https_client_submit_event(unmerge_fail_msg, strlen(unmerge_fail_msg));
        free_strarray(ignore_list);
        if (handle) {
            hc_set_config_hash(handle, "");
        }
        return;
    }

    if (cldir_ex_ignore(SHAREDCFG_DIR, (const char **)ignore_list)) {
        mwarn("Could not clean up the shared configuration directory.");
    }
    free_strarray(ignore_list);

    if (!agt->flags.remote_conf) {
        /* The files are staged either way, but nothing reloads or gates on
         * remote configuration when the agent has opted out of it. */
        return;
    }

    if (verifyRemoteConf()) {
        /* Invalid remote configuration: verifyRemoteConf() already reported it
         * to the manager (AG_IN_RCON). Do not reload or release the gate with
         * a configuration known to be broken. */
        merror("Downloaded configuration failed validation; not reloading.");
        return;
    }

    mdebug1("Applying configuration downloaded over HTTPS (hash=%s).",
            config_hash ? config_hash : "?");

    /* A blocked gate means modules are still waiting in
     * startup_gate_wait_for_ready() for the configuration that just arrived:
     * they have to be started with it, so that reload runs whatever
     * <auto_restart> says. The gate's precondition holds by construction here:
     * the module SHA-256-verified these bytes against the manager's
     * config_hash before the callback fired, and they are now what
     * SHAREDCFG_FILE holds.
     *
     * With the gate already open the reload only serves to pick up a changed
     * configuration, which is exactly what <auto_restart> governs: when it is
     * off the files stay staged for whenever the agent restarts next. Say so at
     * INFO -- what is on disk is no longer what the running agent applies, and
     * only an operator can close that gap. */
    const bool gate_was_blocked = !startup_gate_is_ready();

    if (!agt->flags.auto_restart && !gate_was_blocked) {
        minfo("Agent must restart to apply the new shared configuration; auto_restart is disabled.");
        return;
    }

    if (!agt->flags.auto_restart) {
        minfo("Agent is reloading to apply startup hash validated configuration.");
    } else {
        minfo("Agent is reloading due to shared configuration changes.");
    }

    if (!reloadAgent()) {
        mdebug1("Could not dispatch the reload chain; releasing "
                "the startup gate directly instead (no restart will arrive to do it).");
        startup_gate_release_from_https_apply();
    }
}

/* Maps a producing module to the sync header its *com dispatch expects, and to
 * whether it lives behind syscheck's socket or the wmodules one. Same split
 * receiver.c makes for the legacy transport. */
static const struct {
    const char *module;
    const char *header;
    bool syscheck;
} SYNC_ROUTES[] = {
    {"fim",             FIM_SYNC_HEADER,            true},
    {"syscollector",    SYSCOLECTOR_SYNC_HEADER,    false},
    {"syscollector_vd", SYSCOLECTOR_VD_SYNC_HEADER, false},
    {"sca",             SCA_SYNC_HEADER,            false},
    {"agent-info",      AGENT_INFO_SYNC_HEADER,     false},
};

/* Session ids arrive as "<module>-<session>". Split on the LAST hyphen, not the
 * first: "agent-info" contains one of its own, and the session is always
 * decimal, so the last hyphen is unambiguous. */
static const char *bridge_module_of_session(const char *session_id, size_t *module_len)
{
    const char *dash = session_id ? strrchr(session_id, '-') : NULL;

    if (dash == NULL || dash == session_id || dash[1] == '\0') {
        return NULL;
    }

    for (const char *digit = dash + 1; *digit; digit++) {
        if (!isdigit((unsigned char)*digit)) {
            return NULL;
        }
    }

    *module_len = (size_t)(dash - session_id);
    return session_id;
}

static void bridge_on_sync_response(const char *session_id, int result, const char *body,
                                    size_t body_len, void *user_data)
{
    (void)user_data;
    mdebug1("https_client /stateful session=%s result=%d (%zu byte answer)",
            session_id ? session_id : "?", result, body_len);

    size_t module_len = 0;
    const char *module = bridge_module_of_session(session_id, &module_len);

    if (module == NULL) {
        mdebug2("https_client: session id '%s' carries no module to answer; dropping the result.",
                session_id ? session_id : "?");
        return;
    }

    for (size_t i = 0; i < sizeof(SYNC_ROUTES) / sizeof(SYNC_ROUTES[0]); i++) {
        if (strlen(SYNC_ROUTES[i].module) != module_len ||
            strncmp(module, SYNC_ROUTES[i].module, module_len) != 0) {
            continue;
        }

        /* ACK-less flow: route the raw HTTP status code and body with the session's
         * numeric ID so the receiving module can discard stale callbacks (responses
         * for a previous timed-out session that arrives while a newer one is active)
         * and interpret the /stateful contract itself (a 409 means checksum mismatch,
         * a 200 body may carry {"noop":true}, etc - see agent_sync_protocol's HTTP
         * result handling; this bridge does not interpret the body, only carries it).
         * Format: HCRESULT:<session_number>:<result_code>:<body>
         *
         * session_id format is "<module>-<decimal_uint64>" so the numeric part is
         * everything after module_len + 1 (the '-'). The body is copied verbatim
         * after the second colon: the receiving parser only looks for the first two
         * colons, so a JSON body containing its own colons is never misread. */
        const size_t header_len = strlen(SYNC_ROUTES[i].header);
        const char *session_num = module + module_len + 1; /* points to numeric suffix */

        char prefix[64];
        int prefix_len = snprintf(prefix, sizeof(prefix), "HCRESULT:%s:%d:", session_num, result);

        if (prefix_len <= 0 || (size_t)prefix_len >= sizeof(prefix)) {
            mdebug2("https_client: could not encode sync result for session '%s'; dropping it.",
                    session_id ? session_id : "?");
            return;
        }

        const size_t payload_len = (size_t)prefix_len + body_len;
        char *framed = NULL;
        os_malloc(header_len + payload_len + 1, framed);
        memcpy(framed, SYNC_ROUTES[i].header, header_len);
        memcpy(framed + header_len, prefix, (size_t)prefix_len);
        if (body_len > 0) {
            memcpy(framed + header_len + (size_t)prefix_len, body, body_len);
        }
        framed[header_len + payload_len] = '\0';

        if (SYNC_ROUTES[i].syscheck) {
            ag_send_syscheck(framed, header_len + payload_len);
        } else {
            wmcom_send(framed, header_len + payload_len);
        }

        os_free(framed);
        return;
    }

    mdebug2("https_client: no sync route for module '%.*s'; dropping the result.",
            (int)module_len, module);
}

/* Names the module's connection states for the log The numeric
 * value is kept alongside the name by the caller. */
static const char *bridge_str_conn_state(int hc_state)
{
    switch (hc_state) {
    case HC_STATE_STOPPED:
        return "stopped";
    case HC_STATE_STARTING:
        return "starting";
    case HC_STATE_REGISTERED:
        return "registered";
    case HC_STATE_REJECTED:
        return "rejected";
    case HC_STATE_AUTH_ERROR:
        return "auth_error";
    default:
        return "unknown";
    }
}

static void bridge_on_state_change(int state, void *user_data)
{
    (void)user_data;
    mdebug1("https_client connection state -> %s (%d)", bridge_str_conn_state(state), state);
    w_agentd_state_update(UPDATE_STATUS, (void *)bridge_map_agent_status(state));

    /* Clears a producer lock that outlived whatever armed it: a successful
     * registration means the manager just acknowledged us, so anything still on
     * disk is stale. That covers the boot-time arm in AgentdStart() and a lock
     * left behind by an unclean exit -- on_producer_pause below cannot clear
     * the latter, since it only fires on a paused->running transition and each
     * run starts believing it has paused nothing. os_delwait() is idempotent. */
    if (state == HC_STATE_REGISTERED) {
        os_delwait();
    }
}

/* The reporters call these straight through (not via the task dispatcher): they
 * return a value, and the module frees the buffer after copying it. Collecting
 * is a fan-out over the component sockets, so it runs on the reporter's own
 * thread and cannot stall the other endpoints. */

static char *bridge_collect_config(void *user_data)
{
    (void)user_data;
    return w_agent_collect_config();
}

static char *bridge_collect_stats(void *user_data)
{
    (void)user_data;
    return w_agent_collect_stats();
}

static void bridge_on_producer_pause(bool paused, void *user_data)
{
    (void)user_data;

    if (paused) {
        mwarn(SERVER_UNAV);
        os_setwait();
        w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_NACTIVE);
    } else {
        minfo(SERVER_UP);
        os_delwait();
        w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_ACTIVE);
    }
}

/* Occupancy thresholds the module reports against, so the log lines can quote
 * them as buffer.c did. Filled by bridge_build_config(). */
static int g_buffer_warn_level = 90;
static int g_buffer_normal_level = 70;

/* The wazuh-agent.buffer occupancy event (manager flood rules 202-205), moved
 * here from buffer.c. It used to bypass the ring it reported on; the accumulator
 * is the only route out now, so a report can itself be dropped while the
 * accumulator is full -- the mwarn below always reaches the agent log. */
static void bridge_send_buffer_status_event(const char *action, int severity)
{
    char msg[OS_MAXSTR];
    cJSON *event = cJSON_CreateObject();
    cJSON_AddStringToObject(event, "event.module", "wazuh-agent");
    cJSON_AddStringToObject(event, "event.category", "change");
    cJSON_AddStringToObject(event, "event.dataset", "wazuh-agent.buffer");
    cJSON_AddNumberToObject(event, "event.severity", severity);
    cJSON_AddStringToObject(event, "event.action", action);
    char *json_str = cJSON_PrintUnformatted(event);
    cJSON_Delete(event);
    snprintf(msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", json_str);
    os_free(json_str);
    w_https_client_submit_event(msg, strlen(msg));
}

/* Reports the accumulator's occupancy exactly as the legacy leaky bucket
 * reported the ring it replaced (client-agent/src/buffer.c): the same log lines
 * and the same wazuh-agent.buffer state event, so the manager-side flood rules
 * keep firing now that the accumulator is what fills up. */
static void bridge_on_buffer_level(int level, void *user_data)
{
    (void)user_data;

    switch (level) {
    case HC_BUFFER_WARNING:
        mwarn(WARN_BUFFER, g_buffer_warn_level);
        bridge_send_buffer_status_event("warning", 1);
        break;

    case HC_BUFFER_FULL:
        mwarn(FULL_BUFFER);
        bridge_send_buffer_status_event("full", 2);
        break;

    case HC_BUFFER_FLOOD:
        mwarn(FLOODED_BUFFER);
        bridge_send_buffer_status_event("flooded", 3);
        break;

    case HC_BUFFER_NORMAL:
        mdebug1(NORMAL_BUFFER, g_buffer_normal_level);
        bridge_send_buffer_status_event("normal", 0);
        break;

    default:
        mdebug2("https_client: unknown buffer level %d.", level);
        break;
    }
}

/* Host metadata source for the /control Notify. Pulled fresh each Notify from
 * the shared metadata_provider (hostname/architecture/os.*). Writes an empty
 * string when metadata is not yet available, so the module omits the host
 * block. The agent IP is NOT sourced here: on the HTTPS agent there is no live
 * manager socket (agt->sock is permanently -1), so the module adds host.ip from
 * the actual connection (CURLINFO_LOCAL_IP) instead. Runs on the module's
 * control thread; a shared-memory read, fast and non-blocking. */
static void bridge_on_collect_host(char *json_out, size_t cap, void *user_data)
{
    (void)user_data;

    if (json_out == NULL || cap == 0) {
        return;
    }

    json_out[0] = '\0';

    agent_metadata_t metadata = {0};

    if (metadata_provider_get(&metadata) != 0) {
        mdebug2("https_client: host metadata not available yet; sending Notify without host.");
        return;
    }

    cJSON *host = cJSON_CreateObject();

    if (host == NULL) {
        metadata_provider_free_metadata(&metadata);
        return;
    }

    if (metadata.hostname[0]) {
        cJSON_AddStringToObject(host, "hostname", metadata.hostname);
    }
    if (metadata.architecture[0]) {
        cJSON_AddStringToObject(host, "architecture", metadata.architecture);
    }

    cJSON *os = cJSON_CreateObject();
    if (metadata.os_name[0]) {
        cJSON_AddStringToObject(os, "name", metadata.os_name);
    }
    if (metadata.os_version[0]) {
        cJSON_AddStringToObject(os, "version", metadata.os_version);
    }
    if (metadata.os_platform[0]) {
        cJSON_AddStringToObject(os, "platform", metadata.os_platform);
    }
    if (metadata.os_type[0]) {
        cJSON_AddStringToObject(os, "type", metadata.os_type);
    }
    cJSON_AddItemToObject(host, "os", os);

    char *printed = cJSON_PrintUnformatted(host);
    if (printed) {
        snprintf(json_out, cap, "%s", printed);
        os_free(printed);
    }

    cJSON_Delete(host);
    metadata_provider_free_metadata(&metadata);
}

/* Host metadata source for the /stateless H line. Pulled fresh from the same
 * shared metadata_provider as bridge_on_collect_host() above, but as its own
 * callback (not a reuse) so this endpoint's shape can grow without touching
 * Notify's already-shipped contract.
 *
 * Shape (agent.name/version/groups/host.{architecture,hostname,os.*},
 * cluster.{name}) mirrors EXACTLY what the legacy manager's own
 * append_header() (remoted/src/secure.c) already builds and indexes today --
 * not a new design. The indexer's wazuh.* mapping is strict_allow_templates
 * (unmapped paths are rejected, not ignored), so groups/host/os MUST nest
 * under agent as shown here, not as siblings of it: that shape is what the
 * mapping is actually built for. cluster.name here is the exact same
 * metadata.cluster_name that feeds the Start table's cluster_name
 * on /stateful, so the two transports can never disagree on cluster identity.
 * Writes an empty string when metadata is not yet available, so the module
 * falls back to an H line carrying only agent.id. Runs on the module's
 * stateless sender thread, once per flush (not per event); a shared-memory
 * read, fast and non-blocking. */
static void bridge_on_collect_stateless_host(char *json_out, size_t cap, void *user_data)
{
    (void)user_data;

    if (json_out == NULL || cap == 0) {
        return;
    }

    json_out[0] = '\0';

    agent_metadata_t metadata = {0};

    if (metadata_provider_get(&metadata) != 0) {
        mdebug2("https_client: host metadata not available yet; /stateless H line carries only agent.id.");
        return;
    }

    cJSON *root = cJSON_CreateObject();

    if (root == NULL) {
        metadata_provider_free_metadata(&metadata);
        return;
    }

    cJSON *agent = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "agent", agent);

    if (metadata.agent_name[0]) {
        cJSON_AddStringToObject(agent, "name", metadata.agent_name);
    }
    if (metadata.agent_version[0]) {
        cJSON_AddStringToObject(agent, "version", metadata.agent_version);
    }

    if (metadata.groups_count > 0 && metadata.groups != NULL) {
        cJSON *groups = cJSON_CreateArray();
        for (size_t i = 0; i < metadata.groups_count; i++) {
            if (metadata.groups[i] != NULL) {
                cJSON_AddItemToArray(groups, cJSON_CreateString(metadata.groups[i]));
            }
        }
        cJSON_AddItemToObject(agent, "groups", groups);
    }

    cJSON *host = cJSON_CreateObject();
    cJSON_AddItemToObject(agent, "host", host);

    if (metadata.architecture[0]) {
        cJSON_AddStringToObject(host, "architecture", metadata.architecture);
    }
    if (metadata.hostname[0]) {
        cJSON_AddStringToObject(host, "hostname", metadata.hostname);
    }

    cJSON *os = cJSON_CreateObject();
    if (metadata.os_name[0]) {
        cJSON_AddStringToObject(os, "name", metadata.os_name);
    }
    if (metadata.os_version[0]) {
        cJSON_AddStringToObject(os, "version", metadata.os_version);
    }
    if (metadata.os_platform[0]) {
        cJSON_AddStringToObject(os, "platform", metadata.os_platform);
    }
    if (metadata.os_type[0]) {
        cJSON_AddStringToObject(os, "type", metadata.os_type);
    }
    cJSON_AddItemToObject(host, "os", os);

    cJSON *cluster = cJSON_CreateObject();
    if (metadata.cluster_name[0]) {
        cJSON_AddStringToObject(cluster, "name", metadata.cluster_name);
    }
    cJSON_AddItemToObject(root, "cluster", cluster);

    char *printed = cJSON_PrintUnformatted(root);
    if (printed) {
        snprintf(json_out, cap, "%s", printed);
        os_free(printed);
    }

    cJSON_Delete(root);
    metadata_provider_free_metadata(&metadata);
}

/* Maps the agent config parser's verification_mode enum onto the module
 * ABI's hc_verify_mode_t. The two are defined in independent headers with
 * matching values by convention (both documented "FULL is 0, fails closed");
 * an explicit switch (instead of relying on the numeric coincidence) keeps
 * that convention from silently breaking if either enum is reordered. */
static int bridge_map_verify_mode(int agent_verify_mode)
{
    switch (agent_verify_mode) {
    case AGENT_VERIFY_CERT:
        return HC_VERIFY_CERT;
    case AGENT_VERIFY_NONE:
        return HC_VERIFY_NONE;
    case AGENT_VERIFY_FULL:
    default:
        return HC_VERIFY_FULL;
    }
}

/* The AES-CMAC recipe (settled by the manager's own resolver): decode
 * client.keys' raw_key verbatim as hex, cipher chosen by byte length
 * (16/24/32 bytes = 32/48/64 hex chars). The module's key provider re-derives
 * the same check lazily at signing time (so a bad key never crashes
 * anything), but that means a misconfigured key otherwise fails every
 * request silently forever with no startup error. Validate it here so a
 * broken client.keys is caught once, loudly, at start. */
static bool bridge_key_is_valid(const char *raw_key)
{
    if (!raw_key) {
        return false;
    }

    size_t len = strlen(raw_key);
    if (len != 32 && len != 48 && len != 64) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)raw_key[i])) {
            return false;
        }
    }

    return true;
}

/* Builds the module config from the parsed <server>/<ssl> block (agt->server,
 * agt->ssl; src/config/src/client-config.c) and the already-parsed
 * client.keys entry. Returns false (config left unusable) when the signing
 * key fails validation; the caller must not start the client in that case. */
static bool bridge_build_config(hc_config_t *config)
{
    memset(config, 0, sizeof(*config));

    if (agt->server && agt->server[0].rip) {
        strncpy(config->server_host, agt->server[0].rip, sizeof(config->server_host) - 1);
        config->server_port = (uint16_t)agt->server[0].port;
    }

    const char *raw_key = (keys.keyentries && keys.keyentries[0]) ? keys.keyentries[0]->raw_key : NULL;
    /* The NULL test is redundant with bridge_key_is_valid()'s own, and is here
     * so it is visible at the point of use: the static analyzer does not inline
     * the validator (its hex loop exhausts the inlining budget), so without a
     * local test it explores a path where the key is NULL and reports the
     * strncpy() below, plus the keys.keyentries[0]->id read above it. */
    if (raw_key == NULL || !bridge_key_is_valid(raw_key)) {
        /* keys.keysize == 0 means "never enrolled" (start_agent_prepare()
         * blocks on enrollment before this ever runs, so this should not be
         * reachable in practice -- kept as defense-in-depth against a future
         * ordering regression). A non-zero keysize with an invalid raw_key is
         * a genuinely corrupt client.keys, worth an ERROR. */
        if (keys.keysize == 0) {
            mdebug1("https_client: not enrolled yet (no client.keys); deferring start.");
        } else {
            merror("https_client: agent key is missing or has an invalid length for AES-CMAC "
                   "(expected 32, 48 or 64 hex characters); refusing to start.");
        }
        return false;
    }
    if (keys.keyentries[0]->id) {
        strncpy(config->agent_id, keys.keyentries[0]->id, sizeof(config->agent_id) - 1);
    }
    strncpy(config->agent_key, raw_key, sizeof(config->agent_key) - 1);

    config->verify_mode = bridge_map_verify_mode(agt->ssl.verification_mode);
    if (agt->ssl.certificate_authorities) {
        strncpy(config->ca_path, agt->ssl.certificate_authorities, sizeof(config->ca_path) - 1);
    }
    if (agt->ssl.certificate) {
        strncpy(config->client_cert, agt->ssl.certificate, sizeof(config->client_cert) - 1);
    }
    if (agt->ssl.key) {
        strncpy(config->client_key, agt->ssl.key, sizeof(config->client_key) - 1);
    }
    if (agt->ssl.ciphers) {
        strncpy(config->ciphers, agt->ssl.ciphers, sizeof(config->ciphers) - 1);
    }

    config->notify_interval_s = (uint32_t)agt->notify_time;
    strncpy(config->version, __wazuh_version, sizeof(config->version) - 1);

    /* <client><batch>: the /stateless payload limit and flush window. Left at
     * zero when unset, which the module reads as "use the default" (1 MiB,
     * 10 s). buffer_cap_multiplier has no configuration surface yet, so the
     * accumulator keeps its own 4x default. */
    config->batch_size_bytes = (uint64_t)agt->batch.size;
    config->batch_interval_ms = (uint32_t)(agt->batch.interval * 1000);

    /* <client><stats_report>/<config_report>: the two periodic pushes (#37843),
     * independent of each other. <stats_report> is off unless configured;
     * <config_report> is on by default. Both intervals also default to their
     * effective value (60 s / 3600 s) in ClientConf(), so this copy is never
     * actually zero in practice -- the module's own zero-means-unset fallback
     * (moduleConfig.cpp) stays only as a defensive floor. */
    config->stats_enabled = agt->stats_report.enabled;
    config->stats_interval_s = (uint32_t)agt->stats_report.interval;
    config->config_report_enabled = agt->config_report.enabled;
    config->config_report_interval_s = (uint32_t)agt->config_report.interval;

    /* Occupancy ladder: the same internal options the legacy client buffer
     * read, so tuned thresholds keep working. */
    g_buffer_warn_level = getDefine_Int("agent", "warn_level", 1, 100);
    g_buffer_normal_level = getDefine_Int("agent", "normal_level", 0, g_buffer_warn_level - 1);
    config->buffer_warn_level = (uint32_t)g_buffer_warn_level;
    config->buffer_normal_level = (uint32_t)g_buffer_normal_level;
    config->buffer_flood_tolerance_s = (uint32_t)getDefine_Int("agent", "tolerance", 0, 600);

    /* internal_options.conf toggle, not a <client> XML setting -- request-
     * body compression is an opt-in tuning knob, not user-facing config.
     * getDefine_Int_default (not getDefine_Int) so a missing key defaults to
     * off instead of aborting the agent. */
    config->https_compression_enabled = (bool)getDefine_Int_default("agent", "https_compression_enabled", 0, 1, 0);

    /* Bug found during real-package validation: this used to be
     * getsharedfiles() (client-agent/src/notify.c), which is an MD5 (OS_MD5_File) -- the legacy
     * merged_sum format. config->config_checksum seeds ConfigHashState's initial value
     * (httpsClientFacade.cpp: m_configHash(m_config.configChecksum)), which is compared
     * byte-for-byte against the manager-reported agent.config_hash on every Notify
     * (controlStream.cpp's maybeDownloadConfig()) -- and that value is a SHA-256 ("SHA256 hash
     * of group configuration" per the manager's own contract; confirmed against configFetcher.cpp/digest.hpp,
     * which verify downloads the same way). An MD5 hex string can never equal a SHA-256 hex
     * string, so seeding this from the MD5 guaranteed a mismatch on literally every comparison
     * against this seed, not just the first one -- and while the module's own optimistic
     * ConfigHashState::set() after a successful download corrects this in memory for the
     * lifetime of one https_client instance, this seed is what a FRESH instance starts from
     * every time one is created. On a platform where a config-triggered reload actually restarts
     * the whole agent process (observed as a real, repeated infinite-restart regression on
     * Windows during validation -- Linux's wazuh-control reload explicitly excludes wazuh-agentd
     * from the daemons it restarts, but that exclusion is not guaranteed on every platform/path),
     * every fresh instance reseeds from this same permanently-mismatching MD5 value, so every
     * Notify after every restart looks like "config changed" again, forever, even though the
     * on-disk config never actually changed after the first real download.
     *
     * Fixed by seeding from a SHA-256 of the same file instead, computed the same way the module
     * itself verifies a download (raw bytes, no text-mode newline translation -- OS_BINARY, not
     * OS_TEXT, matching digest.cpp's std::fopen(path, "rb")): once a real download has actually
     * landed the correct bytes on disk, a freshly (re)computed local hash now compares in the
     * SAME hash space the manager uses, so it can actually match and stop forcing a redundant
     * re-download/reload every Notify cycle. A missing/unreadable local merged.mg still seeds an
     * empty checksum (OS_SHA256_File's own failure path; config_checksum was already
     * zero-filled by this function's memset above), which still can never equal a real
     * manager-advertised hash -- preserving the original, correct first-boot behavior (force
     * exactly one bootstrap download when there is nothing meaningful on disk yet). */
    os_sha256 config_sha256;
    if (OS_SHA256_File(SHAREDCFG_FILE, config_sha256, OS_BINARY) == 0) {
        strncpy(config->config_checksum, config_sha256, sizeof(config->config_checksum) - 1);
    }

    /* Stateful sync sessions arrive on a separate STREAM socket so a whole
     * (multi-MB) session bypasses the 64 KB DGRAM event queue; the module
     * streams it to disk and then to /stateful. Stateless events keep using
     * the DGRAM queue. Producers connect via sendSyncSession().
     *
     * Windows has no local socket intake at all (modules run in-process and
     * deliver a session directly via bridge_submit_sync_session() below,
     * registered as agent_sync_protocol's in-process sender) -- leaving this
     * path empty here skips SyncIntake::start() entirely, instead of always
     * attempting and always failing it (SyncIntake's own Windows stub is an
     * intentional no-op, not a real bind failure). */
#ifndef WIN32
    strncpy(config->sync_socket_path, SYNCQUEUE, sizeof(config->sync_socket_path) - 1);
#endif

    return true;
}

#ifdef WIN32
/* In-process /stateful session sender for agent_sync_protocol's Windows stub
 * (SyncSocketTransport has no local socket to connect to there). Registered via
 * asp_set_session_sender() right after hc_start() succeeds below, deregistered before
 * hc_destroy() in w_https_client_stop() -- same lock discipline as
 * w_https_client_submit_event(), since both submit into the same running instance. */
static bool bridge_submit_sync_session(const char *session_id, const uint8_t *buffer, size_t length)
{
    if (session_id == NULL) {
        return false;
    }

    bool ok = false;

    w_mutex_lock(&g_https_client_lock);

    if (g_https_client != NULL && !g_https_client_stopping) {
        ok = hc_submit_sync_session(g_https_client, session_id, buffer, length);
    }

    w_mutex_unlock(&g_https_client_lock);

    return ok;
}
#endif

/* No internal-option gate: by the time AgentdStart() (and so this) runs,
 * client-agent/src/main.c has already refused to start the daemon at all
 * (merror + mlerror_exit, a hard exit) unless agt->server[0] carries a
 * validated address; the port always has a default (DEFAULT_HTTPS_REMOTE_PORT)
 * when unspecified. HTTPS is the only transport on offer, so there is
 * nothing left to gate. */
void w_https_client_start(void)
{
    minfo("https_client: starting.");

    w_mutex_lock(&g_https_client_lock);
    g_https_client_stopping = false;
    w_mutex_unlock(&g_https_client_lock);

    hc_config_t config;
    if (!bridge_build_config(&config)) {
        return; /* bridge_build_config already logged the reason. */
    }

    hc_callbacks_t callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.log = mtLoggingFunctionsWrapper;
    callbacks.on_startup_result = bridge_on_startup_result;
    callbacks.on_reenroll_required = bridge_on_reenroll_required;
    callbacks.on_task = bridge_on_task;
    callbacks.check_and_record_task = bridge_check_and_record_task;
    callbacks.vd_offset_observe = bridge_vd_offset_observe;
    callbacks.vd_offset_clear_pending = bridge_vd_offset_clear_pending;
    callbacks.on_remote_upgrade_ready = bridge_on_remote_upgrade_ready;
    callbacks.on_task_failed = bridge_on_task_failed;
    callbacks.on_manager_config_hash = bridge_on_manager_config_hash;
    callbacks.on_agent_groups = bridge_on_agent_groups;
    callbacks.on_config_downloaded = bridge_on_config_downloaded;
    callbacks.on_sync_response = bridge_on_sync_response;
    callbacks.on_state_change = bridge_on_state_change;
    callbacks.on_buffer_level = bridge_on_buffer_level;
    callbacks.collect_stats = bridge_collect_stats;
    callbacks.collect_config = bridge_collect_config;
    callbacks.on_collect_host = bridge_on_collect_host;
    callbacks.on_collect_stateless_host = bridge_on_collect_stateless_host;
    callbacks.on_producer_pause = bridge_on_producer_pause;

    g_https_client = hc_create(&config, &callbacks);
    if (!g_https_client) {
        merror("https_client: failed to create the client instance.");
        return;
    }
    if (!hc_start(g_https_client)) {
        merror("https_client: failed to start (configuration rejected).");
        hc_destroy(g_https_client);
        g_https_client = NULL;
        return;
    }

#ifdef WIN32
    asp_set_session_sender(bridge_submit_sync_session);
#endif
}

void w_https_client_stop(void)
{
    /* Set the flag under the lock so it is mutually exclusive with the re-
     * enroll thread's key reload: we either block behind an in-flight
     * hc_set_agent_key() (which finishes on the still-valid handle before we
     * continue) or set the flag before the thread checks it (so it abandons
     * without touching the handle). Only then is it safe to destroy. */
    w_mutex_lock(&g_https_client_lock);
    g_https_client_stopping = true;
    w_mutex_unlock(&g_https_client_lock);

#ifdef WIN32
    /* Deregister before destroying the handle: any sender call already past this point but
     * still waiting on g_https_client_lock will see g_https_client_stopping above and bail
     * without touching a (possibly by-then-destroyed) handle. */
    asp_set_session_sender(NULL);
#endif

    if (g_https_client) {
        hc_destroy(g_https_client); /* Implies stop + join. */
        g_https_client = NULL;
    }
}

int w_https_client_submit_event(const char *frame, size_t length)
{
    if (frame == NULL || length == 0) {
        return -1;
    }

    int retval = -1;

    /* Hold the lock across the submit so the handle cannot be destroyed under
     * us: w_https_client_stop() must take this same lock to flag stopping
     * before it calls hc_destroy(), so while we hold it the handle stays valid.
     * hc_submit_event() only appends to the accumulator, so the section is short. */
    w_mutex_lock(&g_https_client_lock);

    const bool running = g_https_client != NULL && !g_https_client_stopping;

    if (running) {
        retval = hc_submit_event(g_https_client, (const uint8_t *)frame, length) ? 0 : -1;
    }

    w_mutex_unlock(&g_https_client_lock);

    /* Mirrors buffer.c's own drop trace, outside the lock: the accumulator is
     * full and applied drop-newest, exactly as the leaky bucket used to. */
    if (running && retval != 0) {
        mdebug2("https_client: unable to store new packet: buffer is full.");
    }

    return retval;
}
