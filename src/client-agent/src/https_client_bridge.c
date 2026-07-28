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
 * The config surface (<server>/<ssl>, parsed by Read_Client/Read_Client_SSL
 * in src/config/src/client-config.c) and the real TLS wiring are done: the
 * module's own fail-closed validation (ModuleConfig::validateTls) now gets a
 * real verify_mode/CA/cert/key/ciphers instead of a forced HC_VERIFY_NONE.
 * on_reenroll_required is wired to the existing authd flow (try_enroll_to_server,
 * start_agent.c) and hc_set_agent_key(); on_state_change feeds the .state file
 * (client-agent/include/state.h) and, since a QA round against #37831 found
 * WAIT_FILE/os_setwait() had no HTTPS release path either, also clears that
 * producer lock on REGISTERED. on_startup_result applies module limits and
 * cluster-name authority (#37830's own scope), and on_config_downloaded
 * writes/applies merged.mg and releases the startup_gate (#37832's own
 * scope) -- both were previously dev-scaffold stubs despite their issues
 * being merged and closed; see startup_gate_release_from_https_apply()'s own
 * comment for why that release cannot reuse the legacy MD5-based gate
 * machinery. Still pending (later integration workstreams of #37702):
 * retiring the legacy TCP data path this module runs alongside.
 */

#include "https_client_bridge.h"

#include <ctype.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>

#include "agentd.h" /* pulls defs.h (__wazuh_version), sec.h (keys), client-config.h (agt) */
#include "https_client.h"
#include "sendmsg.h" /* send_msg(): the AG_IN_UNMERGE manager-visible report on unmerge failure */
#include "sha256_op.h" /* OS_SHA256_File(): config_checksum seed, matching the module's own hash space */
#include "syscheck_op.h" /* ag_send_syscheck: the FIM leg of the sync answer */
#include "wmodules.h"    /* wmcom_send: the leg for every other module */

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

/* Received-work callbacks. The production hookups still pending (later
 * integration workstreams): execd/module-com routing for on_task-equivalent
 * work. */

/* Startup-response parsing (#37830's own "In scope" text: apply module limits
 * and cluster-name authority from the handshake). Deliberately separate,
 * local copies of client-agent/src/start_agent.c's parse_fim_limits()/
 * parse_syscollector_limits()/parse_sca_limits()/parse_limits() logic rather
 * than calling those functions directly: they are file-static in start_agent.c
 * (legacy handshake code, out of this change's scope per finding 4), and
 * strict-required-field parsing is genuinely what the "limits" sub-object
 * needs (unlike cluster/groups below). Field names/nesting confirmed against
 * the current #37733 contract and the https_client module's own demo mock
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

/* Cluster-name authority (#37830): unlike start_agent.c's parse_cluster_name()/
 * parse_cluster_node() -- which are flat top-level fields and REFUSE an empty
 * value -- the HTTPS contract nests them under "cluster":{"name","node"}, and
 * #37830's own scope explicitly wants an unconditional overwrite, even to
 * empty/unknown, so a manager that stops reporting identity doesn't leave a
 * stale value behind. Mirrors ControlStream::applyClusterIdentity() (the
 * module's own internal, HTTPS-side copy of this same rule) so the C side's
 * globals (which agent-info/agcom and the shutdown message already read)
 * agree with what the module itself believes. */
static void bridge_apply_cluster_identity(const cJSON *root)
{
    const cJSON *cluster = cJSON_GetObjectItem(root, "cluster");
    const char *name = NULL;
    const char *node = NULL;

    if (cluster && cJSON_IsObject(cluster)) {
        cJSON *name_field = cJSON_GetObjectItem(cluster, "name");
        cJSON *node_field = cJSON_GetObjectItem(cluster, "node");

        if (name_field && cJSON_IsString(name_field) && name_field->valuestring) {
            name = name_field->valuestring;
        }
        if (node_field && cJSON_IsString(node_field) && node_field->valuestring) {
            node = node_field->valuestring;
        }
    }

    snprintf(agent_cluster_name, sizeof(agent_cluster_name), "%s", name ? name : "");
    snprintf(agent_cluster_node, sizeof(agent_cluster_node), "%s", node ? node : "");
    mdebug1("https_client: cluster identity -> name='%s', node='%s'.", agent_cluster_name, agent_cluster_node);
}

/* agent_groups: HTTPS nests the array under "agent":{"groups":[...]} (see
 * ControlStream's firstGroup(), which reads the same object for /download's
 * group parameter) rather than start_agent.c's flat "agent_groups" array.
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

    /* #37830 "In scope": apply module limits into the existing exposure paths
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
                minfo("https_client: reloading due to module limits changes.");
                reloadAgent();
            } else {
                mdebug1("https_client: module limits have been updated.");
            }
        }
    } else {
        mdebug2("https_client: no valid 'limits' object in the startup response; "
                "module limits are unchanged.");
    }

    bridge_apply_cluster_identity(root);
    bridge_apply_agent_groups(root);

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

static void bridge_on_task(const char *task_id, const char *task_type, const char *payload_json,
                           void *user_data)
{
    (void)payload_json;
    (void)user_data;
    mdebug1("https_client task received: id=%s type=%s", task_id ? task_id : "?",
            task_type ? task_type : "?");
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
    startup_gate_check_manager_config_hash(config_hash);
}

/* Applies a downloaded merged configuration and releases the startup gate.
 *
 * file_path is a module-owned temp file valid ONLY until the callback that
 * received it returns (the module deletes it right after) -- so the very
 * first thing this does is copy it into SHAREDCFG_FILE.
 *
 * Mirrors the legacy apply chain (client-agent/src/receiver.c's FILE_CLOSE_HEADER
 * handling: UnmergeFiles -> cldir_ex_ignore -> verifyRemoteConf -> reloadAgent),
 * reusing the exact same shared-code calls, including receiver.c's own
 * anti-race sequencing between reloadAgent() and the gate release (see its
 * "the reload chain ... is the normal release path" comment): if
 * reloadAgent() actually dispatches, the gate is deliberately NOT released
 * here -- releasing it unconditionally could let a module still blocked in
 * startup_gate_wait_for_ready() unblock and start a moment before the reload
 * chain (modulesd CONTROL_SOCK -> wazuh-control reload -> SIGUSR1) restarts
 * it anyway. client-agent/src/agentd.c's own SIGUSR1 handling
 * (needs_config_reload) calls startup_gate_release_from_https_apply()
 * once that restart has actually happened -- this is the transport-agnostic
 * release path for the common case.
 *
 * The one deliberate difference from receiver.c: the HTTPS /control contract
 * has no merged_sum handshake field (#37733), so there is no later handshake
 * retry to lean on if reloadAgent() cannot even dispatch (control socket
 * unreachable). receiver.c's own fallback ("release inline only if
 * reloadAgent() fails") is mirrored exactly below for that case -- see the
 * reload/gate block near the end of this function, and
 * startup_gate_release_from_https_apply()'s own comment for why that inline
 * release is safe even without the legacy MD5 comparison.
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
     * as a real, Windows-only regression during #37831 real-package
     * validation, 2026-07-28). */
    if (w_copy_file(file_path, SHAREDCFG_FILE, 'b', NULL, 0) != 0) {
        merror("https_client: could not copy the downloaded configuration into '%s'; "
               "keeping the previously applied one.", SHAREDCFG_FILE);
        if (handle) {
            /* What's actually on disk is still the old config, not config_hash:
             * correct the module's optimistic view so the next Notify mismatch
             * re-triggers the download instead of assuming we are in sync. */
            hc_set_config_hash(handle, "");
        }
        return;
    }

    char **ignore_list;
    os_calloc(2, sizeof(char *), ignore_list);
    os_strdup(SHAREDCFG_FILENAME, *ignore_list);

    if (!UnmergeFiles(SHAREDCFG_FILE, SHAREDCFG_DIR, OS_TEXT, &ignore_list)) {
        merror("https_client: failed to unmerge the downloaded configuration "
               "('%s'); keeping the previously applied files.", SHAREDCFG_FILE);
        /* Manager-visible report, mirroring receiver.c's own AG_IN_UNMERGE event
         * on the same failure. */
        char unmerge_fail_msg[OS_MAXSTR];
        snprintf(unmerge_fail_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", AG_IN_UNMERGE);
        send_msg(unmerge_fail_msg, -1);
        free_strarray(ignore_list);
        if (handle) {
            hc_set_config_hash(handle, "");
        }
        return;
    }

    if (cldir_ex_ignore(SHAREDCFG_DIR, (const char **)ignore_list)) {
        mwarn("https_client: could not clean up the shared configuration directory.");
    }
    free_strarray(ignore_list);

    if (!agt->flags.remote_conf) {
        /* Mirrors receiver.c: the files are staged either way, but nothing
         * reloads or gates on remote configuration when the agent has opted
         * out of it. */
        return;
    }

    if (verifyRemoteConf()) {
        /* Invalid remote configuration: verifyRemoteConf() already reported it
         * to the manager (AG_IN_RCON). Do not reload or release the gate with
         * a configuration known to be broken -- mirrors receiver.c, which
         * skips its own reload/gate block on the same check. */
        merror("https_client: downloaded configuration failed validation; not reloading.");
        return;
    }

    minfo("https_client: applying configuration downloaded over HTTPS (hash=%s).",
          config_hash ? config_hash : "?");

    /* Anti-race sequencing, mirroring receiver.c's own FILE_CLOSE_HEADER
     * handling (see its "the reload chain ... is the normal release path"
     * comment): if reloadAgent() actually dispatches, do NOT release the gate
     * here. Doing so unconditionally could let a module still blocked in
     * startup_gate_wait_for_ready() unblock and start a moment before the
     * reload chain (modulesd CONTROL_SOCK -> wazuh-control reload -> SIGUSR1)
     * restarts it anyway -- the exact "briefly start with the new config and
     * then get killed" race receiver.c was written to avoid. agentd.c's own
     * SIGUSR1 handling (needs_config_reload) already calls
     * startup_gate_release_from_https_apply() once that restart has actually
     * happened.
     *
     * Only release inline here as a fallback when reloadAgent() itself could
     * not even dispatch (control socket unreachable) -- no SIGUSR1 will ever
     * arrive to do it later in that case, so the gate would otherwise stay
     * stuck. This is also, concretely, the fresh-install/first-boot case:
     * modulesd/monitoring processes are still blocked in their very first
     * startup_gate_wait_for_ready() call and have no prior instance to
     * restart, so there is nothing to race against. */
    if (!reloadAgent()) {
        mdebug1("https_client: could not dispatch the reload chain; releasing "
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

    if (body == NULL || body_len == 0) {
        return;
    }

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

        /* Hand it back exactly as the legacy path does: the manager answers a
         * session with the same EndAck it always has, so the module parses it
         * unchanged - only the transport that carried it here is different. */
        const size_t header_len = strlen(SYNC_ROUTES[i].header);

        if (body_len > SIZE_MAX - header_len - 1) {
            mdebug2("https_client: sync answer for session '%s' is too large to frame; dropping it.",
                    session_id);
            return;
        }

        char *framed = NULL;
        os_malloc(header_len + body_len + 1, framed);
        memcpy(framed, SYNC_ROUTES[i].header, header_len);
        memcpy(framed + header_len, body, body_len);
        framed[header_len + body_len] = '\0';

        if (SYNC_ROUTES[i].syscheck) {
            ag_send_syscheck(framed, header_len + body_len);
        } else {
            wmcom_send(framed, header_len + body_len);
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

    /* Interim fix for the WAIT_FILE/os_setwait() producer lock (armed
     * unconditionally at agent startup, see agentd.c's AgentdStart()): it is
     * otherwise only ever cleared by a successful LEGACY plaintext handshake,
     * which permanently blocks every module's SendMSG/SendBinaryMSG against a
     * pure-HTTPS manager even though /control is fully connected and healthy.
     * A successful HTTPS registration is the equivalent "the manager
     * acknowledged us" signal, so clear the lock here too. os_delwait() is
     * idempotent (unlink() on an already-absent WAIT_FILE is a harmless
     * no-op, and __wait_lock is just reset to 0), so it is safe to call
     * unconditionally on every REGISTERED transition, including a later one
     * after a reconnect. */
    if (state == HC_STATE_REGISTERED) {
        os_delwait();
    }
}

/* Occupancy thresholds the module reports against, kept so the log lines can
 * quote them exactly as buffer.c does. Filled by bridge_build_config() from the
 * same internal options buffer_init() reads. */
static int g_buffer_warn_level = 90;
static int g_buffer_normal_level = 70;

/* Reports the accumulator's occupancy exactly as the legacy leaky bucket
 * reported the ring it replaced (client-agent/src/buffer.c): the same log lines
 * and the same wazuh-agent.buffer state event, so the manager-side flood rules
 * keep firing now that stateless events no longer pass through buffer_append().
 *
 * The state event bypasses the accumulator -- send_buffer_status_event() writes
 * straight to send_msg() -- exactly as buffer.c bypassed the ring it reports
 * on. A flood report must not queue behind the flood it is reporting. */
static void bridge_on_buffer_level(int level, void *user_data)
{
    (void)user_data;

    switch (level) {
    case HC_BUFFER_WARNING:
        mwarn(WARN_BUFFER, g_buffer_warn_level);
        send_buffer_status_event("warning", 1);
        break;

    case HC_BUFFER_FULL:
        mwarn(FULL_BUFFER);
        send_buffer_status_event("full", 2);
        break;

    case HC_BUFFER_FLOOD:
        mwarn(FLOODED_BUFFER);
        send_buffer_status_event("flooded", 3);
        break;

    case HC_BUFFER_NORMAL:
        mdebug1(NORMAL_BUFFER, g_buffer_normal_level);
        send_buffer_status_event("normal", 0);
        break;

    default:
        mdebug2("https_client: unknown buffer level %d.", level);
        break;
    }
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

/* The AES-CMAC recipe (settled by the manager's resolver, PR #37821): decode
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
        merror("https_client: agent key is missing or has an invalid length for AES-CMAC "
               "(expected 32, 48 or 64 hex characters); refusing to start.");
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

    /* Occupancy ladder: the same internal options buffer_init() reads, so an
     * operator who tuned the legacy client buffer keeps their thresholds now
     * that the accumulator is what fills up. Read here rather than through
     * buffer.c's globals because those are only set when the legacy buffer is
     * enabled, and the accumulator applies either way. */
    g_buffer_warn_level = getDefine_Int("agent", "warn_level", 1, 100);
    g_buffer_normal_level = getDefine_Int("agent", "normal_level", 0, g_buffer_warn_level - 1);
    config->buffer_warn_level = (uint32_t)g_buffer_warn_level;
    config->buffer_normal_level = (uint32_t)g_buffer_normal_level;
    config->buffer_flood_tolerance_s = (uint32_t)getDefine_Int("agent", "tolerance", 0, 600);

    /* Bug found during real-package validation of #37831 (2026-07-28): this used to be
     * getsharedfiles() (client-agent/src/notify.c), which is an MD5 (OS_MD5_File) -- the legacy
     * merged_sum format. config->config_checksum seeds ConfigHashState's initial value
     * (httpsClientFacade.cpp: m_configHash(m_config.configChecksum)), which is compared
     * byte-for-byte against the manager-reported agent.config_hash on every Notify
     * (controlStream.cpp's maybeDownloadConfig()) -- and that value is a SHA-256 ("SHA256 hash
     * of group configuration", #37733 OpenAPI; confirmed against configFetcher.cpp/digest.hpp,
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
     * the DGRAM queue. Producers connect via sendSyncSession() (the eventual
     * agent_sync_protocol transport swap). */
    strncpy(config->sync_socket_path, SYNCQUEUE, sizeof(config->sync_socket_path) - 1);

    return true;
}

/* No internal-option gate: by the time AgentdStart() (and so this) runs,
 * client-agent/src/main.c has already refused to start the daemon at all
 * (merror + mlerror_exit, a hard exit) unless agt->server[0] carries a
 * validated address; the port always has a default (DEFAULT_REMOTE_PORT)
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
    callbacks.on_manager_config_hash = bridge_on_manager_config_hash;
    callbacks.on_config_downloaded = bridge_on_config_downloaded;
    callbacks.on_sync_response = bridge_on_sync_response;
    callbacks.on_state_change = bridge_on_state_change;
    callbacks.on_buffer_level = bridge_on_buffer_level;

    g_https_client = hc_create(&config, &callbacks);
    if (!g_https_client) {
        merror("https_client: failed to create the client instance.");
        return;
    }
    if (!hc_start(g_https_client)) {
        merror("https_client: failed to start (configuration rejected).");
        hc_destroy(g_https_client);
        g_https_client = NULL;
    }
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
