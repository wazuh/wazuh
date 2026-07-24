/*
 * Wazuh agent HTTPS client bridge (development scaffold)
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
 * (client-agent/include/state.h). Still pending (later integration workstreams
 * of #37702): retiring the legacy TCP data path this module runs alongside.
 */

#include "https_client_bridge.h"

#include <ctype.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>

#include "agentd.h" /* pulls defs.h (__wazuh_version), sec.h (keys), client-config.h (agt) */
#include "https_client.h"

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
static void bridge_on_startup_result(bool accepted, const char *metadata_json, void *user_data)
{
    (void)user_data;
    mdebug1("https_client startup %s: %s", accepted ? "accepted" : "rejected",
            metadata_json ? metadata_json : "(no metadata)");
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

static void bridge_on_config_downloaded(const char *config_hash, const char *file_path,
                                        void *user_data)
{
    /* Production hookup (later integration workstream): copy the file inside
     * this callback (the module deletes it right after), then run the legacy
     * apply chain -- write SHAREDCFG_DIR/merged.mg, UnmergeFiles(), verify
     * with getsharedfiles(), reloadAgent() under auto_restart (receiver.c /
     * reload_agent.c) -- and call hc_set_config_hash() if the applied hash
     * diverges. The dev scaffold only logs the delivery. */
    (void)user_data;
    mdebug1("https_client config downloaded (hash=%s, file=%s)",
            config_hash ? config_hash : "?", file_path ? file_path : "?");
}

static void bridge_on_state_change(int state, void *user_data)
{
    (void)user_data;
    mdebug1("https_client connection state -> %d", state);
    w_agentd_state_update(UPDATE_STATUS, (void *)bridge_map_agent_status(state));
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
 * on. A flood report must not queue behind the flood it is reporting. That
 * keeps it on the legacy socket for now; it moves with every other stateless
 * producer when the TCP path is retired. */
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
    if (!bridge_key_is_valid(raw_key)) {
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

    char *checksum = getsharedfiles();
    if (checksum) {
        strncpy(config->config_checksum, checksum, sizeof(config->config_checksum) - 1);
        os_free(checksum);
    }

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
    callbacks.on_config_downloaded = bridge_on_config_downloaded;
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
