/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "enrollment.h"
#include "https_client_bridge.h"
#include "metadata_provider.h"

#ifdef WAZUH_UNIT_TESTING
    // Remove static qualifier when unit testing
    #define STATIC

    // Redefine wazuh_version
    #undef __wazuh_version
    #define __wazuh_version "v5.0.0"
#else
    #define STATIC static
#endif

static void w_agentd_keys_init (void);
STATIC void send_msg_on_startup(void);

/* Arm the startup gate and block until the agent has a usable key, enrolling
 * if needed (see w_agentd_keys_init()). Must complete before the HTTPS client
 * is ever started: bridge_build_config() reads client.keys exactly once, at
 * hc_create() time, with no retry -- if it sees an empty keystore there the
 * client never runs, silently, for the rest of the process's life. */
void start_agent_prepare(void)
{
    startup_gate_initialize();
    w_agentd_keys_init();
}

/* Bring the agent up. There is no connection to establish here any more: the
 * HTTPS module owns registration and its retries. What is left is what the
 * legacy handshake did around it. */
void start_agent(int is_startup)
{
    if (!is_startup) {
        return;
    }

    /* Published from the legacy handshake ACK before; everything but the
     * cluster/groups fields is local, and the bridge republishes those from
     * on_startup_result. */
    w_agentd_populate_metadata();

    send_msg_on_startup();
}

/**
 * @brief Initialize keys structure, counter, agent info and crypto method.
 * Keys are read from client.keys. If no valid entry is found:
 *  -If autoenrollment is enabled, a new key is requested to server and execution is blocked until a valid key is received.
 *  -If autoenrollment is disabled, daemon is stoped
 * */
static void w_agentd_keys_init (void) {

    if (keys.keysize == 0) {
        /* Check if we can auto-enroll */
        if (agt->enrollment.enabled) {
            int delay_sleep = 0;
            while (try_enroll_to_server() != 0) {
                /* #38465: a single unconditional target now (agt->server[0] via
                 * the shared transport config), so the dual-target loop this
                 * used to have (a configured enrollment server, then each
                 * agt->server[rc] in turn) is gone -- see plan.md's D4/Q6. The
                 * retry ramp itself is unchanged and still shared with
                 * bridge_reenroll_thread()'s loop, both reading the values ClientConf() resolved. */
                if (delay_sleep < agt->enrollment.retry_max) {
                    delay_sleep += agt->enrollment.retry_delta;
                }
                mdebug1("Sleeping %d seconds before trying to enroll again", delay_sleep);
                sleep(delay_sleep);
            }
        }
        /* If autoenrollment is disabled, stop daemon */
        else {
            merror_exit(AG_NOKEYS_EXIT);
        }
    }
    else {
        /* If the key store was empty, the counters will already be initialized in the enrollment process */
        OS_StartCounter(&keys);
    }

    os_write_agent_info(keys.keyentries[0]->name, NULL, keys.keyentries[0]->id,
                        agt->profile);

    /* Set the crypto method for the agent */
    os_set_agent_crypto_method(&keys, W_METH_AES);
    mdebug1("Using AES as encryption method.");
}

/* Orchestrates one enrollment attempt over HTTPS (#38465): agentd builds the
 * request, sends it via the shared transport, and parses the response --
 * enrollment.c and https_client_bridge.c never call each other directly.
 * There is no per-attempt server selection any more (unlike the legacy
 * multi-target loop this replaces): w_https_client_enroll() always dials
 * agt->server[0], the same single target every other HTTPS endpoint already
 * uses (agt->server[] beyond index 0 has had no real failover behavior since
 * the HTTPS migration -- confirmed against main.c's own startup validation
 * and bridge_build_transport_config(), both of which only ever look at [0]). */
int try_enroll_to_server(void) {
    w_enroll_request_t request = {0};
    if (w_enrollment_build_request(&request) != 0) {
        return -1;
    }

    hc_enroll_result_t result;
    w_https_client_enroll(request.body_json, request.password, &result);
    w_enroll_request_destroy(&request);

    if (w_enrollment_process_response(&result) != W_ENROLL_OK) {
        return -1;
    }

    /* Wait for key update on agent side */
    mdebug1("Waiting %ld seconds before server connection", (long)agt->enrollment.delay_after_enrollment);
    sleep(agt->enrollment.delay_after_enrollment);
    /* Successful enroll, read keys */
    OS_UpdateKeys(&keys);
    /* Set the crypto method for the agent */
    os_set_agent_crypto_method(&keys, W_METH_AES);
    return 0;
}

/* Attempts, and the pause between them, for reading the record that is about to be replaced.
 * Sized for the `updating` window described in w_agentd_populate_metadata(): a struct copy in
 * another process, not a retry loop around anything that can stay busy. */
#define METADATA_READ_ATTEMPTS 3
#define METADATA_READ_RETRY_MS 10

/* Populate shared memory with agent metadata so the first keepalive already
 * contains full agent info.
 *
 * Serialized: start_agent() publishes from the main thread, bridge_on_startup_result()
 * and bridge_on_control_response() from the module's dispatcher thread, and
 * bridge_reenroll_thread() from the re-enrollment worker, while
 * metadata_provider_update() has no writer lock of its own -- it only raises an
 * `updating` flag readers poll, so two overlapping writers would clear it while
 * one is still copying and a reader would get a torn record. */
void w_agentd_populate_metadata(void)
{
    static pthread_mutex_t metadata_mutex = PTHREAD_MUTEX_INITIALIZER;
    agent_metadata_t metadata = {0};

    w_mutex_lock(&metadata_mutex);

    /* Carry over vd_feed_offset, the one field agentd does not own. metadata_provider_update()
     * replaces the whole record, and that offset is written only by agent-info, from what the
     * manager reports over /control -- publishing a zero makes every VD synchronization abort
     * with NO_VD_OFFSET_ERROR until agent-info's next cycle rewrites it, which in turn fails
     * Syscollector::syncModule() and makes the wodle skip the recovery pass behind it. Every
     * other field here is either local to the agent or set below from what the handshake
     * reported.
     *
     * The read is retried because -1 is not one answer but two: nothing has ever been published
     * (first boot, where a zero offset is the truth), or the reader hit the `updating` flag
     * agent-info raises while it writes. agent-info is a different process, so the mutex above
     * does not serialize against it, and that window is no wider than a struct copy -- but
     * reading it as "no offset" would suppress VD synchronization until agent-info's next
     * /control cycle, which is to say it would disable the identity resync this change exists
     * for, in exactly the window right after a re-enrollment where it is needed. Retrying is the
     * local fix; the structural one is a partial update in the provider, so agentd never has to
     * round-trip a field it does not own. */
    {
        agent_metadata_t previous = {0};
        int carried = 0;

        for (int attempt = 0; attempt < METADATA_READ_ATTEMPTS; attempt++) {
            if (metadata_provider_get(&previous) == 0) {
                metadata.vd_feed_offset = previous.vd_feed_offset;
                metadata_provider_free_metadata(&previous);
                carried = 1;
                break;
            }

            if (attempt + 1 < METADATA_READ_ATTEMPTS) {
                w_time_delay(METADATA_READ_RETRY_MS);
            }
        }

        if (!carried) {
            /* Also the ordinary first-boot path, where there is genuinely nothing to carry. */
            mdebug1("No published agent metadata to carry the VD feed offset from.");
        }
    }

#ifdef WIN32
    os_info *os = get_win_version();
#else
    os_info *os = get_unix_version();
#endif

    /* Agent identity */
    if (keys.keysize > 0 && keys.keyentries[0]) {
        strncpy(metadata.agent_id, keys.keyentries[0]->id, sizeof(metadata.agent_id) - 1);
        strncpy(metadata.agent_name, keys.keyentries[0]->name, sizeof(metadata.agent_name) - 1);
    }
    strncpy(metadata.agent_version, __wazuh_version, sizeof(metadata.agent_version) - 1);

    /* OS info */
    if (os) {
        if (os->os_name) {
            strncpy(metadata.os_name, os->os_name, sizeof(metadata.os_name) - 1);
        }
        if (os->os_version) {
            strncpy(metadata.os_version, os->os_version, sizeof(metadata.os_version) - 1);
        }
        if (os->os_platform) {
            strncpy(metadata.os_platform, os->os_platform, sizeof(metadata.os_platform) - 1);
        }
        if (os->machine) {
            strncpy(metadata.architecture, os->machine, sizeof(metadata.architecture) - 1);
        }
        if (os->nodename) {
            strncpy(metadata.hostname, os->nodename, sizeof(metadata.hostname) - 1);
        }
        free_osinfo(os);
    }

    /* OS type (compile-time constant) */
#ifdef WIN32
    strncpy(metadata.os_type, "windows", sizeof(metadata.os_type) - 1);
#elif defined(__MACH__)
    strncpy(metadata.os_type, "macos", sizeof(metadata.os_type) - 1);
#else
    strncpy(metadata.os_type, "linux", sizeof(metadata.os_type) - 1);
#endif

    /* Cluster info from handshake */
    strncpy(metadata.cluster_name, agent_cluster_name, sizeof(metadata.cluster_name) - 1);

    /* Groups from handshake */
    if (agent_agent_groups[0] != '\0') {
        /* Count groups (comma-separated) */
        size_t count = 1;
        for (const char *p = agent_agent_groups; *p; p++) {
            if (*p == ',') {
                count++;
            }
        }

        metadata.groups = (char **)calloc(count, sizeof(char *));
        if (metadata.groups) {
            char groups_copy[OS_SIZE_65536];
            strncpy(groups_copy, agent_agent_groups, sizeof(groups_copy) - 1);
            groups_copy[sizeof(groups_copy) - 1] = '\0';

            size_t i = 0;
            char *saveptr = NULL;
            char *token = strtok_r(groups_copy, ",", &saveptr);
            while (token && i < count) {
                if (token[0] != '\0') {
                    metadata.groups[i] = strdup(token);
                    i++;
                }
                token = strtok_r(NULL, ",", &saveptr);
            }
            metadata.groups_count = i;
        }
    }

    if (metadata_provider_update(&metadata) == 0) {
        mdebug1("Early metadata populated into shared memory");
    } else {
        mdebug1("Failed to populate early metadata");
    }

    /* Free groups */
    if (metadata.groups) {
        for (size_t i = 0; i < metadata.groups_count; i++) {
            free(metadata.groups[i]);
        }
        free(metadata.groups);
    }

    w_mutex_unlock(&metadata_mutex);
}

/**
 * @brief Reports the agent start, now over /stateless. The event shape is
 *        unchanged, only the transport that carries it.
 * */
STATIC void send_msg_on_startup(void) {

    char fmsg[OS_MAXSTR + 1] = { '\0' };
    char timestamp[32];

    get_iso8601_utc_time(timestamp, sizeof(timestamp));

    cJSON *event = cJSON_CreateObject();
    cJSON_AddStringToObject(event, "event.module", "wazuh-agent");
    cJSON_AddStringToObject(event, "event.action", "agent-start");
    cJSON_AddStringToObject(event, "event.start", timestamp);
    char *json_str = cJSON_PrintUnformatted(event);
    cJSON_Delete(event);

    os_snprintf(fmsg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", json_str);
    os_free(json_str);

    w_https_client_submit_event(fmsg, strlen(fmsg));
}
