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
#include "bulk.h"
#include "agent_metadata_db.h"
#include "os_net.h"
#include "remoted.h"
#include "remoted_op.h"
#include "state.h"
#include "wazuhdb_queries_op.h"
#include "sym_load.h"
#include "remoted_module.h"
#include "indexed_queue_op.h"
#include "batch_queue_op.h"
#include "http_op.h"
#include "legacy_task_delivery.h"

// REMOTED_HTTPS_VERIFY_* (remote-config.h, via remoted.h) and REMOTED_MODULE_HTTPS_VERIFY_*
// (remoted_module.h) are two independently-maintained mirrors of the same values, since
// the config parser and the C++ module don't share a header. rm_config.verification_mode
// below copies one directly into the other with no translation, so a silent reorder of
// either enum would misconfigure TLS client-certificate verification without any build
// failure to catch it -- this is the only place both headers are already included together.
_Static_assert(REMOTED_HTTPS_VERIFY_UNSET == REMOTED_MODULE_HTTPS_VERIFY_UNSET,
               "REMOTED_HTTPS_VERIFY_UNSET must match REMOTED_MODULE_HTTPS_VERIFY_UNSET");
_Static_assert(REMOTED_HTTPS_VERIFY_NONE == REMOTED_MODULE_HTTPS_VERIFY_NONE,
               "REMOTED_HTTPS_VERIFY_NONE must match REMOTED_MODULE_HTTPS_VERIFY_NONE");
_Static_assert(REMOTED_HTTPS_VERIFY_CERTIFICATE == REMOTED_MODULE_HTTPS_VERIFY_CERTIFICATE,
               "REMOTED_HTTPS_VERIFY_CERTIFICATE must match REMOTED_MODULE_HTTPS_VERIFY_CERTIFICATE");
_Static_assert(REMOTED_HTTPS_VERIFY_FULL == REMOTED_MODULE_HTTPS_VERIFY_FULL,
               "REMOTED_HTTPS_VERIFY_FULL must match REMOTED_MODULE_HTTPS_VERIFY_FULL");

// Same reasoning as above, for REMOTED_HTTPS_DUAL_STACK_* / REMOTED_MODULE_HTTPS_DUAL_STACK_*:
// rm_config.dual_stack copies one directly into the other with no translation, so a silent
// reorder of either enum would misconfigure the IPV6_V6ONLY socket option without any build
// failure to catch it.
_Static_assert(REMOTED_HTTPS_DUAL_STACK_UNSET == REMOTED_MODULE_HTTPS_DUAL_STACK_UNSET,
               "REMOTED_HTTPS_DUAL_STACK_UNSET must match REMOTED_MODULE_HTTPS_DUAL_STACK_UNSET");
_Static_assert(REMOTED_HTTPS_DUAL_STACK_YES == REMOTED_MODULE_HTTPS_DUAL_STACK_YES,
               "REMOTED_HTTPS_DUAL_STACK_YES must match REMOTED_MODULE_HTTPS_DUAL_STACK_YES");
_Static_assert(REMOTED_HTTPS_DUAL_STACK_NO == REMOTED_MODULE_HTTPS_DUAL_STACK_NO,
               "REMOTED_HTTPS_DUAL_STACK_NO must match REMOTED_MODULE_HTTPS_DUAL_STACK_NO");

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

static _Atomic time_t s_last_events_drop_warn = 0;
static _Atomic size_t s_pending_events_drop = 0;

/**
 * @brief Increment the pending-drop counter and emit a rate-limited warning.
 *
 * At most one warning per 90-second window is printed. The CAS on
 * s_last_events_drop_warn ensures exactly one thread wins the print slot when
 * multiple handler threads discard events simultaneously.
 */
static void maybe_log_events_queue_drop(void) {
    atomic_fetch_add_explicit(&s_pending_events_drop, 1, memory_order_relaxed);

    time_t now  = time(NULL);
    time_t last = atomic_load_explicit(&s_last_events_drop_warn, memory_order_relaxed);
    if (now - last >= 90 &&
        atomic_compare_exchange_strong_explicit(&s_last_events_drop_warn, &last, now,
                                                memory_order_relaxed, memory_order_relaxed)) {
        size_t count = atomic_exchange_explicit(&s_pending_events_drop, 0, memory_order_relaxed);
        mwarn("Events queue discarded %zu event(s) in the last 90 seconds.", count);
    }
}

/* Global variables */
w_indexed_queue_t *control_msg_queue = NULL;
w_rr_queue_t *events_queue = NULL;

netbuffer_t netbuffer_recv;
netbuffer_t netbuffer_send;

wnotify_t * notify = NULL;

size_t global_counter;

_Atomic (time_t) current_ts;

extern remoted_state_t remoted_state;
STATIC void handle_outgoing_data_to_tcp_socket(int sock_client);
STATIC void handle_incoming_data_from_tcp_socket(int sock_client);
STATIC void handle_incoming_data_from_udp_socket(struct sockaddr_storage * peer_info);
STATIC void handle_new_tcp_connection(wnotify_t * notify, struct sockaddr_storage * peer_info);

// Read the remoted.http_* internal options into the C++ module's config struct
STATIC void remoted_module_https_config(remoted_module_config_t *rm_config);

// Build limits JSON from manager_module_limits (only the limits object, not cluster/groups)
STATIC char* build_limits_json(const module_limits_t *limits);

// Read control endpoint internal options into the C++ module's config struct
STATIC void remoted_module_control_config(remoted_module_config_t *rm_config);

// Headers for messages
#define UPGRADE_ACK_HEADER "u:upgrade_module:"
#define UPGRADE_ACK_HEADER_SIZE 17

// Headers for inventory sync messages
#define INVENTORY_SYNC_HEADER "s:"
#define INVENTORY_SYNC_HEADER_SIZE 2

// Headers for DBSYNC messages (4.x agents - not supported in 5.0)
#define DBSYNC_HEADER "5:"
#define DBSYNC_HEADER_SIZE 2

// Detects (and logs) legacy agent messages the 5.x manager no longer processes.
STATIC bool discard_legacy_agent_message(const char* msg, const char* agent_id);

// Message handler thread
static void * rem_handler_main(void * args);

// Key reloader thread
void * rem_keyupdate_main(__attribute__((unused)) void * args);

/* Handle each message received */
STATIC void HandleSecureMessage(const message_t *message, w_indexed_queue_t * control_msg_queue, w_rr_queue_t * batch_queue);

/**
 * @brief maps logr's <remote><https> config, the `remoted.http_*` internal options,
 *        and the memory-management constants onto the C-ABI struct handed to the C++
 *        remoted_module
 *
 * @param logr remoted configuration structure (source)
 * @param rm_config destination struct; fully zeroed and populated on return
 */
STATIC void w_remoted_build_module_config(const remoted *logr, remoted_module_config_t *rm_config);

// Close and remove socket from keystore
int _close_sock(keystore * keys, int sock);

/* Get current timestamp */
STATIC void *current_timestamp(void *none);

STATIC void * close_fp_main(void * args);

/* Family address reference */
#define FAMILY_ADDRESS_SIZE 46
char *str_family_address[FAMILY_ADDRESS_SIZE] = {
    "AF_UNSPEC", "AF_LOCAL/AF_UNIX/AF_FILE", "AF_INET", "AF_AX25", "AF_IPX",
    "AF_APPLETALK","AF_NETROM", "AF_BRIDGE", "AF_ATMPVC", "AF_X25", "AF_INET6",
    "AF_ROSE", "AF_DECnet", "AF_NETBEUI", "AF_SECURITY", "AF_KEY",
    "AF_NETLINK/AF_ROUTE", "AF_PACKET", "AF_ASH", "AF_ECONET", "AF_ATMSVC",
    "AF_RDS", "AF_SNA", "AF_IRDA", "AF_PPPOX", "AF_WANPIPE", "AF_LLC", "AF_IB",
    "AF_MPLS", "AF_CAN", "AF_TIPC", "AF_BLUETOOTH", "AF_IUCV", "AF_RXRPC",
    "AF_ISDN", "AF_PHONET", "AF_IEEE802154", "AF_CAIF", "AF_ALG", "AF_NFC",
    "AF_VSOCK", "AF_KCM", "AF_QIPCRTR", "AF_SMC", "AF_XDP", "AF_MCTP"
};

/**
 * @brief Structure to hold control message data
 *
 */
typedef struct {
    keyentry * key; ///< Pointer to the key entry of agent to which the message belongs
    char * message; ///< Raw message received
    int is_startup; ///< Validation result: is startup message
    int is_shutdown; ///< Validation result: is shutdown message
    bool post_startup; ///< Keystore flag: pending full sync after startup
} w_ctrl_msg_data_t;

/**
 * @brief Free control message data
 *
 * @param ptr_ctrl_msg_data Pointer to the control message data to be freed
 * @warning The ctrl_msg_data pointer will be invalid after this function call.
 */
static void w_free_ctrl_msg_data(w_ctrl_msg_data_t * ctrl_msg_data) {

    if (ctrl_msg_data == NULL) {
        return;
    }

    if (ctrl_msg_data->key) {
        OS_FreeKey(ctrl_msg_data->key);
    }
    os_free(ctrl_msg_data->message);
    os_free(ctrl_msg_data);
}

/**
 * @brief Get key from control message data for indexed queue
 *
 * @param data Pointer to w_ctrl_msg_data_t structure
 * @return Pointer to agent_id string (must not be freed by caller)
 */
static char *w_ctrl_msg_get_key(void *data) {
    w_ctrl_msg_data_t *ctrl_msg_data = (w_ctrl_msg_data_t *)data;
    if (ctrl_msg_data && ctrl_msg_data->key) {
        return ctrl_msg_data->key->id;
    }
    return NULL;
}

/**
 * @brief Thread function to save control messages
 *
 * This function is executed by the control message thread pool. It waits for messages to be pushed into the queue and processes them.
 * Updates the agent's status in wazuhdb and sends the message to the appropriate handler.
 * @param queue Pointer to the control message queue, which is used to store messages to be processed.
 * @return void* Null
 */
void * save_control_thread(void * queue);

typedef struct {
    char  *raw;
    size_t len;
} evt_item_t;

typedef struct {
    const char *agent_id;
    int   header_added;
    bulk_t bulk;             // body to send (header + events)
} dispatch_ctx_t;

static void dispose_evt_item(void *p) {
    evt_item_t *e = (evt_item_t*)p;
    if (!e) return;
    os_free(e->raw);
    os_free(e);
}

static size_t evt_item_get_bytes(const void *p) {
    const evt_item_t *e = (const evt_item_t *)p;
    return e ? e->len : 0;
}

void * dispach_events_thread(void * queue);

typedef struct {
    w_indexed_queue_t *control_msg_queue; // the indexed control queue
    w_rr_queue_t      *events_queue;      // round robbin event ring
} rem_handler_args_t;

/**
 * @brief Read the C++ module's tunable settings (`remoted.*` internal options: HTTP
 *        transport, memory-management, downstream client, and auth middleware) into
 *        the config struct passed to remoted_module_start().
 */
STATIC void remoted_module_https_config(remoted_module_config_t *rm_config) {
    // io_threads/http_worker_threads: min+default 0 (not 1) so an unset option flows through as a
    // real 0 -- the C++ side resolves 0 via cpp_get_nproc() instead of a fixed constant.
    rm_config->io_threads = getDefine_Int_default("remoted", "http_io_threads", 0, 64, 0);
    rm_config->http_worker_threads = getDefine_Int_default("remoted", "http_worker_threads", 0, 256, 0);
    rm_config->http_read_timeout = getDefine_Int_default("remoted", "http_read_timeout", 1, 300, 10);
    rm_config->http_write_timeout = getDefine_Int_default("remoted", "http_write_timeout", 1, 300, 10);
    rm_config->http_request_timeout = getDefine_Int_default("remoted", "http_request_timeout", 1, 600, 30);
    rm_config->http_max_url_size = getDefine_Int_default("remoted", "http_max_url_size", 1, 65536, 2048);
    rm_config->http_max_header_name_size = getDefine_Int_default("remoted", "http_max_header_name_size", 1, 8192, 256);
    rm_config->http_max_header_value_size = getDefine_Int_default("remoted", "http_max_header_value_size", 1, 65536, 8192);
    rm_config->http_max_header_count = getDefine_Int_default("remoted", "http_max_header_count", 1, 1024, 64);
    rm_config->http_max_pipelined_requests = getDefine_Int_default("remoted", "http_max_pipelined_requests", 1, 64, 4);
    rm_config->http_concurrent_accepts = getDefine_Int_default("remoted", "http_concurrent_accepts", 1, 64, 2);
    rm_config->http_buffer_size = getDefine_Int_default("remoted", "http_buffer_size", 1, 1048576, 8192);
    // Bytes per chunk when streaming a response body (POST /download). Bounded at 1 MiB because
    // this is per IN-FLIGHT TRANSFER: the worst case is roughly this times the number of
    // simultaneous downloads, so a large value trades memory for fewer read/write round trips.
    rm_config->http_stream_chunk_size = getDefine_Int_default("remoted", "http_stream_chunk_size", 4096, 1048576, 65536);
    rm_config->http_content_encoding_enabled =
        getDefine_Int_default("remoted", "http_content_encoding_enabled", 0, 1, 1);

    // Memory-management (backpressure) tunables. These bound in-memory resource usage rather
    // than tune the transport itself; the C++ side still clamps max_inflight_bytes up to at
    // least one max-size request at start(), so a too-small value can't reject everything.
    // max_inflight_bytes caps the HTTPS server's in-flight (unprocessed) request payload
    // before it sheds load with 503. NOT logr->queue_size (that is an event COUNT, not bytes).
    rm_config->max_inflight_bytes =
        getDefine_Int_default("remoted", "max_inflight_bytes", 1048576, 1073741824, 268435456);
    // max_parallel_connections caps simultaneous HTTPS connections, bounding the read-phase
    // memory peak (~ max_parallel_connections * max body size). It is also the ONLY bound on
    // concurrent streamed responses (POST /download): chunked output rearms http_write_timeout
    // per chunk, so a client that keeps reading slowly can hold a transfer open indefinitely.
    // A mass upgrade (the whole fleet fetching a WPK at once, many over slow links) is therefore
    // bounded only by this value, which is why it is settable rather than fixed.
    rm_config->max_parallel_connections = getDefine_Int_default("remoted", "max_parallel_connections", 1, 65536, 512);
    // max_deferred_requests caps requests parked awaiting a downstream service (503 over it).
    // No Retry-After is sent: the agent runs its own retry/backoff on a 503.
    rm_config->max_deferred_requests = getDefine_Int_default("remoted", "max_deferred_requests", 1, 65536, 256);

    // Downstream (async UDS client to the engine's event ingress) tunables.
    rm_config->downstream_connect_timeout = getDefine_Int_default("remoted", "downstream_connect_timeout", 1, 60, 2);
    rm_config->downstream_write_timeout = getDefine_Int_default("remoted", "downstream_write_timeout", 1, 300, 5);
    rm_config->downstream_response_timeout = getDefine_Int_default("remoted", "downstream_response_timeout", 1, 300, 5);
    // /stateful gets its own (longer) response deadline: a sync session is indexed and flushed
    // within the request. The default (2+5+20 s) deliberately stays inside http_request_timeout's
    // default (30 s); raising this past that also requires raising remoted.http_request_timeout
    // (the module warns at startup otherwise).
    rm_config->downstream_stateful_response_timeout =
        getDefine_Int_default("remoted", "downstream_stateful_response_timeout", 1, 3600, 20);
    rm_config->downstream_io_threads = getDefine_Int_default("remoted", "downstream_io_threads", 0, 256, 0);
    rm_config->downstream_post_process_threads = getDefine_Int_default("remoted", "downstream_post_process_threads", 0, 256, 0);
    rm_config->downstream_max_response_body_size =
        getDefine_Int_default("remoted", "downstream_max_response_body_size", 1048576, 67108864, 10485760);

    // Auth middleware (AES-CMAC request verification) tunables.
    rm_config->auth_max_request_age = getDefine_Int_default("remoted", "auth_max_request_age", 1, 3600, 300);
    rm_config->auth_max_future_skew = getDefine_Int_default("remoted", "auth_max_future_skew", 1, 300, 30);
    rm_config->auth_max_body_size = getDefine_Int_default("remoted", "auth_max_body_size", 1048576, 67108864, 10485760);
}

/**
 * @brief Build the config struct passed to remoted_module_start(), combining the
 *        `remoted.http_*` internal options (see remoted_module_https_config()) with
 *        the `<remote><https>` settings parsed into `logr`, plus the memory-management
 *        constants that are deliberately not internal options. Extracted out of
 *        HandleSecure() so it's unit-testable without starting the module.
 */
STATIC void w_remoted_build_module_config(const remoted *logr, remoted_module_config_t *rm_config) {
    memset(rm_config, 0, sizeof(*rm_config));

    // rm_config->port is the HTTPS listening port -- unrelated to logr->port (remoted's
    // own classic TCP/UDP port, already bound by the time we get here). Populated
    // from <remote><https> when configured; otherwise left at 0 so the module falls
    // back to its own default.
    rm_config->port = logr->https.port;
    remoted_module_https_config(rm_config);
    rm_config->keystore_refresh_interval = keyupdate_interval;
    rm_config->worker_node = logr->worker_node;
    rm_config->verification_mode = logr->https.verification_mode;
    rm_config->http_max_body_size = logr->https.max_body_size;
    rm_config->dual_stack = logr->https.dual_stack;

    if (logr->https.bind_addr) {
        snprintf(rm_config->bind_address, sizeof(rm_config->bind_address), "%s", logr->https.bind_addr);
    }

    if (logr->https.certificate) {
        snprintf(rm_config->certificate_path, sizeof(rm_config->certificate_path), "%s", logr->https.certificate);
    }

    if (logr->https.key) {
        snprintf(rm_config->private_key_path, sizeof(rm_config->private_key_path), "%s", logr->https.key);
    }

    if (logr->https.ca) {
        snprintf(rm_config->ca_path, sizeof(rm_config->ca_path), "%s", logr->https.ca);
    }

    if (logr->https.ciphers) {
        snprintf(rm_config->ciphers, sizeof(rm_config->ciphers), "%s", logr->https.ciphers);
    }
}

STATIC char* build_limits_json(const module_limits_t *limits) {
    if (!limits) {
        return NULL;
    }

    cJSON *limits_obj = cJSON_CreateObject();
    if (!limits_obj) {
        return NULL;
    }

    /* FIM limits */
    cJSON *fim = cJSON_CreateObject();
    if (fim) {
        cJSON_AddNumberToObject(fim, "file", limits->fim.file);
        cJSON_AddNumberToObject(fim, "registry_key", limits->fim.registry_key);
        cJSON_AddNumberToObject(fim, "registry_value", limits->fim.registry_value);
        cJSON_AddItemToObject(limits_obj, "fim", fim);
    }

    /* Syscollector limits */
    cJSON *syscollector = cJSON_CreateObject();
    if (syscollector) {
        cJSON_AddNumberToObject(syscollector, "hotfixes", limits->syscollector.hotfixes);
        cJSON_AddNumberToObject(syscollector, "packages", limits->syscollector.packages);
        cJSON_AddNumberToObject(syscollector, "processes", limits->syscollector.processes);
        cJSON_AddNumberToObject(syscollector, "ports", limits->syscollector.ports);
        cJSON_AddNumberToObject(syscollector, "network_iface", limits->syscollector.network_iface);
        cJSON_AddNumberToObject(syscollector, "network_protocol", limits->syscollector.network_protocol);
        cJSON_AddNumberToObject(syscollector, "network_address", limits->syscollector.network_address);
        cJSON_AddNumberToObject(syscollector, "hardware", limits->syscollector.hardware);
        cJSON_AddNumberToObject(syscollector, "os_info", limits->syscollector.os_info);
        cJSON_AddNumberToObject(syscollector, "users", limits->syscollector.users);
        cJSON_AddNumberToObject(syscollector, "groups", limits->syscollector.groups);
        cJSON_AddNumberToObject(syscollector, "services", limits->syscollector.services);
        cJSON_AddNumberToObject(syscollector, "browser_extensions", limits->syscollector.browser_extensions);
        cJSON_AddItemToObject(limits_obj, "syscollector", syscollector);
    }

    /* SCA limits */
    cJSON *sca = cJSON_CreateObject();
    if (sca) {
        cJSON_AddNumberToObject(sca, "checks", limits->sca.checks);
        cJSON_AddItemToObject(limits_obj, "sca", sca);
    }

    char *json_str = cJSON_PrintUnformatted(limits_obj);
    cJSON_Delete(limits_obj);

    return json_str;
}

STATIC void remoted_module_control_config(remoted_module_config_t *rm_config) {
    snprintf(rm_config->manager_version, sizeof(rm_config->manager_version), "%s", __wazuh_version);
    rm_config->allow_higher_versions = logr.allow_higher_versions;

    rm_config->groups_refresh_interval_sec = getDefine_Int_default("remoted", "control_groups_refresh_interval", 1, 3600, 60);
    rm_config->wdb_request_connections = getDefine_Int_default("remoted", "control_wdb_request_connections", 1, 64, 4);
    rm_config->wdb_roundtrip_deadline_ms = getDefine_Int_default("remoted", "control_wdb_roundtrip_deadline", 100, 30000, 2000);
    rm_config->wdb_max_queue_size = getDefine_Int_default("remoted", "control_wdb_max_queue_size", 100, 1000000, 10000);
    rm_config->tm_concurrency = getDefine_Int_default("remoted", "control_tm_concurrency", 1, 64, 4);
    rm_config->tm_deadline_ms = getDefine_Int_default("remoted", "control_tm_deadline", 100, 30000, 2000);
    rm_config->tm_max_queue_size = getDefine_Int_default("remoted", "control_tm_max_queue_size", 100, 1000000, 10000);

    extern module_limits_t manager_module_limits;
    extern bool manager_module_limits_enabled;

    if (manager_module_limits_enabled) {
        char *limits_json = build_limits_json(&manager_module_limits);
        if (limits_json) {
            snprintf(rm_config->limits_json, sizeof(rm_config->limits_json), "%s", limits_json);
            os_free(limits_json);
        } else {
            snprintf(rm_config->limits_json, sizeof(rm_config->limits_json), "{}");
        }
    } else {
        snprintf(rm_config->limits_json, sizeof(rm_config->limits_json), "{}");
    }
}

/* Handle secure connections */
void HandleSecure()
{
    const int protocol = logr.proto;
    int n_events = 0;

    agent_metadata_init();
    legacy_task_delivery_init();

    control_msg_queue = indexed_queue_init(ctrl_msg_queue_size);
    indexed_queue_set_dispose(control_msg_queue, (void (*)(void *))w_free_ctrl_msg_data);
    indexed_queue_set_get_key(control_msg_queue, w_ctrl_msg_get_key);

    events_queue = batch_queue_init(batch_events_capacity);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);
    batch_queue_set_get_item_bytes(events_queue, evt_item_get_bytes);
    batch_queue_set_agent_max(events_queue, batch_events_per_agent_capacity);
    batch_queue_set_bytes_limit(events_queue, batch_events_max_bytes);

    uhttp_global_init();

    struct sockaddr_storage peer_info;
    memset(&peer_info, 0, sizeof(struct sockaddr_storage));

    /* Global stats uptime */
    remoted_state.uptime = time(NULL);

    /* Initialize manager */
    manager_init();

    // Initialize message queue
    rem_msginit(logr.queue_size);
    rem_set_input_queue_max_bytes(queue_max_bytes);

    /* Initialize the agent key table mutex */
    key_lock_init();

    /* Create current timestamp getter thread */
    w_create_thread(current_timestamp, NULL);

    /* Create shared file updating thread */
    w_create_thread(update_shared_files, NULL);

    /* Create Active Response forwarder thread */
    w_create_thread(AR_Forward, NULL);

    // Initialize request module
    req_init();

    // Create com request thread
    w_create_thread(remcom_main, NULL);

    // Create legacy (< v5.0.0) remote_upgrade task delivery poller thread
    w_create_thread(legacy_upgrade_task_delivery, NULL);

    /* Create wait_for_msgs threads */
    {
        mdebug2("Creating %d sender threads.", sender_pool);

        for (int i = 0; i < sender_pool; i++) {
            w_create_thread(wait_for_msgs, NULL);
        }
    }

    // Reset all the agents' connection status in Wazuh DB
    // The master will disconnect and alert the agents on its own DB. Thus, synchronization is not required.
    if (OS_SUCCESS != wdb_reset_agents_connection("synced", NULL))
        mwarn("Unable to reset the agents' connection status. Possible incorrect statuses until the agents get connected to the manager.");

    // Launch the remoted C++ module in its own thread, seeded with a config struct.
    {
        remoted_module_config_t rm_config;
        w_remoted_build_module_config(&logr, &rm_config);
        remoted_module_control_config(&rm_config);

        char *rm_cluster_name = get_cluster_name();
        if (rm_cluster_name) {
            snprintf(rm_config.cluster_name, sizeof(rm_config.cluster_name), "%s", rm_cluster_name);
            os_free(rm_cluster_name);
        }

        remoted_module_start(mtLoggingFunctionsWrapper, &rm_config);
        atexit(remoted_module_stop);
    }

    // Create upsert control message thread
    w_create_thread(save_control_thread, (void *) control_msg_queue);

    // Create dispatch events thread
    w_create_thread(dispach_events_thread, (void *) events_queue);

    /* Create agent metadata cache cleanup thread (after events_queue is initialized) */
    w_create_thread(agent_meta_cleanup_thread, events_queue);

    rem_handler_args_t *worker_args;
    os_malloc(sizeof(*worker_args), worker_args);
    worker_args->control_msg_queue = control_msg_queue;
    worker_args->events_queue      = events_queue;
    // Create message handler thread pool
    {
        // Initialize FD list and counter.
        global_counter = 0;
        rem_initList(FD_LIST_INIT_VALUE);
        for (int i = 0; i < worker_pool; i++) {
            w_create_thread(rem_handler_main, worker_args);
        }
    }

    /* Start up message */
    {
        char *_protocol = NULL;
        if (logr.proto & REMOTED_NET_PROTOCOL_TCP) {
            wm_strcat(&_protocol, REMOTED_NET_PROTOCOL_TCP_STR, 0);
        }
        if (logr.proto & REMOTED_NET_PROTOCOL_UDP) {
            wm_strcat(&_protocol, REMOTED_NET_PROTOCOL_UDP_STR, _protocol ? ',' : 0);
        }
        minfo(STARTUP_MSG " Listening on port %d/%s (secure).",
            (int)getpid(),
            logr.port,
            _protocol ? _protocol : "unknown");
        os_free(_protocol);
    }

    /* Read authentication keys */
    mdebug1(ENC_READ);

    key_lock_write();
    OS_ReadKeys(&keys, W_ENCRYPTION_KEY, 0);
    key_unlock();

    OS_StartCounter(&keys);

    // Key reloader thread
    w_create_thread(rem_keyupdate_main, NULL);

    // fp closer thread
    w_create_thread(close_fp_main, &keys);

    /* Set up peer size */
    logr.peer_size = sizeof(peer_info);

    /* Events watcher is started (is used to monitor sockets events) */
    if (notify = wnotify_init(MAX_EVENTS), !notify) {
        merror_exit("wnotify_init(): %s (%d)", strerror(errno), errno);
    }

    /* If TCP is set on the config, then the corresponding sockets is added to the watching list  */
    if (protocol & REMOTED_NET_PROTOCOL_TCP) {
        if (wnotify_add(notify, logr.tcp_sock, WO_READ) < 0) {
            merror_exit("wnotify_add(%d): %s (%d)", logr.tcp_sock, strerror(errno), errno);
        }
    }

    /* If UDP is set on the config, then the corresponding sockets is added to the watching list  */
    if (protocol & REMOTED_NET_PROTOCOL_UDP) {
        if (wnotify_add(notify, logr.udp_sock, WO_READ) < 0) {
            merror_exit("wnotify_add(%d): %s (%d)", logr.udp_sock, strerror(errno), errno);
        }
    }

    while (1) {

        /* It waits for a socket event */
        if (n_events = wnotify_wait(notify, EPOLL_MILLIS), n_events < 0) {
            if (errno != EINTR) {
                merror("Waiting for connection: %s (%d)", strerror(errno), errno);
                sleep(1);
            }

            continue;
        }

        for (int i = 0u; i < n_events; i++) {
            // Returns the fd of the socket that recived a message
            wevent_t event;
            int fd = wnotify_get(notify, i, &event);

            // In case of failure or unexpected file descriptor
            if (fd <= 0) {
                merror("Unexpected file descriptor: %d, %s (%d)", fd, strerror(errno), errno);
                continue;
            }
            // If a new TCP connection was received and TCP is enabled
            else if ((fd == logr.tcp_sock) && (protocol & REMOTED_NET_PROTOCOL_TCP)) {
                handle_new_tcp_connection(notify, &peer_info);
            }
            // If a new UDP connection was received and UDP is enabled
            else if ((fd == logr.udp_sock) && (protocol & REMOTED_NET_PROTOCOL_UDP)) {
                handle_incoming_data_from_udp_socket(&peer_info);
            }
            // If a message was received through a TCP client and tcp is enabled
            else if ((protocol & REMOTED_NET_PROTOCOL_TCP) && (event & WE_READ)) {
                handle_incoming_data_from_tcp_socket(fd);
            }
            // If a TCP client socket is ready for sending and tcp is enabled
            else if ((protocol & REMOTED_NET_PROTOCOL_TCP) && (event & WE_WRITE)) {
                handle_outgoing_data_to_tcp_socket(fd);
            }
        }
    }

    manager_free();
}

STATIC void handle_new_tcp_connection(wnotify_t * notify, struct sockaddr_storage * peer_info)
{
    int sock_client = accept(logr.tcp_sock, (struct sockaddr *) peer_info, &logr.peer_size);

    if (sock_client >= 0) {
        nb_open(&netbuffer_recv, sock_client, peer_info);
        nb_open(&netbuffer_send, sock_client, peer_info);

        rem_inc_tcp();

        mdebug1("New TCP connection [%d]", sock_client);

        if (wnotify_add(notify, sock_client, WO_READ) < 0) {
            merror("wnotify_add(%d, %d): %s (%d)", notify->fd, sock_client, strerror(errno), errno);
            _close_sock(&keys, sock_client);
        }
    } else {
        switch (errno) {
        case ECONNABORTED:
            mdebug1(ACCEPT_ERROR, strerror(errno), errno);
            break;
        default:
            merror(ACCEPT_ERROR, strerror(errno), errno);
        }
    }
}

STATIC void handle_incoming_data_from_udp_socket(struct sockaddr_storage * peer_info)
{
    char buffer[OS_MAXSTR + 1];
    memset(buffer, '\0', OS_MAXSTR + 1);

    int recv_b = recvfrom(logr.udp_sock, buffer, OS_MAXSTR, 0, (struct sockaddr *) peer_info, &logr.peer_size);

    if (recv_b > 0) {
        rem_msgpush(buffer, recv_b, peer_info, USING_UDP_NO_CLIENT_SOCKET);
        rem_add_recv((unsigned long) recv_b);
    }
}

STATIC void handle_incoming_data_from_tcp_socket(int sock_client)
{
    int recv_b = nb_recv(&netbuffer_recv, sock_client);

    switch (recv_b) {
    case -2:
        mwarn("Too big message size from socket [%d].", sock_client);
        _close_sock(&keys, sock_client);
        return;

    case -1:
        switch (errno) {
        case ECONNRESET:
        case ENOTCONN:
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
        case ETIMEDOUT:
            mdebug1("TCP peer [%d]: %s (%d)", sock_client, strerror(errno), errno);
            break;
        default:
            merror("TCP peer [%d]: %s (%d)", sock_client, strerror(errno), errno);
        }
        WFALLTHROUGH;
    case 0:
        mdebug1("handle incoming close socket [%d].", sock_client);
        _close_sock(&keys, sock_client);
        return;

    default:
        rem_add_recv((unsigned long) recv_b);
    }
}

STATIC void handle_outgoing_data_to_tcp_socket(int sock_client)
{
    int sent_b = nb_send(&netbuffer_send, sock_client);

    switch (sent_b) {
    case -1:
        mdebug1("TCP peer [%d]: %s (%d)", sock_client, strerror(errno), errno);

        switch (errno) {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
            break;
        case EPIPE:
        case EBADF:
        case ECONNRESET:
        default:
            mdebug1("handle outgoing close socket [%d].", sock_client);
            _close_sock(&keys, sock_client);
        }
        return;

    default:
        rem_add_send((unsigned long) sent_b);
    }
}

// Message handler thread
void * rem_handler_main(void * args) {
    message_t * message;
    rem_handler_args_t *queues = (rem_handler_args_t*)args;
    w_indexed_queue_t *control_msg_queue = queues->control_msg_queue;
    w_rr_queue_t      *events_queue      = queues->events_queue;

    mdebug1("Message handler thread started.");

    while (1) {
        message = rem_msgpop();
        HandleSecureMessage(message, control_msg_queue, events_queue);
        rem_msgfree(message);
    }

    return NULL;
}

// Key reloader thread
void * rem_keyupdate_main(__attribute__((unused)) void * args) {
    mdebug1("Key reloader thread started.");

    while (1) {
        mdebug2("Checking for keys file changes.");
        if (check_keyupdate() == 1) {
            rem_inc_keys_reload();
        }
        sleep(keyupdate_interval);
    }
}

// Closer rids thread
STATIC void * close_fp_main(void * args) {
    keystore * keys = (keystore *)args;
    int seconds;
    int flag;

    mdebug1("Rids closer thread started.");
    seconds = logr.rids_closing_time;

    while (1) {
        sleep(seconds);
        key_lock_write();
        flag = 1;
        while (flag) {
            w_linked_queue_node_t * first_node = keys->opened_fp_queue->first;
            mdebug2("Opened rids queue size: %d", keys->opened_fp_queue->elements);
            if (first_node) {
                int now = time(0);
                keyentry * first_node_key = (keyentry *)first_node->data;
                mdebug2("Checking rids_node of agent %s.", first_node_key->id);
                if ((now - seconds) > first_node_key->updating_time) {
                    first_node_key = (keyentry *)linked_queue_pop_ex(keys->opened_fp_queue);
                    w_mutex_lock(&first_node_key->mutex);
                    mdebug2("Pop rids_node of agent %s.", first_node_key->id);
                    if (first_node_key->fp != NULL) {
                        mdebug2("Closing rids for agent %s.", first_node_key->id);
                        fclose(first_node_key->fp);
                        first_node_key->fp = NULL;
                    }
                    first_node_key->updating_time = 0;
                    first_node_key->rids_node = NULL;
                    w_mutex_unlock(&first_node_key->mutex);
                } else {
                    flag = 0;
                }
            } else {
                flag = 0;
            }
        }
        key_unlock();
    #ifdef WAZUH_UNIT_TESTING
        break;
    #endif
    }
    return NULL;
}

STATIC void HandleSecureMessage(const message_t *message, w_indexed_queue_t * control_msg_queue, w_rr_queue_t * batch_queue) {
    int agentid;
    const int protocol = (message->sock == USING_UDP_NO_CLIENT_SOCKET) ? REMOTED_NET_PROTOCOL_UDP : REMOTED_NET_PROTOCOL_TCP;
    char cleartext_msg[OS_MAXSTR + 1];
    char srcmsg[OS_FLSIZE + 1];
    char srcip[IPSIZE + 1] = {0};
    char agname[KEYSIZE + 1] = {0};
    char *agentid_str = NULL;
    char buffer[OS_MAXSTR + 1] = "";
    char *tmp_msg;
    size_t msg_length;
    int r;
    int recv_b = message->size;
    int sock_idle = -1;

    /* Set the source IP */
    switch (message->addr.ss_family) {
    case AF_INET:
        get_ipv4_string(((struct sockaddr_in *)&message->addr)->sin_addr, srcip, IPSIZE);
        break;
    case AF_INET6:
        get_ipv6_string(((struct sockaddr_in6 *)&message->addr)->sin6_addr, srcip, IPSIZE);
        break;
    default:
        if (message->addr.ss_family < sizeof(str_family_address)/sizeof(str_family_address[0])) {
            merror("IP address family '%d':'%s' not supported.", message->addr.ss_family, str_family_address[message->addr.ss_family]);
        }
        else {
            merror("IP address family '%d' not found.", message->addr.ss_family);
        }

        rem_inc_recv_unknown();
        return;
    }

    /* Initialize some variables */
    memset(cleartext_msg, '\0', OS_MAXSTR + 1);
    memset(srcmsg, '\0', OS_FLSIZE + 1);
    tmp_msg = NULL;
    memcpy(buffer, message->buffer, recv_b);

    /* Get a valid agent id */
    if (buffer[0] == '!') {
        tmp_msg = buffer;
        tmp_msg++;

        /* We need to make sure that we have a valid id
         * and that we reduce the recv buffer size
         */
        while (isdigit((int)*tmp_msg)) {
            tmp_msg++;
            recv_b--;
        }

        if (*tmp_msg != '!') {
            merror(ENCFORMAT_ERROR, "(unknown)", srcip);

            if (message->sock >= 0) {
                _close_sock(&keys, message->sock);
            }

            rem_inc_recv_unknown();
            return;
        }

        *tmp_msg = '\0';
        tmp_msg++;
        recv_b -= 2;

        key_lock_read();
        agentid = OS_IsAllowedDynamicID(&keys, buffer + 1, srcip);

        if (agentid == -1) {
            int id = OS_IsAllowedID(&keys, buffer + 1);

            if (id < 0) {
                snprintf(agname, sizeof(agname), "unknown");
            } else {
                snprintf(agname, sizeof(agname), "%s", keys.keyentries[id]->name);
            }

            key_unlock();

            mwarn(ENC_IP_ERROR, buffer + 1, srcip, agname);

            rem_inc_recv_unknown();
            return;
        } else {
            w_mutex_lock(&keys.keyentries[agentid]->mutex);

            if ((keys.keyentries[agentid]->sock >= 0) && (keys.keyentries[agentid]->sock != message->sock)) {
                if ((logr.connection_overtake_time > 0) && (current_ts - keys.keyentries[agentid]->rcvd) > logr.connection_overtake_time) {
                    sock_idle = keys.keyentries[agentid]->sock;

                    mdebug2("Idle socket [%d] from agent ID '%s' will be closed.", sock_idle, keys.keyentries[agentid]->id);

                    keys.keyentries[agentid]->rcvd = current_ts;
                    keys.keyentries[agentid]->conflict_ts = 0;
                } else {
                    // Warn only if the conflict outlives the overtake window: a reconnect self-heals,
                    // a shared key does not.
                    if (keys.keyentries[agentid]->conflict_ts == 0) {
                        keys.keyentries[agentid]->conflict_ts = current_ts;
                    }

                    if ((logr.connection_overtake_time <= 0) || (current_ts - keys.keyentries[agentid]->conflict_ts) > logr.connection_overtake_time) {
                        mwarn("Agent key already in use: agent ID '%s' (source IP: %s)", keys.keyentries[agentid]->id, srcip);
                    } else {
                        mdebug2("Agent ID '%s' reconnected from '%s' before its previous session was closed.", keys.keyentries[agentid]->id, srcip);
                    }

                    w_mutex_unlock(&keys.keyentries[agentid]->mutex);
                    key_unlock();

                    if (message->sock >= 0) {
                        _close_sock(&keys, message->sock);
                    }

                    rem_inc_recv_unknown();
                    return;
                }
            }

            w_mutex_unlock(&keys.keyentries[agentid]->mutex);
        }
    } else if (strncmp(buffer, "#ping", 5) == 0) {
            int retval = 0;
            char *msg = "#pong";
            ssize_t msg_size = strlen(msg);

            if (protocol == REMOTED_NET_PROTOCOL_UDP) {
                retval = sendto(logr.udp_sock, msg, msg_size, 0, (struct sockaddr *)&message->addr, logr.peer_size) == msg_size ? 0 : -1;
            } else {
                retval = OS_SendSecureTCP(message->sock, msg_size, msg);
            }

            if (retval < 0) {
                mwarn("Ping operation could not be delivered completely (%d)", retval);
            }

            rem_inc_recv_ping();
            return;

    } else {
        key_lock_read();

        agentid = OS_IsAllowedIP(&keys, srcip);

        if (agentid < 0) {
            key_unlock();

            mwarn(DENYIP_WARN " Source agent ID is unknown.", srcip);

            rem_inc_recv_unknown();
            return;
        } else {
            w_mutex_lock(&keys.keyentries[agentid]->mutex);

            if ((keys.keyentries[agentid]->sock >= 0) && (keys.keyentries[agentid]->sock != message->sock)) {
                if ((logr.connection_overtake_time > 0) && (current_ts - keys.keyentries[agentid]->rcvd) > logr.connection_overtake_time) {
                    sock_idle = keys.keyentries[agentid]->sock;

                    mdebug2("Idle socket [%d] from agent ID '%s' will be closed.", sock_idle, keys.keyentries[agentid]->id);

                    keys.keyentries[agentid]->rcvd = current_ts;
                    keys.keyentries[agentid]->conflict_ts = 0;
                } else {
                    // Warn only if the conflict outlives the overtake window: a reconnect self-heals,
                    // a shared key does not.
                    if (keys.keyentries[agentid]->conflict_ts == 0) {
                        keys.keyentries[agentid]->conflict_ts = current_ts;
                    }

                    if ((logr.connection_overtake_time <= 0) || (current_ts - keys.keyentries[agentid]->conflict_ts) > logr.connection_overtake_time) {
                        mwarn("Agent key already in use: agent ID '%s' (source IP: %s)", keys.keyentries[agentid]->id, srcip);
                    } else {
                        mdebug2("Agent ID '%s' reconnected from '%s' before its previous session was closed.", keys.keyentries[agentid]->id, srcip);
                    }

                    w_mutex_unlock(&keys.keyentries[agentid]->mutex);
                    key_unlock();

                    if (message->sock >= 0) {
                        _close_sock(&keys, message->sock);
                    }

                    rem_inc_recv_unknown();
                    return;
                }
            }

            w_mutex_unlock(&keys.keyentries[agentid]->mutex);
        }

        tmp_msg = buffer;
    }

    if (recv_b <= 0) {
        mwarn("Received message is empty from '%s'", srcip);
        key_unlock();
        if (message->sock >= 0) {
            _close_sock(&keys, message->sock);
        }

        if (sock_idle >= 0) {
            _close_sock(&keys, sock_idle);
        }

        rem_inc_recv_unknown();
        return;
    }

    /* Decrypt the message */
    if (r = ReadSecMSG(&keys, tmp_msg, cleartext_msg, agentid, recv_b - 1, &msg_length, srcip, &tmp_msg), r != KS_VALID) {
        /* If duplicated, a warning was already generated */
        key_unlock();

        if (message->sock >= 0) {
            mwarn("Decrypt the message fail from '%s', socket %d", srcip, message->sock);
            _close_sock(&keys, message->sock);
        }

        if (sock_idle >= 0) {
            _close_sock(&keys, sock_idle);
        }

        rem_inc_recv_unknown();
        return;
    }

    if (msg_length > OS_MAXSTR)
    {
        mwarn("Message length (%zu) exceeds maximum allowed size (%d) from agent '%s'",
              msg_length,
              OS_MAXSTR,
              keys.keyentries[agentid]->id);
        key_unlock();

        if (message->sock >= 0)
        {
            _close_sock(&keys, message->sock);
        }

        if (sock_idle >= 0)
        {
            _close_sock(&keys, sock_idle);
        }

        rem_inc_recv_unknown();
        return;
    }

    /* Recieved valid message timestamp updated. */
    keys.keyentries[agentid]->rcvd = current_ts;

    /* Check if it is a control message */
    if (IsValidHeader(tmp_msg)) {

        /* let through new and shutdown messages */
        if (message->sock == USING_UDP_NO_CLIENT_SOCKET || message->counter > rem_getCounter(message->sock) || (strncmp(tmp_msg, HC_SHUTDOWN, strlen(HC_SHUTDOWN)) == 0)) {
            /* We need to save the peerinfo if it is a control msg */

            w_mutex_lock(&keys.keyentries[agentid]->mutex);
            keys.keyentries[agentid]->net_protocol = protocol;
            memcpy(&keys.keyentries[agentid]->peer_info, &message->addr, logr.peer_size);

            keyentry * key = OS_DupKeyEntry(keys.keyentries[agentid]);

            if (protocol == REMOTED_NET_PROTOCOL_TCP) {
                if (sock_idle >= 0 || message->counter > rem_getCounter(message->sock)) {
                    keys.keyentries[agentid]->sock = message->sock;
                }

                w_mutex_unlock(&keys.keyentries[agentid]->mutex);

                if ((strncmp(tmp_msg, HC_SHUTDOWN, strlen(HC_SHUTDOWN)) != 0)) {
                    r = OS_AddSocket(&keys, agentid, message->sock);

                    switch (r) {
                    case OS_ADDSOCKET_ERROR:
                        merror("Couldn't add TCP socket to keystore.");
                        break;
                    case OS_ADDSOCKET_KEY_UPDATED:
                        mdebug2("TCP socket %d already in keystore. Updating...", message->sock);
                        break;
                    case OS_ADDSOCKET_KEY_ADDED:
                        mdebug2("TCP socket %d added to keystore.", message->sock);
                        break;
                    default:
                        ;
                    }
                }
            } else {
                keys.keyentries[agentid]->sock = USING_UDP_NO_CLIENT_SOCKET;
                w_mutex_unlock(&keys.keyentries[agentid]->mutex);
            }

            // Validate control message before unlocking to update startup status safely
            char *cleaned_msg = NULL;
            int is_startup = 0, is_shutdown = 0;
            size_t tmp_msg_length = msg_length - 3; // Exclude the header length (3 characters)
            int validation_result = validate_control_msg(key, tmp_msg, tmp_msg_length, &cleaned_msg, &is_startup, &is_shutdown);

            // Update keystore startup status immediately after validation
            if (is_startup) {
                keys.keyentries[agentid]->post_startup = true;
            }

            // Read post_startup state before unlocking
            bool post_startup = keys.keyentries[agentid]->post_startup;

            key_unlock();

            if (sock_idle >= 0) {
                _close_sock(&keys, sock_idle);
            }

            rem_inc_recv_ctrl();

            if (validation_result == 1) {
                // Message should be queued for database processing
                w_ctrl_msg_data_t * ctrl_msg_data;
                os_calloc(1, sizeof(w_ctrl_msg_data_t), ctrl_msg_data);

                /* Parsing msg */
                {
                    agent_info_data *agent_data;
                    os_calloc(1, sizeof(agent_info_data), agent_data);

                    // Text keepalive from 4.x agent
                    int result = parse_agent_update_msg(tmp_msg, agent_data);

                    if (OS_SUCCESS == result) {
                        // Build metadata from parsed agent_info_data and upsert in the global map
                        agent_meta_t *fresh = agent_meta_from_agent_info(key->id, key->name, agent_data);
                        if (fresh) {
                            if (agent_meta_upsert_locked(key->id, fresh) != 0) {
                                mwarn("Failed to update metadata cache for agent ID '%s'", key->id);
                                agent_meta_free(fresh);
                            }
                        }
                    }

                    wdb_free_agent_info_data(agent_data);
                }

                ctrl_msg_data->key = key;

                os_calloc(tmp_msg_length + 1, sizeof(char), ctrl_msg_data->message);
                // Use cleaned message from validation if available, otherwise use original
                memcpy(ctrl_msg_data->message, cleaned_msg ? cleaned_msg : tmp_msg, tmp_msg_length);

                // Store validation results in the control message data structure
                ctrl_msg_data->is_startup = is_startup;
                ctrl_msg_data->is_shutdown = is_shutdown;
                ctrl_msg_data->post_startup = post_startup;

                // Mark metadata for cleanup on shutdown (will be deleted when queue drains)
                if (is_shutdown) {
                    agent_meta_mark_shutdown(key->id);
                }

                // Use upsert to allow updating existing control messages for the same agent
                int res = indexed_queue_upsert_ex(control_msg_queue, key->id, ctrl_msg_data);
                key = NULL;

                switch (res) {
                case 0:
                    rem_inc_ctrl_queue_inserted();
                    break;
                case 1:
                    rem_inc_ctrl_queue_replaced();
                    break;
                default:
                    w_free_ctrl_msg_data(ctrl_msg_data);
                }
            } else if (validation_result == 0) {
                // Message was handled directly (HC_REQUEST), don't queue it
                mdebug2("Control message processed directly, not queued.");
                OS_FreeKey(key);
            } else {
                // Error in validation
                mwarn("Error validating control message from agent ID '%s'.", key->id);
                OS_FreeKey(key);
            }

            // Free cleaned message if allocated
            if (cleaned_msg) {
                os_free(cleaned_msg);
            }

        } else {
            key_unlock();
            rem_inc_recv_dequeued();
        }
        return;
    }

    os_strdup(keys.keyentries[agentid]->id, agentid_str);

    key_unlock();

    if (sock_idle >= 0) {
        _close_sock(&keys, sock_idle);
    }

    // Discard DBSYNC messages from 4.x agents (not supported in 5.0)
    if (strncmp(tmp_msg, DBSYNC_HEADER, DBSYNC_HEADER_SIZE) == 0) {
        mdebug2("Discarding DBSYNC message from 4.x agent '%s' (not supported in 5.0)", agentid_str);
        os_free(agentid_str);
        return;
    }

    // Legacy message types the 5.x manager no longer processes are discarded here, BEFORE the
    // analysisd enqueue: letting them fall through would inject binary payloads as events.
    if (discard_legacy_agent_message(tmp_msg, agentid_str)) {
        os_free(agentid_str);
        return;
    }

    /* Trim trailing nulls from analysisd-bound events. */
    size_t stripped_nulls = 0;
    while (msg_length > 0 && tmp_msg[msg_length - 1] == '\0') {
        msg_length--;
        stripped_nulls++;
    }
    if (stripped_nulls > 0) {
        mdebug1("Stripped %zu trailing null byte(s) from event payload of agent '%s'",
                stripped_nulls, agentid_str);
    }

    evt_item_t *e; os_calloc(1, sizeof(*e), e);
    os_calloc(msg_length + 1, sizeof(char), e->raw);
    memcpy(e->raw, tmp_msg, msg_length);
    e->len = msg_length;

    int rc = batch_queue_enqueue_ex(batch_queue, agentid_str, e);
    if (rc < 0) {
        dispose_evt_item(e);
        rem_inc_recv_events_failed();
        maybe_log_events_queue_drop();
    } else {
        rem_inc_recv_events();
    }

    os_free(agentid_str);
}

STATIC bool discard_legacy_agent_message(const char* msg, const char* agent_id) {

    if (strncmp(msg, INVENTORY_SYNC_HEADER, INVENTORY_SYNC_HEADER_SIZE) == 0) {
        // Since 5.x, stateful synchronization only enters through remoted's authenticated
        // POST /stateful route as a whole FullSession, so the old chunked wire protocol has
        // nowhere to go. Discarded, not an error: it is a not-yet-updated agent, not an attack.
        mdebug2("Discarding legacy stateful-sync message from agent '%s' (since 5.x the manager only accepts "
                "whole sessions over POST /stateful)", agent_id);
        return true;
    }

    if (strncmp(msg, UPGRADE_ACK_HEADER, UPGRADE_ACK_HEADER_SIZE) == 0) {
        // Parse just enough of the ack to confirm it's a valid upgrade_update_status message and
        // reply with clear_upgrade_result, which is what stops the agent's own retry loop (see
        // legacy_task_delivery.c). NOT discarded: the ack still falls through to the normal
        // analysisd/Engine event path (batch_queue_enqueue_ex) like any other agent message.
        legacy_task_process_upgrade_ack(agent_id, msg + UPGRADE_ACK_HEADER_SIZE);
        mdebug2("Upgrade acknowledgment from agent '%s' routed to the normal event path", agent_id);
        return false;
    }

    return false;
}

// Close and remove socket from keystore
int _close_sock(keystore * keys, int sock) {
    int retval = 0;

    rem_setCounter(sock, global_counter);

    key_lock_read();
    retval = OS_DeleteSocket(keys, sock);
    key_unlock();

    if (!close(sock)) {
        nb_close(&netbuffer_recv, sock);
        nb_close(&netbuffer_send, sock);
        rem_dec_tcp();
    }

    mdebug1("TCP peer disconnected [%d]", sock);

    return retval;
}

/* Get current timestamp */
void *current_timestamp(__attribute__((unused)) void *none)
{
    while (1) {
        current_ts = time(NULL);
        sleep(1);
    }

    return NULL;
}

// Save control message thread
void * save_control_thread(void * control_msg_queue)
{
    assert(control_msg_queue != NULL);
    w_indexed_queue_t * queue = (w_indexed_queue_t *)control_msg_queue;
    w_ctrl_msg_data_t * ctrl_msg_data = NULL;
    int wdb_sock = -1;

    while (FOREVER()) {
        if ((ctrl_msg_data = (w_ctrl_msg_data_t *)indexed_queue_pop_ex(queue))) {
            rem_inc_ctrl_queue_processed();

            bool post_startup = ctrl_msg_data->post_startup;

            // Process the control message with the validation results
            save_controlmsg(ctrl_msg_data->key, ctrl_msg_data->message,
                          &wdb_sock, &post_startup, ctrl_msg_data->is_startup, ctrl_msg_data->is_shutdown);

            // Update startup flag after processing the first keepalive post-startup
            if (ctrl_msg_data->post_startup != post_startup) {
                key_lock_read();

                // Use efficient tree lookup to find the key index
                int key_index = OS_IsAllowedID(&keys, ctrl_msg_data->key->id);
                if (key_index >= 0 && key_index < (int)keys.keysize) {
                    keys.keyentries[key_index]->post_startup = post_startup;
                }

                key_unlock();
            }

            w_free_ctrl_msg_data(ctrl_msg_data);
        }
    }

    return NULL;
}

const char* infer_os_type(const char *os_platform) {
    if (!os_platform) return NULL;

    if (strcmp(os_platform, "windows") == 0) {
        return "windows";
    } else if (strcmp(os_platform, "darwin") == 0) {
        return "macos";
    } else if (strcmp(os_platform, "bsd") == 0) {
        return "unix";
    } else if (strcmp(os_platform, "unix") == 0 || strcmp(os_platform, "Unix") == 0) {
        return "unix";
    }

    return "linux";
}

// Encode the header ONLY once above the body
static int append_header(dispatch_ctx_t *ctx) {
    if (!ctx || !ctx->agent_id) return -1;
    if (ctx->header_added) return 0;

    // Snapshot metadata for this agent (copies strings into 'snap')
    agent_meta_t snap = {0};
    int have_meta = (agent_meta_snapshot_str(ctx->agent_id, &snap) == 0);

    // --- Build nested JSON: { "agent": { "id", "name", "version", "host": { "architecture", "os": {...} } } } ---
    cJSON *root = cJSON_CreateObject();
    if (!root) goto fail;

    cJSON *wazuh = cJSON_CreateObject();
    cJSON *agent = cJSON_CreateObject();
    cJSON *host  = cJSON_CreateObject();
    cJSON *os    = cJSON_CreateObject();
    if (!agent || !host || !os) { cJSON_Delete(root); goto fail; }

    cJSON_AddItemToObject(root, "wazuh", wazuh);
    cJSON_AddItemToObject(wazuh, "agent", agent);
    cJSON_AddItemToObject(agent, "host", host);
    cJSON_AddItemToObject(host, "os",    os);

    // agent.*
    cJSON_AddStringToObject(agent, "id", ctx->agent_id);
    if (have_meta && snap.agent_name) {
        cJSON_AddStringToObject(agent, "name", snap.agent_name);
    }
    if (have_meta && snap.agent_version) {
        cJSON_AddStringToObject(agent, "version", snap.agent_version);
    }

    // agent.groups (array)
    if (have_meta && snap.groups && snap.groups_count > 0) {
        cJSON *groups_array = cJSON_CreateArray();
        if (groups_array) {
            for (size_t i = 0; i < snap.groups_count; i++) {
                if (snap.groups[i]) {
                    cJSON_AddItemToArray(groups_array, cJSON_CreateString(snap.groups[i]));
                }
            }
            cJSON_AddItemToObject(agent, "groups", groups_array);
        }
    }

    // agent.host.os.*
    if (have_meta && snap.os_name)     cJSON_AddStringToObject(os, "name",     snap.os_name);
    if (have_meta && snap.os_version)  cJSON_AddStringToObject(os, "version",  snap.os_version);
    if (have_meta && snap.os_platform) cJSON_AddStringToObject(os, "platform", snap.os_platform);

    // agent.host.os.type (ECS-compliant)
    if (have_meta && snap.os_type) {
        cJSON_AddStringToObject(os, "type", snap.os_type);
    } else if (have_meta && snap.os_platform) {
        const char *os_type = infer_os_type(snap.os_platform);
        if (os_type) cJSON_AddStringToObject(os, "type", os_type);
    }

    // agent.host.architecture
    if (have_meta && snap.arch) cJSON_AddStringToObject(host, "architecture", snap.arch);

    // agent.host.hostname (only for Linux/macOS, empty for Windows)
    if (have_meta && snap.hostname) cJSON_AddStringToObject(host, "hostname", snap.hostname);

    // Add wazuh.cluster.name and wazuh.cluster.node
    bool has_cluster_info = false;
    cJSON *cluster = cJSON_CreateObject();
    if (wazuh && cluster) {
        if (have_meta && snap.cluster_name && snap.cluster_name[0]) {
            cJSON_AddStringToObject(cluster, "name", snap.cluster_name);
            has_cluster_info = true;
        } else if (cluster_name && strcmp(cluster_name, "undefined") != 0) {
            cJSON_AddStringToObject(cluster, "name", cluster_name);
            has_cluster_info = true;
        }

        if (node_name && strcmp(node_name, "undefined") != 0) {
            cJSON_AddStringToObject(cluster, "node", node_name);
            has_cluster_info = true;
        }

        if (has_cluster_info) {
            cJSON_AddItemToObject(wazuh, "cluster", cluster);
        } else {
            cJSON_Delete(cluster);
        }
    }

    // Emit header line
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) goto fail;

    if (bulk_append_fmt(&ctx->bulk, "H %s\n", json) < 0) {
        free(json);
        goto fail;
    }
    free(json);

    ctx->header_added = 1;

    agent_meta_clear(&snap);
    return 0;

fail:
    agent_meta_clear(&snap);
    return -1;
}

// --- helper: monotonic ms ---
static uint64_t mono_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + ts.tv_nsec / 1000000ull;
}

// Drop-only consumer: free each queued item without building a bulk
static void drop_consumer(void *data, void *user) {
    (void)user;
    mwarn("Dropped event: unable to connect with analysisd");
    rem_inc_recv_events_failed();
    dispose_evt_item((evt_item_t *)data);
}

/**
 * @brief Append event payload with continuation-line indentation.
 *
 * Multi-line payloads contain embedded '\n' characters.  The framing protocol
 * uses "\nE " to delimit events.  To avoid ambiguity when a continuation line
 * begins with "E ", we indent every continuation line with a single space.
 * The receiver strips exactly one leading space from each continuation line to
 * recover the original payload.
 */
static int bulk_append_indented(bulk_t *b, const char *raw, size_t len) {
    const char *p = raw;
    const char *end = raw + len;

    while (p < end) {
        const char *nl = (const char *)memchr(p, '\n', (size_t)(end - p));
        if (!nl) {
            // No more newlines: append the remaining chunk
            return bulk_append(b, p, (size_t)(end - p));
        }
        // Append everything up to and including the '\n'
        size_t chunk = (size_t)(nl - p) + 1;
        if (bulk_append(b, p, chunk) < 0) return -1;
        // Prefix the continuation line with a space
        if (nl + 1 < end) {
            if (bulk_append(b, " ", 1) < 0) return -1;
        }
        p = nl + 1;
    }
    return 0;
}

// Consumer: Only accumulates in ctx->bulk. Releases each item individually.
static void rr_collect_one(void *data, void *user) {
    evt_item_t *e = (evt_item_t*)data;
    dispatch_ctx_t *ctx = (dispatch_ctx_t*)user;

    // Ensure header at the top of the body
    if (!ctx->header_added) {
        if (append_header(ctx) < 0) {
            mwarn("Unable to append header for agent '%s'", ctx->agent_id ?: "?");
        }
    }

    // Event Framing: "E <indented_payload>\n"
    // Continuation lines within multi-line payloads are space-indented to
    // prevent false "\nE " delimiter matches inside event content.
    if (bulk_append_fmt(&ctx->bulk, "E ") < 0 ||
        bulk_append_indented(&ctx->bulk, e->raw, e->len) < 0 ||
        bulk_append(&ctx->bulk, "\n", 1) < 0) {
        mwarn("Unable to append event for agent '%s'", ctx->agent_id ?: "?");
    }

    dispose_evt_item(e);
}

// Thread that dispatches each ring turn as a single POST
void *dispach_events_thread(void *arg) {
    w_rr_queue_t *q = (w_rr_queue_t*)arg;

    uhttp_options_t opt = {
        .unix_socket_path   = ANLSYS_ENRICH_SOCK,           // analysisd unix socket
        .url                = "http://localhost/events/enriched",
        .content_type       = "application/x-wev1",
        .user_agent         = "wazuh-manager-remoted/1.0",
        .timeout_ms         = 5000,
        .connect_timeout_ms = 2000,
        .keepalive          = true
    };

    uhttp_client_t *cli = NULL;
    int    fail_streak = 0;
    uint64_t reopen_at = 0; // circuit breaker reopen time (ms monotonic)

    for (;;) {
        uint64_t now = mono_ms();

        // Try to (re)open client if breaker is closed or backoff elapsed
        if (!cli && now >= reopen_at) {
            cli = uhttp_client_new(&opt);
            if (!cli) {
                // Still offline: increase backoff (cap ~30s) and drain+drop one turn
                fail_streak++;
                uint64_t backoff = 500u << (fail_streak > 6 ? 6 : fail_streak); // 0.5s .. 32s
                if (backoff > 30000u) backoff = 30000u;
                reopen_at = now + backoff;

                // Drain one agent turn and DROP items (do not build a bulk)
                size_t dropped = batch_queue_drain_next_ex(q, /*abstime=*/NULL,
                                                           drop_consumer, /*user=*/NULL,
                                                           /*out_agent_key=*/NULL);
                if (dropped == 0) {
                    // Nothing to drain: small nap to avoid busy loop while offline
                    struct timespec ts = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000 };
                    nanosleep(&ts, NULL);
                }
                continue;
            } else {
                // Back online
                fail_streak = 0;
                reopen_at = 0;
            }
        }

        // If still offline, keep draining and dropping
        if (!cli) {
            (void)batch_queue_drain_next_ex(q, /*abstime=*/NULL,
                                            drop_consumer, /*user=*/NULL,
                                            /*out_agent_key=*/NULL);
            continue;
        }

        // Online path: build one agent batch and POST it
        dispatch_ctx_t ctx = {
            .agent_id     = NULL,
            .header_added = 0
        };
        bulk_init(&ctx.bulk, 8192);

        size_t drained = batch_queue_drain_next_ex(q, /*abstime=*/NULL,
                                                   rr_collect_one, &ctx, &ctx.agent_id);

        if (drained > 0 && ctx.bulk.len > 0) {
            uhttp_result_t res = {0};
            int rc = uhttp_post(cli, ctx.bulk.buf, ctx.bulk.len, &res);
            if (rc != 0) {
                // POST failed: discard this batch (already in ctx.bulk) and go offline
                mwarn("analysisd offline? POST failed (rc=%d, http=%ld, curl=%d). "
                      "Dropping events until recovery.",
                      rc, res.http_status, res.curl_code);

                uhttp_client_free(cli);
                cli = NULL;

                fail_streak++;
                uint64_t backoff = 500u << (fail_streak > 6 ? 6 : fail_streak);
                if (backoff > 30000u) backoff = 30000u;
                reopen_at = mono_ms() + backoff;

                // From now on (until reopened), the loop will drain with drop_consumer.
            }
        }

        bulk_free(&ctx.bulk);
    }

    if (cli) uhttp_client_free(cli);
    return NULL;
}
