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
#include "../os_net/os_net.h"
#include "remoted.h"
#include "remoted_op.h"
#include "state.h"
#include "../wazuh_db/helpers/wdb_global_helpers.h"
#include "router.h"
#include "sym_load.h"
#include "indexed_queue_op.h"
#include "batch_queue_op.h"
#include "http_op.h"

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

/* Global variables */
w_indexed_queue_t *control_msg_queue = NULL;
w_rr_queue_t *events_queue = NULL;

netbuffer_t netbuffer_recv;
netbuffer_t netbuffer_send;

wnotify_t * notify = NULL;

size_t global_counter;

_Atomic (time_t) current_ts;
OSHash *remoted_agents_state;

extern remoted_state_t remoted_state;
ROUTER_PROVIDER_HANDLE router_upgrade_ack_handle = NULL;
ROUTER_PROVIDER_HANDLE router_sync_handle = NULL;
STATIC void handle_outgoing_data_to_tcp_socket(int sock_client);
STATIC void handle_incoming_data_from_tcp_socket(int sock_client);
STATIC void handle_incoming_data_from_udp_socket(struct sockaddr_storage * peer_info);
STATIC void handle_new_tcp_connection(wnotify_t * notify, struct sockaddr_storage * peer_info);

// Headers for messages
#define UPGRADE_ACK_HEADER "u:upgrade_module:"
#define UPGRADE_ACK_HEADER_SIZE 17

// Headers for inventory sync messages
#define INVENTORY_SYNC_HEADER "s:"
#define INVENTORY_SYNC_HEADER_SIZE 2

// Router message forwarder - returns true if message was forwarded to router
bool router_message_forward(char* msg, size_t msg_length, const char* agent_id);

// Message handler thread
static void * rem_handler_main(void * args);

// Key reloader thread
void * rem_keyupdate_main(__attribute__((unused)) void * args);

/* Handle each message received */
STATIC void HandleSecureMessage(const message_t *message, w_indexed_queue_t * control_msg_queue, w_rr_queue_t * batch_queue);

// Close and remove socket from keystore
int _close_sock(keystore * keys, int sock);

/* Get current timestamp */
STATIC void *current_timestamp(void *none);

STATIC void * close_fp_main(void * args);

/* Status of key-request feature */
static char key_request_available = 0;

/* Decode hostinfo input queue */
static w_queue_t * key_request_queue;

/* Remote key request thread */
void * key_request_thread(__attribute__((unused)) void * args);

/* Push key request */
static void _push_request(const char *request,const char *type);
#define push_request(x, y) if (key_request_available) _push_request(x, y);

/* Connect to key-request feature */
#define KEY_RECONNECT_INTERVAL 300 // 5 minutes
static int key_request_connect();
static int key_request_reconnect();

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
    const char *agent_key;
    char *agent_id;
    char *agent_name;
    char *agent_ip;

    int   header_added;
    bulk_t bulk;             // body to send (header + events)
} dispatch_ctx_t;

static void dispose_evt_item(void *p) {
    evt_item_t *e = (evt_item_t*)p;
    if (!e) return;
    os_free(e->raw);
    os_free(e);
}

void * dispach_events_thread(void * queue);

typedef struct {
    w_indexed_queue_t *control_msg_queue; // the indexed control queue
    w_rr_queue_t      *events_queue;      // round robbin event ring
} rem_handler_args_t;

/* Handle secure connections */
void HandleSecure()
{
    const int protocol = logr.proto[logr.position];
    int n_events = 0;

    agent_metadata_init();

    control_msg_queue = indexed_queue_init(ctrl_msg_queue_size);
    indexed_queue_set_dispose(control_msg_queue, (void (*)(void *))w_free_ctrl_msg_data);
    indexed_queue_set_get_key(control_msg_queue, w_ctrl_msg_get_key);

    events_queue = batch_queue_init(batch_events_capacity);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    batch_queue_set_agent_max(events_queue, batch_events_per_agent_capacity);

    uhttp_global_init();

    struct sockaddr_storage peer_info;
    memset(&peer_info, 0, sizeof(struct sockaddr_storage));

    /* Global stats uptime */
    remoted_state.uptime = time(NULL);

    /* Create OSHash for agents statistics */
    remoted_agents_state = OSHash_Create();
    if (!remoted_agents_state) {
        merror_exit(HASH_ERROR);
    }
    if (!OSHash_setSize(remoted_agents_state, 2048)) {
        merror_exit(HSETSIZE_ERROR, "remoted_agents_state");
    }

    /* Initialize manager */
    manager_init();

    // Initialize messag equeue
    rem_msginit(logr.queue_size);

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

    // Create State writer thread
    w_create_thread(rem_state_main, NULL);

    key_request_queue = queue_init(1024);

    // Create key request thread
    w_create_thread(key_request_thread, NULL);

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

    // Router module logging initialization
    router_initialize(taggedLogFunction);

    // Router providers initialization
    if (router_upgrade_ack_handle = router_provider_create("upgrade_notifications", false), !router_upgrade_ack_handle) {
        mdebug2("Failed to create router handle for 'upgrade_notifications'.");
    }

    if (router_sync_handle = router_provider_create("inventory-states", false), !router_sync_handle) {
        mdebug2("Failed to create router handle for 'inventory synchronization'.");
    }

    // Create upsert control message thread
    w_create_thread(save_control_thread, (void *) control_msg_queue);

    // Create upsert control message thread
    w_create_thread(dispach_events_thread, (void *) events_queue);

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

    /* Connect to the message queue
     * Exit if it fails.
     */
    if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
        merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
    }

    /* Read authentication keys */
    minfo(ENC_READ);

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
    char ip_found = 0;
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

            // Send key request by id
            push_request(buffer + 1, "id");
            if (message->sock >= 0) {
                _close_sock(&keys, message->sock);
            }

            rem_inc_recv_unknown();
            return;
        } else {
            w_mutex_lock(&keys.keyentries[agentid]->mutex);

            if ((keys.keyentries[agentid]->sock >= 0) && (keys.keyentries[agentid]->sock != message->sock)) {
                if ((logr.connection_overtake_time > 0) && (current_ts - keys.keyentries[agentid]->rcvd) > logr.connection_overtake_time) {
                    sock_idle = keys.keyentries[agentid]->sock;

                    mdebug2("Idle socket [%d] from agent ID '%s' will be closed.", sock_idle, keys.keyentries[agentid]->id);

                    keys.keyentries[agentid]->rcvd = current_ts;
                } else {
                    mwarn("Agent key already in use: agent ID '%s'", keys.keyentries[agentid]->id);

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

            // Send key request by ip
            push_request(srcip, "ip");
            if (message->sock >= 0) {
                _close_sock(&keys, message->sock);
            }

            rem_inc_recv_unknown();
            return;
        } else {
            w_mutex_lock(&keys.keyentries[agentid]->mutex);

            if ((keys.keyentries[agentid]->sock >= 0) && (keys.keyentries[agentid]->sock != message->sock)) {
                if ((logr.connection_overtake_time > 0) && (current_ts - keys.keyentries[agentid]->rcvd) > logr.connection_overtake_time) {
                    sock_idle = keys.keyentries[agentid]->sock;

                    mdebug2("Idle socket [%d] from agent ID '%s' will be closed.", sock_idle, keys.keyentries[agentid]->id);

                    keys.keyentries[agentid]->rcvd = current_ts;
                } else {
                    mwarn("Agent key already in use: agent ID '%s'", keys.keyentries[agentid]->id);

                    w_mutex_unlock(&keys.keyentries[agentid]->mutex);
                    key_unlock();

                    if (message->sock >= 0) {
                        _close_sock(&keys, message->sock);
                    }

                    rem_inc_recv_unknown();
                    return;
                }
            }

            ip_found = 1;
            w_mutex_unlock(&keys.keyentries[agentid]->mutex);
        }

        tmp_msg = buffer;
    }

    if (recv_b <= 0) {
        mwarn("Received message is empty");
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

        if (r == KS_ENCKEY) {
            if (ip_found) {
                push_request(srcip, "ip");
            } else {
                push_request(buffer + 1, "id");
            }
        }

        if (message->sock >= 0) {
            mwarn("Decrypt the message fail, socket %d", message->sock);
            _close_sock(&keys, message->sock);
        }

        if (sock_idle >= 0) {
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

            rem_inc_recv_ctrl(key->id);

            if (validation_result == 1) {
                // Message should be queued for database processing
                w_ctrl_msg_data_t * ctrl_msg_data;
                os_calloc(1, sizeof(w_ctrl_msg_data_t), ctrl_msg_data);

                /* Parsing msg */
                {
                    agent_info_data *agent_data;
                    os_calloc(1, sizeof(agent_info_data), agent_data);
                    int result = parse_agent_update_msg(tmp_msg, agent_data);

                    if (OS_SUCCESS == result) {
                        // Build metadata from parsed agent_info_data and upsert in the global map
                        agent_meta_t *fresh = agent_meta_from_agent_info(key->id, agent_data);
                        if (fresh) {
                            if (agent_meta_upsert_locked(key->id, fresh) != 0) {
                                mwarn("Error upsert metadata from agent ID '%s'.", key->id);
                                agent_meta_free(fresh);
                            }
                        }
                    }

                    wdb_free_agent_info_data(agent_data);
                }

                ctrl_msg_data->key = key;

                os_calloc(msg_length, sizeof(char), ctrl_msg_data->message);
                // Use cleaned message from validation if available, otherwise use original
                memcpy(ctrl_msg_data->message, cleaned_msg ? cleaned_msg : tmp_msg, tmp_msg_length);

                // Store validation results in the control message data structure
                ctrl_msg_data->is_startup = is_startup;
                ctrl_msg_data->is_shutdown = is_shutdown;
                ctrl_msg_data->post_startup = post_startup;

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

    // Check if message should be forwarded to router instead of analysisd
    bool forwarded_to_router = false;
    if (router_forwarding_disabled != 1) {
        forwarded_to_router = router_message_forward(tmp_msg, msg_length, agentid_str);
    }

    // Only send to analysisd if not forwarded to router
    if (!forwarded_to_router) {
        evt_item_t *e; os_calloc(1, sizeof(*e), e);
        os_calloc(msg_length, sizeof(char), e->raw);
        memcpy(e->raw, tmp_msg, msg_length);
        e->len = msg_length;

        int rc = batch_queue_enqueue_ex(batch_queue, agentid_str, e);
        if (rc < 0) {
            dispose_evt_item(e);
            mwarn("Dropping event for agent '%s' (rc=%d)", agentid_str, rc);
        }
    }

    os_free(agentid_str);
}

bool router_message_forward(char* msg, size_t msg_length, const char* agent_id) {

    ROUTER_PROVIDER_HANDLE router_handle = NULL;
    int message_header_size = 0;
    msg_type message_type = MT_INVALID;

    if(strncmp(msg, INVENTORY_SYNC_HEADER, INVENTORY_SYNC_HEADER_SIZE) == 0) {
        if (!router_sync_handle) {
            mdebug2("Router handle for 'inventory synchronization' not available.");
            return false;
        }
        router_handle = router_sync_handle;
        message_header_size = INVENTORY_SYNC_HEADER_SIZE;
        message_type = MT_INV_SYNC;
    }
    else if(strncmp(msg, UPGRADE_ACK_HEADER, UPGRADE_ACK_HEADER_SIZE) == 0) {
        if (!router_upgrade_ack_handle) {
            mdebug2("Router handle for 'upgrade_notifications' not available.");
            return false;
        }
        router_handle = router_upgrade_ack_handle;
        message_header_size = UPGRADE_ACK_HEADER_SIZE;
        message_type = MT_UPGRADE_ACK;
    }

    if (!router_handle) {
        return false;
    }

    mdebug2("Forwarding message to router");

    char* msg_start = msg + message_header_size;
    if (message_type == MT_INV_SYNC) {
        // Validate minimum message length: header + "x:y" (4 chars minimum after header)
        if (msg_length <= INVENTORY_SYNC_HEADER_SIZE + 4) {
            mdebug2("Message too short for expected format.");
            return false;
        }

        size_t remaining_len = msg_length - INVENTORY_SYNC_HEADER_SIZE;

        // Find colon separator between module and message
        // Format after header: {module}:{msg}
        char* colon = (char*)memchr(msg_start, ':', remaining_len);
        if (!colon || colon == msg_start) {
            mdebug2("Invalid message format: missing or empty module.");
            return false;
        }

        // Calculate module length and validate it's reasonable
        size_t module_len = colon - msg_start;
        if (module_len == 0 || module_len > OS_SIZE_64) { // Reasonable module name limit
            mdebug2("Invalid module length.");
            return false;
        }

        // Calculate message payload position
        char* msg_to_send = colon + 1;
        size_t payload_offset = msg_to_send - msg;

        if (payload_offset >= msg_length) {
            mdebug2("Invalid message format: no payload data.");
            return false;
        }

        // Calculate safe message size
        size_t msg_size = msg_length - payload_offset;

        // Send the raw flatbuffer to inventory sync with anti-spoofing validation
        if (router_provider_send_sync(router_sync_handle, msg_to_send, msg_size, agent_id) != 0) {
            mdebug2("Unable to forward message for agent '%s'.", agent_id);
            return false;
        }

        return true;
    }
    else if (message_type == MT_UPGRADE_ACK) {

        cJSON* upgrade_ack_json;
        const char *json_err;
        if (upgrade_ack_json = cJSON_ParseWithOpts(msg_start, &json_err, 0), !upgrade_ack_json) {
            mwarn("Failed to parse router message JSON: '%s'", json_err);
            return false;
        }

        cJSON* parameters_obj = cJSON_GetObjectItem(upgrade_ack_json, "parameters");

        if (parameters_obj && cJSON_IsObject(parameters_obj)) {
            int agent = atoi(agent_id);
            cJSON* agents = cJSON_CreateIntArray(&agent, 1);
            cJSON_AddItemToObject(parameters_obj, "agents", agents);

            char *upgrade_message = cJSON_PrintUnformatted(upgrade_ack_json);
            size_t msg_size = strlen(upgrade_message) + 1; // +1 for null terminator

            if (router_provider_send(router_handle, upgrade_message, msg_size) != 0) {
                mwarn("Unable to forward upgrade-ack message '%s' for agent %s", msg_start, agent_id);
                cJSON_free(upgrade_message);
                cJSON_Delete(upgrade_ack_json);
                return false;
            }

            // Free the printed message and JSON object
            cJSON_free(upgrade_message);
            cJSON_Delete(upgrade_ack_json);
            return true;
        }
        else {
            mwarn("Could not get parameters from upgrade message: '%s'", msg_start);
            cJSON_Delete(upgrade_ack_json);
            return false;
        }
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

int key_request_connect() {
#ifndef WIN32
    return OS_ConnectUnixDomain(KEY_REQUEST_SOCK, SOCK_DGRAM, OS_MAXSTR);
#else
    return -1;
#endif
}

static int send_key_request(int socket,const char *msg) {
    return OS_SendUnix(socket,msg,strlen(msg));
}

static void _push_request(const char *request,const char *type) {
    char *msg = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    snprintf(msg, OS_MAXSTR, "%s:%s", type, request);

    if(queue_push_ex(key_request_queue, msg) < 0) {
        os_free(msg);
    }
}

int key_request_reconnect() {
    int socket;
    static int max_attempts = 4;
    int attempts;

    while (1) {
        for (attempts = 0; attempts < max_attempts; attempts++) {
            if (socket = key_request_connect(), socket < 0) {
                sleep(1);
            } else {
                if(OS_SetSendTimeout(socket, 5) < 0){
                    close(socket);
                    continue;
                }
                key_request_available = 1;
                return socket;
            }
        }
        mdebug1("Key-request feature is not available. Retrying connection in %d seconds.", KEY_RECONNECT_INTERVAL);
        sleep(KEY_RECONNECT_INTERVAL);
    }
}

void * key_request_thread(__attribute__((unused)) void * args) {
    char * msg = NULL;
    int socket = -1;

    while(1) {
        if (socket < 0) {
            socket = key_request_reconnect();
        }

        if (msg || (msg = queue_pop_ex(key_request_queue))) {
            int rc;

            if ((rc = send_key_request(socket, msg)) < 0) {
                if (rc == OS_SOCKBUSY) {
                    mdebug1("Key request socket busy.");
                    sleep(1);
                } else {
                    merror("Could not communicate with key request queue (%d). Is the module running?", rc);
                    if (socket >= 0) {
                        key_request_available = 0;
                        close(socket);
                        socket = -1;
                    }
                }
            } else {
                os_free(msg);
            }
        }
    }
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

// Encode the header ONLY once above the body
static int append_header(dispatch_ctx_t *ctx) {
    if (ctx->header_added) return 0;
    if (!ctx || !ctx->agent_key) return -1;

    // Snapshot metadata for this agent (copies strings into 'snap')
    agent_meta_t snap = {0};
    int have_meta = (agent_meta_snapshot_str(ctx->agent_key, &snap) == 0);

    // Fallbacks
    char *agent_name = NULL;
    char *agent_ip   = NULL;

    // Prefer metadata snapshot
    if (have_meta) {
        if (snap.agent_ip) os_strdup(snap.agent_ip, agent_ip);
    }

    // Fallback name from keystore (never deref without lock)
    key_lock_read();
    int idx = OS_IsAllowedID(&keys, ctx->agent_key);
    if (idx >= 0 && idx < (int)keys.keysize) {
        if (!agent_name && keys.keyentries[idx]->name) {
            os_strdup(keys.keyentries[idx]->name, agent_name);
        }
    }
    key_unlock();

    if (!agent_name) os_strdup("-", agent_name);
    if (!agent_ip)   os_strdup("-", agent_ip);

    // Also keep these in ctx for router / metrics
    if (!ctx->agent_id) {
        // agent_id is the string key (e.g. "002"); keep a borrowed pointer or duplicate:
        os_strdup(ctx->agent_key, ctx->agent_id);
    }
    if (!ctx->agent_name) os_strdup(agent_name, ctx->agent_name);
    if (!ctx->agent_ip)   os_strdup(agent_ip,   ctx->agent_ip);

    // --- Build nested JSON: { "agent": {...}, "host": { "ip":[...], "os": {...}, "architecture": ... } } ---
    cJSON *root = cJSON_CreateObject();
    if (!root) goto fail;

    cJSON *agent = cJSON_CreateObject();
    cJSON *host  = cJSON_CreateObject();
    cJSON *os    = cJSON_CreateObject();
    if (!agent || !host || !os) { cJSON_Delete(root); goto fail; }

    cJSON_AddItemToObject(root, "agent", agent);
    cJSON_AddItemToObject(root, "host",  host);
    cJSON_AddItemToObject(host, "os",    os);

    // agent.*
    cJSON_AddStringToObject(agent, "name", agent_name ? agent_name : "-");
    if (have_meta && snap.version) {
        cJSON_AddStringToObject(agent, "version", snap.version);
    }
    cJSON_AddStringToObject(agent, "id", ctx->agent_key);

    // host.ip (array)
    cJSON *ips = cJSON_CreateArray();
    if (!ips) { cJSON_Delete(root); goto fail; }
    if (agent_ip && *agent_ip) cJSON_AddItemToArray(ips, cJSON_CreateString(agent_ip));
    cJSON_AddItemToObject(host, "ip", ips);

    // host.os.*
    if (have_meta && snap.os_name)     cJSON_AddStringToObject(os, "name",     snap.os_name);
    if (have_meta && snap.os_version)  cJSON_AddStringToObject(os, "version",  snap.os_version);
    if (have_meta && snap.os_codename) cJSON_AddStringToObject(os, "full",     snap.os_codename);
    if (have_meta && snap.os_platform) cJSON_AddStringToObject(os, "platform", snap.os_platform);
    if (have_meta && snap.os_build)    cJSON_AddStringToObject(os, "build",    snap.os_build);
    if (have_meta && snap.os_kernel)   cJSON_AddStringToObject(os, "kernel",   snap.os_kernel);

    // host.architecture
    if (have_meta && snap.arch) cJSON_AddStringToObject(host, "architecture", snap.arch);

    // Emit header line
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) goto fail;

    if (bulk_append_fmt(&ctx->bulk, "H\t%s\n", json) < 0) {
        free(json);
        goto fail;
    }
    free(json);

    ctx->header_added = 1;

    os_free(agent_name);
    os_free(agent_ip);
    agent_meta_clear(&snap);
    return 0;

fail:
    // Free local fallbacks
    os_free(agent_name);
    os_free(agent_ip);
    agent_meta_clear(&snap);
    // If you duplicated strings inside 'snap' with snapshot API, free them (see below).
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
    dispose_evt_item((evt_item_t *)data);
}

// Consumer: Only accumulates in ctx->bulk. Releases each item individually.
static void rr_collect_one(void *data, void *user) {
    evt_item_t *e = (evt_item_t*)data;
    dispatch_ctx_t *ctx = (dispatch_ctx_t*)user;

    // Ensure header at the top of the body
    if (!ctx->header_added) {
        if (append_header(ctx) < 0) {
            mwarn("Unable to append header for agent '%s'", ctx->agent_key ?: "?");
        }
    }

    // Event Framing: "E\t<payload>\n"
    if (bulk_append_fmt(&ctx->bulk, "E\t") < 0 ||
        bulk_append(&ctx->bulk, e->raw, e->len) < 0 ||
        bulk_append(&ctx->bulk, "\n", 1) < 0) {
        mwarn("Unable to append event for agent '%s'", ctx->agent_key ?: "?");
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
        .user_agent         = "wazuh-remoted/1.0",
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
            .agent_key    = NULL,
            .agent_id     = NULL, .agent_name = NULL, .agent_ip = NULL,
            .header_added = 0
        };
        bulk_init(&ctx.bulk, 8192);

        size_t drained = batch_queue_drain_next_ex(q, /*abstime=*/NULL,
                                                   rr_collect_one, &ctx, &ctx.agent_key);

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
        os_free(ctx.agent_id); os_free(ctx.agent_name); os_free(ctx.agent_ip);
    }

    if (cli) uhttp_client_free(cli);
    return NULL;
}
