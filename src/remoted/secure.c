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
#include "../os_net/os_net.h"
#include "remoted.h"
#include "state.h"
#include "../wazuh_db/helpers/wdb_global_helpers.h"
#include "router.h"
#include "sym_load.h"
#include "utils/flatbuffers/include/syscollector_synchronization_schema.h"
#include "utils/flatbuffers/include/syscollector_deltas_schema.h"
#include "agent_messages_adapter.h"

enum msg_type {
    MT_INVALID,
    MT_SYS_DELTAS,
    MT_SYS_SYNC,
} msg_type_t;
#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

/* Global variables */
int sender_pool;

netbuffer_t netbuffer_recv;
netbuffer_t netbuffer_send;

wnotify_t * notify = NULL;

size_t global_counter;

_Atomic (time_t) current_ts;

OSHash *remoted_agents_state;

extern remoted_state_t remoted_state;
ROUTER_PROVIDER_HANDLE router_rsync_handle = NULL;
ROUTER_PROVIDER_HANDLE router_syscollector_handle = NULL;
STATIC void handle_outgoing_data_to_tcp_socket(int sock_client);
STATIC void handle_incoming_data_from_tcp_socket(int sock_client);
STATIC void handle_incoming_data_from_udp_socket(struct sockaddr_storage * peer_info);
STATIC void handle_new_tcp_connection(wnotify_t * notify, struct sockaddr_storage * peer_info);

// Headers for syscollector messages: DBSYNC_MQ + WM_SYS_LOCATION and SYSCOLLECTOR_MQ + WM_SYS_LOCATION
#define DBSYNC_SYSCOLLECTOR_HEADER "5:syscollector:"
#define SYSCOLLECTOR_HEADER "d:syscollector:"
#define DBSYNC_SYSCOLLECTOR_HEADER_SIZE 15
#define SYSCOLLECTOR_HEADER_SIZE 15

// Router message forwarder
void router_message_forward(char* msg, const char* agent_id, const char* agent_ip, const char* agent_name);

// Message handler thread
static void * rem_handler_main(void * args);

// Key reloader thread
void * rem_keyupdate_main(__attribute__((unused)) void * args);

/* Handle each message received */
STATIC void HandleSecureMessage(const message_t *message, w_linked_queue_t * control_msg_queue);

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
    size_t length;  ///< Length of the message
    int agent_id;   ///< Agent ID
} w_ctrl_msg_data_t;

/**
 * @brief Thread function to save control messages
 * 
 * This function is executed by the control message thread pool. It waits for messages to be pushed into the queue and processes them.
 * Updates the agent's status in wazuhdb and sends the message to the appropriate handler.
 * @param queue Pointer to the control message queue, which is used to store messages to be processed.
 * @return void* Null
 */
void * save_control_thread(void * queue);


/* Handle secure connections */
void HandleSecure()
{
    const int protocol = logr.proto[logr.position];
    int n_events = 0;

    w_linked_queue_t * control_msg_queue = linked_queue_init(); ///< Pointer to the control message queue

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

    /* Create Security configuration assessment forwarder thread */
    w_create_thread(SCFGA_Forward, NULL);

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
        sender_pool = getDefine_Int("remoted", "sender_pool", 1, 64);

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
    if (router_syscollector_handle = router_provider_create("deltas-syscollector", false), !router_syscollector_handle) {
        mdebug2("Failed to create router handle for 'syscollector'.");
    }

    if (router_rsync_handle = router_provider_create("rsync-syscollector", false), !router_rsync_handle) {
        mdebug2("Failed to create router handle for 'rsync'.");
    }

    // Create upsert control message thread
    w_create_thread(save_control_thread, (void *) control_msg_queue);

    // Create message handler thread pool
    {
        int worker_pool = getDefine_Int("remoted", "worker_pool", 1, 16);
        // Initialize FD list and counter.
        global_counter = 0;
        rem_initList(FD_LIST_INIT_VALUE);
        while (worker_pool > 0) {
            w_create_thread(rem_handler_main, control_msg_queue);
            worker_pool--;
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
    w_linked_queue_t * control_msg_queue = (w_linked_queue_t *) args;
    mdebug1("Message handler thread started.");

    while (1) {
        message = rem_msgpop();
        HandleSecureMessage(message, control_msg_queue);
        rem_msgfree(message);
    }

    return NULL;
}

// Key reloader thread
void * rem_keyupdate_main(__attribute__((unused)) void * args) {
    int seconds;

    mdebug1("Key reloader thread started.");
    seconds = getDefine_Int("remoted", "keyupdate_interval", 1, 3600);

    while (1) {
        mdebug2("Checking for keys file changes.");
        if (check_keyupdate() == 1) {
            rem_inc_keys_reload();
        }
        sleep(seconds);
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

STATIC const char * get_schema(const int type)
{
    if (type == MT_SYS_DELTAS) {
        return syscollector_deltas_SCHEMA;
    } else if (type == MT_SYS_SYNC) {
        return syscollector_synchronization_SCHEMA;
    }
    return NULL;

}
STATIC void HandleSecureMessage(const message_t *message, w_linked_queue_t * control_msg_queue) {
    int agentid;
    const int protocol = (message->sock == USING_UDP_NO_CLIENT_SOCKET) ? REMOTED_NET_PROTOCOL_UDP : REMOTED_NET_PROTOCOL_TCP;
    char cleartext_msg[OS_MAXSTR + 1];
    char srcmsg[OS_FLSIZE + 1];
    char srcip[IPSIZE + 1] = {0};
    char agname[KEYSIZE + 1] = {0};
    char *agentid_str = NULL;
    char *agent_ip = NULL;
    char *agent_name = NULL;
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

            key_unlock();

            if (sock_idle >= 0) {
                _close_sock(&keys, sock_idle);
            }

            bool is_startup = key->is_startup;

            // The critical section for readers closes within this function
            rem_inc_recv_ctrl(key->id);

            // Send the control message to the queue for processing in the control thread
            {
                w_ctrl_msg_data_t * ctrl_msg_data;
                os_calloc(sizeof(w_ctrl_msg_data_t), 1, ctrl_msg_data);
                
                ctrl_msg_data->agent_id = agentid;
                
                ctrl_msg_data->key = key;
                key = NULL;

                ctrl_msg_data->length = msg_length - 3;
                os_calloc(msg_length, sizeof(char), ctrl_msg_data->message);
                memcpy(ctrl_msg_data->message, tmp_msg, ctrl_msg_data->length);

                linked_queue_push_ex(control_msg_queue, ctrl_msg_data);

                rem_inc_ctrl_msg_queue_usage();
                mdebug2("Control message pushed to queue.");
            }

        } else {
            key_unlock();
            rem_inc_recv_dequeued();
        }
        return;
    }

    /* Generate srcmsg */

    snprintf(srcmsg, OS_FLSIZE, "[%s] (%s) %s", keys.keyentries[agentid]->id,
             keys.keyentries[agentid]->name, keys.keyentries[agentid]->ip->ip);

    os_strdup(keys.keyentries[agentid]->id, agentid_str);
    os_strdup(keys.keyentries[agentid]->name, agent_name);
    os_strdup(keys.keyentries[agentid]->ip->ip, agent_ip);

    key_unlock();

    if (sock_idle >= 0) {
        _close_sock(&keys, sock_idle);
    }

    /* If we can't send the message, try to connect to the
     * socket again. If it not exit.
     */
    if (SendMSG(logr.m_queue, tmp_msg, srcmsg, SECURE_MQ) < 0) {
        merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));

        // Try to reconnect infinitely
        logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

        minfo("Successfully reconnected to '%s'", DEFAULTQUEUE);

        if (SendMSG(logr.m_queue, tmp_msg, srcmsg, SECURE_MQ) < 0) {
            // Something went wrong sending a message after an immediate reconnection...
            merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
        } else {
            rem_inc_recv_evt(agentid_str);
        }
    } else {
        rem_inc_recv_evt(agentid_str);
    }

    // Forwarding events to subscribers
    router_message_forward(tmp_msg, agentid_str, agent_ip, agent_name);

    os_free(agentid_str);
    os_free(agent_ip);
    os_free(agent_name);
}

void router_message_forward(char* msg, const char* agent_id, const char* agent_ip, const char* agent_name) {
    // Both syscollector delta and sync messages are sent to the router
    ROUTER_PROVIDER_HANDLE router_handle = NULL;
    int message_header_size = 0;
    int schema_type = -1;

    if(strncmp(msg, SYSCOLLECTOR_HEADER, SYSCOLLECTOR_HEADER_SIZE) == 0) {
        if (!router_syscollector_handle) {
            mdebug2("Router handle for 'syscollector' not available.");
            return;
        }
        router_handle = router_syscollector_handle;
        message_header_size = SYSCOLLECTOR_HEADER_SIZE;
        schema_type = MT_SYS_DELTAS;
    } else if(strncmp(msg, DBSYNC_SYSCOLLECTOR_HEADER, DBSYNC_SYSCOLLECTOR_HEADER_SIZE) == 0) {
        if (!router_rsync_handle) {
            mdebug2("Router handle for 'rsync' not available.");
            return;
        }
        router_handle = router_rsync_handle;
        message_header_size = DBSYNC_SYSCOLLECTOR_HEADER_SIZE;
        schema_type = MT_SYS_SYNC;
    }

    if (!router_handle) {
        return;
    }

    char* msg_to_send = NULL;
    char* msg_start = msg + message_header_size;
    size_t msg_size = strnlen(msg_start, OS_MAXSTR - message_header_size);
    if ((msg_size + message_header_size) < OS_MAXSTR) {
        if (schema_type == MT_SYS_DELTAS) {
            msg_to_send = adapt_delta_message(msg_start, agent_name, agent_id, agent_ip, agent_data_hash);
        } else if (schema_type == MT_SYS_SYNC) {
            msg_to_send = adapt_sync_message(msg_start, agent_name, agent_id, agent_ip, agent_data_hash);
        }

        if (msg_to_send) {
            if (router_provider_send_fb(router_handle, msg_to_send, get_schema(schema_type)) != 0) {
                mdebug2("Unable to forward message '%s' for agent %s", msg_to_send, agent_id);
            }
            cJSON_free(msg_to_send);
        }
    }
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
    w_linked_queue_t * queue = (w_linked_queue_t *)control_msg_queue;
    w_ctrl_msg_data_t * ctrl_msg_data = NULL;
    int wdb_sock = -1;

    while (FOREVER()) {
        if ((ctrl_msg_data = (w_ctrl_msg_data_t *)linked_queue_pop_ex(queue))) {

            rem_dec_ctrl_msg_queue_usage();
            bool is_startup = ctrl_msg_data->key->is_startup;

            // Process the control message
            save_controlmsg(ctrl_msg_data->key, ctrl_msg_data->message, ctrl_msg_data->length, &wdb_sock, &is_startup);

            // Update agent is_startup flag in case it changed
            if (ctrl_msg_data->key->is_startup != is_startup) {
                key_lock_read();
                keys.keyentries[ctrl_msg_data->agent_id]->is_startup = is_startup;
                key_unlock();
            }

            // Free the key entry
            OS_FreeKey(ctrl_msg_data->key);
            os_free(ctrl_msg_data->message);
            os_free(ctrl_msg_data);
        }
    }

    return NULL;

}
