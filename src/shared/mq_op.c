/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "config/config.h"
#include "os_net/os_net.h"

#ifdef WAZUH_UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

static log_builder_t * mq_log_builder;
int sock_fail_time;

#ifndef WIN32

/* Start the Message Queue with specific owner and permissions(Only for READ type). type: WRITE||READ */
int StartMQWithSpecificOwnerAndPerms(const char *path, short int type, short int n_attempts, uid_t uid, gid_t gid, mode_t mode)
{
    if (type == READ) {
        return (OS_BindUnixDomainWithPerms(path, SOCK_DGRAM, OS_MAXSTR + 512, uid, gid, mode));
    }

    /* We give up to 21 seconds for the other end to start */
    else {
        int rc = 0, sleep_time = 5;
        short int attempt = 0;

        // If n_attempts is 0, trying to reconnect infinitely
        while ((rc = OS_ConnectUnixDomain(path, SOCK_DGRAM, OS_MAXSTR + 256)), rc < 0){
            attempt++;
            mdebug1("Can't connect to '%s': %s (%d). Attempt: %d", path, strerror(errno), errno, attempt);
            if (n_attempts != INFINITE_OPENQ_ATTEMPTS && attempt == n_attempts) {
                break;
            }
            sleep(sleep_time += 5);
        }

        if (rc < 0) {
            return OS_INVALID;
        }

        mdebug1("Connected succesfully to '%s' after %d attempts", path, attempt);
        mdebug1(MSG_SOCKET_SIZE, OS_getsocketsize(rc));
        return (rc);
    }
}

/* Start the Message Queue. type: WRITE||READ */
int StartMQ(const char *path, short int type, short int n_attempts)
{
    return StartMQWithSpecificOwnerAndPerms(path, type, n_attempts, getuid(), getgid(), 0660);
}

/* Reconnect to message queue */
int MQReconnectPredicated(const char *path, bool (*fn_ptr)()) {
    int rc = 0;
    while ((rc = OS_ConnectUnixDomain(path, SOCK_DGRAM, OS_MAXSTR + 256)), rc < 0){
        if ((*fn_ptr)()) {
            return OS_INVALID;
        }
        merror(UNABLE_TO_RECONNECT, path, strerror(errno), errno);
        sleep(5);
    }

    mdebug1(SUCCESSFULLY_RECONNECTED_SOCKET, path);
    mdebug1(MSG_SOCKET_SIZE, OS_getsocketsize(rc));
    return (rc);
}

/**
 * @brief Sends a binary message through the queue.
 *
 * This function is designed to send binary data (like FlatBuffers) that may contain
 * null bytes. It constructs the final message manually using memcpy to avoid truncating
 * the binary payload, unlike SendMSGAction which uses string functions.
 *
 * @param queue The message queue file descriptor.
 * @param message Pointer to the start of the binary data payload.
 * @param message_len The length of the binary data payload.
 * @param locmsg The location message (module name, etc.), treated as a C string.
 * @param loc The location character (e.g., SYNC_MQ).
 * @return 0 on success, -1 on failure.
 */
STATIC int SendBinaryMSGAction(int queue, const void *message, size_t message_len, const char *locmsg, char loc) {
    int __mq_rcode;
    char tmpstr[OS_MAXSTR + 1] = {0};
    char loc_buff[OS_SIZE_8192 + 1] = {0};
    char *p = tmpstr; // A pointer to build the message in tmpstr.
    static int reported = 0;
    size_t header_len;
    size_t total_len;

    // Escape the location string, as in the original SendMSGAction.
    if (OS_INVALID == wstr_escape(loc_buff, sizeof(loc_buff), (char *) locmsg, '|', ':')) {
        merror(FORMAT_ERROR);
        return (-1);
    }

    // Check for unsupported modes.
    if (loc == SECURE_MQ) {
        // This mode involves text parsing of the message payload, which is incompatible with binary data.
        merror("SendBinaryMSGAction does not support SECURE_MQ mode.");
        return (-1);
    }

    // Send the fully constructed message.
    if (queue < 0) {
        return (-1);
    }

    // Calculate the total size required for the final message BEFORE building it.
    // Header format is "loc:loc_buff:", so its length is 1 + 1 + strlen(loc_buff) + 1.
    size_t loc_buff_len = strlen(loc_buff);
    header_len = 3 + loc_buff_len;
    total_len = header_len + message_len;

    // Ensure the total message will fit in our fixed-size buffer
    if (total_len > OS_MAXSTR) {
        mwarn("Binary message is too large to be sent (%zu bytes required, %d max). Payload of %zu bytes for module '%s' was dropped.",
              total_len, OS_MAXSTR, message_len, locmsg);
        return (-1);
    }

    // Add header (e.g., "s:fim:")
    *p++ = loc;
    *p++ = ':';
    memcpy(p, loc_buff, loc_buff_len);
    p += loc_buff_len;
    *p++ = ':';

    // Add binary payload
    memcpy(p, message, message_len);

    if ((__mq_rcode = OS_SendUnix(queue, tmpstr, total_len)) < 0) {
        // Error on the socket
        if (__mq_rcode == OS_SOCKTERR) {
            merror("socketerr (not available).");
            close(queue);
            return (-1);
        }

        mdebug2("Socket busy, discarding binary message.");

        if (!reported) {
            reported = 1;
            mwarn("Socket busy, discarding binary message.");
        }
    }

    return (0);
}

/* Send message primitive. */
STATIC int SendMSGAction(int queue, const char *message, const char *locmsg, char loc) {
    int __mq_rcode;
    char tmpstr[OS_MAXSTR + 1] = {0};
    char loc_buff[OS_SIZE_8192 + 1] = {0};
    static int reported = 0;

    tmpstr[OS_MAXSTR] = '\0';

    if (OS_INVALID == wstr_escape(loc_buff, sizeof(loc_buff), (char *) locmsg, '|', ':')) {
        merror(FORMAT_ERROR);
        return (0);
    }

    if (loc == SECURE_MQ) {
        loc = message[0];
        message++;

        if (message[0] != ':') {
            merror(FORMAT_ERROR);
            return (0);
        }
        message++; /* Pointing now to the location */

        if (strncmp(message, "keepalive", 9) == 0) {
            return (0);
        }

        snprintf(tmpstr, OS_MAXSTR, "%c:%s->%s", loc, loc_buff, message);
    } else {
        snprintf(tmpstr, OS_MAXSTR, "%c:%s:%s", loc, loc_buff, message);
    }

    /* Queue not available */
    if (queue < 0) {
        return (-1);
    }

    if ((__mq_rcode = OS_SendUnix(queue, tmpstr, 0)) < 0) {
        /* Error on the socket */
        if (__mq_rcode == OS_SOCKTERR) {
            merror("socketerr (not available).");
            close(queue);
            return (-1);
        }

        /* Unable to send. Socket busy */
        mdebug2("Socket busy, discarding message.");

        if (!reported) {
            reported = 1;
            mwarn("Socket busy, discarding message.");
        }
    }

    return (0);
}

/* Send a message with predicated to run out from while. */
int SendMSGPredicated(int queue, const char *message, const char *locmsg, char loc, bool (*fn_ptr)()) {
    /* Check for global locks */
    os_wait_predicate(fn_ptr);
    return SendMSGAction(queue, message, locmsg, loc);
}

/* Send a message to the queue */
int SendMSG(int queue, const char *message, const char *locmsg, char loc) {
    /* Check for global locks */
    os_wait();
    return SendMSGAction(queue, message, locmsg, loc);
}

/* Send a message to the queue */
int SendBinaryMSG(int queue, const void *message, size_t message_len, const char *locmsg, char loc) {
    /* Check for global locks */
    os_wait();
    return SendBinaryMSGAction(queue, message, message_len, locmsg, loc);
}

/* Send a message to socket */
int SendMSGtoSCK(int queue, const char *message, const char *locmsg, __attribute__((unused)) char loc, logtarget * target)
{
    int __mq_rcode;
    char tmpstr[OS_MAXSTR + 1];
    time_t mtime;
    char * _message = NULL;
    int retval = 0;

    _message = log_builder_build(mq_log_builder, target->format, message, locmsg);

    tmpstr[OS_MAXSTR] = '\0';

    if (strcmp(target->log_socket->name, "agent") == 0) {
        if(SendMSG(queue, _message, locmsg, loc) != 0) {
            free(_message);
            return -1;
        }
    }else{
        int sock_type;
        const char * strmode;

        switch (target->log_socket->mode) {
        case IPPROTO_UDP:
            sock_type = SOCK_DGRAM;
            strmode = "udp";
            break;
        case IPPROTO_TCP:
            sock_type = SOCK_STREAM;
            strmode = "tcp";
            break;
        default:
            merror("At %s(): undefined protocol. This shouldn't happen.", __FUNCTION__);
            free(_message);
            return -1;
        }

        // create message and add prefix
        if (target->log_socket->prefix && *target->log_socket->prefix) {
            snprintf(tmpstr, OS_MAXSTR, "%s%s", target->log_socket->prefix, _message);
        } else {
            snprintf(tmpstr, OS_MAXSTR, "%s", _message);
        }

        // Connect to socket if disconnected
        if (target->log_socket->socket < 0) {
            if (mtime = time(NULL), mtime > target->log_socket->last_attempt + sock_fail_time) {
                if (target->log_socket->socket = OS_ConnectUnixDomain(target->log_socket->location, sock_type, OS_MAXSTR + 256), target->log_socket->socket < 0) {
                    target->log_socket->last_attempt = mtime;
                    merror("Unable to connect to socket '%s': %s (%s)", target->log_socket->name, target->log_socket->location, strmode);
                    free(_message);
                    return -1;
                }

                mdebug1("Connected to socket '%s' (%s)", target->log_socket->name, target->log_socket->location);
            } else {
                mdebug2("Discarding event from '%s' due to connection issue with '%s'", locmsg, target->log_socket->name);
                free(_message);
                return 1;
            }
        }

        // Send msg to socket
        if (__mq_rcode = OS_SendUnix(target->log_socket->socket, tmpstr, strlen(tmpstr)), __mq_rcode < 0) {
            if (__mq_rcode == OS_SOCKTERR) {
                if (mtime = time(NULL), mtime > target->log_socket->last_attempt + sock_fail_time) {
                    close(target->log_socket->socket);

                    if (target->log_socket->socket = OS_ConnectUnixDomain(target->log_socket->location, sock_type, OS_MAXSTR + 256), target->log_socket->socket < 0) {
                        merror("Unable to connect to socket '%s': %s (%s)", target->log_socket->name, target->log_socket->location, strmode);
                        target->log_socket->last_attempt = mtime;
                    } else {
                        mdebug1("Connected to socket '%s' (%s)", target->log_socket->name, target->log_socket->location);

                        if (OS_SendUnix(target->log_socket->socket, tmpstr, strlen(tmpstr)), __mq_rcode < 0) {
                            merror("Cannot send message to socket '%s'. (Retry)", target->log_socket->name);
                            SendMSG(queue, "Cannot send message to socket.", "logcollector", LOCALFILE_MQ);
                            target->log_socket->last_attempt = mtime;
                        }
                    }
                } else {
                    mdebug2("Discarding event from '%s' due to connection issue with '%s'", locmsg, target->log_socket->name);
                }
            } else {
                merror("Cannot send message to socket '%s'. (Retry)", target->log_socket->name);
                SendMSG(queue, "Cannot send message to socket.", "logcollector", LOCALFILE_MQ);
            }
            retval = 1;
        }
    }
    free(_message);
    return (retval);
}

int SendJSONtoSCK(char* message, socket_forwarder* Config) {
    time_t mtime;
    int retval = 0;
    int rcode_send;

    if (!Config) {
        merror("No targets defined for a forwarder.");
        return -1;
    }

    if (strcmp(Config->name, "agent") != 0) {
        int sock_type;
        const char * strmode;

        switch (Config->mode) {
        case IPPROTO_UDP:
            sock_type = SOCK_DGRAM;
            strmode = "udp";
            break;
        case IPPROTO_TCP:
            sock_type = SOCK_STREAM;
            strmode = "tcp";
            break;
        default:
            merror("At %s(): undefined protocol. This shouldn't happen.", __FUNCTION__);
            os_free(message);
            return -1;
        }

        // Connect to socket if disconnected
        if (Config->socket < 0) {
            if (mtime = time(NULL), mtime > Config->last_attempt + sock_fail_time) {
                if (Config->socket = OS_ConnectUnixDomain(Config->location, sock_type, OS_MAXSTR + 256), Config->socket < 0) {
                    Config->last_attempt = mtime;
                    merror("Unable to connect to socket '%s': %s (%s)", Config->name, Config->location, strmode);
                    os_free(message);
                    return -1;
                }
                mdebug1("Connected to socket '%s' (%s)", Config->name, Config->location);
            } else {
                mdebug2("Discarding event '%s' due to connection issue with '%s'", message, Config->name);
                os_free(message);
                return 1;
            }
        }

        // Send msg to socket
        if (rcode_send = OS_SendUnix(Config->socket, message, strlen(message)), rcode_send < 0) {
            if (rcode_send == OS_SOCKTERR) {
                if (mtime = time(NULL), mtime > Config->last_attempt + sock_fail_time) {
                    close(Config->socket);

                    if (Config->socket = OS_ConnectUnixDomain(Config->location, sock_type, OS_MAXSTR + 256), Config->socket < 0) {
                        merror("Unable to connect to socket '%s': %s (%s).", Config->name, Config->location, strmode);
                        Config->last_attempt = mtime;
                    } else {
                        mdebug1("Connected to socket '%s' (%s)", Config->name, Config->location);

                        if (rcode_send = OS_SendUnix(Config->socket, message, strlen(message)), rcode_send < 0) {
                            mdebug2("Cannot send message to socket '%s' due %s. (Abort).", Config->name,strerror(errno));
                            Config->last_attempt = mtime;
                        } else {
                            mdebug2("Message send to socket '%s' (%s) successfully.", Config->name, Config->location);
                        }
                    }
                } else {
                    mdebug2("Discarding event from engine due to connection issue with '%s', %s. (Abort).", Config->name,strerror(errno));
                }
            } else {
                mdebug2("Cannot send message to socket '%s' due %s. (Abort).", Config->name,strerror(errno));
            }
            retval = 1;
        } else {
            mdebug2("Message send to socket '%s' (%s) successfully.", Config->name, Config->location);
        }
    }
    os_free(message);
    return retval;
}

#else

int SendMSGtoSCK(int queue, const char *message, const char *locmsg, char loc, logtarget * targets) {
    char * _message;
    int retval;

    if (!targets[0].log_socket) {
        merror("No targets defined for a localfile.");
        return -1;
    }

    _message = log_builder_build(mq_log_builder, targets[0].format, message, locmsg);
    retval = SendMSG(queue, _message, locmsg, loc);
    free(_message);
    return retval;
}

#endif /* !WIN32 */

void mq_log_builder_init() {
    assert(mq_log_builder == NULL);
    mq_log_builder = log_builder_init(true);
}

int mq_log_builder_update() {
    assert(mq_log_builder != NULL);
    return log_builder_update(mq_log_builder);
}
