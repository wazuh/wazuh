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
#include "os_net/os_net.h"
#include "remoted.h"

#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

/**
 * @brief Get the offset of the syslog message, discarding the PRI header.
 *
 * @param syslog_msg RAW syslog message
 * @return Length of the PRI header, 0 if not present
 */
STATIC size_t w_get_pri_header_len(const char * syslog_msg);

/* Checks if an IP is not allowed */
static int OS_IPNotAllowed(char *srcip)
{
    if (logr.denyips != NULL) {
        if (OS_IPFoundList(srcip, logr.denyips)) {
            return (1);
        }
    }
    if (logr.allowips != NULL) {
        if (OS_IPFoundList(srcip, logr.allowips)) {
            return (0);
        }
    }

    /* If the IP is not allowed, it will be denied */
    return (1);
}

/**
 * @brief Convert an SSL error code into a human-readable string.
 *
 * Fills the provided buffer with the OpenSSL error-queue text for the
 * current thread. If the queue is empty, falls back to SSL_get_error's
 * numeric code so the caller always has something useful to log.
 */
static void format_ssl_error(SSL *ssl, int ret, char *buf, size_t buf_size)
{
    unsigned long err;
    int ssl_err = SSL_get_error(ssl, ret);

    err = ERR_get_error();
    if (err != 0) {
        ERR_error_string_n(err, buf, buf_size);
    } else {
        snprintf(buf, buf_size, "SSL_get_error=%d (no queued error)", ssl_err);
    }
}

/**
 * @brief Forward a single, already-framed syslog message to analysisd.
 *
 * Reconnects to the analysisd queue on failure and retries once; if that
 * also fails, the daemon exits because there is no recovery path for a
 * lost analysisd socket.
 */
static void forward_syslog_message(char *msg, char *srcip)
{
    if (SendMSG(logr.m_queue, msg + w_get_pri_header_len(msg), srcip, SYSLOG_MQ) < 0) {
        merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));

        if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
            merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
        }
    }
}

/**
 * @brief Extract and forward every complete syslog record from the socket buffer.
 *
 * Supports both framing formats defined by RFC 6587:
 *
 *   - @b Non-transparent @b framing (§3.4.2): messages separated by '\n'.
 *     This is what plain-text syslog has always used over TCP.
 *
 *   - @b Octet-counting @b framing (§3.4.1) / RFC 5425: each record is prefixed
 *     with its byte length in ASCII followed by a single space. This is what
 *     syslog-over-TLS senders (FortiGate, rsyslog omfwd, syslog-ng, Palo Alto,
 *     Cisco ASA) use by default.
 *
 * The parser auto-detects framing per record by peeking at the first byte.
 * A conforming syslog message per RFC 3164 / 5424 begins with the PRI header
 * '<', never a digit, so the heuristic is unambiguous for well-formed input.
 * Malformed data (bogus octet counts, unterminated records, zero lengths) is
 * dropped with a warning rather than allowed to stall the connection.
 *
 * Any trailing partial record is preserved at the front of the buffer so it
 * can be completed by the next read.
 */
void send_buffer(sockbuffer_t *socket_buffer, char *srcip)
{
    char *data_pt = socket_buffer->data;
    unsigned long remaining = socket_buffer->data_len;

    while (remaining > 0) {
        /* Octet-counting framing: leading ASCII digits followed by a space. */
        if (isdigit((unsigned char)data_pt[0])) {
            unsigned long header_len = 0;
            unsigned long msg_len = 0;
            unsigned long i;
            int saw_space = 0;

            /* Cap the length-prefix scan to 11 characters. That is enough for
             * any OS_MAXSTR value (currently 65536 -> 5 digits) and prevents
             * a buffer full of digits from driving us into the rest of the
             * payload on malformed input. */
            for (i = 0; i < remaining && i < 11; i++) {
                if (data_pt[i] == ' ') {
                    saw_space = 1;
                    header_len = i + 1;
                    break;
                }
                if (!isdigit((unsigned char)data_pt[i])) {
                    /* Neither digit nor space — not an octet count. */
                    break;
                }
            }

            if (saw_space) {
                char *end = NULL;
                msg_len = strtoul(data_pt, &end, 10);

                if (msg_len == 0 || msg_len > (unsigned long)OS_MAXSTR) {
                    mwarn("Dropping malformed octet-count framing from '%s' (len=%lu).",
                          srcip, msg_len);
                    data_pt++;
                    remaining--;
                    continue;
                }

                if (header_len + msg_len > remaining) {
                    /* Incomplete record — wait for more data. */
                    break;
                }

                /* Temporarily NUL-terminate the record so downstream string
                 * handling works, then restore the original byte before we
                 * advance past it. */
                char saved = data_pt[header_len + msg_len];
                data_pt[header_len + msg_len] = '\0';
                forward_syslog_message(data_pt + header_len, srcip);
                data_pt[header_len + msg_len] = saved;

                data_pt += header_len + msg_len;
                remaining -= header_len + msg_len;
                continue;
            }
            /* Fall through to newline-delimited parsing if the octet count
             * didn't actually materialize. */
        }

        /* Non-transparent framing: split on '\n'. */
        {
            char *newline = memchr(data_pt, '\n', remaining);
            if (newline == NULL) {
                /* Partial record — wait for more data. */
                break;
            }

            unsigned long line_len = newline - data_pt;
            *newline = '\0';
            forward_syslog_message(data_pt, srcip);
            data_pt += line_len + 1;
            remaining -= line_len + 1;
        }
    }

    /* Slide any unprocessed tail back to the front of the buffer so the
     * next read continues where this one left off. */
    if (remaining > 0 && data_pt != socket_buffer->data) {
        memmove(socket_buffer->data, data_pt, remaining);
    }
    socket_buffer->data_len = remaining;
}

/**
 * @brief Per-connection read loop. Reads bytes from the plain socket or from
 *        the SSL wrapper and feeds them to send_buffer() for framing.
 *
 * Runs inside the forked child of HandleSyslogTCP(), so any exit from this
 * function terminates that child without affecting the listener.
 */
static void HandleClient(int client_socket, SSL *ssl, char *srcip)
{
    sockbuffer_t socket_buff;
    int r_sz = 0;
    char err_buf[256];

    os_calloc(OS_MAXSTR + 2, sizeof(char), socket_buff.data);
    socket_buff.data_len = 0;

    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    while (1) {
        int space = OS_MAXSTR - (int)socket_buff.data_len;
        if (space <= 0) {
            merror("Syslog read buffer from '%s' exhausted without a complete message; "
                   "dropping connection.", srcip);
            break;
        }

        if (ssl) {
            r_sz = SSL_read(ssl, socket_buff.data + socket_buff.data_len, space);
        } else {
            r_sz = recv(client_socket, socket_buff.data + socket_buff.data_len, space, 0);
        }

        if (r_sz <= 0) {
            if (r_sz < 0) {
                if (ssl) {
                    format_ssl_error(ssl, r_sz, err_buf, sizeof(err_buf));
                    merror("TLS read error from '%s': %s", srcip, err_buf);
                } else {
                    merror(RECV_ERROR, strerror(errno), errno);
                }
            }
            break;
        }

        socket_buff.data_len += (unsigned long)r_sz;
        socket_buff.data[socket_buff.data_len] = '\0';

        mdebug2("Received %d bytes from '%s'%s", r_sz, srcip, ssl ? " (TLS)" : "");

        send_buffer(&socket_buff, srcip);
    }

    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(client_socket);
    DeletePID(ARGV0);
    os_free(socket_buff.data);
}

/* Handle syslog TCP connections, with optional TLS wrapping. */
void HandleSyslogTCP(SSL_CTX *ssl_ctx)
{
    int childcount = 0;
    char srcip[IPSIZE + 1];

    memset(srcip, '\0', IPSIZE + 1);

    /* Connect to the analysisd message queue; exit if it fails. */
    if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
        merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
    }

    while (1) {
        /* Reap any finished children before blocking on accept(). */
        while (childcount) {
            int wp = waitpid((pid_t) - 1, NULL, WNOHANG);
            if (wp < 0) {
                merror(WAITPID_ERROR, errno, strerror(errno));
                break;
            } else if (wp == 0) {
                break;
            } else {
                childcount--;
            }
        }

        int client_socket = OS_AcceptTCP(logr.tcp_sock, srcip, IPSIZE);
        if (client_socket < 0) {
            mwarn("Accepting TCP connection from client failed: %s (%d)", strerror(errno), errno);
            continue;
        }

        if (OS_IPNotAllowed(srcip)) {
            mwarn(DENYIP_WARN, srcip);
            close(client_socket);
            continue;
        }

        /* Fork-per-connection: each child gets an isolated address space so a
         * protocol bug in OpenSSL cannot corrupt other in-flight sessions. The
         * SSL_CTX is reference-counted by OpenSSL and safe to share across
         * forked children via copy-on-write; we only read from it per-connection
         * via SSL_new(). This matches the model the plain-TCP syslog listener
         * has always used, so TLS does not change the supervisor's contract. */
        pid_t pid = fork();
        if (pid == 0) {
            SSL *ssl = NULL;

            if (ssl_ctx != NULL) {
                ssl = SSL_new(ssl_ctx);
                if (ssl == NULL) {
                    char err_buf[256];
                    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
                    merror("Failed to create TLS session for client '%s': %s", srcip, err_buf);
                    close(client_socket);
                    exit(1);
                }

                if (SSL_set_fd(ssl, client_socket) != 1) {
                    char err_buf[256];
                    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
                    merror("SSL_set_fd failed for client '%s': %s", srcip, err_buf);
                    SSL_free(ssl);
                    close(client_socket);
                    exit(1);
                }

                int hs = SSL_accept(ssl);
                if (hs <= 0) {
                    char err_buf[256];
                    format_ssl_error(ssl, hs, err_buf, sizeof(err_buf));
                    merror("TLS handshake failed for client '%s': %s", srcip, err_buf);
                    SSL_free(ssl);
                    close(client_socket);
                    exit(1);
                }

                minfo("Syslog TLS connection established from '%s' (protocol: %s, cipher: %s).",
                      srcip,
                      SSL_get_version(ssl),
                      SSL_get_cipher_name(ssl));
            }

            HandleClient(client_socket, ssl, srcip);
            exit(0);
        } else if (pid > 0) {
            childcount++;
            close(client_socket);
        } else {
            merror("fork() failed accepting syslog client from '%s': %s", srcip, strerror(errno));
            close(client_socket);
        }
    }
}

STATIC size_t w_get_pri_header_len(const char * syslog_msg)
{
    size_t retval = 0;          // Offset
    char * pri_head_end = NULL; // end of <PRI> head

    if (syslog_msg != NULL && syslog_msg[0] == '<') {
        pri_head_end = strchr(syslog_msg + 1, '>');
        if (pri_head_end != NULL) {
            retval = (pri_head_end + 1) - syslog_msg;
        }
    }

    return retval;
}
