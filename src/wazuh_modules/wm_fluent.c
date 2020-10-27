/*
 * Wazuh Module for Fluent Forwarder
 * Copyright (C) 2015-2020, Wazuh Inc.
 * January 25, 2019.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef WIN32

#include "wmodules.h"
#include <os_net/os_net.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha512/sha512_op.h"
#include "shared.h"
#include "msgpack.h"

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror_critical(msg, ...) _mterror_critical(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

#define REQUEST_SIZE 4096

#define expect_type(obj, t, str) if (obj.type != t) { mdebug2("Expecting %s", str); goto error; }
#define expect_string(obj, s) if (strncmp(obj.via.str.ptr, s, obj.via.str.size)) { mdebug2("Expecting string '%s'", s); goto error; }
#define filled_string(s) (s && *s)

static void * wm_fluent_main(wm_fluent_t * data);   // Module main function. It won't return
static void wm_fluent_destroy(wm_fluent_t * data);  // Destroy data
cJSON *wm_fluent_dump(const wm_fluent_t * data);     // Read config

static char * wm_fluent_strdup(const msgpack_object_str * str);
static char * wm_fluent_bindup(const msgpack_object_bin * bin);
static int wm_fluent_connect(wm_fluent_t * fluent);
static int wm_fluent_ssl_ctx(wm_fluent_t * fluent);
static int wm_fluent_ssl_connect(wm_fluent_t * fluent);
static void wm_fluent_helo_free(wm_fluent_helo_t * helo);
static void wm_fluent_pong_free(wm_fluent_pong_t * pong);
static int wm_fluent_recv(wm_fluent_t * fluent, msgpack_unpacker * unp);
static int wm_fluent_unpack(wm_fluent_t * fluent, msgpack_unpacker * unp, msgpack_unpacked * result);
static wm_fluent_helo_t * wm_fluent_recv_helo(wm_fluent_t * fluent);
static int wm_fluent_send_ping(wm_fluent_t * fluent, const wm_fluent_helo_t * helo);
static wm_fluent_pong_t * wm_fluent_recv_pong(wm_fluent_t * fluent);
static int wm_fluent_hs_tls(wm_fluent_t * fluent);
static int wm_fluent_handshake(wm_fluent_t * fluent);
static int wm_fluent_send(wm_fluent_t * fluent, const char * str, size_t size);
static int wm_fluent_check_config(wm_fluent_t * fluent);
static void wm_fluent_poll_server(wm_fluent_t * fluent);

const wm_context WM_FLUENT_CONTEXT = {
    FLUENT_WM_NAME,
    (wm_routine)wm_fluent_main,
    (wm_routine)(void *)wm_fluent_destroy,
    (cJSON * (*)(const void *))wm_fluent_dump
};

// Module main function. It won't return
void * wm_fluent_main(wm_fluent_t * fluent) {
    int server_sock;
    char * buffer;
    ssize_t recv_b;

    // If module is disabled, exit
    if (fluent->enabled) {
        minfo("Module started.");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    /* Check configuration first */
    if (wm_fluent_check_config(fluent) < 0) {
        merror("Invalid configuration. Closing module.");
        pthread_exit(NULL);
    }

    SSL_load_error_strings();
    SSL_library_init();

    /* Listen socket */
    server_sock = OS_BindUnixDomain(fluent->sock_path, SOCK_DGRAM, OS_MAXSTR);
    if (server_sock < 0) {
        merror("Unable to bind to socket '%s': (%d) %s.", fluent->sock_path, errno, strerror(errno));
        pthread_exit(NULL);
    }

    while (wm_fluent_handshake(fluent) < 0) {
        mdebug2("Handshake failed. Waiting 30 seconds.");
        sleep(30);
    }

    os_malloc(OS_MAXSTR, buffer);

    /* Main loop */
    while (1) {
        switch (wnet_select(server_sock, fluent->poll_interval)) {
        case -1:
            merror("Cannot select input socket: %s (%d). Sleeping 10 minutes.", strerror(errno), errno);
            sleep(600);
            break;

        case 0:
            wm_fluent_poll_server(fluent);
            break;

        case 1:
            recv_b = recv(server_sock, buffer, OS_MAXSTR - 1, 0);

            switch (recv_b) {
            case -1:
                merror("Cannot receive data from '%s': %s (%d)", fluent->sock_path, strerror(errno), errno);
                continue;
            case 0:
                merror("Empty string received from '%s'", fluent->sock_path);
                continue;
            default:
                if (wm_fluent_send(fluent, buffer, recv_b) < 0) {
                    mwarn("Cannot send data to '%s': %s (%d). Reconnecting...", fluent->address, strerror(errno), errno);

                    while (wm_fluent_handshake(fluent) < 0) {
                        mdebug2("Handshake failed. Waiting 30 seconds.");
                        sleep(30);
                    }

                    minfo("Connected to %s:%hu", fluent->address, fluent->port);
                    wm_fluent_send(fluent, buffer, recv_b);
                }
            }
        }

    }

    return NULL;
}

// Destroy data
void wm_fluent_destroy(wm_fluent_t * fluent) {
    free(fluent->tag);
    free(fluent->object_key);
    free(fluent->sock_path);
    free(fluent->address);
    free(fluent->shared_key);
    free(fluent->certificate);
    free(fluent->user_name);
    free(fluent->user_pass);
    os_free(fluent);
}

static char * wm_fluent_strdup(const msgpack_object_str * str) {
    char * string;
    os_malloc(str->size + 1, string);
    memcpy(string, str->ptr, str->size);
    string[str->size] = '\0';
    return string;
}

static char * wm_fluent_bindup(const msgpack_object_bin * bin) {
    char * string;
    os_malloc(bin->size, string);
    memcpy(string, bin->ptr, bin->size);
    return string;
}

static int wm_fluent_connect(wm_fluent_t * fluent) {
    char * ip;

    /* Close old connection */

    if (fluent->client_sock >= 0) {
        close(fluent->client_sock);
        fluent->client_sock = -1;
    }

    /* Resolve host name */

    ip = OS_GetHost(fluent->address, 5);
    if (!ip) {
        merror("Cannot resolve address '%s'", fluent->address);
        return -1;
    }

    /* Connect */

    fluent->client_sock = OS_ConnectTCP(fluent->port, ip, 0);
    free(ip);

    if (fluent->client_sock < 0) {
        merror("Cannot connect to '%s': %s (%d)", fluent->address, strerror(errno), errno);
        return -1;
    }

    /* Set timeout */

    if (fluent->timeout) {
        if (OS_SetSendTimeout(fluent->client_sock, fluent->timeout) < 0) {
            merror("Cannot set sending timeout to '%s': %s (%d)", fluent->address, strerror(errno), errno);
        }

        if (OS_SetRecvTimeout(fluent->client_sock, fluent->timeout, 0) < 0) {
            merror("Cannot set receiving timeout to '%s': %s (%d)", fluent->address, strerror(errno), errno);
        }
    }
    mdebug2("Connected to '%s'.", fluent->address);

    /* Set keepalive */

    if (fluent->keepalive.enabled) {
        if (OS_SetKeepalive(fluent->client_sock) == -1) {
            merror("Cannot enable TCP keepalive on Fluent connection: %s (%d)", strerror(errno), errno);
        } else {
            OS_SetKeepalive_Options(fluent->client_sock, fluent->keepalive.idle, fluent->keepalive.interval, fluent->keepalive.count);
        }
    }

    return 0;
}

static int wm_fluent_ssl_ctx(wm_fluent_t * fluent) {
    /* Free old context */

    if (fluent->ctx) {
        SSL_CTX_free(fluent->ctx);
    }

    /* Create context */

    fluent->ctx = SSL_CTX_new(TLS_method());
    if (!fluent->ctx) {
        merror("Cannot create a SSL context: %s", ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    /* Load CA certificate, if defined */

    if (fluent->certificate) {
        if (fluent->certificate && !SSL_CTX_load_verify_locations(fluent->ctx, fluent->certificate, NULL)) {
            merror("Unable to read CA certificate file '%s': %s", fluent->certificate, ERR_reason_error_string(ERR_get_error()));
            return -1;
        }

        SSL_CTX_set_verify(fluent->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }

    return 0;
}

static int wm_fluent_ssl_connect(wm_fluent_t * fluent) {
    assert(fluent);
    assert(fluent->client_sock >= 0);

    if (fluent->ssl) {
        SSL_free(fluent->ssl);
        fluent->ssl = NULL;
    }

    /* Get context */

    if (wm_fluent_ssl_ctx(fluent) < 0) {
        return -1;
    }

    /* Initialize structures */

    fluent->ssl = SSL_new(fluent->ctx);
    if (!fluent->ssl) {
        merror("Cannot create SSL structure: %s", ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    fluent->bio = BIO_new_socket(fluent->client_sock, 0);
    if (!fluent->bio) {
        merror("Cannot bind SSL to socket: %s", ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    SSL_set_bio(fluent->ssl, fluent->bio, fluent->bio);

    /* SSL handshake */

    switch (SSL_connect(fluent->ssl)) {
    case 0:
        mwarn("Cannot connect to '%s': %s", fluent->address, ERR_reason_error_string(ERR_get_error()));
        return -1;
    case 1:
        return 0;
    default:
        merror("Cannot connect to '%s': %s", fluent->address, ERR_reason_error_string(ERR_get_error()));
        return -1;
    }
}

static void wm_fluent_helo_free(wm_fluent_helo_t * helo) {
    if (helo) {
        free(helo->nonce);
        free(helo->auth);
        free(helo);
    }
}

static void wm_fluent_pong_free(wm_fluent_pong_t * pong) {
    if (pong) {
        free(pong->reason);
        free(pong->server_hostname);
        free(pong->shared_key_hexdigest);
        free(pong);
    }
}

static int wm_fluent_recv(wm_fluent_t * fluent, msgpack_unpacker * unp) {
    int read_b;

    assert(unp);

    /* Extend buffer if needed */

    if (msgpack_unpacker_buffer_capacity(unp) < REQUEST_SIZE && !msgpack_unpacker_reserve_buffer(unp, REQUEST_SIZE)) {
        merror_exit("Cannot extend memory for unpacker.");
    }

    /* Receive data */

    read_b = SSL_read(fluent->ssl, msgpack_unpacker_buffer(unp), 4096);
    if (read_b <= 0) {
        merror("Connection error with '%s': %s", fluent->address, ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    msgpack_unpacker_buffer_consumed(unp, read_b);
    return read_b;
}

static int wm_fluent_unpack(wm_fluent_t * fluent, msgpack_unpacker * unp, msgpack_unpacked * result) {
    msgpack_unpacked_init(result);

    if (wm_fluent_recv(fluent, unp) < 0) {
        return -1;
    }

    if (msgpack_unpacker_next(unp, result) != MSGPACK_UNPACK_SUCCESS) {
        merror("Invalid data received from the server.");
        return -1;
    }

    return 0;
}

static wm_fluent_helo_t * wm_fluent_recv_helo(wm_fluent_t * fluent) {
    msgpack_unpacker unp;
    msgpack_unpacked result;
    wm_fluent_helo_t * helo = NULL;
    msgpack_object * array;
    msgpack_object_kv * map;
    unsigned int i;

    if (!msgpack_unpacker_init(&unp, 4096)) {
        merror_exit("Cannot allocate memory for unpacker.");
    }

    if (wm_fluent_unpack(fluent, &unp, &result)) {
        goto error;
    }

    os_calloc(1, sizeof(wm_fluent_helo_t), helo);
    /* If keepalive is not defined, the default value is true */
    helo->keepalive = 1;

    /* Parse HELO message pack */

    expect_type(result.data, MSGPACK_OBJECT_ARRAY, "array");

    if (result.data.via.array.size < 2) {
        mdebug2("Expecting binary array");
        goto error;
    }

    array = result.data.via.array.ptr;
    expect_type(array[0], MSGPACK_OBJECT_STR, "string");
    expect_string(array[0], "HELO");
    expect_type(array[1], MSGPACK_OBJECT_MAP, "map");

    map = array[1].via.map.ptr;

    for (i = 0; i < array[1].via.map.size; ++i) {
        expect_type(map[i].key, MSGPACK_OBJECT_STR, "string key");

        if (strncmp(map[i].key.via.str.ptr, "nonce", map[i].key.via.str.size) == 0) {
            /* 'nonce' may be either string or binary */

            switch (map[i].val.type) {
            case MSGPACK_OBJECT_STR:
                helo->nonce_size = map[i].val.via.str.size;
                free(helo->nonce);
                helo->nonce = wm_fluent_strdup(&map[i].val.via.str);
                break;

            case MSGPACK_OBJECT_BIN:
                helo->nonce_size = map[i].val.via.bin.size;
                free(helo->nonce);
                helo->nonce = wm_fluent_bindup(&map[i].val.via.bin);
                break;

            default:
                mdebug2("Expecting string or binary value for nonce");
                goto error;
            }
        } else if (strncmp(map[i].key.via.str.ptr, "auth", map[i].key.via.str.size) == 0) {
            /* 'auth' may be either string or binary */

            switch (map[i].val.type) {
            case MSGPACK_OBJECT_STR:
                helo->auth_size = map[i].val.via.str.size;
                free(helo->auth);
                helo->auth = wm_fluent_strdup(&map[i].val.via.str);
                break;

            case MSGPACK_OBJECT_BIN:
                helo->auth_size = map[i].val.via.bin.size;
                free(helo->auth);
                helo->auth = wm_fluent_bindup(&map[i].val.via.bin);
                break;

            default:
                mdebug2("Expecting string or binary value for auth");
                goto error;
            }
        } else if (strncmp(map[i].key.via.str.ptr, "keepalive", map[i].key.via.str.size) == 0) {
            expect_type(map[i].val, MSGPACK_OBJECT_BOOLEAN, "boolean value");
            helo->keepalive = map[i].val.via.boolean;
        } else {
            mdebug2("Unexpected key: %.*s", map[i].key.via.str.size, map[i].key.via.str.ptr);
        }
    }

    /* Check integrity */

    if (helo->nonce_size == 0) {
        merror("The Fluent server sent a HELO message with empty nonce data.");
        goto error;
    }

    if (!helo->nonce) {
        merror("The Fluent server sent a HELO message with no nonce data.");
        goto error;
    }

    if (helo->auth_size > 0 && !helo->auth) {
        merror("The Fluent server sent a HELO message with no auth data.");
        goto error;
    }

    goto end;

error:
    wm_fluent_helo_free(helo);
    helo = NULL;

end:
    msgpack_unpacked_destroy(&result);
    msgpack_unpacker_destroy(&unp);
    return helo;
}

static int wm_fluent_send_ping(wm_fluent_t * fluent, const wm_fluent_helo_t * helo) {
    char salt[16];
    char hostname[512] = "";
    os_sha512 shared_key_hexdigest;
    os_sha512 password = {0};
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    int retval;

    assert(fluent);
    assert(helo);

    randombytes(salt, sizeof(salt));
    if (gethostname(hostname, sizeof(hostname) - 1)) {
        mwarn("Unable to get hostname due to: '%s'.", strerror(errno));
        return OS_INVALID;
    }

    /* Compute shared key hex digest */

    {
        unsigned char md[SHA512_DIGEST_LENGTH];
        SHA512_CTX ctx;
        SHA512_Init(&ctx);

        SHA512_Update(&ctx, salt, sizeof(salt));
        SHA512_Update(&ctx, hostname, strlen(hostname));
        SHA512_Update(&ctx, helo->nonce, helo->nonce_size);
        SHA512_Update(&ctx, fluent->shared_key, strlen(fluent->shared_key));

        SHA512_Final(md, &ctx);
        OS_SHA512_Hex(md, shared_key_hexdigest);
    }


    if (helo->auth_size > 0) {
        unsigned char md[SHA512_DIGEST_LENGTH];
        SHA512_CTX ctx;

        /* Compute password hex digest */

        SHA512_Init(&ctx);
        SHA512_Update(&ctx, helo->auth, helo->auth_size);
        SHA512_Update(&ctx, fluent->user_name, strlen(fluent->user_name));
        SHA512_Update(&ctx, fluent->user_pass, strlen(fluent->user_pass));

        SHA512_Final(md, &ctx);
        OS_SHA512_Hex(md, password);
    }

    /* Pack PING message */

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&pk, 6);
    msgpack_pack_str(&pk, 4);
    msgpack_pack_str_body(&pk, "PING", 4);
    msgpack_pack_str(&pk, strlen(hostname));
    msgpack_pack_str_body(&pk, hostname, strlen(hostname));
    msgpack_pack_str(&pk, sizeof(salt));
    msgpack_pack_str_body(&pk, salt, sizeof(salt));
    msgpack_pack_str(&pk, OS_SHA512_LEN - 1); /* Remove terminator byte */
    msgpack_pack_str_body(&pk, shared_key_hexdigest, OS_SHA512_LEN - 1);

    if (helo->auth_size > 0) {
        msgpack_pack_str(&pk, strlen(fluent->user_name));
        msgpack_pack_str_body(&pk, fluent->user_name, strlen(fluent->user_name));
        msgpack_pack_str(&pk, OS_SHA512_LEN - 1);
        msgpack_pack_str_body(&pk, password, OS_SHA512_LEN - 1);
    } else {
        if (strlen(fluent->user_name) || strlen(fluent->user_pass)){
            mwarn("Credentials are configured but fluentd server does not require authentication. Please check your configuration.");
        }
        msgpack_pack_str(&pk, 0);
        msgpack_pack_str_body(&pk, "", 0);
        msgpack_pack_str(&pk, 0);
        msgpack_pack_str_body(&pk, "", 0);
    }

    /* Send PING message */

    retval = SSL_write(fluent->ssl, sbuf.data, sbuf.size) == (ssize_t)sbuf.size ? 0 : -1;

    msgpack_sbuffer_destroy(&sbuf);
    return retval;
}

static wm_fluent_pong_t * wm_fluent_recv_pong(wm_fluent_t * fluent) {
    msgpack_unpacker unp;
    msgpack_unpacked result;
    wm_fluent_pong_t * pong;
    msgpack_object * array;

    if (!msgpack_unpacker_init(&unp, 4096)) {
        merror_exit("Cannot allocate memory for unpacker.");
    }

    if (wm_fluent_unpack(fluent, &unp, &result)) {
        return NULL;
    }

    os_calloc(1, sizeof(wm_fluent_pong_t), pong);

    expect_type(result.data, MSGPACK_OBJECT_ARRAY, "array");

    if (result.data.via.array.size < 5) {
        mdebug2("Expecting array of size 5");
        goto error;
    }

    array = result.data.via.array.ptr;
    expect_type(array[0], MSGPACK_OBJECT_STR, "string");
    expect_string(array[0], "PONG");

    expect_type(array[1], MSGPACK_OBJECT_BOOLEAN, "boolean");
    pong->auth_result = array[1].via.boolean;

    expect_type(array[2], MSGPACK_OBJECT_STR, "string");
    pong->reason = wm_fluent_strdup(&array[2].via.str);

    expect_type(array[3], MSGPACK_OBJECT_STR, "string");
    pong->server_hostname = wm_fluent_strdup(&array[3].via.str);

    expect_type(array[4], MSGPACK_OBJECT_STR, "string");
    pong->shared_key_hexdigest = wm_fluent_strdup(&array[4].via.str);

    goto end;

error:
    wm_fluent_pong_free(pong);
    pong = NULL;

end:
    msgpack_unpacked_destroy(&result);
    msgpack_unpacker_destroy(&unp);
    return pong;
}

static int wm_fluent_hs_tls(wm_fluent_t * fluent) {
    int retval = -1;

    /* TLS mode */

    if (wm_fluent_ssl_connect(fluent) < 0) {
        return -1;
    }

    mdebug1("Connection with %s:%hu established", fluent->address, fluent->port);

    /* Fluent protocol handshake */
    wm_fluent_helo_t * helo = wm_fluent_recv_helo(fluent);

    if (!helo) {
        merror("Cannot receive HELO message from server");
        return -1;
    }

    wm_fluent_pong_t * pong = NULL;
    if (wm_fluent_send_ping(fluent, helo) < 0) {
        merror("Cannot send PING message to server");
        goto end;
    }

    pong = wm_fluent_recv_pong(fluent);
    if (!pong) {
        merror("Cannot receive PONG message from server");
        goto end;
    }

    /* Check the authentication result */

    if (!pong->auth_result) {
        mwarn("Authentication error: the Fluent server rejected the connection: %s", pong->reason ? pong->reason : "Unknown reason");
        goto end;
    }

    minfo("Connected to host '%s' (%s:%hu)", pong->server_hostname, fluent->address, fluent->port);

    retval = 0;
end:
    wm_fluent_helo_free(helo);
    wm_fluent_pong_free(pong);
    return retval;
}

static int wm_fluent_handshake(wm_fluent_t * fluent) {
    /* Connect to address */

    if (wm_fluent_connect(fluent) < 0) {
        return -1;
    }

    if (fluent->shared_key) {
        if (wm_fluent_hs_tls(fluent) < 0) {
            return -1;
        }
    } else {
        minfo("Connected to host %s:%hu", fluent->address, fluent->port);
    }

    return 0;
}

static int wm_fluent_send(wm_fluent_t * fluent, const char * str, size_t size) {
    size_t taglen = strlen(fluent->tag);
    int retval = -1;

    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);

    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&pk, 4);
    msgpack_pack_str(&pk, taglen);
    msgpack_pack_str_body(&pk, fluent->tag, taglen);
    msgpack_pack_unsigned_int(&pk, time(NULL));
    msgpack_pack_map(&pk, 1);
    msgpack_pack_str(&pk, strlen(fluent->object_key));
    msgpack_pack_str_body(&pk, fluent->object_key, strlen(fluent->object_key));
    msgpack_pack_str(&pk, size);
    msgpack_pack_str_body(&pk, str, size);
    msgpack_pack_map(&pk, 1);
    msgpack_pack_str(&pk, 6);
    msgpack_pack_str_body(&pk, "option", 6);
    msgpack_pack_str(&pk, 8);
    msgpack_pack_str_body(&pk, "optional", 8);

    if (fluent->shared_key) {
        assert(fluent->ssl);
        retval = SSL_write(fluent->ssl, sbuf.data, sbuf.size) == (ssize_t)sbuf.size ? 0 : -1;
    } else {
        if(sbuf.data)
            retval = send(fluent->client_sock, sbuf.data, sbuf.size, 0) == (ssize_t)sbuf.size ? 0 : -1;
    }

    msgpack_sbuffer_destroy(&sbuf);
    return retval;
}

static int wm_fluent_check_config(wm_fluent_t * fluent) {
    /* Tag is required */

    if (!filled_string(fluent->tag)) {
        merror("No tag defined.");
        return -1;
    }

    /* Socket path */

    if (!filled_string(fluent->sock_path)) {
        merror("No socket_path defined.");
        return -1;
    }

    if (!filled_string(fluent->address)) {
        minfo("No client address defined. Using localhost.");
        free(fluent->address);
        os_strdup("localhost", fluent->address);
    }

    /* shared_key implicitly enables SSL */

    if (!filled_string(fluent->shared_key)) {
        if (fluent->certificate) {
            minfo("No shared_key defined. SSL is disabled and the certificate option won't apply.");
        }

        if (filled_string(fluent->user_name)) {
            mwarn("No shared_key defined. SSL is disabled and the user_name option won't apply.");
        } else if (filled_string(fluent->user_pass)) {
            mwarn("No shared_key defined. SSL is disabled and the user_pass option won't apply.");
        }
    }

    /* Password required if user is defined. */

    if (filled_string(fluent->user_name) && !filled_string(fluent->user_pass)) {
        merror("Password required because user_name is defined");
        return -1;
    }


    /* Timeout */

    if (fluent->timeout < 0) {
        merror("Invalid timeout value (negative)");
        return -1;
    }

    return 0;
}

// Poll server connection
void wm_fluent_poll_server(wm_fluent_t * fluent) {
    char buffer[4];
    int flags = fcntl(fluent->client_sock, F_GETFL, 0);

    mdebug2("Polling Fluent server.");

    // Set up non-blocking mode

    if (fcntl(fluent->client_sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        merror("Cannot set up non-blocking mode: %s (%d)", strerror(errno), errno);
        return;
    }

    // Peek connection

    switch (fluent->shared_key ? SSL_read(fluent->ssl, buffer, sizeof(buffer)) : recv(fluent->client_sock, buffer, sizeof(buffer), 0)) {
    case -1:
        // No input data. This is the normal case.
        break;

    case 0:
        minfo("Fluent server is down or timed-out. Reconnecting.");

        while (wm_fluent_handshake(fluent) < 0) {
            mdebug2("Handshake failed. Waiting 30 seconds.");
            sleep(30);
        }

        return;

    default:
        mdebug1("Input data from Fluent server available.");
    }

    // Disable non-blocking mode back

    if (fcntl(fluent->client_sock, F_SETFL, flags) == -1) {
        merror("Cannot restore non-blocking mode: %s (%d)", strerror(errno), errno);
    }
}

cJSON *wm_fluent_dump(const wm_fluent_t *fluent) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();
    cJSON *keepalive = cJSON_CreateObject();

    cJSON_AddStringToObject(wm_wd, "enabled", fluent->enabled ? "yes" : "no");
    if (fluent->tag) cJSON_AddStringToObject(wm_wd, "tag", fluent->tag);
    if (fluent->object_key) cJSON_AddStringToObject(wm_wd, "object_key", fluent->object_key);
    if (fluent->sock_path)cJSON_AddStringToObject(wm_wd, "socket_path", fluent->sock_path);
    if (fluent->address) cJSON_AddStringToObject(wm_wd, "address", fluent->address);
    if (fluent->port) cJSON_AddNumberToObject(wm_wd, "port", fluent->port);
    if (fluent->shared_key) cJSON_AddStringToObject(wm_wd, "shared_key", fluent->shared_key);
    if (fluent->certificate) cJSON_AddStringToObject(wm_wd, "ca_file", fluent->certificate);
    cJSON_AddStringToObject(wm_wd, "user", fluent->user_name);
    cJSON_AddStringToObject(wm_wd, "password", fluent->user_pass);
    cJSON_AddNumberToObject(wm_wd, "timeout", fluent->timeout);
    cJSON_AddNumberToObject(wm_wd, "poll_interval", fluent->poll_interval);

    cJSON_AddStringToObject(keepalive, "enabled", fluent->keepalive.enabled ? "yes" : "no");
    if (fluent->keepalive.count) cJSON_AddNumberToObject(keepalive, "count", fluent->keepalive.count);
    if (fluent->keepalive.idle) cJSON_AddNumberToObject(keepalive, "idle", fluent->keepalive.idle);
    if (fluent->keepalive.interval) cJSON_AddNumberToObject(keepalive, "interval", fluent->keepalive.interval);

    cJSON_AddItemToObject(wm_wd, "keepalive", keepalive);
    cJSON_AddItemToObject(root,"fluent-forward",wm_wd);

    return root;
}
#endif
