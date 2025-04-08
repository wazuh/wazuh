/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 */

#ifndef AUTHD_H
#define AUTHD_H

#ifndef ARGV0
#define ARGV0 "wazuh-authd"
#endif

#include "../addagent/manage_agents.h"
#include "../os_net/os_net.h"
#include "../config/authd-config.h"
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "../os_crypto/md5/md5_op.h"
#include "../os_crypto/sha1/sha1_op.h"

extern BIO *bio_err;
#define KEYFILE  "etc/sslmanager.key"
#define CERTFILE "etc/sslmanager.cert"
#define DEFAULT_CIPHERS "HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH"
#define DEFAULT_PORT 1515
#define DEFAULT_CENTRALIZED_GROUP "default"
#define DEPRECATED_OPTION_WARN "Option '%s' is deprecated. Configure it in the file '%s'."
#define MAX_SSL_PACKET_SIZE 16384
#define SERVER_INDEX 0
#define STOP_FD (AUTH_POOL+1)

#define full(i, j) ((i + 1) % AUTH_POOL == j)
#define empty(i, j) (i == j)
#define forward(x) x = (x + 1) % AUTH_POOL

struct client {
    int socket;
    int index;
    union {
        struct in_addr *addr4;
        struct in6_addr *addr6;
    };
    bool is_ipv6;
    SSL *ssl;
    bool handshake_done;
    char ip[IPSIZE + 1];

    char read_buffer[MAX_SSL_PACKET_SIZE + 1];
    int  read_offset;

    char write_buffer[MAX_SSL_PACKET_SIZE + 1];
    int  write_offset;
    int  write_len;

    char* agentname;
    char* centralized_group;
    char* new_id;
};

struct keynode {
    char *id;
    char *name;
    char *ip;
    char *group;
    char *raw_key;
    struct keynode *next;
};

SSL_CTX *os_ssl_keys(int is_server, const char *os_dir, const char *ciphers, const char *cert, const char *key, const char *ca_cert, int auto_method);
SSL_CTX *get_ssl_context(const char *ciphers, int auto_method);
int load_cert_and_key(SSL_CTX *ctx, const char *cert, const char *key);
int load_ca_cert(SSL_CTX *ctx, const char *ca_cert);
int verify_callback(int ok, X509_STORE_CTX *store);

/**
 * @brief Wraps SSL_read function to read block largers than a record (16K)
 *
 * Calls SSL_read and if the return value is exactly the size of a record
 * calls again with an offset in the buffer until reading is done or until
 * reaching a reading timeout
 * @param ssl ssl connection
 * @param buf buffer to store the read information
 * @param num maximum number of bytes to read
 * */
int wrap_SSL_read(SSL *ssl, void *buf, int num);

// Thread for internal server
void* run_local_server(void *arg);

// Append key to insertion queue
void add_insert(const keyentry *entry,const char *group);

// Append key to deletion queue
void add_remove(const keyentry *entry);

// Read configuration
int authd_read_config(const char *path);
cJSON *getAuthdConfig(void);
size_t authcom_dispatch(const char * command, char ** output);
size_t authcom_getconfig(const char * section, char ** output);

// Block signals
void authd_sigblock();

/**
 * @brief Validate if groups are valid for new enrollment
 * @param groups Comma separated string with new enrollment groups
 * @param response 2048 length buffer where the error response will be copied. NULL if no response is required
 * */
w_err_t w_auth_validate_groups(const char *groups, char *response);

/**
 * @brief Parse a raw buffer from agent request into enrollment data.
 * @param buf Raw buffer to be parsed
 * @param response 2048 length buffer where the error response will be copied
 * @param authpass Authentication password expected on the buffer, NULL if there isn't password
 * @param ip IP direction of the request. Can be override with IP parsed from buffer
 * @param agentname Pointer where parsed agent name will be allocated
 * @param groups Pointer where parsed groups will be allocated
 * @param key_hash Pointer where parsed key hash will be allocated
 * */
w_err_t w_auth_parse_data(const char* buf,
                          char *response,
                          const char *authpass,
                          char *ip,
                          char **agentname,
                          char **groups,
                          char **key_hash);

/**
 * @brief Validates if new enrollment is possible with provided data.
 * With force configuration disabled, if enrollment data is already registered, validation will fail.
 * With force configuration enabled, duplicated entry will be removed.
 * @param response 2048 length buffer where the error response will be copied
 * @param ip New enrollment ip direction
 * @param agentname New enrollment agent name
 * @param groups New enrollment groups
 * @param hash_key Hash of the key on the agent
 * */
w_err_t w_auth_validate_data(char *response,
                             const char *ip,
                             const char *agentname,
                             const char *groups,
                             const char *hash_key);

/**
 * @brief Validates if the old agent can be replaced and removes it.
 * @param key Key structure of the agent to be removed
 * @param hash_key Hash of the key on the agent
 * @param force_options Force configuration structure to define how the agent replacement must be handled.
 * @param str_result A message related to the result of the agent replacement. Must be freed by the caller.
 * */
w_err_t w_auth_replace_agent(keyentry *key,
                             const char *key_hash,
                             authd_force_options_t *force_options,
                             char** str_result);

/**
 * @brief Adds new agent with provided enrollment data.
 * @param response 2048 length buffer where the error response will be copied
 * @param ip New enrollment ip direction
 * @param agentname New enrollment agent name
 * @param id Pointer where new Agent ID will be allocated
 * @param key Pointer where new Agent key will be allocated
 * */
w_err_t w_auth_add_agent(char *response,
                         const char *ip,
                         const char *agentname,
                         char **id,
                         char **key);

/**
 * @brief Adds new agent from a local request
 * @param id Agent ID of the agent to be registered
 * @param ip Agent IP of the agent to be registered
 * @param groups Groups to which the agent belongs
 * @param key Agent key if was already registered
 * @param key_hash Hash of the agent key
 * @param force_options Options to decide if forcing the insertion
 * @return JSON object with the response
 * */
cJSON* local_add(const char *id,
                        const char *name,
                        const char *ip,
                        const char *groups,
                        const char *key,
                        const char *key_hash,
                        authd_force_options_t *force_options);

/**
 * @brief Returns a MD5 hash of some random data collected from different sources.
 *        The result must be freed by the caller.
 *
 * @return const char* The resulting hash or NULL on error.
 */
char *w_generate_random_pass();

extern char shost[512];
extern keystore keys;
extern volatile int write_pending;
extern volatile int running;
extern pthread_mutex_t mutex_keys;
extern pthread_cond_t cond_pending;
extern authd_config_t config;

#endif /* AUTHD_H */
