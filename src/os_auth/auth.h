/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
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

#ifndef _AUTHD_H
#define _AUTHD_H

#ifndef ARGV0
#define ARGV0 "ossec-authd"
#endif

#include "addagent/manage_agents.h"
#include "os_net/os_net.h"
#include "config/authd-config.h"
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

extern BIO *bio_err;
#define KEYFILE  "/etc/sslmanager.key"
#define CERTFILE "/etc/sslmanager.cert"
#define DEFAULT_CIPHERS "HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH"
#define DEFAULT_PORT 1515
#define DEFAULT_CENTRALIZED_GROUP "default"
#define DEPRECATED_OPTION_WARN "Option '%s' is deprecated. Configure it in the file " DEFAULTCPATH "."

#define full(i, j) ((i + 1) % AUTH_POOL == j)
#define empty(i, j) (i == j)
#define forward(x) x = (x + 1) % AUTH_POOL

struct client {
    int socket;
    struct in_addr addr;
};

struct keynode {
    char *id;
    char *name;
    char *ip;
    char *group;
    struct keynode *next;
};

SSL_CTX *os_ssl_keys(int is_server, const char *os_dir, const char *ciphers, const char *cert, const char *key, const char *ca_cert, int auto_method);
SSL_CTX *get_ssl_context(const char *ciphers, int auto_method);
int load_cert_and_key(SSL_CTX *ctx, const char *cert, const char *key);
int load_ca_cert(SSL_CTX *ctx, const char *ca_cert);
int verify_callback(int ok, X509_STORE_CTX *store);

// Thread for internal server
void* run_local_server(void *arg);

// Append key to insertion queue
void add_insert(const keyentry *entry,const char *group);

// Append key to backup queue
void add_backup(const keyentry *entry);

// Append key to deletion queue
void add_remove(const keyentry *entry);

// Read configuration
int authd_read_config(const char *path);
cJSON *getAuthdConfig(void);
size_t authcom_dispatch(const char * command, char ** output);
size_t authcom_getconfig(const char * section, char ** output);

// Block signals
void authd_sigblock();

extern char shost[];
extern keystore keys;
extern volatile int write_pending;
extern volatile int running;
extern pthread_mutex_t mutex_keys;
extern pthread_cond_t cond_pending;
extern authd_config_t config;

#endif /* _AUTHD_H */
