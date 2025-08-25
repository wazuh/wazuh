/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/**
 * @file enrollment_op.h
 * @date 4 April 2020
 * @brief Library that handles the enrollment process of an agent
 *
 * Wazuh agents need to register to a manager before being able to start sending messages
 * There are several way of registering according to manager's configuration
 * This library receives a enrollment configuration and target especification and registers to the
 * manager or shows several messages in case of failure
 * For details on enrollment process @see https://documentation.wazuh.com/3.12/user-manual/registering/
 */
#ifndef ENROLLMENT_CLIENT_H
#define ENROLLMENT_CLIENT_H

#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include "sec.h"

#define ENROLLMENT_WRONG_CONFIGURATION -1
#define ENROLLMENT_CONNECTION_FAILURE -2

/**
 * @brief Struct that defines the connection target
 * */
typedef struct _enrollment_target_cfg {
    char *manager_name;       /**< Manager's direction or ip address */
    int port;                 /**< Manager's port */
    uint32_t network_interface;  /**< (optional) Interface name to use in IPv6(link-local) connections */
    char *agent_name;         /**< (optional) Name of the agent. In case of NULL enrollment message will send local hostname */
    char *centralized_group;  /**< (optional) In case the agent belong to a group */
    char *sender_ip;          /**< (optional) IP adress or CIDR of the agent. In case of null the manager will use the source ip */
    int use_src_ip;           /**< (optional) Forces manager to use source ip  */
} w_enrollment_target;

/**
 * @brief Certificate configurations
 *
 * Struct that defines the enrollment certificate configuration
 * Client Enrollment methods:
 * 1. Simple verification (only chipers needed)
 * 2. Password (uses authpass param)
 * 3. Manager Verificatiion (uses ca_cert param)
 * 4. Manager and Agent Verification (uses agent_cert and agent_key params)
 */
typedef struct _enrollment_cert_cfg {
    char *ciphers;              /**< chipers string (default DEFAULT_CIPHERS) */
    char *authpass_file;        /**< password file (default AUTHD_PASS) */
    char *authpass;             /**< override password file for password verification */
    char *agent_cert;           /**< Agent Certificate (null if not used) */
    char *agent_key;            /**< Agent Key (null if not used) */
    char *ca_cert;              /**< CA Certificate to verificate server (null if not used) */
    unsigned int auto_method:1; /**< 0 for TLS v1.2 only (Default), 1 for Auto negotiate the most secure common SSL/TLS method with the client. */
} w_enrollment_cert;

/**
 * @brief Strcture that handles all the enrollment configuration
 * */
typedef struct _enrollment_ctx {
    w_enrollment_target *target_cfg;    /**< for details @see _enrollment_target_cfg */
    w_enrollment_cert *cert_cfg;        /**< for details @see _enrollment_cert_cfg */
    keystore *keys;                     /**< keys structure */
    SSL *ssl;                           /**< will hold the connection instance with the manager */
    bool enabled;                       /**< enables / disables auto enrollment */
    bool allow_localhost;               /**< true by default. If this flag is false, using agent_name "localhost" will not be allowed */
    time_t delay_after_enrollment;      /**< 20 by default, number of seconds to wait for enrollment */
    char *agent_version;                /**< will hold the __ossec_version value*/
    int recv_timeout;                   /**< reception timeout, in seconds */
} w_enrollment_ctx;

/**
 * Default initialization of w_enrollment_target
 * structure
 * */
w_enrollment_target *w_enrollment_target_init();

/**
 * Frees enrollment_target structure
 * */
void w_enrollment_target_destroy(w_enrollment_target *target);

/**
 * Default initialization of w_enrollment_cert
 * structure
 * */
w_enrollment_cert *w_enrollment_cert_init();

/**
 * Frees enrollment_cert structure
 * */
void w_enrollment_cert_destroy(w_enrollment_cert *cert);

/**
 * Initializes parameters of an w_enrollment_ctx structure based
 * on a target and certificate configurations
 * */
w_enrollment_ctx * w_enrollment_init(w_enrollment_target *target, w_enrollment_cert *cert, keystore *keys);

/**
 * Frees parameers of an w_enrollment_ctx structure
 * target_cfg and cert_cfg should be freed on their own since there are constant pointers
 * */
void w_enrollment_destroy(w_enrollment_ctx *cfg);

/**
 * @brief Generates an enrollment process
 *
 * @param cfg configuration @see w_enrollment_ctx
 * @param server_adress (optional) If null server_adress will be obtained from cfg
 * @param network_interface (not necesary for IPv4) Host network interface to use in an IPv6 connection.
 * @return 0 if successfull, -1 on error
 * */
int w_enrollment_request_key(w_enrollment_ctx *cfg, const char * server_address, uint32_t network_interface);

#endif
