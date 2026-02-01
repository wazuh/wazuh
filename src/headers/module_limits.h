/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MODULE_LIMITS_H
#define MODULE_LIMITS_H

#include <stdbool.h>

/* FIM default values */
#define DEFAULT_FIM_FILE_LIMIT                          0
#define DEFAULT_FIM_REGISTRY_KEY_LIMIT                  0
#define DEFAULT_FIM_REGISTRY_VALUE_LIMIT                0

/* Syscollector default values */
#define DEFAULT_SYSCOLLECTOR_HOTFIXES_LIMIT             0
#define DEFAULT_SYSCOLLECTOR_PACKAGES_LIMIT             0
#define DEFAULT_SYSCOLLECTOR_PROCESSES_LIMIT            0
#define DEFAULT_SYSCOLLECTOR_PORTS_LIMIT                0
#define DEFAULT_SYSCOLLECTOR_NETWORK_IFACE_LIMIT        0
#define DEFAULT_SYSCOLLECTOR_NETWORK_PROTO_LIMIT        0
#define DEFAULT_SYSCOLLECTOR_NETWORK_ADDR_LIMIT         0
#define DEFAULT_SYSCOLLECTOR_HARDWARE_LIMIT             0
#define DEFAULT_SYSCOLLECTOR_OS_INFO_LIMIT              0
#define DEFAULT_SYSCOLLECTOR_USERS_LIMIT                0
#define DEFAULT_SYSCOLLECTOR_GROUPS_LIMIT               0
#define DEFAULT_SYSCOLLECTOR_SERVICES_LIMIT             0
#define DEFAULT_SYSCOLLECTOR_BROWSER_EXTENSIONS_LIMIT   0

/* SCA default values */
#define DEFAULT_SCA_CHECKS_LIMIT                        0

/**
 * @brief FIM module limits structure
 */
typedef struct fim_limits_t {
    int file;
    int registry_key;
    int registry_value;
} fim_limits_t;

/**
 * @brief Syscollector module limits structure
 */
typedef struct syscollector_limits_t {
    int hotfixes;
    int packages;
    int processes;
    int ports;
    int network_iface;
    int network_protocol;
    int network_address;
    int hardware;
    int os_info;
    int users;
    int groups;
    int services;
    int browser_extensions;
} syscollector_limits_t;

/**
 * @brief SCA module limits structure
 */
typedef struct sca_limits_t {
    int checks;
} sca_limits_t;

/**
 * @brief Structure to hold all module limits
 */
typedef struct module_limits_t {
    fim_limits_t fim;
    syscollector_limits_t syscollector;
    sca_limits_t sca;
    bool limits_received;
} module_limits_t;

/**
 * @brief Initialize module limits structure with default values
 * @param limits Pointer to structure to initialize
 */
void module_limits_init(module_limits_t *limits);

/**
 * @brief Reset structure to default values
 * @param limits Pointer to structure to reset
 */
void module_limits_reset(module_limits_t *limits);

/**
 * @brief Initialize FIM limits with defaults
 * @param fim Pointer to FIM limits structure
 */
void fim_limits_init(fim_limits_t *fim);

/**
 * @brief Initialize Syscollector limits with defaults
 * @param syscollector Pointer to Syscollector limits structure
 */
void syscollector_limits_init(syscollector_limits_t *syscollector);

/**
 * @brief Initialize SCA limits with defaults
 * @param sca Pointer to SCA limits structure
 */
void sca_limits_init(sca_limits_t *sca);

#endif /* MODULE_LIMITS_H */
