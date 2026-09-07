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

/* Syscollector container-inventory default values (#37532 / #37534).
 *
 * Separate from the host limits above, and that separation IS the point:
 * container rows and host rows share a sync index, so with one budget a node
 * running fifty containers can spend the whole host processes cap on container
 * processes, and which rows survive is decided by scan order. One cap per
 * dimension, shared across every container on the agent (not per container).
 *
 * Default 0 = unlimited, so an agent that never hears these behaves exactly as
 * before — except that container rows no longer draw down the host's counters. */
#define DEFAULT_SYSCOLLECTOR_CONTAINERS_PROCESSES_LIMIT       0
#define DEFAULT_SYSCOLLECTOR_CONTAINERS_PORTS_LIMIT           0
#define DEFAULT_SYSCOLLECTOR_CONTAINERS_PACKAGES_LIMIT        0
#define DEFAULT_SYSCOLLECTOR_CONTAINERS_USERS_LIMIT           0
#define DEFAULT_SYSCOLLECTOR_CONTAINERS_GROUPS_LIMIT          0
#define DEFAULT_SYSCOLLECTOR_CONTAINERS_OS_INFO_LIMIT         0
#define DEFAULT_SYSCOLLECTOR_CONTAINERS_NETWORK_IFACE_LIMIT   0
#define DEFAULT_SYSCOLLECTOR_CONTAINERS_NETWORK_PROTO_LIMIT   0
#define DEFAULT_SYSCOLLECTOR_CONTAINERS_NETWORK_ADDR_LIMIT    0
#define DEFAULT_SYSCOLLECTOR_CONTAINERS_HARDWARE_LIMIT        0

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
 * @brief Syscollector container-inventory module limits structure
 * (#37532 / #37534).
 *
 * Per-dimension row ceiling shared across every container on the agent; 0 means
 * unlimited, the same convention as syscollector_limits_t. No `hotfixes`,
 * `services` or `browser_extensions`: the container scanner does not collect
 * those, so a cap for them would be a knob with nothing behind it.
 */
typedef struct syscollector_containers_limits_t {
    int processes;
    int ports;
    int packages;
    int users;
    int groups;
    int os_info;
    int network_iface;
    int network_protocol;
    int network_address;
    int hardware;
} syscollector_containers_limits_t;

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
    syscollector_containers_limits_t syscollector_containers;
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
void syscollector_containers_limits_init(syscollector_containers_limits_t *syscollector_containers);

/**
 * @brief Initialize SCA limits structure with default values
 * @param sca Pointer to structure to initialize
 */
void sca_limits_init(sca_limits_t *sca);

/**
 * @brief Compare two module limits structures
 * @param limits1 First limits structure
 * @param limits2 Second limits structure
 * @return true if limits are different, false if they are the same
 */
bool module_limits_changed(const module_limits_t *limits1, const module_limits_t *limits2);

#endif /* MODULE_LIMITS_H */
