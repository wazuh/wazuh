/* Copyright (C) Wazuh Inc.
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

/* Container FIM's document budget, PER CONTAINER (#37532 / O10).
 *
 * It lives in the fim namespace rather than one of its own because that is how
 * every other limit is spelled: fim.file_limit bounds the host, and
 * fim.container_file_limit bounds each container separately. There is no
 * registry counterpart -- containers are Linux-only here and registry
 * monitoring is Windows-only.
 *
 * PER CONTAINER is the whole point: one budget shared by every container lets
 * one of them spend the rest's allowance, and which rows survive is then
 * decided by scan order. Measured on a real node, one container produced 25% of
 * the node's inventory rows -- see 23-nfr3-container-limits.md.
 *
 * 30000 matches the host cap. A manager that never sends it leaves the agent
 * on this value, which is the same answer the host gets. */
#define DEFAULT_FIM_CONTAINER_FILE_LIMIT                30000

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

/* Syscollector container-inventory default values, PER CONTAINER
 * (#37532 / #37534 / O10).
 *
 * Spelled container_<dimension> inside the syscollector namespace, like every
 * other limit, rather than in a namespace of their own.
 *
 * PER CONTAINER is the point: container rows and host rows share a sync index,
 * so one budget across all containers lets a node running fifty of them spend
 * the host's allowance, and which rows survive is then decided by scan order.
 * Measured on a real node, ONE container produced 25% of all container
 * inventory rows -- see 23-nfr3-container-limits.md.
 *
 * ELEVEN dimensions, mirroring CONTAINER_BASELINE_TABLES rather than the host's
 * thirteen. `hotfixes` has no Linux data source at all and containers here are
 * Linux-only, so a cap for it could never do anything; `browser_extensions` has
 * no container scanner yet. `services` IS collected -- it was left out on the
 * belief that containers run no init, and measurement disproved that.
 *
 * 30000 matches the host caps. An agent that never hears them stays on this
 * value, and container rows no longer draw down the host's counters either way. */
#define DEFAULT_SYSCOLLECTOR_CONTAINER_PROCESSES_LIMIT        30000
#define DEFAULT_SYSCOLLECTOR_CONTAINER_PORTS_LIMIT            30000
#define DEFAULT_SYSCOLLECTOR_CONTAINER_PACKAGES_LIMIT         30000
#define DEFAULT_SYSCOLLECTOR_CONTAINER_USERS_LIMIT            30000
#define DEFAULT_SYSCOLLECTOR_CONTAINER_GROUPS_LIMIT           30000
#define DEFAULT_SYSCOLLECTOR_CONTAINER_OS_INFO_LIMIT          30000
#define DEFAULT_SYSCOLLECTOR_CONTAINER_NETWORK_IFACE_LIMIT    30000
#define DEFAULT_SYSCOLLECTOR_CONTAINER_NETWORK_PROTO_LIMIT    30000
#define DEFAULT_SYSCOLLECTOR_CONTAINER_NETWORK_ADDR_LIMIT     30000
#define DEFAULT_SYSCOLLECTOR_CONTAINER_HARDWARE_LIMIT         30000
#define DEFAULT_SYSCOLLECTOR_CONTAINER_SERVICES_LIMIT         30000

/* SCA default values */
#define DEFAULT_SCA_CHECKS_LIMIT                        0

/**
 * @brief FIM module limits structure
 */
typedef struct fim_limits_t {
    int file;
    int container_file; /* Per container, not shared across them. */
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
    /* Per container, not shared across them (#37532 / O10). Eleven, mirroring
     * CONTAINER_BASELINE_TABLES: no hotfixes (no Linux data source) and no
     * browser_extensions (no container scanner). */
    int container_processes;
    int container_ports;
    int container_packages;
    int container_users;
    int container_groups;
    int container_os_info;
    int container_network_iface;
    int container_network_protocol;
    int container_network_address;
    int container_hardware;
    int container_services;
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
