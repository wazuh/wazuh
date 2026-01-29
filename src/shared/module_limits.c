/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "module_limits.h"

void fim_limits_init(fim_limits_t *fim) {
    if (!fim) {
        return;
    }
    fim->file = DEFAULT_FIM_FILE_LIMIT;
    fim->registry_key = DEFAULT_FIM_REGISTRY_KEY_LIMIT;
    fim->registry_value = DEFAULT_FIM_REGISTRY_VALUE_LIMIT;
}

void syscollector_limits_init(syscollector_limits_t *syscollector) {
    if (!syscollector) {
        return;
    }
    syscollector->hotfixes = DEFAULT_SYSCOLLECTOR_HOTFIXES_LIMIT;
    syscollector->packages = DEFAULT_SYSCOLLECTOR_PACKAGES_LIMIT;
    syscollector->processes = DEFAULT_SYSCOLLECTOR_PROCESSES_LIMIT;
    syscollector->ports = DEFAULT_SYSCOLLECTOR_PORTS_LIMIT;
    syscollector->network_iface = DEFAULT_SYSCOLLECTOR_NETWORK_IFACE_LIMIT;
    syscollector->network_protocol = DEFAULT_SYSCOLLECTOR_NETWORK_PROTO_LIMIT;
    syscollector->network_address = DEFAULT_SYSCOLLECTOR_NETWORK_ADDR_LIMIT;
    syscollector->hardware = DEFAULT_SYSCOLLECTOR_HARDWARE_LIMIT;
    syscollector->os_info = DEFAULT_SYSCOLLECTOR_OS_INFO_LIMIT;
    syscollector->users = DEFAULT_SYSCOLLECTOR_USERS_LIMIT;
    syscollector->groups = DEFAULT_SYSCOLLECTOR_GROUPS_LIMIT;
    syscollector->services = DEFAULT_SYSCOLLECTOR_SERVICES_LIMIT;
    syscollector->browser_extensions = DEFAULT_SYSCOLLECTOR_BROWSER_EXTENSIONS_LIMIT;
}

void sca_limits_init(sca_limits_t *sca) {
    if (!sca) {
        return;
    }
    sca->checks = DEFAULT_SCA_CHECKS_LIMIT;
}

void module_limits_init(module_limits_t *limits) {
    if (!limits) {
        return;
    }
    fim_limits_init(&limits->fim);
    syscollector_limits_init(&limits->syscollector);
    sca_limits_init(&limits->sca);
    limits->limits_received = false;
}

void module_limits_reset(module_limits_t *limits) {
    module_limits_init(limits);
}
