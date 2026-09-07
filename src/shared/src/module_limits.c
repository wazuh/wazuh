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

void syscollector_containers_limits_init(syscollector_containers_limits_t *syscollector_containers) {
    if (!syscollector_containers) {
        return;
    }
    syscollector_containers->processes = DEFAULT_SYSCOLLECTOR_CONTAINERS_PROCESSES_LIMIT;
    syscollector_containers->ports = DEFAULT_SYSCOLLECTOR_CONTAINERS_PORTS_LIMIT;
    syscollector_containers->packages = DEFAULT_SYSCOLLECTOR_CONTAINERS_PACKAGES_LIMIT;
    syscollector_containers->users = DEFAULT_SYSCOLLECTOR_CONTAINERS_USERS_LIMIT;
    syscollector_containers->groups = DEFAULT_SYSCOLLECTOR_CONTAINERS_GROUPS_LIMIT;
    syscollector_containers->os_info = DEFAULT_SYSCOLLECTOR_CONTAINERS_OS_INFO_LIMIT;
    syscollector_containers->network_iface = DEFAULT_SYSCOLLECTOR_CONTAINERS_NETWORK_IFACE_LIMIT;
    syscollector_containers->network_protocol = DEFAULT_SYSCOLLECTOR_CONTAINERS_NETWORK_PROTO_LIMIT;
    syscollector_containers->network_address = DEFAULT_SYSCOLLECTOR_CONTAINERS_NETWORK_ADDR_LIMIT;
    syscollector_containers->hardware = DEFAULT_SYSCOLLECTOR_CONTAINERS_HARDWARE_LIMIT;
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
    syscollector_containers_limits_init(&limits->syscollector_containers);
    sca_limits_init(&limits->sca);
    limits->limits_received = false;
}

void module_limits_reset(module_limits_t *limits) {
    module_limits_init(limits);
}

bool module_limits_changed(const module_limits_t *limits1, const module_limits_t *limits2) {
    if (!limits1 || !limits2) {
        return false;
    }

    // Compare FIM limits
    if (limits1->fim.file != limits2->fim.file ||
        limits1->fim.registry_key != limits2->fim.registry_key ||
        limits1->fim.registry_value != limits2->fim.registry_value) {
        return true;
    }

    // Compare Syscollector limits
    if (limits1->syscollector.hotfixes != limits2->syscollector.hotfixes ||
        limits1->syscollector.packages != limits2->syscollector.packages ||
        limits1->syscollector.processes != limits2->syscollector.processes ||
        limits1->syscollector.ports != limits2->syscollector.ports ||
        limits1->syscollector.network_iface != limits2->syscollector.network_iface ||
        limits1->syscollector.network_protocol != limits2->syscollector.network_protocol ||
        limits1->syscollector.network_address != limits2->syscollector.network_address ||
        limits1->syscollector.hardware != limits2->syscollector.hardware ||
        limits1->syscollector.os_info != limits2->syscollector.os_info ||
        limits1->syscollector.users != limits2->syscollector.users ||
        limits1->syscollector.groups != limits2->syscollector.groups ||
        limits1->syscollector.services != limits2->syscollector.services ||
        limits1->syscollector.browser_extensions != limits2->syscollector.browser_extensions) {
        return true;
    }

    // Compare Syscollector container-inventory limits
    if (limits1->syscollector_containers.processes != limits2->syscollector_containers.processes ||
        limits1->syscollector_containers.ports != limits2->syscollector_containers.ports ||
        limits1->syscollector_containers.packages != limits2->syscollector_containers.packages ||
        limits1->syscollector_containers.users != limits2->syscollector_containers.users ||
        limits1->syscollector_containers.groups != limits2->syscollector_containers.groups ||
        limits1->syscollector_containers.os_info != limits2->syscollector_containers.os_info ||
        limits1->syscollector_containers.network_iface != limits2->syscollector_containers.network_iface ||
        limits1->syscollector_containers.network_protocol != limits2->syscollector_containers.network_protocol ||
        limits1->syscollector_containers.network_address != limits2->syscollector_containers.network_address ||
        limits1->syscollector_containers.hardware != limits2->syscollector_containers.hardware) {
        return true;
    }

    // Compare SCA limits
    if (limits1->sca.checks != limits2->sca.checks) {
        return true;
    }

    return false;
}
