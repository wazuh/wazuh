/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "module_limits.h"

/* fim_limits_init tests */

static void test_fim_limits_init_success(void **state) {
    (void)state;
    fim_limits_t fim;

    /* Initialize with garbage to ensure function sets values */
    memset(&fim, 0xFF, sizeof(fim));

    fim_limits_init(&fim);

    assert_int_equal(fim.file, DEFAULT_FIM_FILE_LIMIT);
    assert_int_equal(fim.registry_key, DEFAULT_FIM_REGISTRY_KEY_LIMIT);
    assert_int_equal(fim.registry_value, DEFAULT_FIM_REGISTRY_VALUE_LIMIT);
}

static void test_fim_limits_init_null(void **state) {
    (void)state;

    /* Should not crash when passed NULL */
    fim_limits_init(NULL);
}

/* syscollector_limits_init tests */

static void test_syscollector_limits_init_success(void **state) {
    (void)state;
    syscollector_limits_t syscollector;

    /* Initialize with garbage to ensure function sets values */
    memset(&syscollector, 0xFF, sizeof(syscollector));

    syscollector_limits_init(&syscollector);

    assert_int_equal(syscollector.hotfixes, DEFAULT_SYSCOLLECTOR_HOTFIXES_LIMIT);
    assert_int_equal(syscollector.packages, DEFAULT_SYSCOLLECTOR_PACKAGES_LIMIT);
    assert_int_equal(syscollector.processes, DEFAULT_SYSCOLLECTOR_PROCESSES_LIMIT);
    assert_int_equal(syscollector.ports, DEFAULT_SYSCOLLECTOR_PORTS_LIMIT);
    assert_int_equal(syscollector.network_iface, DEFAULT_SYSCOLLECTOR_NETWORK_IFACE_LIMIT);
    assert_int_equal(syscollector.network_protocol, DEFAULT_SYSCOLLECTOR_NETWORK_PROTO_LIMIT);
    assert_int_equal(syscollector.network_address, DEFAULT_SYSCOLLECTOR_NETWORK_ADDR_LIMIT);
    assert_int_equal(syscollector.hardware, DEFAULT_SYSCOLLECTOR_HARDWARE_LIMIT);
    assert_int_equal(syscollector.os_info, DEFAULT_SYSCOLLECTOR_OS_INFO_LIMIT);
    assert_int_equal(syscollector.users, DEFAULT_SYSCOLLECTOR_USERS_LIMIT);
    assert_int_equal(syscollector.groups, DEFAULT_SYSCOLLECTOR_GROUPS_LIMIT);
    assert_int_equal(syscollector.services, DEFAULT_SYSCOLLECTOR_SERVICES_LIMIT);
    assert_int_equal(syscollector.browser_extensions, DEFAULT_SYSCOLLECTOR_BROWSER_EXTENSIONS_LIMIT);
}

static void test_syscollector_limits_init_null(void **state) {
    (void)state;

    /* Should not crash when passed NULL */
    syscollector_limits_init(NULL);
}

/* sca_limits_init tests */

/* Container-scope limit tests (#37532 / #37534 / O10).
 *
 * The container caps used to live in a struct and a namespace of their own and
 * to be ONE allowance shared by every container. Both are now wrong: they are
 * spelled container_<dimension> inside the submodule that owns them, and each
 * applies to one container. */

static void test_syscollector_container_limits_init_success(void **state) {
    (void)state;
    syscollector_limits_t syscollector;

    memset(&syscollector, 0xFF, sizeof(syscollector));

    syscollector_limits_init(&syscollector);

    assert_int_equal(syscollector.container_processes, DEFAULT_SYSCOLLECTOR_CONTAINER_PROCESSES_LIMIT);
    assert_int_equal(syscollector.container_ports, DEFAULT_SYSCOLLECTOR_CONTAINER_PORTS_LIMIT);
    assert_int_equal(syscollector.container_packages, DEFAULT_SYSCOLLECTOR_CONTAINER_PACKAGES_LIMIT);
    assert_int_equal(syscollector.container_users, DEFAULT_SYSCOLLECTOR_CONTAINER_USERS_LIMIT);
    assert_int_equal(syscollector.container_groups, DEFAULT_SYSCOLLECTOR_CONTAINER_GROUPS_LIMIT);
    assert_int_equal(syscollector.container_os_info, DEFAULT_SYSCOLLECTOR_CONTAINER_OS_INFO_LIMIT);
    assert_int_equal(syscollector.container_network_iface, DEFAULT_SYSCOLLECTOR_CONTAINER_NETWORK_IFACE_LIMIT);
    assert_int_equal(syscollector.container_network_protocol, DEFAULT_SYSCOLLECTOR_CONTAINER_NETWORK_PROTO_LIMIT);
    assert_int_equal(syscollector.container_network_address, DEFAULT_SYSCOLLECTOR_CONTAINER_NETWORK_ADDR_LIMIT);
    assert_int_equal(syscollector.container_hardware, DEFAULT_SYSCOLLECTOR_CONTAINER_HARDWARE_LIMIT);
    assert_int_equal(syscollector.container_services, DEFAULT_SYSCOLLECTOR_CONTAINER_SERVICES_LIMIT);
}

/* ELEVEN container dimensions, mirroring the tables the container scanner
 * actually fills -- not the host's thirteen. `hotfixes` has no data source on
 * the platform containers run on, so a cap for it could never do anything, and
 * `browser_extensions` has no container scanner. `services` IS collected: it
 * was omitted on the belief that containers run no init, and a measurement on a
 * real node found it producing 144 rows, the second-largest dimension. */
static void test_syscollector_container_dimensions_mirror_what_is_collected(void **state) {
    (void)state;
    syscollector_limits_t syscollector;

    syscollector_limits_init(&syscollector);

    /* Collected for containers, so capped. */
    assert_int_equal(syscollector.container_services, DEFAULT_SYSCOLLECTOR_CONTAINER_SERVICES_LIMIT);

    /* The container caps default to the same value the host ones do: nothing
     * about running in a container makes a file less worth reporting. */
    assert_int_equal(syscollector.container_packages, syscollector.packages);
    assert_int_equal(syscollector.container_processes, syscollector.processes);
}

/* The FIM container cap lives in the fim namespace, beside the host one, and is
 * PER CONTAINER. There is no registry counterpart: containers are Linux-only
 * here and registry monitoring is Windows-only. */
static void test_fim_container_limit_sits_beside_the_host_one(void **state) {
    (void)state;
    fim_limits_t fim;

    memset(&fim, 0xFF, sizeof(fim));

    fim_limits_init(&fim);

    assert_int_equal(fim.container_file, DEFAULT_FIM_CONTAINER_FILE_LIMIT);
    assert_int_equal(fim.container_file, fim.file);
}

/* A change in a container dimension must be seen as a change. Without this the
 * agent would keep the previous budget after a manager reconfigured only the
 * container caps, because module_limits_changed() gates the re-application. */
static void test_module_limits_changed_detects_container_dimensions(void **state) {
    (void)state;
    module_limits_t a;
    module_limits_t b;

    module_limits_init(&a);
    module_limits_init(&b);

    assert_false(module_limits_changed(&a, &b));

    b.syscollector.container_processes = 500;
    assert_true(module_limits_changed(&a, &b));

    module_limits_init(&b);
    b.syscollector.container_services = 1;
    assert_true(module_limits_changed(&a, &b));

    module_limits_init(&b);
    b.fim.container_file = 7;
    assert_true(module_limits_changed(&a, &b));

    /* And a container dimension must not be confused with the host one of the
     * same name: the two budgets are independent. */
    module_limits_init(&b);
    b.syscollector.processes = 500;
    assert_true(module_limits_changed(&a, &b));
    assert_int_equal(b.syscollector.container_processes,
                     DEFAULT_SYSCOLLECTOR_CONTAINER_PROCESSES_LIMIT);
}

static void test_sca_limits_init_success(void **state) {
    (void)state;
    sca_limits_t sca;

    /* Initialize with garbage to ensure function sets values */
    memset(&sca, 0xFF, sizeof(sca));

    sca_limits_init(&sca);

    assert_int_equal(sca.checks, DEFAULT_SCA_CHECKS_LIMIT);
}

static void test_sca_limits_init_null(void **state) {
    (void)state;

    /* Should not crash when passed NULL */
    sca_limits_init(NULL);
}

/* module_limits_init tests */

static void test_module_limits_init_success(void **state) {
    (void)state;
    module_limits_t limits;

    /* Initialize with garbage to ensure function sets values */
    memset(&limits, 0xFF, sizeof(limits));

    module_limits_init(&limits);

    /* Verify FIM limits */
    assert_int_equal(limits.fim.file, DEFAULT_FIM_FILE_LIMIT);
    assert_int_equal(limits.fim.registry_key, DEFAULT_FIM_REGISTRY_KEY_LIMIT);
    assert_int_equal(limits.fim.registry_value, DEFAULT_FIM_REGISTRY_VALUE_LIMIT);

    /* Verify Syscollector limits */
    assert_int_equal(limits.syscollector.hotfixes, DEFAULT_SYSCOLLECTOR_HOTFIXES_LIMIT);
    assert_int_equal(limits.syscollector.packages, DEFAULT_SYSCOLLECTOR_PACKAGES_LIMIT);
    assert_int_equal(limits.syscollector.processes, DEFAULT_SYSCOLLECTOR_PROCESSES_LIMIT);
    assert_int_equal(limits.syscollector.ports, DEFAULT_SYSCOLLECTOR_PORTS_LIMIT);
    assert_int_equal(limits.syscollector.network_iface, DEFAULT_SYSCOLLECTOR_NETWORK_IFACE_LIMIT);
    assert_int_equal(limits.syscollector.network_protocol, DEFAULT_SYSCOLLECTOR_NETWORK_PROTO_LIMIT);
    assert_int_equal(limits.syscollector.network_address, DEFAULT_SYSCOLLECTOR_NETWORK_ADDR_LIMIT);
    assert_int_equal(limits.syscollector.hardware, DEFAULT_SYSCOLLECTOR_HARDWARE_LIMIT);
    assert_int_equal(limits.syscollector.os_info, DEFAULT_SYSCOLLECTOR_OS_INFO_LIMIT);
    assert_int_equal(limits.syscollector.users, DEFAULT_SYSCOLLECTOR_USERS_LIMIT);
    assert_int_equal(limits.syscollector.groups, DEFAULT_SYSCOLLECTOR_GROUPS_LIMIT);
    assert_int_equal(limits.syscollector.services, DEFAULT_SYSCOLLECTOR_SERVICES_LIMIT);
    assert_int_equal(limits.syscollector.browser_extensions, DEFAULT_SYSCOLLECTOR_BROWSER_EXTENSIONS_LIMIT);

    /* Verify Syscollector container-inventory limits */
    assert_int_equal(limits.syscollector.container_processes, DEFAULT_SYSCOLLECTOR_CONTAINER_PROCESSES_LIMIT);
    assert_int_equal(limits.syscollector.container_ports, DEFAULT_SYSCOLLECTOR_CONTAINER_PORTS_LIMIT);
    assert_int_equal(limits.syscollector.container_packages, DEFAULT_SYSCOLLECTOR_CONTAINER_PACKAGES_LIMIT);
    assert_int_equal(limits.syscollector.container_users, DEFAULT_SYSCOLLECTOR_CONTAINER_USERS_LIMIT);
    assert_int_equal(limits.syscollector.container_groups, DEFAULT_SYSCOLLECTOR_CONTAINER_GROUPS_LIMIT);
    assert_int_equal(limits.syscollector.container_os_info, DEFAULT_SYSCOLLECTOR_CONTAINER_OS_INFO_LIMIT);
    assert_int_equal(limits.syscollector.container_network_iface, DEFAULT_SYSCOLLECTOR_CONTAINER_NETWORK_IFACE_LIMIT);
    assert_int_equal(limits.syscollector.container_network_protocol, DEFAULT_SYSCOLLECTOR_CONTAINER_NETWORK_PROTO_LIMIT);
    assert_int_equal(limits.syscollector.container_network_address, DEFAULT_SYSCOLLECTOR_CONTAINER_NETWORK_ADDR_LIMIT);
    assert_int_equal(limits.syscollector.container_hardware, DEFAULT_SYSCOLLECTOR_CONTAINER_HARDWARE_LIMIT);

    /* Verify SCA limits */
    assert_int_equal(limits.sca.checks, DEFAULT_SCA_CHECKS_LIMIT);

    /* Verify limits_received flag */
    assert_false(limits.limits_received);
}

static void test_module_limits_init_null(void **state) {
    (void)state;

    /* Should not crash when passed NULL */
    module_limits_init(NULL);
}

/* module_limits_reset tests */

static void test_module_limits_reset_success(void **state) {
    (void)state;
    module_limits_t limits;

    /* Set to non-default values */
    limits.fim.file = 999;
    limits.fim.registry_key = 888;
    limits.fim.registry_value = 887;
    limits.syscollector.hotfixes = 777;
    limits.syscollector.packages = 666;
    limits.syscollector.processes = 555;
    limits.syscollector.ports = 444;
    limits.syscollector.network_iface = 333;
    limits.syscollector.network_protocol = 222;
    limits.syscollector.network_address = 111;
    limits.syscollector.hardware = 99;
    limits.syscollector.os_info = 88;
    limits.syscollector.users = 77;
    limits.syscollector.groups = 66;
    limits.syscollector.services = 55;
    limits.syscollector.browser_extensions = 44;
    limits.sca.checks = 33;
    limits.limits_received = true;

    module_limits_reset(&limits);

    /* Verify all values are reset to defaults */
    assert_int_equal(limits.fim.file, DEFAULT_FIM_FILE_LIMIT);
    assert_int_equal(limits.fim.registry_key, DEFAULT_FIM_REGISTRY_KEY_LIMIT);
    assert_int_equal(limits.fim.registry_value, DEFAULT_FIM_REGISTRY_VALUE_LIMIT);
    assert_int_equal(limits.syscollector.hotfixes, DEFAULT_SYSCOLLECTOR_HOTFIXES_LIMIT);
    assert_int_equal(limits.syscollector.packages, DEFAULT_SYSCOLLECTOR_PACKAGES_LIMIT);
    assert_int_equal(limits.syscollector.processes, DEFAULT_SYSCOLLECTOR_PROCESSES_LIMIT);
    assert_int_equal(limits.syscollector.ports, DEFAULT_SYSCOLLECTOR_PORTS_LIMIT);
    assert_int_equal(limits.syscollector.network_iface, DEFAULT_SYSCOLLECTOR_NETWORK_IFACE_LIMIT);
    assert_int_equal(limits.syscollector.network_protocol, DEFAULT_SYSCOLLECTOR_NETWORK_PROTO_LIMIT);
    assert_int_equal(limits.syscollector.network_address, DEFAULT_SYSCOLLECTOR_NETWORK_ADDR_LIMIT);
    assert_int_equal(limits.syscollector.hardware, DEFAULT_SYSCOLLECTOR_HARDWARE_LIMIT);
    assert_int_equal(limits.syscollector.os_info, DEFAULT_SYSCOLLECTOR_OS_INFO_LIMIT);
    assert_int_equal(limits.syscollector.users, DEFAULT_SYSCOLLECTOR_USERS_LIMIT);
    assert_int_equal(limits.syscollector.groups, DEFAULT_SYSCOLLECTOR_GROUPS_LIMIT);
    assert_int_equal(limits.syscollector.services, DEFAULT_SYSCOLLECTOR_SERVICES_LIMIT);
    assert_int_equal(limits.syscollector.browser_extensions, DEFAULT_SYSCOLLECTOR_BROWSER_EXTENSIONS_LIMIT);
    assert_int_equal(limits.sca.checks, DEFAULT_SCA_CHECKS_LIMIT);
    assert_false(limits.limits_received);
}

static void test_module_limits_reset_null(void **state) {
    (void)state;

    /* Should not crash when passed NULL */
    module_limits_reset(NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* fim_limits_init tests */
        cmocka_unit_test(test_fim_limits_init_success),
        cmocka_unit_test(test_fim_limits_init_null),
        /* syscollector_limits_init tests */
        cmocka_unit_test(test_syscollector_limits_init_success),
        cmocka_unit_test(test_syscollector_limits_init_null),
        /* sca_limits_init tests */
        cmocka_unit_test(test_syscollector_container_limits_init_success),
        cmocka_unit_test(test_syscollector_container_dimensions_mirror_what_is_collected),
        cmocka_unit_test(test_fim_container_limit_sits_beside_the_host_one),
        cmocka_unit_test(test_module_limits_changed_detects_container_dimensions),

        cmocka_unit_test(test_sca_limits_init_success),
        cmocka_unit_test(test_sca_limits_init_null),
        /* module_limits_init tests */
        cmocka_unit_test(test_module_limits_init_success),
        cmocka_unit_test(test_module_limits_init_null),
        /* module_limits_reset tests */
        cmocka_unit_test(test_module_limits_reset_success),
        cmocka_unit_test(test_module_limits_reset_null),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
