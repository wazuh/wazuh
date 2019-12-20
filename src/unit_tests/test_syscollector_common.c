/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
#include <stdlib.h>

#include "../wazuh_modules/wmodules.h"

time_t get_sleep_time(int *run);
void update_next_time(int *run);

int __wrap__minfo()
{
    return 0;
}

int __wrap__merror()
{
    return 0;
}

int __wrap__mwarn()
{
    return 0;
}

int __wrap_rbtree_insert(rb_tree * tree, const char * key, void * value)
{
    check_expected_ptr(key);
    check_expected_ptr(value);
    return mock();
}

int __wrap_rbtree_replace(rb_tree * tree, const char * key, void * value)
{
    check_expected_ptr(key);
    check_expected_ptr(value);
    return mock();
}

int __wrap_rbtree_delete(rb_tree * tree, const char * key)
{
    check_expected_ptr(key);
    return 0;
}

void *__wrap_rbtree_get(const rb_tree * tree, const char * key)
{
    check_expected_ptr(key);
    return mock_type(void *);
}

char **__wrap_rbtree_keys(const rb_tree * tree)
{
    return mock_type(char **);
}

char *__wrap_w_get_timestamp()
{
    return strdup("");
}

int __wrap_wm_sendmsg()
{
    return 0;
}

static int init_sys_config(void **state)
{
    wmodule *sys_module = NULL;

    ReadConfig(CWMODULE, "test_syscollector.conf", &sys_module, NULL);

    sys = sys_module->data;
    
    if (!sys->default_interval) sys->default_interval = WM_SYS_DEF_INTERVAL;
    if (!sys->hw_interval) sys->hw_interval = sys->default_interval;
    if (!sys->os_interval) sys->os_interval = sys->default_interval;
    if (!sys->interfaces_interval) sys->interfaces_interval = sys->default_interval;
    if (!sys->programs_interval) sys->programs_interval = sys->default_interval;
    if (!sys->hotfixes_interval) sys->hotfixes_interval = sys->default_interval;
    if (!sys->ports_interval) sys->ports_interval = sys->default_interval;
    if (!sys->processes_interval) sys->processes_interval = sys->default_interval;

    time_t time_start = time(NULL);
    sys->state.hw_next_time = time_start + sys->hw_interval;
    sys->state.os_next_time = time_start + sys->os_interval;
    sys->state.interfaces_next_time = time_start + sys->interfaces_interval;
    sys->state.programs_next_time = time_start + sys->programs_interval;
    sys->state.hotfixes_next_time = time_start + sys->hotfixes_interval;
    sys->state.ports_next_time = time_start + sys->ports_interval;
    sys->state.processes_next_time = time_start + sys->processes_interval;

    *state = sys_module;

    wm_max_eps = 1;

    return 0;
}

static int delete_sys_config(void **state)
{
    wmodule *sys_module = *state;

    wm_module_free(sys_module);

    return 0;
}

void test_scan_rotation(void **state)
{
    (void) state;

    int run = 0;
    time_t sleep = get_sleep_time(&run);

    assert_int_equal(run, 64);

    wm_delay(10 * sleep);
    update_next_time(&run);
    sleep = get_sleep_time(&run);

    assert_int_equal(run, 96);

    wm_delay(100 * sleep);
    update_next_time(&run);
    sleep = get_sleep_time(&run);

    assert_int_equal(run, 68);

    wm_delay(10 * sleep);
    update_next_time(&run);
    sleep = get_sleep_time(&run);

    assert_int_equal(run, 97);

    wm_delay(10 * sleep);
    update_next_time(&run);
    sleep = get_sleep_time(&run);

    assert_int_equal(run, 74);
}

void test_initialize_datastores(void **state)
{
    (void) state;

    sys_initialize_datastores();
}

void test_analyze_hw_added(void **state)
{
    (void) state;

    sys->hw_data = init_hw_data();
    w_mutex_init(&sys->hardware_mutex, NULL);

    hw_entry *hw = init_hw_data();
    hw->board_serial = strdup("1234567890");
    hw->cpu_name = strdup("processor123");
    hw->cpu_cores = 4;
    hw->cpu_MHz = 2.5;
    hw->ram_total = 22222;
    hw->ram_free = 1000;
    hw->ram_usage = 55;

    char *expected = "{\"type\":\"hardware\","
                       "\"data\":{\"type\":\"added\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"board_serial\":\"1234567890\","
                                                 "\"cpu_name\":\"processor123\","
                                                 "\"cpu_cores\":4,"
                                                 "\"cpu_MHz\":2.5,"
                                                 "\"ram_total\":22222,"
                                                 "\"ram_free\":1000,"
                                                 "\"ram_usage\":55}}}";

    char *result = analyze_hw(hw, "");

    assert_string_equal(result, expected);

    assert_non_null(sys->hw_data);
    assert_string_equal(sys->hw_data->board_serial, hw->board_serial);
    assert_string_equal(sys->hw_data->cpu_name, hw->cpu_name);
    assert_int_equal(sys->hw_data->cpu_cores, hw->cpu_cores);
    assert_int_equal(sys->hw_data->cpu_MHz, hw->cpu_MHz);
    assert_int_equal(sys->hw_data->ram_total, hw->ram_total);
    assert_int_equal(sys->hw_data->ram_free, hw->ram_free);
    assert_int_equal(sys->hw_data->ram_usage, hw->ram_usage);

    free(result);
}

void test_analyze_hw_modified(void **state)
{
    (void) state;

    sys->hw_data = init_hw_data();
    w_mutex_init(&sys->hardware_mutex, NULL);

    sys->hw_data->board_serial = strdup("1234567890");
    sys->hw_data->cpu_name = strdup("processor123");
    sys->hw_data->cpu_cores = 4;
    sys->hw_data->cpu_MHz = 2.5;
    sys->hw_data->ram_total = 22222;
    sys->hw_data->ram_free = 1000;
    sys->hw_data->ram_usage = 55;

    hw_entry *hw = init_hw_data();
    hw->board_serial = strdup("1234567890");
    hw->cpu_name = strdup("processor123");
    hw->cpu_cores = 4;
    hw->cpu_MHz = 2.5;
    hw->ram_total = 22222;
    hw->ram_free = 595;
    hw->ram_usage = 80;

    char *expected = "{\"type\":\"hardware\","
                       "\"data\":{\"type\":\"modified\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"board_serial\":\"1234567890\","
                                                 "\"cpu_name\":\"processor123\","
                                                 "\"cpu_cores\":4,"
                                                 "\"cpu_MHz\":2.5,"
                                                 "\"ram_total\":22222,"
                                                 "\"ram_free\":595,"
                                                 "\"ram_usage\":80},"
                                 "\"changed_attributes\":[\"ram_free\",\"ram_usage\"],"
                                 "\"old_attributes\":{\"board_serial\":\"1234567890\","
                                                    "\"cpu_name\":\"processor123\","
                                                    "\"cpu_cores\":4,"
                                                    "\"cpu_MHz\":2.5,"
                                                    "\"ram_total\":22222,"
                                                    "\"ram_free\":1000,"
                                                    "\"ram_usage\":55}}}";

    char *result = analyze_hw(hw, "");

    assert_string_equal(result, expected);

    assert_non_null(sys->hw_data);
    assert_string_equal(sys->hw_data->board_serial, hw->board_serial);
    assert_string_equal(sys->hw_data->cpu_name, hw->cpu_name);
    assert_int_equal(sys->hw_data->cpu_cores, hw->cpu_cores);
    assert_int_equal(sys->hw_data->cpu_MHz, hw->cpu_MHz);
    assert_int_equal(sys->hw_data->ram_total, hw->ram_total);
    assert_int_equal(sys->hw_data->ram_free, hw->ram_free);
    assert_int_equal(sys->hw_data->ram_usage, hw->ram_usage);

    free(result);
}

void test_analyze_hw_not_modified(void **state)
{
    (void) state;

    sys->hw_data = init_hw_data();
    w_mutex_init(&sys->hardware_mutex, NULL);

    sys->hw_data->board_serial = strdup("1234567890");
    sys->hw_data->cpu_name = strdup("processor123");
    sys->hw_data->cpu_cores = 4;
    sys->hw_data->cpu_MHz = 2.5;
    sys->hw_data->ram_total = 22222;
    sys->hw_data->ram_free = 1000;
    sys->hw_data->ram_usage = 55;

    hw_entry *hw = init_hw_data();
    hw->board_serial = strdup("1234567890");
    hw->cpu_name = strdup("processor123");
    hw->cpu_cores = 4;
    hw->cpu_MHz = 2.5;
    hw->ram_total = 22222;
    hw->ram_free = 1000;
    hw->ram_usage = 55;

    char *result = analyze_hw(hw, "");

    assert_null(result);

    assert_non_null(sys->hw_data);
    assert_string_equal(sys->hw_data->board_serial, "1234567890");
    assert_string_equal(sys->hw_data->cpu_name, "processor123");
    assert_int_equal(sys->hw_data->cpu_cores, 4);
    assert_int_equal(sys->hw_data->cpu_MHz, 2.5);
    assert_int_equal(sys->hw_data->ram_total, 22222);
    assert_int_equal(sys->hw_data->ram_free, 1000);
    assert_int_equal(sys->hw_data->ram_usage, 55);
}

void test_analyze_hw_invalid(void **state)
{
    (void) state;

    sys->hw_data = init_hw_data();
    w_mutex_init(&sys->hardware_mutex, NULL);

    sys->hw_data->board_serial = strdup("1234567890");
    sys->hw_data->cpu_name = strdup("processor123");
    sys->hw_data->cpu_cores = 4;
    sys->hw_data->cpu_MHz = 2.5;
    sys->hw_data->ram_total = 22222;
    sys->hw_data->ram_free = 1000;
    sys->hw_data->ram_usage = 55;

    hw_entry *hw = init_hw_data();

    char *result = analyze_hw(hw, "");

    assert_null(result);

    assert_non_null(sys->hw_data);
    assert_string_equal(sys->hw_data->board_serial, "1234567890");
    assert_string_equal(sys->hw_data->cpu_name, "processor123");
    assert_int_equal(sys->hw_data->cpu_cores, 4);
    assert_int_equal(sys->hw_data->cpu_MHz, 2.5);
    assert_int_equal(sys->hw_data->ram_total, 22222);
    assert_int_equal(sys->hw_data->ram_free, 1000);
    assert_int_equal(sys->hw_data->ram_usage, 55);
}

void test_analyze_os_added(void **state)
{
    (void) state;

    sys->os_data = init_os_data();
    w_mutex_init(&sys->os_mutex, NULL);

    os_entry *os = init_os_data();
    os->os_name = strdup("Ubuntu");
    os->os_major = strdup("18");
    os->os_minor = strdup("4");
    os->os_build = strdup("1515");
    os->os_version = strdup("Desktop");
    os->os_codename = strdup("UU");
    os->os_platform = strdup("Linux");
    os->sysname = strdup("UbuntuOS");
    os->hostname = strdup("wazuh");
    os->release = strdup("1.5");
    os->version = strdup("5");
    os->architecture = strdup("x86_64");
    os->os_release = strdup("x23");

    char *expected = "{\"type\":\"OS\","
                       "\"data\":{\"type\":\"added\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"os_name\":\"Ubuntu\","
                                                 "\"os_major\":\"18\","
                                                 "\"os_minor\":\"4\","
                                                 "\"os_build\":\"1515\","
                                                 "\"os_version\":\"Desktop\","
                                                 "\"os_codename\":\"UU\","
                                                 "\"os_platform\":\"Linux\","
                                                 "\"sysname\":\"UbuntuOS\","
                                                 "\"hostname\":\"wazuh\","
                                                 "\"release\":\"1.5\","
                                                 "\"version\":\"5\","
                                                 "\"architecture\":\"x86_64\","
                                                 "\"os_release\":\"x23\"}}}";

    char *result = analyze_os(os, "");

    assert_string_equal(result, expected);

    assert_non_null(sys->os_data);
    assert_string_equal(sys->os_data->os_name, os->os_name);
    assert_string_equal(sys->os_data->os_major, os->os_major);
    assert_string_equal(sys->os_data->os_minor, os->os_minor);
    assert_string_equal(sys->os_data->os_build, os->os_build);
    assert_string_equal(sys->os_data->os_version, os->os_version);
    assert_string_equal(sys->os_data->os_codename, os->os_codename);
    assert_string_equal(sys->os_data->os_platform, os->os_platform);
    assert_string_equal(sys->os_data->sysname, os->sysname);
    assert_string_equal(sys->os_data->hostname, os->hostname);
    assert_string_equal(sys->os_data->release, os->release);
    assert_string_equal(sys->os_data->version, os->version);
    assert_string_equal(sys->os_data->architecture, os->architecture);
    assert_string_equal(sys->os_data->os_release, os->os_release);

    free(result);
}

void test_analyze_os_modified(void **state)
{
    (void) state;

    sys->os_data = init_os_data();
    w_mutex_init(&sys->os_mutex, NULL);

    sys->os_data->os_name = strdup("Ubuntu");
    sys->os_data->os_major = strdup("18");
    sys->os_data->os_minor = strdup("4");
    sys->os_data->os_build = strdup("1515");
    sys->os_data->os_version = strdup("Desktop");
    sys->os_data->os_codename = strdup("UU");
    sys->os_data->os_platform = strdup("Linux");
    sys->os_data->sysname = strdup("UbuntuOS");
    sys->os_data->hostname = strdup("wazuh");
    sys->os_data->release = strdup("1.5");
    sys->os_data->version = strdup("5");
    sys->os_data->architecture = strdup("x86_64");
    sys->os_data->os_release = strdup("x23");

    os_entry *os = init_os_data();
    os->os_name = strdup("Ubuntu");
    os->os_major = strdup("18");
    os->os_minor = strdup("4");
    os->os_build = strdup("1520");
    os->os_version = strdup("Desktop");
    os->os_codename = strdup("UU");
    os->os_platform = strdup("Linux");
    os->sysname = strdup("UbuntuOS");
    os->hostname = strdup("wazuh");
    os->release = strdup("1.6");
    os->version = strdup("5.1");
    os->architecture = strdup("x86_64");
    os->os_release = strdup("x23");

    char *expected = "{\"type\":\"OS\","
                       "\"data\":{\"type\":\"modified\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"os_name\":\"Ubuntu\","
                                                 "\"os_major\":\"18\","
                                                 "\"os_minor\":\"4\","
                                                 "\"os_build\":\"1520\","
                                                 "\"os_version\":\"Desktop\","
                                                 "\"os_codename\":\"UU\","
                                                 "\"os_platform\":\"Linux\","
                                                 "\"sysname\":\"UbuntuOS\","
                                                 "\"hostname\":\"wazuh\","
                                                 "\"release\":\"1.6\","
                                                 "\"version\":\"5.1\","
                                                 "\"architecture\":\"x86_64\","
                                                 "\"os_release\":\"x23\"},"
                                 "\"changed_attributes\":[\"os_build\",\"release\",\"version\"],"
                                 "\"old_attributes\":{\"os_name\":\"Ubuntu\","
                                                     "\"os_major\":\"18\","
                                                     "\"os_minor\":\"4\","
                                                     "\"os_build\":\"1515\","
                                                     "\"os_version\":\"Desktop\","
                                                     "\"os_codename\":\"UU\","
                                                     "\"os_platform\":\"Linux\","
                                                     "\"sysname\":\"UbuntuOS\","
                                                     "\"hostname\":\"wazuh\","
                                                     "\"release\":\"1.5\","
                                                     "\"version\":\"5\","
                                                     "\"architecture\":\"x86_64\","
                                                     "\"os_release\":\"x23\"}}}";

    char *result = analyze_os(os, "");

    assert_string_equal(result, expected);

    assert_non_null(sys->os_data);
    assert_string_equal(sys->os_data->os_name, os->os_name);
    assert_string_equal(sys->os_data->os_major, os->os_major);
    assert_string_equal(sys->os_data->os_minor, os->os_minor);
    assert_string_equal(sys->os_data->os_build, os->os_build);
    assert_string_equal(sys->os_data->os_version, os->os_version);
    assert_string_equal(sys->os_data->os_codename, os->os_codename);
    assert_string_equal(sys->os_data->os_platform, os->os_platform);
    assert_string_equal(sys->os_data->sysname, os->sysname);
    assert_string_equal(sys->os_data->hostname, os->hostname);
    assert_string_equal(sys->os_data->release, os->release);
    assert_string_equal(sys->os_data->version, os->version);
    assert_string_equal(sys->os_data->architecture, os->architecture);
    assert_string_equal(sys->os_data->os_release, os->os_release);

    free(result);
}

void test_analyze_os_not_modified(void **state)
{
    (void) state;

    sys->os_data = init_os_data();
    w_mutex_init(&sys->os_mutex, NULL);

    sys->os_data->os_name = strdup("Ubuntu");
    sys->os_data->os_major = strdup("18");
    sys->os_data->os_minor = strdup("4");
    sys->os_data->os_build = strdup("1515");
    sys->os_data->os_version = strdup("Desktop");
    sys->os_data->os_codename = strdup("UU");
    sys->os_data->os_platform = strdup("Linux");
    sys->os_data->sysname = strdup("UbuntuOS");
    sys->os_data->hostname = strdup("wazuh");
    sys->os_data->release = strdup("1.5");
    sys->os_data->version = strdup("5");
    sys->os_data->architecture = strdup("x86_64");
    sys->os_data->os_release = strdup("x23");

    os_entry *os = init_os_data();
    os->os_name = strdup("Ubuntu");
    os->os_major = strdup("18");
    os->os_minor = strdup("4");
    os->os_build = strdup("1515");
    os->os_version = strdup("Desktop");
    os->os_codename = strdup("UU");
    os->os_platform = strdup("Linux");
    os->sysname = strdup("UbuntuOS");
    os->hostname = strdup("wazuh");
    os->release = strdup("1.5");
    os->version = strdup("5");
    os->architecture = strdup("x86_64");
    os->os_release = strdup("x23");

    char *result = analyze_os(os, "");

    assert_null(result);

    assert_non_null(sys->os_data);
    assert_string_equal(sys->os_data->os_name, "Ubuntu");
    assert_string_equal(sys->os_data->os_major, "18");
    assert_string_equal(sys->os_data->os_minor, "4");
    assert_string_equal(sys->os_data->os_build, "1515");
    assert_string_equal(sys->os_data->os_version, "Desktop");
    assert_string_equal(sys->os_data->os_codename, "UU");
    assert_string_equal(sys->os_data->os_platform, "Linux");
    assert_string_equal(sys->os_data->sysname, "UbuntuOS");
    assert_string_equal(sys->os_data->hostname, "wazuh");
    assert_string_equal(sys->os_data->release, "1.5");
    assert_string_equal(sys->os_data->version, "5");
    assert_string_equal(sys->os_data->architecture, "x86_64");
    assert_string_equal(sys->os_data->os_release, "x23");
}

void test_analyze_os_invalid(void **state)
{
    (void) state;

    sys->os_data = init_os_data();
    w_mutex_init(&sys->os_mutex, NULL);

    sys->os_data->os_name = strdup("Ubuntu");
    sys->os_data->os_major = strdup("18");
    sys->os_data->os_minor = strdup("4");
    sys->os_data->os_build = strdup("1515");
    sys->os_data->os_version = strdup("Desktop");
    sys->os_data->os_codename = strdup("UU");
    sys->os_data->os_platform = strdup("Linux");
    sys->os_data->sysname = strdup("UbuntuOS");
    sys->os_data->hostname = strdup("wazuh");
    sys->os_data->release = strdup("1.5");
    sys->os_data->version = strdup("5");
    sys->os_data->architecture = strdup("x86_64");
    sys->os_data->os_release = strdup("x23");

    os_entry *os= init_os_data();

    char *result = analyze_os(os, "");

    assert_null(result);

    assert_non_null(sys->os_data);
    assert_string_equal(sys->os_data->os_name, "Ubuntu");
    assert_string_equal(sys->os_data->os_major, "18");
    assert_string_equal(sys->os_data->os_minor, "4");
    assert_string_equal(sys->os_data->os_build, "1515");
    assert_string_equal(sys->os_data->os_version, "Desktop");
    assert_string_equal(sys->os_data->os_codename, "UU");
    assert_string_equal(sys->os_data->os_platform, "Linux");
    assert_string_equal(sys->os_data->sysname, "UbuntuOS");
    assert_string_equal(sys->os_data->hostname, "wazuh");
    assert_string_equal(sys->os_data->release, "1.5");
    assert_string_equal(sys->os_data->version, "5");
    assert_string_equal(sys->os_data->architecture, "x86_64");
    assert_string_equal(sys->os_data->os_release, "x23");
}

void test_analyze_interface_added(void **state)
{
    (void) state;

    interface_entry_data *iface = init_interface_data_entry();
    iface->name = strdup("ensp0");
    iface->adapter = strdup("eth");
    iface->type = strdup("2");
    iface->state = strdup("up");
    iface->mac = strdup("fa-48-e4-80");
    iface->mtu = 1500;
    iface->tx_packets = 1000;
    iface->rx_packets = 990;
    iface->tx_bytes = 800;
    iface->rx_bytes = 750;
    iface->tx_errors = 2;
    iface->rx_errors = 5;
    iface->tx_dropped = 23;
    iface->rx_dropped = 12;
    iface->ipv4 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv4->address);
    os_malloc(2 * sizeof(char *), iface->ipv4->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv4->broadcast);
    iface->ipv4->address[0] = strdup("10.0.0.2");
    iface->ipv4->address[1] = NULL;
    iface->ipv4->netmask[0] = strdup("255.0.0.0");
    iface->ipv4->netmask[1] = NULL;
    iface->ipv4->broadcast[0] = strdup("10.255.255.255");
    iface->ipv4->broadcast[1] = NULL;
    iface->ipv4->metric = 500;
    iface->ipv4->gateway = strdup("10.0.0.1");
    iface->ipv4->dhcp = strdup("true");
    iface->ipv6 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv6->address);
    os_malloc(2 * sizeof(char *), iface->ipv6->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv6->broadcast);
    iface->ipv6->address[0] = strdup("f800::1");
    iface->ipv6->address[1] = NULL;
    iface->ipv6->netmask[0] = strdup("ffff::1");
    iface->ipv6->netmask[1] = NULL;
    iface->ipv6->broadcast[0] = strdup("ff20::1");
    iface->ipv6->broadcast[1] = NULL;
    iface->ipv6->metric = 10;
    iface->ipv6->gateway = strdup("ff10::1");
    iface->ipv6->dhcp = strdup("false");

    char *expected = "{\"type\":\"network\","
                       "\"data\":{\"type\":\"added\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"name\":\"ensp0\","
                                                 "\"adapter\":\"eth\","
                                                 "\"type\":\"2\","
                                                 "\"state\":\"up\","
                                                 "\"MAC\":\"fa-48-e4-80\","
                                                 "\"MTU\":1500,"
                                                 "\"tx_packets\":1000,"
                                                 "\"rx_packets\":990,"
                                                 "\"tx_bytes\":800,"
                                                 "\"rx_bytes\":750,"
                                                 "\"tx_errors\":2,"
                                                 "\"rx_errors\":5,"
                                                 "\"tx_dropped\":23,"
                                                 "\"rx_dropped\":12,"
                                                 "\"IPv4\":{\"address\":[\"10.0.0.2\"],"
                                                           "\"netmask\":[\"255.0.0.0\"],"
                                                           "\"broadcast\":[\"10.255.255.255\"],"
                                                           "\"metric\":500,"
                                                           "\"gateway\":\"10.0.0.1\","
                                                           "\"DHCP\":\"true\"},"
                                                 "\"IPv6\":{\"address\":[\"f800::1\"],"
                                                           "\"netmask\":[\"ffff::1\"],"
                                                           "\"broadcast\":[\"ff20::1\"],"
                                                           "\"metric\":10,"
                                                           "\"gateway\":\"ff10::1\","
                                                           "\"DHCP\":\"false\"}}}}";

    expect_string(__wrap_rbtree_get, key, "ensp0");
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap_rbtree_insert, key, "ensp0");
    expect_memory(__wrap_rbtree_insert, value, iface, sizeof(iface));
    will_return(__wrap_rbtree_insert, 1);

    char *result = analyze_interface(iface, "");

    assert_string_equal(result, expected);

    free_interface_data(iface);
    free(result);
}

void test_analyze_interface_added_failure(void **state)
{
    (void) state;

    interface_entry_data *iface = init_interface_data_entry();
    iface->name = strdup("ensp0");
    iface->adapter = strdup("eth");
    iface->type = strdup("2");
    iface->state = strdup("up");
    iface->mac = strdup("fa-48-e4-80");
    iface->mtu = 1500;
    iface->tx_packets = 1000;
    iface->rx_packets = 990;
    iface->tx_bytes = 800;
    iface->rx_bytes = 750;
    iface->tx_errors = 2;
    iface->rx_errors = 5;
    iface->tx_dropped = 23;
    iface->rx_dropped = 12;
    iface->ipv4 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv4->address);
    os_malloc(2 * sizeof(char *), iface->ipv4->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv4->broadcast);
    iface->ipv4->address[0] = strdup("10.0.0.2");
    iface->ipv4->address[1] = NULL;
    iface->ipv4->netmask[0] = strdup("255.0.0.0");
    iface->ipv4->netmask[1] = NULL;
    iface->ipv4->broadcast[0] = strdup("10.255.255.255");
    iface->ipv4->broadcast[1] = NULL;
    iface->ipv4->metric = 500;
    iface->ipv4->gateway = strdup("10.0.0.1");
    iface->ipv4->dhcp = strdup("true");
    iface->ipv6 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv6->address);
    os_malloc(2 * sizeof(char *), iface->ipv6->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv6->broadcast);
    iface->ipv6->address[0] = strdup("f800::1");
    iface->ipv6->address[1] = NULL;
    iface->ipv6->netmask[0] = strdup("ffff::1");
    iface->ipv6->netmask[1] = NULL;
    iface->ipv6->broadcast[0] = strdup("ff20::1");
    iface->ipv6->broadcast[1] = NULL;
    iface->ipv6->metric = 10;
    iface->ipv6->gateway = strdup("ff10::1");
    iface->ipv6->dhcp = strdup("false");

    expect_string(__wrap_rbtree_get, key, "ensp0");
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap_rbtree_insert, key, "ensp0");
    expect_memory(__wrap_rbtree_insert, value, iface, sizeof(iface));
    will_return(__wrap_rbtree_insert, 0);

    char *result = analyze_interface(iface, "");

    assert_null(result);
}

void test_analyze_interface_modified(void **state)
{
    (void) state;

    interface_entry_data *iface_old = init_interface_data_entry();
    iface_old->name = strdup("ensp0");
    iface_old->adapter = strdup("eth");
    iface_old->type = strdup("2");
    iface_old->state = strdup("up");
    iface_old->mac = strdup("fa-48-e4-80");
    iface_old->mtu = 1500;
    iface_old->tx_packets = 1000;
    iface_old->rx_packets = 990;
    iface_old->tx_bytes = 800;
    iface_old->rx_bytes = 750;
    iface_old->tx_errors = 2;
    iface_old->rx_errors = 5;
    iface_old->tx_dropped = 23;
    iface_old->rx_dropped = 12;
    iface_old->ipv4 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface_old->ipv4->address);
    os_malloc(2 * sizeof(char *), iface_old->ipv4->netmask);
    os_malloc(2 * sizeof(char *), iface_old->ipv4->broadcast);
    iface_old->ipv4->address[0] = strdup("10.0.0.2");
    iface_old->ipv4->address[1] = NULL;
    iface_old->ipv4->netmask[0] = strdup("255.0.0.0");
    iface_old->ipv4->netmask[1] = NULL;
    iface_old->ipv4->broadcast[0] = strdup("10.255.255.255");
    iface_old->ipv4->broadcast[1] = NULL;
    iface_old->ipv4->metric = 500;
    iface_old->ipv4->gateway = strdup("10.0.0.1");
    iface_old->ipv4->dhcp = strdup("true");
    iface_old->ipv6 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface_old->ipv6->address);
    os_malloc(2 * sizeof(char *), iface_old->ipv6->netmask);
    os_malloc(2 * sizeof(char *), iface_old->ipv6->broadcast);
    iface_old->ipv6->address[0] = strdup("f800::1");
    iface_old->ipv6->address[1] = NULL;
    iface_old->ipv6->netmask[0] = strdup("ffff::1");
    iface_old->ipv6->netmask[1] = NULL;
    iface_old->ipv6->broadcast[0] = strdup("ff20::1");
    iface_old->ipv6->broadcast[1] = NULL;
    iface_old->ipv6->metric = 10;
    iface_old->ipv6->gateway = strdup("ff10::1");
    iface_old->ipv6->dhcp = strdup("false");

    interface_entry_data *iface = init_interface_data_entry();
    iface->name = strdup("ensp0");
    iface->adapter = strdup("eth");
    iface->type = strdup("2");
    iface->state = strdup("down");
    iface->mac = strdup("fa-48-e4-80");
    iface->mtu = 1600;
    iface->tx_packets = 1200;
    iface->rx_packets = 1100;
    iface->tx_bytes = 2100;
    iface->rx_bytes = 1750;
    iface->tx_errors = 45;
    iface->rx_errors = 18;
    iface->tx_dropped = 23;
    iface->rx_dropped = 12;
    iface->ipv4 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv4->address);
    os_malloc(2 * sizeof(char *), iface->ipv4->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv4->broadcast);
    iface->ipv4->address[0] = strdup("10.0.0.3");
    iface->ipv4->address[1] = NULL;
    iface->ipv4->netmask[0] = strdup("255.0.0.0");
    iface->ipv4->netmask[1] = NULL;
    iface->ipv4->broadcast[0] = strdup("10.255.255.255");
    iface->ipv4->broadcast[1] = NULL;
    iface->ipv4->metric = 500;
    iface->ipv4->gateway = strdup("10.0.0.1");
    iface->ipv4->dhcp = strdup("false");
    iface->ipv6 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv6->address);
    os_malloc(2 * sizeof(char *), iface->ipv6->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv6->broadcast);
    iface->ipv6->address[0] = strdup("f800::1");
    iface->ipv6->address[1] = NULL;
    iface->ipv6->netmask[0] = strdup("ffff::1");
    iface->ipv6->netmask[1] = NULL;
    iface->ipv6->broadcast[0] = strdup("ff20::2");
    iface->ipv6->broadcast[1] = NULL;
    iface->ipv6->metric = 15;
    iface->ipv6->gateway = strdup("ff10::1");
    iface->ipv6->dhcp = strdup("false");

    char *expected = "{\"type\":\"network\","
                       "\"data\":{\"type\":\"modified\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"name\":\"ensp0\","
                                                 "\"adapter\":\"eth\","
                                                 "\"type\":\"2\","
                                                 "\"state\":\"down\","
                                                 "\"MAC\":\"fa-48-e4-80\","
                                                 "\"MTU\":1600,"
                                                 "\"tx_packets\":1200,"
                                                 "\"rx_packets\":1100,"
                                                 "\"tx_bytes\":2100,"
                                                 "\"rx_bytes\":1750,"
                                                 "\"tx_errors\":45,"
                                                 "\"rx_errors\":18,"
                                                 "\"tx_dropped\":23,"
                                                 "\"rx_dropped\":12,"
                                                 "\"IPv4\":{\"address\":[\"10.0.0.3\"],"
                                                           "\"netmask\":[\"255.0.0.0\"],"
                                                           "\"broadcast\":[\"10.255.255.255\"],"
                                                           "\"metric\":500,"
                                                           "\"gateway\":\"10.0.0.1\","
                                                           "\"DHCP\":\"false\"},"
                                                 "\"IPv6\":{\"address\":[\"f800::1\"],"
                                                           "\"netmask\":[\"ffff::1\"],"
                                                           "\"broadcast\":[\"ff20::2\"],"
                                                           "\"metric\":15,"
                                                           "\"gateway\":\"ff10::1\","
                                                           "\"DHCP\":\"false\"}},"
                                 "\"changed_attributes\":[\"state\",\"ipv4_address\",\"ipv4_dhcp\",\"ipv6_broadcast\",\"ipv6_metric\",\"mtu\","
                                                         "\"tx_packets\",\"rx_packets\",\"tx_bytes\",\"rx_bytes\",\"tx_errors\",\"rx_errors\"],"
                                 "\"old_attributes\":{\"name\":\"ensp0\","
                                                     "\"adapter\":\"eth\","
                                                     "\"type\":\"2\","
                                                     "\"state\":\"up\","
                                                     "\"MAC\":\"fa-48-e4-80\","
                                                     "\"MTU\":1500,"
                                                     "\"tx_packets\":1000,"
                                                     "\"rx_packets\":990,"
                                                     "\"tx_bytes\":800,"
                                                     "\"rx_bytes\":750,"
                                                     "\"tx_errors\":2,"
                                                     "\"rx_errors\":5,"
                                                     "\"tx_dropped\":23,"
                                                     "\"rx_dropped\":12,"
                                                     "\"IPv4\":{\"address\":[\"10.0.0.2\"],"
                                                               "\"netmask\":[\"255.0.0.0\"],"
                                                               "\"broadcast\":[\"10.255.255.255\"],"
                                                               "\"metric\":500,"
                                                               "\"gateway\":\"10.0.0.1\","
                                                               "\"DHCP\":\"true\"},"
                                                     "\"IPv6\":{\"address\":[\"f800::1\"],"
                                                                "\"netmask\":[\"ffff::1\"],"
                                                               "\"broadcast\":[\"ff20::1\"],"
                                                               "\"metric\":10,"
                                                               "\"gateway\":\"ff10::1\","
                                                               "\"DHCP\":\"false\"}}}}";

    expect_string(__wrap_rbtree_get, key, "ensp0");
    will_return(__wrap_rbtree_get, iface_old);

    expect_string(__wrap_rbtree_replace, key, "ensp0");
    expect_memory(__wrap_rbtree_replace, value, iface, sizeof(iface));
    will_return(__wrap_rbtree_replace, 1);

    char *result = analyze_interface(iface, "");

    assert_string_equal(result, expected);

    free_interface_data(iface_old);
    free_interface_data(iface);
    free(result);
}

void test_analyze_interface_modified_failure(void **state)
{
    (void) state;

    interface_entry_data *iface_old = init_interface_data_entry();
    iface_old->name = strdup("ensp0");
    iface_old->adapter = strdup("eth");
    iface_old->type = strdup("2");
    iface_old->state = strdup("up");
    iface_old->mac = strdup("fa-48-e4-80");
    iface_old->mtu = 1500;
    iface_old->tx_packets = 1000;
    iface_old->rx_packets = 990;
    iface_old->tx_bytes = 800;
    iface_old->rx_bytes = 750;
    iface_old->tx_errors = 2;
    iface_old->rx_errors = 5;
    iface_old->tx_dropped = 23;
    iface_old->rx_dropped = 12;
    iface_old->ipv4 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface_old->ipv4->address);
    os_malloc(2 * sizeof(char *), iface_old->ipv4->netmask);
    os_malloc(2 * sizeof(char *), iface_old->ipv4->broadcast);
    iface_old->ipv4->address[0] = strdup("10.0.0.2");
    iface_old->ipv4->address[1] = NULL;
    iface_old->ipv4->netmask[0] = strdup("255.0.0.0");
    iface_old->ipv4->netmask[1] = NULL;
    iface_old->ipv4->broadcast[0] = strdup("10.255.255.255");
    iface_old->ipv4->broadcast[1] = NULL;
    iface_old->ipv4->metric = 500;
    iface_old->ipv4->gateway = strdup("10.0.0.1");
    iface_old->ipv4->dhcp = strdup("true");
    iface_old->ipv6 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface_old->ipv6->address);
    os_malloc(2 * sizeof(char *), iface_old->ipv6->netmask);
    os_malloc(2 * sizeof(char *), iface_old->ipv6->broadcast);
    iface_old->ipv6->address[0] = strdup("f800::1");
    iface_old->ipv6->address[1] = NULL;
    iface_old->ipv6->netmask[0] = strdup("ffff::1");
    iface_old->ipv6->netmask[1] = NULL;
    iface_old->ipv6->broadcast[0] = strdup("ff20::1");
    iface_old->ipv6->broadcast[1] = NULL;
    iface_old->ipv6->metric = 10;
    iface_old->ipv6->gateway = strdup("ff10::1");
    iface_old->ipv6->dhcp = strdup("false");

    interface_entry_data *iface = init_interface_data_entry();
    iface->name = strdup("ensp0");
    iface->adapter = strdup("eth");
    iface->type = strdup("2");
    iface->state = strdup("down");
    iface->mac = strdup("fa-48-e4-80");
    iface->mtu = 1600;
    iface->tx_packets = 1200;
    iface->rx_packets = 1100;
    iface->tx_bytes = 2100;
    iface->rx_bytes = 1750;
    iface->tx_errors = 45;
    iface->rx_errors = 18;
    iface->tx_dropped = 23;
    iface->rx_dropped = 12;
    iface->ipv4 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv4->address);
    os_malloc(2 * sizeof(char *), iface->ipv4->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv4->broadcast);
    iface->ipv4->address[0] = strdup("10.0.0.3");
    iface->ipv4->address[1] = NULL;
    iface->ipv4->netmask[0] = strdup("255.0.0.0");
    iface->ipv4->netmask[1] = NULL;
    iface->ipv4->broadcast[0] = strdup("10.255.255.255");
    iface->ipv4->broadcast[1] = NULL;
    iface->ipv4->metric = 500;
    iface->ipv4->gateway = strdup("10.0.0.1");
    iface->ipv4->dhcp = strdup("false");
    iface->ipv6 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv6->address);
    os_malloc(2 * sizeof(char *), iface->ipv6->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv6->broadcast);
    iface->ipv6->address[0] = strdup("f800::1");
    iface->ipv6->address[1] = NULL;
    iface->ipv6->netmask[0] = strdup("ffff::1");
    iface->ipv6->netmask[1] = NULL;
    iface->ipv6->broadcast[0] = strdup("ff20::2");
    iface->ipv6->broadcast[1] = NULL;
    iface->ipv6->metric = 15;
    iface->ipv6->gateway = strdup("ff10::1");
    iface->ipv6->dhcp = strdup("false");

    expect_string(__wrap_rbtree_get, key, "ensp0");
    will_return(__wrap_rbtree_get, iface_old);

    expect_string(__wrap_rbtree_replace, key, "ensp0");
    expect_memory(__wrap_rbtree_replace, value, iface, sizeof(iface));
    will_return(__wrap_rbtree_replace, 0);

    char *result = analyze_interface(iface, "");

    assert_null(result);

    free_interface_data(iface_old);
}

void test_analyze_interface_not_modified(void **state)
{
    (void) state;

    interface_entry_data *iface_old = init_interface_data_entry();
    iface_old->name = strdup("ensp0");
    iface_old->adapter = strdup("eth");
    iface_old->type = strdup("2");
    iface_old->state = strdup("up");
    iface_old->mac = strdup("fa-48-e4-80");
    iface_old->mtu = 1500;
    iface_old->tx_packets = 1000;
    iface_old->rx_packets = 990;
    iface_old->tx_bytes = 800;
    iface_old->rx_bytes = 750;
    iface_old->tx_errors = 2;
    iface_old->rx_errors = 5;
    iface_old->tx_dropped = 23;
    iface_old->rx_dropped = 12;
    iface_old->ipv4 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface_old->ipv4->address);
    os_malloc(2 * sizeof(char *), iface_old->ipv4->netmask);
    os_malloc(2 * sizeof(char *), iface_old->ipv4->broadcast);
    iface_old->ipv4->address[0] = strdup("10.0.0.2");
    iface_old->ipv4->address[1] = NULL;
    iface_old->ipv4->netmask[0] = strdup("255.0.0.0");
    iface_old->ipv4->netmask[1] = NULL;
    iface_old->ipv4->broadcast[0] = strdup("10.255.255.255");
    iface_old->ipv4->broadcast[1] = NULL;
    iface_old->ipv4->metric = 500;
    iface_old->ipv4->gateway = strdup("10.0.0.1");
    iface_old->ipv4->dhcp = strdup("true");
    iface_old->ipv6 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface_old->ipv6->address);
    os_malloc(2 * sizeof(char *), iface_old->ipv6->netmask);
    os_malloc(2 * sizeof(char *), iface_old->ipv6->broadcast);
    iface_old->ipv6->address[0] = strdup("f800::1");
    iface_old->ipv6->address[1] = NULL;
    iface_old->ipv6->netmask[0] = strdup("ffff::1");
    iface_old->ipv6->netmask[1] = NULL;
    iface_old->ipv6->broadcast[0] = strdup("ff20::1");
    iface_old->ipv6->broadcast[1] = NULL;
    iface_old->ipv6->metric = 10;
    iface_old->ipv6->gateway = strdup("ff10::1");
    iface_old->ipv6->dhcp = strdup("false");

    expect_string(__wrap_rbtree_get, key, "ensp0");
    will_return(__wrap_rbtree_get, iface_old);

    char *result = analyze_interface(iface_old, "");

    assert_null(result);
}

void test_analyze_interface_invalid(void **state)
{
    (void) state;

    interface_entry_data *iface = init_interface_data_entry();

    char *result = analyze_interface(iface, "");

    assert_null(result);
}

void test_check_disabled_interfaces_deleted(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("ensp0", keys);

    interface_entry_data *iface = init_interface_data_entry();
    iface->name = strdup("ensp0");
    iface->adapter = strdup("eth");
    iface->type = strdup("2");
    iface->state = strdup("down");
    iface->mac = strdup("fa-48-e4-80");
    iface->mtu = 1600;
    iface->tx_packets = 1200;
    iface->rx_packets = 1100;
    iface->tx_bytes = 2100;
    iface->rx_bytes = 1750;
    iface->tx_errors = 45;
    iface->rx_errors = 18;
    iface->tx_dropped = 23;
    iface->rx_dropped = 12;
    iface->ipv4 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv4->address);
    os_malloc(2 * sizeof(char *), iface->ipv4->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv4->broadcast);
    iface->ipv4->address[0] = strdup("10.0.0.3");
    iface->ipv4->address[1] = NULL;
    iface->ipv4->netmask[0] = strdup("255.0.0.0");
    iface->ipv4->netmask[1] = NULL;
    iface->ipv4->broadcast[0] = strdup("10.255.255.255");
    iface->ipv4->broadcast[1] = NULL;
    iface->ipv4->metric = 500;
    iface->ipv4->gateway = strdup("10.0.0.1");
    iface->ipv4->dhcp = strdup("false");
    iface->ipv6 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv6->address);
    os_malloc(2 * sizeof(char *), iface->ipv6->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv6->broadcast);
    iface->ipv6->address[0] = strdup("f800::1");
    iface->ipv6->address[1] = NULL;
    iface->ipv6->netmask[0] = strdup("ffff::1");
    iface->ipv6->netmask[1] = NULL;
    iface->ipv6->broadcast[0] = strdup("ff20::2");
    iface->ipv6->broadcast[1] = NULL;
    iface->ipv6->metric = 15;
    iface->ipv6->gateway = strdup("ff10::1");
    iface->ipv6->dhcp = strdup("false");
    iface->enabled = 0;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "ensp0");
    will_return(__wrap_rbtree_get, iface);

    expect_string(__wrap_rbtree_get, key, "ensp0");
    will_return(__wrap_rbtree_get, iface);

    expect_string(__wrap_rbtree_delete, key, "ensp0");

    check_disabled_interfaces();

    free_interface_data(iface);
}

void test_check_disabled_interfaces_not_deleted(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("ensp0", keys);

    interface_entry_data *iface = init_interface_data_entry();
    iface->name = strdup("ensp0");
    iface->adapter = strdup("eth");
    iface->type = strdup("2");
    iface->state = strdup("down");
    iface->mac = strdup("fa-48-e4-80");
    iface->mtu = 1600;
    iface->tx_packets = 1200;
    iface->rx_packets = 1100;
    iface->tx_bytes = 2100;
    iface->rx_bytes = 1750;
    iface->tx_errors = 45;
    iface->rx_errors = 18;
    iface->tx_dropped = 23;
    iface->rx_dropped = 12;
    iface->ipv4 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv4->address);
    os_malloc(2 * sizeof(char *), iface->ipv4->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv4->broadcast);
    iface->ipv4->address[0] = strdup("10.0.0.3");
    iface->ipv4->address[1] = NULL;
    iface->ipv4->netmask[0] = strdup("255.0.0.0");
    iface->ipv4->netmask[1] = NULL;
    iface->ipv4->broadcast[0] = strdup("10.255.255.255");
    iface->ipv4->broadcast[1] = NULL;
    iface->ipv4->metric = 500;
    iface->ipv4->gateway = strdup("10.0.0.1");
    iface->ipv4->dhcp = strdup("false");
    iface->ipv6 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv6->address);
    os_malloc(2 * sizeof(char *), iface->ipv6->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv6->broadcast);
    iface->ipv6->address[0] = strdup("f800::1");
    iface->ipv6->address[1] = NULL;
    iface->ipv6->netmask[0] = strdup("ffff::1");
    iface->ipv6->netmask[1] = NULL;
    iface->ipv6->broadcast[0] = strdup("ff20::2");
    iface->ipv6->broadcast[1] = NULL;
    iface->ipv6->metric = 15;
    iface->ipv6->gateway = strdup("ff10::1");
    iface->ipv6->dhcp = strdup("false");
    iface->enabled = 1;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "ensp0");
    will_return(__wrap_rbtree_get, iface);

    check_disabled_interfaces();

    assert_int_equal(iface->enabled, 0);

    free_interface_data(iface);
}

void test_check_disabled_interfaces_no_data(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("ensp0", keys);

    interface_entry_data *iface = NULL;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "ensp0");
    will_return(__wrap_rbtree_get, iface);

    check_disabled_interfaces();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_scan_rotation, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_initialize_datastores, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_hw_added, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_hw_modified, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_hw_not_modified, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_hw_invalid, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_os_added, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_os_modified, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_os_not_modified, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_os_invalid, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_interface_added, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_interface_added_failure, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_interface_modified, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_interface_modified_failure, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_interface_not_modified, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_interface_invalid, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_disabled_interfaces_deleted, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_disabled_interfaces_not_deleted, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_disabled_interfaces_no_data, init_sys_config, delete_sys_config)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}