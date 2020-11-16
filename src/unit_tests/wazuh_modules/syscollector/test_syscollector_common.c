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
    return mock();
}

static int init_sys_config(void **state)
{
    wmodule *sys_module = NULL;

    ReadConfig(CWMODULE, "test_syscollector.conf", &sys_module, NULL);

    sys = sys_module->data;

    *state = sys_module;

    return 0;
}

static int init_sys_scan_config(void **state)
{
    init_sys_config(state);

    if (!sys->default_interval) {
        sys->default_interval = WM_SYS_DEF_INTERVAL;
    }

    if (!sys->hw_interval) {
        sys->hw_interval = sys->default_interval;
    }

    if (!sys->os_interval) {
        sys->os_interval = sys->default_interval;
    }

    if (!sys->interfaces_interval) {
        sys->interfaces_interval = sys->default_interval;
    }

    if (!sys->programs_interval) {
        sys->programs_interval = sys->default_interval;
    }

    if (!sys->hotfixes_interval) {
        sys->hotfixes_interval = sys->default_interval;
    }

    if (!sys->ports_interval) {
        sys->ports_interval = sys->default_interval;
    }

    if (!sys->processes_interval) {
        sys->processes_interval = sys->default_interval;
    }

    time_t time_start = time(NULL);
    sys->state.hw_next_time = time_start + sys->hw_interval;
    sys->state.os_next_time = time_start + sys->os_interval;
    sys->state.interfaces_next_time = time_start + sys->interfaces_interval;
    sys->state.programs_next_time = time_start + sys->programs_interval;
    sys->state.hotfixes_next_time = time_start + sys->hotfixes_interval;
    sys->state.ports_next_time = time_start + sys->ports_interval;
    sys->state.processes_next_time = time_start + sys->processes_interval;

    return 0;
}

static int init_sys_deleted_config(void **state)
{
    init_sys_config(state);

    wm_max_eps = 1;

    return 0;
}

static int delete_sys_config(void **state)
{
    wmodule *sys_module = *state;

    wm_module_free(sys_module);

    return 0;
}

hw_entry * get_hw_entry(char * board_serial, char * cpu_name, int cpu_cores, double cpu_MHz, long ram_total, long ram_free, int ram_usage)
{
    hw_entry *hw = init_hw_data();
    hw->board_serial = strdup(board_serial);
    hw->cpu_name = strdup(cpu_name);
    hw->cpu_cores = cpu_cores;
    hw->cpu_MHz = cpu_MHz;
    hw->ram_total = ram_total;
    hw->ram_free = ram_free;
    hw->ram_usage = ram_usage;

    return hw;
}

os_entry * get_os_entry(char * os_name, char * os_major, char * os_minor, char * os_build, char * os_version, char * os_codename, char * os_platform, char * sysname, char * hostname, char * release, char * version, char * architecture, char * os_release)
{
    os_entry *os = init_os_data();
    os->os_name = strdup(os_name);
    os->os_major = strdup(os_major);
    os->os_minor = strdup(os_minor);
    os->os_build = strdup(os_build);
    os->os_version = strdup(os_version);
    os->os_codename = strdup(os_codename);
    os->os_platform = strdup(os_platform);
    os->sysname = strdup(sysname);
    os->hostname = strdup(hostname);
    os->release = strdup(release);
    os->version = strdup(version);
    os->architecture = strdup(architecture);
    os->os_release = strdup(os_release);

    return os;
}

interface_entry_data * get_interface_entry(char * name, char * adapter, char * type, char * state, char * mac, int mtu, int tx_packets, int rx_packets, int tx_bytes, int rx_bytes, int tx_errors, int rx_errors, int tx_dropped, int rx_dropped, char * ipv4_address, char * ipv4_netmask, char * ipv4_broadcast, int ipv4_metric, char * ipv4_gateway, char * ipv4_dhcp, char * ipv6_address, char * ipv6_netmask, char * ipv6_broadcast, int ipv6_metric, char * ipv6_gateway, char * ipv6_dhcp)
{
    interface_entry_data *iface = init_interface_data_entry();
    iface->name = strdup(name);
    iface->adapter = strdup(adapter);
    iface->type = strdup(type);
    iface->state = strdup(state);
    iface->mac = strdup(mac);
    iface->mtu = mtu;
    iface->tx_packets = tx_packets;
    iface->rx_packets = rx_packets;
    iface->tx_bytes = tx_bytes;
    iface->rx_bytes = rx_bytes;
    iface->tx_errors = tx_errors;
    iface->rx_errors = rx_errors;
    iface->tx_dropped = tx_dropped;
    iface->rx_dropped = rx_dropped;
    iface->ipv4 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv4->address);
    os_malloc(2 * sizeof(char *), iface->ipv4->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv4->broadcast);
    iface->ipv4->address[0] = strdup(ipv4_address);
    iface->ipv4->address[1] = NULL;
    iface->ipv4->netmask[0] = strdup(ipv4_netmask);
    iface->ipv4->netmask[1] = NULL;
    iface->ipv4->broadcast[0] = strdup(ipv4_broadcast);
    iface->ipv4->broadcast[1] = NULL;
    iface->ipv4->metric = ipv4_metric;
    iface->ipv4->gateway = strdup(ipv4_gateway);
    iface->ipv4->dhcp = strdup(ipv4_dhcp);
    iface->ipv6 = init_net_addr();
    os_malloc(2 * sizeof(char *), iface->ipv6->address);
    os_malloc(2 * sizeof(char *), iface->ipv6->netmask);
    os_malloc(2 * sizeof(char *), iface->ipv6->broadcast);
    iface->ipv6->address[0] = strdup(ipv6_address);
    iface->ipv6->address[1] = NULL;
    iface->ipv6->netmask[0] = strdup(ipv6_netmask);
    iface->ipv6->netmask[1] = NULL;
    iface->ipv6->broadcast[0] = strdup(ipv6_broadcast);
    iface->ipv6->broadcast[1] = NULL;
    iface->ipv6->metric = ipv6_metric;
    iface->ipv6->gateway = strdup(ipv6_gateway);
    iface->ipv6->dhcp = strdup(ipv6_dhcp);

    return iface;
}

program_entry_data * get_program_entry(char * format, char * name, char * priority, char * group, long size, char * vendor, char * install_time, char * version, char * architecture, char * multi_arch , char * source, char * description, char * location)
{
    program_entry_data *pkg = init_program_data_entry();
    pkg->format = strdup(format);
    pkg->name = strdup(name);
    pkg->priority = strdup(priority);
    pkg->group = strdup(group);
    pkg->size = size;
    pkg->vendor = strdup(vendor);
    pkg->install_time = strdup(install_time);
    pkg->version = strdup(version);
    pkg->architecture = strdup(architecture);
    pkg->multi_arch = strdup(multi_arch);
    pkg->source = strdup(source);
    pkg->description = strdup(description);
    pkg->location = strdup(location);

    return pkg;
}

hotfix_entry_data * get_hotfix_entry(char * hotfix)
{
    hotfix_entry_data *hfix = init_hotfix_data_entry();
    hfix->hotfix = strdup(hotfix);

    return hfix;
}

port_entry_data * get_port_entry(char * protocol, char * local_ip, int local_port, char * remote_ip, int remote_port, int tx_queue, int rx_queue, int inode, char * state, int pid, char * process)
{
    port_entry_data *port = init_port_data_entry();
    port->protocol = strdup(protocol);
    port->local_ip = strdup(local_ip);
    port->local_port = local_port;
    port->remote_ip = strdup(remote_ip);
    port->remote_port = remote_port;
    port->tx_queue = tx_queue;
    port->rx_queue = rx_queue;
    port->inode = inode;
    port->state = strdup(state);
    port->pid = pid;
    port->process = strdup(process);

    return port;
}

process_entry_data * get_process_entry(int pid, int ppid, char * name, char * cmd, char * argvs, char * state, char * euser, char * ruser, char * suser, char * egroup, char * rgroup, char * sgroup, char * fgroup, int priority, int nice, long size, long vm_size, long resident, long share, long long start_time, long long utime, long long stime, int pgrp, int session, int nlwp, int tgid, int tty, int processor)
{
    process_entry_data *proc = init_process_data_entry();
    proc->pid = pid;
    proc->ppid = ppid;
    proc->name = strdup(name);
    proc->cmd = strdup(cmd);
    os_malloc(2 * sizeof(char *), proc->argvs);
    proc->argvs[0] = strdup(argvs);
    proc->argvs[1] = NULL;
    proc->state = strdup(state);
    proc->euser = strdup(euser);
    proc->ruser = strdup(ruser);
    proc->suser = strdup(suser);
    proc->egroup = strdup(egroup);
    proc->rgroup = strdup(rgroup);
    proc->sgroup = strdup(sgroup);
    proc->fgroup = strdup(fgroup);
    proc->priority = priority;
    proc->nice = nice;
    proc->size = size;
    proc->vm_size = vm_size;
    proc->resident = resident;
    proc->share = share;
    proc->start_time = start_time;
    proc->utime = utime;
    proc->stime = stime;
    proc->pgrp = pgrp;
    proc->session = session;
    proc->nlwp = nlwp;
    proc->tgid = tgid;
    proc->tty = tty;
    proc->processor = processor;

    return proc;
}

void test_scan_rotation(void **state)
{
    (void) state;

    int run = 0;
    time_t sleep = get_sleep_time(&run);

    assert_int_equal(run, 64);

    w_time_delay(10 * sleep);
    update_next_time(&run);
    sleep = get_sleep_time(&run);

    assert_int_equal(run, 96);

    w_time_delay(100 * sleep);
    update_next_time(&run);
    sleep = get_sleep_time(&run);

    assert_int_equal(run, 68);

    w_time_delay(10 * sleep);
    update_next_time(&run);
    sleep = get_sleep_time(&run);

    assert_int_equal(run, 97);

    w_time_delay(10 * sleep);
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

    hw_entry *hw = get_hw_entry("1234567890", "processor123", 4, 2.5, 22222, 1000, 55);

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

    sys->hw_data = get_hw_entry("1234567890", "processor123", 4, 2.5, 22222, 1000, 55);

    hw_entry *hw = get_hw_entry("1234567890", "processor123", 4, 2.5, 22222, 595, 80);

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

    sys->hw_data = get_hw_entry("1234567890", "processor123", 4, 2.5, 22222, 1000, 55);

    hw_entry *hw = get_hw_entry("1234567890", "processor123", 4, 2.5, 22222, 1000, 55);

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

    sys->hw_data = get_hw_entry("1234567890", "processor123", 4, 2.5, 22222, 1000, 55);

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

    os_entry *os = get_os_entry("Ubuntu", "18", "4", "1515", "Desktop", "UU", "Linux", "UbuntuOS", "wazuh", "1.5", "5", "x86_64", "x23");

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

    sys->os_data = get_os_entry("Ubuntu", "18", "4", "1515", "Desktop", "UU", "Linux", "UbuntuOS", "wazuh", "1.5", "5", "x86_64", "x23");

    os_entry *os = get_os_entry("Ubuntu", "18", "4", "1520", "Desktop", "UU", "Linux", "UbuntuOS", "wazuh", "1.6", "5.1", "x86_64", "x23");

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

    sys->os_data = get_os_entry("Ubuntu", "18", "4", "1515", "Desktop", "UU", "Linux", "UbuntuOS", "wazuh", "1.5", "5", "x86_64", "x23");

    os_entry *os = get_os_entry("Ubuntu", "18", "4", "1515", "Desktop", "UU", "Linux", "UbuntuOS", "wazuh", "1.5", "5", "x86_64", "x23");

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

    sys->os_data = get_os_entry("Ubuntu", "18", "4", "1515", "Desktop", "UU", "Linux", "UbuntuOS", "wazuh", "1.5", "5", "x86_64", "x23");

    os_entry *os = init_os_data();

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

    interface_entry_data *iface = get_interface_entry("ensp0", "eth", "2", "up", "fa-48-e4-80", 1500, 1000, 990, 800, 750, 2, 5, 23, 12, "10.0.0.2", "255.0.0.0", "10.255.255.255", 500, "10.0.0.1", "true", "f800::1", "ffff::1", "ff20::1", 10, "ff10::1", "false");

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

    interface_entry_data *iface = get_interface_entry("ensp0", "eth", "2", "up", "fa-48-e4-80", 1500, 1000, 990, 800, 750, 2, 5, 23, 12, "10.0.0.2", "255.0.0.0", "10.255.255.255", 500, "10.0.0.1", "true", "f800::1", "ffff::1", "ff20::1", 10, "ff10::1", "false");

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

    interface_entry_data *iface_old = get_interface_entry("ensp0", "eth", "2", "up", "fa-48-e4-80", 1500, 1000, 990, 800, 750, 2, 5, 23, 12, "10.0.0.2", "255.0.0.0", "10.255.255.255", 500, "10.0.0.1", "true", "f800::1", "ffff::1", "ff20::1", 10, "ff10::1", "false");

    interface_entry_data *iface = get_interface_entry("ensp0", "eth", "2", "down", "fa-48-e4-80", 1600, 1200, 1100, 2100, 1750, 45, 18, 23, 12, "10.0.0.3", "255.0.0.0", "10.255.255.255", 500, "10.0.0.1", "false", "f800::1", "ffff::1", "ff20::2", 15, "ff10::1", "false");

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

    interface_entry_data *iface_old = get_interface_entry("ensp0", "eth", "2", "up", "fa-48-e4-80", 1500, 1000, 990, 800, 750, 2, 5, 23, 12, "10.0.0.2", "255.0.0.0", "10.255.255.255", 500, "10.0.0.1", "true", "f800::1", "ffff::1", "ff20::1", 10, "ff10::1", "false");

    interface_entry_data *iface = get_interface_entry("ensp0", "eth", "2", "down", "fa-48-e4-80", 1600, 1200, 1100, 2100, 1750, 45, 18, 23, 12, "10.0.0.3", "255.0.0.0", "10.255.255.255", 500, "10.0.0.1", "false", "f800::1", "ffff::1", "ff20::2", 15, "ff10::1", "false");

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

    interface_entry_data *iface_old = get_interface_entry("ensp0", "eth", "2", "up", "fa-48-e4-80", 1500, 1000, 990, 800, 750, 2, 5, 23, 12, "10.0.0.2", "255.0.0.0", "10.255.255.255", 500, "10.0.0.1", "true", "f800::1", "ffff::1", "ff20::1", 10, "ff10::1", "false");

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

    interface_entry_data *iface = get_interface_entry("ensp0", "eth", "2", "up", "fa-48-e4-80", 1500, 1000, 990, 800, 750, 2, 5, 23, 12, "10.0.0.2", "255.0.0.0", "10.255.255.255", 500, "10.0.0.1", "true", "f800::1", "ffff::1", "ff20::1", 10, "ff10::1", "false");
    iface->enabled = 0;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "ensp0");
    will_return(__wrap_rbtree_get, iface);

    expect_string(__wrap_rbtree_get, key, "ensp0");
    will_return(__wrap_rbtree_get, iface);

    will_return(__wrap_wm_sendmsg, 1);

    expect_string(__wrap_rbtree_delete, key, "ensp0");

    check_disabled_interfaces();

    free_interface_data(iface);
}

void test_check_disabled_interfaces_not_deleted(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("ensp0", keys);

    interface_entry_data *iface = get_interface_entry("ensp0", "eth", "2", "up", "fa-48-e4-80", 1500, 1000, 990, 800, 750, 2, 5, 23, 12, "10.0.0.2", "255.0.0.0", "10.255.255.255", 500, "10.0.0.1", "true", "f800::1", "ffff::1", "ff20::1", 10, "ff10::1", "false");
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

void test_analyze_program_added(void **state)
{
    (void) state;

    program_entry_data *pkg = get_program_entry("pkg", "Wazuh", "high", "000", 15000, "Wazuh Inc", "123456789", "3.12", "x64", "x64_86", "C", "Wazuh agent package", "/var/bin");

    char *expected = "{\"type\":\"program\","
                       "\"data\":{\"type\":\"added\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"name\":\"Wazuh\","
                                                 "\"format\":\"pkg\","
                                                 "\"priority\":\"high\","
                                                 "\"group\":\"000\","
                                                 "\"size\":15000,"
                                                 "\"vendor\":\"Wazuh Inc\","
                                                 "\"install_time\":\"123456789\","
                                                 "\"version\":\"3.12\","
                                                 "\"architecture\":\"x64\","
                                                 "\"multi-arch\":\"x64_86\","
                                                 "\"source\":\"C\","
                                                 "\"description\":\"Wazuh agent package\","
                                                 "\"location\":\"/var/bin\"}}}";

    expect_string(__wrap_rbtree_get, key, "Wazuh-3.12-x64");
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap_rbtree_insert, key, "Wazuh-3.12-x64");
    expect_memory(__wrap_rbtree_insert, value, pkg, sizeof(pkg));
    will_return(__wrap_rbtree_insert, 1);

    char *result = analyze_program(pkg, "");

    assert_string_equal(result, expected);

    free_program_data(pkg);
    free(result);
}

void test_analyze_program_added_failure(void **state)
{
    (void) state;

    program_entry_data *pkg = get_program_entry("pkg", "Wazuh", "high", "000", 15000, "Wazuh Inc", "123456789", "3.12", "x64", "x64_86", "C", "Wazuh agent package", "/var/bin");

    expect_string(__wrap_rbtree_get, key, "Wazuh-3.12-x64");
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap_rbtree_insert, key, "Wazuh-3.12-x64");
    expect_memory(__wrap_rbtree_insert, value, pkg, sizeof(pkg));
    will_return(__wrap_rbtree_insert, 0);

    char *result = analyze_program(pkg, "");

    assert_null(result);
}

void test_analyze_program_modified(void **state)
{
    (void) state;

    program_entry_data *pkg_old = get_program_entry("pkg", "Wazuh", "high", "000", 15000, "Wazuh Inc", "123456789", "3.12", "x64", "x64_86", "C", "Wazuh agent package", "/var/bin");

    program_entry_data *pkg = get_program_entry("pkg", "Wazuh", "high", "001", 15150, "Wazuh Inc", "234567891", "3.12", "x64", "x64_86", "D", "Wazuh agent package", "/var/bin");

    char *expected = "{\"type\":\"program\","
                       "\"data\":{\"type\":\"modified\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"name\":\"Wazuh\","
                                                 "\"format\":\"pkg\","
                                                 "\"priority\":\"high\","
                                                 "\"group\":\"001\","
                                                 "\"size\":15150,"
                                                 "\"vendor\":\"Wazuh Inc\","
                                                 "\"install_time\":\"234567891\","
                                                 "\"version\":\"3.12\","
                                                 "\"architecture\":\"x64\","
                                                 "\"multi-arch\":\"x64_86\","
                                                 "\"source\":\"D\","
                                                 "\"description\":\"Wazuh agent package\","
                                                 "\"location\":\"/var/bin\"},"
                                 "\"changed_attributes\":[\"group\",\"install_time\",\"source\",\"size\"],"
                                 "\"old_attributes\":{\"name\":\"Wazuh\","
                                                     "\"format\":\"pkg\","
                                                     "\"priority\":\"high\","
                                                     "\"group\":\"000\","
                                                     "\"size\":15000,"
                                                     "\"vendor\":\"Wazuh Inc\","
                                                     "\"install_time\":\"123456789\","
                                                     "\"version\":\"3.12\","
                                                     "\"architecture\":\"x64\","
                                                     "\"multi-arch\":\"x64_86\","
                                                     "\"source\":\"C\","
                                                     "\"description\":\"Wazuh agent package\","
                                                     "\"location\":\"/var/bin\"}}}";

    expect_string(__wrap_rbtree_get, key, "Wazuh-3.12-x64");
    will_return(__wrap_rbtree_get, pkg_old);

    expect_string(__wrap_rbtree_replace, key, "Wazuh-3.12-x64");
    expect_memory(__wrap_rbtree_replace, value, pkg, sizeof(pkg));
    will_return(__wrap_rbtree_replace, 1);

    char *result = analyze_program(pkg, "");

    assert_string_equal(result, expected);

    free_program_data(pkg_old);
    free_program_data(pkg);
    free(result);
}

void test_analyze_program_modified_failure(void **state)
{
    (void) state;

    program_entry_data *pkg_old = get_program_entry("pkg", "Wazuh", "high", "000", 15000, "Wazuh Inc", "123456789", "3.12", "x64", "x64_86", "C", "Wazuh agent package", "/var/bin");

    program_entry_data *pkg = get_program_entry("pkg", "Wazuh", "high", "001", 15150, "Wazuh Inc", "234567891", "3.12", "x64", "x64_86", "D", "Wazuh agent package", "/var/bin");

    expect_string(__wrap_rbtree_get, key, "Wazuh-3.12-x64");
    will_return(__wrap_rbtree_get, pkg_old);

    expect_string(__wrap_rbtree_replace, key, "Wazuh-3.12-x64");
    expect_memory(__wrap_rbtree_replace, value, pkg, sizeof(pkg));
    will_return(__wrap_rbtree_replace, 0);

    char *result = analyze_program(pkg, "");

    assert_null(result);

    free_program_data(pkg_old);
}

void test_analyze_program_not_modified(void **state)
{
    (void) state;

    program_entry_data *pkg_old = get_program_entry("pkg", "Wazuh", "high", "000", 15000, "Wazuh Inc", "123456789", "3.12", "x64", "x64_86", "C", "Wazuh agent package", "/var/bin");

    expect_string(__wrap_rbtree_get, key, "Wazuh-3.12-x64");
    will_return(__wrap_rbtree_get, pkg_old);

    char *result = analyze_program(pkg_old, "");

    assert_null(result);
}

void test_analyze_program_invalid(void **state)
{
    (void) state;

    program_entry_data *pkg = init_program_data_entry();

    char *result = analyze_program(pkg, "");

    assert_null(result);
}

void test_check_uninstalled_programs_deleted(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("Wazuh-3.12-x64", keys);

    program_entry_data *pkg = get_program_entry("pkg", "Wazuh", "high", "000", 15000, "Wazuh Inc", "123456789", "3.12", "x64", "x64_86", "C", "Wazuh agent package", "/var/bin");
    pkg->installed = 0;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "Wazuh-3.12-x64");
    will_return(__wrap_rbtree_get, pkg);

    expect_string(__wrap_rbtree_get, key, "Wazuh-3.12-x64");
    will_return(__wrap_rbtree_get, pkg);

    will_return(__wrap_wm_sendmsg, 1);

    expect_string(__wrap_rbtree_delete, key, "Wazuh-3.12-x64");

    check_uninstalled_programs();

    free_program_data(pkg);
}

void test_check_uninstalled_programs_not_deleted(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("Wazuh-3.12-x64", keys);

    program_entry_data *pkg = get_program_entry("pkg", "Wazuh", "high", "000", 15000, "Wazuh Inc", "123456789", "3.12", "x64", "x64_86", "C", "Wazuh agent package", "/var/bin");
    pkg->installed = 1;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "Wazuh-3.12-x64");
    will_return(__wrap_rbtree_get, pkg);

    check_uninstalled_programs();

    assert_int_equal(pkg->installed, 0);

    free_program_data(pkg);
}

void test_check_uninstalled_programs_no_data(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("Wazuh-3.12-x64", keys);

    program_entry_data *pkg = NULL;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "Wazuh-3.12-x64");
    will_return(__wrap_rbtree_get, pkg);

    check_uninstalled_programs();
}

void test_analyze_hotfix_added(void **state)
{
    (void) state;

    hotfix_entry_data *hfix = get_hotfix_entry("KB12345");

    char *expected = "{\"type\":\"hotfix\","
                       "\"data\":{\"type\":\"added\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"hotfix\":\"KB12345\"}}}";

    expect_string(__wrap_rbtree_get, key, "KB12345");
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap_rbtree_insert, key, "KB12345");
    expect_memory(__wrap_rbtree_insert, value, hfix, sizeof(hfix));
    will_return(__wrap_rbtree_insert, 1);

    char *result = analyze_hotfix(hfix, "");

    assert_string_equal(result, expected);

    free_hotfix_data(hfix);
    free(result);
}

void test_analyze_hotfix_added_failure(void **state)
{
    (void) state;

    hotfix_entry_data *hfix = get_hotfix_entry("KB12345");

    expect_string(__wrap_rbtree_get, key, "KB12345");
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap_rbtree_insert, key, "KB12345");
    expect_memory(__wrap_rbtree_insert, value, hfix, sizeof(hfix));
    will_return(__wrap_rbtree_insert, 0);

    char *result = analyze_hotfix(hfix, "");

    assert_null(result);
}

void test_analyze_hotfix_invalid(void **state)
{
    (void) state;

    hotfix_entry_data *hfix = init_hotfix_data_entry();

    char *result = analyze_hotfix(hfix, "");

    assert_null(result);
}

void test_check_uninstalled_hotfixes_deleted(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("KB12345", keys);

    hotfix_entry_data *hfix = get_hotfix_entry("KB12345");
    hfix->installed = 0;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "KB12345");
    will_return(__wrap_rbtree_get, hfix);

    expect_string(__wrap_rbtree_get, key, "KB12345");
    will_return(__wrap_rbtree_get, hfix);

    will_return(__wrap_wm_sendmsg, 1);

    expect_string(__wrap_rbtree_delete, key, "KB12345");

    check_uninstalled_hotfixes();

    free_hotfix_data(hfix);
}

void test_check_uninstalled_hotfixes_not_deleted(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("KB12345", keys);

    hotfix_entry_data *hfix = get_hotfix_entry("KB12345");
    hfix->installed = 1;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "KB12345");
    will_return(__wrap_rbtree_get, hfix);

    check_uninstalled_hotfixes();

    assert_int_equal(hfix->installed, 0);

    free_hotfix_data(hfix);
}

void test_check_uninstalled_hotfixes_no_data(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("KB12345", keys);

    hotfix_entry_data *hfix = NULL;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "KB12345");
    will_return(__wrap_rbtree_get, hfix);

    check_uninstalled_hotfixes();
}

void test_analyze_port_added(void **state)
{
    (void) state;

    port_entry_data *port = get_port_entry("tcp", "10.0.2.9", 5555, "10.0.2.6", 22, 500, 200, 0, "listening", 1234, "ssh");

    char *expected = "{\"type\":\"port\","
                       "\"data\":{\"type\":\"added\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"protocol\":\"tcp\","
                                                 "\"local_ip\":\"10.0.2.9\","
                                                 "\"local_port\":5555,"
                                                 "\"remote_ip\":\"10.0.2.6\","
                                                 "\"remote_port\":22,"
                                                 "\"tx_queue\":500,"
                                                 "\"rx_queue\":200,"
                                                 "\"inode\":0,"
                                                 "\"state\":\"listening\","
                                                 "\"PID\":1234,"
                                                 "\"process\":\"ssh\"}}}";

    expect_string(__wrap_rbtree_get, key, "tcp-10.0.2.9-5555-1234");
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap_rbtree_insert, key, "tcp-10.0.2.9-5555-1234");
    expect_memory(__wrap_rbtree_insert, value, port, sizeof(port));
    will_return(__wrap_rbtree_insert, 1);

    char *result = analyze_port(port, "");

    assert_string_equal(result, expected);

    free_port_data(port);
    free(result);
}

void test_analyze_port_added_failure(void **state)
{
    (void) state;

    port_entry_data *port = get_port_entry("tcp", "10.0.2.9", 5555, "10.0.2.6", 22, 500, 200, 0, "listening", 1234, "ssh");

    expect_string(__wrap_rbtree_get, key, "tcp-10.0.2.9-5555-1234");
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap_rbtree_insert, key, "tcp-10.0.2.9-5555-1234");
    expect_memory(__wrap_rbtree_insert, value, port, sizeof(port));
    will_return(__wrap_rbtree_insert, 0);

    char *result = analyze_port(port, "");

    assert_null(result);
}

void test_analyze_port_modified(void **state)
{
    (void) state;

    port_entry_data *port_old = get_port_entry("tcp", "10.0.2.9", 5555, "10.0.2.6", 22, 500, 200, 0, "listening", 1234, "ssh");

    port_entry_data *port = get_port_entry("tcp", "10.0.2.9", 5555, "10.0.2.7", 22, 550, 230, 1, "listening", 1234, "ssh");

    char *expected = "{\"type\":\"port\","
                       "\"data\":{\"type\":\"modified\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"protocol\":\"tcp\","
                                                 "\"local_ip\":\"10.0.2.9\","
                                                 "\"local_port\":5555,"
                                                 "\"remote_ip\":\"10.0.2.7\","
                                                 "\"remote_port\":22,"
                                                 "\"tx_queue\":550,"
                                                 "\"rx_queue\":230,"
                                                 "\"inode\":1,"
                                                 "\"state\":\"listening\","
                                                 "\"PID\":1234,"
                                                 "\"process\":\"ssh\"},"
                                 "\"changed_attributes\":[\"remote_ip\",\"tx_queue\",\"rx_queue\",\"inode\"],"
                                 "\"old_attributes\":{\"protocol\":\"tcp\","
                                                     "\"local_ip\":\"10.0.2.9\","
                                                     "\"local_port\":5555,"
                                                     "\"remote_ip\":\"10.0.2.6\","
                                                     "\"remote_port\":22,"
                                                     "\"tx_queue\":500,"
                                                     "\"rx_queue\":200,"
                                                     "\"inode\":0,"
                                                     "\"state\":\"listening\","
                                                     "\"PID\":1234,"
                                                     "\"process\":\"ssh\"}}}";

    expect_string(__wrap_rbtree_get, key, "tcp-10.0.2.9-5555-1234");
    will_return(__wrap_rbtree_get, port_old);

    expect_string(__wrap_rbtree_replace, key, "tcp-10.0.2.9-5555-1234");
    expect_memory(__wrap_rbtree_replace, value, port, sizeof(port));
    will_return(__wrap_rbtree_replace, 1);

    char *result = analyze_port(port, "");

    assert_string_equal(result, expected);

    free_port_data(port_old);
    free_port_data(port);
    free(result);
}

void test_analyze_port_modified_failure(void **state)
{
    (void) state;

    port_entry_data *port_old = get_port_entry("tcp", "10.0.2.9", 5555, "10.0.2.6", 22, 500, 200, 0, "listening", 1234, "ssh");

    port_entry_data *port = get_port_entry("tcp", "10.0.2.9", 5555, "10.0.2.7", 22, 550, 230, 1, "listening", 1234, "ssh");

    expect_string(__wrap_rbtree_get, key, "tcp-10.0.2.9-5555-1234");
    will_return(__wrap_rbtree_get, port_old);

    expect_string(__wrap_rbtree_replace, key, "tcp-10.0.2.9-5555-1234");
    expect_memory(__wrap_rbtree_replace, value, port, sizeof(port));
    will_return(__wrap_rbtree_replace, 0);

    char *result = analyze_port(port, "");

    assert_null(result);

    free_port_data(port_old);
}

void test_analyze_port_not_modified(void **state)
{
    (void) state;

    port_entry_data *port_old = get_port_entry("tcp", "10.0.2.9", 5555, "10.0.2.6", 22, 500, 200, 0, "listening", 1234, "ssh");

    expect_string(__wrap_rbtree_get, key, "tcp-10.0.2.9-5555-1234");
    will_return(__wrap_rbtree_get, port_old);

    char *result = analyze_port(port_old, "");

    assert_null(result);
}

void test_analyze_port_invalid(void **state)
{
    (void) state;

    port_entry_data *port = init_port_data_entry();

    char *result = analyze_port(port, "");

    assert_null(result);
}

void test_check_closed_ports_deleted(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("tcp-10.0.2.9-5555-1234", keys);

    port_entry_data *port = get_port_entry("tcp", "10.0.2.9", 5555, "10.0.2.6", 22, 500, 200, 0, "listening", 1234, "ssh");
    port->opened = 0;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "tcp-10.0.2.9-5555-1234");
    will_return(__wrap_rbtree_get, port);

    expect_string(__wrap_rbtree_get, key, "tcp-10.0.2.9-5555-1234");
    will_return(__wrap_rbtree_get, port);

    will_return(__wrap_wm_sendmsg, 1);

    expect_string(__wrap_rbtree_delete, key, "tcp-10.0.2.9-5555-1234");

    check_closed_ports();

    free_port_data(port);
}

void test_check_closed_ports_not_deleted(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("tcp-10.0.2.9-5555-1234", keys);

    port_entry_data *port = get_port_entry("tcp", "10.0.2.9", 5555, "10.0.2.6", 22, 500, 200, 0, "listening", 1234, "ssh");
    port->opened = 1;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "tcp-10.0.2.9-5555-1234");
    will_return(__wrap_rbtree_get, port);

    check_closed_ports();

    assert_int_equal(port->opened, 0);

    free_port_data(port);
}

void test_check_closed_ports_no_data(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("tcp-10.0.2.9-5555-1234", keys);

    port_entry_data *port = NULL;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "tcp-10.0.2.9-5555-1234");
    will_return(__wrap_rbtree_get, port);

    check_closed_ports();
}

void test_analyze_process_added(void **state)
{
    (void) state;

    process_entry_data *proc = get_process_entry(1234, 123, "bash", "bash -c", "python", "S", "root", "root", "root", "admin", "admin", "admin", "admin", 10, 0, 1000, 500, 200, 100, 123456789, 456, 123, 75, 12, 33, 5, 15, 2);

    char *expected = "{\"type\":\"process\","
                       "\"data\":{\"type\":\"added\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"pid\":1234,"
                                                 "\"name\":\"bash\","
                                                 "\"state\":\"S\","
                                                 "\"ppid\":123,"
                                                 "\"utime\":456,"
                                                 "\"stime\":123,"
                                                 "\"cmd\":\"bash -c\","
                                                 "\"argvs\":[\"python\"],"
                                                 "\"euser\":\"root\","
                                                 "\"ruser\":\"root\","
                                                 "\"suser\":\"root\","
                                                 "\"egroup\":\"admin\","
                                                 "\"rgroup\":\"admin\","
                                                 "\"sgroup\":\"admin\","
                                                 "\"fgroup\":\"admin\","
                                                 "\"priority\":10,"
                                                 "\"nice\":0,"
                                                 "\"size\":1000,"
                                                 "\"vm_size\":500,"
                                                 "\"resident\":200,"
                                                 "\"share\":100,"
                                                 "\"start_time\":123456789,"
                                                 "\"pgrp\":75,"
                                                 "\"session\":12,"
                                                 "\"nlwp\":33,"
                                                 "\"tgid\":5,"
                                                 "\"tty\":15,"
                                                 "\"processor\":2}}}";

    expect_string(__wrap_rbtree_get, key, "1234-bash");
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap_rbtree_insert, key, "1234-bash");
    expect_memory(__wrap_rbtree_insert, value, proc, sizeof(proc));
    will_return(__wrap_rbtree_insert, 1);

    char *result = analyze_process(proc, "");

    assert_string_equal(result, expected);

    free_process_data(proc);
    free(result);
}

void test_analyze_process_added_failure(void **state)
{
    (void) state;

    process_entry_data *proc = get_process_entry(1234, 123, "bash", "bash -c", "python", "S", "root", "root", "root", "admin", "admin", "admin", "admin", 10, 0, 1000, 500, 200, 100, 123456789, 456, 123, 75, 12, 33, 5, 15, 2);

    expect_string(__wrap_rbtree_get, key, "1234-bash");
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap_rbtree_insert, key, "1234-bash");
    expect_memory(__wrap_rbtree_insert, value, proc, sizeof(proc));
    will_return(__wrap_rbtree_insert, 0);

    char *result = analyze_process(proc, "");

    assert_null(result);
}

void test_analyze_process_modified(void **state)
{
    (void) state;

    process_entry_data *proc_old = get_process_entry(1234, 123, "bash", "bash -c", "python", "S", "root", "root", "root", "admin", "admin", "admin", "admin", 10, 0, 1000, 500, 200, 100, 123456789, 456, 123, 75, 12, 33, 5, 15, 2);

    process_entry_data *proc = get_process_entry(1234, 123, "bash", "bash -c", "nc", "S", "user", "root", "root", "admin", "admin", "admin", "admin", 15, -5, 1000, 510, 200, 120, 123456789, 700, 230, 75, 12, 33, 5, 15, 3);

    char *expected = "{\"type\":\"process\","
                       "\"data\":{\"type\":\"modified\","
                                 "\"timestamp\":\"\","
                                 "\"attributes\":{\"pid\":1234,"
                                                 "\"name\":\"bash\","
                                                 "\"state\":\"S\","
                                                 "\"ppid\":123,"
                                                 "\"utime\":700,"
                                                 "\"stime\":230,"
                                                 "\"cmd\":\"bash -c\","
                                                 "\"argvs\":[\"nc\"],"
                                                 "\"euser\":\"user\","
                                                 "\"ruser\":\"root\","
                                                 "\"suser\":\"root\","
                                                 "\"egroup\":\"admin\","
                                                 "\"rgroup\":\"admin\","
                                                 "\"sgroup\":\"admin\","
                                                 "\"fgroup\":\"admin\","
                                                 "\"priority\":15,"
                                                 "\"nice\":-5,"
                                                 "\"size\":1000,"
                                                 "\"vm_size\":510,"
                                                 "\"resident\":200,"
                                                 "\"share\":120,"
                                                 "\"start_time\":123456789,"
                                                 "\"pgrp\":75,"
                                                 "\"session\":12,"
                                                 "\"nlwp\":33,"
                                                 "\"tgid\":5,"
                                                 "\"tty\":15,"
                                                 "\"processor\":3},"
                                 "\"changed_attributes\":[\"argvs\",\"euser\",\"priority\",\"nice\",\"vm_size\",\"share\",\"utime\",\"stime\",\"processor\"],"
                                 "\"old_attributes\":{\"pid\":1234,"
                                                     "\"name\":\"bash\","
                                                     "\"state\":\"S\","
                                                     "\"ppid\":123,"
                                                     "\"utime\":456,"
                                                     "\"stime\":123,"
                                                     "\"cmd\":\"bash -c\","
                                                     "\"argvs\":[\"python\"],"
                                                     "\"euser\":\"root\","
                                                     "\"ruser\":\"root\","
                                                     "\"suser\":\"root\","
                                                     "\"egroup\":\"admin\","
                                                     "\"rgroup\":\"admin\","
                                                     "\"sgroup\":\"admin\","
                                                     "\"fgroup\":\"admin\","
                                                     "\"priority\":10,"
                                                     "\"nice\":0,"
                                                     "\"size\":1000,"
                                                     "\"vm_size\":500,"
                                                     "\"resident\":200,"
                                                     "\"share\":100,"
                                                     "\"start_time\":123456789,"
                                                     "\"pgrp\":75,"
                                                     "\"session\":12,"
                                                     "\"nlwp\":33,"
                                                     "\"tgid\":5,"
                                                     "\"tty\":15,"
                                                     "\"processor\":2}}}";

    expect_string(__wrap_rbtree_get, key, "1234-bash");
    will_return(__wrap_rbtree_get, proc_old);

    expect_string(__wrap_rbtree_replace, key, "1234-bash");
    expect_memory(__wrap_rbtree_replace, value, proc, sizeof(proc));
    will_return(__wrap_rbtree_replace, 1);

    char *result = analyze_process(proc, "");

    assert_string_equal(result, expected);

    free_process_data(proc_old);
    free_process_data(proc);
    free(result);
}

void test_analyze_process_modified_failure(void **state)
{
    (void) state;

    process_entry_data *proc_old = get_process_entry(1234, 123, "bash", "bash -c", "python", "S", "root", "root", "root", "admin", "admin", "admin", "admin", 10, 0, 1000, 500, 200, 100, 123456789, 456, 123, 75, 12, 33, 5, 15, 2);

    process_entry_data *proc = get_process_entry(1234, 123, "bash", "bash -c", "nc", "S", "user", "root", "root", "admin", "admin", "admin", "admin", 15, -5, 1000, 510, 200, 120, 123456789, 700, 230, 75, 12, 33, 5, 15, 3);

    expect_string(__wrap_rbtree_get, key, "1234-bash");
    will_return(__wrap_rbtree_get, proc_old);

    expect_string(__wrap_rbtree_replace, key, "1234-bash");
    expect_memory(__wrap_rbtree_replace, value, proc, sizeof(proc));
    will_return(__wrap_rbtree_replace, 0);

    char *result = analyze_process(proc, "");

    assert_null(result);

    free_process_data(proc_old);
}

void test_analyze_process_not_modified(void **state)
{
    (void) state;

    process_entry_data *proc_old = get_process_entry(1234, 123, "bash", "bash -c", "python", "S", "root", "root", "root", "admin", "admin", "admin", "admin", 10, 0, 1000, 500, 200, 100, 123456789, 456, 123, 75, 12, 33, 5, 15, 2);

    expect_string(__wrap_rbtree_get, key, "1234-bash");
    will_return(__wrap_rbtree_get, proc_old);

    char *result = analyze_process(proc_old, "");

    assert_null(result);
}

void test_analyze_process_invalid(void **state)
{
    (void) state;

    process_entry_data *proc = init_process_data_entry();

    char *result = analyze_process(proc, "");

    assert_null(result);
}

void test_check_terminated_processes_deleted(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("1234-bash", keys);

    process_entry_data *proc = get_process_entry(1234, 123, "bash", "bash -c", "python", "S", "root", "root", "root", "admin", "admin", "admin", "admin", 10, 0, 1000, 500, 200, 100, 123456789, 456, 123, 75, 12, 33, 5, 15, 2);
    proc->running = 0;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "1234-bash");
    will_return(__wrap_rbtree_get, proc);

    expect_string(__wrap_rbtree_get, key, "1234-bash");
    will_return(__wrap_rbtree_get, proc);

    will_return(__wrap_wm_sendmsg, 1);

    expect_string(__wrap_rbtree_delete, key, "1234-bash");

    check_terminated_processes();

    free_process_data(proc);
}

void test_check_terminated_processes_not_deleted(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("1234-bash", keys);

    process_entry_data *proc = get_process_entry(1234, 123, "bash", "bash -c", "python", "S", "root", "root", "root", "admin", "admin", "admin", "admin", 10, 0, 1000, 500, 200, 100, 123456789, 456, 123, 75, 12, 33, 5, 15, 2);
    proc->running = 1;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "1234-bash");
    will_return(__wrap_rbtree_get, proc);

    check_terminated_processes();

    assert_int_equal(proc->running, 0);

    free_process_data(proc);
}

void test_check_terminated_processes_no_data(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("1234-bash", keys);

    process_entry_data *proc = NULL;

    will_return(__wrap_rbtree_keys, keys);

    expect_string(__wrap_rbtree_get, key, "1234-bash");
    will_return(__wrap_rbtree_get, proc);

    check_terminated_processes();
}

void test_send_scan_event(void **state)
{
    (void) state;

    char ** keys = NULL;
    keys = os_AddStrArray("1234-bash", keys);

    will_return(__wrap_rbtree_keys, keys);

    will_return(__wrap_wm_sendmsg, 1);

    sys_send_scan_event(PROC_SCAN);
}

void test_hw_json_event(void **state)
{
    (void) state;

    hw_entry *old_hw = get_hw_entry("2345678901", "processor234", 3, 3.0, 30000, 700, 90);
    hw_entry *hw = get_hw_entry("1234567890", "processor123", 4, 2.5, 22222, 595, 80);

    cJSON *hw_added = hw_json_event(NULL, hw, SYS_ADD, "12345");

    assert_string_equal(cJSON_GetObjectItem(hw_added, "type")->valuestring, "hardware");

    cJSON *data = cJSON_GetObjectItem(hw_added, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "added");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "12345");
    assert_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(hw_added);

    cJSON *hw_modified = hw_json_event(old_hw, hw, SYS_MODIFY, "23456");

    assert_string_equal(cJSON_GetObjectItem(hw_modified, "type")->valuestring, "hardware");

    data = cJSON_GetObjectItem(hw_modified, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "modified");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "23456");
    assert_non_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(hw_modified);

    free_hw_data(old_hw);
    free_hw_data(hw);
}

void test_hw_json_compare(void **state)
{
    (void) state;

    hw_entry *old_hw = get_hw_entry("2345678901", "processor234", 3, 3.0, 30000, 700, 90);
    hw_entry *hw = get_hw_entry("1234567890", "processor123", 4, 2.5, 22222, 595, 80);

    cJSON *hw_compare = hw_json_compare(old_hw, hw);

    assert_int_equal(cJSON_GetArraySize(hw_compare), 7);
    assert_string_equal(cJSON_GetArrayItem(hw_compare, 0)->valuestring, "board_serial");
    assert_string_equal(cJSON_GetArrayItem(hw_compare, 1)->valuestring, "cpu_name");
    assert_string_equal(cJSON_GetArrayItem(hw_compare, 2)->valuestring, "cpu_cores");
    assert_string_equal(cJSON_GetArrayItem(hw_compare, 3)->valuestring, "cpu_MHz");
    assert_string_equal(cJSON_GetArrayItem(hw_compare, 4)->valuestring, "ram_total");
    assert_string_equal(cJSON_GetArrayItem(hw_compare, 5)->valuestring, "ram_free");
    assert_string_equal(cJSON_GetArrayItem(hw_compare, 6)->valuestring, "ram_usage");

    cJSON_Delete(hw_compare);

    free_hw_data(old_hw);
    free_hw_data(hw);
}

void test_hw_json_attributes(void **state)
{
    (void) state;

    hw_entry *hw = get_hw_entry("1234567890", "processor123", 4, 2.5, 22222, 595, 80);

    cJSON *hw_attributes = hw_json_attributes(hw);

    assert_string_equal(cJSON_GetObjectItem(hw_attributes, "board_serial")->valuestring, "1234567890");
    assert_string_equal(cJSON_GetObjectItem(hw_attributes, "cpu_name")->valuestring, "processor123");
    assert_int_equal(cJSON_GetObjectItem(hw_attributes, "cpu_cores")->valueint, 4);
    assert_int_equal(cJSON_GetObjectItem(hw_attributes, "cpu_MHz")->valuedouble, 2.5);
    assert_int_equal(cJSON_GetObjectItem(hw_attributes, "ram_total")->valuedouble, 22222);
    assert_int_equal(cJSON_GetObjectItem(hw_attributes, "ram_free")->valuedouble, 595);
    assert_int_equal(cJSON_GetObjectItem(hw_attributes, "ram_usage")->valueint, 80);

    cJSON_Delete(hw_attributes);

    free_hw_data(hw);
}

void test_os_json_event(void **state)
{
    (void) state;

    os_entry *old_os = get_os_entry("Centos", "7", "5", "2564", "Server", "KK", "LNX", "OSLinux", "system", "3.1", "2", "x86", "x21");
    os_entry *os = get_os_entry("Ubuntu", "18", "4", "1515", "Desktop", "UU", "Linux", "UbuntuOS", "wazuh", "1.5", "5", "x86_64", "x23");

    cJSON *os_added = os_json_event(NULL, os, SYS_ADD, "12345");

    assert_string_equal(cJSON_GetObjectItem(os_added, "type")->valuestring, "OS");

    cJSON *data = cJSON_GetObjectItem(os_added, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "added");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "12345");
    assert_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(os_added);

    cJSON *os_modified = os_json_event(old_os, os, SYS_MODIFY, "23456");

    assert_string_equal(cJSON_GetObjectItem(os_modified, "type")->valuestring, "OS");

    data = cJSON_GetObjectItem(os_modified, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "modified");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "23456");
    assert_non_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(os_modified);

    free_os_data(old_os);
    free_os_data(os);
}

void test_os_json_compare(void **state)
{
    (void) state;

    os_entry *old_os = get_os_entry("Centos", "7", "5", "2564", "Server", "KK", "LNX", "OSLinux", "system", "3.1", "2", "x86", "x21");
    os_entry *os = get_os_entry("Ubuntu", "18", "4", "1515", "Desktop", "UU", "Linux", "UbuntuOS", "wazuh", "1.5", "5", "x86_64", "x23");

    cJSON *os_compare = os_json_compare(old_os, os);

    assert_int_equal(cJSON_GetArraySize(os_compare), 13);
    assert_string_equal(cJSON_GetArrayItem(os_compare, 0)->valuestring, "hostname");
    assert_string_equal(cJSON_GetArrayItem(os_compare, 1)->valuestring, "architecture");
    assert_string_equal(cJSON_GetArrayItem(os_compare, 2)->valuestring, "os_name");
    assert_string_equal(cJSON_GetArrayItem(os_compare, 3)->valuestring, "os_release");
    assert_string_equal(cJSON_GetArrayItem(os_compare, 4)->valuestring, "os_version");
    assert_string_equal(cJSON_GetArrayItem(os_compare, 5)->valuestring, "os_codename");
    assert_string_equal(cJSON_GetArrayItem(os_compare, 6)->valuestring, "os_major");
    assert_string_equal(cJSON_GetArrayItem(os_compare, 7)->valuestring, "os_minor");
    assert_string_equal(cJSON_GetArrayItem(os_compare, 8)->valuestring, "os_build");
    assert_string_equal(cJSON_GetArrayItem(os_compare, 9)->valuestring, "os_platform");
    assert_string_equal(cJSON_GetArrayItem(os_compare, 10)->valuestring, "sysname");
    assert_string_equal(cJSON_GetArrayItem(os_compare, 11)->valuestring, "release");
    assert_string_equal(cJSON_GetArrayItem(os_compare, 12)->valuestring, "version");

    cJSON_Delete(os_compare);

    free_os_data(old_os);
    free_os_data(os);
}

void test_os_json_attributes(void **state)
{
    (void) state;

    os_entry *os = get_os_entry("Ubuntu", "18", "4", "1515", "Desktop", "UU", "Linux", "UbuntuOS", "wazuh", "1.5", "5", "x86_64", "x23");

    cJSON *os_attributes = os_json_attributes(os);

    assert_string_equal(cJSON_GetObjectItem(os_attributes, "os_name")->valuestring, "Ubuntu");
    assert_string_equal(cJSON_GetObjectItem(os_attributes, "os_major")->valuestring, "18");
    assert_string_equal(cJSON_GetObjectItem(os_attributes, "os_minor")->valuestring, "4");
    assert_string_equal(cJSON_GetObjectItem(os_attributes, "os_build")->valuestring, "1515");
    assert_string_equal(cJSON_GetObjectItem(os_attributes, "os_version")->valuestring, "Desktop");
    assert_string_equal(cJSON_GetObjectItem(os_attributes, "os_codename")->valuestring, "UU");
    assert_string_equal(cJSON_GetObjectItem(os_attributes, "os_platform")->valuestring, "Linux");
    assert_string_equal(cJSON_GetObjectItem(os_attributes, "sysname")->valuestring, "UbuntuOS");
    assert_string_equal(cJSON_GetObjectItem(os_attributes, "hostname")->valuestring, "wazuh");
    assert_string_equal(cJSON_GetObjectItem(os_attributes, "release")->valuestring, "1.5");
    assert_string_equal(cJSON_GetObjectItem(os_attributes, "version")->valuestring, "5");
    assert_string_equal(cJSON_GetObjectItem(os_attributes, "architecture")->valuestring, "x86_64");
    assert_string_equal(cJSON_GetObjectItem(os_attributes, "os_release")->valuestring, "x23");

    cJSON_Delete(os_attributes);

    free_os_data(os);
}

void test_interface_json_event(void **state)
{
    (void) state;

    interface_entry_data *old_iface = get_interface_entry("ensp1", "wifi", "1", "down", "fa-54-a2-e1", 1200, 800, 550, 430, 540, 4, 13, 33, 21, "10.0.1.2", "255.255.0.0", "10.0.255.255", 300, "10.0.1.1", "false", "f800::3", "ffff::3", "ff20::3", 5, "ff10::3", "true");
    interface_entry_data *iface = get_interface_entry("ensp0", "eth", "2", "up", "fa-48-e4-80", 1500, 1000, 990, 800, 750, 2, 5, 23, 12, "10.0.0.2", "255.0.0.0", "10.255.255.255", 500, "10.0.0.1", "true", "f800::1", "ffff::1", "ff20::1", 10, "ff10::1", "false");

    cJSON *iface_added = interface_json_event(NULL, iface, SYS_ADD, "12345");

    assert_string_equal(cJSON_GetObjectItem(iface_added, "type")->valuestring, "network");

    cJSON *data = cJSON_GetObjectItem(iface_added, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "added");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "12345");
    assert_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(iface_added);

    cJSON *iface_modified = interface_json_event(old_iface, iface, SYS_MODIFY, "23456");

    assert_string_equal(cJSON_GetObjectItem(iface_modified, "type")->valuestring, "network");

    data = cJSON_GetObjectItem(iface_modified, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "modified");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "23456");
    assert_non_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(iface_modified);

    cJSON *iface_deleted = interface_json_event(NULL, iface, SYS_DELETE, "34567");

    assert_string_equal(cJSON_GetObjectItem(iface_deleted, "type")->valuestring, "network");

    data = cJSON_GetObjectItem(iface_deleted, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "deleted");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "34567");
    assert_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(iface_deleted);

    free_interface_data(old_iface);
    free_interface_data(iface);
}

void test_interface_json_compare(void **state)
{
    (void) state;

    interface_entry_data *old_iface = get_interface_entry("ensp1", "wifi", "1", "down", "fa-54-a2-e1", 1200, 800, 550, 430, 540, 4, 13, 33, 21, "10.0.1.2", "255.255.0.0", "10.0.255.255", 300, "10.0.1.1", "false", "f800::3", "ffff::3", "ff20::3", 5, "ff10::3", "true");
    interface_entry_data *iface = get_interface_entry("ensp0", "eth", "2", "up", "fa-48-e4-80", 1500, 1000, 990, 800, 750, 2, 5, 23, 12, "10.0.0.2", "255.0.0.0", "10.255.255.255", 500, "10.0.0.1", "true", "f800::1", "ffff::1", "ff20::1", 10, "ff10::1", "false");

    cJSON *iface_compare = interface_json_compare(old_iface, iface);

    assert_int_equal(cJSON_GetArraySize(iface_compare), 26);
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 0)->valuestring, "name");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 1)->valuestring, "adapter");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 2)->valuestring, "type");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 3)->valuestring, "state");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 4)->valuestring, "mac");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 5)->valuestring, "ipv4_address");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 6)->valuestring, "ipv4_netmask");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 7)->valuestring, "ipv4_broadcast");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 8)->valuestring, "ipv4_gateway");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 9)->valuestring, "ipv4_dhcp");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 10)->valuestring, "ipv4_metric");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 11)->valuestring, "ipv6_address");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 12)->valuestring, "ipv6_netmask");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 13)->valuestring, "ipv6_broadcast");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 14)->valuestring, "ipv6_gateway");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 15)->valuestring, "ipv6_dhcp");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 16)->valuestring, "ipv6_metric");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 17)->valuestring, "mtu");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 18)->valuestring, "tx_packets");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 19)->valuestring, "rx_packets");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 20)->valuestring, "tx_bytes");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 21)->valuestring, "rx_bytes");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 22)->valuestring, "tx_errors");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 23)->valuestring, "rx_errors");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 24)->valuestring, "tx_dropped");
    assert_string_equal(cJSON_GetArrayItem(iface_compare, 25)->valuestring, "rx_dropped");

    cJSON_Delete(iface_compare);

    free_interface_data(old_iface);
    free_interface_data(iface);
}

void test_interface_json_attributes(void **state)
{
    (void) state;

    interface_entry_data *iface = get_interface_entry("ensp0", "eth", "2", "up", "fa-48-e4-80", 1500, 1000, 990, 800, 750, 2, 5, 23, 12, "10.0.0.2", "255.0.0.0", "10.255.255.255", 500, "10.0.0.1", "true", "f800::1", "ffff::1", "ff20::1", 10, "ff10::1", "false");

    cJSON *iface_attributes = interface_json_attributes(iface);

    assert_string_equal(cJSON_GetObjectItem(iface_attributes, "name")->valuestring, "ensp0");
    assert_string_equal(cJSON_GetObjectItem(iface_attributes, "adapter")->valuestring, "eth");
    assert_string_equal(cJSON_GetObjectItem(iface_attributes, "type")->valuestring, "2");
    assert_string_equal(cJSON_GetObjectItem(iface_attributes, "state")->valuestring, "up");
    assert_string_equal(cJSON_GetObjectItem(iface_attributes, "MAC")->valuestring, "fa-48-e4-80");
    assert_int_equal(cJSON_GetObjectItem(iface_attributes, "MTU")->valueint, 1500);
    assert_int_equal(cJSON_GetObjectItem(iface_attributes, "tx_packets")->valueint, 1000);
    assert_int_equal(cJSON_GetObjectItem(iface_attributes, "rx_packets")->valueint, 990);
    assert_int_equal(cJSON_GetObjectItem(iface_attributes, "tx_bytes")->valueint, 800);
    assert_int_equal(cJSON_GetObjectItem(iface_attributes, "rx_bytes")->valueint, 750);
    assert_int_equal(cJSON_GetObjectItem(iface_attributes, "tx_errors")->valueint, 2);
    assert_int_equal(cJSON_GetObjectItem(iface_attributes, "rx_errors")->valueint, 5);
    assert_int_equal(cJSON_GetObjectItem(iface_attributes, "tx_dropped")->valueint, 23);
    assert_int_equal(cJSON_GetObjectItem(iface_attributes, "rx_dropped")->valueint, 12);

    cJSON *iface_ipv4 = cJSON_GetObjectItem(iface_attributes, "IPv4");
    assert_non_null(iface_ipv4);
    assert_string_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(iface_ipv4, "address"), 0)->valuestring, "10.0.0.2");
    assert_null(cJSON_GetArrayItem(cJSON_GetObjectItem(iface_ipv4, "address"), 1));
    assert_string_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(iface_ipv4, "netmask"), 0)->valuestring, "255.0.0.0");
    assert_null(cJSON_GetArrayItem(cJSON_GetObjectItem(iface_ipv4, "netmask"), 1));
    assert_string_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(iface_ipv4, "broadcast"), 0)->valuestring, "10.255.255.255");
    assert_null(cJSON_GetArrayItem(cJSON_GetObjectItem(iface_ipv4, "broadcast"), 1));
    assert_int_equal(cJSON_GetObjectItem(iface_ipv4, "metric")->valueint, 500);
    assert_string_equal(cJSON_GetObjectItem(iface_ipv4, "gateway")->valuestring, "10.0.0.1");
    assert_string_equal(cJSON_GetObjectItem(iface_ipv4, "DHCP")->valuestring, "true");

    cJSON *iface_ipv6 = cJSON_GetObjectItem(iface_attributes, "IPv6");
    assert_non_null(iface_ipv6);
    assert_string_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(iface_ipv6, "address"), 0)->valuestring, "f800::1");
    assert_null(cJSON_GetArrayItem(cJSON_GetObjectItem(iface_ipv6, "address"), 1));
    assert_string_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(iface_ipv6, "netmask"), 0)->valuestring, "ffff::1");
    assert_null(cJSON_GetArrayItem(cJSON_GetObjectItem(iface_ipv6, "netmask"), 1));
    assert_string_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(iface_ipv6, "broadcast"), 0)->valuestring, "ff20::1");
    assert_null(cJSON_GetArrayItem(cJSON_GetObjectItem(iface_ipv6, "broadcast"), 1));
    assert_int_equal(cJSON_GetObjectItem(iface_ipv6, "metric")->valueint, 10);
    assert_string_equal(cJSON_GetObjectItem(iface_ipv6, "gateway")->valuestring, "ff10::1");
    assert_string_equal(cJSON_GetObjectItem(iface_ipv6, "DHCP")->valuestring, "false");

    cJSON_Delete(iface_attributes);

    free_interface_data(iface);
}

void test_program_json_event(void **state)
{
    (void) state;

    program_entry_data *old_pkg = get_program_entry("deb", "Wazuh-api", "medium", "005", 12500, "Wazuh LLC", "012345678", "3.10", "x86", "x86", "D", "Wazuh api package", "/usr/bin");
    program_entry_data *pkg = get_program_entry("pkg", "Wazuh", "high", "000", 15000, "Wazuh Inc", "123456789", "3.12", "x64", "x64_86", "C", "Wazuh agent package", "/var/bin");

    cJSON *pkg_added = program_json_event(NULL, pkg, SYS_ADD, "12345");

    assert_string_equal(cJSON_GetObjectItem(pkg_added, "type")->valuestring, "program");

    cJSON *data = cJSON_GetObjectItem(pkg_added, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "added");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "12345");
    assert_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(pkg_added);

    cJSON *pkg_modified = program_json_event(old_pkg, pkg, SYS_MODIFY, "23456");

    assert_string_equal(cJSON_GetObjectItem(pkg_modified, "type")->valuestring, "program");

    data = cJSON_GetObjectItem(pkg_modified, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "modified");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "23456");
    assert_non_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(pkg_modified);

    cJSON *pkg_deleted = program_json_event(NULL, pkg, SYS_DELETE, "34567");

    assert_string_equal(cJSON_GetObjectItem(pkg_deleted, "type")->valuestring, "program");

    data = cJSON_GetObjectItem(pkg_deleted, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "deleted");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "34567");
    assert_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(pkg_deleted);

    free_program_data(old_pkg);
    free_program_data(pkg);
}

void test_program_json_compare(void **state)
{
    (void) state;

    program_entry_data *old_pkg = get_program_entry("deb", "Wazuh-api", "medium", "005", 12500, "Wazuh LLC", "012345678", "3.10", "x86", "x86", "D", "Wazuh api package", "/usr/bin");
    program_entry_data *pkg = get_program_entry("pkg", "Wazuh", "high", "000", 15000, "Wazuh Inc", "123456789", "3.12", "x64", "x64_86", "C", "Wazuh agent package", "/var/bin");

    cJSON *pkg_compare = program_json_compare(old_pkg, pkg);

    assert_int_equal(cJSON_GetArraySize(pkg_compare), 13);
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 0)->valuestring, "format");
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 1)->valuestring, "name");
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 2)->valuestring, "priority");
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 3)->valuestring, "group");
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 4)->valuestring, "vendor");
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 5)->valuestring, "install_time");
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 6)->valuestring, "version");
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 7)->valuestring, "architecture");
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 8)->valuestring, "multi_arch");
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 9)->valuestring, "source");
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 10)->valuestring, "description");
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 11)->valuestring, "location");
    assert_string_equal(cJSON_GetArrayItem(pkg_compare, 12)->valuestring, "size");

    cJSON_Delete(pkg_compare);

    free_program_data(old_pkg);
    free_program_data(pkg);
}

void test_program_json_attributes(void **state)
{
    (void) state;

    program_entry_data *pkg = get_program_entry("pkg", "Wazuh", "high", "000", 15000, "Wazuh Inc", "123456789", "3.12", "x64", "x64_86", "C", "Wazuh agent package", "/var/bin");

    cJSON *pkg_attributes = program_json_attributes(pkg);

    assert_string_equal(cJSON_GetObjectItem(pkg_attributes, "name")->valuestring, "Wazuh");
    assert_string_equal(cJSON_GetObjectItem(pkg_attributes, "format")->valuestring, "pkg");
    assert_string_equal(cJSON_GetObjectItem(pkg_attributes, "priority")->valuestring, "high");
    assert_string_equal(cJSON_GetObjectItem(pkg_attributes, "group")->valuestring, "000");
    assert_int_equal(cJSON_GetObjectItem(pkg_attributes, "size")->valuedouble, 15000);
    assert_string_equal(cJSON_GetObjectItem(pkg_attributes, "vendor")->valuestring, "Wazuh Inc");
    assert_string_equal(cJSON_GetObjectItem(pkg_attributes, "install_time")->valuestring, "123456789");
    assert_string_equal(cJSON_GetObjectItem(pkg_attributes, "version")->valuestring, "3.12");
    assert_string_equal(cJSON_GetObjectItem(pkg_attributes, "architecture")->valuestring, "x64");
    assert_string_equal(cJSON_GetObjectItem(pkg_attributes, "multi-arch")->valuestring, "x64_86");
    assert_string_equal(cJSON_GetObjectItem(pkg_attributes, "source")->valuestring, "C");
    assert_string_equal(cJSON_GetObjectItem(pkg_attributes, "description")->valuestring, "Wazuh agent package");
    assert_string_equal(cJSON_GetObjectItem(pkg_attributes, "location")->valuestring, "/var/bin");

    cJSON_Delete(pkg_attributes);

    free_program_data(pkg);
}

void test_hotfix_json_event(void **state)
{
    (void) state;

    hotfix_entry_data *old_hfix = get_hotfix_entry("KB11547");
    hotfix_entry_data *hfix = get_hotfix_entry("KB12345");

    cJSON *hfix_added = hotfix_json_event(NULL, hfix, SYS_ADD, "12345");

    assert_string_equal(cJSON_GetObjectItem(hfix_added, "type")->valuestring, "hotfix");

    cJSON *data = cJSON_GetObjectItem(hfix_added, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "added");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "12345");
    assert_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(hfix_added);

    cJSON *hfix_modified = hotfix_json_event(old_hfix, hfix, SYS_MODIFY, "23456");

    assert_string_equal(cJSON_GetObjectItem(hfix_modified, "type")->valuestring, "hotfix");

    data = cJSON_GetObjectItem(hfix_modified, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "modified");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "23456");
    assert_non_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(hfix_modified);

    cJSON *hfix_deleted = hotfix_json_event(NULL, hfix, SYS_DELETE, "34567");

    assert_string_equal(cJSON_GetObjectItem(hfix_deleted, "type")->valuestring, "hotfix");

    data = cJSON_GetObjectItem(hfix_deleted, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "deleted");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "34567");
    assert_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(hfix_deleted);

    free_hotfix_data(old_hfix);
    free_hotfix_data(hfix);
}

void test_hotfix_json_compare(void **state)
{
    (void) state;

    hotfix_entry_data *old_hfix = get_hotfix_entry("KB11547");
    hotfix_entry_data *hfix = get_hotfix_entry("KB12345");

    cJSON *hfix_compare = hotfix_json_compare(old_hfix, hfix);

    assert_int_equal(cJSON_GetArraySize(hfix_compare), 1);
    assert_string_equal(cJSON_GetArrayItem(hfix_compare, 0)->valuestring, "hotfix");

    cJSON_Delete(hfix_compare);

    free_hotfix_data(old_hfix);
    free_hotfix_data(hfix);
}

void test_hotfix_json_attributes(void **state)
{
    (void) state;

    hotfix_entry_data *hfix = get_hotfix_entry("KB12345");

    cJSON *hfix_attributes = hotfix_json_attributes(hfix);

    assert_string_equal(cJSON_GetObjectItem(hfix_attributes, "hotfix")->valuestring, "KB12345");

    cJSON_Delete(hfix_attributes);

    free_hotfix_data(hfix);
}

void test_port_json_event(void **state)
{
    (void) state;

    port_entry_data *old_port = get_port_entry("udp", "10.0.2.8", 4444, "10.0.2.7", 53, 450, 310, 1, "-", 2345, "dns");
    port_entry_data *port = get_port_entry("tcp", "10.0.2.9", 5555, "10.0.2.6", 22, 500, 200, 0, "listening", 1234, "ssh");

    cJSON *port_added = port_json_event(NULL, port, SYS_ADD, "12345");

    assert_string_equal(cJSON_GetObjectItem(port_added, "type")->valuestring, "port");

    cJSON *data = cJSON_GetObjectItem(port_added, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "added");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "12345");
    assert_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(port_added);

    cJSON *port_modified = port_json_event(old_port, port, SYS_MODIFY, "23456");

    assert_string_equal(cJSON_GetObjectItem(port_modified, "type")->valuestring, "port");

    data = cJSON_GetObjectItem(port_modified, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "modified");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "23456");
    assert_non_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(port_modified);

    cJSON *port_deleted = port_json_event(NULL, port, SYS_DELETE, "34567");

    assert_string_equal(cJSON_GetObjectItem(port_deleted, "type")->valuestring, "port");

    data = cJSON_GetObjectItem(port_deleted, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "deleted");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "34567");
    assert_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(port_deleted);

    free_port_data(old_port);
    free_port_data(port);
}

void test_port_json_compare(void **state)
{
    (void) state;

    port_entry_data *old_port = get_port_entry("udp", "10.0.2.8", 4444, "10.0.2.7", 53, 450, 310, 1, "-", 2345, "dns");
    port_entry_data *port = get_port_entry("tcp", "10.0.2.9", 5555, "10.0.2.6", 22, 500, 200, 0, "listening", 1234, "ssh");

    cJSON *port_compare = port_json_compare(old_port, port);

    assert_int_equal(cJSON_GetArraySize(port_compare), 11);
    assert_string_equal(cJSON_GetArrayItem(port_compare, 0)->valuestring, "protocol");
    assert_string_equal(cJSON_GetArrayItem(port_compare, 1)->valuestring, "local_ip");
    assert_string_equal(cJSON_GetArrayItem(port_compare, 2)->valuestring, "remote_ip");
    assert_string_equal(cJSON_GetArrayItem(port_compare, 3)->valuestring, "state");
    assert_string_equal(cJSON_GetArrayItem(port_compare, 4)->valuestring, "process");
    assert_string_equal(cJSON_GetArrayItem(port_compare, 5)->valuestring, "local_port");
    assert_string_equal(cJSON_GetArrayItem(port_compare, 6)->valuestring, "remote_port");
    assert_string_equal(cJSON_GetArrayItem(port_compare, 7)->valuestring, "tx_queue");
    assert_string_equal(cJSON_GetArrayItem(port_compare, 8)->valuestring, "rx_queue");
    assert_string_equal(cJSON_GetArrayItem(port_compare, 9)->valuestring, "inode");
    assert_string_equal(cJSON_GetArrayItem(port_compare, 10)->valuestring, "pid");

    cJSON_Delete(port_compare);

    free_port_data(old_port);
    free_port_data(port);
}

void test_port_json_attributes(void **state)
{
    (void) state;

    port_entry_data *port = get_port_entry("tcp", "10.0.2.9", 5555, "10.0.2.6", 22, 500, 200, 0, "listening", 1234, "ssh");

    cJSON *port_attributes = port_json_attributes(port);

    assert_string_equal(cJSON_GetObjectItem(port_attributes, "protocol")->valuestring, "tcp");
    assert_string_equal(cJSON_GetObjectItem(port_attributes, "local_ip")->valuestring, "10.0.2.9");
    assert_int_equal(cJSON_GetObjectItem(port_attributes, "local_port")->valueint, 5555);
    assert_string_equal(cJSON_GetObjectItem(port_attributes, "remote_ip")->valuestring, "10.0.2.6");
    assert_int_equal(cJSON_GetObjectItem(port_attributes, "remote_port")->valueint, 22);
    assert_int_equal(cJSON_GetObjectItem(port_attributes, "tx_queue")->valueint, 500);
    assert_int_equal(cJSON_GetObjectItem(port_attributes, "rx_queue")->valueint, 200);
    assert_int_equal(cJSON_GetObjectItem(port_attributes, "inode")->valueint, 0);
    assert_string_equal(cJSON_GetObjectItem(port_attributes, "state")->valuestring, "listening");
    assert_int_equal(cJSON_GetObjectItem(port_attributes, "PID")->valueint, 1234);
    assert_string_equal(cJSON_GetObjectItem(port_attributes, "process")->valuestring, "ssh");

    cJSON_Delete(port_attributes);

    free_port_data(port);
}

void test_process_json_event(void **state)
{
    (void) state;

    process_entry_data *old_proc = get_process_entry(123, 25, "sh", "sh -c", "nc", "R", "user", "user", "user", "users", "users", "users", "users", 15, -5, 500, 200, 100, 50, 112345678, 235, 85, 24, 10, 22, 3, 11, 0);
    process_entry_data *proc = get_process_entry(1234, 123, "bash", "bash -c", "python", "S", "root", "root", "root", "admin", "admin", "admin", "admin", 10, 0, 1000, 500, 200, 100, 123456789, 456, 123, 75, 12, 33, 5, 15, 2);

    cJSON *proc_added = process_json_event(NULL, proc, SYS_ADD, "12345");

    assert_string_equal(cJSON_GetObjectItem(proc_added, "type")->valuestring, "process");

    cJSON *data = cJSON_GetObjectItem(proc_added, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "added");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "12345");
    assert_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(proc_added);

    cJSON *proc_modified = process_json_event(old_proc, proc, SYS_MODIFY, "23456");

    assert_string_equal(cJSON_GetObjectItem(proc_modified, "type")->valuestring, "process");

    data = cJSON_GetObjectItem(proc_modified, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "modified");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "23456");
    assert_non_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(proc_modified);

    cJSON *proc_deleted = process_json_event(NULL, proc, SYS_DELETE, "34567");

    assert_string_equal(cJSON_GetObjectItem(proc_deleted, "type")->valuestring, "process");

    data = cJSON_GetObjectItem(proc_deleted, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "type")->valuestring, "deleted");
    assert_string_equal(cJSON_GetObjectItem(data, "timestamp")->valuestring, "34567");
    assert_null(cJSON_GetObjectItem(data, "changed_attributes"));
    assert_null(cJSON_GetObjectItem(data, "old_attributes"));
    assert_non_null(cJSON_GetObjectItem(data, "attributes"));

    cJSON_Delete(proc_deleted);

    free_process_data(old_proc);
    free_process_data(proc);
}

void test_process_json_compare(void **state)
{
    (void) state;

    process_entry_data *old_proc = get_process_entry(123, 25, "sh", "sh -c", "nc", "R", "user", "user", "user", "users", "users", "users", "users", 15, -5, 500, 200, 100, 50, 112345678, 235, 85, 24, 10, 22, 3, 11, 0);
    process_entry_data *proc = get_process_entry(1234, 123, "bash", "bash -c", "python", "S", "root", "root", "root", "admin", "admin", "admin", "admin", 10, 0, 1000, 500, 200, 100, 123456789, 456, 123, 75, 12, 33, 5, 15, 2);

    cJSON *proc_compare = process_json_compare(old_proc, proc);

    assert_int_equal(cJSON_GetArraySize(proc_compare), 28);
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 0)->valuestring, "name");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 1)->valuestring, "cmd");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 2)->valuestring, "argvs");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 3)->valuestring, "state");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 4)->valuestring, "euser");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 5)->valuestring, "ruser");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 6)->valuestring, "suser");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 7)->valuestring, "egroup");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 8)->valuestring, "rgroup");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 9)->valuestring, "sgroup");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 10)->valuestring, "fgroup");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 11)->valuestring, "pid");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 12)->valuestring, "ppid");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 13)->valuestring, "priority");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 14)->valuestring, "nice");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 15)->valuestring, "size");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 16)->valuestring, "vm_size");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 17)->valuestring, "resident");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 18)->valuestring, "share");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 19)->valuestring, "start_time");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 20)->valuestring, "utime");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 21)->valuestring, "stime");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 22)->valuestring, "pgrp");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 23)->valuestring, "session");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 24)->valuestring, "nlwp");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 25)->valuestring, "tgid");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 26)->valuestring, "tty");
    assert_string_equal(cJSON_GetArrayItem(proc_compare, 27)->valuestring, "processor");

    cJSON_Delete(proc_compare);

    free_process_data(old_proc);
    free_process_data(proc);
}

void test_process_json_attributes(void **state)
{
    (void) state;

    process_entry_data *proc = get_process_entry(1234, 123, "bash", "bash -c", "python", "S", "root", "root", "root", "admin", "admin", "admin", "admin", 10, 0, 1000, 500, 200, 100, 123456789, 456, 123, 75, 12, 33, 5, 15, 2);

    cJSON *proc_attributes = process_json_attributes(proc);

    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "pid")->valueint, 1234);
    assert_string_equal(cJSON_GetObjectItem(proc_attributes, "name")->valuestring, "bash");
    assert_string_equal(cJSON_GetObjectItem(proc_attributes, "state")->valuestring, "S");
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "ppid")->valueint, 123);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "utime")->valuedouble, 456);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "stime")->valuedouble, 123);
    assert_string_equal(cJSON_GetObjectItem(proc_attributes, "cmd")->valuestring, "bash -c");
    assert_string_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(proc_attributes, "argvs"), 0)->valuestring, "python");
    assert_null(cJSON_GetArrayItem(cJSON_GetObjectItem(proc_attributes, "argvs"), 1));
    assert_string_equal(cJSON_GetObjectItem(proc_attributes, "euser")->valuestring, "root");
    assert_string_equal(cJSON_GetObjectItem(proc_attributes, "ruser")->valuestring, "root");
    assert_string_equal(cJSON_GetObjectItem(proc_attributes, "suser")->valuestring, "root");
    assert_string_equal(cJSON_GetObjectItem(proc_attributes, "egroup")->valuestring, "admin");
    assert_string_equal(cJSON_GetObjectItem(proc_attributes, "rgroup")->valuestring, "admin");
    assert_string_equal(cJSON_GetObjectItem(proc_attributes, "sgroup")->valuestring, "admin");
    assert_string_equal(cJSON_GetObjectItem(proc_attributes, "fgroup")->valuestring, "admin");
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "priority")->valueint, 10);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "nice")->valueint, 0);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "size")->valuedouble, 1000);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "vm_size")->valuedouble, 500);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "resident")->valuedouble, 200);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "share")->valuedouble, 100);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "start_time")->valuedouble, 123456789);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "pgrp")->valueint, 75);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "session")->valueint, 12);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "nlwp")->valueint, 33);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "tgid")->valueint, 5);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "tty")->valueint, 15);
    assert_int_equal(cJSON_GetObjectItem(proc_attributes, "processor")->valueint, 2);

    cJSON_Delete(proc_attributes);

    free_process_data(proc);
}

void test_json_scan_event(void **state)
{
    (void) state;

    cJSON *hw_scan = sys_json_scan_event(HW_SCAN, 123456789, 1);

    assert_string_equal(cJSON_GetObjectItem(hw_scan, "type")->valuestring, "hardware_scan");

    cJSON *data = cJSON_GetObjectItem(hw_scan, "data");
    assert_non_null(data);
    assert_int_equal(cJSON_GetObjectItem(data, "timestamp")->valuedouble, 123456789);
    assert_int_equal(cJSON_GetObjectItem(data, "items")->valueint, 1);

    cJSON_Delete(hw_scan);

    cJSON *os_scan = sys_json_scan_event(OS_SCAN, 234567891, 1);

    assert_string_equal(cJSON_GetObjectItem(os_scan, "type")->valuestring, "OS_scan");

    data = cJSON_GetObjectItem(os_scan, "data");
    assert_non_null(data);
    assert_int_equal(cJSON_GetObjectItem(data, "timestamp")->valuedouble, 234567891);
    assert_int_equal(cJSON_GetObjectItem(data, "items")->valueint, 1);

    cJSON_Delete(os_scan);

    cJSON *iface_scan = sys_json_scan_event(IFACE_SCAN, 345678912, 3);

    assert_string_equal(cJSON_GetObjectItem(iface_scan, "type")->valuestring, "network_scan");

    data = cJSON_GetObjectItem(iface_scan, "data");
    assert_non_null(data);
    assert_int_equal(cJSON_GetObjectItem(data, "timestamp")->valuedouble, 345678912);
    assert_int_equal(cJSON_GetObjectItem(data, "items")->valueint, 3);

    cJSON_Delete(iface_scan);

    cJSON *pkg_scan = sys_json_scan_event(PKG_SCAN, 456789123, 150);

    assert_string_equal(cJSON_GetObjectItem(pkg_scan, "type")->valuestring, "program_scan");

    data = cJSON_GetObjectItem(pkg_scan, "data");
    assert_non_null(data);
    assert_int_equal(cJSON_GetObjectItem(data, "timestamp")->valuedouble, 456789123);
    assert_int_equal(cJSON_GetObjectItem(data, "items")->valueint, 150);

    cJSON_Delete(pkg_scan);

    cJSON *hfix_scan = sys_json_scan_event(HFIX_SCAN, 567891234, 54);

    assert_string_equal(cJSON_GetObjectItem(hfix_scan, "type")->valuestring, "hotfix_scan");

    data = cJSON_GetObjectItem(hfix_scan, "data");
    assert_non_null(data);
    assert_int_equal(cJSON_GetObjectItem(data, "timestamp")->valuedouble, 567891234);
    assert_int_equal(cJSON_GetObjectItem(data, "items")->valueint, 54);

    cJSON_Delete(hfix_scan);

    cJSON *port_scan = sys_json_scan_event(PORT_SCAN, 678912345, 15);

    assert_string_equal(cJSON_GetObjectItem(port_scan, "type")->valuestring, "port_scan");

    data = cJSON_GetObjectItem(port_scan, "data");
    assert_non_null(data);
    assert_int_equal(cJSON_GetObjectItem(data, "timestamp")->valuedouble, 678912345);
    assert_int_equal(cJSON_GetObjectItem(data, "items")->valueint, 15);

    cJSON_Delete(port_scan);

    cJSON *proc_scan = sys_json_scan_event(PROC_SCAN, 789123456, 255);

    assert_string_equal(cJSON_GetObjectItem(proc_scan, "type")->valuestring, "process_scan");

    data = cJSON_GetObjectItem(proc_scan, "data");
    assert_non_null(data);
    assert_int_equal(cJSON_GetObjectItem(data, "timestamp")->valuedouble, 789123456);
    assert_int_equal(cJSON_GetObjectItem(data, "items")->valueint, 255);

    cJSON_Delete(proc_scan);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_scan_rotation, init_sys_scan_config, delete_sys_config),
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
        cmocka_unit_test_setup_teardown(test_check_disabled_interfaces_deleted, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_disabled_interfaces_not_deleted, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_disabled_interfaces_no_data, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_program_added, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_program_added_failure, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_program_modified, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_program_modified_failure, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_program_not_modified, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_program_invalid, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_uninstalled_programs_deleted, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_uninstalled_programs_not_deleted, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_uninstalled_programs_no_data, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_hotfix_added, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_hotfix_added_failure, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_hotfix_invalid, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_uninstalled_hotfixes_deleted, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_uninstalled_hotfixes_not_deleted, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_uninstalled_hotfixes_no_data, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_port_added, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_port_added_failure, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_port_modified, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_port_modified_failure, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_port_not_modified, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_port_invalid, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_closed_ports_deleted, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_closed_ports_not_deleted, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_closed_ports_no_data, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_process_added, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_process_added_failure, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_process_modified, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_process_modified_failure, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_process_not_modified, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_analyze_process_invalid, init_sys_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_terminated_processes_deleted, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_terminated_processes_not_deleted, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_check_terminated_processes_no_data, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test_setup_teardown(test_send_scan_event, init_sys_deleted_config, delete_sys_config),
        cmocka_unit_test(test_hw_json_event),
        cmocka_unit_test(test_hw_json_compare),
        cmocka_unit_test(test_hw_json_attributes),
        cmocka_unit_test(test_os_json_event),
        cmocka_unit_test(test_os_json_compare),
        cmocka_unit_test(test_os_json_attributes),
        cmocka_unit_test(test_interface_json_event),
        cmocka_unit_test(test_interface_json_compare),
        cmocka_unit_test(test_interface_json_attributes),
        cmocka_unit_test(test_program_json_event),
        cmocka_unit_test(test_program_json_compare),
        cmocka_unit_test(test_program_json_attributes),
        cmocka_unit_test(test_hotfix_json_event),
        cmocka_unit_test(test_hotfix_json_compare),
        cmocka_unit_test(test_hotfix_json_attributes),
        cmocka_unit_test(test_port_json_event),
        cmocka_unit_test(test_port_json_compare),
        cmocka_unit_test(test_port_json_attributes),
        cmocka_unit_test(test_process_json_event),
        cmocka_unit_test(test_process_json_compare),
        cmocka_unit_test(test_process_json_attributes),
        cmocka_unit_test(test_json_scan_event)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
