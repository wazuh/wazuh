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

#include "../wazuh_db/wdb.h"

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_wdb_hardware_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * serial, const char * cpu_name, int cpu_cores, const char * cpu_mhz, uint64_t ram_total, uint64_t ram_free, int ram_usage)
{
    check_expected(scan_id);
    check_expected(scan_time);
    check_expected(serial);
    check_expected(cpu_name);
    check_expected(cpu_cores);
    check_expected(cpu_mhz);
    check_expected(ram_total);
    check_expected(ram_free);
    check_expected(ram_usage);
    return mock();
}

int __wrap_wdb_osinfo_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * hostname, const char * architecture, const char * os_name, const char * os_version, const char * os_codename, const char * os_major, const char * os_minor, const char * os_build, const char * os_platform, const char * sysname, const char * release, const char * version, const char * os_release)
{
    check_expected(scan_id);
    check_expected(scan_time);
    check_expected(hostname);
    check_expected(architecture);
    check_expected(os_name);
    check_expected(os_version);
    check_expected(os_codename);
    check_expected(os_major);
    check_expected(os_minor);
    check_expected(os_build);
    check_expected(os_platform);
    check_expected(sysname);
    check_expected(release);
    check_expected(version);
    check_expected(os_release);
    return mock();
}

int __wrap_wdb_netinfo_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * name, const char * adapter, const char * type, const char * _state, int mtu, const char * mac, long tx_packets, long rx_packets, long tx_bytes, long rx_bytes, long tx_errors, long rx_errors, long tx_dropped, long rx_dropped)
{
    check_expected(scan_id);
    check_expected(scan_time);
    check_expected(name);
    check_expected(adapter);
    check_expected(type);
    check_expected(_state);
    check_expected(mtu);
    check_expected(mac);
    check_expected(tx_packets);
    check_expected(rx_packets);
    check_expected(tx_bytes);
    check_expected(rx_bytes);
    check_expected(tx_errors);
    check_expected(rx_errors);
    check_expected(tx_dropped);
    check_expected(rx_dropped);
    return mock();
}

int __wrap_wdb_netproto_save(wdb_t * wdb, const char * scan_id, const char * iface, int type, const char * gateway, const char * dhcp, int metric)
{
    check_expected(scan_id);
    check_expected(iface);
    check_expected(type);
    check_expected(gateway);
    check_expected(dhcp);
    check_expected(metric);
    return mock();
}

int __wrap_wdb_netaddr_save(wdb_t * wdb, const char * scan_id, const char * iface, int proto, const char * address, const char * netmask, const char * broadcast)
{
    check_expected(scan_id);
    check_expected(iface);
    check_expected(proto);
    check_expected(address);
    check_expected(netmask);
    check_expected(broadcast);
    return mock();
}

int __wrap_wdb_netinfo_delete2(wdb_t * wdb, const char * name)
{
    check_expected(name);
    return mock();
}

int __wrap_wdb_package_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * format, const char * name, const char * priority, const char * section, long size, const char * vendor, const char * install_time, const char * version, const char * architecture, const char * multiarch, const char * source, const char * description, const char * location)
{
    check_expected(scan_id);
    check_expected(scan_time);
    check_expected(format);
    check_expected(name);
    check_expected(priority);
    check_expected(section);
    check_expected(size);
    check_expected(vendor);
    check_expected(install_time);
    check_expected(version);
    check_expected(architecture);
    check_expected(multiarch);
    check_expected(source);
    check_expected(description);
    check_expected(location);
    return mock();
}

int __wrap_wdb_package_delete2(wdb_t * wdb, const char * name, const char * version, const char * architecture)
{
    check_expected(name);
    check_expected(version);
    check_expected(architecture);
    return mock();
}

int __wrap_wdb_hotfix_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char *hotfix)
{
    check_expected(scan_id);
    check_expected(scan_time);
    check_expected(hotfix);
    return mock();
}

void __wrap_wdb_set_hotfix_metadata()
{
    return;
}

int __wrap_wdb_hotfix_delete2(wdb_t * wdb, const char * hotfix)
{
    check_expected(hotfix);
    return mock();
}

static int init_wdb_object(void **state)
{
    wdb_t * wdb = NULL;
    os_calloc(1, sizeof(wdb_t), wdb);
    w_mutex_init(&wdb->mutex, NULL);
    wdb->agent_id = strdup("000");

    *state = wdb;

    return 0;
}

static int delete_wdb_object(void **state)
{
    wdb_t * wdb = *state;

    free(wdb->agent_id);
    w_mutex_destroy(&wdb->mutex);
    free(wdb);

    return 0;
}

void test_inventory_hardware_save(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"added\","
                     "\"timestamp\":\"12345\","
                     "\"attributes\":{\"board_serial\":\"1234567890\","
                                     "\"cpu_name\":\"processor123\","
                                     "\"cpu_cores\":4,"
                                     "\"cpu_MHz\":2.5,"
                                     "\"ram_total\":22222,"
                                     "\"ram_free\":1000,"
                                     "\"ram_usage\":55}}";

    expect_string(__wrap_wdb_hardware_save, scan_id, "1");
    expect_string(__wrap_wdb_hardware_save, scan_time, "12345");
    expect_string(__wrap_wdb_hardware_save, serial, "1234567890");
    expect_string(__wrap_wdb_hardware_save, cpu_name, "processor123");
    expect_value(__wrap_wdb_hardware_save, cpu_cores, 4);
    expect_string(__wrap_wdb_hardware_save, cpu_mhz, "2.5");
    expect_value(__wrap_wdb_hardware_save, ram_total, 22222);
    expect_value(__wrap_wdb_hardware_save, ram_free, 1000);
    expect_value(__wrap_wdb_hardware_save, ram_usage, 55);
    will_return(__wrap_wdb_hardware_save, 0);

    int ret = wdb_inventory_save_hw(*state, payload);

    assert_int_equal(ret, 0);
}

void test_inventory_hardware_save_error(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"added\","
                     "\"timestamp\":\"12345\","
                     "\"attributes\":{\"board_serial\":\"1234567890\","
                                     "\"cpu_name\":\"processor123\","
                                     "\"cpu_cores\":4,"
                                     "\"cpu_MHz\":2.5,"
                                     "\"ram_total\":22222,"
                                     "\"ram_free\":1000,"
                                     "\"ram_usage\":55}}";

    expect_string(__wrap_wdb_hardware_save, scan_id, "1");
    expect_string(__wrap_wdb_hardware_save, scan_time, "12345");
    expect_string(__wrap_wdb_hardware_save, serial, "1234567890");
    expect_string(__wrap_wdb_hardware_save, cpu_name, "processor123");
    expect_value(__wrap_wdb_hardware_save, cpu_cores, 4);
    expect_string(__wrap_wdb_hardware_save, cpu_mhz, "2.5");
    expect_value(__wrap_wdb_hardware_save, ram_total, 22222);
    expect_value(__wrap_wdb_hardware_save, ram_free, 1000);
    expect_value(__wrap_wdb_hardware_save, ram_usage, 55);
    will_return(__wrap_wdb_hardware_save, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save HW information.");

    int ret = wdb_inventory_save_hw(*state, payload);

    assert_int_equal(ret, -1);
}

void test_inventory_hardware_save_invalid_input(void **state)
{
    (void) state;

    char *payload1 = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: '(null)'");

    int ret = wdb_inventory_save_hw(*state, payload1);

    assert_int_equal(ret, -1);

    char *payload2 = "abcdef";

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: 'abcdef'");

    ret = wdb_inventory_save_hw(*state, payload2);

    assert_int_equal(ret, -1);

    char *payload3 = "{\"type\":\"added\","
                     "\"attributes\":{\"board_serial\":\"1234567890\","
                                     "\"cpu_name\":\"processor123\","
                                     "\"cpu_cores\":4,"
                                     "\"cpu_MHz\":2.5,"
                                     "\"ram_total\":22222,"
                                     "\"ram_free\":1000,"
                                     "\"ram_usage\":55}}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) HW save request with no timestamp path argument.");

    ret = wdb_inventory_save_hw(*state, payload3);

    assert_int_equal(ret, -1);

    char *payload4 = "{\"type\":\"added\","
                     "\"timestamp\":\"12345\"}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) HW save request with no attributes argument.");

    ret = wdb_inventory_save_hw(*state, payload4);

    assert_int_equal(ret, -1);
}

void test_inventory_os_save(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"added\","
                     "\"timestamp\":\"23456\","
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
                                     "\"os_release\":\"x23\"}}";

    expect_string(__wrap_wdb_osinfo_save, scan_id, "1");
    expect_string(__wrap_wdb_osinfo_save, scan_time, "23456");
    expect_string(__wrap_wdb_osinfo_save, hostname, "wazuh");
    expect_string(__wrap_wdb_osinfo_save, architecture, "x86_64");
    expect_string(__wrap_wdb_osinfo_save, os_name, "Ubuntu");
    expect_string(__wrap_wdb_osinfo_save, os_version, "Desktop");
    expect_string(__wrap_wdb_osinfo_save, os_codename, "UU");
    expect_string(__wrap_wdb_osinfo_save, os_major, "18");
    expect_string(__wrap_wdb_osinfo_save, os_minor, "4");
    expect_string(__wrap_wdb_osinfo_save, os_build, "1515");
    expect_string(__wrap_wdb_osinfo_save, os_platform, "Linux");
    expect_string(__wrap_wdb_osinfo_save, sysname, "UbuntuOS");
    expect_string(__wrap_wdb_osinfo_save, release, "1.5");
    expect_string(__wrap_wdb_osinfo_save, version, "5");
    expect_string(__wrap_wdb_osinfo_save, os_release, "x23");
    will_return(__wrap_wdb_osinfo_save, 0);

    int ret = wdb_inventory_save_os(*state, payload);

    assert_int_equal(ret, 0);
}

void test_inventory_os_save_error(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"added\","
                     "\"timestamp\":\"23456\","
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
                                     "\"os_release\":\"x23\"}}";

    expect_string(__wrap_wdb_osinfo_save, scan_id, "1");
    expect_string(__wrap_wdb_osinfo_save, scan_time, "23456");
    expect_string(__wrap_wdb_osinfo_save, hostname, "wazuh");
    expect_string(__wrap_wdb_osinfo_save, architecture, "x86_64");
    expect_string(__wrap_wdb_osinfo_save, os_name, "Ubuntu");
    expect_string(__wrap_wdb_osinfo_save, os_version, "Desktop");
    expect_string(__wrap_wdb_osinfo_save, os_codename, "UU");
    expect_string(__wrap_wdb_osinfo_save, os_major, "18");
    expect_string(__wrap_wdb_osinfo_save, os_minor, "4");
    expect_string(__wrap_wdb_osinfo_save, os_build, "1515");
    expect_string(__wrap_wdb_osinfo_save, os_platform, "Linux");
    expect_string(__wrap_wdb_osinfo_save, sysname, "UbuntuOS");
    expect_string(__wrap_wdb_osinfo_save, release, "1.5");
    expect_string(__wrap_wdb_osinfo_save, version, "5");
    expect_string(__wrap_wdb_osinfo_save, os_release, "x23");
    will_return(__wrap_wdb_osinfo_save, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save OS information.");

    int ret = wdb_inventory_save_os(*state, payload);

    assert_int_equal(ret, -1);
}

void test_inventory_os_save_invalid_input(void **state)
{
    (void) state;

    char *payload1 = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: '(null)'");

    int ret = wdb_inventory_save_os(*state, payload1);

    assert_int_equal(ret, -1);

    char *payload2 = "abcdef";

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: 'abcdef'");

    ret = wdb_inventory_save_os(*state, payload2);

    assert_int_equal(ret, -1);

    char *payload3 = "{\"type\":\"added\","
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
                                     "\"os_release\":\"x23\"}}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) OS save request with no timestamp path argument.");

    ret = wdb_inventory_save_os(*state, payload3);

    assert_int_equal(ret, -1);

    char *payload4 = "{\"type\":\"added\","
                     "\"timestamp\":\"12345\"}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) OS save request with no attributes argument.");

    ret = wdb_inventory_save_os(*state, payload4);

    assert_int_equal(ret, -1);
}

void test_inventory_network_save(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"added\","
                     "\"timestamp\":\"34567\","
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
                                             "\"DHCP\":\"false\"}}}";

    expect_string(__wrap_wdb_netinfo_save, scan_id, "1");
    expect_string(__wrap_wdb_netinfo_save, scan_time, "34567");
    expect_string(__wrap_wdb_netinfo_save, name, "ensp0");
    expect_string(__wrap_wdb_netinfo_save, adapter, "eth");
    expect_string(__wrap_wdb_netinfo_save, type, "2");
    expect_string(__wrap_wdb_netinfo_save, _state, "up");
    expect_value(__wrap_wdb_netinfo_save, mtu, 1500);
    expect_string(__wrap_wdb_netinfo_save, mac, "fa-48-e4-80");
    expect_value(__wrap_wdb_netinfo_save, tx_packets, 1000);
    expect_value(__wrap_wdb_netinfo_save, rx_packets, 990);
    expect_value(__wrap_wdb_netinfo_save, tx_bytes, 800);
    expect_value(__wrap_wdb_netinfo_save, rx_bytes, 750);
    expect_value(__wrap_wdb_netinfo_save, tx_errors, 2);
    expect_value(__wrap_wdb_netinfo_save, rx_errors, 5);
    expect_value(__wrap_wdb_netinfo_save, tx_dropped, 23);
    expect_value(__wrap_wdb_netinfo_save, rx_dropped, 12);
    will_return(__wrap_wdb_netinfo_save, 0);

    expect_string(__wrap_wdb_netproto_save, scan_id, "1");
    expect_string(__wrap_wdb_netproto_save, iface, "ensp0");
    expect_value(__wrap_wdb_netproto_save, type, 0);
    expect_string(__wrap_wdb_netproto_save, gateway, "10.0.0.1");
    expect_string(__wrap_wdb_netproto_save, dhcp, "true");
    expect_value(__wrap_wdb_netproto_save, metric, 500);
    will_return(__wrap_wdb_netproto_save, 0);

    expect_string(__wrap_wdb_netaddr_save, scan_id, "1");
    expect_string(__wrap_wdb_netaddr_save, iface, "ensp0");
    expect_value(__wrap_wdb_netaddr_save, proto, 0);
    expect_string(__wrap_wdb_netaddr_save, address, "10.0.0.2");
    expect_string(__wrap_wdb_netaddr_save, netmask, "255.0.0.0");
    expect_string(__wrap_wdb_netaddr_save, broadcast, "10.255.255.255");
    will_return(__wrap_wdb_netaddr_save, 0);

    expect_string(__wrap_wdb_netproto_save, scan_id, "1");
    expect_string(__wrap_wdb_netproto_save, iface, "ensp0");
    expect_value(__wrap_wdb_netproto_save, type, 1);
    expect_string(__wrap_wdb_netproto_save, gateway, "ff10::1");
    expect_string(__wrap_wdb_netproto_save, dhcp, "false");
    expect_value(__wrap_wdb_netproto_save, metric, 10);
    will_return(__wrap_wdb_netproto_save, 0);

    expect_string(__wrap_wdb_netaddr_save, scan_id, "1");
    expect_string(__wrap_wdb_netaddr_save, iface, "ensp0");
    expect_value(__wrap_wdb_netaddr_save, proto, 1);
    expect_string(__wrap_wdb_netaddr_save, address, "f800::1");
    expect_string(__wrap_wdb_netaddr_save, netmask, "ffff::1");
    expect_string(__wrap_wdb_netaddr_save, broadcast, "ff20::1");
    will_return(__wrap_wdb_netaddr_save, 0);

    int ret = wdb_inventory_save_network(*state, payload);

    assert_int_equal(ret, 0);
}

void test_inventory_network_save_error(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"added\","
                     "\"timestamp\":\"34567\","
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
                                             "\"DHCP\":\"false\"}}}";

    expect_string(__wrap_wdb_netinfo_save, scan_id, "1");
    expect_string(__wrap_wdb_netinfo_save, scan_time, "34567");
    expect_string(__wrap_wdb_netinfo_save, name, "ensp0");
    expect_string(__wrap_wdb_netinfo_save, adapter, "eth");
    expect_string(__wrap_wdb_netinfo_save, type, "2");
    expect_string(__wrap_wdb_netinfo_save, _state, "up");
    expect_value(__wrap_wdb_netinfo_save, mtu, 1500);
    expect_string(__wrap_wdb_netinfo_save, mac, "fa-48-e4-80");
    expect_value(__wrap_wdb_netinfo_save, tx_packets, 1000);
    expect_value(__wrap_wdb_netinfo_save, rx_packets, 990);
    expect_value(__wrap_wdb_netinfo_save, tx_bytes, 800);
    expect_value(__wrap_wdb_netinfo_save, rx_bytes, 750);
    expect_value(__wrap_wdb_netinfo_save, tx_errors, 2);
    expect_value(__wrap_wdb_netinfo_save, rx_errors, 5);
    expect_value(__wrap_wdb_netinfo_save, tx_dropped, 23);
    expect_value(__wrap_wdb_netinfo_save, rx_dropped, 12);
    will_return(__wrap_wdb_netinfo_save, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save netinfo information.");

    int ret = wdb_inventory_save_network(*state, payload);

    assert_int_equal(ret, -1);

    expect_string(__wrap_wdb_netinfo_save, scan_id, "1");
    expect_string(__wrap_wdb_netinfo_save, scan_time, "34567");
    expect_string(__wrap_wdb_netinfo_save, name, "ensp0");
    expect_string(__wrap_wdb_netinfo_save, adapter, "eth");
    expect_string(__wrap_wdb_netinfo_save, type, "2");
    expect_string(__wrap_wdb_netinfo_save, _state, "up");
    expect_value(__wrap_wdb_netinfo_save, mtu, 1500);
    expect_string(__wrap_wdb_netinfo_save, mac, "fa-48-e4-80");
    expect_value(__wrap_wdb_netinfo_save, tx_packets, 1000);
    expect_value(__wrap_wdb_netinfo_save, rx_packets, 990);
    expect_value(__wrap_wdb_netinfo_save, tx_bytes, 800);
    expect_value(__wrap_wdb_netinfo_save, rx_bytes, 750);
    expect_value(__wrap_wdb_netinfo_save, tx_errors, 2);
    expect_value(__wrap_wdb_netinfo_save, rx_errors, 5);
    expect_value(__wrap_wdb_netinfo_save, tx_dropped, 23);
    expect_value(__wrap_wdb_netinfo_save, rx_dropped, 12);
    will_return(__wrap_wdb_netinfo_save, 0);

    expect_string(__wrap_wdb_netproto_save, scan_id, "1");
    expect_string(__wrap_wdb_netproto_save, iface, "ensp0");
    expect_value(__wrap_wdb_netproto_save, type, 0);
    expect_string(__wrap_wdb_netproto_save, gateway, "10.0.0.1");
    expect_string(__wrap_wdb_netproto_save, dhcp, "true");
    expect_value(__wrap_wdb_netproto_save, metric, 500);
    will_return(__wrap_wdb_netproto_save, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save netproto information.");

    expect_string(__wrap_wdb_netproto_save, scan_id, "1");
    expect_string(__wrap_wdb_netproto_save, iface, "ensp0");
    expect_value(__wrap_wdb_netproto_save, type, 1);
    expect_string(__wrap_wdb_netproto_save, gateway, "ff10::1");
    expect_string(__wrap_wdb_netproto_save, dhcp, "false");
    expect_value(__wrap_wdb_netproto_save, metric, 10);
    will_return(__wrap_wdb_netproto_save, 0);

    expect_string(__wrap_wdb_netaddr_save, scan_id, "1");
    expect_string(__wrap_wdb_netaddr_save, iface, "ensp0");
    expect_value(__wrap_wdb_netaddr_save, proto, 1);
    expect_string(__wrap_wdb_netaddr_save, address, "f800::1");
    expect_string(__wrap_wdb_netaddr_save, netmask, "ffff::1");
    expect_string(__wrap_wdb_netaddr_save, broadcast, "ff20::1");
    will_return(__wrap_wdb_netaddr_save, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save netaddr information.");

    ret = wdb_inventory_save_network(*state, payload);

    assert_int_equal(ret, -1);
}

void test_inventory_network_save_invalid_input(void **state)
{
    (void) state;

    char *payload1 = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: '(null)'");

    int ret = wdb_inventory_save_network(*state, payload1);

    assert_int_equal(ret, -1);

    char *payload2 = "abcdef";

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: 'abcdef'");

    ret = wdb_inventory_save_network(*state, payload2);

    assert_int_equal(ret, -1);

    char *payload3 = "{\"type\":\"added\","
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
                                              "\"DHCP\":\"false\"}}}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) network save request with no timestamp path argument.");

    ret = wdb_inventory_save_network(*state, payload3);

    assert_int_equal(ret, -1);

    char *payload4 = "{\"type\":\"added\","
                     "\"timestamp\":\"12345\"}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) network save request with no attributes argument.");

    ret = wdb_inventory_save_network(*state, payload4);

    assert_int_equal(ret, -1);
}

void test_inventory_network_delete(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"deleted\","
                     "\"timestamp\":\"34567\","
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
                                             "\"DHCP\":\"false\"}}}";

    expect_string(__wrap_wdb_netinfo_delete2, name, "ensp0");
    will_return(__wrap_wdb_netinfo_delete2, 0);

    int ret = wdb_inventory_delete_network(*state, payload);

    assert_int_equal(ret, 0);
}

void test_inventory_network_delete_error(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"deleted\","
                     "\"timestamp\":\"34567\","
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
                                             "\"DHCP\":\"false\"}}}";

    expect_string(__wrap_wdb_netinfo_delete2, name, "ensp0");
    will_return(__wrap_wdb_netinfo_delete2, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot delete old network entry.");

    int ret = wdb_inventory_delete_network(*state, payload);

    assert_int_equal(ret, -1);
}

void test_inventory_network_delete_invalid_input(void **state)
{
    (void) state;

    char *payload1 = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: '(null)'");

    int ret = wdb_inventory_delete_network(*state, payload1);

    assert_int_equal(ret, -1);

    char *payload2 = "abcdef";

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: 'abcdef'");

    ret = wdb_inventory_delete_network(*state, payload2);

    assert_int_equal(ret, -1);

    char *payload3 = "{\"type\":\"deleted\","
                     "\"timestamp\":\"12345\"}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) network delete request with no attributes argument.");

    ret = wdb_inventory_delete_network(*state, payload3);

    assert_int_equal(ret, -1);
}

void test_inventory_program_save(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"added\","
                     "\"timestamp\":\"45678\","
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
                                     "\"location\":\"/var/bin\"}}";

    expect_string(__wrap_wdb_package_save, scan_id, "1");
    expect_string(__wrap_wdb_package_save, scan_time, "45678");
    expect_string(__wrap_wdb_package_save, format, "pkg");
    expect_string(__wrap_wdb_package_save, name, "Wazuh");
    expect_string(__wrap_wdb_package_save, priority, "high");
    expect_string(__wrap_wdb_package_save, section, "000");
    expect_value(__wrap_wdb_package_save, size, 15000);
    expect_string(__wrap_wdb_package_save, vendor, "Wazuh Inc");
    expect_string(__wrap_wdb_package_save, install_time, "123456789");
    expect_string(__wrap_wdb_package_save, version, "3.12");
    expect_string(__wrap_wdb_package_save, architecture, "x64");
    expect_string(__wrap_wdb_package_save, multiarch, "x64_86");
    expect_string(__wrap_wdb_package_save, source, "C");
    expect_string(__wrap_wdb_package_save, description, "Wazuh agent package");
    expect_string(__wrap_wdb_package_save, location, "/var/bin");
    will_return(__wrap_wdb_package_save, 0);

    int ret = wdb_inventory_save_program(*state, payload);

    assert_int_equal(ret, 0);
}

void test_inventory_program_save_error(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"added\","
                     "\"timestamp\":\"45678\","
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
                                     "\"location\":\"/var/bin\"}}";

    expect_string(__wrap_wdb_package_save, scan_id, "1");
    expect_string(__wrap_wdb_package_save, scan_time, "45678");
    expect_string(__wrap_wdb_package_save, format, "pkg");
    expect_string(__wrap_wdb_package_save, name, "Wazuh");
    expect_string(__wrap_wdb_package_save, priority, "high");
    expect_string(__wrap_wdb_package_save, section, "000");
    expect_value(__wrap_wdb_package_save, size, 15000);
    expect_string(__wrap_wdb_package_save, vendor, "Wazuh Inc");
    expect_string(__wrap_wdb_package_save, install_time, "123456789");
    expect_string(__wrap_wdb_package_save, version, "3.12");
    expect_string(__wrap_wdb_package_save, architecture, "x64");
    expect_string(__wrap_wdb_package_save, multiarch, "x64_86");
    expect_string(__wrap_wdb_package_save, source, "C");
    expect_string(__wrap_wdb_package_save, description, "Wazuh agent package");
    expect_string(__wrap_wdb_package_save, location, "/var/bin");
    will_return(__wrap_wdb_package_save, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save Package information.");

    int ret = wdb_inventory_save_program(*state, payload);

    assert_int_equal(ret, -1);
}

void test_inventory_program_save_invalid_input(void **state)
{
    (void) state;

    char *payload1 = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: '(null)'");

    int ret = wdb_inventory_save_program(*state, payload1);

    assert_int_equal(ret, -1);

    char *payload2 = "abcdef";

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: 'abcdef'");

    ret = wdb_inventory_save_program(*state, payload2);

    assert_int_equal(ret, -1);

    char *payload3 = "{\"type\":\"added\","
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
                                     "\"location\":\"/var/bin\"}}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) program save request with no timestamp path argument.");

    ret = wdb_inventory_save_program(*state, payload3);

    assert_int_equal(ret, -1);

    char *payload4 = "{\"type\":\"added\","
                     "\"timestamp\":\"12345\"}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) program save request with no attributes argument.");

    ret = wdb_inventory_save_program(*state, payload4);

    assert_int_equal(ret, -1);
}

void test_inventory_program_delete(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"deleted\","
                     "\"timestamp\":\"45678\","
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
                                     "\"location\":\"/var/bin\"}}";

    expect_string(__wrap_wdb_package_delete2, name, "Wazuh");
    expect_string(__wrap_wdb_package_delete2, version, "3.12");
    expect_string(__wrap_wdb_package_delete2, architecture, "x64");
    will_return(__wrap_wdb_package_delete2, 0);

    int ret = wdb_inventory_delete_program(*state, payload);

    assert_int_equal(ret, 0);
}

void test_inventory_program_delete_error(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"deleted\","
                     "\"timestamp\":\"45678\","
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
                                     "\"location\":\"/var/bin\"}}";

    expect_string(__wrap_wdb_package_delete2, name, "Wazuh");
    expect_string(__wrap_wdb_package_delete2, version, "3.12");
    expect_string(__wrap_wdb_package_delete2, architecture, "x64");
    will_return(__wrap_wdb_package_delete2, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot delete old Package information.");

    int ret = wdb_inventory_delete_program(*state, payload);

    assert_int_equal(ret, -1);
}

void test_inventory_program_delete_invalid_input(void **state)
{
    (void) state;

    char *payload1 = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: '(null)'");

    int ret = wdb_inventory_delete_program(*state, payload1);

    assert_int_equal(ret, -1);

    char *payload2 = "abcdef";

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: 'abcdef'");

    ret = wdb_inventory_delete_program(*state, payload2);

    assert_int_equal(ret, -1);

    char *payload3 = "{\"type\":\"deleted\","
                     "\"timestamp\":\"12345\"}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) program delete request with no attributes argument.");

    ret = wdb_inventory_delete_program(*state, payload3);

    assert_int_equal(ret, -1);
}

void test_inventory_hotfix_save(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"added\","
                     "\"timestamp\":\"56789\","
                     "\"attributes\":{\"hotfix\":\"KB12345\"}}";

    expect_string(__wrap_wdb_hotfix_save, scan_id, "1");
    expect_string(__wrap_wdb_hotfix_save, scan_time, "56789");
    expect_string(__wrap_wdb_hotfix_save, hotfix, "KB12345");
    will_return(__wrap_wdb_hotfix_save, 0);

    int ret = wdb_inventory_save_hotfix(*state, payload);

    assert_int_equal(ret, 0);
}

void test_inventory_hotfix_save_error(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"added\","
                     "\"timestamp\":\"56789\","
                     "\"attributes\":{\"hotfix\":\"KB12345\"}}";

    expect_string(__wrap_wdb_hotfix_save, scan_id, "1");
    expect_string(__wrap_wdb_hotfix_save, scan_time, "56789");
    expect_string(__wrap_wdb_hotfix_save, hotfix, "KB12345");
    will_return(__wrap_wdb_hotfix_save, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save Hotfix information.");

    int ret = wdb_inventory_save_hotfix(*state, payload);

    assert_int_equal(ret, -1);
}

void test_inventory_hotfix_save_invalid_input(void **state)
{
    (void) state;

    char *payload1 = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: '(null)'");

    int ret = wdb_inventory_save_hotfix(*state, payload1);

    assert_int_equal(ret, -1);

    char *payload2 = "abcdef";

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: 'abcdef'");

    ret = wdb_inventory_save_hotfix(*state, payload2);

    assert_int_equal(ret, -1);

    char *payload3 = "{\"type\":\"added\","
                     "\"attributes\":{\"hotfix\":\"KB12345\"}}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) hotfix save request with no timestamp path argument.");

    ret = wdb_inventory_save_hotfix(*state, payload3);

    assert_int_equal(ret, -1);

    char *payload4 = "{\"type\":\"added\","
                     "\"timestamp\":\"12345\"}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) hotfix save request with no attributes argument.");

    ret = wdb_inventory_save_hotfix(*state, payload4);

    assert_int_equal(ret, -1);
}

void test_inventory_hotfix_delete(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"deleted\","
                     "\"timestamp\":\"56789\","
                     "\"attributes\":{\"hotfix\":\"KB12345\"}}";

    expect_string(__wrap_wdb_hotfix_delete2, hotfix, "KB12345");
    will_return(__wrap_wdb_hotfix_delete2, 0);

    int ret = wdb_inventory_delete_hotfix(*state, payload);

    assert_int_equal(ret, 0);
}

void test_inventory_hotfix_delete_error(void **state)
{
    (void) state;

    char *payload = "{\"type\":\"deleted\","
                     "\"timestamp\":\"56789\","
                     "\"attributes\":{\"hotfix\":\"KB12345\"}}";

    expect_string(__wrap_wdb_hotfix_delete2, hotfix, "KB12345");
    will_return(__wrap_wdb_hotfix_delete2, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot delete old Hotfix information.");

    int ret = wdb_inventory_delete_hotfix(*state, payload);

    assert_int_equal(ret, -1);
}

void test_inventory_hotfix_delete_invalid_input(void **state)
{
    (void) state;

    char *payload1 = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: '(null)'");

    int ret = wdb_inventory_delete_hotfix(*state, payload1);

    assert_int_equal(ret, -1);

    char *payload2 = "abcdef";

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse inventory payload: 'abcdef'");

    ret = wdb_inventory_delete_hotfix(*state, payload2);

    assert_int_equal(ret, -1);

    char *payload3 = "{\"type\":\"deleted\","
                     "\"timestamp\":\"12345\"}";

    expect_string(__wrap__merror, formatted_msg, "DB(000) hotfix delete request with no attributes argument.");

    ret = wdb_inventory_delete_hotfix(*state, payload3);

    assert_int_equal(ret, -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_inventory_hardware_save),
        cmocka_unit_test(test_inventory_hardware_save_error),
        cmocka_unit_test(test_inventory_hardware_save_invalid_input),
        cmocka_unit_test(test_inventory_os_save),
        cmocka_unit_test(test_inventory_os_save_error),
        cmocka_unit_test(test_inventory_os_save_invalid_input),
        cmocka_unit_test(test_inventory_network_save),
        cmocka_unit_test(test_inventory_network_save_error),
        cmocka_unit_test(test_inventory_network_save_invalid_input),
        cmocka_unit_test(test_inventory_network_delete),
        cmocka_unit_test(test_inventory_network_delete_error),
        cmocka_unit_test(test_inventory_network_delete_invalid_input),
        cmocka_unit_test(test_inventory_program_save),
        cmocka_unit_test(test_inventory_program_save_error),
        cmocka_unit_test(test_inventory_program_save_invalid_input),
        cmocka_unit_test(test_inventory_program_delete),
        cmocka_unit_test(test_inventory_program_delete_error),
        cmocka_unit_test(test_inventory_program_delete_invalid_input),
        cmocka_unit_test(test_inventory_hotfix_save),
        cmocka_unit_test(test_inventory_hotfix_save_error),
        cmocka_unit_test(test_inventory_hotfix_save_invalid_input),
        cmocka_unit_test(test_inventory_hotfix_delete),
        cmocka_unit_test(test_inventory_hotfix_delete_error),
        cmocka_unit_test(test_inventory_hotfix_delete_invalid_input)
    };
    return cmocka_run_group_tests(tests, init_wdb_object, delete_wdb_object);
}
