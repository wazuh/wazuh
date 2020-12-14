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

#include "../analysisd/decoders/decoder.h"
#include "../analysisd/eventinfo.h"

int DecodeSyscollector(Eventinfo *lf, int *socket);
void w_free_event_info(Eventinfo *lf);

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

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_fillData()
{
    return 0;
}

int __wrap_OS_ConnectUnixDomain(const char *path, int type, int max_msg_size) {
    check_expected(path);
    check_expected(type);
    check_expected(max_msg_size);

    return mock();
}

int __wrap_OS_SendSecureTCP(int sock, uint32_t size, const void * msg) {
    check_expected(sock);
    check_expected(size);
    check_expected(msg);

    return mock();
}

int __wrap_OS_RecvSecureTCP(int sock, char * ret, uint32_t size) {
    check_expected(sock);
    check_expected(size);

    snprintf(ret, size, "%s", mock_type(char*));

    return mock();
}

Eventinfo * get_event_info(char *log, char *agent_id, char *location)
{
    Eventinfo *info = NULL;

    os_calloc(1, sizeof(Eventinfo), info);
    Zero_Eventinfo(info);
    info->agent_id = strdup(agent_id);
    info->location = strdup(location);
    info->log = strdup(log);

    return info;
}

void test_decode_syscollector_invalid_location(void **state)
{
    (void) state;

    char * message = "{}";

    Eventinfo *info = get_event_info(message, "000", "sys-collector");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid received event. (Location)");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_parse_error(void **state)
{
    (void) state;

    char * message = "abcdef";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "Error parsing JSON event.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_no_type(void **state)
{
    (void) state;

    char * message = "{}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid message. Type not found.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_invalid_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"registry\","
                      "\"data\":{}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid message type: registry.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hardware_no_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hardware\","
                      "\"data\":{}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "No member 'type' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hardware information to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hardware_invalid_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hardware\","
                      "\"data\":{\"type\":\"restored\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid 'type' value 'restored' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hardware information to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hardware_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hardware\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hardware save {\"type\":\"added\"}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 1);

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_hardware_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hardware\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hardware save {\"type\":\"added\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_hardware_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hardware\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hardware save {\"type\":\"added\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hardware information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hardware_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hardware\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hardware save {\"type\":\"added\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hardware information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hardware_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hardware\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hardware save {\"type\":\"added\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hardware information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_os_no_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"OS\","
                      "\"data\":{}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "No member 'type' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send osinfo message to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_os_invalid_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"OS\","
                      "\"data\":{\"type\":\"updated\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid 'type' value 'updated' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send osinfo message to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_os_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"OS\","
                      "\"data\":{\"type\":\"modified\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory OS save {\"type\":\"modified\"}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 2);

    expect_value(__wrap_OS_SendSecureTCP, sock, 2);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 2);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_os_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"OS\","
                      "\"data\":{\"type\":\"modified\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory OS save {\"type\":\"modified\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_os_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"OS\","
                      "\"data\":{\"type\":\"modified\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory OS save {\"type\":\"modified\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send osinfo message to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_os_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"OS\","
                      "\"data\":{\"type\":\"modified\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory OS save {\"type\":\"modified\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send osinfo message to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_os_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"OS\","
                      "\"data\":{\"type\":\"modified\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory OS save {\"type\":\"modified\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send osinfo message to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_network_no_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"network\","
                      "\"data\":{}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "No member 'type' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_network_invalid_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"network\","
                      "\"data\":{\"type\":\"removed\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid 'type' value 'removed' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_network_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"network\","
                      "\"data\":{\"type\":\"deleted\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory network delete {\"type\":\"deleted\"}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 3);

    expect_value(__wrap_OS_SendSecureTCP, sock, 3);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 3);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_network_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"network\","
                      "\"data\":{\"type\":\"deleted\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory network delete {\"type\":\"deleted\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_network_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"network\","
                      "\"data\":{\"type\":\"deleted\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory network delete {\"type\":\"deleted\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_network_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"network\","
                      "\"data\":{\"type\":\"deleted\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory network delete {\"type\":\"deleted\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_network_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"network\","
                      "\"data\":{\"type\":\"deleted\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory network delete {\"type\":\"deleted\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_program_no_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"program\","
                      "\"data\":{}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "No member 'type' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send packages information to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_program_invalid_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"program\","
                      "\"data\":{\"type\":\"installed\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid 'type' value 'installed' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send packages information to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_program_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"program\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory program save {\"type\":\"added\"}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 4);

    expect_value(__wrap_OS_SendSecureTCP, sock, 4);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 4);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_program_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"program\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory program save {\"type\":\"added\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_program_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"program\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory program save {\"type\":\"added\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send packages information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_program_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"program\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory program save {\"type\":\"added\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send packages information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_program_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"program\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory program save {\"type\":\"added\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send packages information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hotfix_no_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hotfix\","
                      "\"data\":{}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "No member 'type' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfixes information to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hotfix_invalid_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hotfix\","
                      "\"data\":{\"type\":\"upgrade\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid 'type' value 'upgrade' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfixes information to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hotfix_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hotfix\","
                      "\"data\":{\"type\":\"modified\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hotfix save {\"type\":\"modified\"}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 5);

    expect_value(__wrap_OS_SendSecureTCP, sock, 5);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 5);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_hotfix_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hotfix\","
                      "\"data\":{\"type\":\"modified\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hotfix save {\"type\":\"modified\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_hotfix_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hotfix\","
                      "\"data\":{\"type\":\"modified\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hotfix save {\"type\":\"modified\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfixes information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hotfix_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hotfix\","
                      "\"data\":{\"type\":\"modified\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hotfix save {\"type\":\"modified\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfixes information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hotfix_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hotfix\","
                      "\"data\":{\"type\":\"modified\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hotfix save {\"type\":\"modified\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfixes information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_port_no_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"port\","
                      "\"data\":{}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "No member 'type' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send ports information to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_port_invalid_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"port\","
                      "\"data\":{\"type\":\"closed\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid 'type' value 'closed' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send ports information to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_port_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"port\","
                      "\"data\":{\"type\":\"deleted\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory port delete {\"type\":\"deleted\"}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 6);

    expect_value(__wrap_OS_SendSecureTCP, sock, 6);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 6);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_port_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"port\","
                      "\"data\":{\"type\":\"deleted\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory port delete {\"type\":\"deleted\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_port_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"port\","
                      "\"data\":{\"type\":\"deleted\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory port delete {\"type\":\"deleted\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send ports information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_port_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"port\","
                      "\"data\":{\"type\":\"deleted\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory port delete {\"type\":\"deleted\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send ports information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_port_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"port\","
                      "\"data\":{\"type\":\"deleted\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory port delete {\"type\":\"deleted\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send ports information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_process_no_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"process\","
                      "\"data\":{}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "No member 'type' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send processes information to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_process_invalid_type(void **state)
{
    (void) state;

    char * message = "{\"type\":\"process\","
                      "\"data\":{\"type\":\"started\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid 'type' value 'started' in JSON payload.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send processes information to Wazuh DB.");

    int ret = DecodeSyscollector(info, 0);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_process_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"process\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory process save {\"type\":\"added\"}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 7);

    expect_value(__wrap_OS_SendSecureTCP, sock, 7);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 7);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_process_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"process\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory process save {\"type\":\"added\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_process_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"process\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory process save {\"type\":\"added\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send processes information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_process_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"process\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory process save {\"type\":\"added\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send processes information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_process_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"process\","
                      "\"data\":{\"type\":\"added\"}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory process save {\"type\":\"added\"}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send processes information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hardware_scan_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hardware_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hardware_scan update {\"timestamp\":12345}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 1);

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_hardware_scan_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hardware_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hardware_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_hardware_scan_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hardware_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hardware_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hardware scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hardware_scan_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hardware_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hardware_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hardware scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hardware_scan_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hardware_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hardware_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hardware scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_os_scan_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"OS_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory OS_scan update {\"timestamp\":12345}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 2);

    expect_value(__wrap_OS_SendSecureTCP, sock, 2);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 2);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_os_scan_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"OS_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory OS_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_os_scan_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"OS_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory OS_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send OS scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_os_scan_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"OS_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory OS_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send OS scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_os_scan_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"OS_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory OS_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send OS scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_network_scan_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"network_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory network_scan update {\"timestamp\":12345}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 3);

    expect_value(__wrap_OS_SendSecureTCP, sock, 3);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 3);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_network_scan_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"network_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory network_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_network_scan_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"network_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory network_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send network scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_network_scan_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"network_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory network_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send network scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_network_scan_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"network_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory network_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send network scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_program_scan_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"program_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory program_scan update {\"timestamp\":12345}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 4);

    expect_value(__wrap_OS_SendSecureTCP, sock, 4);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 4);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_program_scan_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"program_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory program_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_program_scan_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"program_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory program_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send program scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_program_scan_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"program_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory program_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send program scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_program_scan_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"program_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory program_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send program scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hotfix_scan_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hotfix_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hotfix_scan update {\"timestamp\":12345}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 5);

    expect_value(__wrap_OS_SendSecureTCP, sock, 5);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 5);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_hotfix_scan_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hotfix_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hotfix_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_hotfix_scan_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hotfix_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hotfix_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfix scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hotfix_scan_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hotfix_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hotfix_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfix scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_hotfix_scan_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"hotfix_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory hotfix_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfix scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_port_scan_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"port_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory port_scan update {\"timestamp\":12345}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 6);

    expect_value(__wrap_OS_SendSecureTCP, sock, 6);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 6);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_port_scan_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"port_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory port_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_port_scan_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"port_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory port_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send port scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_port_scan_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"port_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory port_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send port scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_port_scan_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"port_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory port_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send port scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_process_scan_connect_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"process_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory process_scan update {\"timestamp\":12345}";

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK_PATH);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 7);

    expect_value(__wrap_OS_SendSecureTCP, sock, 7);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 7);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = -1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_process_scan_send_receive(void **state)
{
    (void) state;

    char * message = "{\"type\":\"process_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory process_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 1);

    w_free_event_info(info);
}

void test_decode_syscollector_process_scan_send_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"process_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory process_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send process scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_process_scan_send_receive_response_error(void **state)
{
    (void) state;

    char * message = "{\"type\":\"process_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory process_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "error");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send process scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

void test_decode_syscollector_process_scan_send_receive_no_response(void **state)
{
    (void) state;

    char * message = "{\"type\":\"process_scan\","
                      "\"data\":{\"timestamp\":12345}}";

    Eventinfo *info = get_event_info(message, "000", "syscollector");

    char * wdb_msg = "agent 000 inventory process_scan update {\"timestamp\":12345}";

    expect_value(__wrap_OS_SendSecureTCP, sock, 1);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(wdb_msg) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, wdb_msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 1);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send process scan information to Wazuh DB.");

    int s = 1;
    int ret = DecodeSyscollector(info, &s);

    assert_int_equal(ret, 0);

    w_free_event_info(info);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_decode_syscollector_parse_error),
        cmocka_unit_test(test_decode_syscollector_invalid_location),
        cmocka_unit_test(test_decode_syscollector_no_type),
        cmocka_unit_test(test_decode_syscollector_invalid_type),
        cmocka_unit_test(test_decode_syscollector_hardware_no_type),
        cmocka_unit_test(test_decode_syscollector_hardware_invalid_type),
        cmocka_unit_test(test_decode_syscollector_hardware_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_hardware_send_receive),
        cmocka_unit_test(test_decode_syscollector_hardware_send_error),
        cmocka_unit_test(test_decode_syscollector_hardware_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_hardware_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_os_no_type),
        cmocka_unit_test(test_decode_syscollector_os_invalid_type),
        cmocka_unit_test(test_decode_syscollector_os_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_os_send_receive),
        cmocka_unit_test(test_decode_syscollector_os_send_error),
        cmocka_unit_test(test_decode_syscollector_os_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_os_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_network_no_type),
        cmocka_unit_test(test_decode_syscollector_network_invalid_type),
        cmocka_unit_test(test_decode_syscollector_network_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_network_send_receive),
        cmocka_unit_test(test_decode_syscollector_network_send_error),
        cmocka_unit_test(test_decode_syscollector_network_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_network_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_program_no_type),
        cmocka_unit_test(test_decode_syscollector_program_invalid_type),
        cmocka_unit_test(test_decode_syscollector_program_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_program_send_receive),
        cmocka_unit_test(test_decode_syscollector_program_send_error),
        cmocka_unit_test(test_decode_syscollector_program_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_program_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_hotfix_no_type),
        cmocka_unit_test(test_decode_syscollector_hotfix_invalid_type),
        cmocka_unit_test(test_decode_syscollector_hotfix_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_hotfix_send_receive),
        cmocka_unit_test(test_decode_syscollector_hotfix_send_error),
        cmocka_unit_test(test_decode_syscollector_hotfix_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_hotfix_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_port_no_type),
        cmocka_unit_test(test_decode_syscollector_port_invalid_type),
        cmocka_unit_test(test_decode_syscollector_port_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_port_send_receive),
        cmocka_unit_test(test_decode_syscollector_port_send_error),
        cmocka_unit_test(test_decode_syscollector_port_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_port_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_process_no_type),
        cmocka_unit_test(test_decode_syscollector_process_invalid_type),
        cmocka_unit_test(test_decode_syscollector_process_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_process_send_receive),
        cmocka_unit_test(test_decode_syscollector_process_send_error),
        cmocka_unit_test(test_decode_syscollector_process_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_process_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_hardware_scan_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_hardware_scan_send_receive),
        cmocka_unit_test(test_decode_syscollector_hardware_scan_send_error),
        cmocka_unit_test(test_decode_syscollector_hardware_scan_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_hardware_scan_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_os_scan_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_os_scan_send_receive),
        cmocka_unit_test(test_decode_syscollector_os_scan_send_error),
        cmocka_unit_test(test_decode_syscollector_os_scan_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_os_scan_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_network_scan_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_network_scan_send_receive),
        cmocka_unit_test(test_decode_syscollector_network_scan_send_error),
        cmocka_unit_test(test_decode_syscollector_network_scan_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_network_scan_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_program_scan_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_program_scan_send_receive),
        cmocka_unit_test(test_decode_syscollector_program_scan_send_error),
        cmocka_unit_test(test_decode_syscollector_program_scan_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_program_scan_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_hotfix_scan_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_hotfix_scan_send_receive),
        cmocka_unit_test(test_decode_syscollector_hotfix_scan_send_error),
        cmocka_unit_test(test_decode_syscollector_hotfix_scan_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_hotfix_scan_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_port_scan_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_port_scan_send_receive),
        cmocka_unit_test(test_decode_syscollector_port_scan_send_error),
        cmocka_unit_test(test_decode_syscollector_port_scan_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_port_scan_send_receive_no_response),
        cmocka_unit_test(test_decode_syscollector_process_scan_connect_send_receive),
        cmocka_unit_test(test_decode_syscollector_process_scan_send_receive),
        cmocka_unit_test(test_decode_syscollector_process_scan_send_error),
        cmocka_unit_test(test_decode_syscollector_process_scan_send_receive_response_error),
        cmocka_unit_test(test_decode_syscollector_process_scan_send_receive_no_response)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
