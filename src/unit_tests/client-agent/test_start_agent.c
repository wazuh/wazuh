/*
 * Copyright (C) 2015, Wazuh Inc.
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

#include "../wrappers/common.h"
#include "../wrappers/wazuh/client-agent/start_agent.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "../wrappers/wazuh/monitord/monitord_wrappers.h"

#ifdef TEST_WINAGENT
#include "../wrappers/wazuh/shared/randombytes_wrappers.h"
#endif

#include "../client-agent/agentd.h"

extern void send_msg_on_startup(void);
extern bool agent_handshake_to_server(int server_id, bool is_startup);
extern void send_agent_stopped_message();
extern int _s_verify_counter;

int __wrap_send_msg(const char *msg, ssize_t msg_length) {
    check_expected(msg);
    return 0;
}

#ifndef TEST_WINAGENT
ssize_t __wrap_recv(int __fd, void *__buf, size_t __n, int __flags) {
    char* rcv = (char*)mock_ptr_type(char *);
    int len = strlen(rcv);
    snprintf(__buf, len+1, "%s", rcv);
    return len;
}
#endif

int __wrap_fseek(FILE *__stream, long __off, int __whence) {
    return 0;
}
int __wrap_fprintf(FILE *__restrict__ __stream, const char *__restrict__ __format, ...) {
    return 0;
}
int __wrap_fflush(FILE *__stream) {
    return 0;
}

int __wrap_ReadSecMSG(keystore *keys, char *buffer, char *cleartext, int id, unsigned int buffer_size, size_t *final_size, const char *srcip, char **output) {
    check_expected(buffer);
    *output = (char*)mock_ptr_type(char *);
    return (int)mock();
}

/* Aux */
/* ACK encrypted with id=001, Name=agent0 and key=6958b43cb096e036f872d65d6a4dc01b3c828f64a204c04 */
char SERVER_ENC_ACK[] = {0x23,0x41,0x45,0x53,0x3a,0x4c,0x63,0x7a,0xef,0x9e,0x16,0xcc,0x94,0xf8,0xfc,0x5e,0x81,0xc9,0x80,0x24,0xd3,0x61,0xc6,0xb7,0x9b,0xdf,0xb1,0xfe,0xf5,0xa0,0x31,0xa7,0xba,0x92,0x74,0x3b,0xda,0x0c,0x70,0xed,0x39,0x8f,0xb7,0xda,0xe2,0xe0,0xcb,0x9c,0x86,0x87,0x39,0xaa,0x7b,0xb9,0x5a,0xb3,0xa5,0x81,0xea,0x78,0x15,0xa9,0xfd,0x8b,0x14,0xfb,0x6b,0xcb,0x08,0x04,0x0d,0x77,0xf6,0xd7,0xbc,0x29,0xeb,0x06,0x84,0x07,0x14,0x55,0xaf,0x0c,0x37,0x00};
char SERVER_NULL_ACK[] = {0x00};
char SERVER_WRONG_ACK[] = {0x01,0x02,0x03,0x00};

void add_server_config(char* address, int protocol) {
    os_realloc(agt->server, sizeof(agent_server) * (agt->rip_id + 2), agt->server);
    os_strdup(address, agt->server[agt->rip_id].rip);
    agt->server[agt->rip_id].port = 1514;
    agt->server[agt->rip_id].protocol = 0;
    memset(agt->server + agt->rip_id + 1, 0, sizeof(agent_server));
    agt->server[agt->rip_id].protocol = protocol;
    agt->rip_id++;
    agt->server_count++;
}

void keys_init(keystore *keys) {
    /* Initialize trees */

    keys->keytree_id = rbtree_init();
    keys->keytree_ip = rbtree_init();
    keys->keytree_sock = rbtree_init();

    if (!(keys->keytree_id && keys->keytree_ip && keys->keytree_sock)) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    /* Initialize structure */
    os_calloc(1, sizeof(keyentry*), keys->keyentries);
    keys->keysize = 0;
    keys->id_counter = 0;
    keys->flags.key_mode = W_RAW_KEY;
    keys->flags.save_removed = 0;

    /* Add additional entry for sender == keysize */
    os_calloc(1, sizeof(keyentry), keys->keyentries[keys->keysize]);
    w_mutex_init(&keys->keyentries[keys->keysize]->mutex, NULL);
}

/* setup/teardown */
static int setup_test(void **state) {
    agt = (agent *)calloc(1, sizeof(agent));
    /* Default conf */
    agt->server = NULL;
    agt->rip_id = 0;
    agt->execdq = 0;
    agt->profile = NULL;
    agt->buffer = 1;
    agt->buflength = 5000;
    agt->events_persec = 500;
    agt->flags.auto_restart = 1;
    agt->crypto_method = W_METH_AES;
    /* Connected sock */
    agt->sock = -1;
    /* Server */
    add_server_config("127.0.0.1", IPPROTO_UDP);
    add_server_config("127.0.0.2", IPPROTO_TCP);
    add_server_config("VALID_HOSTNAME/127.0.0.3", IPPROTO_UDP);
    add_server_config("INVALID_HOSTNAME/", IPPROTO_UDP);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, 1);
    will_return(__wrap_w_expression_match, 0);

    /* Keys */
    keys_init(&keys);
    OS_AddKey(&keys, "001", "agent0", "any", "6958b43cb096e036f872d65d6a4dc01b3c828f64a204c04", 0);
    os_set_agent_crypto_method(&keys,agt->crypto_method);

    _s_verify_counter = 0;

    return 0;
}

static int teardown_test(void **state) {
    for (unsigned i=0; agt->server[i].rip; i++) {
        os_free(agt->server[i].rip);
    }
    os_free(agt->server);
    os_free(agt);
    OS_FreeKeys(&keys);
    return 0;
}

/* tests */
/* connect_server */
static void test_connect_server(void **state) {
    bool connected = false;
    expect_any(__wrap__minfo, formatted_msg);
    /* Connect to first server (UDP)*/
    will_return(__wrap_getDefine_Int, 5);
    expect_string(__wrap_OS_GetHost, host, agt->server[0].rip);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    will_return(__wrap_OS_ConnectUDP, 11);

    expect_any_count(__wrap__minfo, formatted_msg, 2);

    connected = connect_server(0, true);
    assert_int_equal(agt->rip_id, 0);
    assert_int_equal(agt->sock, 11);
    assert_true(connected);

    /* Connect to second server (TCP), previous connection must be closed*/
    will_return(__wrap_getDefine_Int, 5);
    expect_string(__wrap_OS_GetHost, host, agt->server[1].rip);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.2"));

    expect_any(__wrap_OS_ConnectTCP, _port);
    expect_any(__wrap_OS_ConnectTCP, _ip);
    expect_any(__wrap_OS_ConnectTCP, ipv6);
    will_return(__wrap_OS_ConnectTCP, 12);
    expect_value(__wrap_OS_CloseSocket, sock, 11);
    will_return(__wrap_OS_CloseSocket, 0);

    expect_any_count(__wrap__minfo, formatted_msg, 2);

    connected = connect_server(1, true);
    assert_int_equal(agt->rip_id, 1);
    assert_int_equal(agt->sock, 12);
    assert_true(connected);

    /* Connect to third server (UDP), valid host name*/
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OS_ConnectUDP, 13);
    expect_value(__wrap_OS_CloseSocket, sock, 12);
    will_return(__wrap_OS_CloseSocket, 0);

    expect_any_count(__wrap__minfo, formatted_msg, 2);

    connected = connect_server(2, true);
    assert_int_equal(agt->rip_id, 2);
    assert_int_equal(agt->sock, 13);
    assert_true(connected);

    /* Connect to fourth server (UDP), invalid host name*/
    will_return(__wrap_getDefine_Int, 5);
    expect_value(__wrap_OS_CloseSocket, sock, 13);
    will_return(__wrap_OS_CloseSocket, 0);

    expect_any(__wrap__minfo, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);

    connected = connect_server(3, true);
    assert_false(connected);

    /* Connect to first server (UDP), simulate connection error*/
    will_return(__wrap_getDefine_Int, 5);
    expect_string(__wrap_OS_GetHost, host, agt->server[0].rip);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    will_return(__wrap_OS_ConnectUDP, -1);
    connected = connect_server(0, true);
    assert_false(connected);

    return;
}

/* agent_handshake_to_server */
static void test_agent_handshake_to_server(void **state) {
    bool handshaked = false;

    /* Handshake with first server (UDP) */
    will_return(__wrap_getDefine_Int, 5);
    expect_string(__wrap_OS_GetHost, host, agt->server[0].rip);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    will_return(__wrap_OS_ConnectUDP, 21);
    #ifndef TEST_WINAGENT
    will_return(__wrap_recv, SERVER_ENC_ACK);
    #else
    will_return(wrap_recv, SERVER_ENC_ACK);
    #endif
    will_return(__wrap_wnet_select, 1);
    expect_string(__wrap_send_msg, msg, "#!-agent startup {\"version\":\"v4.5.0\"}");
    expect_string(__wrap_ReadSecMSG, buffer, SERVER_ENC_ACK);
    will_return(__wrap_ReadSecMSG, "#!-agent ack ");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_any_count(__wrap__minfo, formatted_msg, 3);

    handshaked = agent_handshake_to_server(0, false);
    assert_true(handshaked);

    /* Handshake with second server (TCP) */
    will_return(__wrap_getDefine_Int, 5);
    expect_string(__wrap_OS_GetHost, host, agt->server[1].rip);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.2"));

    expect_any(__wrap_OS_ConnectTCP, _port);
    expect_any(__wrap_OS_ConnectTCP, _ip);
    expect_any(__wrap_OS_ConnectTCP, ipv6);
    will_return(__wrap_OS_ConnectTCP, 22);
    expect_value(__wrap_OS_CloseSocket, sock, 21);
    will_return(__wrap_OS_CloseSocket, 0);
    will_return(__wrap_wnet_select, 1);
    expect_any(__wrap_OS_RecvSecureTCP, sock);
    expect_any(__wrap_OS_RecvSecureTCP, size);
    will_return(__wrap_OS_RecvSecureTCP, SERVER_ENC_ACK);
    will_return(__wrap_OS_RecvSecureTCP, strlen(SERVER_ENC_ACK));
    expect_string(__wrap_send_msg, msg, "#!-agent startup {\"version\":\"v4.5.0\"}");
    expect_string(__wrap_ReadSecMSG, buffer, SERVER_ENC_ACK);
    will_return(__wrap_ReadSecMSG, "#!-agent ack ");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_any_count(__wrap__minfo, formatted_msg, 6);

    handshaked = agent_handshake_to_server(1, false);
    assert_true(handshaked);

    /* Handshake sending the startup message */
    will_return(__wrap_getDefine_Int, 5);
    expect_string(__wrap_OS_GetHost, host, agt->server[1].rip);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.2"));

    expect_any(__wrap_OS_ConnectTCP, _port);
    expect_any(__wrap_OS_ConnectTCP, _ip);
    expect_any(__wrap_OS_ConnectTCP, ipv6);
    will_return(__wrap_OS_ConnectTCP, 23);
    expect_value(__wrap_OS_CloseSocket, sock, 22);
    will_return(__wrap_OS_CloseSocket, 0);
    will_return(__wrap_wnet_select, 1);
    expect_any(__wrap_OS_RecvSecureTCP, sock);
    expect_any(__wrap_OS_RecvSecureTCP, size);
    will_return(__wrap_OS_RecvSecureTCP, SERVER_ENC_ACK);
    will_return(__wrap_OS_RecvSecureTCP, strlen(SERVER_ENC_ACK));
    expect_string(__wrap_send_msg, msg, "#!-agent startup {\"version\":\"v4.5.0\"}");
    expect_string(__wrap_send_msg, msg, "1:wazuh-agent:ossec: Agent started: 'agent0->any'.");
    expect_string(__wrap_ReadSecMSG, buffer, SERVER_ENC_ACK);
    will_return(__wrap_ReadSecMSG, "#!-agent ack ");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_any_count(__wrap__minfo, formatted_msg, 3);

    handshaked = agent_handshake_to_server(1, true);
    assert_true(handshaked);

    /* Handshake with connection error */
    will_return(__wrap_getDefine_Int, 5);
    expect_string(__wrap_OS_GetHost, host, agt->server[0].rip);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    will_return(__wrap_OS_ConnectUDP, -1);
    expect_value(__wrap_OS_CloseSocket, sock, 23);
    will_return(__wrap_OS_CloseSocket, 0);

    expect_any(__wrap__minfo, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);

    handshaked = agent_handshake_to_server(0, false);
    assert_false(handshaked);

    /* Handshake with reception error */
    will_return(__wrap_getDefine_Int, 5);
    expect_string(__wrap_OS_GetHost, host, agt->server[0].rip);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    will_return(__wrap_OS_ConnectUDP, 23);
    will_return(__wrap_wnet_select, 0);
    expect_string(__wrap_send_msg, msg, "#!-agent startup {\"version\":\"v4.5.0\"}");

    expect_any(__wrap__mwarn, formatted_msg);

    handshaked = agent_handshake_to_server(0, false);
    assert_false(handshaked);

    /* Handshake with decode error */
    will_return(__wrap_getDefine_Int, 5);
    expect_string(__wrap_OS_GetHost, host, agt->server[0].rip);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    will_return(__wrap_OS_ConnectUDP, 24);
    expect_value(__wrap_OS_CloseSocket, sock, 23);
    will_return(__wrap_OS_CloseSocket, 0);
#ifndef TEST_WINAGENT
    will_return(__wrap_recv, SERVER_WRONG_ACK);
#else
    will_return(wrap_recv, SERVER_WRONG_ACK);
#endif
    will_return(__wrap_wnet_select, 1);
    expect_string(__wrap_send_msg, msg, "#!-agent startup {\"version\":\"v4.5.0\"}");
    expect_string(__wrap_ReadSecMSG, buffer, SERVER_WRONG_ACK);
    will_return(__wrap_ReadSecMSG, SERVER_WRONG_ACK);
    will_return(__wrap_ReadSecMSG, KS_CORRUPT);

    handshaked = agent_handshake_to_server(0, false);
    assert_false(handshaked);

    return;
}

static void test_agent_handshake_to_server_invalid_version(void **state) {
    bool handshaked = false;

    /* Handshake with first server (UDP) */
    will_return(__wrap_getDefine_Int, 5);
    expect_string(__wrap_OS_GetHost, host, agt->server[0].rip);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    will_return(__wrap_OS_ConnectUDP, 21);
    #ifndef TEST_WINAGENT
    will_return(__wrap_recv, SERVER_ENC_ACK);
    #else
    will_return(wrap_recv, SERVER_ENC_ACK);
    #endif
    will_return(__wrap_wnet_select, 1);
    expect_string(__wrap_send_msg, msg, "#!-agent startup {\"version\":\"v4.5.0\"}");
    expect_string(__wrap_ReadSecMSG, buffer, SERVER_ENC_ACK);
    will_return(__wrap_ReadSecMSG, "#!-err {\"message\": \"Agent version must be lower or equal to manager version\"}");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_any_count(__wrap__minfo, formatted_msg, 1);

    expect_string(__wrap__mwarn, formatted_msg ,"Couldn't connect to server '127.0.0.1': 'Agent version must be lower or equal to manager version'");

    handshaked = agent_handshake_to_server(0, false);
    assert_false(handshaked);
}

static void test_agent_handshake_to_server_error_getting_msg1(void **state) {
    bool handshaked = false;

    /* Handshake with first server (UDP) */
    will_return(__wrap_getDefine_Int, 5);
    expect_string(__wrap_OS_GetHost, host, agt->server[0].rip);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    will_return(__wrap_OS_ConnectUDP, 21);
    #ifndef TEST_WINAGENT
    will_return(__wrap_recv, SERVER_ENC_ACK);
    #else
    will_return(wrap_recv, SERVER_ENC_ACK);
    #endif
    will_return(__wrap_wnet_select, 1);
    expect_string(__wrap_send_msg, msg, "#!-agent startup {\"version\":\"v4.5.0\"}");
    expect_string(__wrap_ReadSecMSG, buffer, SERVER_ENC_ACK);
    will_return(__wrap_ReadSecMSG, "#!-err \"message\": \"Agent version must be lower or equal to manager version\"}");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_any_count(__wrap__minfo, formatted_msg, 1);

    expect_string(__wrap__merror, formatted_msg ,"Error getting message from server '127.0.0.1'");

    handshaked = agent_handshake_to_server(0, false);
    assert_false(handshaked);
}

static void test_agent_handshake_to_server_error_getting_msg2(void **state) {
    bool handshaked = false;

    /* Handshake with first server (UDP) */
    will_return(__wrap_getDefine_Int, 5);
    expect_string(__wrap_OS_GetHost, host, agt->server[0].rip);
    will_return(__wrap_OS_GetHost, strdup("127.0.0.1"));
    will_return(__wrap_OS_ConnectUDP, 21);
    #ifndef TEST_WINAGENT
    will_return(__wrap_recv, SERVER_ENC_ACK);
    #else
    will_return(wrap_recv, SERVER_ENC_ACK);
    #endif
    will_return(__wrap_wnet_select, 1);
    expect_string(__wrap_send_msg, msg, "#!-agent startup {\"version\":\"v4.5.0\"}");
    expect_string(__wrap_ReadSecMSG, buffer, SERVER_ENC_ACK);
    will_return(__wrap_ReadSecMSG, "#!-err {\"key\": \"Agent version must be lower or equal to manager version\"}");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_any_count(__wrap__minfo, formatted_msg, 1);

    expect_string(__wrap__merror, formatted_msg ,"Error getting message from server '127.0.0.1'");

    handshaked = agent_handshake_to_server(0, false);
    assert_false(handshaked);
}

/* agent_start_up_to_server */
static void test_send_msg_on_startup(void **state) {
    expect_string(__wrap_send_msg, msg, "1:wazuh-agent:ossec: Agent started: 'agent0->any'.");
    send_msg_on_startup();
    return;
}

/* send_agent_stopped_message */
static void test_send_agent_stopped_message(void **state) {

    /* Sending the shutdown message */
    expect_string(__wrap_send_msg, msg, "#!-agent shutdown ");

    send_agent_stopped_message();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_connect_server, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_agent_handshake_to_server, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_agent_handshake_to_server_invalid_version, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_agent_handshake_to_server_error_getting_msg1, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_agent_handshake_to_server_error_getting_msg2, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_send_msg_on_startup, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_send_agent_stopped_message, setup_test, teardown_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
