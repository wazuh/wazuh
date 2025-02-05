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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/read-agents_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

#include "../analysisd/eventinfo.h"
#include "../analysisd/decoders/decoder.h"
#include "../headers/wazuhdb_op.h"

/* setup/teardown redefinitions */
#define setup_dispatch_check setup_dispatch_answer
#define teardown_dispatch_check teardown_dispatch_answer
#define setup_dispatch_state setup_dispatch_answer
#define teardown_dispatch_state teardown_dispatch_answer
#define setup_dispatch_clear setup_dispatch_answer
#define teardown_dispatch_clear teardown_dispatch_answer

void dispatch_send_local(dbsync_context_t * ctx, const char * query);
void dispatch_send_remote(dbsync_context_t * ctx, const char * query, unsigned attempts);
void dispatch_answer(dbsync_context_t * ctx, const char * result);
void dispatch_check(dbsync_context_t * ctx, const char * command);
void dispatch_state(dbsync_context_t * ctx);
void dispatch_clear(dbsync_context_t * ctx);
void DispatchDBSync(dbsync_context_t * ctx, Eventinfo * lf);

/* auxiliary structs */
typedef struct __test_dbsync_s{
    dbsync_context_t *ctx;
    Eventinfo *lf;
}test_dbsync_t;

/* setup/teardowns */
static int setup_dbsync_context(void **state) {
    test_dbsync_t *data;

    if(data = calloc(1, sizeof(test_dbsync_t)), !data)
        return -1;

    if(data->ctx = calloc(1, sizeof(dbsync_context_t)), !data->ctx)
        return -1;

    *state = data;

    return 0;
}

static int teardown_dbsync_context(void **state) {
    test_dbsync_t *data = *state;

    if(data->ctx){
        free(data->ctx);
        data->ctx = NULL;
    }

    if(data) {
        free(data);
        data = NULL;
    }

    return 0;
}

static int setup_send_local(void **state) {
    test_dbsync_t *data = *state;

    data->ctx->component = calloc(OS_SIZE_32, sizeof(char));

    if(data->ctx->component == NULL) return -1;

    return 0;
}

static int teardown_dispatch_send_local(void **state) {
    test_dbsync_t *data = *state;

    if(data->ctx->component) {
        free(data->ctx->component);
        data->ctx->component = NULL;
    }

    errno = 0;

    return 0;
}

static int setup_dispatch_send_remote(void **state) {
    test_dbsync_t *data = *state;

    data->ctx->agent_id = calloc(OS_SIZE_16, sizeof(char));
    data->ctx->component = calloc(OS_SIZE_16, sizeof(char));

    if(data->ctx->agent_id == NULL ||
       data->ctx->component == NULL)
        return -1;

    return 0;
}

static int teardown_dispatch_send_remote(void **state) {
    test_dbsync_t *data = *state;

    if(data->ctx->agent_id) {
        free(data->ctx->agent_id);
        data->ctx->agent_id = NULL;
    }

    if(data->ctx->component) {
        free(data->ctx->component);
        data->ctx->component = NULL;
    }

    return 0;
}

static int setup_dispatch_answer(void **state) {
    test_dbsync_t *data = *state;

    data->ctx->data = cJSON_Parse(
        "{\"tail\": \"tail\", \"checksum\": \"checksum\", \"begin\": \"/a/path\", \"end\": \"/z/path\"}");
    data->ctx->agent_id = calloc(OS_SIZE_16, sizeof(char));
    data->ctx->component = calloc(OS_SIZE_16, sizeof(char));

    if(data->ctx->data == NULL ||
       data->ctx->agent_id == NULL ||
       data->ctx->component == NULL)
        return -1;

    return 0;
}

static int teardown_dispatch_answer(void **state) {
    test_dbsync_t *data = *state;

    cJSON_Delete(data->ctx->data);
    data->ctx->data = NULL;

    if(data->ctx->agent_id) {
        free(data->ctx->agent_id);
        data->ctx->agent_id = NULL;
    }

    if(data->ctx->component) {
        free(data->ctx->component);
        data->ctx->component = NULL;
    }

    return 0;
}

static int setup_DispatchDBSync(void **state) {
    test_dbsync_t *data = *state;

    if(data->lf = calloc(1, sizeof(Eventinfo)), !data->lf)
        return -1;

    data->lf->log = strdup(
        "{"
            "\"component\": \"syscheck\","
            "\"type\": \"integrity_check_test\","
            "\"data\": {"
                "\"tail\": \"tail\","
                "\"checksum\": \"checksum\","
                "\"begin\": \"/a/path\","
                "\"end\": \"/z/path\""
            "}"
        "}");

    if(data->lf->log == NULL) return -1;

    data->lf->agent_id = calloc(OS_SIZE_16, sizeof(char));

    if(data->lf->agent_id == NULL) return -1;

    return 0;
}

static int teardown_DispatchDBSync(void **state) {
    test_dbsync_t *data = *state;

    if(data->lf->log) {
        free(data->lf->log);
        data->lf->log = NULL;
    }

    Free_Eventinfo(data->lf);

    return 0;
}

/* tests */
/* dispatch_send_local */
static void test_dispatch_send_local_success(void **state) {
    test_dbsync_t *data = *state;
    const char *query = "This is a mock query, it won't go anywhere...";

    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_string(__wrap_OS_ConnectUnixDomain, path, SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, 65555);

    expect_value(__wrap_OS_SendSecureTCP, sock, 65555);
    expect_value(__wrap_OS_SendSecureTCP, size, 0x36);
    expect_string(__wrap_OS_SendSecureTCP, msg, "syscheck This is a mock query, it won't go anywhere...");
    will_return(__wrap_OS_SendSecureTCP, 0);

    // Assertions to this function are done through wrappers.
    dispatch_send_local(data->ctx, query);
}

static void test_dispatch_send_local_success_syscollector(void **state) {
    test_dbsync_t *data = *state;
    const char *query = "This is a mock query, it won't go anywhere...";

    snprintf(data->ctx->component, OS_SIZE_32, "syscollector-process");

    expect_string(__wrap_OS_ConnectUnixDomain, path, WM_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, 65555);

    expect_value(__wrap_OS_SendSecureTCP, sock, 65555);
    expect_value(__wrap_OS_SendSecureTCP, size, 66);
    expect_string(__wrap_OS_SendSecureTCP, msg, "syscollector-process This is a mock query, it won't go anywhere...");
    will_return(__wrap_OS_SendSecureTCP, 0);

    // Assertions to this function are done through wrappers.
    dispatch_send_local(data->ctx, query);
}

static void test_dispatch_send_local_socket_connect_error(void **state) {
    test_dbsync_t *data = *state;
    const char *query = "This is a mock query, it won't go anywhere...";

    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_string(__wrap_OS_ConnectUnixDomain, path, SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, OS_SOCKTERR);

    expect_string(__wrap__merror, formatted_msg, "dbsync: cannot connect to syscheck: Too many open files in system (23)");

    errno = ENFILE;

    // Assertions to this function are done through wrappers.
    dispatch_send_local(data->ctx, query);
}

static void test_dispatch_send_local_wrong_component(void **state) {
    test_dbsync_t *data = *state;
    const char *query = "This is a mock query, it won't go anywhere...";

    snprintf(data->ctx->component, OS_SIZE_16, "invalid");

    expect_string(__wrap__merror, formatted_msg, "dbsync: unknown location 'invalid'");

    // Assertions to this function are done through wrappers.
    dispatch_send_local(data->ctx, query);
}

static void test_dispatch_send_local_null_component(void **state) {
    test_dbsync_t *data = *state;
    const char *query = "This is a mock query, it won't go anywhere...";

    expect_string(__wrap__merror, formatted_msg, "dbsync: unknown location ''");

    // Assertions to this function are done through wrappers.
    dispatch_send_local(data->ctx, query);
}

/* dispatch_send_remote */
static void test_dispatch_send_remote_success(void **state) {
    test_dbsync_t *data = *state;
    const char *query = "This is a mock query, it won't go anywhere...";

    data->ctx->ar_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_send_msg_to_agent, msocket, 65555);
    expect_string(__wrap_send_msg_to_agent, msg,
        "syscheck This is a mock query, it won't go anywhere...");
    expect_string(__wrap_send_msg_to_agent, agt_id, "007");
    expect_value(__wrap_send_msg_to_agent, exec, NULL);
    will_return(__wrap_send_msg_to_agent, 0);

    // Assertions to this function are done through wrappers.
    dispatch_send_remote(data->ctx, query, 3);
}

static void test_dispatch_send_remote_not_connected_success(void **state) {
    test_dbsync_t *data = *state;
    const char *query = "This is a mock query, it won't go anywhere...";

    data->ctx->ar_sock = -1;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    will_return(__wrap_connect_to_remoted, 65555);

    expect_value(__wrap_send_msg_to_agent, msocket, 65555);
    expect_string(__wrap_send_msg_to_agent, msg,
        "syscheck This is a mock query, it won't go anywhere...");
    expect_string(__wrap_send_msg_to_agent, agt_id, "007");
    expect_value(__wrap_send_msg_to_agent, exec, NULL);
    will_return(__wrap_send_msg_to_agent, 0);

    // Assertions to this function are done through wrappers.
    dispatch_send_remote(data->ctx, query, 3);
}

static void test_dispatch_send_remote_not_connected_error(void **state) {
    test_dbsync_t *data = *state;
    const char *query = "This is a mock query, it won't go anywhere...";

    data->ctx->ar_sock = -1;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    will_return(__wrap_connect_to_remoted, -1);

    // Assertions to this function are done through wrappers.
    dispatch_send_remote(data->ctx, query, 3);
}

static void test_dispatch_send_remote_retry(void **state) {
    test_dbsync_t *data = *state;
    const char *query = "This is a mock query, it won't go anywhere...";

    data->ctx->ar_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value_count(__wrap_send_msg_to_agent, msocket, 65555, 2);
    expect_string_count(__wrap_send_msg_to_agent, msg,
        "syscheck This is a mock query, it won't go anywhere...", 2);
    expect_string_count(__wrap_send_msg_to_agent, agt_id, "007", 2);
    expect_value_count(__wrap_send_msg_to_agent, exec, NULL, 2);

    will_return(__wrap_send_msg_to_agent, -1);  // Fail the first time

    will_return(__wrap_connect_to_remoted, 65555);  //  Reconnect and send successfully
    will_return(__wrap_send_msg_to_agent, 0);

    // Assertions to this function are done through wrappers.
    dispatch_send_remote(data->ctx, query, 3);
}

static void test_dispatch_send_remote_retry_3_times(void **state) {
    test_dbsync_t *data = *state;
    const char *query = "This is a mock query, it won't go anywhere...";

    data->ctx->ar_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    will_return_always(__wrap_connect_to_remoted, 65555);  //  Always reconnect

    expect_value_count(__wrap_send_msg_to_agent, msocket, 65555, 4);
    expect_string_count(__wrap_send_msg_to_agent, msg,
        "syscheck This is a mock query, it won't go anywhere...", 4);
    expect_string_count(__wrap_send_msg_to_agent, agt_id, "007", 4);
    expect_value_count(__wrap_send_msg_to_agent, exec, NULL, 4);

    will_return_always(__wrap_send_msg_to_agent, -1);  // Always fail to send

    // Assertions to this function are done through wrappers.
    dispatch_send_remote(data->ctx, query, 3);
}

/* dispatch_answer */
static void test_dispatch_answer_local_success(void **state) {
    test_dbsync_t *data = *state;
    const char *result = "result_text";

    data->ctx->ar_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "000");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_string(__wrap_OS_ConnectUnixDomain, path, SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, 65555);

    expect_value(__wrap_OS_SendSecureTCP, sock, 65555);
    expect_value(__wrap_OS_SendSecureTCP, size, 0x3f);
    expect_string(__wrap_OS_SendSecureTCP, msg, "syscheck dbsync result_text {\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    will_return(__wrap_OS_SendSecureTCP, 0);

    dispatch_answer(data->ctx, result);
}

static void test_dispatch_answer_remote_success(void **state) {
    test_dbsync_t *data = *state;
    const char *result = "result_text";

    data->ctx->ar_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_send_msg_to_agent, msocket, 65555);
    expect_string(__wrap_send_msg_to_agent, msg,
        "syscheck dbsync result_text {\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_string(__wrap_send_msg_to_agent, agt_id, "007");
    expect_value(__wrap_send_msg_to_agent, exec, NULL);
    will_return(__wrap_send_msg_to_agent, 0);

    dispatch_answer(data->ctx, result);
}

static void test_dispatch_answer_query_too_long(void **state) {
    test_dbsync_t *data = *state;
    char result[OS_MAXSTR];

    data->ctx->ar_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    memset(result, 'a', OS_MAXSTR);
    result[OS_MAXSTR - 1] = '\0';

    expect_string(__wrap__merror, formatted_msg, "dbsync: Cannot build query for agent: query is too long.");

    dispatch_answer(data->ctx, result);
}

static void test_dispatch_answer_query_invalid(void **state) {
    test_dbsync_t *data = *state;
    char result[OS_MAXSTR];

    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_64, "blasqlblabla");

    expect_string(__wrap__merror, formatted_msg, "dbsync: Invalid component specified.");

    dispatch_answer(data->ctx, result);
}

/* dispatch_check */
static void test_dispatch_check_success(void **state) {
    test_dbsync_t *data = *state;
    const char *command = "command";
    char *response = "This is a mock response, payload points -> here <-";

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck command {\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, response);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_value(__wrap_send_msg_to_agent, msocket, 65555);
    expect_string(__wrap_send_msg_to_agent, msg,
        "syscheck dbsync is a mock response, payload points -> here <- {\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_string(__wrap_send_msg_to_agent, agt_id, "007");
    expect_value(__wrap_send_msg_to_agent, exec, NULL);
    will_return(__wrap_send_msg_to_agent, 0);

    dispatch_check(data->ctx, command);
}

static void test_dispatch_check_corrupt_message(void **state) {
    dbsync_context_t ctx;
    const char *command = "command";

    ctx.data = NULL;

    expect_string(__wrap__merror, formatted_msg, "dbsync: Corrupt message: cannot get data member.");

    dispatch_check(&ctx, command);
}

static void test_dispatch_check_query_too_long(void **state) {
    test_dbsync_t *data = *state;
    char command[OS_MAXSTR];

    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    memset(command, 'a', OS_MAXSTR);
    command[OS_MAXSTR - 1] = '\0';

    expect_string(__wrap__merror, formatted_msg, "dbsync: Cannot build check query: input is too long.");

    dispatch_check(data->ctx, command);
}

static void test_dispatch_check_query_invalid(void **state) {
    test_dbsync_t *data = *state;
    const char *command = "command";

    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_64, "command_component");

    expect_string(__wrap__merror, formatted_msg, "dbsync: Invalid component specified.");

    dispatch_check(data->ctx, command);
}

static void test_dispatch_check_unable_to_communicate_with_db(void **state) {
    test_dbsync_t *data = *state;
    const char *command = "command";
    char *response = "This is a mock response, payload points -> here <-";

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck command {\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -2);

    expect_string(__wrap__merror, formatted_msg, "dbsync: Cannot communicate with database.");

    dispatch_check(data->ctx, command);
}

static void test_dispatch_check_no_response_from_db(void **state) {
    test_dbsync_t *data = *state;
    const char *command = "command";
    char *response = "This is a mock response, payload points -> here <-";

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck command {\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__merror, formatted_msg, "dbsync: Cannot get response from database.");

    dispatch_check(data->ctx, command);
}

static void test_dispatch_check_error_parsing_response(void **state) {
    test_dbsync_t *data = *state;
    const char *command = "command";
    char *response = "This is a mock response";

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck command {\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, response);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);

    expect_string(__wrap__merror, formatted_msg, "dbsync: Bad response from database: is a mock response");

    dispatch_check(data->ctx, command);
}

/* dispatch_state */
static void test_dispatch_state_success(void **state) {
    test_dbsync_t *data = *state;
    char *response = "This is a mock response, payload points -> here <-";

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck save2 "
        "{\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, response);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // Assertions for this test are done through wrappers
    dispatch_state(data->ctx);
}

static void test_dispatch_state_corrupted_message(void **state) {
    test_dbsync_t *data = *state;

    cJSON_Delete(data->ctx->data);
    data->ctx->data = NULL;

    expect_string(__wrap__merror, formatted_msg, "dbsync: Corrupt message: cannot get data member.");

    // Assertions for this test are done through wrappers
    dispatch_state(data->ctx);
}

static void test_dispatch_state_query_too_long(void **state) {
    test_dbsync_t *data = *state;
    char *p;

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");

    p = realloc(data->ctx->component, OS_MAXSTR * sizeof(char));

    if(p == NULL)
        fail();

    data->ctx->component = p;

    memset(data->ctx->component, 'a', OS_MAXSTR);
    data->ctx->component[OS_MAXSTR - 1] = '\0';

    expect_string(__wrap__merror, formatted_msg, "dbsync: Cannot build save query: input is too long.");

    // Assertions for this test are done through wrappers
    dispatch_state(data->ctx);
}

static void test_dispatch_state_invalid(void **state) {
    test_dbsync_t *data = *state;
    const char *command = "command";

    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_64, "command_component-");

    expect_string(__wrap__merror, formatted_msg, "dbsync: Invalid component specified.");

    // Assertions for this test are done through wrappers
    dispatch_state(data->ctx);
}

static void test_dispatch_state_unable_to_communicate_with_db(void **state) {
    test_dbsync_t *data = *state;

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck save2 "
        "{\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, NULL);
    will_return(__wrap_wdbc_query_ex, -2);

    expect_string(__wrap__merror, formatted_msg, "dbsync: Cannot communicate with database.");

    // Assertions for this test are done through wrappers
    dispatch_state(data->ctx);
}

static void test_dispatch_state_no_response_from_db(void **state) {
    test_dbsync_t *data = *state;

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck save2 "
        "{\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, NULL);
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__merror, formatted_msg, "dbsync: Cannot get response from database.");

    // Assertions for this test are done through wrappers
    dispatch_state(data->ctx);
}

static void test_dispatch_state_error_parsing_response(void **state) {
    test_dbsync_t *data = *state;
    char *response = "This is a mock response, payload points -> here <-";

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck save2 "
        "{\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, response);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);

    expect_string(__wrap__merror, formatted_msg,
        "dbsync: Bad response from database: is a mock response, payload points -> here <-");

    // Assertions for this test are done through wrappers
    dispatch_state(data->ctx);
}

/* dispatch_clear */
static void test_dispatch_clear_success(void **state) {
    test_dbsync_t *data = *state;
    char *response = "This is a mock response, payload points -> here <-";

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck integrity_clear "
        "{\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, response);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // Assertions for this test are done through wrappers
    dispatch_clear(data->ctx);
}

static void test_dispatch_clear_corrupted_message(void **state) {
    test_dbsync_t *data = *state;

    cJSON_Delete(data->ctx->data);
    data->ctx->data = NULL;

    expect_string(__wrap__merror, formatted_msg, "dbsync: Corrupt message: cannot get data member.");

    // Assertions for this test are done through wrappers
    dispatch_clear(data->ctx);
}

static void test_dispatch_clear_query_too_long(void **state) {
    test_dbsync_t *data = *state;
    char *p;

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");

    p = realloc(data->ctx->component, OS_MAXSTR * sizeof(char));

    if(p == NULL)
        fail();

    data->ctx->component = p;
    memset(data->ctx->component, 'a', OS_MAXSTR);
    data->ctx->component[OS_MAXSTR - 1] = '\0';

    expect_string(__wrap__merror, formatted_msg, "dbsync: Cannot build clear query: input is too long.");

    // Assertions for this test are done through wrappers
    dispatch_clear(data->ctx);
}

static void test_dispatch_clear_query_invalid(void **state) {
    test_dbsync_t *data = *state;
    const char *command = "command";

    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_64, "xxxxx");

    expect_string(__wrap__merror, formatted_msg, "dbsync: Invalid component specified.");

    // Assertions for this test are done through wrappers
    dispatch_clear(data->ctx);
}

static void test_dispatch_clear_unable_to_communicate_with_db(void **state) {
    test_dbsync_t *data = *state;

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck integrity_clear "
        "{\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, NULL);
    will_return(__wrap_wdbc_query_ex, -2);

    expect_string(__wrap__merror, formatted_msg, "dbsync: Cannot communicate with database.");

    // Assertions for this test are done through wrappers
    dispatch_clear(data->ctx);
}

static void test_dispatch_clear_no_response_from_db(void **state) {
    test_dbsync_t *data = *state;

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck integrity_clear "
        "{\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, NULL);
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__merror, formatted_msg, "dbsync: Cannot get response from database.");

    // Assertions for this test are done through wrappers
    dispatch_clear(data->ctx);
}

static void test_dispatch_clear_error_parsing_response(void **state) {
    test_dbsync_t *data = *state;
    char *response = "This is a mock response, payload points -> here <-";

    data->ctx->db_sock = 65555;
    snprintf(data->ctx->agent_id, OS_SIZE_16, "007");
    snprintf(data->ctx->component, OS_SIZE_16, "syscheck");

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck integrity_clear "
        "{\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, response);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);

    expect_string(__wrap__merror, formatted_msg,
        "dbsync: Bad response from database: is a mock response, payload points -> here <-");

    // Assertions for this test are done through wrappers
    dispatch_clear(data->ctx);
}

/* DispatchDBSync */
static void test_DispatchDBSync_integrity_check_success(void **state) {
    test_dbsync_t *data = *state;
    char *response = "This is a mock response, payload points -> here <-";

    snprintf(data->lf->agent_id, OS_SIZE_16, "007");

    data->ctx->db_sock = 65555;

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck integrity_check_test {\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, response);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_value(__wrap_send_msg_to_agent, msocket, 65555);
    expect_string(__wrap_send_msg_to_agent, msg,
        "syscheck dbsync is a mock response, payload points -> here <- {\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_string(__wrap_send_msg_to_agent, agt_id, "007");
    expect_value(__wrap_send_msg_to_agent, exec, NULL);
    will_return(__wrap_send_msg_to_agent, 0);

    DispatchDBSync(data->ctx, data->lf);
}

static void test_DispatchDBSync_state_success(void **state) {
    test_dbsync_t *data = *state;
    char *response = "This is a mock response, payload points -> here <-";
    cJSON *root = cJSON_Parse(data->lf->log);

    snprintf(data->lf->agent_id, OS_SIZE_16, "007");

    data->ctx->db_sock = 65555;

    cJSON_DeleteItemFromObject(root, "type");
    cJSON_AddStringToObject(root, "type", "state");

    free(data->lf->log);
    data->lf->log = cJSON_PrintUnformatted(root);

    cJSON_Delete(root);

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck save2 "
        "{\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, response);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    DispatchDBSync(data->ctx, data->lf);
}

static void test_DispatchDBSync_integrity_clear_success(void **state) {
    test_dbsync_t *data = *state;
    char *response = "This is a mock response, payload points -> here <-";
    cJSON *root = cJSON_Parse(data->lf->log);

    snprintf(data->lf->agent_id, OS_SIZE_16, "007");

    data->ctx->db_sock = 65555;

    cJSON_DeleteItemFromObject(root, "type");
    cJSON_AddStringToObject(root, "type", "integrity_clear");

    free(data->lf->log);
    data->lf->log = cJSON_PrintUnformatted(root);

    cJSON_Delete(root);

    expect_value(__wrap_wdbc_query_ex, *sock, data->ctx->db_sock);
    expect_string(__wrap_wdbc_query_ex, query,
        "agent 007 syscheck integrity_clear "
        "{\"tail\":\"tail\",\"checksum\":\"checksum\",\"begin\":\"/a/path\",\"end\":\"/z/path\"}");
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, response);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    DispatchDBSync(data->ctx, data->lf);
}

static void test_DispatchDBSync_invalid_log(void **state) {
    test_dbsync_t *data = *state;

    snprintf(data->lf->agent_id, OS_SIZE_16, "007");

    data->ctx->db_sock = 65555;

    free(data->lf->log);
    if(data->lf->log = strdup("This is no JSON"), data->lf->log == NULL)
        fail();

    expect_string(__wrap__merror, formatted_msg, "dbsync: Cannot parse JSON: This is no JSON");

    DispatchDBSync(data->ctx, data->lf);
}

static void test_DispatchDBSync_no_component(void **state) {
    test_dbsync_t *data = *state;
    cJSON *root = cJSON_Parse(data->lf->log);

    snprintf(data->lf->agent_id, OS_SIZE_16, "007");

    data->ctx->db_sock = 65555;

    cJSON_DeleteItemFromObject(root, "component");

    free(data->lf->log);
    data->lf->log = cJSON_PrintUnformatted(root);

    cJSON_Delete(root);

    expect_string(__wrap__merror, formatted_msg, "dbsync: Corrupt message: cannot get component member.");

    DispatchDBSync(data->ctx, data->lf);
}

static void test_DispatchDBSync_no_type(void **state) {
    test_dbsync_t *data = *state;
    cJSON *root = cJSON_Parse(data->lf->log);

    snprintf(data->lf->agent_id, OS_SIZE_16, "007");

    data->ctx->db_sock = 65555;

    cJSON_DeleteItemFromObject(root, "type");

    free(data->lf->log);
    data->lf->log = cJSON_PrintUnformatted(root);

    cJSON_Delete(root);

    expect_string(__wrap__merror, formatted_msg, "dbsync: Corrupt message: cannot get type member.");

    DispatchDBSync(data->ctx, data->lf);
}

static void test_DispatchDBSync_invalid_message_type(void **state) {
    test_dbsync_t *data = *state;
    cJSON *root = cJSON_Parse(data->lf->log);

    snprintf(data->lf->agent_id, OS_SIZE_16, "007");

    data->ctx->db_sock = 65555;

    cJSON_DeleteItemFromObject(root, "type");
    cJSON_AddStringToObject(root, "type", "invalid");

    free(data->lf->log);
    data->lf->log = cJSON_PrintUnformatted(root);

    cJSON_Delete(root);

    expect_string(__wrap__merror, formatted_msg, "dbsync: Wrong message type 'invalid' received from agent 007.");

    DispatchDBSync(data->ctx, data->lf);
}

static void test_DispatchDBSync_null_ctx(void **state) {
    test_dbsync_t *data = *state;

    expect_assert_failure(DispatchDBSync(NULL, data->lf));
}

static void test_DispatchDBSync_null_lf(void **state) {
    test_dbsync_t *data = *state;

    expect_assert_failure(DispatchDBSync(data->ctx, NULL));
}


int main(void) {
    const struct CMUnitTest tests[] = {
        /* dispatch_send_local */
        cmocka_unit_test_setup_teardown(test_dispatch_send_local_success, setup_send_local, teardown_dispatch_send_local),
        cmocka_unit_test_setup_teardown(test_dispatch_send_local_success_syscollector, setup_send_local, teardown_dispatch_send_local),
        cmocka_unit_test_setup_teardown(test_dispatch_send_local_socket_connect_error, setup_send_local, teardown_dispatch_send_local),
        cmocka_unit_test_setup_teardown(test_dispatch_send_local_wrong_component, setup_send_local, teardown_dispatch_send_local),
        cmocka_unit_test_setup_teardown(test_dispatch_send_local_null_component, setup_send_local, teardown_dispatch_send_local),

        /* dispatch_send_remote */
        cmocka_unit_test_setup_teardown(test_dispatch_send_remote_success, setup_dispatch_send_remote, teardown_dispatch_send_remote),
        cmocka_unit_test_setup_teardown(test_dispatch_send_remote_not_connected_success, setup_dispatch_send_remote, teardown_dispatch_send_remote),
        cmocka_unit_test_setup_teardown(test_dispatch_send_remote_not_connected_error, setup_dispatch_send_remote, teardown_dispatch_send_remote),
        cmocka_unit_test_setup_teardown(test_dispatch_send_remote_retry, setup_dispatch_send_remote, teardown_dispatch_send_remote),
        cmocka_unit_test_setup_teardown(test_dispatch_send_remote_retry_3_times, setup_dispatch_send_remote, teardown_dispatch_send_remote),

        /* dispatch_answer */
        cmocka_unit_test_setup_teardown(test_dispatch_answer_local_success, setup_dispatch_answer, teardown_dispatch_answer),
        cmocka_unit_test_setup_teardown(test_dispatch_answer_remote_success, setup_dispatch_answer, teardown_dispatch_answer),
        cmocka_unit_test_setup_teardown(test_dispatch_answer_query_too_long, setup_dispatch_answer, teardown_dispatch_answer),
        cmocka_unit_test_setup_teardown(test_dispatch_answer_query_invalid, setup_dispatch_answer, teardown_dispatch_answer),

        /* dispatch_check */
        cmocka_unit_test_setup_teardown(test_dispatch_check_success, setup_dispatch_check, teardown_dispatch_check),
        cmocka_unit_test_setup_teardown(test_dispatch_check_corrupt_message, setup_dispatch_check, teardown_dispatch_check),
        cmocka_unit_test_setup_teardown(test_dispatch_check_query_too_long, setup_dispatch_check, teardown_dispatch_check),
        cmocka_unit_test_setup_teardown(test_dispatch_check_query_invalid, setup_dispatch_check, teardown_dispatch_check),
        cmocka_unit_test_setup_teardown(test_dispatch_check_unable_to_communicate_with_db, setup_dispatch_check, teardown_dispatch_check),
        cmocka_unit_test_setup_teardown(test_dispatch_check_no_response_from_db, setup_dispatch_check, teardown_dispatch_check),
        cmocka_unit_test_setup_teardown(test_dispatch_check_error_parsing_response, setup_dispatch_check, teardown_dispatch_check),

        /* dispatch_state */
        cmocka_unit_test_setup_teardown(test_dispatch_state_success, setup_dispatch_state, teardown_dispatch_state),
        cmocka_unit_test_setup_teardown(test_dispatch_state_corrupted_message, setup_dispatch_state, teardown_dispatch_state),
        cmocka_unit_test_setup_teardown(test_dispatch_state_query_too_long, setup_dispatch_state, teardown_dispatch_state),
        cmocka_unit_test_setup_teardown(test_dispatch_state_invalid, setup_dispatch_state, teardown_dispatch_state),
        cmocka_unit_test_setup_teardown(test_dispatch_state_unable_to_communicate_with_db, setup_dispatch_state, teardown_dispatch_state),
        cmocka_unit_test_setup_teardown(test_dispatch_state_no_response_from_db, setup_dispatch_state, teardown_dispatch_state),
        cmocka_unit_test_setup_teardown(test_dispatch_state_error_parsing_response, setup_dispatch_state, teardown_dispatch_state),

        /* dispatch_clear */
        cmocka_unit_test_setup_teardown(test_dispatch_clear_success, setup_dispatch_clear, teardown_dispatch_clear),
        cmocka_unit_test_setup_teardown(test_dispatch_clear_corrupted_message, setup_dispatch_clear, teardown_dispatch_clear),
        cmocka_unit_test_setup_teardown(test_dispatch_clear_query_too_long, setup_dispatch_clear, teardown_dispatch_clear),
        cmocka_unit_test_setup_teardown(test_dispatch_clear_query_invalid, setup_dispatch_clear, teardown_dispatch_clear),
        cmocka_unit_test_setup_teardown(test_dispatch_clear_unable_to_communicate_with_db, setup_dispatch_clear, teardown_dispatch_clear),
        cmocka_unit_test_setup_teardown(test_dispatch_clear_no_response_from_db, setup_dispatch_clear, teardown_dispatch_clear),
        cmocka_unit_test_setup_teardown(test_dispatch_clear_error_parsing_response, setup_dispatch_clear, teardown_dispatch_clear),

        /* DispatchDBSync */
        cmocka_unit_test_setup_teardown(test_DispatchDBSync_integrity_check_success, setup_DispatchDBSync, teardown_DispatchDBSync),
        cmocka_unit_test_setup_teardown(test_DispatchDBSync_state_success, setup_DispatchDBSync, teardown_DispatchDBSync),
        cmocka_unit_test_setup_teardown(test_DispatchDBSync_integrity_clear_success, setup_DispatchDBSync, teardown_DispatchDBSync),
        cmocka_unit_test_setup_teardown(test_DispatchDBSync_invalid_log, setup_DispatchDBSync, teardown_DispatchDBSync),
        cmocka_unit_test_setup_teardown(test_DispatchDBSync_no_component, setup_DispatchDBSync, teardown_DispatchDBSync),
        cmocka_unit_test_setup_teardown(test_DispatchDBSync_no_type, setup_DispatchDBSync, teardown_DispatchDBSync),
        cmocka_unit_test_setup_teardown(test_DispatchDBSync_invalid_message_type, setup_DispatchDBSync, teardown_DispatchDBSync),
        cmocka_unit_test_setup_teardown(test_DispatchDBSync_null_ctx, setup_DispatchDBSync, teardown_DispatchDBSync),
        cmocka_unit_test_setup_teardown(test_DispatchDBSync_null_lf, setup_DispatchDBSync, teardown_DispatchDBSync),
    };

    return cmocka_run_group_tests(tests, setup_dbsync_context, teardown_dbsync_context);
}
