/**
 * @file dbsync.c
 * @brief Database synchronization decoder
 * @date 2019-09-03
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../eventinfo.h"
#include "wazuhdb_op.h"

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when unit testing */
#define static

/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

static void dispatch_send_local(dbsync_context_t * ctx, const char * query) {
    int sock;

    if (strcmp(ctx->component, "syscheck") == 0) {
        sock = OS_ConnectUnixDomain(SYS_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
    } else {
        merror("dbsync: unknown location '%s'", ctx->component);
        return;
    }

    if (sock == OS_SOCKTERR) {
        merror("dbsync: cannot connect to %s: %s (%d)", ctx->component, strerror(errno), errno);
        return;
    }

    OS_SendSecureTCP(sock, strlen(query), query);
    close(sock);
}

static void dispatch_send_remote(dbsync_context_t * ctx, const char * query, unsigned attempts) {
    if (ctx->ar_sock == -1) {
        ctx->ar_sock = connect_to_remoted();

        if (ctx->ar_sock == -1) {
            return;
        }
    }

    char * buffer;
    os_malloc(OS_MAXSTR, buffer);
    snprintf(buffer, OS_MAXSTR, "%s %s", ctx->component, query);

    if (send_msg_to_agent(ctx->ar_sock, buffer, ctx->agent_id, NULL) == -1) {
        os_free(buffer);
        close(ctx->ar_sock);
        ctx->ar_sock = -1;

        if (attempts > 0) {
            dispatch_send_remote(ctx, query, attempts - 1);
        }
    }

    os_free(buffer);
}

static void dispatch_answer(dbsync_context_t * ctx, const char * result) {
    cJSON_DeleteItemFromObject(ctx->data, "tail");
    cJSON_DeleteItemFromObject(ctx->data, "checksum");

    char * data_plain = cJSON_PrintUnformatted(ctx->data);
    char * query;
    os_malloc(OS_MAXSTR, query);

    // Sample: 'dbsync checksum_fail {"begin":"/a","end":"/z"}'
    if (snprintf(query, OS_MAXSTR, "dbsync %s %s", result, data_plain) >= OS_MAXSTR) {
        merror("dbsync: Cannot build query for agent: query is too long.");
        goto end;
    }

    if (strcmp(ctx->agent_id, "000") == 0) {
        dispatch_send_local(ctx, query);
    } else {
        dispatch_send_remote(ctx, query, 1);
    }

end:
    free(data_plain);
    free(query);
}

static void dispatch_check(dbsync_context_t * ctx, const char * command) {
    if (ctx->data == NULL) {
        merror("dbsync: Corrupt message: cannot get data member.");
        return;
    }

    char * data_plain = cJSON_PrintUnformatted(ctx->data);
    char * query;
    char * response;
    char * arg;

    os_malloc(OS_MAXSTR, query);
    os_malloc(OS_MAXSTR, response);

    if (snprintf(query, OS_MAXSTR, "agent %s %s %s %s", ctx->agent_id, ctx->component, command, data_plain) >= OS_MAXSTR) {
        merror("dbsync: Cannot build check query: input is too long.");
        goto end;
    }

    switch (wdbc_query_ex(&ctx->db_sock, query, response, OS_MAXSTR)) {
    case -2:
        merror("dbsync: Cannot communicate with database.");
        goto end;
    case -1:
        merror("dbsync: Cannot get response from database.");
        goto end;
    }

    switch (wdbc_parse_result(response, &arg)) {
    case WDBC_OK:
        break;
    case WDBC_ERROR:
        merror("dbsync: Bad response from database: %s", arg);
        // Fallthrough
    default:
        goto end;
    }

    if (*arg) {
        dispatch_answer(ctx, arg);
    }

end: // LCOV_EXCL_LINE
    free(data_plain);
    free(query);
    free(response);
}

static void dispatch_state(dbsync_context_t * ctx) {
    if (ctx->data == NULL) {
        merror("dbsync: Corrupt message: cannot get data member.");
        return;
    }

    char * data_plain = cJSON_PrintUnformatted(ctx->data);
    char * query;
    char * response;
    char * arg;

    os_malloc(OS_MAXSTR, query);
    os_malloc(OS_MAXSTR, response);

    if (snprintf(query, OS_MAXSTR, "agent %s %s save2 %s", ctx->agent_id, ctx->component, data_plain) >= OS_MAXSTR) {
        merror("dbsync: Cannot build save query: input is too long.");
        goto end;
    }

    switch (wdbc_query_ex(&ctx->db_sock, query, response, OS_MAXSTR)) {
    case -2:
        merror("dbsync: Cannot communicate with database.");
        goto end;
    case -1:
        merror("dbsync: Cannot get response from database.");
        goto end;
    }

    switch (wdbc_parse_result(response, &arg)) {
    case WDBC_OK:
        break;
    case WDBC_ERROR:
        merror("dbsync: Bad response from database: %s", arg);
        // Fallthrough
    default:
        goto end;
    }

end:
    free(data_plain);
    free(query);
    free(response);
}

static void dispatch_clear(dbsync_context_t * ctx) {
    if (ctx->data == NULL) {
        merror("dbsync: Corrupt message: cannot get data member.");
        return;
    }

    char * data_plain = cJSON_PrintUnformatted(ctx->data);
    char * query;
    char * response;
    char * arg;

    os_malloc(OS_MAXSTR, query);
    os_malloc(OS_MAXSTR, response);

    if (snprintf(query, OS_MAXSTR, "agent %s %s integrity_clear %s", ctx->agent_id, ctx->component, data_plain) >= OS_MAXSTR) {
        merror("dbsync: Cannot build clear query: input is too long.");
        goto end;
    }

    switch (wdbc_query_ex(&ctx->db_sock, query, response, OS_MAXSTR)) {
    case -2:
        merror("dbsync: Cannot communicate with database.");
        goto end;
    case -1:
        merror("dbsync: Cannot get response from database.");
        goto end;
    }

    switch (wdbc_parse_result(response, &arg)) {
    case WDBC_OK:
        break;
    case WDBC_ERROR:
        merror("dbsync: Bad response from database: %s", arg);
        // Fallthrough
    default:
        goto end;
    }

end:
    free(data_plain);
    free(query);
    free(response);
}

void DispatchDBSync(dbsync_context_t * ctx, Eventinfo * lf) {
    assert(ctx != NULL);
    assert(lf != NULL);

    ctx->agent_id = lf->agent_id;

    cJSON * root = cJSON_Parse(lf->log);

    if (root == NULL) {
        merror("dbsync: Cannot parse JSON: %s", lf->log);
        return;
    }

    ctx->component = cJSON_GetStringValue(cJSON_GetObjectItem(root, "component"));
    if (ctx->component == NULL) {
        merror("dbsync: Corrupt message: cannot get component member.");
        goto end;
    }

    char * mtype = cJSON_GetStringValue(cJSON_GetObjectItem(root, "type"));
    if (mtype == NULL) {
        merror("dbsync: Corrupt message: cannot get type member.");
        goto end;
    }

    ctx->data = cJSON_GetObjectItem(root, "data");

    if (strncmp(mtype, "integrity_check_", 16) == 0) {
        dispatch_check(ctx, mtype);
    } else if (strcmp(mtype, "state") == 0) {
        dispatch_state(ctx);
    } else if (strcmp(mtype, "integrity_clear") == 0) {
        dispatch_clear(ctx);
    } else {
        merror("dbsync: Wrong message type '%s' received from agent %s.", mtype, ctx->agent_id);
    }

end:
    cJSON_Delete(root);
}
