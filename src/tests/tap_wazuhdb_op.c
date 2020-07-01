#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../headers/wazuhdb_op.h"
#include "tap.h"


int test_ok_query(int *sock) {

    int ret = 0;
    char *query = "agent 000 syscheck save file 0:0:0:0:0:0:0:0:0:0:0:0:0!0:0 /tmp/test.file";
    char response[OS_SIZE_6144];
    char *message;
    if (wdbc_query_ex(sock, query, response, OS_SIZE_6144) == 0) {
        if (wdbc_parse_result(response, &message) == WDBC_OK) {
            ret = 1;
        }
    }
    return ret;
}


int test_ok2_query(int *sock) {

    int ret = 0;
    char *query = "agent 000 syscheck delete /tmp/test.file";
    char response[OS_SIZE_6144];
    char *message;
    if (wdbc_query_ex(sock, query, response, OS_SIZE_6144) == 0) {
        if (wdbc_parse_result(response, &message) == WDBC_OK) {
            ret = 1;
        }
    }
    return ret;
}


int test_okmsg_query(int *sock) {

    int ret = 0;
    char *query = "agent 000 syscheck scan_info_get start_scan";
    char response[OS_SIZE_6144];
    char *message;
    if (wdbc_query_ex(sock, query, response, OS_SIZE_6144) == 0) {
        if (wdbc_parse_result(response, &message) == WDBC_OK) {
            ret = 1;
        }
    }
    return ret;
}


int test_err_query(int *sock) {

    int ret = 0;
    char *query = "agent 000";
    char response[OS_SIZE_6144];
    char *message;
    if (wdbc_query_ex(sock, query, response, OS_SIZE_6144) == 0) {
        if (wdbc_parse_result(response, &message) == WDBC_ERROR) {
            ret = 1;
        }
    }
    return ret;
}


int main(void) {

    int wdb_sock = -1;

    printf("\n\n   STARTING TEST - WAZUHDB_OS   \n\n");

    TAP_TEST_MSG(test_ok_query(&wdb_sock), "Send query and receive a 'ok' message (Add syscheck entry).");

    TAP_TEST_MSG(test_ok2_query(&wdb_sock), "Send query and receive a 'ok' message (Delete syscheck entry).");

    TAP_TEST_MSG(test_okmsg_query(&wdb_sock), "Send query and receive a message starting with 'ok' (Get syscheck scan info).");

    TAP_TEST_MSG(test_err_query(&wdb_sock), "Send query and receive a message starting with 'err' (Invalid syscheck query syntax).");

    TAP_PLAN;
    int r = tap_summary();
    close(wdb_sock);
    printf("\n   ENDING TEST  - WAZUHDB_OS   \n\n");
    return r;

}
