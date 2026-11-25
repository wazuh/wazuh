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

#include "../../headers/shared.h"
#include "../../analysisd/rules.h"
#include "../../analysisd/cdb/cdb.h"
#include "../../analysisd/cdb/cdb_make.h"
#include "../../analysisd/analysisd.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>

void os_remove_cdblist(ListNode **l_node);
void os_remove_cdbrules(ListRule **l_rule);
ListNode *OS_FindList(const char *listname, ListNode **l_node);
void OS_ListLoadRules(ListNode **l_node, ListRule **lrule);

void __real_OSMatch_FreePattern(OSMatch *reg);

/* setup/teardown */

typedef struct address_value_state {
    char cdb_path[PATH_MAX];
    ListNode *node;
    ListRule *rule;       // address_match_key_value with check_value "funny"
    ListRule *addr_rule;  // address_match_key over the same list
} address_value_state;

static ListRule *create_list_rule(ListNode *node, int lookup_type) {
    ListRule *rule;
    os_calloc(1, sizeof(ListRule), rule);
    rule->loaded = 1;
    rule->lookup_type = lookup_type;
    rule->field = RULE_SRCIP;
    rule->db = node;
    rule->mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
    return rule;
}

static int teardown_address_match_value(void **state) {
    address_value_state *data = *state;

    os_remove_cdblist(&data->node);
    unlink(data->cdb_path);

    if (data->rule->matcher) {
        __real_OSMatch_FreePattern(data->rule->matcher);
    }
    os_free(data->rule->matcher);
    os_free(data->rule);
    os_free(data->addr_rule);
    os_free(data);
    return 0;
}

/* Builds a CDB list with full addresses and subnet prefixes, including a
 * one-octet prefix, and two rules over it that share the list node. */
static int setup_address_match_value(void **state) {
    address_value_state *data;
    os_calloc(1, sizeof(address_value_state), data);

    snprintf(data->cdb_path, sizeof(data->cdb_path), "/tmp/test_lists_list_XXXXXX");
    int fd = mkstemp(data->cdb_path);
    if (fd < 0) {
        os_free(data);
        return -1;
    }

    FILE *fp = fdopen(fd, "w+");
    if (fp == NULL) {
        close(fd);
        unlink(data->cdb_path);
        os_free(data);
        return -1;
    }

    struct cdb_make cdbm;
    cdb_make_start(&cdbm, fp);
    cdb_make_add(&cdbm, "10.10.10.10", strlen("10.10.10.10"), "funny", strlen("funny"));
    cdb_make_add(&cdbm, "172.16.0.1", strlen("172.16.0.1"), "serious", strlen("serious"));
    cdb_make_add(&cdbm, "192.168.", strlen("192.168."), "funny", strlen("funny"));
    cdb_make_add(&cdbm, "10.20.", strlen("10.20."), "serious", strlen("serious"));
    cdb_make_add(&cdbm, "10.", strlen("10."), "funny", strlen("funny"));
    cdb_make_finish(&cdbm);
    fclose(fp);

    os_calloc(1, sizeof(ListNode), data->node);
    os_strdup(data->cdb_path, data->node->cdb_filename);
    os_strdup("ssh-watch-list", data->node->txt_filename);
    data->node->mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

    data->rule = create_list_rule(data->node, LR_ADDRESS_MATCH_VALUE);
    data->addr_rule = create_list_rule(data->node, LR_ADDRESS_MATCH);

    *state = data;

    os_calloc(1, sizeof(OSMatch), data->rule->matcher);
    if (!OSMatch_Compile("funny", data->rule->matcher, 0)) {
        teardown_address_match_value(state);
        *state = NULL;
        return -1;
    }

    return 0;
}

/* wraps */

void __wrap_OSMatch_FreePattern(OSMatch *reg) {
    return;
}

/* tests */

/* os_remove_cdblist */
void test_os_remove_cdblist_OK(void **state)
{
    ListNode *l_node;
    os_calloc(1,sizeof(ListNode), l_node);
    os_calloc(1,sizeof(ListNode), l_node->cdb_filename);
    os_calloc(1,sizeof(char*), l_node->txt_filename);

    os_remove_cdblist(&l_node);

}

/* os_remove_cdbrules */
void test_os_remove_cdbrules_OK(void **state)
{
    ListRule *l_rule;
    os_calloc(1,sizeof(ListRule), l_rule);
    os_calloc(1,sizeof(ListRule), l_rule->matcher);
    os_calloc(1,sizeof(char*), l_rule->dfield);
    os_calloc(1,sizeof(char*), l_rule->filename);
    os_remove_cdbrules(&l_rule);

}

/* OS_FindList */
void test_OS_FindList_dont_match(void ** state) {

    const char list[] = "list_test.cbd";
    ListNode * node;
    ListNode * retval;

    os_calloc(1, sizeof(ListNode), node);
    node->next = NULL;
    node->txt_filename = "not_list_test.cbd";
    node->cdb_filename = "not_2_list_test.cbd";

    retval = OS_FindList(list, &node);

    assert_null(retval);

    os_free(node);
}

void test_OS_FindList_empty_node(void ** state) {

    const char list[] = "list_test.cbd";
    ListNode * node = NULL;
    ListNode * retval;

    retval = OS_FindList(list, &node);

    assert_null(retval);
}

void test_OS_FindList_txt_match(void ** state) {

    const char list[] = "list_test.cbd";
    ListNode * node;
    os_calloc(1, sizeof(ListNode), node);
    ListNode * retval;
    const ListNode * expect_retval = node;

    node->next = NULL;
    node->txt_filename = "list_test.cbd";
    node->cdb_filename = "not_2_list_test.cbd";

    retval = OS_FindList(list, &node);

    assert_non_null(retval);
    assert_ptr_equal(retval, expect_retval);

    os_free(node);
}

void test_OS_FindList_cdb_match(void ** state) {

    const char list[] = "list_test.cbd";
    ListNode * node;
    os_calloc(1, sizeof(ListNode), node);
    ListNode * retval;
    const ListNode * expect_retval = node;

    node->next = NULL;
    node->txt_filename = "_not_list_test.cbd";
    node->cdb_filename = "list_test.cbd";

    retval = OS_FindList(list, &node);

    assert_non_null(retval);
    assert_ptr_equal(retval, expect_retval);

    os_free(node);
}

/* OS_ListLoadRules */
void test_OS_ListLoadRules_rule_null_check(void ** state) {
    ListNode * l_node = (ListNode *) 1;
    ListRule * lrule = NULL;

    OS_ListLoadRules(&l_node, &lrule);
}

void test_OS_ListLoadRules_list_checked(void ** state) {
    ListRule * lrule;
    ListRule * firstrule;
    ListNode * l_node = NULL;

    os_calloc(1, sizeof(ListRule), lrule);
    firstrule = lrule;
    lrule->next = NULL;
    lrule->loaded = 0;
    lrule->filename = strdup("test_file");

    OS_ListLoadRules(&l_node, &lrule);

    assert_int_equal(firstrule->loaded, 1);
    os_free(firstrule->filename);
    os_free(firstrule);
}

void test_OS_ListLoadRules_list_checked_and_load (void ** state) {
    ListRule * lrule;
    ListRule * firstrule;
    ListNode * l_node = NULL;

    os_calloc(1, sizeof(ListRule), lrule);
    firstrule = lrule;
    lrule->next = NULL;
    lrule->loaded = 0;
    lrule->filename = strdup("list_test.cbd");

    /* OS_FindList */
    ListNode * node;
    os_calloc(1, sizeof(ListNode), node);

    node->next = NULL;
    node->txt_filename = "_not_list_test.cbd";
    node->cdb_filename = "list_test.cbd";

    OS_ListLoadRules(&node, &lrule);

    assert_int_equal(firstrule->loaded, 1);
    os_free(firstrule->filename);
    os_free(firstrule);
    os_free(node);
}

void test_OS_ListLoadRules_already_load(void ** state) {
    ListRule * lrule;
    ListRule * firstrule;
    ListNode * l_node = NULL;

    os_calloc(1, sizeof(ListRule), lrule);
    firstrule = lrule;
    lrule->next = NULL;
    lrule->loaded = 1;

    OS_ListLoadRules(&l_node, &lrule);

    assert_int_equal(firstrule->loaded, 1);
    os_free(firstrule);
    os_free(lrule);
}

/* OS_DBSearch with address_match_key_value */

/* Runs the address_match_key_value rule with another check_value */
static int search_value(address_value_state *data, const char *check_value, char *key) {
    OSMatch matcher = {0};
    OSMatch *saved = data->rule->matcher;
    int result;

    if (!OSMatch_Compile(check_value, &matcher, 0)) {
        fail_msg("Cannot compile '%s'", check_value);
    }

    data->rule->matcher = &matcher;
    result = OS_DBSearch(data->rule, key, &data->node);
    data->rule->matcher = saved;
    __real_OSMatch_FreePattern(&matcher);

    return result;
}

void test_OS_DBSearch_address_match_value_ip_value_match(void **state) {
    address_value_state *data = *state;

    assert_int_equal(OS_DBSearch(data->rule, "10.10.10.10", &data->node), 1);
}

void test_OS_DBSearch_address_match_value_ip_value_mismatch(void **state) {
    address_value_state *data = *state;

    assert_int_equal(OS_DBSearch(data->rule, "172.16.0.1", &data->node), 0);
    // The address is listed: only its value makes the lookup fail
    assert_int_equal(search_value(data, "serious", "172.16.0.1"), 1);
}

void test_OS_DBSearch_address_match_value_subnet_value_match(void **state) {
    address_value_state *data = *state;

    assert_int_equal(OS_DBSearch(data->rule, "192.168.1.25", &data->node), 1);
}

void test_OS_DBSearch_address_match_value_subnet_value_mismatch(void **state) {
    address_value_state *data = *state;

    // The longest prefix "10.20." wins over "10."
    assert_int_equal(OS_DBSearch(data->rule, "10.20.30.40", &data->node), 0);
    assert_int_equal(search_value(data, "serious", "10.20.30.40"), 1);
}

void test_OS_DBSearch_address_match_value_one_octet_prefix(void **state) {
    address_value_state *data = *state;

    assert_int_equal(OS_DBSearch(data->rule, "10.99.1.1", &data->node), 1);
    assert_int_equal(search_value(data, "serious", "10.99.1.1"), 0);
}

void test_OS_DBSearch_address_match_value_not_listed(void **state) {
    address_value_state *data = *state;

    assert_int_equal(OS_DBSearch(data->rule, "8.8.8.8", &data->node), 0);
    assert_int_equal(search_value(data, "serious", "8.8.8.8"), 0);
    assert_int_equal(OS_DBSearch(data->addr_rule, "8.8.8.8", &data->node), 0);
    // The same lookup does find a listed address
    assert_int_equal(OS_DBSearch(data->addr_rule, "172.16.0.1", &data->node), 1);
}

void test_OS_DBSearch_address_match_value_no_list(void **state) {
    address_value_state *data = *state;

    data->rule->db = NULL;

    assert_int_equal(OS_DBSearch(data->rule, "10.10.10.10", &data->node), 0);
}

/* An anchored check_value compares the whole value as a string */
void test_OS_DBSearch_address_match_value_ip_anchored(void **state) {
    address_value_state *data = *state;

    assert_int_equal(search_value(data, "^funny$", "10.10.10.10"), 1);
    assert_int_equal(search_value(data, "funny$", "10.10.10.10"), 1);
    assert_int_equal(search_value(data, "^serious$", "10.10.10.10"), 0);
    assert_int_equal(search_value(data, "^serious$", "172.16.0.1"), 1);
}

void test_OS_DBSearch_address_match_value_subnet_anchored(void **state) {
    address_value_state *data = *state;

    assert_int_equal(search_value(data, "^funny$", "192.168.1.25"), 1);
    assert_int_equal(search_value(data, "funny$", "192.168.1.25"), 1);
    assert_int_equal(search_value(data, "^serious$", "192.168.1.25"), 0);
    assert_int_equal(search_value(data, "serious$", "10.20.30.40"), 1);
}

/* Lookups from several threads on the same list, through two rules that share
 * it, starting before the list is opened */
/* Runs a lookup of the given type over the setup's list, with an optional check_value */
static int search_lookup(address_value_state *data, int lookup_type, const char *check_value, char *key) {
    ListRule *rule = create_list_rule(data->node, lookup_type);
    int result;

    if (check_value) {
        os_calloc(1, sizeof(OSMatch), rule->matcher);
        if (!OSMatch_Compile(check_value, rule->matcher, 0)) {
            fail_msg("Cannot compile '%s'", check_value);
        }
    }

    result = OS_DBSearch(rule, key, &data->node);

    if (rule->matcher) {
        __real_OSMatch_FreePattern(rule->matcher);
        os_free(rule->matcher);
    }
    os_free(rule);

    return result;
}

void test_OS_DBSearch_address_match_value_negated(void **state) {
    address_value_state *data = *state;

    // Listed entries whose value is not "funny" match; unlisted addresses do not
    assert_int_equal(search_value(data, "!funny", "172.16.0.1"), 1);
    assert_int_equal(search_value(data, "!funny", "10.20.30.40"), 1);
    assert_int_equal(search_value(data, "!funny", "10.10.10.10"), 0);
    assert_int_equal(search_value(data, "!funny", "192.168.1.25"), 0);
    assert_int_equal(search_value(data, "!funny", "8.8.8.8"), 0);
}

void test_OS_DBSearch_address_match_value_alternatives(void **state) {
    address_value_state *data = *state;

    assert_int_equal(search_value(data, "serious|funny", "10.10.10.10"), 1);
    assert_int_equal(search_value(data, "serious|funny", "172.16.0.1"), 1);
    assert_int_equal(search_value(data, "serious|funny", "10.20.30.40"), 1);
    assert_int_equal(search_value(data, "serious|funny", "8.8.8.8"), 0);
}

void test_OS_DBSearch_address_prefix_boundaries(void **state) {
    address_value_state *data = *state;

    // A listed address is not a prefix of a longer one
    assert_int_equal(OS_DBSearch(data->addr_rule, "172.16.0.10", &data->node), 0);
    // Prefixes only end at a dot
    assert_int_equal(OS_DBSearch(data->addr_rule, "192.1680.1.1", &data->node), 0);
    // The prefix key itself is listed
    assert_int_equal(OS_DBSearch(data->addr_rule, "192.168.", &data->node), 1);
    // The longest listed prefix gives the value: "10.20." (serious) before "10." (funny)
    assert_int_equal(search_value(data, "^serious$", "10.20.30.40"), 1);
    assert_int_equal(search_value(data, "^funny$", "10.20.30.40"), 0);
}

void test_OS_DBSearch_address_match_value_lazy_load_by_name(void **state) {
    address_value_state *data = *state;

    // Rule as the parser leaves it: not resolved yet, only the list name
    data->rule->loaded = 0;
    data->rule->db = NULL;
    os_strdup("ssh-watch-list", data->rule->filename);

    assert_int_equal(OS_DBSearch(data->rule, "192.168.1.25", &data->node), 1);
    assert_ptr_equal(data->rule->db, data->node);
    assert_int_equal(OS_DBSearch(data->rule, "10.20.30.40", &data->node), 0);

    os_free(data->rule->filename);
}

void test_OS_DBSearch_other_lookups(void **state) {
    address_value_state *data = *state;

    assert_int_equal(search_lookup(data, LR_STRING_MATCH, NULL, "10.10.10.10"), 1);
    assert_int_equal(search_lookup(data, LR_STRING_MATCH, NULL, "10.10.10.100"), 0);
    // match_key compares the whole key: a listed prefix does not match an address
    assert_int_equal(search_lookup(data, LR_STRING_MATCH, NULL, "192.168.1.25"), 0);

    assert_int_equal(search_lookup(data, LR_STRING_NOT_MATCH, NULL, "10.10.10.10"), 0);
    assert_int_equal(search_lookup(data, LR_STRING_NOT_MATCH, NULL, "8.8.8.8"), 1);

    assert_int_equal(search_lookup(data, LR_STRING_MATCH_VALUE, "^funny$", "10.10.10.10"), 1);
    assert_int_equal(search_lookup(data, LR_STRING_MATCH_VALUE, "^funny$", "172.16.0.1"), 0);
    assert_int_equal(search_lookup(data, LR_STRING_MATCH_VALUE, "^funny$", "8.8.8.8"), 0);

    assert_int_equal(search_lookup(data, LR_ADDRESS_MATCH, NULL, "192.168.1.25"), 1);
    assert_int_equal(search_lookup(data, LR_ADDRESS_MATCH, NULL, "8.8.8.8"), 0);

    assert_int_equal(search_lookup(data, LR_ADDRESS_NOT_MATCH, NULL, "10.20.30.40"), 0);
    assert_int_equal(search_lookup(data, LR_ADDRESS_NOT_MATCH, NULL, "8.8.8.8"), 1);
}

#define CONCURRENT_THREADS 4
#define CONCURRENT_ROUNDS 4000

static void *concurrent_lookups(void *arg) {
    address_value_state *data = arg;
    static struct {
        char *key;
        int value_match;
        int address_match;
    } cases[] = {
        {"10.10.10.10", 1, 1},
        {"172.16.0.1", 0, 1},
        {"192.168.1.25", 1, 1},
        {"10.20.30.40", 0, 1},
        {"10.99.1.1", 1, 1},
        {"8.8.8.8", 0, 0},
    };
    intptr_t wrong = 0;

    for (int round = 0; round < CONCURRENT_ROUNDS; round++) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            if (OS_DBSearch(data->rule, cases[i].key, &data->node) != cases[i].value_match) {
                wrong++;
            }
            if (OS_DBSearch(data->addr_rule, cases[i].key, &data->node) != cases[i].address_match) {
                wrong++;
            }
        }
    }

    return (void *) wrong;
}

void test_OS_DBSearch_address_lookups_concurrent(void **state) {
    address_value_state *data = *state;
    pthread_t threads[CONCURRENT_THREADS];
    intptr_t wrong = 0;

    assert_int_equal(data->node->loaded, 0);

    for (int i = 0; i < CONCURRENT_THREADS; i++) {
        assert_int_equal(pthread_create(&threads[i], NULL, concurrent_lookups, data), 0);
    }

    for (int i = 0; i < CONCURRENT_THREADS; i++) {
        void *thread_wrong;
        assert_int_equal(pthread_join(threads[i], &thread_wrong), 0);
        wrong += (intptr_t) thread_wrong;
    }

    assert_int_equal(wrong, 0);
}

/* os_remove_cdblist on a list built by the setup */

static int count_open_fds(void) {
    DIR *dir = opendir("/proc/self/fd");
    struct dirent *entry;
    int count = 0;

    if (dir == NULL) {
        fail_msg("Cannot open /proc/self/fd: %s", strerror(errno));
    }
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') {
            count++;
        }
    }
    closedir(dir);

    return count;
}

void test_os_remove_cdblist_closes_loaded_cdb(void **state) {
    address_value_state *data = *state;

    assert_int_equal(OS_DBSearch(data->addr_rule, "10.10.10.10", &data->node), 1);
    assert_int_equal(data->node->loaded, 1);
    int fd = data->node->cdb.fd;

    os_remove_cdblist(&data->node);

    assert_null(data->node);
    assert_int_equal(fcntl(fd, F_GETFD), -1);
    assert_int_equal(errno, EBADF);
}

void test_os_remove_cdblist_never_loaded(void **state) {
    address_value_state *data = *state;
    int fds = count_open_fds();

    assert_int_equal(data->node->loaded, 0);

    os_remove_cdblist(&data->node);

    assert_null(data->node);
    // Nothing was opened, so nothing (standard input included) is closed
    assert_int_equal(count_open_fds(), fds);
    assert_int_not_equal(fcntl(STDIN_FILENO, F_GETFD), -1);
}

void test_os_remove_cdblist_no_fd_growth(void **state) {
    int fds = -1;

    for (int i = 0; i < 20; i++) {
        assert_int_equal(setup_address_match_value(state), 0);
        address_value_state *data = *state;
        assert_int_equal(OS_DBSearch(data->rule, "192.168.1.25", &data->node), 1);
        assert_int_equal(teardown_address_match_value(state), 0);

        if (fds == -1) {
            fds = count_open_fds();
        } else {
            assert_int_equal(count_open_fds(), fds);
        }
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests os_remove_cdblist
        cmocka_unit_test(test_os_remove_cdblist_OK),
        // Tests os_remove_cdbrules
        cmocka_unit_test(test_os_remove_cdbrules_OK),
        // Tests OS_FindList
        cmocka_unit_test(test_OS_FindList_dont_match),
        cmocka_unit_test(test_OS_FindList_empty_node),
        cmocka_unit_test(test_OS_FindList_cdb_match),
        cmocka_unit_test(test_OS_FindList_txt_match),
        // Tests OS_ListLoadRules
        cmocka_unit_test(test_OS_ListLoadRules_rule_null_check),
        cmocka_unit_test(test_OS_ListLoadRules_list_checked),
        cmocka_unit_test(test_OS_ListLoadRules_list_checked_and_load),
        cmocka_unit_test(test_OS_ListLoadRules_already_load),
        // Tests OS_DBSearch with address_match_key_value
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_ip_value_match, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_ip_value_mismatch, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_subnet_value_match, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_subnet_value_mismatch, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_not_listed, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_no_list, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_one_octet_prefix, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_ip_anchored, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_subnet_anchored, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_negated, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_alternatives, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_prefix_boundaries, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_match_value_lazy_load_by_name, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_other_lookups, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_OS_DBSearch_address_lookups_concurrent, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_os_remove_cdblist_closes_loaded_cdb, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test_setup_teardown(test_os_remove_cdblist_never_loaded, setup_address_match_value, teardown_address_match_value),
        cmocka_unit_test(test_os_remove_cdblist_no_fd_growth),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
