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

#include "../wrappers/common.h"
#include "../wrappers/wazuh/os_crypto/sha256_op_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/agent_op_wrappers.h"
#include "../wrappers/wazuh/remoted/shared_download_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"
#include "../wrappers/posix/dirent_wrappers.h"
#include "../wrappers/wazuh/remoted/request_wrappers.h"
#include "../wrappers/wazuh/remoted/remoted_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"

#include "../remoted/remoted.h"
#include "../remoted/shared_download.h"
#include "../../remoted/manager.c"

int lookfor_agent_group(const char *agent_id, char *msg, char **r_group, int* wdb_sock);

/* tests */

#define LONG_PATH "190-characters-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

void keyentry_init(keyentry *key, char *name, char *id, char *ip, char *raw_key) {
    os_calloc(1, sizeof(os_ip), key->ip);
    key->ip->ip = ip ? strdup(ip) : NULL;
    key->name = name ? strdup(name) : NULL;
    key->id = id ? strdup(id) : NULL;
    key->raw_key = raw_key ? strdup(raw_key) : NULL;
}

void free_keyentry(keyentry *key) {
    os_free(key->ip->ip);
    os_free(key->ip);
    os_free(key->name);
    os_free(key->id);
    os_free(key->raw_key);
}

int __wrap_send_msg(const char *msg, ssize_t msg_length) {
    check_expected(msg);
    return 0;
}

static int test_setup_group(void ** state) {
    test_mode = 1;
    return 0;
}

static int test_teardown_group(void ** state) {
    test_mode = 0;
    return 0;
}

static int test_c_group_setup(void ** state) {
    os_calloc(1, (2) * sizeof(group_t *), groups);
    os_calloc(1, sizeof(group_t), groups[0]);
    groups[0]->name = strdup("test_default");
    groups[1] = NULL;

    return 0;
}

static int test_find_group_setup(void ** state) {
    os_calloc(1, (3) * sizeof(group_t *), groups);
    os_calloc(1, sizeof(group_t), groups[0]);
    groups[0]->name = strdup("test_default");
    os_calloc(2, sizeof(file_sum *), groups[0]->f_sum);
    os_calloc(1, sizeof(file_sum), groups[0]->f_sum[0]);
    os_strdup("test_file", groups[0]->f_sum[0]->name);
    strncpy(groups[0]->f_sum[0]->sum, "ABCDEF1234567890", 32);
    os_calloc(1, sizeof(group_t), groups[1]);
    groups[1]->name = strdup("test_test_default");
    os_calloc(2, sizeof(file_sum *), groups[1]->f_sum);
    os_calloc(1, sizeof(file_sum), groups[1]->f_sum[0]);
    os_strdup("test_test_file", groups[1]->f_sum[0]->name);
    strncpy(groups[1]->f_sum[0]->sum, "12345ABCDEF67890", 32);
    groups[2] = NULL;

    return 0;
}

static int test_find_multi_group_setup(void ** state) {
    os_calloc(1, (3) * sizeof(group_t *), multi_groups);
    os_calloc(1, sizeof(group_t), multi_groups[0]);
    multi_groups[0]->name = strdup("test_default2");
    os_calloc(2, sizeof(file_sum *), multi_groups[0]->f_sum);
    os_calloc(1, sizeof(file_sum), multi_groups[0]->f_sum[0]);
    os_strdup("test_file2", multi_groups[0]->f_sum[0]->name);
    strncpy(multi_groups[0]->f_sum[0]->sum, "1234567890ABCDEF", 32);
    os_calloc(1, sizeof(group_t), multi_groups[1]);
    multi_groups[1]->name = strdup("test_test_default2");
    os_calloc(2, sizeof(file_sum *), multi_groups[1]->f_sum);
    os_calloc(1, sizeof(file_sum), multi_groups[1]->f_sum[0]);
    os_strdup("test_test_file2", multi_groups[1]->f_sum[0]->name);
    strncpy(multi_groups[1]->f_sum[0]->sum, "67890ABCDEF12345", 32);
    multi_groups[2] = NULL;

    return 0;
}

static int test_fsum_changed_setup(void ** state) {
    file_sum **f_sum1;
    file_sum **f_sum2;
    os_calloc(3, sizeof(file_sum *), f_sum1);
    os_calloc(1, sizeof(file_sum), f_sum1[0]);
    os_calloc(1, sizeof(file_sum), f_sum1[1]);
    strncpy(f_sum1[0]->sum, "FEDCBA0987654321", 32);
    os_strdup("file1", f_sum1[0]->name);
    strncpy(f_sum1[1]->sum, "0987654321FEDCBA", 32);
    os_strdup("file2", f_sum1[1]->name);
    os_calloc(3, sizeof(file_sum *), f_sum2);
    os_calloc(1, sizeof(file_sum), f_sum2[0]);
    os_calloc(1, sizeof(file_sum), f_sum2[1]);
    strncpy(f_sum2[0]->sum, "0987654321FEDCBA", 32);
    os_strdup("file2", f_sum2[0]->name);
    strncpy(f_sum2[1]->sum, "FEDCBA0987654321", 32);
    os_strdup("file1", f_sum2[1]->name);

    state[0] = f_sum1;
    state[1] = f_sum2;

    return 0;
}

static int test_process_group_setup(void ** state) {
    os_calloc(1, (2) * sizeof(group_t *), groups);
    os_calloc(1, sizeof(group_t), groups[0]);
    groups[0]->name = strdup("test_default");
    os_calloc(2, sizeof(file_sum *), groups[0]->f_sum);
    os_calloc(1, sizeof(file_sum), groups[0]->f_sum[0]);
    strncpy(groups[0]->f_sum[0]->sum, "AAAAAAAAAAAAAAAA", 32);
    os_strdup("merged.mg", groups[0]->f_sum[0]->name);
    groups[1] = NULL;

    return 0;
}

static int test_process_multi_groups_setup(void ** state) {
    os_calloc(1, (2) * sizeof(group_t *), multi_groups);
    os_calloc(1, sizeof(group_t), multi_groups[0]);
    multi_groups[0]->name = strdup("groupA,groupB");
    os_calloc(2, sizeof(file_sum *), multi_groups[0]->f_sum);
    os_calloc(1, sizeof(file_sum), multi_groups[0]->f_sum[0]);
    os_strdup("test_file2", multi_groups[0]->f_sum[0]->name);
    strncpy(multi_groups[0]->f_sum[0]->sum, "1234567890ABCDEF", 32);
    multi_groups[1] = NULL;

    return 0;
}

static int test_process_multi_groups_group_changed_setup(void ** state) {
    os_calloc(1, (2) * sizeof(group_t *), multi_groups);
    os_calloc(1, sizeof(group_t), multi_groups[0]);
    multi_groups[0]->name = strdup("group1,group2");
    os_calloc(2, sizeof(file_sum *), multi_groups[0]->f_sum);
    os_calloc(1, sizeof(file_sum), multi_groups[0]->f_sum[0]);
    os_strdup("test_file2", multi_groups[0]->f_sum[0]->name);
    strncpy(multi_groups[0]->f_sum[0]->sum, "1234567890ABCDEF", 32);
    multi_groups[1] = NULL;

    os_calloc(1, (3) * sizeof(group_t *), groups);
    os_calloc(1, sizeof(group_t), groups[0]);
    groups[0]->name = strdup("group1");
    groups[0]->has_changed = true;
    groups[0]->exists = true;
    os_calloc(1, sizeof(group_t), groups[1]);
    groups[1]->name = strdup("group2");
    groups[1]->has_changed = false;
    groups[1]->exists = true;
    groups[2] = NULL;

    return 0;
}

static int test_process_multi_groups_group_not_changed_setup(void ** state) {

    os_calloc(1, (2) * sizeof(group_t *), multi_groups);
    os_calloc(1, sizeof(group_t), multi_groups[0]);
    multi_groups[0]->name = strdup("group1,group2");
    os_calloc(2, sizeof(file_sum *), multi_groups[0]->f_sum);
    os_calloc(1, sizeof(file_sum), multi_groups[0]->f_sum[0]);
    os_strdup("test_file2", multi_groups[0]->f_sum[0]->name);
    strncpy(multi_groups[0]->f_sum[0]->sum, "1234567890ABCDEF", 32);
    multi_groups[1] = NULL;

    os_calloc(1, (3) * sizeof(group_t *), groups);
    os_calloc(1, sizeof(group_t), groups[0]);
    groups[0]->name = strdup("group1");
    groups[0]->has_changed = false;
    groups[0]->exists = true;
    os_calloc(1, sizeof(group_t), groups[1]);
    groups[1]->name = strdup("group2");
    groups[1]->has_changed = false;
    groups[1]->exists = true;
    groups[2] = NULL;

    return 0;
}

static int test_c_files_setup(void ** state) {
    os_calloc(1, (3) * sizeof(group_t *), groups);
    os_calloc(1, sizeof(group_t), groups[0]);
    groups[0]->name = strdup("test_default");
    os_calloc(2, sizeof(file_sum *), groups[0]->f_sum);
    os_calloc(1, sizeof(file_sum), groups[0]->f_sum[0]);
    os_strdup("test_file", groups[0]->f_sum[0]->name);
    strncpy(groups[0]->f_sum[0]->sum, "ABCDEF1234567890", 32);
    os_calloc(1, sizeof(group_t), groups[1]);
    groups[1]->name = strdup("test_test_default");
    os_calloc(2, sizeof(file_sum *), groups[1]->f_sum);
    os_calloc(1, sizeof(file_sum), groups[1]->f_sum[0]);
    os_strdup("test_test_file", groups[1]->f_sum[0]->name);
    strncpy(groups[1]->f_sum[0]->sum, "12345ABCDEF67890", 32);
    groups[2] = NULL;

    os_calloc(1, (3) * sizeof(group_t *), multi_groups);
    os_calloc(1, sizeof(group_t), multi_groups[0]);
    multi_groups[0]->name = strdup("test_default2");
    os_calloc(2, sizeof(file_sum *), multi_groups[0]->f_sum);
    os_calloc(1, sizeof(file_sum), multi_groups[0]->f_sum[0]);
    os_strdup("test_file2", multi_groups[0]->f_sum[0]->name);
    strncpy(multi_groups[0]->f_sum[0]->sum, "1234567890ABCDEF", 32);
    os_calloc(1, sizeof(group_t), multi_groups[1]);
    multi_groups[1]->name = strdup("test_test_default2");
    os_calloc(2, sizeof(file_sum *), multi_groups[1]->f_sum);
    os_calloc(1, sizeof(file_sum), multi_groups[1]->f_sum[0]);
    os_strdup("test_test_file2", multi_groups[1]->f_sum[0]->name);
    strncpy(multi_groups[1]->f_sum[0]->sum, "67890ABCDEF12345", 32);
    multi_groups[2] = NULL;

    return 0;
}

static int test_c_group_teardown(void ** state) {
    int i;
    int j;
    file_sum **f_sum = NULL;

    if (groups) {
        for (i = 0; groups[i]; i++) {
            free_file_sum(groups[i]->f_sum);
            os_free(groups[i]->name);
            os_free(groups[i]);
        }

        os_free(groups);
    }

    return 0;
}

static int test_c_multi_group_teardown(void ** state) {
    int i;
    int j;
    file_sum **f_sum = NULL;

    if (multi_groups) {
        for (i = 0; multi_groups[i]; i++) {
            free_file_sum(multi_groups[i]->f_sum);
            os_free(multi_groups[i]->name);
            os_free(multi_groups[i]);
        }

        os_free(multi_groups);
    }

    return 0;
}

static int test_fsum_changed_teardown(void ** state) {
    file_sum **f_sum1 = (file_sum **)state[0];
    file_sum **f_sum2 = (file_sum **)state[1];
    free_file_sum(f_sum1);
    free_file_sum(f_sum2);

    return 0;
}

static int test_process_multi_group_check_group_changed_teardown(void ** state) {
    int i;
    int j;

    if (multi_groups) {
        for (i = 0; multi_groups[i]; i++) {
            os_free(multi_groups[i]->name);
            os_free(multi_groups[i]);
        }

        os_free(multi_groups);
    }

    if (groups) {
        for (j = 0; groups[j]; j++) {
            free_file_sum(groups[j]->f_sum);
            os_free(groups[j]->name);
            os_free(groups[j]);
        }

        os_free(groups);
    }

    return 0;
}

static int test_c_files_teardown(void ** state) {
    int i;
    int j;
    file_sum **f_sum = NULL;

    if (groups) {
        for (i = 0; groups[i]; i++) {
            free_file_sum(groups[i]->f_sum);
            os_free(groups[i]->name);
            os_free(groups[i]);
        }

        os_free(groups);
    }

    if (multi_groups) {
        for (i = 0; multi_groups[i]; i++) {
            free_file_sum(multi_groups[i]->f_sum);
            os_free(multi_groups[i]->name);
            os_free(multi_groups[i]);
        }

        os_free(multi_groups);
    }

    return 0;
}

/* Tests lookfor_agent_group */

void test_lookfor_agent_group_with_group()
{
    const int agent_id = 1;
    const char agent_id_str[] = "001";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00\nc2305e0ac17e7176e924294c69cc7a24 merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;
    char *test_group = strdup("TESTGROUP");

    expect_value(__wrap_wdb_get_agent_group, id, agent_id);
    will_return(__wrap_wdb_get_agent_group, test_group);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' group is 'TESTGROUP'");

    int ret = lookfor_agent_group(agent_id_str, msg, &r_group, NULL);
    assert_int_equal(OS_SUCCESS, ret);
    assert_string_equal(r_group, test_group);
}

void test_lookfor_agent_group_null_groups()
{
    const int agent_id = 1;
    const char agent_id_str[] = "001";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00\nc2305e0ac17e7176e924294c69cc7a24 merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    expect_value(__wrap_wdb_get_agent_group, id, agent_id);
    will_return(__wrap_wdb_get_agent_group, NULL);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' with file 'merged.mg' MD5 'c2305e0ac17e7176e924294c69cc7a24'");

    will_return(__wrap_w_is_single_node, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Group assigned: 'default'");

    expect_value(__wrap_wdb_set_agent_groups_csv, id, agent_id);
    will_return(__wrap_wdb_set_agent_groups_csv, 0);

    int ret = lookfor_agent_group(agent_id_str, msg, &r_group, NULL);
    assert_int_equal(OS_SUCCESS, ret);
    assert_string_equal(r_group, "default");

    os_free(r_group);
}

void test_lookfor_agent_group_set_default_group()
{
    const int agent_id = 1;
    const char agent_id_str[] = "001";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00\nc2305e0ac17e7176e924294c69cc7a24 merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    expect_value(__wrap_wdb_get_agent_group, id, agent_id);
    will_return(__wrap_wdb_get_agent_group, NULL);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' with file 'merged.mg' MD5 'c2305e0ac17e7176e924294c69cc7a24'");

    will_return(__wrap_w_is_single_node, 0);

    expect_value(__wrap_wdb_set_agent_groups_csv, id, agent_id);
    will_return(__wrap_wdb_set_agent_groups_csv, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Group assigned: 'default'");

    int ret = lookfor_agent_group(agent_id_str, msg, &r_group, NULL);
    assert_int_equal(OS_SUCCESS, ret);
    assert_string_equal(r_group, "default");

    os_free(r_group);
}

void test_lookfor_agent_group_msg_without_enter()
{
    const int agent_id = 2;
    const char agent_id_str[] = "002";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00c2305e0ac17e7176e924294c69cc7a24 merged.mg";
    char *r_group = NULL;

    expect_value(__wrap_wdb_get_agent_group, id, agent_id);
    will_return(__wrap_wdb_get_agent_group, NULL);

    expect_string(__wrap__merror, formatted_msg, "Invalid message from agent ID '002' (strchr \\n)");

    int ret = lookfor_agent_group(agent_id_str, msg, &r_group, NULL);
    assert_int_equal(OS_INVALID, ret);
    assert_null(r_group);
}

void test_lookfor_agent_group_bad_message()
{
    const int agent_id = 3;
    const char agent_id_str[] = "003";
    char *msg = "Linux |localhost.localdomain\n#c2305e0ac17e7176e924294c69cc7a24 merged.mg\nc2305e0ac17e7176e924294c69cc7a24merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    expect_value(__wrap_wdb_get_agent_group, id, agent_id);
    will_return(__wrap_wdb_get_agent_group, NULL);

     expect_string(__wrap__merror, formatted_msg, "Invalid message from agent ID '003' (strchr ' ')");

    int ret = lookfor_agent_group(agent_id_str, msg, &r_group, NULL);
    assert_int_equal(OS_INVALID, ret);
    assert_null(r_group);
}

void test_lookfor_agent_group_message_without_second_enter()
{
    const int agent_id = 4;
    const char agent_id_str[] = "004";
    char *msg = "Linux |localhost.localdomain \n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    expect_value(__wrap_wdb_get_agent_group, id, agent_id);
    will_return(__wrap_wdb_get_agent_group, NULL);

    expect_string(__wrap__merror, formatted_msg, "Invalid message from agent ID '004' (strchr \\n)");

    int ret = lookfor_agent_group(agent_id_str, msg, &r_group, NULL);
    assert_int_equal(OS_INVALID, ret);
    assert_null(r_group);
}

void test_c_group_fail(void **state)
{
    const char *group = "test_default";

    expect_string(__wrap_w_parser_get_group, name, groups[0]->name);
    will_return(__wrap_w_parser_get_group, NULL);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "At validate_shared_files(): Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_MergeAppendFile, tag, "test_default");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    expect_string(__wrap_OS_MoveFile, src, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_OS_MoveFile, dst, "etc/shared/test_default/merged.mg");
    will_return(__wrap_OS_MoveFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/merged.mg'");

    c_group(group, &groups[0]->f_sum, SHAREDCFG_DIR, true);

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "merged.mg");
    assert_null(groups[0]->f_sum[1]);
    assert_null(groups[1]);

}

void test_c_group_downloaded_file_is_corrupted(void **state)
{
    const char *group = "test_default";

    // Initialize r_group structure
    remote_files_group *r_group = NULL;
    os_malloc(sizeof(remote_files_group), r_group);
    os_strdup("r_group_name", r_group->name);
    os_malloc(sizeof(file), r_group->files);
    os_strdup("r_group->files_name", r_group->files->name);
    os_strdup("r_group->files_url", r_group->files->url);

    r_group->poll = 0;
    r_group->current_polling_time = 0;
    r_group->merge_file_index = 0;
    r_group->merged_is_downloaded = 1;

    expect_string(__wrap_w_parser_get_group, name, groups[0]->name);
    will_return(__wrap_w_parser_get_group, r_group);

    expect_string(__wrap__mdebug1, formatted_msg, "Downloading shared file 'etc/shared/test_default/merged.mg' from 'r_group->files_url'");

    expect_string(__wrap_wurl_request, url, r_group->files->url);
    expect_string(__wrap_wurl_request, dest, "var/download/merged.mg");
    will_return(__wrap_wurl_request, 0);

    expect_string(__wrap_TestUnmergeFiles, finalpath, "var/download/merged.mg");
    will_return(__wrap_TestUnmergeFiles, 0);

    expect_string(__wrap__merror, formatted_msg, "The downloaded file 'var/download/merged.mg' is corrupted.");
    expect_string(__wrap__merror, formatted_msg, "Failed to delete file 'var/download/merged.mg'");

    c_group(group, &groups[0]->f_sum, SHAREDCFG_DIR, true);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);
}

void test_c_group_download_all_files(void **state)
{
    const char *group = "test_default";

    // Initialize r_group structure
    remote_files_group *r_group = NULL;
    os_malloc(sizeof(remote_files_group), r_group);
    os_strdup("r_group_name", r_group->name);

    os_calloc(1, (2) * sizeof(file), r_group->files);
    r_group->files[0].name = strdup("r_group->files_name");
    r_group->files[0].url = strdup("r_group->files_url");;

    r_group->files[1].name = NULL;

    r_group->poll = 0;
    r_group->current_polling_time = 0;
    r_group->merge_file_index = -1;
    r_group->merged_is_downloaded = 1;

    expect_string(__wrap_w_parser_get_group, name, groups[0]->name);
    will_return(__wrap_w_parser_get_group, r_group);

    expect_string(__wrap__mdebug1, formatted_msg, "Downloading shared file 'etc/shared/test_default/r_group->files_name' from 'r_group->files_url'");

    expect_string(__wrap_wurl_request, url, r_group->files->url);
    expect_string(__wrap_wurl_request, dest, "var/download/r_group->files_name");
    will_return(__wrap_wurl_request, 0);

    expect_string(__wrap_OS_MoveFile, src, "var/download/r_group->files_name");
    expect_string(__wrap_OS_MoveFile, dst, "etc/shared/test_default/r_group->files_name");
    will_return(__wrap_OS_MoveFile, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/merged.mg'");

    c_group(group, &groups[0]->f_sum, SHAREDCFG_DIR, true);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);
}

void test_c_group_read_directory(void **state)
{
    const char *group = "test_default";

    // Initialize r_group structure
    remote_files_group *r_group = NULL;
    os_malloc(sizeof(remote_files_group), r_group);
    os_strdup("r_group_name", r_group->name);
    os_malloc(sizeof(file), r_group->files);
    os_strdup("r_group->files_name", r_group->files->name);
    os_strdup("r_group->files_url", r_group->files->url);

    r_group->poll = 0;
    r_group->current_polling_time = 0;
    r_group->merge_file_index = 0;
    r_group->merged_is_downloaded = 0;

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "At validate_shared_files(): Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    c_group(group, &groups[0]->f_sum, SHAREDCFG_DIR, false);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "merged.mg");
    assert_null(groups[0]->f_sum[1]);
    assert_null(groups[1]);
}

void test_c_group_invalid_share_file(void **state)
{
    const char *group = "test_default";

    // Initialize r_group structure
    remote_files_group *r_group = NULL;
    os_malloc(sizeof(remote_files_group), r_group);
    os_strdup("r_group_name", r_group->name);
    os_malloc(sizeof(file), r_group->files);
    os_strdup("r_group->files_name", r_group->files->name);
    os_strdup("r_group->files_url", r_group->files->url);

    r_group->poll = 0;
    r_group->current_polling_time = 0;
    r_group->merge_file_index = 0;
    r_group->merged_is_downloaded = 0;

    expect_string(__wrap_w_parser_get_group, name, groups[0]->name);
    will_return(__wrap_w_parser_get_group, NULL);

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_MergeAppendFile, tag, "test_default");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test_default/merged.mg.tmp");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "At validate_shared_files(): Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_string(__wrap_OS_MoveFile, src, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_OS_MoveFile, dst, "etc/shared/test_default/merged.mg");
    will_return(__wrap_OS_MoveFile, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/merged.mg'");

    c_group(group, &groups[0]->f_sum, SHAREDCFG_DIR, true);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);
}

void test_c_multi_group_hash_multigroup_null(void **state)
{
    char *multi_group = NULL;
    file_sum ***_f_sum = NULL;
    char *hash_multigroup = NULL;

    c_multi_group(multi_group, _f_sum, hash_multigroup, true);
}

void test_c_multi_group_open_directory_fail(void **state)
{
    char *multi_group = NULL;
    file_sum ***_f_sum = NULL;
    char *hash_multigroup = NULL;

    os_strdup("multi_group_test", multi_group);
    os_strdup("multi_group_hash", hash_multigroup);

    will_return(__wrap_cldir_ex, 0);
    will_return(__wrap_opendir, 0);

    will_return(__wrap_strerror, "No such file or directory");

    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    c_multi_group(multi_group, _f_sum, hash_multigroup, true);

    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_call_copy_directory(void **state)
{
    char *multi_group = NULL;
    char *hash_multigroup = NULL;
    file_sum ***_f_sum = NULL;
    os_malloc(sizeof(file_sum *), _f_sum);

    os_strdup("multi_group_test", multi_group);
    os_strdup("multi_group_hash", hash_multigroup);

    will_return(__wrap_cldir_ex, 0);
    will_return(__wrap_opendir, 1);

    expect_string(__wrap_wreaddir, name, "etc/shared/multi_group_test");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mwarn, formatted_msg, "Could not open directory 'etc/shared/multi_group_test'. Group folder was deleted.");

    expect_string(__wrap_wdb_remove_group_db, name, "multi_group_test");
    will_return(__wrap_wdb_remove_group_db, OS_SUCCESS);

    /* Open the multi-group files and generate merged */
    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': No such file or directory");

    c_multi_group(multi_group, _f_sum, hash_multigroup, true);

    os_free(_f_sum);
    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_read_dir_fail_no_entry(void **state)
{
    char *multi_group = NULL;
    file_sum ***_f_sum = NULL;
    char *hash_multigroup = NULL;

    os_strdup("multi_group_test", multi_group);
    os_strdup("multi_group_hash", hash_multigroup);

    will_return(__wrap_cldir_ex, 0);
    will_return(__wrap_opendir, 1);

    expect_string(__wrap_wreaddir, name, "etc/shared/multi_group_test");
    will_return(__wrap_wreaddir, NULL);

    /* Open the multi-group files and generate merged */
    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "Not a directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': Not a directory");

    errno = ENOTDIR;

    c_multi_group(multi_group, _f_sum, hash_multigroup, true);

    errno = 0;

    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_Ignore_hidden_files(void **state)
{
    char *multi_group = NULL;
    file_sum ***_f_sum = NULL;
    char *hash_multigroup = NULL;

    os_strdup("multi_group_test", multi_group);
    os_strdup("multi_group_hash", hash_multigroup);

    will_return(__wrap_cldir_ex, 0);
    will_return(__wrap_opendir, 1);

    char** files = NULL;
    os_malloc(5 * sizeof(char *), files);
    os_strdup(".file_1", files[0]);
    os_strdup("file_2", files[1]);
    os_strdup("agent.conf", files[2]);
    os_strdup("ignore_file", files[3]);
    files[4] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/multi_group_test");
    will_return(__wrap_wreaddir, files);

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/multi_group_test/file_2");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_w_copy_file, src, "etc/shared/multi_group_test/file_2");
    expect_string(__wrap_w_copy_file, dst, "var/multigroups/multi_group_hash/file_2");
    expect_value(__wrap_w_copy_file, mode, 0x63);
    expect_value(__wrap_w_copy_file, silent, 1);
    will_return(__wrap_w_copy_file, 0);


    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/multi_group_test/agent.conf");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_w_copy_file, src, "etc/shared/multi_group_test/agent.conf");
    expect_string(__wrap_w_copy_file, dst, "var/multigroups/multi_group_hash/agent.conf");
    expect_value(__wrap_w_copy_file, mode, 0x61);
    expect_value(__wrap_w_copy_file, silent, 1);
    will_return(__wrap_w_copy_file, 0);

    time_t *last_modify;
    os_calloc(1, sizeof(time_t), last_modify);
    *last_modify = 10000;

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/multi_group_test/ignore_file");
    will_return(__wrap_OSHash_Get, last_modify);

    /* Open the multi-group files and generate merged */
    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': No such file or directory");

    c_multi_group(multi_group, _f_sum, hash_multigroup, true);

    os_free(last_modify);
    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_subdir_fail(void **state)
{
    char *multi_group = NULL;
    file_sum ***_f_sum = NULL;
    char *hash_multigroup = NULL;

    os_strdup("multi_group_test", multi_group);
    os_strdup("hash_multi_group_test",hash_multigroup);

    will_return(__wrap_cldir_ex, 0);

    /* Open the multi-group files and generate merged */
    will_return(__wrap_opendir, 1);

    // Start copy_directory function
    expect_string(__wrap_wreaddir, name, "etc/shared/multi_group_test");
    will_return(__wrap_wreaddir, NULL);

    errno = 1;
    expect_string(__wrap__mwarn, formatted_msg, "Could not open directory 'etc/shared/multi_group_test'. Group folder was deleted.");

    // End copy_directory function

    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "ERROR");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': ERROR");

    c_multi_group(multi_group, _f_sum, hash_multigroup, true);

    errno = 0;
    os_free(_f_sum);
    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_call_c_group(void **state)
{
    char *multi_group = NULL;
    file_sum ***_f_sum = NULL;
    os_malloc(sizeof(file_sum *), _f_sum);

    char *hash_multigroup = NULL;

    os_strdup("multi_group_test", multi_group);
    os_strdup("hash_multi_group_test",hash_multigroup);

    will_return(__wrap_cldir_ex, 0);

    /* Open the multi-group files and generate merged */
    will_return(__wrap_opendir, 1);

    // Start copy_directory function
    expect_string(__wrap_wreaddir, name, "etc/shared/multi_group_test");
    will_return(__wrap_wreaddir, NULL);

    errno = 1;
    expect_string(__wrap__mwarn, formatted_msg, "Could not open directory 'etc/shared/multi_group_test'. Group folder was deleted.");

    expect_string(__wrap_wdb_remove_group_db, name, "multi_group_test");
    will_return(__wrap_wdb_remove_group_db, OS_SUCCESS);

    // End copy_directory function

    will_return(__wrap_opendir, 1);

    // Start c_group function
    expect_string(__wrap_w_parser_get_group, name, "hash_multi_group_test");
    will_return(__wrap_w_parser_get_group, NULL);

    expect_string(__wrap_MergeAppendFile, finalpath, "var/multigroups/hash_multi_group_test/merged.mg.tmp");
    expect_string(__wrap_MergeAppendFile, tag, "hash_multi_group_test");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "var/multigroups/hash_multi_group_test");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "At validate_shared_files(): Could not open directory 'var/multigroups/hash_multi_group_test'");
    // End validate_shared_files function

    expect_string(__wrap_OS_MoveFile, src, "var/multigroups/hash_multi_group_test/merged.mg.tmp");
    expect_string(__wrap_OS_MoveFile, dst, "var/multigroups/hash_multi_group_test/merged.mg");
    will_return(__wrap_OS_MoveFile, 0);

    expect_string(__wrap_OS_MD5_File, fname, "var/multigroups/hash_multi_group_test/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test_mult");
    will_return(__wrap_OS_MD5_File, 0);
    // End c_group function

    c_multi_group(multi_group, _f_sum, hash_multigroup, true);

    assert_non_null(_f_sum);
    assert_non_null(_f_sum[0][0]);
    assert_non_null(_f_sum[0][0]);
    assert_string_equal(_f_sum[0][0]->name, "merged.mg");
    assert_string_equal((char *)_f_sum[0][0]->sum, "md5_test_mult");
    assert_null(_f_sum[0][1]);

    errno = 0;
    os_free(_f_sum[0][0]->name);
    os_free(_f_sum[0][0]);
    os_free(_f_sum[0]);
    os_free(_f_sum);
    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_find_group_found(void **state)
{
    group_t *group = find_group("test_default");

    assert_non_null(group);
    assert_string_equal(group->name, "test_default");
    assert_non_null(group->f_sum);
    assert_non_null(group->f_sum[0]);
    assert_string_equal(group->f_sum[0]->name, "test_file");
    assert_string_equal(group->f_sum[0]->sum, "ABCDEF1234567890");
    assert_null(group->f_sum[1]);
}

void test_find_group_not_found(void **state)
{
    group_t *group = find_group("invalid_group");

    assert_null(group);
}

void test_find_multi_group_found(void **state)
{
    group_t *multi_group = find_multi_group("test_default2");

    assert_non_null(multi_group);
    assert_string_equal(multi_group->name, "test_default2");
    assert_non_null(multi_group->f_sum);
    assert_non_null(multi_group->f_sum[0]);
    assert_string_equal(multi_group->f_sum[0]->name, "test_file2");
    assert_string_equal(multi_group->f_sum[0]->sum, "1234567890ABCDEF");
    assert_null(multi_group->f_sum[1]);
}

void test_find_multi_group_not_found(void **state)
{
    group_t *multi_group = find_multi_group("invalid_multi_group");

    assert_null(multi_group);
}

void test_find_group_from_file_found(void **state)
{
    char group_name[OS_SIZE_65536] = {0};
    group_t *group = find_group_from_file("test_file", "ABCDEF1234567890", group_name);

    assert_string_equal(group_name, "test_default");
    assert_non_null(group);
    assert_string_equal(group->name, "test_default");
    assert_non_null(group->f_sum);
    assert_non_null(group->f_sum[0]);
    assert_string_equal(group->f_sum[0]->name, "test_file");
    assert_string_equal(group->f_sum[0]->sum, "ABCDEF1234567890");
    assert_null(group->f_sum[1]);
}

void test_find_group_from_file_not_found(void **state)
{
    char group_name[OS_SIZE_65536] = {0};
    group_t *group = find_group_from_file("invalid_file", "", group_name);

    assert_string_equal(group_name, "\0");
    assert_null(group);
}

void test_find_multi_group_from_file_found(void **state)
{
    char multi_group_name[OS_SIZE_65536] = {0};
    group_t *multi_group = find_multi_group_from_file("test_file2", "1234567890ABCDEF", multi_group_name);

    assert_string_equal(multi_group_name, "test_default2");
    assert_non_null(multi_group);
    assert_string_equal(multi_group->name, "test_default2");
    assert_non_null(multi_group->f_sum);
    assert_non_null(multi_group->f_sum[0]);
    assert_string_equal(multi_group->f_sum[0]->name, "test_file2");
    assert_string_equal(multi_group->f_sum[0]->sum, "1234567890ABCDEF");
    assert_null(multi_group->f_sum[1]);
}

void test_find_multi_group_from_file_not_found(void **state)
{
    char multi_group_name[OS_SIZE_65536] = {0};
    group_t *multi_group = find_multi_group_from_file("invalid_file", "", multi_group_name);

    assert_string_equal(multi_group_name, "\0");
    assert_null(multi_group);
}

void test_fsum_changed_same_fsum(void **state)
{
    file_sum **f_sum1 = (file_sum **)state[0];
    file_sum **f_sum2 = (file_sum **)state[1];

    assert_false(fsum_changed(f_sum1, f_sum2));
}

void test_fsum_changed_different_fsum_sum(void **state)
{
    file_sum **f_sum1 = (file_sum **)state[0];
    file_sum **f_sum2 = (file_sum **)state[1];

    strncpy(f_sum2[1]->sum, "0987654321FEDCAB", 32);

    assert_true(fsum_changed(f_sum1, f_sum2));
}

void test_fsum_changed_different_fsum_name(void **state)
{
    file_sum **f_sum1 = (file_sum **)state[0];
    file_sum **f_sum2 = (file_sum **)state[1];

    os_free(f_sum2[0]->name);
    os_strdup("file3", f_sum2[0]->name);

    assert_true(fsum_changed(f_sum1, f_sum2));
}

void test_fsum_changed_different_size(void **state)
{
    file_sum **f_sum1 = (file_sum **)state[0];
    file_sum **f_sum2 = NULL;

    os_calloc(2, sizeof(file_sum *), f_sum2);
    os_calloc(1, sizeof(file_sum), f_sum2[0]);
    strncpy(f_sum2[0]->sum, "0987654321FEDCBA", 32);
    os_strdup("file2", f_sum2[0]->name);

    assert_true(fsum_changed(f_sum1, f_sum2));

    free_file_sum(f_sum2);
}

void test_fsum_changed_one_null(void **state)
{
    file_sum **f_sum1 = (file_sum **)state[0];
    file_sum **f_sum2 = NULL;

    assert_true(fsum_changed(f_sum1, f_sum2));
}

void test_fsum_changed_both_null(void **state)
{
    file_sum **f_sum1 = NULL;
    file_sum **f_sum2 = NULL;

    assert_false(fsum_changed(f_sum1, f_sum2));
}

void test_group_changed_not_changed(void **state)
{
    groups[0]->exists = true;
    groups[0]->has_changed = false;
    groups[1]->exists = true;
    groups[1]->has_changed = false;

    assert_false(group_changed("test_default,test_test_default"));
}

void test_group_changed_has_changed(void **state)
{
    groups[0]->exists = true;
    groups[0]->has_changed = false;
    groups[1]->exists = true;
    groups[1]->has_changed = true;

    assert_true(group_changed("test_default,test_test_default"));
}

void test_group_changed_not_exists(void **state)
{
    groups[0]->exists = true;
    groups[0]->has_changed = false;
    groups[1]->exists = false;
    groups[1]->has_changed = false;

    assert_true(group_changed("test_default,test_test_default"));
}

void test_group_changed_invalid_group(void **state)
{
    groups[0]->exists = true;
    groups[0]->has_changed = false;
    groups[1]->exists = true;
    groups[1]->has_changed = false;

    assert_true(group_changed("test_default,test_test_default,invalid_group"));
}

void test_process_deleted_groups_delete(void **state)
{
    groups[0]->exists = false;
    groups[0]->has_changed = false;
    groups[1]->exists = true;
    groups[1]->has_changed = false;

    process_deleted_groups();

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "test_test_file");
    assert_string_equal(groups[0]->f_sum[0]->sum, "12345ABCDEF67890");
    assert_null(groups[0]->f_sum[1]);
    assert_false(groups[0]->has_changed);
    assert_false(groups[0]->exists);
    assert_null(groups[1]);
}

void test_process_deleted_groups_no_changes(void **state)
{
    groups[0]->exists = true;
    groups[0]->has_changed = false;
    groups[1]->exists = true;
    groups[1]->has_changed = false;

    process_deleted_groups();

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "test_file");
    assert_string_equal(groups[0]->f_sum[0]->sum, "ABCDEF1234567890");
    assert_null(groups[0]->f_sum[1]);
    assert_false(groups[0]->has_changed);
    assert_false(groups[0]->exists);
    assert_non_null(groups[1]);
    assert_string_equal(groups[1]->name, "test_test_default");
    assert_non_null(groups[1]->f_sum);
    assert_non_null(groups[1]->f_sum[0]);
    assert_string_equal(groups[1]->f_sum[0]->name, "test_test_file");
    assert_string_equal(groups[1]->f_sum[0]->sum, "12345ABCDEF67890");
    assert_null(groups[1]->f_sum[1]);
    assert_false(groups[1]->has_changed);
    assert_false(groups[1]->exists);
    assert_null(groups[2]);
}

void test_process_deleted_multi_groups_delete(void **state)
{
    multi_groups[0]->exists = false;
    multi_groups[0]->has_changed = false;
    multi_groups[1]->exists = true;
    multi_groups[1]->has_changed = false;

    will_return(__wrap_OSHash_Clean, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, NULL);

    expect_any(__wrap_OS_SHA256_String, str);
    will_return(__wrap_OS_SHA256_String, "6e3a107738e7d0fc85241f04ed9686d37738e7d08086fb46e3a100fc85241f04");

    expect_string(__wrap_rmdir_ex, name, "var/multigroups/6e3a1077");
    will_return(__wrap_rmdir_ex, 0);

    process_deleted_multi_groups();

    assert_non_null(multi_groups[0]);
    assert_string_equal(multi_groups[0]->name, "test_test_default2");
    assert_non_null(multi_groups[0]->f_sum);
    assert_non_null(multi_groups[0]->f_sum[0]);
    assert_string_equal(multi_groups[0]->f_sum[0]->name, "test_test_file2");
    assert_string_equal(multi_groups[0]->f_sum[0]->sum, "67890ABCDEF12345");
    assert_null(multi_groups[0]->f_sum[1]);
    assert_false(multi_groups[0]->has_changed);
    assert_false(multi_groups[0]->exists);
    assert_null(multi_groups[1]);
}

void test_process_deleted_multi_groups_no_changes(void **state)
{
    multi_groups[0]->exists = true;
    multi_groups[0]->has_changed = false;
    multi_groups[1]->exists = true;
    multi_groups[1]->has_changed = false;

    will_return(__wrap_OSHash_Clean, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, NULL);

    process_deleted_multi_groups();

    assert_non_null(multi_groups[0]);
    assert_string_equal(multi_groups[0]->name, "test_default2");
    assert_non_null(multi_groups[0]->f_sum);
    assert_non_null(multi_groups[0]->f_sum[0]);
    assert_string_equal(multi_groups[0]->f_sum[0]->name, "test_file2");
    assert_string_equal(multi_groups[0]->f_sum[0]->sum, "1234567890ABCDEF");
    assert_null(multi_groups[0]->f_sum[1]);
    assert_false(multi_groups[0]->has_changed);
    assert_false(multi_groups[0]->exists);
    assert_non_null(multi_groups[1]);
    assert_string_equal(multi_groups[1]->name, "test_test_default2");
    assert_non_null(multi_groups[1]->f_sum);
    assert_non_null(multi_groups[1]->f_sum[0]);
    assert_string_equal(multi_groups[1]->f_sum[0]->name, "test_test_file2");
    assert_string_equal(multi_groups[1]->f_sum[0]->sum, "67890ABCDEF12345");
    assert_null(multi_groups[1]->f_sum[1]);
    assert_false(multi_groups[1]->has_changed);
    assert_false(multi_groups[1]->exists);
    assert_null(multi_groups[2]);
}

void test_process_groups_open_directory_fail(void **state)
{
    will_return(__wrap_opendir, 0);

    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug1, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    process_groups();
}

void test_process_groups_readdir_fail(void **state)
{
    will_return(__wrap_opendir, 1);

    will_return(__wrap_readdir, NULL);

    process_groups();
}

void test_process_groups_subdir_null(void **state)
{
    struct dirent *entry;
    os_calloc(1, sizeof(struct dirent), entry);
    strcpy(entry->d_name, "test");

    will_return(__wrap_opendir, 1);

    will_return(__wrap_readdir, entry);

    expect_string(__wrap_wreaddir, name, "etc/shared/test");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "At process_groups(): Could not open directory 'etc/shared/test'");

    will_return(__wrap_readdir, NULL);

    process_groups();

    os_free(entry);
}

void test_process_groups_skip(void **state)
{
    struct dirent *entry;
    os_calloc(1, sizeof(struct dirent), entry);
    strcpy(entry->d_name, ".");

    will_return(__wrap_opendir, 1);

    will_return(__wrap_readdir, entry);

    will_return(__wrap_readdir, NULL);

    process_groups();

    os_free(entry);
}

void test_process_groups_skip_2(void **state)
{
    struct dirent *entry;
    os_calloc(1, sizeof(struct dirent), entry);
    strcpy(entry->d_name, "..");

    will_return(__wrap_opendir, 1);

    will_return(__wrap_readdir, entry);

    will_return(__wrap_readdir, NULL);

    process_groups();

    os_free(entry);
}

void test_process_groups_find_group_null(void **state)
{
    struct dirent *entry;
    os_calloc(1, sizeof(struct dirent), entry);
    strcpy(entry->d_name, "test");

    char** subdir = NULL;
    os_malloc(2 * sizeof(char *), subdir);
    os_strdup("file_1", subdir[0]);
    subdir[1] = NULL;

    will_return(__wrap_opendir, 1);

    will_return(__wrap_readdir, entry);

    expect_string(__wrap_wreaddir, name, "etc/shared/test");
    will_return(__wrap_wreaddir, subdir);

    // Start c_group function
    expect_string(__wrap_w_parser_get_group, name, "test");
    will_return(__wrap_w_parser_get_group, NULL);

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test/merged.mg.tmp");
    expect_string(__wrap_MergeAppendFile, tag, "test");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "At validate_shared_files(): Could not open directory 'etc/shared/test'");
    // End validate_shared_files function
    // End c_group function

    expect_string(__wrap_OS_MoveFile, src, "etc/shared/test/merged.mg.tmp");
    expect_string(__wrap_OS_MoveFile, dst, "etc/shared/test/merged.mg");
    will_return(__wrap_OS_MoveFile, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_merged");
    will_return(__wrap_OS_MD5_File, 0);

    will_return(__wrap_readdir, NULL);

    process_groups();

    assert_non_null(groups[1]);
    assert_string_equal(groups[1]->name, "test");
    assert_non_null(groups[1]->f_sum);
    assert_non_null(groups[1]->f_sum[0]);
    assert_string_equal(groups[1]->f_sum[0]->name, "merged.mg");
    assert_true(groups[1]->has_changed);
    assert_true(groups[1]->exists);
    assert_null(groups[2]);

    os_free(entry);
}

void test_process_groups_find_group_changed(void **state)
{
    struct dirent *entry;
    os_calloc(1, sizeof(struct dirent), entry);
    strcpy(entry->d_name, "test_default");

    char** subdir = NULL;
    os_malloc(2 * sizeof(char *), subdir);
    os_strdup("test_file_change", subdir[0]);
    subdir[1] = NULL;

    will_return(__wrap_opendir, 1);

    will_return(__wrap_readdir, entry);

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, subdir);

    // Start c_group function
    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "new_md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "At validate_shared_files(): Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function
    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "1212121212121");
    will_return(__wrap_OS_MD5_File, 0);
    // End c_group function

    // Start c_group function
    expect_string(__wrap_w_parser_get_group, name, "test_default");
    will_return(__wrap_w_parser_get_group, NULL);

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_MergeAppendFile, tag, "test_default");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "new_md5_test_2");
    will_return(__wrap_OS_MD5_File, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "At validate_shared_files(): Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function
    expect_string(__wrap_OS_MoveFile, src, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_OS_MoveFile, dst, "etc/shared/test_default/merged.mg");
    will_return(__wrap_OS_MoveFile, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "3434343434343");
    will_return(__wrap_OS_MD5_File, 0);
    // End c_group function

    expect_string(__wrap__mdebug2, formatted_msg, "Group 'test_default' has changed.");

    will_return(__wrap_readdir, NULL);

    process_groups();

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "merged.mg");
    assert_string_equal((char *)groups[0]->f_sum[0]->sum, "3434343434343");
    assert_null(groups[0]->f_sum[1]);
    assert_true(groups[0]->has_changed);
    assert_true(groups[0]->exists);
    assert_null(groups[1]);

    os_free(entry);
}

void test_process_groups_find_group_not_changed(void **state)
{
    struct dirent *entry;
    os_calloc(1, sizeof(struct dirent), entry);
    strcpy(entry->d_name, "test_default");

    char** subdir = NULL;
    os_malloc(4 * sizeof(char *), subdir);
    os_strdup("merged.mg", subdir[0]);
    os_strdup("test_file", subdir[1]);
    os_strdup("agent.conf", subdir[2]);
    subdir[3] = NULL;

    will_return(__wrap_opendir, 1);

    will_return(__wrap_readdir, entry);

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, subdir);

    // Start c_group function
    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "new_md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "At validate_shared_files(): Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function
    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "AAAAAAAAAAAAAAAA");
    will_return(__wrap_OS_MD5_File, 0);
    // End c_group function

    will_return(__wrap_readdir, NULL);

    process_groups();

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "merged.mg");
    assert_null(groups[0]->f_sum[1]);
    assert_false(groups[0]->has_changed);
    assert_true(groups[0]->exists);
    assert_null(groups[1]);

    os_free(entry);
}

void test_process_multi_groups_no_agents(void **state)
{
    expect_value(__wrap_wdb_get_all_agents, include_manager, false);
    will_return(__wrap_wdb_get_all_agents, NULL);

    expect_value(__wrap_OSHash_Begin, self, NULL);
    will_return(__wrap_OSHash_Begin, NULL);

    process_multi_groups();
}

void test_process_multi_groups_single_group(void **state)
{
    int *agents_array = NULL;
    os_calloc(2, sizeof(int), agents_array);
    agents_array[0] = 1;
    agents_array[1] = -1;

    cJSON* j_agent_info = cJSON_Parse("{\"group\":\"group1\",\"group_hash\":\"ec282560\"}");

    expect_value(__wrap_wdb_get_all_agents, include_manager, false);
    will_return(__wrap_wdb_get_all_agents, agents_array);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    expect_value(__wrap_OSHash_Begin, self, NULL);
    will_return(__wrap_OSHash_Begin, NULL);

    process_multi_groups();
}

void test_process_multi_groups_OSHash_Add_fail(void **state)
{
    int *agents_array = NULL;
    os_calloc(2, sizeof(int), agents_array);
    agents_array[0] = 1;
    agents_array[1] = -1;

    cJSON* j_agent_info = cJSON_Parse("[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]");

    expect_value(__wrap_wdb_get_all_agents, include_manager, false);
    will_return(__wrap_wdb_get_all_agents, agents_array);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    m_hash = __real_OSHash_Create();

    expect_value(__wrap_OSHash_Add_ex, self, m_hash);
    expect_string(__wrap_OSHash_Add_ex, key, "group1,group2");
    expect_string(__wrap_OSHash_Add_ex, data, "ef48b4cd");
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Couldn't add multigroup 'group1,group2' to hash table 'm_hash'");

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, NULL);

    process_multi_groups();

    __real_OSHash_Clean(m_hash, cleaner);
}

void test_process_multi_groups_open_fail(void **state)
{
    test_mode = 0;
    int *agents_array = NULL;
    os_calloc(2, sizeof(int), agents_array);
    agents_array[0] = 1;
    agents_array[1] = -1;

    cJSON* j_agent_info = cJSON_Parse("[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]");

    expect_value(__wrap_wdb_get_all_agents, include_manager, false);
    will_return(__wrap_wdb_get_all_agents, agents_array);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    m_hash = __real_OSHash_Create();

    OSHashNode * hash_node;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    w_strdup("group1,group2", hash_node->key);
    hash_node->data = "ef48b4cd";

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, hash_node);

    expect_string(__wrap_wreaddir, name, "var/multigroups/ef48b4cd");
    will_return(__wrap_wreaddir, NULL);
    errno = EACCES;
    will_return(__wrap_strerror, "Permission denied");
    expect_string(__wrap__merror, formatted_msg, "Cannot open multigroup directory 'var/multigroups/ef48b4cd': Permission denied (13)");

    expect_value(__wrap_OSHash_Next, self, m_hash);
    will_return(__wrap_OSHash_Next, NULL);

    process_multi_groups();

    errno = 0;

    os_free(hash_node->key);
    os_free(hash_node);
    __real_OSHash_Clean(m_hash, cleaner);
    test_mode = 1;
}

void test_process_multi_groups_find_multi_group_null(void **state)
{
    test_mode = 0;
    int *agents_array = NULL;
    os_calloc(2, sizeof(int), agents_array);
    agents_array[0] = 1;
    agents_array[1] = -1;

    cJSON* j_agent_info = cJSON_Parse("[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]");

    expect_value(__wrap_wdb_get_all_agents, include_manager, false);
    will_return(__wrap_wdb_get_all_agents, agents_array);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    m_hash = __real_OSHash_Create();

    OSHashNode * hash_node;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    w_strdup("group1,group2", hash_node->key);
    hash_node->data = "ef48b4cd";

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, hash_node);

    char** subdir = NULL;
    os_malloc(2 * sizeof(char *), subdir);
    os_strdup("merged.mg", subdir[0]);
    subdir[1] = NULL;

    expect_string(__wrap_wreaddir, name, "var/multigroups/ef48b4cd");
    will_return(__wrap_wreaddir, subdir);

    // Start c_multi_group
    // Open the multi-group files and generate merged
    will_return(__wrap_cldir_ex, 0);

    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    expect_value(__wrap_OSHash_Next, self, m_hash);
    will_return(__wrap_OSHash_Next, NULL);

    process_multi_groups();

    assert_non_null(multi_groups[1]);
    assert_string_equal(multi_groups[1]->name, "group1,group2");
    assert_true(multi_groups[1]->exists);
    assert_null(multi_groups[2]);

    os_free(hash_node->key);
    os_free(hash_node);
    __real_OSHash_Clean(m_hash, cleaner);
    test_mode = 1;
}

void test_process_multi_groups_group_changed(void **state)
{
    test_mode = 0;
    int *agents_array = NULL;
    os_calloc(2, sizeof(int), agents_array);
    agents_array[0] = 1;
    agents_array[1] = -1;

    cJSON* j_agent_info = cJSON_Parse("[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]");

    expect_value(__wrap_wdb_get_all_agents, include_manager, false);
    will_return(__wrap_wdb_get_all_agents, agents_array);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    m_hash = __real_OSHash_Create();

    OSHashNode * hash_node;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    w_strdup("group1,group2", hash_node->key);
    hash_node->data = "ef48b4cd";

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, hash_node);

    char** subdir = NULL;
    os_malloc(2 * sizeof(char *), subdir);
    os_strdup("merged.mg", subdir[0]);
    subdir[1] = NULL;

    expect_string(__wrap_wreaddir, name, "var/multigroups/ef48b4cd");
    will_return(__wrap_wreaddir, subdir);

    // Start c_multi_group
    // Open the multi-group files and generate merged
    will_return(__wrap_cldir_ex, 0);

    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    expect_string(__wrap__mdebug2, formatted_msg, "Multigroup 'group1,group2' has changed.");

    expect_value(__wrap_OSHash_Next, self, m_hash);
    will_return(__wrap_OSHash_Next, NULL);

    process_multi_groups();

    assert_non_null(multi_groups[0]);
    assert_string_equal(multi_groups[0]->name, "group1,group2");
    assert_null(multi_groups[1]);

    os_free(hash_node->key);
    os_free(hash_node);
    __real_OSHash_Clean(m_hash, cleaner);
    test_mode = 1;
}

void test_process_multi_groups_changed_outside(void **state)
{
    test_mode = 0;
    int *agents_array = NULL;
    os_calloc(2, sizeof(int), agents_array);
    agents_array[0] = 1;
    agents_array[1] = -1;

    cJSON* j_agent_info = cJSON_Parse("[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]");

    expect_value(__wrap_wdb_get_all_agents, include_manager, false);
    will_return(__wrap_wdb_get_all_agents, agents_array);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    m_hash = __real_OSHash_Create();

    OSHashNode * hash_node;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    w_strdup("group1,group2", hash_node->key);
    hash_node->data = "ef48b4cd";

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, hash_node);

    char** subdir = NULL;
    os_malloc(2 * sizeof(char *), subdir);
    os_strdup("merged.mg", subdir[0]);
    subdir[1] = NULL;

    expect_string(__wrap_wreaddir, name, "var/multigroups/ef48b4cd");
    will_return(__wrap_wreaddir, subdir);

    // Start c_multi_group
    // Open the multi-group files, no generate merged
    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': No such file or directory");

    // Open the multi-group files and generate merged
    will_return(__wrap_cldir_ex, 0);

    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    expect_string(__wrap__mwarn, formatted_msg, "Multigroup 'group1,group2' was modified from outside, so it was regenerated.");

    expect_value(__wrap_OSHash_Next, self, m_hash);
    will_return(__wrap_OSHash_Next, NULL);

    process_multi_groups();

    assert_non_null(multi_groups[0]);
    assert_string_equal(multi_groups[0]->name, "group1,group2");
    assert_null(multi_groups[1]);

    os_free(hash_node->key);
    os_free(hash_node);
    __real_OSHash_Clean(m_hash, cleaner);
    test_mode = 1;
}

void test_process_multi_groups_changed_outside_nocmerged(void **state)
{
    test_mode = 0;
    int *agents_array = NULL;
    os_calloc(2, sizeof(int), agents_array);
    agents_array[0] = 1;
    agents_array[1] = -1;

    cJSON* j_agent_info = cJSON_Parse("[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]");

    expect_value(__wrap_wdb_get_all_agents, include_manager, false);
    will_return(__wrap_wdb_get_all_agents, agents_array);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    m_hash = __real_OSHash_Create();

    OSHashNode * hash_node;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    w_strdup("group1,group2", hash_node->key);
    hash_node->data = "ef48b4cd";

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, hash_node);

    char** subdir = NULL;
    os_malloc(2 * sizeof(char *), subdir);
    os_strdup("merged.mg", subdir[0]);
    subdir[1] = NULL;

    expect_string(__wrap_wreaddir, name, "var/multigroups/ef48b4cd");
    will_return(__wrap_wreaddir, subdir);

    // Start c_multi_group
    // Open the multi-group files, no generate merged
    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': No such file or directory");

    expect_string(__wrap__mdebug2, formatted_msg, "Multigroup 'group1,group2' was modified from outside.");
    logr.nocmerged = 1;
    expect_value(__wrap_OSHash_Next, self, m_hash);
    will_return(__wrap_OSHash_Next, NULL);

    process_multi_groups();

    logr.nocmerged = 0;

    assert_non_null(multi_groups[0]);
    assert_string_equal(multi_groups[0]->name, "group1,group2");
    assert_null(multi_groups[1]);

    os_free(hash_node->key);
    os_free(hash_node);
    __real_OSHash_Clean(m_hash, cleaner);
    test_mode = 1;
}

void test_c_files(void **state)
{
    expect_string(__wrap__mdebug2, formatted_msg, "Updating shared files sums.");

    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug1, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    groups[0]->exists = true;
    groups[0]->has_changed = false;
    groups[1]->exists = true;
    groups[1]->has_changed = false;

    multi_groups[0]->exists = true;
    multi_groups[0]->has_changed = false;
    multi_groups[1]->exists = true;
    multi_groups[1]->has_changed = false;

    will_return(__wrap_OSHash_Clean, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, NULL);

    expect_value(__wrap_wdb_get_all_agents, include_manager, false);
    will_return(__wrap_wdb_get_all_agents, NULL);

    m_hash = (OSHash *)1;
    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, NULL);

    expect_string(__wrap__mdebug2, formatted_msg, "End updating shared files sums.");

    c_files();

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "test_file");
    assert_string_equal(groups[0]->f_sum[0]->sum, "ABCDEF1234567890");
    assert_null(groups[0]->f_sum[1]);
    assert_false(groups[0]->has_changed);
    assert_false(groups[0]->exists);
    assert_non_null(groups[1]);
    assert_string_equal(groups[1]->name, "test_test_default");
    assert_non_null(groups[1]->f_sum);
    assert_non_null(groups[1]->f_sum[0]);
    assert_string_equal(groups[1]->f_sum[0]->name, "test_test_file");
    assert_string_equal(groups[1]->f_sum[0]->sum, "12345ABCDEF67890");
    assert_null(groups[1]->f_sum[1]);
    assert_false(groups[1]->has_changed);
    assert_false(groups[1]->exists);
    assert_null(groups[2]);

    assert_non_null(multi_groups[0]);
    assert_string_equal(multi_groups[0]->name, "test_default2");
    assert_non_null(multi_groups[0]->f_sum);
    assert_non_null(multi_groups[0]->f_sum[0]);
    assert_string_equal(multi_groups[0]->f_sum[0]->name, "test_file2");
    assert_string_equal(multi_groups[0]->f_sum[0]->sum, "1234567890ABCDEF");
    assert_null(multi_groups[0]->f_sum[1]);
    assert_false(multi_groups[0]->has_changed);
    assert_false(multi_groups[0]->exists);
    assert_non_null(multi_groups[1]);
    assert_string_equal(multi_groups[1]->name, "test_test_default2");
    assert_non_null(multi_groups[1]->f_sum);
    assert_non_null(multi_groups[1]->f_sum[0]);
    assert_string_equal(multi_groups[1]->f_sum[0]->name, "test_test_file2");
    assert_string_equal(multi_groups[1]->f_sum[0]->sum, "67890ABCDEF12345");
    assert_null(multi_groups[1]->f_sum[1]);
    assert_false(multi_groups[1]->has_changed);
    assert_false(multi_groups[1]->exists);
    assert_null(multi_groups[2]);
}

void test_validate_shared_files_files_null(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "At validate_shared_files(): Could not open directory 'etc/shared/test_default'");

    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_null(groups[1]);
    assert_null(f_sum);
    assert_int_equal(f_size, 0);
}

void test_validate_shared_files_hidden_file(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup(".hidden_file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_null(groups[1]);
    assert_null(f_sum[0]);
    assert_int_equal(f_size, 0);

    free_file_sum(f_sum);
}

void test_validate_shared_files_merged_file(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("merged.mg");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_null(groups[1]);
    assert_null(f_sum[0]);
    assert_int_equal(f_size, 0);

    free_file_sum(f_sum);
}

void test_validate_shared_files_max_path_size_warning(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);
    char log_str[PATH_MAX + 1] = {0};

    snprintf(log_str, PATH_MAX, "At validate_shared_files(): path too long '%s/test-file'", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-files");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, LONG_PATH);
    will_return(__wrap_wreaddir, files);

    expect_string(__wrap__mwarn, formatted_msg, log_str);

    reported_path_size_exceeded = 0;

    validate_shared_files(LONG_PATH, "test_default", "merged_tmp", &f_sum, &f_size, false, -1);

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_null(groups[1]);
    assert_null(f_sum[0]);
    assert_int_equal(f_size, 0);

    free_file_sum(f_sum);
}

void test_validate_shared_files_max_path_size_debug(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);
    char log_str[PATH_MAX + 1] = {0};

    snprintf(log_str, PATH_MAX, "At validate_shared_files(): path too long '%s/test-file'", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-files");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, LONG_PATH);
    will_return(__wrap_wreaddir, files);

    expect_string(__wrap__mdebug2, formatted_msg, log_str);

    reported_path_size_exceeded = 1;

    validate_shared_files(LONG_PATH, "test_default", "merged_tmp", &f_sum, &f_size, false, -1);

    reported_path_size_exceeded = 0;
    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_null(groups[1]);
    assert_null(f_sum[0]);
    assert_int_equal(f_size, 0);

    free_file_sum(f_sum);
}

void test_validate_shared_files_valid_file_limite_size(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);
    char file_str[PATH_MAX + 1] = {0};
    snprintf(file_str, PATH_MAX, "%s/test-file", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, LONG_PATH);
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, file_str);
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, file_str);
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, file_str);
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, file_str);
    will_return(__wrap_checkBinaryFile, 0);

    validate_shared_files(LONG_PATH, "test_default", "merged_tmp", &f_sum, &f_size, false, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, file_str);
    assert_string_equal((char *)groups[0]->f_sum[0]->sum, "md5_test");
    assert_null(groups[0]->f_sum[1]);
    assert_null(groups[1]);
    assert_int_equal(f_size, 1);
}

void test_validate_shared_files_md5_fail(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-file");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test-file");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/test-file'");

    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_null(groups[1]);
    assert_null(f_sum[0]);
    assert_int_equal(f_size, 0);
}

void test_validate_shared_files_still_invalid(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-file");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test-file");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    time_t *last_modify;
    os_calloc(1, sizeof(time_t), last_modify);
    *last_modify = 10000;

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, last_modify);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 1);

    expect_any(__wrap_OSHash_Set, self);
    expect_string(__wrap_OSHash_Set, key, "etc/shared/test_default/test-file");
    expect_any(__wrap_OSHash_Set, data);
    will_return(__wrap_OSHash_Set, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "File 'etc/shared/test_default/test-file' in group 'test_default' modified but still invalid.");

    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_null(groups[1]);
    assert_null(f_sum[0]);
    assert_int_equal(f_size, 0);

    os_free(last_modify);
}

void test_validate_shared_files_valid_now(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-file");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test-file");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    time_t *last_modify;
    os_calloc(1, sizeof(time_t), last_modify);
    *last_modify = 10000;

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, last_modify);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    expect_any(__wrap_OSHash_Delete, self);
    expect_string(__wrap_OSHash_Delete, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Delete, NULL);

    expect_string(__wrap__minfo, formatted_msg, "File 'etc/shared/test_default/test-file' in group 'test_default' is valid after last modification.");

    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "etc/shared/test_default/test-file");
    assert_null(groups[0]->f_sum[1]);
    assert_null(groups[1]);
    assert_int_equal(f_size, 1);
}

void test_validate_shared_files_valid_file(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-file");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test-file");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "etc/shared/test_default/test-file");
    assert_string_equal((char *)groups[0]->f_sum[0]->sum, "md5_test");
    assert_null(groups[0]->f_sum[1]);
    assert_null(groups[1]);
    assert_int_equal(f_size, 1);
}

void test_validate_shared_files_stat_error(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((3) * sizeof(char *), files);
    files[0] = strdup("stat-error-file");
    files[1] = strdup("test-file");
    files[2] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf_err = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/stat-error-file");
    will_return(__wrap_stat, &stat_buf_err);
    will_return(__wrap_stat, -1);

    expect_string(__wrap__merror, formatted_msg, "At validate_shared_files(): Unable to get entry attributes 'etc/shared/test_default/stat-error-file'");

    struct stat stat_buf = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-file");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test-file");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "etc/shared/test_default/test-file");
    assert_string_equal((char *)groups[0]->f_sum[0]->sum, "md5_test");
    assert_null(groups[0]->f_sum[1]);
    assert_null(groups[1]);
    assert_int_equal(f_size, 1);
}

void test_validate_shared_files_merge_file(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-file");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test-file");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    expect_string(__wrap_MergeAppendFile, finalpath, "merged_tmp");
    expect_value(__wrap_MergeAppendFile, path_offset, 0x18);
    will_return(__wrap_MergeAppendFile, 1);

    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, true, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "etc/shared/test_default/test-file");
    assert_string_equal((char *)groups[0]->f_sum[0]->sum, "md5_test");
    assert_null(groups[0]->f_sum[1]);
    assert_null(groups[1]);
    assert_int_equal(f_size, 1);
}

void test_validate_shared_files_fail_add(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-file");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test-file");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 1);

    expect_string(__wrap_OSHash_Add, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Add, 0);

    expect_string(__wrap__merror, formatted_msg, "Unable to add file 'etc/shared/test_default/test-file' to hash table of invalid files.");


    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_null(groups[1]);
    assert_null(f_sum[0]);
    assert_int_equal(f_size, 0);
}

void test_validate_shared_files_subfolder_empty(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-subfolder");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = 0040000 };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "At validate_shared_files(): Could not open directory 'etc/shared/test_default/test-subfolder'");


    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_null(groups[1]);
    assert_null(f_sum[0]);
    assert_int_equal(f_size, 0);
}

void test_validate_shared_files_valid_file_subfolder_empty(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((3) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = strdup("test-subfolder");
    files[2] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-file");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test-file");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    struct stat stat_buf_2 = { .st_mode = S_IFDIR };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_stat, &stat_buf_2);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "At validate_shared_files(): Could not open directory 'etc/shared/test_default/test-subfolder'");


    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "etc/shared/test_default/test-file");
    assert_string_equal((char *)groups[0]->f_sum[0]->sum, "md5_test");
    assert_null(groups[0]->f_sum[1]);
    assert_null(groups[1]);
    assert_int_equal(f_size, 1);
}

void test_validate_shared_files_subfolder_valid_file(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-subfolder");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = S_IFDIR };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    // Initialize files structure
    char ** files2 = NULL;
    os_malloc((2) * sizeof(char *), files2);
    files2[0] = strdup("test-file");
    files2[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_wreaddir, files2);

    struct stat stat_buf_2 = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_stat, &stat_buf_2);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test-subfolder/test-file");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "etc/shared/test_default/test-subfolder/test-file");
    assert_string_equal((char *)groups[0]->f_sum[0]->sum, "md5_test");
    assert_null(groups[0]->f_sum[1]);
    assert_null(groups[1]);
    assert_int_equal(f_size, 1);
}

void test_validate_shared_files_valid_file_subfolder_valid_file(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((3) * sizeof(char *), files);
    files[0] = strdup("test-subfolder");
    files[1] = strdup("test-file-main-folder");
    files[2] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = S_IFDIR };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    // Initialize files structure
    char ** files2 = NULL;
    os_malloc((2) * sizeof(char *), files2);
    files2[0] = strdup("test-file");
    files2[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_wreaddir, files2);

    struct stat stat_buf_2 = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_stat, &stat_buf_2);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test-subfolder/test-file");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    struct stat stat_buf_3 = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-file-main-folder");
    will_return(__wrap_stat, &stat_buf_3);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test-file-main-folder");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_file_main");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file-main-folder");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file-main-folder");
    will_return(__wrap_checkBinaryFile, 0);

    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "etc/shared/test_default/test-subfolder/test-file");
    assert_string_equal((char *)groups[0]->f_sum[0]->sum, "md5_test");
    assert_string_equal(groups[0]->f_sum[1]->name, "etc/shared/test_default/test-file-main-folder");
    assert_string_equal((char *)groups[0]->f_sum[1]->sum, "md5_file_main");
    assert_null(groups[0]->f_sum[2]);
    assert_null(groups[1]);
    assert_int_equal(f_size, 2);
}

void test_validate_shared_files_sub_subfolder_valid_file(void **state)
{
    file_sum **f_sum = NULL;
    unsigned int f_size = 0;
    os_calloc(2, sizeof(file_sum *), f_sum);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-subfolder");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = S_IFDIR };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    // Initialize files structure
    char ** files2 = NULL;
    os_malloc((2) * sizeof(char *), files2);
    files2[0] = strdup("test-subfolder2");
    files2[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_wreaddir, files2);

    struct stat stat_buf_2 = { .st_mode = S_IFDIR };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-subfolder/test-subfolder2");
    will_return(__wrap_stat, &stat_buf_2);
    will_return(__wrap_stat, 0);

    // Initialize files structure
    char ** files3 = NULL;
    os_malloc((2) * sizeof(char *), files3);
    files3[0] = strdup("test-file");
    files3[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default/test-subfolder/test-subfolder2");
    will_return(__wrap_wreaddir, files3);

    struct stat stat_buf_3 = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-subfolder/test-subfolder2/test-file");
    will_return(__wrap_stat, &stat_buf_3);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test-subfolder/test-subfolder2/test-file");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-subfolder/test-subfolder2/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-subfolder/test-subfolder2/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    validate_shared_files("etc/shared/test_default", "test_default", "merged_tmp", &f_sum, &f_size, false, -1);
    groups[0]->f_sum = f_sum;

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "etc/shared/test_default/test-subfolder/test-subfolder2/test-file");
    assert_string_equal((char *)groups[0]->f_sum[0]->sum, "md5_test");
    assert_null(groups[0]->f_sum[1]);
    assert_null(groups[1]);
    assert_int_equal(f_size, 1);
}

void test_copy_directory_files_null_initial(void **state)
{
    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, NULL);

    errno = 1;
    expect_string(__wrap__mwarn, formatted_msg, "Could not open directory 'src_path'. Group folder was deleted.");

    expect_string(__wrap_wdb_remove_group_db, name, "group_test");
    will_return(__wrap_wdb_remove_group_db, OS_SUCCESS);

    copy_directory("src_path", "dst_path", "group_test", true);

}

void test_copy_directory_files_null_not_initial(void **state)
{
    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, NULL);

    errno = 1;
    will_return(__wrap_strerror, "ERROR");
    expect_string(__wrap__mdebug2, formatted_msg, "Could not open directory 'src_path': ERROR (1)");

    copy_directory("src_path", "dst_path", "group_test", false);

}

void test_copy_directory_hidden_file(void **state)
{
    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup(".hidden_file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    copy_directory("src_path", "dst_path", "group_test", true);
}

void test_copy_directory_merged_file(void **state)
{
    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("merged.mg");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    copy_directory("src_path", "dst_path", "group_test", true);
}

void test_copy_directory_source_path_too_long_warning(void **state)
{
    char log_str[PATH_MAX + 1] = {0};
    snprintf(log_str, PATH_MAX, "At copy_directory(): source path too long '%s/test-file'", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-files");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, LONG_PATH);
    will_return(__wrap_wreaddir, files);

    expect_string(__wrap__mwarn, formatted_msg, log_str);

    reported_path_size_exceeded = 0;

    copy_directory(LONG_PATH, "dst_path", "group_test", true);
}

void test_copy_directory_source_path_too_long_debug(void **state)
{
    char log_str[PATH_MAX + 1] = {0};
    snprintf(log_str, PATH_MAX, "At copy_directory(): source path too long '%s/test-file'", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-files");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, LONG_PATH);
    will_return(__wrap_wreaddir, files);

    expect_string(__wrap__mdebug2, formatted_msg, log_str);

    reported_path_size_exceeded = 1;

    copy_directory(LONG_PATH, "dst_path", "group_test", true);

    reported_path_size_exceeded = 0;
}

void test_copy_directory_destination_path_too_long_warning(void **state)
{
    char log_str[PATH_MAX + 1] = {0};
    snprintf(log_str, PATH_MAX, "At copy_directory(): destination path too long '%s/test-file'", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-files");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    expect_string(__wrap__mwarn, formatted_msg, log_str);

    reported_path_size_exceeded = 0;

    copy_directory("src_path", LONG_PATH, "group_test", true);
}

void test_copy_directory_destination_path_too_long_debug(void **state)
{
    char log_str[PATH_MAX + 1] = {0};
    snprintf(log_str, PATH_MAX, "At copy_directory(): destination path too long '%s/test-file'", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-files");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    expect_string(__wrap__mdebug2, formatted_msg, log_str);

    reported_path_size_exceeded = 1;

    copy_directory("src_path", LONG_PATH, "group_test", true);

    reported_path_size_exceeded = 0;
}

void test_copy_directory_invalid_file(void **state)
{
    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    will_return(__wrap_opendir, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    time_t *last_modify;
    os_calloc(1, sizeof(time_t), last_modify);
    *last_modify = 10000;

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "src_path/test-file");
    will_return(__wrap_OSHash_Get, last_modify);

    copy_directory("src_path", "dst_path", "group_test", true);

    os_free(last_modify);
}

void test_copy_directory_agent_conf_file(void **state)
{
    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("agent.conf");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    will_return(__wrap_opendir, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "src_path/agent.conf");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_w_copy_file, src, "src_path/agent.conf");
    expect_string(__wrap_w_copy_file, dst, "dst_path/agent.conf");
    expect_value(__wrap_w_copy_file, mode, 0x61);
    expect_value(__wrap_w_copy_file, silent, 1);
    will_return(__wrap_w_copy_file, 0);

    copy_directory("src_path", "dst_path", "group_test", true);
}

void test_copy_directory_valid_file(void **state)
{
    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    will_return(__wrap_opendir, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "src_path/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_w_copy_file, src, "src_path/test-file");
    expect_string(__wrap_w_copy_file, dst, "dst_path/test-file");
    expect_value(__wrap_w_copy_file, mode, 0x63);
    expect_value(__wrap_w_copy_file, silent, 1);
    will_return(__wrap_w_copy_file, 0);

    copy_directory("src_path", "dst_path", "group_test", true);
}

void test_copy_directory_valid_file_subfolder_file(void **state)
{
    // Initialize files structure
    char ** files = NULL;
    os_malloc((3) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = strdup("subfolder");
    files[2] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    will_return(__wrap_opendir, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "src_path/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_w_copy_file, src, "src_path/test-file");
    expect_string(__wrap_w_copy_file, dst, "dst_path/test-file");
    expect_value(__wrap_w_copy_file, mode, 0x63);
    expect_value(__wrap_w_copy_file, silent, 1);
    will_return(__wrap_w_copy_file, 0);

    will_return(__wrap_opendir, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Making new directory: subfolder");

    expect_string(__wrap_mkdir, __path, "dst_path/subfolder");
    expect_value(__wrap_mkdir, __mode, 0770);
    will_return(__wrap_mkdir, 0);

    // Initialize files structure
    char ** files2 = NULL;
    os_malloc((2) * sizeof(char *), files2);
    files2[0] = strdup("test-file");
    files2[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path/subfolder");
    will_return(__wrap_wreaddir, files2);

    will_return(__wrap_opendir, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "src_path/subfolder/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_w_copy_file, src, "src_path/subfolder/test-file");
    expect_string(__wrap_w_copy_file, dst, "dst_path/subfolder/test-file");
    expect_value(__wrap_w_copy_file, mode, 0x63);
    expect_value(__wrap_w_copy_file, silent, 1);
    will_return(__wrap_w_copy_file, 0);

    copy_directory("src_path", "dst_path", "group_test", true);
}

void test_copy_directory_mkdir_fail(void **state)
{
    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("subfolder");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    will_return(__wrap_opendir, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Making new directory: subfolder");

    expect_string(__wrap_mkdir, __path, "dst_path/subfolder");
    expect_value(__wrap_mkdir, __mode, 0770);
    will_return(__wrap_mkdir, -1);

    errno = 10;
    will_return(__wrap_strerror, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Cannot create directory 'dst_path/subfolder': ERROR (10)");

    copy_directory("src_path", "dst_path", "group_test", true);
    errno = 0;
}

void test_copy_directory_mkdir_exist(void **state)
{
    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("subfolder");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    will_return(__wrap_opendir, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Making new directory: subfolder");

    expect_string(__wrap_mkdir, __path, "dst_path/subfolder");
    expect_value(__wrap_mkdir, __mode, 0770);
    will_return(__wrap_mkdir, -1);

    errno = 17;
    expect_string(__wrap_wreaddir, name, "src_path/subfolder");
    will_return(__wrap_wreaddir, NULL);

    will_return(__wrap_strerror, "ERROR");
    expect_string(__wrap__mdebug2, formatted_msg, "Could not open directory 'src_path/subfolder': ERROR (17)");

    copy_directory("src_path", "dst_path", "group_test", true);
    errno = 0;
}

void test_copy_directory_file_subfolder_file(void **state)
{
    // Initialize files structure
    char ** files = NULL;
    os_malloc((4) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = strdup("subfolder");
    files[2] = strdup("test-file-2");
    files[3] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    will_return(__wrap_opendir, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "src_path/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_w_copy_file, src, "src_path/test-file");
    expect_string(__wrap_w_copy_file, dst, "dst_path/test-file");
    expect_value(__wrap_w_copy_file, mode, 0x63);
    expect_value(__wrap_w_copy_file, silent, 1);
    will_return(__wrap_w_copy_file, 0);

    will_return(__wrap_opendir, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Making new directory: subfolder");

    expect_string(__wrap_mkdir, __path, "dst_path/subfolder");
    expect_value(__wrap_mkdir, __mode, 0770);
    will_return(__wrap_mkdir, 0);

    // Initialize files structure
    char ** files2 = NULL;
    os_malloc((2) * sizeof(char *), files2);
    files2[0] = strdup("test-file");
    files2[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path/subfolder");
    will_return(__wrap_wreaddir, files2);

    will_return(__wrap_opendir, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "src_path/subfolder/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_w_copy_file, src, "src_path/subfolder/test-file");
    expect_string(__wrap_w_copy_file, dst, "dst_path/subfolder/test-file");
    expect_value(__wrap_w_copy_file, mode, 0x63);
    expect_value(__wrap_w_copy_file, silent, 1);
    will_return(__wrap_w_copy_file, 0);

    will_return(__wrap_opendir, 0);

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "src_path/test-file-2");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_w_copy_file, src, "src_path/test-file-2");
    expect_string(__wrap_w_copy_file, dst, "dst_path/test-file-2");
    expect_value(__wrap_w_copy_file, mode, 0x63);
    expect_value(__wrap_w_copy_file, silent, 1);
    will_return(__wrap_w_copy_file, 0);

    copy_directory("src_path", "dst_path", "group_test", true);
}

void test_save_controlmsg_request_error(void **state)
{
    keyentry * key =  NULL;
    char *r_msg = "req ";
    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap__merror, formatted_msg, "Request control format error.");
    expect_string(__wrap__mdebug2, formatted_msg, "r_msg = \"req \"");

    save_controlmsg(key, r_msg, msg_length, wdb_sock);
}


void test_save_controlmsg_request_success(void **state)
{
    char r_msg[OS_SIZE_128] = {0};
    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    strcpy(r_msg, "req payload is here");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);

    expect_string(__wrap_req_save, counter, "payload");
    expect_string(__wrap_req_save, buffer, "is here");
    expect_value(__wrap_req_save, length, OS_SIZE_128 - strlen(HC_REQUEST) - strlen("payload "));
    will_return(__wrap_req_save, 0);

    expect_string(__wrap_rem_inc_recv_ctrl_request, agent_id, "001");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    free_keyentry(&key);
}

void test_save_controlmsg_invalid_msg(void **state)
{

    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, "Invalid message");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, msg, "001");

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    expect_string(__wrap__mwarn, formatted_msg, "Invalid message from agent: 'NEW_AGENT' (001)");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    free_keyentry(&key);
}

void test_save_controlmsg_could_not_add_pending_data(void **state)
{
    test_mode = true;

    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, "Invalid message \n with enter");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, msg, "001");

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    expect_string(__wrap_rem_inc_recv_ctrl_keepalive, agent_id, "001");

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);
    pending_data = OSHash_Create();

    expect_value(__wrap_OSHash_Get, self, pending_data);
    expect_string(__wrap_OSHash_Get, key, "001");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_OSHash_Add, key, "001");
    will_return(__wrap_OSHash_Add, 0);

    expect_string(__wrap__merror, formatted_msg, "Couldn't add pending data into hash table.");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    free_keyentry(&key);
}

void test_save_controlmsg_unable_to_save_last_keepalive(void **state)
{
    test_mode = true;

    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, "Invalid message \n with enter");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, msg, "001");

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    expect_string(__wrap_rem_inc_recv_ctrl_keepalive, agent_id, "001");

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);
    pending_data = OSHash_Create();

    pending_data_t data;
    char * message = strdup("Invalid message \n");
    data.changed = true;
    data.message = message;

    expect_value(__wrap_OSHash_Get, self, pending_data);
    expect_string(__wrap_OSHash_Get, key, "001");
    will_return(__wrap_OSHash_Get, &data);

    expect_value(__wrap_wdb_update_agent_keepalive, id, 1);
    expect_string(__wrap_wdb_update_agent_keepalive, connection_status, AGENT_CS_ACTIVE);
    expect_string(__wrap_wdb_update_agent_keepalive, sync_status, "synced");
    will_return(__wrap_wdb_update_agent_keepalive, OS_INVALID);

    expect_string(__wrap__mwarn, formatted_msg, "Unable to save last keepalive and set connection status as active for agent: 001");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);
    free_keyentry(&key);
    os_free(data.message);
}

void test_save_controlmsg_update_msg_error_parsing(void **state)
{
    test_mode = true;

    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, "valid message \n with enter");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, msg, "001");

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    expect_string(__wrap_rem_inc_recv_ctrl_keepalive, agent_id, "001");

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);
    pending_data = OSHash_Create();

    pending_data_t *data;
    os_calloc(1, sizeof(struct pending_data_t), data);
    char * message = strdup("different message");
    data->changed = true;
    data->message = message;

    expect_value(__wrap_OSHash_Get, self, pending_data);
    expect_string(__wrap_OSHash_Get, key, "001");
    will_return(__wrap_OSHash_Get, data);

    expect_string(__wrap__mdebug2, formatted_msg, "save_controlmsg(): inserting 'valid message \n'");

    static group_t *test_groups = NULL;
    groups = &test_groups;
    multi_groups = &test_groups;

    char* group = NULL;
    w_strdup("test_group", group);
    expect_value(__wrap_wdb_get_agent_group, id, 1);
    will_return(__wrap_wdb_get_agent_group, group);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' group is 'test_group'");

    expect_string(__wrap__mdebug1, formatted_msg, "No such group 'test_group' for agent '001'");

    agent_info_data *agent_data;
    os_calloc(1, sizeof(agent_info_data), agent_data);
    agent_data->id = 1;

    expect_string(__wrap_parse_agent_update_msg, msg, "valid message \n");
    will_return(__wrap_parse_agent_update_msg, agent_data);
    will_return(__wrap_parse_agent_update_msg, OS_INVALID);

    expect_string(__wrap__merror, formatted_msg, "Error parsing message for agent '001'");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    os_free(agent_data);

    free_keyentry(&key);
    os_free(data->message);
    os_free(data->group);
    os_free(data);
}

void test_save_controlmsg_update_msg_unable_to_update_information(void **state)
{
    test_mode = true;

    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, "valid message \n with enter");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, msg, "001");

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    expect_string(__wrap_rem_inc_recv_ctrl_keepalive, agent_id, "001");

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);
    pending_data = OSHash_Create();

    pending_data_t *data;
    os_calloc(1, sizeof(struct pending_data_t), data);
    char * message = strdup("different message");
    data->changed = false;
    data->message = message;

    expect_value(__wrap_OSHash_Get, self, pending_data);
    expect_string(__wrap_OSHash_Get, key, "001");
    will_return(__wrap_OSHash_Get, data);

    expect_string(__wrap__mdebug2, formatted_msg, "save_controlmsg(): inserting 'valid message \n'");

    os_calloc(1, (2) * sizeof(group_t *), groups);
    os_calloc(1, sizeof(group_t), groups[0]);
    groups[0]->name = strdup("test_group");
    groups[0]->has_changed = false;
    groups[0]->exists = true;
    groups[1] = NULL;

    os_calloc(2, sizeof(file_sum *), groups[0]->f_sum);
    os_calloc(1, sizeof(file_sum), groups[0]->f_sum[0]);
    os_strdup("test_group", groups[0]->f_sum[0]->name);
    strncpy(groups[0]->f_sum[0]->sum, "ABCDEF1234567890", 32);
    groups[0]->f_sum[1] = NULL;

    os_calloc(1, (2) * sizeof(group_t *), multi_groups);
    os_calloc(1, sizeof(group_t), multi_groups[0]);
    multi_groups[0]->name = strdup("test_group");
    multi_groups[0]->has_changed = false;
    multi_groups[0]->exists = true;
    multi_groups[1] = NULL;

    char* group = NULL;
    w_strdup("test_group", group);
    expect_value(__wrap_wdb_get_agent_group, id, 1);
    will_return(__wrap_wdb_get_agent_group, group);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' group is 'test_group'");

    agent_info_data *agent_data;
    os_calloc(1, sizeof(agent_info_data), agent_data);
    agent_data->id = 1;
    os_strdup("managerHost", agent_data->manager_host);
    os_strdup("10.2.2.2", agent_data->agent_ip);
    os_strdup("version 4.3", agent_data->version);
    os_strdup("112358", agent_data->merged_sum);

    os_strdup("NodeName", node_name);

    expect_string(__wrap_parse_agent_update_msg, msg, "valid message \n");
    will_return(__wrap_parse_agent_update_msg, agent_data);
    will_return(__wrap_parse_agent_update_msg, OS_SUCCESS);

    expect_any(__wrap_wdb_update_agent_data, agent_data);
    will_return(__wrap_wdb_update_agent_data, OS_INVALID);

    os_calloc(1, sizeof(w_linked_queue_t), pending_queue);

    expect_any(__wrap_linked_queue_push_ex, queue);
    expect_any(__wrap_linked_queue_push_ex, data);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to update information in global.db for agent: 001");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    os_free(agent_data->manager_host);
    os_free(agent_data);

    os_free(node_name);

    free_keyentry(&key);
    os_free(data->message);
    os_free(data->group);
    os_free(data);
}

void test_save_controlmsg_update_msg_lookfor_agent_group_fail(void **state)
{
    test_mode = true;

    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, "valid message \n with enter");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, msg, "001");

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    expect_string(__wrap_rem_inc_recv_ctrl_keepalive, agent_id, "001");

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);
    pending_data = OSHash_Create();

    pending_data_t *data;
    os_calloc(1, sizeof(struct pending_data_t), data);
    char * message = strdup("different message");
    data->changed = false;
    data->message = message;

    expect_value(__wrap_OSHash_Get, self, pending_data);
    expect_string(__wrap_OSHash_Get, key, "001");
    will_return(__wrap_OSHash_Get, data);

    expect_string(__wrap__mdebug2, formatted_msg, "save_controlmsg(): inserting 'valid message \n'");

    expect_value(__wrap_wdb_get_agent_group, id, 1);
    will_return(__wrap_wdb_get_agent_group, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error getting group for agent '001'");

    agent_info_data *agent_data;
    os_calloc(1, sizeof(agent_info_data), agent_data);
    agent_data->id = 1;
    os_strdup("manager_host", agent_data->manager_host);
    os_strdup("10.2.2.2", agent_data->agent_ip);
    os_strdup("version 4.3", agent_data->version);
    os_strdup("112358", agent_data->merged_sum);

    expect_string(__wrap_parse_agent_update_msg, msg, "valid message \n");
    will_return(__wrap_parse_agent_update_msg, agent_data);
    will_return(__wrap_parse_agent_update_msg, OS_SUCCESS);

    expect_any(__wrap_wdb_update_agent_data, agent_data);
    will_return(__wrap_wdb_update_agent_data, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to update information in global.db for agent: 001");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    os_free(agent_data->manager_host);
    os_free(agent_data);

    free_keyentry(&key);
    os_free(data->message);
    os_free(data->group);
    os_free(data);
}

void test_save_controlmsg_startup(void **state)
{
    test_mode = true;
    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, HC_STARTUP);
    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);
    key.peer_info.ss_family = 0;
    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, msg, "001");

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    expect_string(__wrap_rem_inc_recv_ctrl_startup, agent_id, "001");

    expect_string(__wrap__mdebug1, formatted_msg, "Agent NEW_AGENT sent HC_STARTUP from ''");

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);
    pending_data = OSHash_Create();

    pending_data_t data;
    char * message = strdup("startup message \n");
    data.changed = false;
    data.message = message;

    expect_value(__wrap_OSHash_Get, self, pending_data);
    expect_string(__wrap_OSHash_Get, key, "001");
    will_return(__wrap_OSHash_Get, &data);

    expect_value(__wrap_wdb_update_agent_keepalive, id, 1);
    expect_string(__wrap_wdb_update_agent_keepalive, connection_status, AGENT_CS_PENDING);
    expect_string(__wrap_wdb_update_agent_keepalive, sync_status, "synced");
    will_return(__wrap_wdb_update_agent_keepalive, OS_INVALID);

    expect_string(__wrap__mwarn, formatted_msg, "Unable to save last keepalive and set connection status as pending for agent: 001");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    free_keyentry(&key);
    os_free(message);
}

void test_save_controlmsg_shutdown(void **state)
{
    test_mode = true;
    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, HC_SHUTDOWN);
    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);
    memset(&key.peer_info, 0, sizeof(struct sockaddr_storage));
    key.peer_info.ss_family = AF_INET;

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, msg, "001");

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    expect_string(__wrap_rem_inc_recv_ctrl_shutdown, agent_id, "001");

    expect_any(__wrap_get_ipv4_string, address);
    expect_any(__wrap_get_ipv4_string, address_size);
    will_return(__wrap_get_ipv4_string, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent NEW_AGENT sent HC_SHUTDOWN from ''");

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);
    pending_data = OSHash_Create();

    pending_data_t data;
    char * message = strdup("shutdown message \n");
    data.changed = false;
    data.message = message;

    expect_value(__wrap_OSHash_Get, self, pending_data);
    expect_string(__wrap_OSHash_Get, key, "001");
    will_return(__wrap_OSHash_Get, &data);

    expect_value(__wrap_wdb_update_agent_connection_status, id, 1);
    expect_string(__wrap_wdb_update_agent_connection_status, connection_status, AGENT_CS_DISCONNECTED);
    expect_string(__wrap_wdb_update_agent_connection_status, sync_status, "synced");
    will_return(__wrap_wdb_update_agent_connection_status, OS_SUCCESS);

    expect_string(__wrap_SendMSG, message, "1:wazuh-remoted:ossec: Agent stopped: 'NEW_AGENT->10.2.2.5'.");
    expect_string(__wrap_SendMSG, locmsg, "[001] (NEW_AGENT) 10.2.2.5");
    expect_any(__wrap_SendMSG, loc);
    will_return(__wrap_SendMSG, -1);

    will_return(__wrap_strerror, "fail");
    expect_string(__wrap__merror, formatted_msg, "(1210): Queue 'queue/sockets/queue' not accessible: 'fail'");

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, -1);

    expect_string(__wrap__minfo, formatted_msg, "Successfully reconnected to 'queue/sockets/queue'");

    expect_string(__wrap_SendMSG, message, "1:wazuh-remoted:ossec: Agent stopped: 'NEW_AGENT->10.2.2.5'.");
    expect_string(__wrap_SendMSG, locmsg, "[001] (NEW_AGENT) 10.2.2.5");
    expect_any(__wrap_SendMSG, loc);
    will_return(__wrap_SendMSG, -1);

    will_return(__wrap_strerror, "fail");
    expect_string(__wrap__merror, formatted_msg, "(1210): Queue 'queue/sockets/queue' not accessible: 'fail'");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    free_keyentry(&key);
    os_free(message);
}

void test_save_controlmsg_shutdown_wdb_fail(void **state)
{
    test_mode = true;
    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, HC_SHUTDOWN);
    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);
    memset(&key.peer_info, 0, sizeof(struct sockaddr_storage));
    key.peer_info.ss_family = AF_INET6;
    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, msg, "001");

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    expect_string(__wrap_rem_inc_recv_ctrl_shutdown, agent_id, "001");

    expect_any(__wrap_get_ipv6_string, address);
    expect_any(__wrap_get_ipv6_string, address_size);
    will_return(__wrap_get_ipv6_string, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent NEW_AGENT sent HC_SHUTDOWN from ''");

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);
    pending_data = OSHash_Create();

    pending_data_t data;
    char * message = strdup("shutdown message \n");
    data.changed = false;
    data.message = message;

    expect_value(__wrap_OSHash_Get, self, pending_data);
    expect_string(__wrap_OSHash_Get, key, "001");
    will_return(__wrap_OSHash_Get, &data);

    expect_value(__wrap_wdb_update_agent_connection_status, id, 1);
    expect_string(__wrap_wdb_update_agent_connection_status, connection_status, AGENT_CS_DISCONNECTED);
    expect_string(__wrap_wdb_update_agent_connection_status, sync_status, "synced");
    will_return(__wrap_wdb_update_agent_connection_status, OS_INVALID);

    expect_string(__wrap__mwarn, formatted_msg, "Unable to set connection status as disconnected for agent: 001");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    free_keyentry(&key);
    os_free(message);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests lookfor_agent_group
        cmocka_unit_test(test_lookfor_agent_group_set_default_group),
        cmocka_unit_test(test_lookfor_agent_group_null_groups),
        cmocka_unit_test(test_lookfor_agent_group_msg_without_enter),
        cmocka_unit_test(test_lookfor_agent_group_bad_message),
        cmocka_unit_test(test_lookfor_agent_group_message_without_second_enter),
        // Tests c_group
        cmocka_unit_test_setup_teardown(test_c_group_fail, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_downloaded_file_is_corrupted, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_download_all_files, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_read_directory, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_invalid_share_file, test_c_group_setup, test_c_group_teardown),
        // Tests c_multi_group
        cmocka_unit_test(test_c_multi_group_hash_multigroup_null),
        cmocka_unit_test(test_c_multi_group_open_directory_fail),
        cmocka_unit_test(test_c_multi_group_call_copy_directory),
        cmocka_unit_test(test_c_multi_group_call_c_group),
        // Test find_group
        cmocka_unit_test_setup_teardown(test_find_group_found, test_find_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_find_group_not_found, test_find_group_setup, test_c_group_teardown),
        // Test find_multi_group
        cmocka_unit_test_setup_teardown(test_find_multi_group_found, test_find_multi_group_setup, test_c_multi_group_teardown),
        cmocka_unit_test_setup_teardown(test_find_multi_group_not_found, test_find_multi_group_setup, test_c_multi_group_teardown),
        // Test find_group_from_file
        cmocka_unit_test_setup_teardown(test_find_group_from_file_found, test_find_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_find_group_from_file_not_found, test_find_group_setup, test_c_group_teardown),
        // Test find_multi_group_from_file
        cmocka_unit_test_setup_teardown(test_find_multi_group_from_file_found, test_find_multi_group_setup, test_c_multi_group_teardown),
        cmocka_unit_test_setup_teardown(test_find_multi_group_from_file_not_found, test_find_multi_group_setup, test_c_multi_group_teardown),
        // Test fsum_changed
        cmocka_unit_test_setup_teardown(test_fsum_changed_same_fsum, test_fsum_changed_setup, test_fsum_changed_teardown),
        cmocka_unit_test_setup_teardown(test_fsum_changed_different_fsum_sum, test_fsum_changed_setup, test_fsum_changed_teardown),
        cmocka_unit_test_setup_teardown(test_fsum_changed_different_fsum_name, test_fsum_changed_setup, test_fsum_changed_teardown),
        cmocka_unit_test_setup_teardown(test_fsum_changed_different_size, test_fsum_changed_setup, test_fsum_changed_teardown),
        cmocka_unit_test_setup_teardown(test_fsum_changed_one_null, test_fsum_changed_setup, test_fsum_changed_teardown),
        cmocka_unit_test(test_fsum_changed_both_null),
        // Test group_changed
        cmocka_unit_test_setup_teardown(test_group_changed_not_changed, test_find_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_group_changed_has_changed, test_find_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_group_changed_not_exists, test_find_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_group_changed_invalid_group, test_find_group_setup, test_c_group_teardown),
        // Test process_deleted_groups
        cmocka_unit_test_setup_teardown(test_process_deleted_groups_delete, test_find_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_process_deleted_groups_no_changes, test_find_group_setup, test_c_group_teardown),
        // Test process_deleted_multi_groups
        cmocka_unit_test_setup_teardown(test_process_deleted_multi_groups_delete, test_find_multi_group_setup, test_c_multi_group_teardown),
        cmocka_unit_test_setup_teardown(test_process_deleted_multi_groups_no_changes, test_find_multi_group_setup, test_c_multi_group_teardown),
        // Test process_groups
        cmocka_unit_test(test_process_groups_open_directory_fail),
        cmocka_unit_test(test_process_groups_readdir_fail),
        cmocka_unit_test(test_process_groups_subdir_null),
        cmocka_unit_test(test_process_groups_skip),
        cmocka_unit_test(test_process_groups_skip_2),
        cmocka_unit_test_setup_teardown(test_process_groups_find_group_null, test_process_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_process_groups_find_group_changed, test_process_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_process_groups_find_group_not_changed, test_process_group_setup, test_c_group_teardown),
        // Test process_multi_groups
        cmocka_unit_test(test_process_multi_groups_no_agents),
        cmocka_unit_test(test_process_multi_groups_single_group),
        cmocka_unit_test(test_process_multi_groups_OSHash_Add_fail),
        cmocka_unit_test(test_process_multi_groups_open_fail),
        cmocka_unit_test_setup_teardown(test_process_multi_groups_find_multi_group_null, test_process_multi_groups_setup, test_c_multi_group_teardown),
        cmocka_unit_test_setup_teardown(test_process_multi_groups_group_changed, test_process_multi_groups_group_changed_setup, test_process_multi_group_check_group_changed_teardown),
        cmocka_unit_test_setup_teardown(test_process_multi_groups_changed_outside, test_process_multi_groups_group_not_changed_setup, test_process_multi_group_check_group_changed_teardown),
        cmocka_unit_test_setup_teardown(test_process_multi_groups_changed_outside_nocmerged, test_process_multi_groups_group_not_changed_setup, test_process_multi_group_check_group_changed_teardown),
        // Test c_files
        cmocka_unit_test_setup_teardown(test_c_files, test_c_files_setup, test_c_files_teardown),
        // Test validate_shared_files
        cmocka_unit_test_setup_teardown(test_validate_shared_files_files_null, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_hidden_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_merged_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_max_path_size_warning, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_max_path_size_debug, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_valid_file_limite_size, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_md5_fail, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_still_invalid, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_valid_now, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_valid_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_fail_add, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_stat_error, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_merge_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_subfolder_empty, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_valid_file_subfolder_empty, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_subfolder_valid_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_valid_file_subfolder_valid_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_sub_subfolder_valid_file, test_c_group_setup, test_c_group_teardown),
        // Test copy_directory
        cmocka_unit_test(test_copy_directory_files_null_initial),
        cmocka_unit_test(test_copy_directory_files_null_not_initial),
        cmocka_unit_test(test_copy_directory_hidden_file),
        cmocka_unit_test(test_copy_directory_merged_file),
        cmocka_unit_test(test_copy_directory_source_path_too_long_warning),
        cmocka_unit_test(test_copy_directory_source_path_too_long_debug),
        cmocka_unit_test(test_copy_directory_destination_path_too_long_warning),
        cmocka_unit_test(test_copy_directory_destination_path_too_long_debug),
        cmocka_unit_test(test_copy_directory_invalid_file),
        cmocka_unit_test(test_copy_directory_agent_conf_file),
        cmocka_unit_test(test_copy_directory_valid_file),
        cmocka_unit_test(test_copy_directory_valid_file_subfolder_file),
        cmocka_unit_test(test_copy_directory_mkdir_fail),
        cmocka_unit_test(test_copy_directory_mkdir_exist),
        cmocka_unit_test(test_copy_directory_file_subfolder_file),
        // Tests save_controlmsg
        cmocka_unit_test(test_save_controlmsg_request_error),
        cmocka_unit_test(test_save_controlmsg_request_success),
        cmocka_unit_test(test_save_controlmsg_invalid_msg),
        cmocka_unit_test(test_save_controlmsg_could_not_add_pending_data),
        cmocka_unit_test(test_save_controlmsg_unable_to_save_last_keepalive),
        cmocka_unit_test(test_save_controlmsg_update_msg_error_parsing),
        cmocka_unit_test(test_save_controlmsg_update_msg_unable_to_update_information),
        cmocka_unit_test(test_save_controlmsg_update_msg_lookfor_agent_group_fail),
        cmocka_unit_test(test_save_controlmsg_startup),
        cmocka_unit_test(test_save_controlmsg_shutdown),
        cmocka_unit_test(test_save_controlmsg_shutdown_wdb_fail),
    };
    return cmocka_run_group_tests(tests, test_setup_group, test_teardown_group);
}
