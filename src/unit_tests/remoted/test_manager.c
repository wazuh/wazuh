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
#include "../wrappers/wazuh/shared/agent_op_wrappers.h"
#include "../wrappers/wazuh/remoted/shared_download_wrappers.h"
#include "../wrappers/posix/dirent_wrappers.h"

#include "../remoted/remoted.h"
#include "../remoted/shared_download.h"
#include "../../remoted/manager.c"
/* tests */

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
    os_calloc(4, sizeof(file_sum *), groups[0]->f_sum);
    os_calloc(1, sizeof(file_sum), groups[0]->f_sum[0]);
    os_calloc(1, sizeof(file_sum), groups[0]->f_sum[1]);
    os_calloc(1, sizeof(file_sum), groups[0]->f_sum[2]);
    strncpy(groups[0]->f_sum[0]->sum, "AAAAAAAAAAAAAAAA", 32);
    os_strdup("merged.mg", groups[0]->f_sum[0]->name);
    strncpy(groups[0]->f_sum[1]->sum, "BBBBBBBBBBBBBBBB", 32);
    os_strdup("test_file", groups[0]->f_sum[1]->name);
    strncpy(groups[0]->f_sum[2]->sum, "CCCCCCCCCCCCCCCC", 32);
    os_strdup("agent.conf", groups[0]->f_sum[2]->name);
    groups[1] = NULL;

    return 0;
}

static int test_c_group_teardown(void ** state) {
    int i;
    int j;
    file_sum **f_sum;

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
    file_sum **f_sum;

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


/* Tests lookfor_agent_group */

void test_lookfor_agent_group_set_default_group(void **state)
{
    const char *agent_id = "001";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00\nc2305e0ac17e7176e924294c69cc7a24 merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    agent_group *agt_group = NULL;

    static group_t *test_groups = NULL;
    // groups is a manager.c global variable
    groups = &test_groups;

    expect_string(__wrap_w_parser_get_agent, name, agent_id);
    will_return(__wrap_w_parser_get_agent, agt_group);

    expect_string(__wrap_get_agent_group, id, agent_id);
    will_return(__wrap_get_agent_group, "");
    will_return(__wrap_get_agent_group, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' group is ''");

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' with group '' file 'merged.mg' MD5 'c2305e0ac17e7176e924294c69cc7a24'");

    expect_string(__wrap_set_agent_group, id, agent_id);
    expect_string(__wrap_set_agent_group, group, "default");
    will_return(__wrap_set_agent_group, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Group assigned: 'default'");

    int ret = lookfor_agent_group(agent_id, msg, &r_group);
    assert_int_equal(OS_SUCCESS, ret);
    assert_string_equal(r_group, "default");

    os_free(r_group);
}

void test_lookfor_agent_group_get_group_from_files_yml(void **state)
{
    const char *agent_id = "001";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00\nc2305e0ac17e7176e924294c69cc7a24 merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    agent_group *agt_group;
    os_calloc(1, sizeof(agent_group), agt_group);
    os_strdup("group_from_files", agt_group->group);

    static group_t *test_groups = NULL;
    // groups is a manager.c global variable
    groups = &test_groups;

    expect_string(__wrap_w_parser_get_agent, name, agent_id);
    will_return(__wrap_w_parser_get_agent, agt_group);

    expect_string(__wrap_set_agent_group, id, agent_id);
    expect_string(__wrap_set_agent_group, group, agt_group->group);
    will_return(__wrap_set_agent_group, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' group is 'group_from_files'");

    int ret = lookfor_agent_group(agent_id, msg, &r_group);
    assert_int_equal(OS_SUCCESS, ret);
    assert_string_equal(r_group, agt_group->group);

    os_free(agt_group->group);
    os_free(agt_group);
    os_free(r_group);
}

void test_lookfor_agent_group_msg_without_enter(void **state)
{
    const char *agent_id = "002";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00c2305e0ac17e7176e924294c69cc7a24 merged.mg";
    char *r_group = NULL;

    agent_group *agt_group = NULL;

    static group_t *test_groups = NULL;
    // groups is a manager.c global variable
    groups = &test_groups;

    expect_string(__wrap_w_parser_get_agent, name, agent_id);
    will_return(__wrap_w_parser_get_agent, agt_group);

    expect_string(__wrap_get_agent_group, id, agent_id);
    will_return(__wrap_get_agent_group, "");
    will_return(__wrap_get_agent_group, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '002' group is ''");

    expect_string(__wrap__merror, formatted_msg, "Invalid message from agent ID '002' (strchr \\n)");

    int ret = lookfor_agent_group(agent_id, msg, &r_group);
    assert_int_equal(OS_INVALID, ret);
    assert_null(r_group);
}

void test_lookfor_agent_group_bad_message(void **state)
{
    const char *agent_id = "003";
    char *msg = "Linux |localhost.localdomain\n#c2305e0ac17e7176e924294c69cc7a24 merged.mg\nc2305e0ac17e7176e924294c69cc7a24merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    agent_group *agt_group = NULL;

    static group_t *test_groups = NULL;
    // groups is a manager.c global variable
    groups = &test_groups;

    expect_string(__wrap_w_parser_get_agent, name, agent_id);
    will_return(__wrap_w_parser_get_agent, agt_group);

    expect_string(__wrap_get_agent_group, id, agent_id);
    will_return(__wrap_get_agent_group, "");
    will_return(__wrap_get_agent_group, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '003' group is ''");

    expect_string(__wrap__merror, formatted_msg, "Invalid message from agent ID '003' (strchr ' ')");

    int ret = lookfor_agent_group(agent_id, msg, &r_group);
    assert_int_equal(OS_INVALID, ret);
    assert_null(r_group);
}

void test_lookfor_agent_group_message_without_second_enter(void **state)
{
    const char *agent_id = "004";
    char *msg = "Linux |localhost.localdomain \n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    agent_group *agt_group = NULL;

    static group_t *test_groups = NULL;
    // groups is a manager.c global variable
    groups = &test_groups;

    expect_string(__wrap_w_parser_get_agent, name, agent_id);
    will_return(__wrap_w_parser_get_agent, agt_group);

    expect_string(__wrap_get_agent_group, id, agent_id);
    will_return(__wrap_get_agent_group, "");
    will_return(__wrap_get_agent_group, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '004' group is ''");

    expect_string(__wrap__merror, formatted_msg, "Invalid message from agent ID '004' (strchr \\n)");

    int ret = lookfor_agent_group(agent_id, msg, &r_group);
    assert_int_equal(OS_INVALID, ret);
    assert_null(r_group);
}

void test_c_group_fail(void **state)
{
    const char *group = "test_default";

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test_files");
    files[1] = NULL;

    expect_string(__wrap_w_parser_get_group, name, groups[0]->name);
    will_return(__wrap_w_parser_get_group, NULL);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test_files");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_MergeAppendFile, tag, "test_default");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/test_files'");

    expect_string(__wrap_OS_MoveFile, src, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_OS_MoveFile, dst, "etc/shared/test_default/merged.mg");
    will_return(__wrap_OS_MoveFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/merged.mg'");

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR, true);

    free_strarray(files);
}

void test_c_group_downloaded_file_is_corrupted(void **state)
{
    const char *group = "test_default";

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test_files");
    files[1] = NULL;

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

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR, true);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);

    free_strarray(files);
}

void test_c_group_download_all_files(void **state)
{
    const char *group = "test_default";

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test_files");
    files[1] = NULL;

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

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR, true);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);

    free_strarray(files);
}

void test_c_group_read_directory(void **state)
{
    const char *group = "test_default";

    // Initialize files structure
    char ** files = NULL;
    os_malloc((3) * sizeof(char *), files);
    files[0] = strdup(".");
    files[1] = strdup("test_files");
    files[2] = NULL;

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

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test_files");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test_files");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test_files");
    will_return(__wrap_checkBinaryFile, 1);

    expect_string(__wrap_OSHash_Add, key, "etc/shared/test_default/test_files");
    will_return(__wrap_OSHash_Add, 0);

    expect_string(__wrap__merror, formatted_msg, "Unable to add file 'test_files' to hash table of invalid files.");

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR, false);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);

    free_strarray(files);
}

void test_c_group_invalid_share_file(void **state)
{
    const char *group = "test_default";

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test_files");
    files[1] = NULL;

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

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test_files");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test_files");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test_files");
    will_return(__wrap_checkBinaryFile, 1);

    expect_string(__wrap_OSHash_Add, key, "etc/shared/test_default/test_files");
    will_return(__wrap_OSHash_Add, 0);

    expect_string(__wrap__merror, formatted_msg, "Unable to add file 'test_files' to hash table of invalid files.");

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test_default/merged.mg.tmp");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    expect_string(__wrap_OS_MoveFile, src, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_OS_MoveFile, dst, "etc/shared/test_default/merged.mg");
    will_return(__wrap_OS_MoveFile, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/merged.mg'");

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR, true);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);

    free_strarray(files);
}

void test_c_group_timeout_not_null(void **state)
{
    const char *group = "test_default";

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test_files");
    files[1] = NULL;

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
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test_files");
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
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test_files");
    will_return(__wrap_OSHash_Get, last_modify);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test_files");
    will_return(__wrap_checkBinaryFile, 1);

    expect_any(__wrap_OSHash_Set, self);
    expect_string(__wrap_OSHash_Set, key, "etc/shared/test_default/test_files");
    expect_any(__wrap_OSHash_Set, data);
    will_return(__wrap_OSHash_Set, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "File 'test_files' in group 'test_default' modified but still invalid.");

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR, false);

    os_free(last_modify);
    os_free(r_group->name);
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);

    free_strarray(files);
}

void test_c_group_timeout_not_null_not_binary_file(void **state)
{
    const char *group = "test_default";

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test_files");
    files[1] = NULL;

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
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test_files");
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
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test_files");
    will_return(__wrap_OSHash_Get, last_modify);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test_files");
    will_return(__wrap_checkBinaryFile, 0);

    expect_any(__wrap_OSHash_Delete, self);
    expect_string(__wrap_OSHash_Delete, key, "etc/shared/test_default/test_files");
    will_return(__wrap_OSHash_Delete, NULL);

    expect_string(__wrap__minfo, formatted_msg, "File 'test_files' in group 'test_default' is valid after last modification.");

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR, false);

    os_free(r_group->name);
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);

    free_strarray(files);
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

    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'etc/shared/multi_group_test': No such file or directory");

    c_multi_group(multi_group, _f_sum, hash_multigroup, true);

    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_read_dir_fail(void **state)
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

    expect_string(__wrap__mwarn, formatted_msg, "Could not open directory 'etc/shared/multi_group_test'. Group folder was deleted.");

    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug1, formatted_msg, "At purge_group(): Opening directory: 'queue/agent-groups': No such file or directory");

    /* Open the multi-group files and generate merged */
    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': No such file or directory");

    c_multi_group(multi_group, _f_sum, hash_multigroup, true);

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

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/multi_group_test/agent.conf");
    will_return(__wrap_OSHash_Get, NULL);

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

    /* Open the multi-group files and generate merged */
    will_return(__wrap_opendir, 1);

    char** subdir = NULL;
    expect_string(__wrap_wreaddir, name, "var/multigroups/hash_multi_group_test");
    will_return(__wrap_wreaddir, subdir);

    expect_string(__wrap__mdebug2, formatted_msg, "At c_multi_group(): Could not open directory 'var/multigroups/hash_multi_group_test'");

    c_multi_group(multi_group, _f_sum, hash_multigroup, false);

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

    /* Open the multi-group files and generate merged */
    will_return(__wrap_opendir, 1);

    // Initialize files structure
    char ** subdir = NULL;
    os_malloc(1 * sizeof(char *), subdir);
    subdir[0] = NULL;

    expect_string(__wrap_wreaddir, name, "var/multigroups/hash_multi_group_test");
    will_return(__wrap_wreaddir, subdir);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap_OS_MD5_File, fname, "var/multigroups/hash_multi_group_test/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    c_multi_group(multi_group, _f_sum, hash_multigroup, false);

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
    os_malloc(5 * sizeof(char *), subdir);
    os_strdup("file_1", subdir[0]);
    os_strdup("file_2", subdir[1]);
    os_strdup("agent.conf", subdir[2]);
    subdir[3] = NULL;

    will_return(__wrap_opendir, 1);

    will_return(__wrap_readdir, entry);

    expect_string(__wrap_wreaddir, name, "etc/shared/test");
    will_return(__wrap_wreaddir, subdir);

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

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test/file_1");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_file_1");
    will_return(__wrap_OS_MD5_File, 0);

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test/file_1");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test/file_1");
    will_return(__wrap_checkBinaryFile, 0);

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test/merged.mg.tmp");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test/file_2");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_file_2");
    will_return(__wrap_OS_MD5_File, 0);

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test/file_2");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test/file_2");
    will_return(__wrap_checkBinaryFile, 0);

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test/merged.mg.tmp");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test/agent.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_agent.conf");
    will_return(__wrap_OS_MD5_File, 0);

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test/agent.conf");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test/agent.conf");
    will_return(__wrap_checkBinaryFile, 0);

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test/merged.mg.tmp");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

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
    assert_non_null(groups[1]->f_sum[1]);
    assert_string_equal(groups[1]->f_sum[1]->name, "file_1");
    assert_non_null(groups[1]->f_sum[2]);
    assert_string_equal(groups[1]->f_sum[2]->name, "file_2");
    assert_non_null(groups[1]->f_sum[3]);
    assert_string_equal(groups[1]->f_sum[3]->name, "agent.conf");
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

    // Start c_group
    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test_file_change");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "AAAAAAAAAAAAAAA");
    will_return(__wrap_OS_MD5_File, 0);

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test_file_change");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test_file_change");
    will_return(__wrap_checkBinaryFile, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "BBBBBBBBBBBBB");
    will_return(__wrap_OS_MD5_File, 0);
    // End c_group

    // Start c_group
    expect_string(__wrap_w_parser_get_group, name, "test_default");
    will_return(__wrap_w_parser_get_group, NULL);

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_MergeAppendFile, tag, "test_default");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test_file_change");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "AAAAAAAAAAAAAAA");
    will_return(__wrap_OS_MD5_File, 0);

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test_file_change");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test_file_change");
    will_return(__wrap_checkBinaryFile, 0);

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test_default/merged.mg.tmp");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    expect_string(__wrap_OS_MoveFile, src, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_OS_MoveFile, dst, "etc/shared/test_default/merged.mg");
    will_return(__wrap_OS_MoveFile, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "BBBBBBBBBBBBB");
    will_return(__wrap_OS_MD5_File, 0);
    // End c_group

    expect_string(__wrap__mdebug2, formatted_msg, "Group 'test_default' has changed.");

    will_return(__wrap_readdir, NULL);

    process_groups();

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "merged.mg");
    assert_non_null(groups[0]->f_sum[1]);
    assert_string_equal(groups[0]->f_sum[1]->name, "test_file_change");
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

    // Start c_group
    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/ar.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/test_file");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "BBBBBBBBBBBBBBBB");
    will_return(__wrap_OS_MD5_File, 0);

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test_file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test_file");
    will_return(__wrap_checkBinaryFile, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/agent.conf");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "CCCCCCCCCCCCCCCC");
    will_return(__wrap_OS_MD5_File, 0);

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/agent.conf");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/agent.conf");
    will_return(__wrap_checkBinaryFile, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "AAAAAAAAAAAAAAAA");
    will_return(__wrap_OS_MD5_File, 0);
    // End c_group

    will_return(__wrap_readdir, NULL);

    process_groups();

    assert_non_null(groups[0]);
    assert_string_equal(groups[0]->name, "test_default");
    assert_non_null(groups[0]->f_sum);
    assert_non_null(groups[0]->f_sum[0]);
    assert_string_equal(groups[0]->f_sum[0]->name, "merged.mg");
    assert_non_null(groups[0]->f_sum[1]);
    assert_string_equal(groups[0]->f_sum[1]->name, "test_file");
    assert_non_null(groups[0]->f_sum[1]);
    assert_string_equal(groups[0]->f_sum[2]->name, "agent.conf");
    assert_false(groups[0]->has_changed);
    assert_true(groups[0]->exists);
    assert_null(groups[1]);

    os_free(entry);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests lookfor_agent_group
        cmocka_unit_test(test_lookfor_agent_group_set_default_group),
        cmocka_unit_test(test_lookfor_agent_group_get_group_from_files_yml),
        cmocka_unit_test(test_lookfor_agent_group_msg_without_enter),
        cmocka_unit_test(test_lookfor_agent_group_bad_message),
        cmocka_unit_test(test_lookfor_agent_group_message_without_second_enter),
        // Tests c_group
        cmocka_unit_test_setup_teardown(test_c_group_fail, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_downloaded_file_is_corrupted, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_download_all_files, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_read_directory, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_invalid_share_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_timeout_not_null, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_timeout_not_null_not_binary_file, test_c_group_setup, test_c_group_teardown),
        // Tests c_multi_group
        cmocka_unit_test(test_c_multi_group_hash_multigroup_null),
        cmocka_unit_test(test_c_multi_group_open_directory_fail),
        cmocka_unit_test(test_c_multi_group_read_dir_fail),
        cmocka_unit_test(test_c_multi_group_read_dir_fail_no_entry),
        cmocka_unit_test(test_c_multi_group_Ignore_hidden_files),
        cmocka_unit_test(test_c_multi_group_subdir_fail),
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

    };
    return cmocka_run_group_tests(tests, test_setup_group, test_teardown_group);
}
