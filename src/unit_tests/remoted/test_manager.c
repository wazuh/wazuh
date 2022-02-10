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
#include "../wrappers/wazuh/shared/agent_op_wrappers.h"
#include "../wrappers/wazuh/remoted/shared_download_wrappers.h"
#include "../wrappers/posix/dirent_wrappers.h"

#include "../remoted/remoted.h"
#include "../remoted/shared_download.h"
#include "../../remoted/manager.c"
#include "../../headers/hash_op.h"
/* tests */

static int test_c_group_setup(void ** state) {
    test_mode = 1;

    logr.nocmerged = 0;

    // Initialize main groups structure
    os_calloc(1, (2) * sizeof(group_t *), groups);
    os_calloc(1, sizeof(group_t), groups[0]);
    groups[0]->group = strdup("test_default");
    groups[1] = NULL;

    return 0;
}

static int test_c_group_teardown(void ** state) {
    int i;
    int j;
    file_sum **f_sum;

    if (groups) {
        for (i = 0; groups[i]; i++) {
            f_sum = groups[i]->f_sum;

            if (f_sum) {
                for (j = 0; f_sum[j]; j++) {
                    free(f_sum[j]->name);
                    free(f_sum[j]);
                    f_sum[j] = NULL;
                }

                free(f_sum);
                f_sum = NULL;
            }

            free(groups[i]->group);
            free(groups[i]);
        }

        free(groups);
        groups = NULL;
    }

    return 0;
}

static int test_c_multi_group_setup(void ** state) {
    test_mode = 1;
    logr.nocmerged = 0;

    return 0;
}


/* Tests lookfor_agent_group */

void test_lookfor_agent_group_null_groups(void **state)
{
    const char *agent_id = "001";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00\nc2305e0ac17e7176e924294c69cc7a24 merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    expect_string(__wrap_w_parser_get_agent, name, agent_id);
    will_return(__wrap_w_parser_get_agent, NULL);

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

    expect_string(__wrap_w_parser_get_group, name, groups[0]->group);
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

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR);

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

    expect_string(__wrap_w_parser_get_group, name, groups[0]->group);
    will_return(__wrap_w_parser_get_group, r_group);

    expect_string(__wrap__mdebug1, formatted_msg, "Downloading shared file 'etc/shared/test_default/merged.mg' from 'r_group->files_url'");

    expect_string(__wrap_wurl_request, url, r_group->files->url);
    expect_string(__wrap_wurl_request, dest, "var/download/merged.mg");
    will_return(__wrap_wurl_request, 0);

    expect_string(__wrap_TestUnmergeFiles, finalpath, "var/download/merged.mg");
    will_return(__wrap_TestUnmergeFiles, 0);

    expect_string(__wrap__merror, formatted_msg, "The downloaded file 'var/download/merged.mg' is corrupted.");
    expect_string(__wrap__merror, formatted_msg, "Failed to delete file 'var/download/merged.mg'");

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR);

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

    expect_string(__wrap_w_parser_get_group, name, groups[0]->group);
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

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);

    free_strarray(files);
}

void test_c_group_read_directory(void **state)
{
    logr.nocmerged = 1;
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

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);

    free_strarray(files);
}

void test_c_group_timeout_not_null(void **state)
{
    logr.nocmerged = 1;
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

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR);

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
    logr.nocmerged = 1;
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

    c_group(group, files, &groups[0]->f_sum, SHAREDCFG_DIR);

    //os_free(last_modify);
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

    c_multi_group(multi_group, _f_sum, hash_multigroup);
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

    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'etc/shared/multi_group_test': No such file or directory");

    c_multi_group(multi_group, _f_sum, hash_multigroup);

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
    expect_string(__wrap__mdebug1, formatted_msg, "on purge_group(): Opening directory: 'queue/agent-groups': No such file or directory");

    //expect_function_call(__wrap_closedir);

    /* Open the multi-group files and generate merged */
    will_return(__wrap_opendir, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': No such file or directory");

    c_multi_group(multi_group, _f_sum, hash_multigroup);

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

    //expect_function_call(__wrap_closedir);

    /* Open the multi-group files and generate merged */
    will_return(__wrap_opendir, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': No such file or directory");

    c_multi_group(multi_group, _f_sum, hash_multigroup);

    os_free(last_modify);
    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_large_path_fail(void **state)
{
    logr.nocmerged = 1;

    char *multi_group = NULL;
    file_sum ***_f_sum = NULL;
    char *hash_multigroup = NULL;

    os_calloc((4096 + 2), sizeof(char*), hash_multigroup);
    for (unsigned int a = 0; a < 4096 + 2; a++) {
        hash_multigroup[a] = 'c';
    }

    /* Open the multi-group files and generate merged */
    will_return(__wrap_opendir, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "At c_multi_group(): path too long.");

    c_multi_group(multi_group, _f_sum, hash_multigroup);

    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_subdir_fail(void **state)
{
    logr.nocmerged = 1;

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

    c_multi_group(multi_group, _f_sum, hash_multigroup);

    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_call_c_group(void **state)
{
    logr.nocmerged = 1;

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
    will_return(__wrap_OS_MD5_File, 1);

    expect_string(__wrap_OS_MD5_File, fname, "var/multigroups/hash_multi_group_test/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    c_multi_group(multi_group, _f_sum, hash_multigroup);

    os_free(_f_sum[0][0]->name);
    os_free(_f_sum[0][0]);
    os_free(_f_sum[0]);
    os_free(_f_sum);
    os_free(hash_multigroup);
    os_free(multi_group);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests lookfor_agent_group
        cmocka_unit_test(test_lookfor_agent_group_null_groups),
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
        cmocka_unit_test_setup_teardown(test_c_group_timeout_not_null, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_timeout_not_null_not_binary_file, test_c_group_setup, test_c_group_teardown),
        // Tests c_multi_group
        cmocka_unit_test_setup(test_c_multi_group_hash_multigroup_null, test_c_multi_group_setup),
        cmocka_unit_test_setup(test_c_multi_group_open_directory_fail, test_c_multi_group_setup),
        cmocka_unit_test_setup(test_c_multi_group_read_dir_fail, test_c_multi_group_setup),
        cmocka_unit_test_setup(test_c_multi_group_Ignore_hidden_files, test_c_multi_group_setup),
        cmocka_unit_test_setup(test_c_multi_group_large_path_fail, test_c_multi_group_setup),
        cmocka_unit_test_setup(test_c_multi_group_subdir_fail, test_c_multi_group_setup),
        cmocka_unit_test_setup(test_c_multi_group_call_c_group, test_c_multi_group_setup),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
