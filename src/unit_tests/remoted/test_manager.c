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
#include "../wrappers/posix/dirent_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/remoted/request_wrappers.h"
#include "../wrappers/wazuh/remoted/remoted_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"

#include "../wazuh_db/wdb.h"
#include "../remoted/remoted.h"
#include "../remoted/shared_download.h"
#include "../../remoted/manager.c"

int lookfor_agent_group(const char *agent_id, char **r_group, int* wdb_sock);
extern OSHash *agent_data_hash;

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

static void free_group(void *data) {
    if (data) {
        group_t *group = (group_t *)data;
        if (group->f_time) {
            OSHash_Clean(group->f_time, free_file_time);
        }
        os_free(group->name);
        os_free(group);
    }
}

static void free_group_c_group(void *data) {
    if (data) {
        group_t *group = (group_t *)data;
        os_free(group->name);
        os_free(group);
    }
}

static int setup_globals(void ** state) {
    agent_data_hash = __real_OSHash_Create();
    test_mode = 1;

    return 0;
}

static int setup_globals_no_test_mode(void ** state) {
    agent_data_hash = __real_OSHash_Create();
    test_mode = 0;

    return 0;
}

static int teardown_globals(void ** state) {
    __real_OSHash_Clean(agent_data_hash, agent_data_hash_cleaner);
    test_mode = 0;

    return 0;
}

static int setup_test_mode(void ** state) {
    test_mode = 1;

    return 0;
}

static int teardown_test_mode(void ** state) {
    test_mode = 0;

    return 0;
}


int __wrap_send_msg(const char *agent_id, const char *msg, ssize_t msg_length) {
    check_expected(agent_id);
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
    group_t *group = NULL;

    test_mode = 0;

    groups = OSHash_Create();

    os_calloc(1, sizeof(group_t), group);
    group->name = strdup("test_default");
    OSHash_Add_ex(groups, "test_default", group);

    test_mode = 1;

    state[0] = group;

    return 0;
}

static int test_find_group_setup(void ** state) {
    group_t *group1 = NULL;
    group_t *group2 = NULL;

    test_mode = 0;

    groups = OSHash_Create();

    os_calloc(1, sizeof(group_t), group1);
    group1->name = strdup("test_default");
    snprintf(group1->merged_sum, 17, "ABCDEF1234567890");
    OSHash_Add_ex(groups, "test_default", group1);

    os_calloc(1, sizeof(group_t), group2);
    group2->name = strdup("test_test_default");
    snprintf(group2->merged_sum, 17, "ABCDEF1234567809");
    OSHash_Add_ex(groups, "test_test_default", group2);

    test_mode = 1;

    state[0] = group1;
    state[1] = group2;

    return 0;
}

static int test_process_deleted_groups_setup(void ** state) {
    group_t *group1 = NULL;
    group_t *group2 = NULL;

    test_mode = 0;

    multi_groups = OSHash_Create();

    os_calloc(1, sizeof(group_t), group1);
    group1->name = strdup("test_default");

    os_calloc(1, sizeof(group_t), group2);
    group2->name = strdup("test_test_default");

    test_mode = 1;

    state[0] = group1;
    state[1] = group2;

    return 0;
}

static int test_find_multi_group_setup(void ** state) {
    group_t *multigroup1 = NULL;
    group_t *multigroup2 = NULL;

    test_mode = 0;

    multi_groups = OSHash_Create();

    os_calloc(1, sizeof(group_t), multigroup1);
    multigroup1->name = strdup("test_default2");
    snprintf(multigroup1->merged_sum, 17, "1234567890ABCDEF");
    OSHash_Add_ex(multi_groups, "test_default2", multigroup1);

    os_calloc(1, sizeof(group_t), multigroup2);
    multigroup2->name = strdup("test_test_default2");
    snprintf(multigroup2->merged_sum, 17, "1234567890ABCDFE");
    OSHash_Add_ex(multi_groups, "test_test_default2", multigroup2);

    test_mode = 1;

    state[0] = multigroup1;
    state[1] = multigroup2;

    return 0;
}

static int test_process_deleted_multi_groups_setup(void ** state) {
    group_t *multigroup1 = NULL;
    group_t *multigroup2 = NULL;

    test_mode = 0;

    multi_groups = OSHash_Create();

    os_calloc(1, sizeof(group_t), multigroup1);
    multigroup1->name = strdup("test_default2");

    os_calloc(1, sizeof(group_t), multigroup2);
    multigroup2->name = strdup("test_test_default2");

    test_mode = 1;

    state[0] = multigroup1;
    state[1] = multigroup2;

    return 0;
}

static int test_ftime_changed_setup(void ** state) {
    file_time *file1 = NULL;
    file_time *file2 = NULL;
    file_time *file3 = NULL;
    file_time *file4 = NULL;

    test_mode = 0;

    os_calloc(1, sizeof(file_time), file1);
    file1->name = strdup("file1");
    file1->m_time = 123456789;

    os_calloc(1, sizeof(file_time), file2);
    file2->name = strdup("file2");
    file2->m_time = 123456798;

    test_mode = 1;

    state[0] = file1;
    state[1] = file2;

    return 0;
}

static int test_process_group_setup(void ** state) {
    group_t *group = NULL;
    file_time *file = NULL;

    test_mode = 0;

    groups = OSHash_Create();

    os_calloc(1, sizeof(group_t), group);
    group->name = strdup("test_default");
    group->f_time = OSHash_Create();
    os_calloc(1, sizeof(file_time), file);
    file->name = strdup("merged.mg");
    file->m_time = 123456789;
    OSHash_Add_ex(group->f_time, "merged.mg", file);
    strncpy(group->merged_sum, "AAAAAAAAAAAAAAAA", 32);
    OSHash_Add_ex(groups, "test_default", group);

    if (setup_hashmap(state) != 0) {
        return 1;
    }

    test_mode = 1;

    state[0] = group->f_time;
    state[1] = group;

    return 0;
}

static int test_process_multi_groups_setup(void ** state) {
    group_t *multigroup = NULL;
    file_time *file = NULL;

    test_mode = 0;

    multi_groups = OSHash_Create();

    os_calloc(1, sizeof(group_t), multigroup);
    multigroup->name = strdup("groupA,groupB");
    multigroup->f_time = OSHash_Create();
    os_calloc(1, sizeof(file_time), file);
    file->name = strdup("test_file2");
    file->m_time = 123456789;
    OSHash_Add_ex(multigroup->f_time, "test_file2", file);
    OSHash_Add_ex(multi_groups, "groupA,groupB", multigroup);

    if (setup_hashmap(state) != 0) {
        return 1;
    }

    test_mode = 1;

    return 0;
}

static int test_process_multi_groups_groups_setup(void ** state) {
    group_t *group1 = NULL;
    group_t *group2 = NULL;
    group_t *multigroup = NULL;
    file_time *file = NULL;

    test_mode = 0;

    multi_groups = OSHash_Create();

    os_calloc(1, sizeof(group_t), multigroup);
    multigroup->name = strdup("group1,group2");
    multigroup->f_time = OSHash_Create();
    os_calloc(1, sizeof(file_time), file);
    file->name = strdup("test_file2");
    file->m_time = 123456789;
    OSHash_Add_ex(multigroup->f_time, "test_file2", file);
    OSHash_Add_ex(multi_groups, "group1,group2", multigroup);

    groups = OSHash_Create();

    os_calloc(1, sizeof(group_t), group1);
    group1->name = strdup("group1");
    group1->has_changed = true;
    group1->exists = true;
    OSHash_Add_ex(groups, "group1", group1);

    os_calloc(1, sizeof(group_t), group2);
    group2->name = strdup("group2");
    group2->has_changed = false;
    group2->exists = true;
    OSHash_Add_ex(groups, "group2", group2);

    if (setup_hashmap(state) != 0) {
        return 1;
    }

    test_mode = 1;

    state[0] = group1;
    state[1] = multigroup;

    return 0;
}

static int test_c_files_setup(void ** state) {
    group_t *group1 = NULL;
    group_t *group2 = NULL;
    group_t *multigroup1 = NULL;
    group_t *multigroup2 = NULL;
    file_time *file1 = NULL;
    file_time *file2 = NULL;
    file_time *file3 = NULL;
    file_time *file4 = NULL;

    test_mode = 0;

    groups = OSHash_Create();

    os_calloc(1, sizeof(group_t), group1);
    group1->name = strdup("test_default");
    group1->f_time = OSHash_Create();
    os_calloc(1, sizeof(file_time), file1);
    file1->name = strdup("test_file");
    file1->m_time = 123456789;
    OSHash_Add_ex(group1->f_time, "test_file", file1);
    OSHash_Add_ex(groups, "test_default", group1);

    os_calloc(1, sizeof(group_t), group2);
    group2->name = strdup("test_test_default");
    group2->f_time = OSHash_Create();
    os_calloc(1, sizeof(file_time), file2);
    file2->name = strdup("test_test_file");
    file2->m_time = 123456798;
    OSHash_Add_ex(group2->f_time, "test_test_file", file2);
    OSHash_Add_ex(groups, "test_test_default", group2);

    multi_groups = OSHash_Create();

    os_calloc(1, sizeof(group_t), multigroup1);
    multigroup1->name = strdup("test_default2");
    multigroup1->f_time = OSHash_Create();
    os_calloc(1, sizeof(file_time), file3);
    file3->name = strdup("test_file2");
    file3->m_time = 123456789;
    OSHash_Add_ex(multigroup1->f_time, "test_file2", file3);
    OSHash_Add_ex(multi_groups, "test_default2", multigroup1);

    os_calloc(1, sizeof(group_t), multigroup2);
    multigroup2->name = strdup("test_test_default2");
    multigroup2->f_time = OSHash_Create();
    os_calloc(1, sizeof(file_time), file4);
    file4->name = strdup("test_test_file2");
    file4->m_time = 123456798;
    OSHash_Add_ex(multigroup2->f_time, "test_test_file2", file4);
    OSHash_Add_ex(multi_groups, "test_test_default2", multigroup2);

    test_mode = 1;

    return 0;
}

static int test_c_group_teardown(void ** state) {
    test_mode = 0;

    if (groups) {
        OSHash_Clean(groups, free_group_c_group);
    }

    test_mode = 1;

    return 0;
}

static int test_c_multi_group_teardown(void ** state) {
    test_mode = 0;

    if (multi_groups) {
        OSHash_Clean(multi_groups, free_group);
    }

    test_mode = 1;

    return 0;
}

static int test_process_deleted_groups_teardown(void ** state) {
    group_t *group = (group_t *)state[1];

    test_mode = 0;

    free_group_c_group(group);
    OSHash_Free(multi_groups);

    test_mode = 1;

    return 0;
}

static int test_ftime_changed_teardown(void ** state) {
    file_time *file1 = (file_time *)state[0];
    file_time *file2 = (file_time *)state[1];

    test_mode = 0;

    free_file_time(file1);
    free_file_time(file2);

    test_mode = 1;

    return 0;
}

static int test_process_groups_teardown(void ** state) {
    OSHash *f_time = (OSHash *)state[0];

    test_mode = 0;

    OSHash_Clean(f_time, free_file_time);

    if (groups) {
        OSHash_Clean(groups, free_group_c_group);
    }

    if (teardown_hashmap(NULL) != 0) {
        return -1;
    }

    test_mode = 1;

    return 0;
}

static int test_process_multi_groups_teardown(void ** state) {
    test_mode = 0;

    if (multi_groups) {
        OSHash_Clean(multi_groups, free_group);
    }

    if (teardown_hashmap(NULL) != 0) {
        return -1;
    }

    test_mode = 1;

    return 0;
}

static int test_process_multi_groups_groups_teardown(void ** state) {
    OSHash *f_time = (OSHash *)state[0];

    test_mode = 0;

    OSHash_Clean(f_time, free_file_time);

    if (multi_groups) {
        OSHash_Clean(multi_groups, free_group_c_group);
    }

    if (groups) {
        OSHash_Clean(groups, free_group);
    }

    if (teardown_hashmap(NULL) != 0) {
        return -1;
    }

    test_mode = 1;

    return 0;
}

static int test_c_files_teardown(void ** state) {
    test_mode = 0;

    if (groups) {
        OSHash_Clean(groups, free_group);
    }

    if (multi_groups) {
        OSHash_Clean(multi_groups, free_group);
    }

    test_mode = 1;

    return 0;
}

/* Tests lookfor_agent_group */

void test_lookfor_agent_group_with_group()
{
    const int agent_id = 1;
    const char agent_id_str[] = "001";
    char *r_group = NULL;
    char *test_group = strdup("TESTGROUP");

    expect_value(__wrap_wdb_get_agent_group, id, agent_id);
    will_return(__wrap_wdb_get_agent_group, test_group);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' group is 'TESTGROUP'");

    int ret = lookfor_agent_group(agent_id_str, &r_group, NULL);
    assert_int_equal(OS_SUCCESS, ret);
    assert_string_equal(r_group, test_group);

    os_free(test_group);
}

void test_c_group_no_changes(void **state)
{
    disk_storage = 0;

    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, NULL);

    will_return(__wrap_open_memstream, strdup("buffer stream"));
    will_return(__wrap_open_memstream, 13);
    will_return(__wrap_open_memstream, (FILE *)1);

    expect_value(__wrap_fprintf, __stream, (FILE *)1);
    expect_string(__wrap_fprintf, formatted_msg, "#test_default\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_value(__wrap_fclose, _File, (FILE *)1);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_OS_MD5_Str, str, "buffer stream");
    expect_value(__wrap_OS_MD5_Str, length, 13);
    will_return(__wrap_OS_MD5_Str, "md5_test");
    will_return(__wrap_OS_MD5_Str, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_stat, __file, "etc/shared/test_default/merged.mg");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "merged.mg");
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_string(__wrap__merror, formatted_msg, "Couldn't add file 'merged.mg' to group hash table.");

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    assert_string_equal(group->name, "test_default");
    assert_string_equal(group->merged_sum, "md5_test");
    assert_non_null(group->f_time);
}

void test_c_group_no_changes_disk(void **state)
{
    disk_storage = 1;

    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, NULL);

    expect_string(__wrap_wfopen, path, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)1);

    expect_value(__wrap_fprintf, __stream, (FILE *)1);
    expect_string(__wrap_fprintf, formatted_msg, "#test_default\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_value(__wrap_fclose, _File, (FILE *)1);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg.tmp");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_unlink, file, "etc/shared/test_default/merged.mg.tmp");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_stat, __file, "etc/shared/test_default/merged.mg");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "merged.mg");
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_string(__wrap__merror, formatted_msg, "Couldn't add file 'merged.mg' to group hash table.");

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    assert_string_equal(group->name, "test_default");
    assert_string_equal(group->merged_sum, "md5_test");
    assert_non_null(group->f_time);
}

void test_c_group_changes(void **state)
{
    disk_storage = 0;

    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, NULL);

    will_return(__wrap_open_memstream, strdup("buffer stream"));
    will_return(__wrap_open_memstream, 13);
    will_return(__wrap_open_memstream, (FILE *)1);

    expect_value(__wrap_fprintf, __stream, (FILE *)1);
    expect_string(__wrap_fprintf, formatted_msg, "#test_default\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_value(__wrap_fclose, _File, (FILE *)1);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_OS_MD5_Str, str, "buffer stream");
    expect_value(__wrap_OS_MD5_Str, length, 13);
    will_return(__wrap_OS_MD5_Str, "md5_test");
    will_return(__wrap_OS_MD5_Str, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test2");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_wfopen, path, "etc/shared/test_default/merged.mg");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)2);

    will_return(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, (FILE *)2);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test2");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_stat, __file, "etc/shared/test_default/merged.mg");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    expect_string(__wrap__merror, formatted_msg, "Unable to get entry attributes 'etc/shared/test_default/merged.mg'");

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    assert_string_equal(group->name, "test_default");
    assert_string_equal(group->merged_sum, "md5_test2");
    assert_non_null(group->f_time);
}

void test_c_group_changes_disk(void **state)
{
    disk_storage = 1;

    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, NULL);

    expect_string(__wrap_wfopen, path, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)1);

    expect_value(__wrap_fprintf, __stream, (FILE *)1);
    expect_string(__wrap_fprintf, formatted_msg, "#test_default\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_value(__wrap_fclose, _File, (FILE *)1);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg.tmp");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test2");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_OS_MoveFile, src, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_OS_MoveFile, dst, "etc/shared/test_default/merged.mg");
    will_return(__wrap_OS_MoveFile, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test2");
    will_return(__wrap_OS_MD5_File, 0);

    expect_string(__wrap_stat, __file, "etc/shared/test_default/merged.mg");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    expect_string(__wrap__merror, formatted_msg, "Unable to get entry attributes 'etc/shared/test_default/merged.mg'");

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    assert_string_equal(group->name, "test_default");
    assert_string_equal(group->merged_sum, "md5_test2");
    assert_non_null(group->f_time);
}

void test_c_group_fail(void **state)
{
    disk_storage = 0;

    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, NULL);

    will_return(__wrap_open_memstream, strdup("buffer stream"));
    will_return(__wrap_open_memstream, 13);
    will_return(__wrap_open_memstream, (FILE *)1);

    expect_value(__wrap_fprintf, __stream, (FILE *)1);
    expect_string(__wrap_fprintf, formatted_msg, "#test_default\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_value(__wrap_fclose, _File, (FILE *)1);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_OS_MD5_Str, str, "buffer stream");
    expect_value(__wrap_OS_MD5_Str, length, 13);
    will_return(__wrap_OS_MD5_Str, "md5_test");
    will_return(__wrap_OS_MD5_Str, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap_wfopen, path, "etc/shared/test_default/merged.mg");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)2);

    will_return(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, (FILE *)2);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/merged.mg'");

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    assert_string_equal(group->name, "test_default");
    assert_string_equal(group->merged_sum, "");
    assert_non_null(group->f_time);
}

void test_c_group_fail_disk(void **state)
{
    disk_storage = 1;

    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, NULL);

    expect_string(__wrap_wfopen, path, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)1);

    expect_value(__wrap_fprintf, __stream, (FILE *)1);
    expect_string(__wrap_fprintf, formatted_msg, "#test_default\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_value(__wrap_fclose, _File, (FILE *)1);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg.tmp");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/merged.mg.tmp'");

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    assert_string_equal(group->name, "test_default");
    assert_string_equal(group->merged_sum, "");
    assert_non_null(group->f_time);
}

void test_c_group_downloaded_file(void **state)
{
    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, r_group);

    expect_string(__wrap__mdebug1, formatted_msg, "Downloading shared file 'etc/shared/test_default/merged.mg' from 'r_group->files_url'");

    expect_string(__wrap_wurl_request, url, r_group->files->url);
    expect_string(__wrap_wurl_request, dest, "var/download/merged.mg");
    will_return(__wrap_wurl_request, 0);

    expect_string(__wrap_TestUnmergeFiles, finalpath, "var/download/merged.mg");
    will_return(__wrap_TestUnmergeFiles, 1);

    expect_string(__wrap_OS_MoveFile, src, "var/download/merged.mg");
    expect_string(__wrap_OS_MoveFile, dst, "etc/shared/test_default/merged.mg");
    will_return(__wrap_OS_MoveFile, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/merged.mg'");

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);
}

void test_c_group_downloaded_file_no_poll(void **state)
{
    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

    // Initialize r_group structure
    remote_files_group *r_group = NULL;
    os_malloc(sizeof(remote_files_group), r_group);
    os_strdup("r_group_name", r_group->name);
    os_malloc(sizeof(file), r_group->files);
    os_strdup("r_group->files_name", r_group->files->name);
    os_strdup("r_group->files_url", r_group->files->url);

    r_group->poll = 0;
    r_group->current_polling_time = 1;
    r_group->merge_file_index = 0;
    r_group->merged_is_downloaded = 1;

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, r_group);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/merged.mg'");

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);
}

void test_c_group_downloaded_file_is_corrupted(void **state)
{
    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, r_group);

    expect_string(__wrap__mdebug1, formatted_msg, "Downloading shared file 'etc/shared/test_default/merged.mg' from 'r_group->files_url'");

    expect_string(__wrap_wurl_request, url, r_group->files->url);
    expect_string(__wrap_wurl_request, dest, "var/download/merged.mg");
    will_return(__wrap_wurl_request, 0);

    expect_string(__wrap_TestUnmergeFiles, finalpath, "var/download/merged.mg");
    will_return(__wrap_TestUnmergeFiles, 0);

    expect_string(__wrap_unlink, file, "var/download/merged.mg");
    will_return(__wrap_unlink, -1);

    expect_string(__wrap__merror, formatted_msg, "The downloaded file 'var/download/merged.mg' is corrupted.");
    expect_string(__wrap__merror, formatted_msg, "Failed to delete file 'var/download/merged.mg'");

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);
}

void test_c_group_download_all_files(void **state)
{
    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
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

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);
}

void test_c_group_no_create_shared_file(void **state)
{
    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, false, false);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);

    assert_string_equal(group->name, "test_default");
    assert_string_equal(group->merged_sum, "");
    assert_non_null(group->f_time);
}

void test_c_group_invalid_share_file(void **state)
{
    disk_storage = 0;

    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, NULL);

    will_return(__wrap_open_memstream, strdup("buffer stream"));
    will_return(__wrap_open_memstream, 13);
    will_return(__wrap_open_memstream, (FILE *)1);

    expect_value(__wrap_fprintf, __stream, (FILE *)1);
    expect_string(__wrap_fprintf, formatted_msg, "#test_default\n");
    will_return(__wrap_fprintf, 0);

    struct stat stat_buf = { .st_mtime = 123456788 };
    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_value(__wrap_MergeAppendFile, finalfp, (FILE *)1);
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "ar.conf");
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_string(__wrap__merror, formatted_msg, "Couldn't add file 'ar.conf' to group hash table.");

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_value(__wrap_fclose, _File, (FILE *)1);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_OS_MD5_Str, str, "buffer stream");
    expect_value(__wrap_OS_MD5_Str, length, 13);
    will_return(__wrap_OS_MD5_Str, "md5_test");
    will_return(__wrap_OS_MD5_Str, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap_wfopen, path, "etc/shared/test_default/merged.mg");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, NULL);

    will_return(__wrap_strerror, "No such file or directory");

    expect_string(__wrap__merror, formatted_msg, "Unable to open file: 'etc/shared/test_default/merged.mg' due to [(0)-(No such file or directory)].");

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);
}

void test_c_group_append_file_error(void **state)
{
    disk_storage = 0;

    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, NULL);

    will_return(__wrap_open_memstream, strdup("buffer stream"));
    will_return(__wrap_open_memstream, 13);
    will_return(__wrap_open_memstream, (FILE *)1);

    expect_value(__wrap_fprintf, __stream, (FILE *)1);
    expect_string(__wrap_fprintf, formatted_msg, "#test_default\n");
    will_return(__wrap_fprintf, 0);

    struct stat stat_buf = { .st_mtime = 123456788 };
    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_value(__wrap_MergeAppendFile, finalfp, (FILE *)1);
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "ar.conf");
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__merror, formatted_msg, "Couldn't add file 'ar.conf' to group hash table.");

    // Start validate_shared_files function
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf2 = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-file");
    will_return(__wrap_stat, &stat_buf2);
    will_return(__wrap_stat, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    expect_value(__wrap_MergeAppendFile, finalfp, (FILE *)1);
    expect_value(__wrap_MergeAppendFile, path_offset, 0x18);
    will_return(__wrap_MergeAppendFile, 0);
    // End validate_shared_files function

    expect_value(__wrap_fclose, _File, (FILE *)1);
    will_return(__wrap_fclose, 0);

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);
}

void test_c_group_append_ar_error(void **state)
{
    disk_storage = 0;

    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, NULL);

    will_return(__wrap_open_memstream, strdup("buffer stream"));
    will_return(__wrap_open_memstream, 13);
    will_return(__wrap_open_memstream, (FILE *)1);

    expect_value(__wrap_fprintf, __stream, (FILE *)1);
    expect_string(__wrap_fprintf, formatted_msg, "#test_default\n");
    will_return(__wrap_fprintf, 0);

    struct stat stat_buf = { .st_mtime = 123456788 };
    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_value(__wrap_MergeAppendFile, finalfp, (FILE *)1);
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 0);

    expect_value(__wrap_fclose, _File, (FILE *)1);
    will_return(__wrap_fclose, 0);

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);
}

void test_c_group_truncate_error(void **state)
{
    disk_storage = 0;

    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, NULL);

    will_return(__wrap_open_memstream, strdup("buffer stream"));
    will_return(__wrap_open_memstream, 13);
    will_return(__wrap_open_memstream, NULL);

    will_return(__wrap_strerror, "No such file or directory");

    expect_string(__wrap__merror, formatted_msg, "Unable to open memory stream due to [(0)-(No such file or directory)].");

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);
}

void test_c_group_truncate_error_disk(void **state)
{
    disk_storage = 1;

    group_t *group = (group_t *)state[0];

    const char *group_name = "test_default";

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, group->name);
    will_return(__wrap_w_parser_get_group, NULL);

    expect_string(__wrap_wfopen, path, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, NULL);

    will_return(__wrap_strerror, "No such file or directory");

    expect_string(__wrap__merror, formatted_msg, "Unable to create merged file: 'etc/shared/test_default/merged.mg.tmp' due to [(0)-(No such file or directory)].");

    c_group(group_name, &group->f_time, &group->merged_sum, SHAREDCFG_DIR, true, false);

    os_free(r_group->name)
    os_free(r_group->files->name);
    os_free(r_group->files->url);
    os_free(r_group->files);
    os_free(r_group);
}

void test_c_multi_group_hash_multigroup_null(void **state)
{
    char *multi_group = NULL;
    OSHash *_f_time = (OSHash *)10;
    os_md5 sum;
    char *hash_multigroup = NULL;

    c_multi_group(multi_group, &_f_time, &sum, hash_multigroup, true);
}

void test_c_multi_group_open_directory_fail(void **state)
{
    char *multi_group = NULL;
    OSHash *_f_time = (OSHash *)10;
    os_md5 sum;
    char *hash_multigroup = NULL;

    os_strdup("multi_group_test", multi_group);
    os_strdup("multi_group_hash", hash_multigroup);

    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups/multi_group_hash");
    will_return(__wrap_cldir_ex_ignore, 0);

    will_return(__wrap_opendir, 0);

    will_return(__wrap_strerror, "No such file or directory");

    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    c_multi_group(multi_group, &_f_time, &sum, hash_multigroup, true);

    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_call_copy_directory(void **state)
{
    char *multi_group = NULL;
    OSHash *_f_time = (OSHash *)10;
    os_md5 sum;
    char *hash_multigroup = NULL;

    os_strdup("multi_group_test", multi_group);
    os_strdup("multi_group_hash", hash_multigroup);

    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups/multi_group_hash");
    will_return(__wrap_cldir_ex_ignore, 0);

    will_return(__wrap_opendir, 1);

    expect_string(__wrap_wreaddir, name, "etc/shared/multi_group_test");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mwarn, formatted_msg, "Could not open directory 'etc/shared/multi_group_test'. Group folder was deleted.");

    /* Open the multi-group files and generate merged */
    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': No such file or directory");

    c_multi_group(multi_group, &_f_time, &sum, hash_multigroup, true);

    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_read_dir_fail_no_entry(void **state)
{
    char *multi_group = NULL;
    OSHash *_f_time = (OSHash *)10;
    os_md5 sum;
    char *hash_multigroup = NULL;

    os_strdup("multi_group_test", multi_group);
    os_strdup("multi_group_hash", hash_multigroup);

    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups/multi_group_hash");
    will_return(__wrap_cldir_ex_ignore, 0);

    will_return(__wrap_opendir, 1);

    expect_string(__wrap_wreaddir, name, "etc/shared/multi_group_test");
    will_return(__wrap_wreaddir, NULL);

    // Open the multi-group files and generate merged //
    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "Not a directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': Not a directory");

    errno = ENOTDIR;

    c_multi_group(multi_group, &_f_time, &sum, hash_multigroup, true);

    errno = 0;

    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_Ignore_hidden_files(void **state)
{
    char *multi_group = NULL;
    OSHash *_f_time = (OSHash *)10;
    os_md5 sum;
    char *hash_multigroup = NULL;

    os_strdup("multi_group_test", multi_group);
    os_strdup("multi_group_hash", hash_multigroup);

    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups/multi_group_hash");
    will_return(__wrap_cldir_ex_ignore, 0);

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

    will_return(__wrap_opendir, 0);

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/multi_group_test/file_2");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_w_copy_file, src, "etc/shared/multi_group_test/file_2");
    expect_string(__wrap_w_copy_file, dst, "var/multigroups/multi_group_hash/file_2");
    expect_value(__wrap_w_copy_file, mode, 0x63);
    expect_value(__wrap_w_copy_file, silent, 1);
    will_return(__wrap_w_copy_file, 0);

    will_return(__wrap_opendir, 0);

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

    will_return(__wrap_opendir, 0);

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/multi_group_test/ignore_file");
    will_return(__wrap_OSHash_Get, last_modify);

    // Open the multi-group files and generate merged //
    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': No such file or directory");

    c_multi_group(multi_group, &_f_time, &sum, hash_multigroup, true);

    os_free(last_modify);
    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_subdir_fail(void **state)
{
    char *multi_group = NULL;
    OSHash *_f_time = (OSHash *)10;
    os_md5 sum;
    char *hash_multigroup = NULL;

    os_strdup("multi_group_test", multi_group);
    os_strdup("hash_multi_group_test",hash_multigroup);

    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups/hash_multi_group_test");
    will_return(__wrap_cldir_ex_ignore, 0);

    // Open the multi-group files and generate merged //
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

    c_multi_group(multi_group, &_f_time, &sum, hash_multigroup, true);

    errno = 0;
    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_c_multi_group_call_c_group(void **state)
{
    disk_storage = 0;

    char *multi_group = NULL;
    OSHash *_f_time = (OSHash *)10;
    os_md5 sum;
    char *hash_multigroup = NULL;

    os_strdup("multi_group_test", multi_group);
    os_strdup("hash_multi_group_test",hash_multigroup);

    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups/hash_multi_group_test");
    will_return(__wrap_cldir_ex_ignore, 0);

    // Open the multi-group files and generate merged //
    will_return(__wrap_opendir, 1);

    // Start copy_directory function
    expect_string(__wrap_wreaddir, name, "etc/shared/multi_group_test");
    will_return(__wrap_wreaddir, NULL);

    errno = 1;
    expect_string(__wrap__mwarn, formatted_msg, "Could not open directory 'etc/shared/multi_group_test'. Group folder was deleted.");

    // End copy_directory function

    will_return(__wrap_opendir, 1);

    // Start c_group function
    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, "hash_multi_group_test");
    will_return(__wrap_w_parser_get_group, NULL);

    will_return(__wrap_open_memstream, strdup("buffer stream"));
    will_return(__wrap_open_memstream, 13);
    will_return(__wrap_open_memstream, NULL);

    will_return(__wrap_strerror, "No such file or directory");

    expect_string(__wrap__merror, formatted_msg, "Unable to open memory stream due to [(1)-(No such file or directory)].");
    // End c_group function

    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups/hash_multi_group_test");
    will_return(__wrap_cldir_ex_ignore, 0);

    c_multi_group(multi_group, &_f_time, &sum, hash_multigroup, true);

    errno = 0;

    os_free(hash_multigroup);
    os_free(multi_group);
}

void test_ftime_changed_same_fsum(void **state)
{
    file_time *file1 = (file_time *)state[0];

    OSHashNode* node1 = NULL;
    os_calloc(1, sizeof(OSHashNode), node1);
    node1->data = file1;

    OSHash *hash1 = (OSHash *)10;
    OSHash *hash2 = (OSHash *)11;

    expect_value(__wrap_OSHash_Get_Elem_ex, self, hash1);
    will_return(__wrap_OSHash_Get_Elem_ex, 2);

    expect_value(__wrap_OSHash_Get_Elem_ex, self, hash2);
    will_return(__wrap_OSHash_Get_Elem_ex, 2);

    expect_value(__wrap_OSHash_Begin, self, hash1);
    will_return(__wrap_OSHash_Begin, node1);

    expect_value(__wrap_OSHash_Get_ex, self, hash2);
    expect_string(__wrap_OSHash_Get_ex, key, "file1");
    will_return(__wrap_OSHash_Get_ex, file1);

    expect_value(__wrap_OSHash_Next, self, hash1);
    will_return(__wrap_OSHash_Next, NULL);

    assert_false(ftime_changed(hash1, hash2));

    os_free(node1);
}

void test_ftime_changed_different_fsum_sum(void **state)
{
    file_time *file1 = (file_time *)state[0];
    file_time *file2 = (file_time *)state[1];

    OSHashNode* node1 = NULL;
    os_calloc(1, sizeof(OSHashNode), node1);
    node1->data = file1;

    OSHash *hash1 = (OSHash *)10;
    OSHash *hash2 = (OSHash *)11;

    expect_value(__wrap_OSHash_Get_Elem_ex, self, hash1);
    will_return(__wrap_OSHash_Get_Elem_ex, 2);

    expect_value(__wrap_OSHash_Get_Elem_ex, self, hash2);
    will_return(__wrap_OSHash_Get_Elem_ex, 2);

    expect_value(__wrap_OSHash_Begin, self, hash1);
    will_return(__wrap_OSHash_Begin, node1);

    expect_value(__wrap_OSHash_Get_ex, self, hash2);
    expect_string(__wrap_OSHash_Get_ex, key, "file1");
    will_return(__wrap_OSHash_Get_ex, file2);

    assert_true(ftime_changed(hash1, hash2));

    os_free(node1);
}

void test_ftime_changed_different_fsum_name(void **state)
{
    file_time *file1 = (file_time *)state[0];

    OSHashNode* node1 = NULL;
    os_calloc(1, sizeof(OSHashNode), node1);
    node1->data = file1;

    OSHash *hash1 = (OSHash *)10;
    OSHash *hash2 = (OSHash *)11;

    expect_value(__wrap_OSHash_Get_Elem_ex, self, hash1);
    will_return(__wrap_OSHash_Get_Elem_ex, 2);

    expect_value(__wrap_OSHash_Get_Elem_ex, self, hash2);
    will_return(__wrap_OSHash_Get_Elem_ex, 2);

    expect_value(__wrap_OSHash_Begin, self, hash1);
    will_return(__wrap_OSHash_Begin, node1);

    expect_value(__wrap_OSHash_Get_ex, self, hash2);
    expect_string(__wrap_OSHash_Get_ex, key, "file1");
    will_return(__wrap_OSHash_Get_ex, NULL);

    assert_true(ftime_changed(hash1, hash2));

    os_free(node1);
}

void test_ftime_changed_different_size(void **state)
{
    OSHash *hash1 = (OSHash *)10;
    OSHash *hash2 = (OSHash *)11;

    expect_value(__wrap_OSHash_Get_Elem_ex, self, hash1);
    will_return(__wrap_OSHash_Get_Elem_ex, 2);

    expect_value(__wrap_OSHash_Get_Elem_ex, self, hash2);
    will_return(__wrap_OSHash_Get_Elem_ex, 1);

    assert_true(ftime_changed(hash1, hash2));
}

void test_ftime_changed_one_null(void **state)
{
    OSHash *hash1 = (OSHash *)10;
    OSHash *hash2 = NULL;

    assert_true(ftime_changed(hash1, hash2));
}

void test_ftime_changed_both_null(void **state)
{
    OSHash *hash1 = NULL;
    OSHash *hash2 = NULL;

    assert_false(ftime_changed(hash1, hash2));
}

void test_group_changed_not_changed(void **state)
{
    group_t *group1 = (group_t *)state[0];
    group_t *group2 = (group_t *)state[1];

    group1->exists = true;
    group1->has_changed = false;
    group2->exists = true;
    group2->has_changed = false;

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_default");
    will_return(__wrap_OSHash_Get_ex, group1);

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_test_default");
    will_return(__wrap_OSHash_Get_ex, group2);

    assert_false(group_changed("test_default,test_test_default"));
}

void test_group_changed_has_changed(void **state)
{
    group_t *group1 = (group_t *)state[0];
    group_t *group2 = (group_t *)state[1];

    group1->exists = true;
    group1->has_changed = false;
    group2->exists = true;
    group2->has_changed = true;

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_default");
    will_return(__wrap_OSHash_Get_ex, group1);

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_test_default");
    will_return(__wrap_OSHash_Get_ex, group2);

    assert_true(group_changed("test_default,test_test_default"));
}

void test_group_changed_not_exists(void **state)
{
    group_t *group1 = (group_t *)state[0];
    group_t *group2 = (group_t *)state[1];

    group1->exists = true;
    group1->has_changed = false;
    group2->exists = false;
    group2->has_changed = false;

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_default");
    will_return(__wrap_OSHash_Get_ex, group1);

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_test_default");
    will_return(__wrap_OSHash_Get_ex, group2);

    assert_true(group_changed("test_default,test_test_default"));
}

void test_group_changed_invalid_group(void **state)
{
    group_t *group1 = (group_t *)state[0];
    group_t *group2 = (group_t *)state[1];

    group1->exists = true;
    group1->has_changed = false;
    group2->exists = true;
    group2->has_changed = false;

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_default");
    will_return(__wrap_OSHash_Get_ex, group1);

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_test_default");
    will_return(__wrap_OSHash_Get_ex, group2);

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "invalid_group");
    will_return(__wrap_OSHash_Get_ex, NULL);

    assert_true(group_changed("test_default,test_test_default,invalid_group"));
}

void test_process_deleted_groups_delete(void **state)
{
    group_t *group1 = (group_t *)state[0];
    group_t *group2 = (group_t *)state[1];

    group1->exists = false;
    group1->has_changed = false;
    group2->exists = true;
    group2->has_changed = false;

    OSHashNode* node1 = NULL;
    os_calloc(1, sizeof(OSHashNode), node1);
    node1->key = "test_default";
    node1->data = group1;

    OSHashNode* node2 = NULL;
    os_calloc(1, sizeof(OSHashNode), node2);
    node2->key = "test_test_default";
    node2->data = group2;

    expect_value(__wrap_OSHash_Begin, self, groups);
    will_return(__wrap_OSHash_Begin, node1);

    expect_value(__wrap_OSHash_Next, self, groups);
    will_return(__wrap_OSHash_Next, node2);

    expect_value(__wrap_OSHash_Delete_ex, self, groups);
    expect_string(__wrap_OSHash_Delete_ex, key, "test_default");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    will_return(__wrap_OSHash_Clean, 0);

    expect_value(__wrap_OSHash_Next, self, groups);
    will_return(__wrap_OSHash_Next, NULL);

    process_deleted_groups();

    assert_non_null(group2);
    assert_string_equal(group2->name, "test_test_default");
    assert_false(group2->has_changed);
    assert_false(group2->exists);

    os_free(node1);
    os_free(node2);
}

void test_process_deleted_groups_no_changes(void **state)
{
    group_t *group1 = (group_t *)state[0];
    group_t *group2 = (group_t *)state[1];

    group1->exists = true;
    group1->has_changed = false;
    group2->exists = true;
    group2->has_changed = false;

    OSHashNode* node1 = NULL;
    os_calloc(1, sizeof(OSHashNode), node1);
    node1->key = "test_default";
    node1->data = group1;

    OSHashNode* node2 = NULL;
    os_calloc(1, sizeof(OSHashNode), node2);
    node2->key = "test_test_default";
    node2->data = group2;

    expect_value(__wrap_OSHash_Begin, self, groups);
    will_return(__wrap_OSHash_Begin, node1);

    expect_value(__wrap_OSHash_Next, self, groups);
    will_return(__wrap_OSHash_Next, node2);

    expect_value(__wrap_OSHash_Next, self, groups);
    will_return(__wrap_OSHash_Next, NULL);

    process_deleted_groups();

    assert_non_null(group1);
    assert_string_equal(group1->name, "test_default");
    assert_false(group1->has_changed);
    assert_false(group1->exists);
    assert_non_null(group2);
    assert_string_equal(group2->name, "test_test_default");
    assert_false(group2->has_changed);
    assert_false(group2->exists);

    os_free(node1);
    os_free(node2);
}

void test_process_deleted_multi_groups_delete(void **state)
{
    group_t *multigroup1 = (group_t *)state[0];
    group_t *multigroup2 = (group_t *)state[1];

    multigroup1->exists = false;
    multigroup1->has_changed = false;
    multigroup2->exists = true;
    multigroup2->has_changed = false;

    OSHashNode* node1 = NULL;
    os_calloc(1, sizeof(OSHashNode), node1);
    node1->key = "test_default2";
    node1->data = multigroup1;

    OSHashNode* node2 = NULL;
    os_calloc(1, sizeof(OSHashNode), node2);
    node2->key = "test_test_default2";
    node2->data = multigroup2;

    will_return(__wrap_OSHash_Clean, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_value(__wrap_OSHash_Begin, self, multi_groups);
    will_return(__wrap_OSHash_Begin, node1);

    expect_value(__wrap_OSHash_Next, self, multi_groups);
    will_return(__wrap_OSHash_Next, node2);

    expect_value(__wrap_OSHash_Delete_ex, self, multi_groups);
    expect_string(__wrap_OSHash_Delete_ex, key, "test_default2");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    will_return(__wrap_OSHash_Clean, 0);

    expect_value(__wrap_OSHash_Next, self, multi_groups);
    will_return(__wrap_OSHash_Next, NULL);

    expect_any(__wrap_OS_SHA256_String, str);
    will_return(__wrap_OS_SHA256_String, "6e3a107738e7d0fc85241f04ed9686d37738e7d08086fb46e3a100fc85241f04");

    expect_string(__wrap_rmdir_ex, name, "var/multigroups/6e3a1077");
    will_return(__wrap_rmdir_ex, 0);

    process_deleted_multi_groups(false);

    assert_non_null(multigroup2);
    assert_string_equal(multigroup2->name, "test_test_default2");
    assert_false(multigroup2->has_changed);
    assert_false(multigroup2->exists);

    os_free(node1);
    os_free(node2);
}

void test_process_deleted_multi_groups_no_changes(void **state)
{
    group_t *multigroup1 = (group_t *)state[0];
    group_t *multigroup2 = (group_t *)state[1];

    multigroup1->exists = true;
    multigroup1->has_changed = false;
    multigroup2->exists = true;
    multigroup2->has_changed = false;

    OSHashNode* node1 = NULL;
    os_calloc(1, sizeof(OSHashNode), node1);
    node1->key = "test_default2";
    node1->data = multigroup1;

    OSHashNode* node2 = NULL;
    os_calloc(1, sizeof(OSHashNode), node2);
    node2->key = "test_test_default2";
    node2->data = multigroup2;

    will_return(__wrap_OSHash_Clean, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_value(__wrap_OSHash_Begin, self, multi_groups);
    will_return(__wrap_OSHash_Begin, node1);

    expect_value(__wrap_OSHash_Next, self, multi_groups);
    will_return(__wrap_OSHash_Next, node2);

    expect_value(__wrap_OSHash_Next, self, multi_groups);
    will_return(__wrap_OSHash_Next, NULL);

    process_deleted_multi_groups(false);

    assert_non_null(multigroup1);
    assert_string_equal(multigroup1->name, "test_default2");
    assert_false(multigroup1->has_changed);
    assert_false(multigroup1->exists);
    assert_non_null(multigroup2);
    assert_string_equal(multigroup2->name, "test_test_default2");
    assert_false(multigroup2->has_changed);
    assert_false(multigroup2->exists);

    os_free(node1);
    os_free(node2);
}

void test_process_deleted_multi_groups_no_changes_initial_scan(void **state)
{
    group_t *multigroup1 = (group_t *)state[0];
    group_t *multigroup2 = (group_t *)state[1];

    multigroup1->exists = true;
    multigroup1->has_changed = false;
    multigroup2->exists = true;
    multigroup2->has_changed = false;

    OSHashNode* node1 = NULL;
    os_calloc(1, sizeof(OSHashNode), node1);
    node1->key = "test_default2";
    node1->data = multigroup1;

    OSHashNode* node2 = NULL;
    os_calloc(1, sizeof(OSHashNode), node2);
    node2->key = "test_test_default2";
    node2->data = multigroup2;

    OSHashNode* node3 = NULL;
    os_calloc(1, sizeof(OSHashNode), node3);
    node3->key = "ignore";
    node3->data = "ignore_hash";

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, node3);

    expect_value(__wrap_OSHash_Next, self, m_hash);
    will_return(__wrap_OSHash_Next, NULL);

    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups");
    will_return(__wrap_cldir_ex_ignore, 0);

    will_return(__wrap_OSHash_Clean, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_value(__wrap_OSHash_Begin, self, multi_groups);
    will_return(__wrap_OSHash_Begin, node1);

    expect_value(__wrap_OSHash_Next, self, multi_groups);
    will_return(__wrap_OSHash_Next, node2);

    expect_value(__wrap_OSHash_Next, self, multi_groups);
    will_return(__wrap_OSHash_Next, NULL);

    process_deleted_multi_groups(true);

    assert_non_null(multigroup1);
    assert_string_equal(multigroup1->name, "test_default2");
    assert_false(multigroup1->has_changed);
    assert_false(multigroup1->exists);
    assert_non_null(multigroup2);
    assert_string_equal(multigroup2->name, "test_test_default2");
    assert_false(multigroup2->has_changed);
    assert_false(multigroup2->exists);

    os_free(node1);
    os_free(node2);
    os_free(node3);
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

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test'");

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
    disk_storage = 0;

    struct dirent *entry;
    os_calloc(1, sizeof(struct dirent), entry);
    strcpy(entry->d_name, "test");

    char** subdir = NULL;
    os_malloc(2 * sizeof(char *), subdir);
    os_strdup("file_1", subdir[0]);
    subdir[1] = NULL;

    __real_OSHash_SetFreeDataPointer(mock_hashmap, (void (*)(void *))free_group_c_group);

    will_return(__wrap_opendir, 1);

    will_return(__wrap_readdir, entry);

    expect_string(__wrap_wreaddir, name, "etc/shared/test");
    will_return(__wrap_wreaddir, subdir);

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test");
    will_return(__wrap_OSHash_Get_ex, NULL);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, groups);
    expect_string(__wrap_OSHash_Add_ex, key, "test");
    will_return(__wrap_OSHash_Add_ex, 2);

    // Start c_group function
    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_w_parser_get_group, name, "test");
    will_return(__wrap_w_parser_get_group, NULL);

    will_return(__wrap_open_memstream, strdup("buffer stream"));
    will_return(__wrap_open_memstream, 13);
    will_return(__wrap_open_memstream, (FILE *)1);

    expect_value(__wrap_fprintf, __stream, (FILE *)1);
    expect_string(__wrap_fprintf, formatted_msg, "#test\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test'");
    // End validate_shared_files function

    expect_value(__wrap_fclose, _File, (FILE *)1);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_OS_MD5_Str, str, "buffer stream");
    expect_value(__wrap_OS_MD5_Str, length, 13);
    will_return(__wrap_OS_MD5_Str, "md5_test");
    will_return(__wrap_OS_MD5_Str, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap_wfopen, path, "etc/shared/test/merged.mg");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, NULL);

    will_return(__wrap_strerror, "No such file or directory");

    expect_string(__wrap__merror, formatted_msg, "Unable to open file: 'etc/shared/test/merged.mg' due to [(0)-(No such file or directory)].");
    // End c_group function

    will_return(__wrap_readdir, NULL);

    process_groups();

    os_free(entry);
}

void test_process_groups_find_group_changed(void **state)
{
    disk_storage = 0;

    group_t *group = (group_t *)state[1];

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

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_default");
    will_return(__wrap_OSHash_Get_ex, group);

    // Start c_group function
    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "1212121212121");
    will_return(__wrap_OS_MD5_File, -1);
    // End c_group function

    // Start ftime_changed
    expect_value(__wrap_OSHash_Get_Elem_ex, self, group->f_time);
    will_return(__wrap_OSHash_Get_Elem_ex, 2);

    expect_value(__wrap_OSHash_Get_Elem_ex, self, (OSHash *)10);
    will_return(__wrap_OSHash_Get_Elem_ex, 1);
    // End ftime_changed

    will_return(__wrap_OSHash_Clean, NULL);

    // Start c_group function
    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)11);

    expect_string(__wrap_w_parser_get_group, name, "test_default");
    will_return(__wrap_w_parser_get_group, NULL);

    will_return(__wrap_open_memstream, strdup("buffer stream"));
    will_return(__wrap_open_memstream, 13);
    will_return(__wrap_open_memstream, (FILE *)1);

    expect_value(__wrap_fprintf, __stream, (FILE *)1);
    expect_string(__wrap_fprintf, formatted_msg, "#test_default\n");
    will_return(__wrap_fprintf, 0);

    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_value(__wrap_fclose, _File, (FILE *)1);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_OS_MD5_Str, str, "buffer stream");
    expect_value(__wrap_OS_MD5_Str, length, 13);
    will_return(__wrap_OS_MD5_Str, "md5_test");
    will_return(__wrap_OS_MD5_Str, 0);

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "md5_test");
    will_return(__wrap_OS_MD5_File, -1);

    expect_string(__wrap_wfopen, path, "etc/shared/test_default/merged.mg");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, NULL);

    will_return(__wrap_strerror, "No such file or directory");

    expect_string(__wrap__merror, formatted_msg, "Unable to open file: 'etc/shared/test_default/merged.mg' due to [(0)-(No such file or directory)].");
    // End c_group function

    expect_string(__wrap__mdebug2, formatted_msg, "Group 'test_default' has changed.");

    will_return(__wrap_OSHash_Clean, NULL);

    will_return(__wrap_readdir, NULL);

    process_groups();

    os_free(entry);
}

void test_process_groups_find_group_not_changed(void **state)
{
    group_t *group = (group_t *)state[1];

    struct dirent *entry;
    os_calloc(1, sizeof(struct dirent), entry);
    strcpy(entry->d_name, "test_default");

    char** subdir = NULL;
    os_malloc(4 * sizeof(char *), subdir);
    os_strdup("merged.mg", subdir[0]);
    os_strdup("test_file", subdir[1]);
    os_strdup("agent.conf", subdir[2]);
    subdir[3] = NULL;

    OSHashNode* node1 = NULL;
    os_calloc(1, sizeof(OSHashNode), node1);
    node1->data = group->f_time;

    will_return(__wrap_opendir, 1);

    will_return(__wrap_readdir, entry);

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, subdir);

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_default");
    will_return(__wrap_OSHash_Get_ex, group);

    // Start c_group function
    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_string(__wrap_stat, __file, "etc/shared/ar.conf");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);

    // Start validate_shared_files function
    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default'");
    // End validate_shared_files function

    expect_string(__wrap_OS_MD5_File, fname, "etc/shared/test_default/merged.mg");
    expect_value(__wrap_OS_MD5_File, mode, OS_TEXT);
    will_return(__wrap_OS_MD5_File, "1212121212121");
    will_return(__wrap_OS_MD5_File, -1);
    // End c_group function

    // Start ftime_changed
    expect_value(__wrap_OSHash_Get_Elem_ex, self, group->f_time);
    will_return(__wrap_OSHash_Get_Elem_ex, 2);

    expect_value(__wrap_OSHash_Get_Elem_ex, self, (OSHash *)10);
    will_return(__wrap_OSHash_Get_Elem_ex, 2);

    expect_value(__wrap_OSHash_Begin, self, group->f_time);
    will_return(__wrap_OSHash_Begin, node1);

    expect_value(__wrap_OSHash_Get_ex, self, (OSHash *)10);
    expect_any(__wrap_OSHash_Get_ex, key);
    will_return(__wrap_OSHash_Get_ex, group->f_time);

    expect_value(__wrap_OSHash_Next, self, group->f_time);
    will_return(__wrap_OSHash_Next, NULL);
    // End ftime_changed

    will_return(__wrap_OSHash_Clean, NULL);

    will_return(__wrap_readdir, NULL);

    process_groups();

    os_free(entry);
    os_free(node1);
}

void test_process_multi_groups_no_groups(void **state)
{
    will_return(__wrap_wdb_get_distinct_agent_groups, NULL);

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, NULL);

    process_multi_groups();
}

void test_process_multi_groups_single_group(void **state)
{
    cJSON* j_agent_info = cJSON_Parse("[{\"group\":\"group1\",\"group_hash\":\"ec282560\"}]");

    will_return(__wrap_wdb_get_distinct_agent_groups, j_agent_info);

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, NULL);

    process_multi_groups();
}

void test_process_multi_groups_OSHash_Add_fail(void **state)
{
    cJSON* j_agent_info = cJSON_Parse("[[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]]");

    will_return(__wrap_wdb_get_distinct_agent_groups, j_agent_info);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, m_hash);
    expect_string(__wrap_OSHash_Add_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Couldn't add multigroup 'group1,group2' to hash table 'm_hash'");

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, NULL);

    process_multi_groups();
}

void test_process_multi_groups_OSHash_Add_fail_multi_chunk_empty_first(void **state)
{
    cJSON* j_agent_info = cJSON_Parse("[[],[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]]");

    will_return(__wrap_wdb_get_distinct_agent_groups, j_agent_info);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, m_hash);
    expect_string(__wrap_OSHash_Add_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Couldn't add multigroup 'group1,group2' to hash table 'm_hash'");

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, NULL);

    process_multi_groups();
}

void test_process_multi_groups_OSHash_Add_fail_multi_chunk_empty_second(void **state)
{
    cJSON* j_agent_info = cJSON_Parse("[[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}],[]]");

    will_return(__wrap_wdb_get_distinct_agent_groups, j_agent_info);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, m_hash);
    expect_string(__wrap_OSHash_Add_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Couldn't add multigroup 'group1,group2' to hash table 'm_hash'");

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, NULL);

    process_multi_groups();
}

void test_process_multi_groups_OSHash_Add_fail_multi_chunk(void **state)
{
    cJSON* j_agent_info = cJSON_Parse("[[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}], [{\"group\":\"group3,group4\",\"group_hash\":\"abcdef\"}]]");

    will_return(__wrap_wdb_get_distinct_agent_groups, j_agent_info);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, m_hash);
    expect_string(__wrap_OSHash_Add_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Couldn't add multigroup 'group1,group2' to hash table 'm_hash'");

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, m_hash);
    expect_string(__wrap_OSHash_Add_ex, key, "group3,group4");
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Couldn't add multigroup 'group3,group4' to hash table 'm_hash'");

    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, NULL);

    process_multi_groups();
}

void test_process_multi_groups_open_fail(void **state)
{
    cJSON* j_agent_info = cJSON_Parse("[[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]]");

    will_return(__wrap_wdb_get_distinct_agent_groups, j_agent_info);

    __real_OSHash_SetFreeDataPointer(mock_hashmap, (void (*)(void *))cleaner);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, m_hash);
    expect_string(__wrap_OSHash_Add_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Add_ex, 2);

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
}

void test_process_multi_groups_find_multi_group_null(void **state)
{
    cJSON* j_agent_info = cJSON_Parse("[[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]]");

    will_return(__wrap_wdb_get_distinct_agent_groups, j_agent_info);

    __real_OSHash_SetFreeDataPointer(mock_hashmap, (void (*)(void *))free_group_c_group);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, m_hash);
    expect_string(__wrap_OSHash_Add_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Couldn't add multigroup 'group1,group2' to hash table 'm_hash'");

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

    expect_value(__wrap_OSHash_Get_ex, self, multi_groups);
    expect_string(__wrap_OSHash_Get_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Get_ex, NULL);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, multi_groups);
    expect_string(__wrap_OSHash_Add_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Add_ex, 2);

    // Start c_multi_group
    // Open the multi-group files and generate merged
    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups/ef48b4cd");
    will_return(__wrap_cldir_ex_ignore, 0);

    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    expect_value(__wrap_OSHash_Next, self, m_hash);
    will_return(__wrap_OSHash_Next, NULL);

    process_multi_groups();

    os_free(hash_node->key);
    os_free(hash_node);
}

void test_process_multi_groups_group_changed(void **state)
{
    group_t *group = (group_t *)state[0];
    group_t *multigroup = (group_t *)state[1];

    state[0] = multigroup->f_time;

    cJSON* j_agent_info = cJSON_Parse("[[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]]");

    will_return(__wrap_wdb_get_distinct_agent_groups, j_agent_info);

    __real_OSHash_SetFreeDataPointer(mock_hashmap, (void (*)(void *))cleaner);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, m_hash);
    expect_string(__wrap_OSHash_Add_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Add_ex, 2);

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

    expect_value(__wrap_OSHash_Get_ex, self, multi_groups);
    expect_string(__wrap_OSHash_Get_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Get_ex, multigroup);

    // Start group_changed
    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "group1");
    will_return(__wrap_OSHash_Get_ex, group);
    // End group_changed

    will_return(__wrap_OSHash_Clean, NULL);

    // Start c_multi_group
    // Open the multi-group files and generate merged
    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups/ef48b4cd");
    will_return(__wrap_cldir_ex_ignore, 0);

    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    expect_string(__wrap__mdebug2, formatted_msg, "Multigroup 'group1,group2' has changed.");

    expect_value(__wrap_OSHash_Next, self, m_hash);
    will_return(__wrap_OSHash_Next, NULL);

    process_multi_groups();

    os_free(hash_node->key);
    os_free(hash_node);
}

void test_process_multi_groups_changed_outside(void **state)
{
    group_t *group = (group_t *)state[0];
    group_t *multigroup = (group_t *)state[1];

    group->has_changed = false;

    state[0] = multigroup->f_time;

    cJSON* j_agent_info = cJSON_Parse("[[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]]");

    will_return(__wrap_wdb_get_distinct_agent_groups, j_agent_info);

    __real_OSHash_SetFreeDataPointer(mock_hashmap, (void (*)(void *))cleaner);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, m_hash);
    expect_string(__wrap_OSHash_Add_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Add_ex, 2);

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

    expect_value(__wrap_OSHash_Get_ex, self, multi_groups);
    expect_string(__wrap_OSHash_Get_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Get_ex, multigroup);

    // Start group_changed
    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "group1");
    will_return(__wrap_OSHash_Get_ex, group);
    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "group2");
    will_return(__wrap_OSHash_Get_ex, group);
    // End group_changed

    will_return(__wrap_OSHash_Clean, NULL);

    // Start c_multi_group
    // Open the multi-group files, no generate merged
    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups/ef48b4cd");
    will_return(__wrap_cldir_ex_ignore, 0);

    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': No such file or directory");

    // Open the multi-group files and generate merged
    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups/ef48b4cd");
    will_return(__wrap_cldir_ex_ignore, 0);

    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    expect_string(__wrap__mwarn, formatted_msg, "Multigroup 'group1,group2' was modified from outside, so it was regenerated.");

    expect_value(__wrap_OSHash_Next, self, m_hash);
    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_OSHash_Clean, NULL);

    process_multi_groups();

    os_free(hash_node->key);
    os_free(hash_node);
}

void test_process_multi_groups_changed_outside_nocmerged(void **state)
{
    group_t *group = (group_t *)state[0];
    group_t *multigroup = (group_t *)state[1];

    group->has_changed = false;

    state[0] = multigroup->f_time;

    cJSON* j_agent_info = cJSON_Parse("[[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]]");

    will_return(__wrap_wdb_get_distinct_agent_groups, j_agent_info);

    __real_OSHash_SetFreeDataPointer(mock_hashmap, (void (*)(void *))cleaner);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, m_hash);
    expect_string(__wrap_OSHash_Add_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Add_ex, 2);

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

    expect_value(__wrap_OSHash_Get_ex, self, multi_groups);
    expect_string(__wrap_OSHash_Get_ex, key, "group1,group2");
    will_return(__wrap_OSHash_Get_ex, multigroup);

    // Start group_changed
    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "group1");
    will_return(__wrap_OSHash_Get_ex, group);
    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "group2");
    will_return(__wrap_OSHash_Get_ex, group);
    // End group_changed

    will_return(__wrap_OSHash_Clean, NULL);

    // Start c_multi_group
    // Open the multi-group files, no generate merged
    expect_string(__wrap_cldir_ex_ignore, name, "var/multigroups/ef48b4cd");
    will_return(__wrap_cldir_ex_ignore, 0);

    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug2, formatted_msg, "Opening directory: 'var/multigroups': No such file or directory");

    expect_string(__wrap__mdebug2, formatted_msg, "Multigroup 'group1,group2' was modified from outside.");
    logr.nocmerged = 1;
    expect_value(__wrap_OSHash_Next, self, m_hash);
    will_return(__wrap_OSHash_Next, NULL);

    process_multi_groups();

    logr.nocmerged = 0;

    os_free(hash_node->key);
    os_free(hash_node);
}

void test_c_files(void **state)
{
    expect_string(__wrap__mdebug2, formatted_msg, "Updating shared files.");

    expect_function_call(__wrap_pthread_mutex_lock);

    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "No such file or directory");
    expect_string(__wrap__mdebug1, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    will_return(__wrap_wdb_get_distinct_agent_groups, NULL);

    m_hash = (OSHash *)1;
    expect_value(__wrap_OSHash_Begin, self, m_hash);
    will_return(__wrap_OSHash_Begin, NULL);

    expect_value(__wrap_OSHash_Begin, self, groups);
    will_return(__wrap_OSHash_Begin, NULL);

    will_return(__wrap_OSHash_Clean, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, (OSHash *)10);

    expect_value(__wrap_OSHash_Begin, self, multi_groups);
    will_return(__wrap_OSHash_Begin, NULL);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__mdebug2, formatted_msg, "End updating shared files.");

    c_files(false);
}

void test_validate_shared_files_files_null(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default'");

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_hidden_file(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup(".hidden_file");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_merged_file(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("merged.mg");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_max_path_size_warning(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;
    char log_str[PATH_MAX + 1] = {0};

    snprintf(log_str, PATH_MAX, "Path too long '%s/test-file'", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-files");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, LONG_PATH);
    will_return(__wrap_wreaddir, files);

    expect_string(__wrap__mwarn, formatted_msg, log_str);

    reported_path_size_exceeded = 0;

    validate_shared_files(LONG_PATH, finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_max_path_size_debug(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;
    char log_str[PATH_MAX + 1] = {0};

    snprintf(log_str, PATH_MAX, "Path too long '%s/test-file'", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-files");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, LONG_PATH);
    will_return(__wrap_wreaddir, files);

    expect_string(__wrap__mdebug2, formatted_msg, log_str);

    reported_path_size_exceeded = 1;

    validate_shared_files(LONG_PATH, finalfp, &_f_time, false, false, -1);

    reported_path_size_exceeded = 0;
}

void test_validate_shared_files_valid_file_limite_size(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;
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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, file_str);
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, file_str);
    will_return(__wrap_checkBinaryFile, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, file_str);
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_any(__wrap__merror, formatted_msg);

    validate_shared_files(LONG_PATH, finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_still_invalid(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

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

    expect_string(__wrap__mdebug1, formatted_msg, "File 'etc/shared/test_default/test-file' modified but still invalid.");

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);

    os_free(last_modify);
}

void test_validate_shared_files_valid_now(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

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

    expect_string(__wrap__minfo, formatted_msg, "File 'etc/shared/test_default/test-file' is valid after last modification.");

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_any(__wrap__merror, formatted_msg);

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_valid_file(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_any(__wrap__merror, formatted_msg);

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_stat_error(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

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

    expect_string(__wrap__merror, formatted_msg, "Unable to get entry attributes 'etc/shared/test_default/stat-error-file'");

    struct stat stat_buf = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-file");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_any(__wrap__merror, formatted_msg);

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_merge_file(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    expect_value(__wrap_MergeAppendFile, finalfp, finalfp);
    expect_value(__wrap_MergeAppendFile, path_offset, 0x18);
    will_return(__wrap_MergeAppendFile, 1);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_any(__wrap__merror, formatted_msg);

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, true, false, -1);
}

void test_validate_shared_files_merge_file_append_fail(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    expect_value(__wrap_MergeAppendFile, finalfp, finalfp);
    expect_value(__wrap_MergeAppendFile, path_offset, 0x18);
    will_return(__wrap_MergeAppendFile, 0);

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, true, false, -1);
}

void test_validate_shared_files_fail_add(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

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

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_subfolder_empty(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

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

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default/test-subfolder'");

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_subfolder_append_fail(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-subfolder");
    files[1] = NULL;
    char ** files2 = NULL;
    os_malloc((2) * sizeof(char *), files2);
    files2[0] = strdup("test-file");
    files2[1] = NULL;

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default");
    will_return(__wrap_wreaddir, files);

    struct stat stat_buf = { .st_mode = 0040000 };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_stat, &stat_buf);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_wreaddir, files2);

    struct stat stat_buf2 = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_stat, &stat_buf2);
    will_return(__wrap_stat, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    expect_value(__wrap_MergeAppendFile, finalfp, finalfp);
    expect_value(__wrap_MergeAppendFile, path_offset, 0x18);
    will_return(__wrap_MergeAppendFile, 0);

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, true, false, -1);
}

void test_validate_shared_files_valid_file_subfolder_empty(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "etc/shared/test_default/test-file");
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_any(__wrap__merror, formatted_msg);

    struct stat stat_buf_2 = { .st_mode = S_IFDIR };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_stat, &stat_buf_2);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_wreaddir, name, "etc/shared/test_default/test-subfolder");
    will_return(__wrap_wreaddir, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not open directory 'etc/shared/test_default/test-subfolder'");

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_subfolder_valid_file(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_any(__wrap__merror, formatted_msg);

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_valid_file_subfolder_valid_file(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "etc/shared/test_default/test-subfolder/test-file");
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_any(__wrap__merror, formatted_msg);

    struct stat stat_buf_3 = { .st_mode = S_IFREG };
    expect_string(__wrap_stat, __file, "etc/shared/test_default/test-file-main-folder");
    will_return(__wrap_stat, &stat_buf_3);
    will_return(__wrap_stat, 0);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-file-main-folder");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-file-main-folder");
    will_return(__wrap_checkBinaryFile, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "etc/shared/test_default/test-file-main-folder");
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_any(__wrap__merror, formatted_msg);

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);
}

void test_validate_shared_files_sub_subfolder_valid_file(void **state)
{
    FILE * finalfp = (FILE *)5;
    OSHash *_f_time = (OSHash *)10;

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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 10);
    invalid_files = OSHash_Create();

    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "etc/shared/test_default/test-subfolder/test-subfolder2/test-file");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_checkBinaryFile, f_name, "etc/shared/test_default/test-subfolder/test-subfolder2/test-file");
    will_return(__wrap_checkBinaryFile, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, (OSHash *)10);
    expect_string(__wrap_OSHash_Add_ex, key, "etc/shared/test_default/test-subfolder/test-subfolder2/test-file");
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_any(__wrap__merror, formatted_msg);

    validate_shared_files("etc/shared/test_default", finalfp, &_f_time, false, false, -1);
}

void test_copy_directory_files_null(void **state)
{
    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, NULL);

    errno = 1;
    expect_string(__wrap__mwarn, formatted_msg, "Could not open directory 'src_path'. Group folder was deleted.");

    copy_directory("src_path", "dst_path", "group_test");

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

    copy_directory("src_path", "dst_path", "group_test");
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

    copy_directory("src_path", "dst_path", "group_test");
}

void test_copy_directory_source_path_too_long_warning(void **state)
{
    char log_str[PATH_MAX + 1] = {0};
    snprintf(log_str, PATH_MAX, "Source path too long '%s/test-file'", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-files");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, LONG_PATH);
    will_return(__wrap_wreaddir, files);

    expect_string(__wrap__mwarn, formatted_msg, log_str);

    reported_path_size_exceeded = 0;

    copy_directory(LONG_PATH, "dst_path", "group_test");
}

void test_copy_directory_source_path_too_long_debug(void **state)
{
    char log_str[PATH_MAX + 1] = {0};
    snprintf(log_str, PATH_MAX, "Source path too long '%s/test-file'", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-files");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, LONG_PATH);
    will_return(__wrap_wreaddir, files);

    expect_string(__wrap__mdebug2, formatted_msg, log_str);

    reported_path_size_exceeded = 1;

    copy_directory(LONG_PATH, "dst_path", "group_test");

    reported_path_size_exceeded = 0;
}

void test_copy_directory_destination_path_too_long_warning(void **state)
{
    char log_str[PATH_MAX + 1] = {0};
    snprintf(log_str, PATH_MAX, "Destination path too long '%s/test-file'", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-files");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    expect_string(__wrap__mwarn, formatted_msg, log_str);

    reported_path_size_exceeded = 0;

    copy_directory("src_path", LONG_PATH, "group_test");
}

void test_copy_directory_destination_path_too_long_debug(void **state)
{
    char log_str[PATH_MAX + 1] = {0};
    snprintf(log_str, PATH_MAX, "Destination path too long '%s/test-file'", LONG_PATH);

    // Initialize files structure
    char ** files = NULL;
    os_malloc((2) * sizeof(char *), files);
    files[0] = strdup("test-files");
    files[1] = NULL;

    expect_string(__wrap_wreaddir, name, "src_path");
    will_return(__wrap_wreaddir, files);

    expect_string(__wrap__mdebug2, formatted_msg, log_str);

    reported_path_size_exceeded = 1;

    copy_directory("src_path", LONG_PATH, "group_test");

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

    copy_directory("src_path", "dst_path", "group_test");

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

    copy_directory("src_path", "dst_path", "group_test");
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

    copy_directory("src_path", "dst_path", "group_test");
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

    copy_directory("src_path", "dst_path", "group_test");
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

    copy_directory("src_path", "dst_path", "group_test");
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

    expect_string(__wrap__mwarn, formatted_msg, "Could not open directory 'src_path/subfolder'. Group folder was deleted.");

    copy_directory("src_path", "dst_path", "group_test");
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

    copy_directory("src_path", "dst_path", "group_test");
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

    expect_string(__wrap__mwarn, formatted_msg, "Invalid message from agent: 'NEW_AGENT' (001)");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    free_keyentry(&key);
}

void test_save_controlmsg_agent_invalid_version(void **state)
{
    char r_msg[OS_SIZE_128] = {0};
    char s_msg[OS_FLSIZE + 1] = {0};
    strcpy(r_msg, "agent startup {\"version\":\"v4.6.0\"}");
    snprintf(s_msg, OS_FLSIZE, "%s%s%s%s%s", CONTROL_HEADER, HC_ERROR, "{\"message\":\"", HC_INVALID_VERSION_RESPONSE, "\"}");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);
    memset(&key.peer_info, 0, sizeof(struct sockaddr_storage));

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "Agent NEW_AGENT sent HC_STARTUP from ''");

    expect_string(__wrap_compare_wazuh_versions, version1, "v4.5.0");
    expect_string(__wrap_compare_wazuh_versions, version2, "v4.6.0");
    expect_value(__wrap_compare_wazuh_versions, compare_patch, false);
    will_return(__wrap_compare_wazuh_versions, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Unable to connect agent: '001': 'Incompatible version'");

    expect_value(__wrap_wdb_update_agent_status_code, id, 1);
    expect_value(__wrap_wdb_update_agent_status_code, status_code, INVALID_VERSION);
    expect_string(__wrap_wdb_update_agent_status_code, version, "v4.6.0");
    expect_string(__wrap_wdb_update_agent_status_code, sync_status, "synced");
    will_return(__wrap_wdb_update_agent_status_code, OS_SUCCESS);

    expect_string(__wrap_send_msg, agent_id, "001");
    expect_string(__wrap_send_msg, msg, s_msg);

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    free_keyentry(&key);
}

void test_save_controlmsg_get_agent_version_fail(void **state)
{
    char r_msg[OS_SIZE_128] = {0};
    char s_msg[OS_FLSIZE + 1] = {0};
    strcpy(r_msg, "agent startup {\"test\":\"fail\"}");
    snprintf(s_msg, OS_FLSIZE, "%s%s%s%s%s", CONTROL_HEADER, HC_ERROR, "{\"message\":\"", HC_RETRIEVE_VERSION, "\"}");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);
    memset(&key.peer_info, 0, sizeof(struct sockaddr_storage));

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "Agent NEW_AGENT sent HC_STARTUP from ''");
    expect_string(__wrap__merror, formatted_msg, "Error getting version from agent '001'");

    expect_string(__wrap__mdebug2, formatted_msg, "Unable to connect agent: '001': 'Couldn't retrieve version'");

    expect_value(__wrap_wdb_update_agent_status_code, id, 1);
    expect_value(__wrap_wdb_update_agent_status_code, status_code, ERR_VERSION_RECV);
    expect_string(__wrap_wdb_update_agent_status_code, sync_status, "synced");
    will_return(__wrap_wdb_update_agent_status_code, OS_INVALID);

    expect_string(__wrap__mwarn, formatted_msg, "Unable to set status code for agent: '001'");

    expect_string(__wrap_send_msg, agent_id, "001");
    expect_string(__wrap_send_msg, msg, s_msg);

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    free_keyentry(&key);
}

void test_save_controlmsg_could_not_add_pending_data(void **state)
{
    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, "Invalid message \n with enter");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, agent_id, "001");
    expect_string(__wrap_send_msg, msg, "#!-agent ack ");

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    expect_string(__wrap_rem_inc_recv_ctrl_keepalive, agent_id, "001");

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);
    pending_data = OSHash_Create();

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_OSHash_Get, self, pending_data);
    expect_string(__wrap_OSHash_Get, key, "001");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap_OSHash_Add, key, "001");
    will_return(__wrap_OSHash_Add, 0);

    expect_string(__wrap__merror, formatted_msg, "Couldn't add pending data into hash table.");

    expect_function_call(__wrap_pthread_mutex_unlock);

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    free_keyentry(&key);
}

void test_save_controlmsg_unable_to_save_last_keepalive(void **state)
{
    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, "Invalid message \n with enter");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, agent_id, "001");
    expect_string(__wrap_send_msg, msg, "#!-agent ack ");

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

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

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
    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, "valid message \n with enter");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, agent_id, "001");
    expect_string(__wrap_send_msg, msg, "#!-agent ack ");

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

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_OSHash_Get, self, pending_data);
    expect_string(__wrap_OSHash_Get, key, "001");
    will_return(__wrap_OSHash_Get, data);

    expect_string(__wrap__mdebug2, formatted_msg, "save_controlmsg(): inserting 'valid message \n'");

    groups = (OSHash *)10;
    multi_groups = (OSHash *)10;

    char* group = NULL;
    w_strdup("test_group", group);
    expect_value(__wrap_wdb_get_agent_group, id, 1);
    will_return(__wrap_wdb_get_agent_group, group);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' group is 'test_group'");

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_group");
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_value(__wrap_OSHash_Get_ex, self, multi_groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_group");
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "No such group 'test_group' for agent '001'");

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_unlock);

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
    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, "valid message \n with enter");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, agent_id, "001");
    expect_string(__wrap_send_msg, msg, "#!-agent ack ");

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

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_OSHash_Get, self, pending_data);
    expect_string(__wrap_OSHash_Get, key, "001");
    will_return(__wrap_OSHash_Get, data);

    expect_string(__wrap__mdebug2, formatted_msg, "save_controlmsg(): inserting 'valid message \n'");

    groups = (OSHash *)10;
    multi_groups = (OSHash *)10;

    group_t *group = NULL;
    os_calloc(1, sizeof(group_t), group);
    group->name = strdup("test_group");
    memset(&group->merged_sum, 0, sizeof(os_md5));
    snprintf(group->merged_sum, 7, "112359");

    expect_function_call(__wrap_pthread_mutex_lock);

    char* group_name = NULL;
    w_strdup("test_group", group_name);
    expect_value(__wrap_wdb_get_agent_group, id, 1);
    will_return(__wrap_wdb_get_agent_group, group_name);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' group is 'test_group'");

    expect_value(__wrap_OSHash_Get_ex, self, groups);
    expect_string(__wrap_OSHash_Get_ex, key, "test_group");
    will_return(__wrap_OSHash_Get_ex, group);

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_unlock);

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

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_any(__wrap_wdb_update_agent_data, agent_data);
    will_return(__wrap_wdb_update_agent_data, OS_INVALID);

    os_calloc(1, sizeof(w_linked_queue_t), pending_queue);

    expect_any(__wrap_linked_queue_push_ex, queue);
    expect_any(__wrap_linked_queue_push_ex, data);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to update information in global.db for agent: 001");

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    os_free(group->name);
    os_free(group);

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
    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, "valid message \n with enter");

    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, agent_id, "001");
    expect_string(__wrap_send_msg, msg, "#!-agent ack ");

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

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_string(__wrap__mdebug2, formatted_msg, "save_controlmsg(): inserting 'valid message \n'");

    expect_value(__wrap_wdb_get_agent_group, id, 1);
    will_return(__wrap_wdb_get_agent_group, NULL);

    expect_function_call(__wrap_pthread_mutex_unlock);

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

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

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
    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, "agent startup {\"version\":\"v4.5.0\"}");
    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);
    key.peer_info.ss_family = 0;
    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_string(__wrap_send_msg, agent_id, "001");
    expect_string(__wrap_send_msg, msg, "#!-agent ack ");

    expect_string(__wrap_rem_inc_send_ack, agent_id, "001");

    expect_string(__wrap_rem_inc_recv_ctrl_startup, agent_id, "001");

    expect_string(__wrap__mdebug1, formatted_msg, "Agent NEW_AGENT sent HC_STARTUP from ''");

    expect_string(__wrap_compare_wazuh_versions, version1, "v4.5.0");
    expect_string(__wrap_compare_wazuh_versions, version2, "v4.5.0");
    expect_value(__wrap_compare_wazuh_versions, compare_patch, false);
    will_return(__wrap_compare_wazuh_versions, 0);

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

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

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
    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, HC_SHUTDOWN);
    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);
    memset(&key.peer_info, 0, sizeof(struct sockaddr_storage));
    key.peer_info.ss_family = AF_INET;

    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_any(__wrap_get_ipv4_string, address);
    expect_any(__wrap_get_ipv4_string, address_size);
    will_return(__wrap_get_ipv4_string, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent NEW_AGENT sent HC_SHUTDOWN from ''");

    expect_string(__wrap_rem_inc_recv_ctrl_shutdown, agent_id, "001");

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

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

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

    will_return(__wrap_OSHash_Delete_ex, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, "001");
    expect_value(__wrap_OSHash_Delete_ex, self, agent_data_hash);

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    free_keyentry(&key);
    os_free(message);
}

void test_save_controlmsg_shutdown_wdb_fail(void **state)
{
    char r_msg[OS_SIZE_128] = {0};
    strcpy(r_msg, HC_SHUTDOWN);
    keyentry key;
    keyentry_init(&key, "NEW_AGENT", "001", "10.2.2.5", NULL);
    memset(&key.peer_info, 0, sizeof(struct sockaddr_storage));
    key.peer_info.ss_family = AF_INET6;
    size_t msg_length = sizeof(r_msg);
    int *wdb_sock = NULL;

    expect_any(__wrap_get_ipv6_string, address);
    expect_any(__wrap_get_ipv6_string, address_size);
    will_return(__wrap_get_ipv6_string, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Agent NEW_AGENT sent HC_SHUTDOWN from ''");

    expect_string(__wrap_rem_inc_recv_ctrl_shutdown, agent_id, "001");

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

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_value(__wrap_wdb_update_agent_connection_status, id, 1);
    expect_string(__wrap_wdb_update_agent_connection_status, connection_status, AGENT_CS_DISCONNECTED);
    expect_string(__wrap_wdb_update_agent_connection_status, sync_status, "synced");
    will_return(__wrap_wdb_update_agent_connection_status, OS_INVALID);

    expect_string(__wrap__mwarn, formatted_msg, "Unable to set connection status as disconnected for agent: 001");

    will_return(__wrap_OSHash_Delete_ex, NULL);
    expect_string(__wrap_OSHash_Delete_ex, key, "001");
    expect_value(__wrap_OSHash_Delete_ex, self, agent_data_hash);

    save_controlmsg(&key, r_msg, msg_length, wdb_sock);

    free_keyentry(&key);
    os_free(message);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests lookfor_agent_group
        cmocka_unit_test(test_lookfor_agent_group_with_group),
        // Tests c_group
        cmocka_unit_test_setup_teardown(test_c_group_no_changes, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_no_changes_disk, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_changes, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_changes_disk, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_fail, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_fail_disk, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_downloaded_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_downloaded_file_no_poll, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_downloaded_file_is_corrupted, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_download_all_files, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_no_create_shared_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_invalid_share_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_append_file_error, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_append_ar_error, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_truncate_error, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_c_group_truncate_error_disk, test_c_group_setup, test_c_group_teardown),
        // Tests c_multi_group
        cmocka_unit_test(test_c_multi_group_hash_multigroup_null),
        cmocka_unit_test(test_c_multi_group_open_directory_fail),
        cmocka_unit_test(test_c_multi_group_call_copy_directory),
        cmocka_unit_test(test_c_multi_group_read_dir_fail_no_entry),
        cmocka_unit_test(test_c_multi_group_Ignore_hidden_files),
        cmocka_unit_test(test_c_multi_group_subdir_fail),
        cmocka_unit_test(test_c_multi_group_call_c_group),
        // Test ftime_changed
        cmocka_unit_test_setup_teardown(test_ftime_changed_same_fsum, test_ftime_changed_setup, test_ftime_changed_teardown),
        cmocka_unit_test_setup_teardown(test_ftime_changed_different_fsum_sum, test_ftime_changed_setup, test_ftime_changed_teardown),
        cmocka_unit_test_setup_teardown(test_ftime_changed_different_fsum_name, test_ftime_changed_setup, test_ftime_changed_teardown),
        cmocka_unit_test_setup_teardown(test_ftime_changed_different_size, test_ftime_changed_setup, test_ftime_changed_teardown),
        cmocka_unit_test_setup_teardown(test_ftime_changed_one_null, test_ftime_changed_setup, test_ftime_changed_teardown),
        cmocka_unit_test(test_ftime_changed_both_null),
        // Test group_changed
        cmocka_unit_test_setup_teardown(test_group_changed_not_changed, test_find_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_group_changed_has_changed, test_find_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_group_changed_not_exists, test_find_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_group_changed_invalid_group, test_find_group_setup, test_c_group_teardown),
        // Test process_deleted_groups
        cmocka_unit_test_setup_teardown(test_process_deleted_groups_delete, test_process_deleted_groups_setup, test_process_deleted_groups_teardown),
        cmocka_unit_test_setup_teardown(test_process_deleted_groups_no_changes, test_find_group_setup, test_c_group_teardown),
        // Test process_deleted_multi_groups
        cmocka_unit_test_setup_teardown(test_process_deleted_multi_groups_delete, test_process_deleted_multi_groups_setup, test_process_deleted_groups_teardown),
        cmocka_unit_test_setup_teardown(test_process_deleted_multi_groups_no_changes, test_find_multi_group_setup, test_c_multi_group_teardown),
        cmocka_unit_test_setup_teardown(test_process_deleted_multi_groups_no_changes_initial_scan, test_find_multi_group_setup, test_c_multi_group_teardown),
        // Test process_groups
        cmocka_unit_test(test_process_groups_open_directory_fail),
        cmocka_unit_test(test_process_groups_readdir_fail),
        cmocka_unit_test(test_process_groups_subdir_null),
        cmocka_unit_test(test_process_groups_skip),
        cmocka_unit_test(test_process_groups_skip_2),
        cmocka_unit_test_setup_teardown(test_process_groups_find_group_null, test_process_group_setup, test_process_groups_teardown),
        cmocka_unit_test_setup_teardown(test_process_groups_find_group_changed, test_process_group_setup, test_process_groups_teardown),
        cmocka_unit_test_setup_teardown(test_process_groups_find_group_not_changed, test_process_group_setup, test_process_groups_teardown),
        // Test process_multi_groups
        cmocka_unit_test(test_process_multi_groups_no_groups),
        cmocka_unit_test(test_process_multi_groups_single_group),
        cmocka_unit_test(test_process_multi_groups_OSHash_Add_fail),
        cmocka_unit_test(test_process_multi_groups_OSHash_Add_fail_multi_chunk_empty_first),
        cmocka_unit_test(test_process_multi_groups_OSHash_Add_fail_multi_chunk_empty_second),
        cmocka_unit_test(test_process_multi_groups_OSHash_Add_fail_multi_chunk),
        cmocka_unit_test_setup_teardown(test_process_multi_groups_open_fail, test_process_multi_groups_setup, test_process_multi_groups_teardown),
        cmocka_unit_test_setup_teardown(test_process_multi_groups_find_multi_group_null, test_process_multi_groups_setup, test_process_multi_groups_teardown),
        cmocka_unit_test_setup_teardown(test_process_multi_groups_group_changed, test_process_multi_groups_groups_setup, test_process_multi_groups_groups_teardown),
        cmocka_unit_test_setup_teardown(test_process_multi_groups_changed_outside, test_process_multi_groups_groups_setup, test_process_multi_groups_groups_teardown),
        cmocka_unit_test_setup_teardown(test_process_multi_groups_changed_outside_nocmerged, test_process_multi_groups_groups_setup, test_process_multi_groups_groups_teardown),
        // Test c_files
        cmocka_unit_test_setup_teardown(test_c_files, test_c_files_setup, test_c_files_teardown),
        // Test validate_shared_files
        cmocka_unit_test_setup_teardown(test_validate_shared_files_files_null, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_hidden_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_merged_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_max_path_size_warning, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_max_path_size_debug, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_valid_file_limite_size, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_still_invalid, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_valid_now, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_valid_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_fail_add, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_stat_error, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_merge_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_merge_file_append_fail, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_subfolder_empty, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_subfolder_append_fail, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_valid_file_subfolder_empty, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_subfolder_valid_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_valid_file_subfolder_valid_file, test_c_group_setup, test_c_group_teardown),
        cmocka_unit_test_setup_teardown(test_validate_shared_files_sub_subfolder_valid_file, test_c_group_setup, test_c_group_teardown),
        // Test copy_directory
        cmocka_unit_test(test_copy_directory_files_null),
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
        cmocka_unit_test_setup_teardown(test_save_controlmsg_agent_invalid_version, setup_globals_no_test_mode, teardown_globals),
        cmocka_unit_test_setup_teardown(test_save_controlmsg_get_agent_version_fail, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_save_controlmsg_could_not_add_pending_data, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_save_controlmsg_unable_to_save_last_keepalive, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_save_controlmsg_update_msg_error_parsing, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_save_controlmsg_update_msg_unable_to_update_information, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_save_controlmsg_update_msg_lookfor_agent_group_fail, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_save_controlmsg_startup, setup_globals, teardown_globals),
        cmocka_unit_test_setup_teardown(test_save_controlmsg_shutdown, setup_globals, teardown_globals),
        cmocka_unit_test_setup_teardown(test_save_controlmsg_shutdown_wdb_fail, setup_globals, teardown_globals),
    };
    return cmocka_run_group_tests(tests, test_setup_group, test_teardown_group);
}
