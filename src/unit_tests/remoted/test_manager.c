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

#include "../remoted/remoted.h"
#include "../remoted/shared_download.h"
#include "../../remoted/manager.c"
#include "../../headers/hash_op.h"
/* tests */

static int test_c_groups_setup(void ** state) {

    return 0;
}

static int test_c_groups_teardown(void ** state) {
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

#if 0
void test_c_files_free_groups_fail_opendir(void **state)
{
    groups = NULL;
    should_clean = 1;

    OSHash * m_hash = OSHash_Create();

    expect_string(__wrap__mdebug2, formatted_msg, "Updating shared files sums.");
    expect_string(__wrap__mdebug1, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    c_files();
}

void test_c_files_scan_directory_fail_opendir(void **state)
{
    groups = NULL;
    should_clean = 0;

    expect_string(__wrap__mdebug2, formatted_msg, "Updating shared files sums.");
    expect_string(__wrap__mdebug1, formatted_msg, "Opening directory: 'etc/shared': No such file or directory");

    c_files();
}
#endif

void test_c_group_fail(void **state)
{

    const char *group = "test_default";
    char ** files = NULL;

    // static group_t *test_groups = NULL;
    // // groups is a manager.c global variable
    // groups = &test_groups;

    // Initialize main groups structure
    os_calloc(1, sizeof(group_t *), groups);

    int p_size = 0;
    os_realloc(groups, (p_size + 2) * sizeof(group_t *), groups);
    os_calloc(1, sizeof(group_t), groups[p_size]);

    groups[p_size]->group = strdup("test_default");
    groups[p_size + 1] = NULL;


    os_malloc(sizeof(char *), files);
    os_realloc(files, (p_size + 2) * sizeof(char *), files);

    files[p_size] = strdup("files");
    files[p_size + 1] = NULL;

    expect_string(__wrap_MergeAppendFile, finalpath, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_MergeAppendFile, tag, "test_default");
    expect_value(__wrap_MergeAppendFile, path_offset, -1);
    will_return(__wrap_MergeAppendFile, 1);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/files'");

    expect_string(__wrap_OS_MoveFile, src, "etc/shared/test_default/merged.mg.tmp");
    expect_string(__wrap_OS_MoveFile, dst, "etc/shared/test_default/merged.mg");
    will_return(__wrap_OS_MoveFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Accessing file 'etc/shared/test_default/merged.mg'");

    //c_group(entry->d_name, subdir, &groups[p_size]->f_sum, SHAREDCFG_DIR);
    c_group(group, files, &groups[p_size]->f_sum, SHAREDCFG_DIR);

    os_free(files[p_size]);
    os_free(files[p_size+1]);
    os_free(files);
}

//void c_group(const char *group, char ** files, file_sum ***_f_sum, char * sharedcfg_dir)

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
        // Tests c_files
        //cmocka_unit_test(test_c_files_free_groups_fail_opendir),
        //cmocka_unit_test(test_c_files_scan_directory_fail_opendir),
        cmocka_unit_test_setup_teardown(test_c_group_fail, test_c_groups_setup, test_c_groups_teardown),

    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
