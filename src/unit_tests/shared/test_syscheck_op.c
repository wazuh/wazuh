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

#include "../headers/syscheck_op.h"

#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/posix/grp_wrappers.h"
#include "../wrappers/posix/pwd_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/string_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/privsep_op_wrappers.h"
#include "../wrappers/wazuh/shared/utf8_winapi_wrapper_wrappers.h"
#include "../wrappers/common.h"

#ifdef TEST_WINAGENT
#include "../wrappers/wazuh/syscheckd/syscom_wrappers.h"
#include "../wrappers/windows/sddl_wrappers.h"
#include "../wrappers/windows/winreg_wrappers.h"
#include "../wrappers/windows/aclapi_wrappers.h"
#include "../wrappers/windows/winbase_wrappers.h"
#include "../wrappers/windows/fileapi_wrappers.h"
#include "../wrappers/windows/handleapi_wrappers.h"
#include "../wrappers/windows/errhandlingapi_wrappers.h"
#include "../wrappers/windows/securitybaseapi_wrappers.h"
#else
#include "../wrappers/posix/unistd_wrappers.h"
#endif

/* Auxiliar structs */

#ifdef TEST_WINAGENT
typedef struct __registry_group_information {
    char *name;
    char *id;
} registry_group_information_t;

#define BASE_WIN_SID "S-1-5-32-636"
#endif

/* setup/teardown */

static int teardown_string(void **state) {
    free(*state);
    return 0;
}

#ifdef TEST_WINAGENT

static int setup_string_array(void **state) {
    char **array = calloc(10, sizeof(char*));

    if(array == NULL)
        return -1;

    *state = array;
    test_mode = 1;

    return 0;
}

static int teardown_string_array(void **state) {
    char **array = *state;

    free_strarray(array);
    test_mode = 0;

    return 0;
}

static int setup_get_registry_group(void **state) {
    registry_group_information_t *group_information = (registry_group_information_t *)
                                                        calloc(1, sizeof(registry_group_information_t));

    if (group_information == NULL) {
        return -1;
    }

    group_information->name = (char *)calloc(OS_SIZE_6144 + 1, sizeof(char));
    group_information->id = (char *)calloc(OS_SIZE_6144 + 1, sizeof(char));

    if (group_information->name == NULL || group_information->id == NULL) {
        return -1;
    }

    *state = group_information;

    return 0;
}

static int teardown_get_registry_group(void **state) {
    registry_group_information_t *group_information = *state;

    free(group_information->name);
    free(group_information->id);
    free(group_information);

    return 0;
}

#endif

static int teardown_cjson(void **state) {
    cJSON *array = *state;

    cJSON_Delete(array);

    return 0;
}

/* Tests */

/* remove_empty_folders tests */
static void test_remove_empty_folders_success(void **state) {
#ifndef TEST_WINAGENT
    char *input = "queue/diff/local/test-dir/";
    char *first_subdir = "queue/diff/local/test-dir";
    char *second_subdir = "queue/diff/local";
#else
    char *input = "queue/diff\\local\\test-dir\\";
    char *first_subdir = "queue/diff\\local\\test-dir";
    char *second_subdir = "queue/diff\\local";
#endif
    int ret = -1;
    char message[OS_SIZE_1024];
    char **mock_directory_content;

    if(mock_directory_content = calloc(2, sizeof(char*)), !mock_directory_content)
        fail();

    mock_directory_content[0] = strdup("some-file.tmp");
    mock_directory_content[1] = NULL;

    expect_wreaddir_call(first_subdir, NULL);

    snprintf(message, OS_SIZE_1024, "Removing empty directory '%s'.", first_subdir);
    expect_string(__wrap__mdebug1, formatted_msg, message);

    expect_rmdir_ex_call(first_subdir, 0);

    expect_wreaddir_call(second_subdir, mock_directory_content);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

static void test_remove_empty_folders_recursive_success(void **state) {
#ifndef TEST_WINAGENT
    char *input = "queue/diff/local/dir1/dir2/";
    static const char *parent_dirs[] = {
        "queue/diff/local/dir1/dir2",
        "queue/diff/local/dir1",
        "queue/diff/local"
    };
#else
    char *input = "queue/diff\\local\\dir1\\dir2\\";
    static const char *parent_dirs[] = {
        "queue/diff\\local\\dir1\\dir2",
        "queue/diff\\local\\dir1",
        "queue/diff\\local"
    };
#endif
    char messages[3][OS_SIZE_1024];
    int ret = -1;
    char **mock_directory_content;

    if(mock_directory_content = calloc(2, sizeof(char*)), !mock_directory_content)
        fail();

    mock_directory_content[0] = strdup("some-file.tmp");
    mock_directory_content[1] = NULL;

    snprintf(messages[0], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[0]);
    snprintf(messages[1], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[1]);

    // Remove dir2
    expect_wreaddir_call(parent_dirs[0], NULL);

    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);

    expect_rmdir_ex_call(parent_dirs[0], 0);

    // Remove dir1
    expect_wreaddir_call(parent_dirs[1], NULL);

    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);

    expect_rmdir_ex_call(parent_dirs[1], 0);

    expect_wreaddir_call(parent_dirs[2], mock_directory_content);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

static void test_remove_empty_folders_null_input(void **state) {
    expect_assert_failure(remove_empty_folders(NULL));
}

// TODO: Validate this condition is required to be tested
static void test_remove_empty_folders_relative_path(void **state) {
#ifndef TEST_WINAGENT
    char *input = "./local/test-dir/";
    const static char *parent_dirs[] = {"./local/test-dir", "./local", "."};
#else
    char *input = ".\\local\\test-dir\\";
    const static char *parent_dirs[] = {".\\local\\test-dir", ".\\local", "."};
#endif
    char messages[3][OS_SIZE_1024];
    int ret = -1;

    snprintf(messages[0], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[0]);
    snprintf(messages[1], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[1]);
    snprintf(messages[2], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[2]);

    expect_wreaddir_call(parent_dirs[0], NULL);
    expect_wreaddir_call(parent_dirs[1], NULL);
    expect_wreaddir_call(parent_dirs[2], NULL);

    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);
    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);
    expect_string(__wrap__mdebug1, formatted_msg, messages[2]);

    expect_rmdir_ex_call(parent_dirs[0], 0);
    expect_rmdir_ex_call(parent_dirs[1], 0);
    expect_rmdir_ex_call(parent_dirs[2], 0);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

// TODO: Validate this condition is required to be tested
static void test_remove_empty_folders_absolute_path(void **state) {
    int ret = -1;
#ifndef TEST_WINAGENT
    char *input = "/home/user1/";
    static const char *parent_dirs[] = {
        "/home/user1",
        "/home",
        ""
    };
#else
    char *input = "c:\\home\\user1\\";
    static const char *parent_dirs[] = {
        "c:\\home\\user1",
        "c:\\home",
        "c:"
    };
#endif
    char messages[3][OS_SIZE_1024];

    snprintf(messages[0], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[0]);
    snprintf(messages[1], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[1]);
    snprintf(messages[2], OS_SIZE_1024, "Removing empty directory '%s'.", parent_dirs[2]);

    expect_wreaddir_call(parent_dirs[0], NULL);
    expect_wreaddir_call(parent_dirs[1], NULL);
    expect_wreaddir_call(parent_dirs[2], NULL);

    expect_string(__wrap__mdebug1, formatted_msg, messages[0]);
    expect_string(__wrap__mdebug1, formatted_msg, messages[1]);
    expect_string(__wrap__mdebug1, formatted_msg, messages[2]);

    expect_rmdir_ex_call(parent_dirs[0], 0);
    expect_rmdir_ex_call(parent_dirs[1], 0);
    expect_rmdir_ex_call(parent_dirs[2], 0);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

static void test_remove_empty_folders_non_empty_dir(void **state) {
#ifndef TEST_WINAGENT
    char *input = "queue/diff/local/test-dir/";
    static const char *parent_dir = "queue/diff/local/test-dir";
#else
    char *input = "queue/diff\\local\\c\\test-dir\\";
    static const char *parent_dir = "queue/diff\\local\\c\\test-dir";
#endif
    int ret = -1;
    char **subdir;

    if(subdir = calloc(2, sizeof(char*)), !subdir)
        fail();

    subdir[0] = strdup("some-file.tmp");
    subdir[1] = NULL;

    expect_wreaddir_call(parent_dir, subdir);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, 0);
}

static void test_remove_empty_folders_error_removing_dir(void **state) {
#ifndef TEST_WINAGENT
    char *input = "queue/diff/local/test-dir/";
    static const char *parent_dir = "queue/diff/local/test-dir";
#else
    char *input = "queue/diff\\local\\test-dir\\";
    static const char *parent_dir = "queue/diff\\local\\test-dir";
#endif
    int ret = -1;
    char remove_dir_message[OS_SIZE_1024];
    char dir_not_deleted_message[OS_SIZE_1024];

    expect_wreaddir_call(parent_dir, NULL);

    snprintf(remove_dir_message, OS_SIZE_1024, "Removing empty directory '%s'.", parent_dir);
    expect_string(__wrap__mdebug1, formatted_msg, remove_dir_message);

    expect_rmdir_ex_call(parent_dir, -1);

    snprintf(dir_not_deleted_message, OS_SIZE_1024,
        "Empty directory '%s' couldn't be deleted. ('Directory not empty')", parent_dir);
    expect_string(__wrap__mwarn, formatted_msg, dir_not_deleted_message);

    ret = remove_empty_folders(input);

    assert_int_equal(ret, -1);
}

#ifndef TEST_WINAGENT
/* get_user tests */
static void test_get_user_success(void **state) {
    char *user;

    will_return(__wrap_sysconf, 16384);

    will_return(__wrap_getpwuid_r, "user_name");
    will_return(__wrap_getpwuid_r, 1);
    will_return(__wrap_getpwuid_r, 0);

    user = get_user(1);

    *state = user;

    assert_string_equal(user, "user_name");
}

static void test_get_user_uid_not_found(void **state) {
    char *user;

    will_return(__wrap_sysconf, -1);

    will_return(__wrap_getpwuid_r, "user_name");
    will_return(__wrap_getpwuid_r, NULL);
    will_return(__wrap_getpwuid_r, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "User with uid '1' not found.\n");

    user = get_user(1);

    *state = user;

    assert_null(user);
}

static void test_get_user_error(void **state) {
    char *user;

    will_return(__wrap_sysconf, 16384);

    will_return(__wrap_getpwuid_r, "user_name");
    will_return(__wrap_getpwuid_r, NULL);
    will_return(__wrap_getpwuid_r, ENOENT);

    expect_string(__wrap__mdebug2, formatted_msg, "Failed getting user_name for uid 1: (2): 'No such file or directory'\n");

    user = get_user(1);

    *state = user;

    assert_null(user);
}
#endif

#if defined(TEST_WINAGENT)
struct group {
    const char *gr_name;
};
#endif

/* get_group tests */
#ifndef TEST_WINAGENT
static void test_get_group_success(void **state) {
    struct group group = { .gr_name = "group" };
    char *output;

    will_return(__wrap_sysconf, -1);

    expect_value(__wrap_w_getgrgid, gid, 1000);
    will_return(__wrap_w_getgrgid, &group);
    will_return(__wrap_w_getgrgid, NULL); // We don't care about member buffers
    will_return(__wrap_w_getgrgid, 1); // Success

    output = get_group(1000);

    assert_string_equal(output, group.gr_name);

    free(output);
}

static void test_get_group_no_group(void **state) {
    const char *output;

    errno = 0;

    will_return(__wrap_sysconf, 8);

    expect_value(__wrap_w_getgrgid, gid, 1000);
    will_return(__wrap_w_getgrgid, NULL);
    will_return(__wrap_w_getgrgid, NULL); // We don't care about member buffers
    will_return(__wrap_w_getgrgid, 0); // Fail

    expect_string(__wrap__mdebug2, formatted_msg, "Group with gid '1000' not found.\n");

    output = get_group(1000);

    assert_null(output);
}

static void test_get_group_error(void **state) {
    const char *output;

    errno = ENOENT;

    will_return(__wrap_sysconf, 8);

    expect_value(__wrap_w_getgrgid, gid, 1000);
    will_return(__wrap_w_getgrgid, NULL);
    will_return(__wrap_w_getgrgid, NULL); // We don't care about member buffers
    will_return(__wrap_w_getgrgid, 0); // Fail

    expect_string(__wrap__mdebug2, formatted_msg, "Failed getting group_name for gid 1000: (2): 'No such file or directory'\n");

    output = get_group(1000);

    assert_null(output);
}

#else
static void test_get_group(void **state) {
    assert_string_equal(get_group(0), "");
}
#endif

/* ag_send_syscheck tests */
/* ag_send_syscheck does not modify inputs or return anything, so there are no asserts */
/* validation of this function is done through the wrapped functions. */
#ifndef TEST_WINAGENT
static void test_ag_send_syscheck_success(void **state) {
    char *input = "This is a mock message, it wont be sent anywhere";

    expect_string(__wrap_OS_ConnectUnixDomain, path, SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);

    will_return(__wrap_OS_ConnectUnixDomain, 1234);

    expect_value(__wrap_OS_SendSecureTCP, sock, 1234);
    expect_value(__wrap_OS_SendSecureTCP, size, 48);
    expect_string(__wrap_OS_SendSecureTCP, msg, input);

    will_return(__wrap_OS_SendSecureTCP, 48);

    ag_send_syscheck(input, strlen(input));
}

static void test_ag_send_syscheck_unable_to_connect(void **state) {
    char *input = "This is a mock message, it wont be sent anywhere";

    expect_string(__wrap_OS_ConnectUnixDomain, path, SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);

    will_return(__wrap_OS_ConnectUnixDomain, OS_SOCKTERR);

    errno = EADDRNOTAVAIL;

    expect_string(__wrap__mwarn, formatted_msg, "dbsync: cannot connect to syscheck: Cannot assign requested address (99)");

    ag_send_syscheck(input, strlen(input));

    errno = 0;
}
static void test_ag_send_syscheck_error_sending_message(void **state) {
    char *input = "This is a mock message, it wont be sent anywhere";

    expect_string(__wrap_OS_ConnectUnixDomain, path, SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);

    will_return(__wrap_OS_ConnectUnixDomain, 1234);

    expect_value(__wrap_OS_SendSecureTCP, sock, 1234);
    expect_value(__wrap_OS_SendSecureTCP, size, 48);
    expect_string(__wrap_OS_SendSecureTCP, msg, input);

    will_return(__wrap_OS_SendSecureTCP, OS_SOCKTERR);

    errno = EWOULDBLOCK;

    expect_string(__wrap__mwarn, formatted_msg, "Cannot send message to syscheck: Resource temporarily unavailable (11)");

    ag_send_syscheck(input, strlen(input));

    errno = 0;
}
#else
static void test_ag_send_syscheck(void **state) {
    char *response = strdup("A mock reponse message");

    expect_string(__wrap_syscom_dispatch, command, "command");
    will_return(__wrap_syscom_dispatch, response);
    will_return(__wrap_syscom_dispatch, 23);

    ag_send_syscheck("command", strlen("command"));
}
#endif

/* decode_win_attributes tests */
static void test_decode_win_attributes_all_attributes(void **state) {
    char str[OS_SIZE_256];
    unsigned int attrs = 0;

    attrs |= FILE_ATTRIBUTE_ARCHIVE     |
             FILE_ATTRIBUTE_COMPRESSED  |
             FILE_ATTRIBUTE_DEVICE      |
             FILE_ATTRIBUTE_DIRECTORY   |
             FILE_ATTRIBUTE_ENCRYPTED   |
             FILE_ATTRIBUTE_HIDDEN      |
             FILE_ATTRIBUTE_NORMAL      |
             FILE_ATTRIBUTE_OFFLINE     |
             FILE_ATTRIBUTE_READONLY    |
             FILE_ATTRIBUTE_SPARSE_FILE |
             FILE_ATTRIBUTE_SYSTEM      |
             FILE_ATTRIBUTE_TEMPORARY   |
             FILE_ATTRIBUTE_VIRTUAL     |
             FILE_ATTRIBUTE_NO_SCRUB_DATA |
             FILE_ATTRIBUTE_REPARSE_POINT |
             FILE_ATTRIBUTE_RECALL_ON_OPEN |
             FILE_ATTRIBUTE_INTEGRITY_STREAM |
             FILE_ATTRIBUTE_NOT_CONTENT_INDEXED |
             FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

    decode_win_attributes(str, attrs);

    assert_string_equal(str, "ARCHIVE, COMPRESSED, DEVICE, DIRECTORY, ENCRYPTED, "
                             "HIDDEN, INTEGRITY_STREAM, NORMAL, NOT_CONTENT_INDEXED, "
                             "NO_SCRUB_DATA, OFFLINE, READONLY, RECALL_ON_DATA_ACCESS, "
                             "RECALL_ON_OPEN, REPARSE_POINT, SPARSE_FILE, SYSTEM, TEMPORARY, "
                             "VIRTUAL");
}

static void test_decode_win_attributes_no_attributes(void **state) {
    char str[OS_SIZE_256];
    unsigned int attrs = 0;

    decode_win_attributes(str, attrs);

    assert_string_equal(str, "");
}

static void test_decode_win_attributes_some_attributes(void **state) {
    char str[OS_SIZE_256];
    unsigned int attrs = 0;

    attrs |= FILE_ATTRIBUTE_ARCHIVE     |
             FILE_ATTRIBUTE_DEVICE      |
             FILE_ATTRIBUTE_ENCRYPTED   |
             FILE_ATTRIBUTE_NORMAL      |
             FILE_ATTRIBUTE_READONLY    |
             FILE_ATTRIBUTE_SPARSE_FILE |
             FILE_ATTRIBUTE_TEMPORARY   |
             FILE_ATTRIBUTE_NO_SCRUB_DATA |
             FILE_ATTRIBUTE_RECALL_ON_OPEN;

    decode_win_attributes(str, attrs);

    assert_string_equal(str, "ARCHIVE, DEVICE, ENCRYPTED, NORMAL, NO_SCRUB_DATA, "
                             "READONLY, RECALL_ON_OPEN, SPARSE_FILE, TEMPORARY");
}

/* decode_win_acl_json */
void assert_ace_full_perms(const cJSON * const ace) {
    int i;
    const char *it;
    cJSON *element;
    static const char * const perm_strings[] = {
        "generic_read",
        "generic_write",
        "generic_execute",
        "generic_all",
        "delete",
        "read_control",
        "write_dac",
        "write_owner",
        "synchronize",
        "read_data",
        "write_data",
        "append_data",
        "read_ea",
        "write_ea",
        "execute",
        "read_attributes",
        "write_attributes",
        NULL
    };

    assert_non_null(ace);
    assert_true(cJSON_IsArray(ace));

    for (i = 0, it = perm_strings[0]; it; it = perm_strings[++i]) {
        int fail = 1;
        cJSON_ArrayForEach(element, ace) {
            if (strcmp(cJSON_GetStringValue(element), it) == 0) {
                fail = 0;
                break;
            }
        }

        if (fail) {
            fail_msg("%s not found", it);
        }
    }
}

#define set_full_perms(x)                                                                                   \
    x |= GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL | DELETE | READ_CONTROL | WRITE_DAC | \
         WRITE_OWNER | SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA |   \
         FILE_WRITE_EA | FILE_EXECUTE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES

static void test_decode_win_acl_json_null_json(void **state) {
    expect_assert_failure(decode_win_acl_json(NULL));
}

static void test_decode_win_acl_fail_creating_object(void **state) {
    int full_perms = 0, i = 0;
    const char * it;
    cJSON *acl = __real_cJSON_CreateObject();
    cJSON *ace = __real_cJSON_CreateObject();
    cJSON *element;

    if (acl == NULL || ace == NULL) {
        fail_msg("Failed to create cJSON object");
    }

    *state = acl;
    set_full_perms(full_perms);

    cJSON_AddItemToObject(acl, "S-1-5-32-636", ace);

    cJSON_AddItemToObject(ace, "allowed", cJSON_CreateNumber(full_perms));

    will_return(__wrap_cJSON_CreateArray, NULL);

    expect_string(__wrap__mwarn, formatted_msg, FIM_CJSON_ERROR_CREATE_ITEM);

    decode_win_acl_json(acl);

    ace = cJSON_GetObjectItem(acl, "S-1-5-32-636");
    assert_non_null(ace);

    cJSON *denied = cJSON_GetObjectItem(ace, "denied");
    assert_null(denied);

    cJSON *allowed = cJSON_GetObjectItem(ace, "allowed");
    assert_non_null(allowed);
    assert_int_equal(full_perms, allowed->valueint);
}

static void test_decode_win_acl_json_allowed_ace_only(void **state) {
    int full_perms = 0, i = 0;
    const char * it;
    cJSON *acl = __real_cJSON_CreateObject();
    cJSON *ace = __real_cJSON_CreateObject();
    cJSON *element;

    if (acl == NULL || ace == NULL) {
        fail_msg("Failed to create cJSON object");
    }

    *state = acl;
    set_full_perms(full_perms);

    cJSON_AddItemToObject(acl, "S-1-5-32-636", ace);

    cJSON_AddItemToObject(ace, "allowed", cJSON_CreateNumber(full_perms));

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    decode_win_acl_json(acl);

    ace = cJSON_GetObjectItem(acl, "S-1-5-32-636");
    assert_non_null(ace);

    cJSON *denied = cJSON_GetObjectItem(ace, "denied");
    assert_null(denied);

    cJSON *allowed = cJSON_GetObjectItem(ace, "allowed");
    assert_ace_full_perms(allowed);
}

static void test_decode_win_acl_json_denied_ace_only(void **state) {
    int full_perms = 0, i = 0;
    const char * it;
    cJSON *acl = __real_cJSON_CreateObject();
    cJSON *ace = __real_cJSON_CreateObject();
    cJSON *element;

    if (acl == NULL || ace == NULL) {
        fail_msg("Failed to create cJSON object");
    }

    *state = acl;
    set_full_perms(full_perms);

    cJSON_AddItemToObject(acl, "S-1-5-32-636", ace);

    cJSON_AddItemToObject(ace, "denied", cJSON_CreateNumber(full_perms));

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    decode_win_acl_json(acl);

    ace = cJSON_GetObjectItem(acl, "S-1-5-32-636");
    assert_non_null(ace);

    cJSON *allowed = cJSON_GetObjectItem(ace, "allowed");
    assert_null(allowed);

    cJSON *denied = cJSON_GetObjectItem(ace, "denied");
    assert_ace_full_perms(denied);
}

static void test_decode_win_acl_json_both_ace_types(void **state) {
    int full_perms = 0, i = 0;
    const char * it;
    cJSON *acl = __real_cJSON_CreateObject();
    cJSON *ace = __real_cJSON_CreateObject();
    cJSON *element;

    if (acl == NULL || ace == NULL) {
        fail_msg("Failed to create cJSON object");
    }

    *state = acl;
    set_full_perms(full_perms);

    cJSON_AddItemToObject(acl, "S-1-5-32-636", ace);

    cJSON_AddItemToObject(ace, "name", cJSON_CreateString("username"));
    cJSON_AddItemToObject(ace, "denied", cJSON_CreateNumber(full_perms));
    cJSON_AddItemToObject(ace, "allowed", cJSON_CreateNumber(full_perms));

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    decode_win_acl_json(acl);

    ace = cJSON_GetObjectItem(acl, "S-1-5-32-636");
    assert_non_null(ace);

    cJSON *allowed = cJSON_GetObjectItem(ace, "allowed");
    assert_ace_full_perms(allowed);

    cJSON *denied = cJSON_GetObjectItem(ace, "denied");
    assert_ace_full_perms(denied);

    // User name must be untouched, same as other unused fields
    cJSON *name = cJSON_GetObjectItem(ace, "name");
    assert_non_null(name);
    assert_string_equal("username", cJSON_GetStringValue(name));
}

static void test_decode_win_acl_json_empty_acl(void **state) {
    cJSON *acl = __real_cJSON_CreateObject();
    *state = acl;

    if (acl == NULL) {
        fail_msg("Failed to create cJSON object");
    }

    decode_win_acl_json(acl);

    assert_int_equal(0, cJSON_GetArraySize(acl));
}

static void test_decode_win_acl_json_empty_ace(void **state) {
    int full_perms = 0, i = 0;
    const char * it;
    cJSON *acl = __real_cJSON_CreateObject();
    cJSON *ace = __real_cJSON_CreateObject();
    cJSON *element;

    if (acl == NULL || ace == NULL) {
        fail_msg("Failed to create cJSON object");
    }

    *state = acl;
    set_full_perms(full_perms);

    cJSON_AddItemToObject(acl, "S-1-5-32-636", ace);

    decode_win_acl_json(acl);

    ace = cJSON_GetObjectItem(acl, "S-1-5-32-636");
    assert_non_null(ace);
    assert_int_equal(0, cJSON_GetArraySize(ace));
}

static void test_decode_win_acl_json_multiple_aces(void **state) {
    const char * const SIDS[] = {
        [0] = "S-1-5-32-636",
        [1] = "S-1-5-32-363",
        [2] = "S-1-5-32-444",
        [3] = NULL
    };
    const char * const USERNAMES[] = {
        [0] = "username",
        [1] = "someone",
        [2] = "anon",
        [3] = NULL
    };
    int full_perms = 0, i = 0;
    const char * it;
    cJSON *acl = __real_cJSON_CreateObject();
    cJSON *ace = NULL;
    cJSON *element;

    if (acl == NULL) {
        fail_msg("Failed to create ACL cJSON object");
    }

    *state = acl;
    set_full_perms(full_perms);

    for (i = 0, it = SIDS[0]; it; it = SIDS[++i]) {
        ace = __real_cJSON_CreateObject();
        if (ace == NULL) {
            fail_msg("Failed to create ACE cJSON object");
        }

        cJSON_AddItemToObject(acl, it, ace);

        cJSON_AddItemToObject(ace, "name", cJSON_CreateString(USERNAMES[i]));
        cJSON_AddItemToObject(ace, "denied", cJSON_CreateNumber(full_perms));
        cJSON_AddItemToObject(ace, "allowed", cJSON_CreateNumber(full_perms));

        will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
        will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    }

    decode_win_acl_json(acl);

    for (i = 0, it = SIDS[0]; it; it = SIDS[++i]) {
        ace = cJSON_GetObjectItem(acl, it);
        assert_non_null(ace);

        cJSON *allowed = cJSON_GetObjectItem(ace, "allowed");
        assert_ace_full_perms(allowed);

        cJSON *denied = cJSON_GetObjectItem(ace, "denied");
        assert_ace_full_perms(denied);

        // User name must be untouched, same as other unused fields
        cJSON *name = cJSON_GetObjectItem(ace, "name");
        assert_non_null(name);
        assert_string_equal(USERNAMES[i], cJSON_GetStringValue(name));
    }
}

#ifdef TEST_WINAGENT

static void test_get_file_user_CreateFile_error_access_denied(void **state) {
    char **array = *state;

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)INVALID_HANDLE_VALUE);

    expect_GetLastError_call(ERROR_ACCESS_DENIED);

    expect_FormatMessage_call("An error message");

    expect_string(__wrap__mdebug1, formatted_msg, "At get_user(C:\\a\\path): wCreateFile(): An error message (5)");

    expect_CloseHandle_call(INVALID_HANDLE_VALUE, 1);

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
}

static void test_get_file_user_CreateFile_error_sharing_violation(void **state) {
    char **array = *state;

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)INVALID_HANDLE_VALUE);

    expect_GetLastError_call(ERROR_SHARING_VIOLATION);

    expect_FormatMessage_call("An error message");

    expect_string(__wrap__mdebug1, formatted_msg, "At get_user(C:\\a\\path): wCreateFile(): An error message (32)");

    expect_CloseHandle_call(INVALID_HANDLE_VALUE, 1);

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
}

static void test_get_file_user_CreateFile_error_generic(void **state) {
    char **array = *state;

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)INVALID_HANDLE_VALUE);

    expect_GetLastError_call(127);

    expect_FormatMessage_call("An error message");

    expect_string(__wrap__mwarn, formatted_msg, "At get_user(C:\\a\\path): wCreateFile(): An error message (127)");

    expect_CloseHandle_call(INVALID_HANDLE_VALUE, 1);

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
}

static void test_get_file_user_GetSecurityInfo_error(void **state) {
    char **array = *state;
    char error_msg[OS_SIZE_1024];

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)1234);

    expect_CloseHandle_call((HANDLE)1234, 1);

    expect_GetSecurityInfo_call(NULL, (PSID)"", ERROR_ACCESS_DENIED);

    expect_ConvertSidToStringSid_call("", FALSE);

    will_return(__wrap_win_strerror,"Access denied.");

    expect_string(__wrap__mdebug1, formatted_msg, "The user's SID could not be extracted.");

    snprintf(error_msg,
             OS_SIZE_1024,
             "GetSecurityInfo error code = (%lu), 'Access denied.'",
             ERROR_ACCESS_DENIED);

    expect_string(__wrap__mdebug1, formatted_msg, error_msg);

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
}

static void test_get_file_user_LookupAccountSid_error(void **state) {
    char **array = *state;

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)1234);

    expect_CloseHandle_call((HANDLE)1234, 1);

    expect_GetSecurityInfo_call(NULL, (PSID)"", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("sid", TRUE);

    expect_utf8_LookupAccountSid_call("", "domainname", FALSE);
    expect_GetLastError_call(ERROR_ACCESS_DENIED);
    expect_FormatMessage_call("Access is denied.");
    expect_string(__wrap__mwarn, formatted_msg, "(6950): Error in LookupAccountSidW getting user. (5): Access is denied.");

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
    assert_string_equal(array[1], "sid");
}

static void test_get_file_user_LookupAccountSid_error_none_mapped(void **state) {
    char **array = *state;
    char error_msg[OS_SIZE_1024];

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)1234);

    expect_CloseHandle_call((HANDLE)1234, 1);

    expect_GetSecurityInfo_call(NULL, (PSID)"", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("sid", TRUE);

    expect_utf8_LookupAccountSid_call("", "domainname", FALSE);
    expect_GetLastError_call(ERROR_NONE_MAPPED);

    snprintf(error_msg,
             OS_SIZE_1024,
             "Account owner not found for '%s'",
             "C:\\a\\path");

    expect_string(__wrap__mdebug1, formatted_msg, error_msg);

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "");
    assert_string_equal(array[1], "sid");
}

static void test_get_file_user_success(void **state) {
    char **array = *state;

    expect_string(__wrap_utf8_CreateFile, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_CreateFile, (HANDLE)1234);

    expect_CloseHandle_call((HANDLE)1234, 1);

    expect_GetSecurityInfo_call(NULL, (PSID)"", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("sid", TRUE);

    expect_utf8_LookupAccountSid_call("accountName", "domainname", TRUE);

    array[0] = get_file_user("C:\\a\\path", &array[1]);

    assert_string_equal(array[0], "accountName");
    assert_string_equal(array[1], "sid");
}

void test_w_get_account_info_LookupAccountSid_error_insufficient_buffer(void **state) {
    char **array = *state;
    int ret;
    SID input;

    expect_utf8_LookupAccountSid_call("", "", FALSE);
    will_return(wrap_GetLastError, ERROR_INVALID_NAME);

    ret = w_get_account_info(&input, &array[0], &array[1]);

    assert_int_equal(ret, ERROR_INVALID_NAME);
}

void test_w_get_account_info_LookupAccountSid_error_second_call(void **state) {
    char **array = *state;
    int ret;
    SID input;

    expect_utf8_LookupAccountSid_call("", "", FALSE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);

    ret = w_get_account_info(&input, &array[0], &array[1]);

    assert_int_equal(ret, ERROR_INSUFFICIENT_BUFFER);
}

void test_w_get_account_info_success(void **state) {
    char **array = *state;
    int ret;
    SID input;

    expect_utf8_LookupAccountSid_call("accountName", "domainName", 1);

    ret = w_get_account_info(&input, &array[0], &array[1]);

    assert_int_equal(ret, 0);
    assert_string_equal(array[0], "accountName");
    assert_string_equal(array[1], "domainName");
}

void test_w_get_file_permissions_GetFileSecurity_error_on_size(void **state) {
    cJSON *permissions = NULL;
    int ret;

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, 0);
    will_return(__wrap_utf8_GetFileSecurity, 0);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, ERROR_ACCESS_DENIED);
    assert_null(permissions);
}

void test_w_get_file_permissions_GetFileSecurity_error(void **state) {
    cJSON *permissions = NULL;
    int ret;

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, NULL);
    will_return(__wrap_utf8_GetFileSecurity, 0);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, ERROR_ACCESS_DENIED);
    assert_null(permissions);
}

void test_w_get_file_permissions_create_cjson_error(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mwarn, formatted_msg, FIM_CJSON_ERROR_CREATE_ITEM);

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, -1);
    assert_null(permissions);
}

void test_w_get_file_permissions_GetSecurityDescriptorDacl_error(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(wrap_GetSecurityDescriptorDacl, FALSE);
    will_return(wrap_GetSecurityDescriptorDacl, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "GetSecurityDescriptorDacl failed. GetLastError returned: 5");

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, ERROR_ACCESS_DENIED);
    assert_null(permissions);
}

void test_w_get_file_permissions_no_dacl(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(wrap_GetSecurityDescriptorDacl, FALSE);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "No DACL was found (all access is denied), or a NULL DACL (unrestricted access) was found.");

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, -2);
    assert_null(permissions);
}

void test_w_get_file_permissions_GetAclInformation_error(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(wrap_GetSecurityDescriptorDacl, TRUE);
    will_return(wrap_GetSecurityDescriptorDacl, (PACL)123456);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    will_return(wrap_GetAclInformation, NULL);
    will_return(wrap_GetAclInformation, 0);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mdebug2, formatted_msg, "GetAclInformation failed. GetLastError returned: 5");

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, ERROR_ACCESS_DENIED);
    assert_null(permissions);
}

void test_w_get_file_permissions_GetAce_error(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;
    ACL_SIZE_INFORMATION acl_size = { .AceCount = 1 };

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(wrap_GetSecurityDescriptorDacl, TRUE);
    will_return(wrap_GetSecurityDescriptorDacl, (PACL)123456);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    will_return(wrap_GetAclInformation, &acl_size);
    will_return(wrap_GetAclInformation, 1);

    will_return(wrap_GetAce, NULL);
    will_return(wrap_GetAce, 0);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);
    expect_string(__wrap__mdebug2, formatted_msg, "GetAce failed. GetLastError returned: 5");

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, 0);
    assert_non_null(permissions);
    cJSON_Delete(permissions);
}

void test_w_get_file_permissions_success(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;
    ACL_SIZE_INFORMATION acl_size = {
        .AceCount = 1,
    };
    ACCESS_ALLOWED_ACE ace = {
        .Header.AceType = ACCESS_ALLOWED_ACE_TYPE,
    };

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(wrap_GetSecurityDescriptorDacl, TRUE);
    will_return(wrap_GetSecurityDescriptorDacl, (PACL)123456);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    will_return(wrap_GetAclInformation, &acl_size);
    will_return(wrap_GetAclInformation, 1);

    will_return(wrap_GetAce, &ace);
    will_return(wrap_GetAce, 1);

    // Inside process_ace_info
    {
        will_return(wrap_IsValidSid, 1);

        // Inside w_get_account_info
        expect_utf8_LookupAccountSid_call("accountName", "domainName", 1);

        expect_ConvertSidToStringSid_call(BASE_WIN_SID, TRUE);
    }

    // Inside add_ace_to_json
    {
        will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());
    }

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, 0);
    assert_non_null(permissions);

    cJSON *ace_json = cJSON_GetObjectItem(permissions, BASE_WIN_SID);
    assert_non_null(ace_json);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ace_json, "name")), "accountName");
    assert_int_equal(cJSON_GetObjectItem(ace_json, "allowed")->valueint, 0);
    assert_null(cJSON_GetObjectItem(ace_json, "denied"));

    cJSON_Delete(permissions);
}

void test_w_get_file_permissions_process_ace_info_error(void **state) {
    cJSON *permissions = NULL;
    int ret;
    SECURITY_DESCRIPTOR sec_desc;
    ACL_SIZE_INFORMATION acl_size = {
        .AceCount = 1,
    };
    ACCESS_ALLOWED_ACE ace = {
        .Header.AceType = SYSTEM_AUDIT_ACE_TYPE,
    };

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, OS_SIZE_1024);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    expect_string(__wrap_utf8_GetFileSecurity, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileSecurity, &sec_desc);
    will_return(__wrap_utf8_GetFileSecurity, 1);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    will_return(wrap_GetSecurityDescriptorDacl, TRUE);
    will_return(wrap_GetSecurityDescriptorDacl, (PACL)123456);
    will_return(wrap_GetSecurityDescriptorDacl, 1);

    will_return(wrap_GetAclInformation, &acl_size);
    will_return(wrap_GetAclInformation, 1);

    will_return(wrap_GetAce, &ace);
    will_return(wrap_GetAce, 1);

    // Inside process_ace_info
    expect_string(__wrap__mdebug2, formatted_msg, "Invalid ACE type.");

    expect_string(__wrap__mdebug1, formatted_msg,
        "ACE number 0 could not be processed.");

    ret = w_get_file_permissions("C:\\a\\path", &permissions);

    assert_int_equal(ret, 0);
    assert_non_null(permissions);
}

void test_w_get_file_attrs_error(void **state) {
    int ret;

    expect_string(__wrap_utf8_GetFileAttributes, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileAttributes, INVALID_FILE_ATTRIBUTES);

    will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mdebug2, formatted_msg, "The attributes for 'C:\\a\\path' could not be obtained. Error '5'.");

    ret = w_get_file_attrs("C:\\a\\path");

    assert_int_equal(ret, 0);
}

void test_w_get_file_attrs_success(void **state) {
    int ret;

    expect_string(__wrap_utf8_GetFileAttributes, utf8_path, "C:\\a\\path");
    will_return(__wrap_utf8_GetFileAttributes, 123456);

    ret = w_get_file_attrs("C:\\a\\path");

    assert_int_equal(ret, 123456);
}

void test_w_directory_exists_null_path(void **state) {
    unsigned int ret;

    ret = w_directory_exists(NULL);

    assert_null(ret);
}

void test_w_directory_exists_error_getting_attrs(void **state) {
    unsigned int ret;

    // Inside w_get_file_attrs
    {
        expect_string(__wrap_utf8_GetFileAttributes, utf8_path, "C:\\a\\path");
        will_return(__wrap_utf8_GetFileAttributes, INVALID_FILE_ATTRIBUTES);

        will_return(wrap_GetLastError, ERROR_ACCESS_DENIED);

        expect_string(__wrap__mdebug2, formatted_msg,
            "The attributes for 'C:\\a\\path' could not be obtained. Error '5'.");
    }

    ret = w_directory_exists("C:\\a\\path");

    assert_null(ret);
}

void test_w_directory_exists_path_is_not_dir(void **state) {
    unsigned int ret;

    // Inside w_get_file_attrs
    {
        expect_string(__wrap_utf8_GetFileAttributes, utf8_path, "C:\\a\\path");
        will_return(__wrap_utf8_GetFileAttributes, FILE_ATTRIBUTE_NORMAL);
    }

    ret = w_directory_exists("C:\\a\\path");

    assert_null(ret);
}

void test_w_directory_exists_path_is_dir(void **state) {
    unsigned int ret;

    // Inside w_get_file_attrs
    {
        expect_string(__wrap_utf8_GetFileAttributes, utf8_path, "C:\\a\\path");
        will_return(__wrap_utf8_GetFileAttributes, FILE_ATTRIBUTE_DIRECTORY);
    }

    ret = w_directory_exists("C:\\a\\path");

    assert_non_null(ret);
}

void test_get_registry_group_GetSecurityInfo_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    registry_group_information_t *group_information = *state;
    char *group = group_information->name;
    char *group_id = group_information->id;
    char error_msg[OS_SIZE_1024];

    expect_GetSecurityInfo_call(NULL, (PSID)"", ERROR_ACCESS_DENIED);
    expect_ConvertSidToStringSid_call("", TRUE);
    will_return(__wrap_win_strerror, "Access denied.");

    snprintf(error_msg,
             OS_SIZE_1024,
             "GetSecurityInfo error code = (%lu), 'Access denied.'",
             ERROR_ACCESS_DENIED);

    expect_string(__wrap__mdebug1, formatted_msg, error_msg);

    group = get_registry_group(&group_id, hndl);

    assert_string_equal(group, "");
    assert_string_equal(group_id, "");
}

void test_get_registry_group_ConvertSidToStringSid_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    registry_group_information_t *group_information = *state;
    char *group = group_information->name;
    char *group_id = group_information->id;

    expect_GetSecurityInfo_call(NULL, (PSID)"groupid", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("dummy", FALSE);

    expect_string(__wrap__mdebug1, formatted_msg, "The user's SID could not be extracted.");

    expect_utf8_LookupAccountSid_call("groupname", "domainname", TRUE);

    group = get_registry_group(&group_id, hndl);

    assert_string_equal(group, "groupname");
    assert_string_equal(group_id, "");
}

void test_get_registry_group_LookupAccountSid_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    registry_group_information_t *group_information = *state;
    char *group = group_information->name;
    char *group_id = group_information->id;

    expect_GetSecurityInfo_call(NULL, (PSID)"groupid", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("groupid", TRUE);

    expect_utf8_LookupAccountSid_call("", "domainname", FALSE);
    expect_GetLastError_call(ERROR_ACCESS_DENIED);
    expect_FormatMessage_call("Access is denied.");
    expect_string(__wrap__mwarn, formatted_msg, "(6950): Error in LookupAccountSidW getting group. (5): Access is denied.");

    group = get_registry_group(&group_id, hndl);

    assert_string_equal(group, "");
    assert_string_equal(group_id, "groupid");
}

void test_get_registry_group_LookupAccountSid_not_found(void **state) {
    HKEY hndl = (HKEY)123456;
    registry_group_information_t *group_information = *state;
    char *group = group_information->name;
    char *group_id = group_information->id;

    expect_GetSecurityInfo_call(NULL, (PSID)"groupid", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("groupid", TRUE);

    expect_utf8_LookupAccountSid_call("", "domainname", FALSE);
    expect_GetLastError_call(ERROR_NONE_MAPPED);

    expect_string(__wrap__mdebug1, formatted_msg, "Group not found for registry key");

    group = get_registry_group(&group_id, hndl);

    assert_string_equal(group, "");
    assert_string_equal(group_id, "groupid");
}

void test_get_registry_group_success(void **state) {
    HKEY hndl = (HKEY)123456;
    registry_group_information_t *group_information = *state;
    char *group = group_information->name;
    char *group_id = group_information->id;

    expect_GetSecurityInfo_call(NULL, (PSID)"groupid", ERROR_SUCCESS);

    expect_ConvertSidToStringSid_call("groupid", TRUE);

    expect_utf8_LookupAccountSid_call("groupname", "domainname", TRUE);

    group = get_registry_group(&group_id, hndl);

    assert_string_equal(group, "groupname");
    assert_string_equal(group_id, "groupid");
}

void test_get_registry_permissions_RegGetKeySecurity_insufficient_buffer(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_ACCESS_DENIED);

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_equal(retval, ERROR_ACCESS_DENIED);
    assert_null(permissions);
}

void test_get_registry_permissions_RegGetKeySecurity_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_ACCESS_DENIED);

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_equal(retval, ERROR_ACCESS_DENIED);
    assert_null(permissions);
}

void test_get_registry_permissions_GetSecurityDescriptorDacl_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_SUCCESS);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    expect_GetSecurityDescriptorDacl_call(TRUE, (PACL*)0, FALSE);

    expect_GetLastError_call(ERROR_SUCCESS);
    expect_string(__wrap__mdebug2, formatted_msg, "GetSecurityDescriptorDacl failed. GetLastError returned: 0");

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_equal(retval, ERROR_SUCCESS);
    assert_null(permissions);
}

void test_get_registry_permissions_GetSecurityDescriptorDacl_no_DACL(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;
    char error_msg[OS_SIZE_1024];

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_SUCCESS);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    expect_GetSecurityDescriptorDacl_call(TRUE, (PACL*)0, TRUE);

    snprintf(error_msg,
             OS_SIZE_1024,
             "%s",
             "No DACL was found (all access is denied), or a NULL DACL (unrestricted access) was found.");

    expect_string(__wrap__mdebug2, formatted_msg, error_msg);

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_not_equal(retval, ERROR_SUCCESS);
    assert_null(permissions);
}

void test_get_registry_permissions_GetAclInformation_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_SUCCESS);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    expect_GetSecurityDescriptorDacl_call(TRUE, (PACL*)4321, TRUE);

    expect_GetAclInformation_call(NULL, FALSE);

    expect_GetLastError_call(ERROR_SUCCESS);
    expect_string(__wrap__mdebug2, formatted_msg, "GetAclInformation failed. GetLastError returned: 0");

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_equal(retval, ERROR_SUCCESS);
    assert_null(permissions);
}

void test_get_registry_permissions_GetAce_fails(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;
    ACL_SIZE_INFORMATION acl_size = { .AceCount = 1 };

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_SUCCESS);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    expect_GetSecurityDescriptorDacl_call(TRUE, (PACL*)4321, TRUE);

    expect_GetAclInformation_call(&acl_size, TRUE);

    expect_GetAce_call(NULL, FALSE);

    expect_GetLastError_call(ERROR_SUCCESS);
    expect_string(__wrap__mdebug2, formatted_msg, "GetAce failed. GetLastError returned: 0");

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_equal(retval, ERROR_SUCCESS);
    assert_non_null(permissions);
}

void test_get_registry_permissions_success(void **state) {
    HKEY hndl = (HKEY)123456;
    unsigned int retval = 0;
    cJSON *permissions = NULL;
    ACL_SIZE_INFORMATION acl_size = { .AceCount = 1 };
    ACCESS_ALLOWED_ACE ace = {
        .Header.AceType = ACCESS_ALLOWED_ACE_TYPE,
    };

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_SUCCESS);

    will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());

    expect_GetSecurityDescriptorDacl_call(TRUE, (PACL*)4321, TRUE);

    expect_GetAclInformation_call(&acl_size, TRUE);

    expect_GetAce_call((LPVOID*)&ace, TRUE);

    // Inside process_ace_info
    {
        will_return(wrap_IsValidSid, 1);

        // Inside w_get_account_info
        expect_utf8_LookupAccountSid_call("accountName", "domainName", 1);

        expect_ConvertSidToStringSid_call(BASE_WIN_SID, TRUE);

        will_return(__wrap_cJSON_CreateObject, __real_cJSON_CreateObject());
    }

    retval = get_registry_permissions(hndl, &permissions);

    assert_int_equal(retval, ERROR_SUCCESS);
    assert_non_null(permissions);

    cJSON *ace_json = cJSON_GetObjectItem(permissions, BASE_WIN_SID);
    assert_non_null(ace_json);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ace_json, "name")), "accountName");
    assert_int_equal(cJSON_GetObjectItem(ace_json, "allowed")->valueint, 0);
    assert_null(cJSON_GetObjectItem(ace_json, "denied"));

    cJSON_Delete(permissions);
}

void test_get_registry_mtime_RegQueryInfoKeyA_fails(void **state) {
    FILETIME last_write_time;
    unsigned int retval = 0;
    HKEY hndl = (HKEY)123456;

    expect_RegQueryInfoKeyA_call(&last_write_time, ERROR_MORE_DATA);

    expect_string(__wrap__mwarn, formatted_msg, "Couldn't get modification time for registry key.");

    retval = get_registry_mtime(hndl);

    assert_int_equal(retval, 0);
}

void test_get_registry_mtime_success(void **state) {
    FILETIME last_write_time;
    unsigned int retval = 0;
    HKEY hndl = (HKEY)123456;

    expect_RegQueryInfoKeyA_call(&last_write_time, ERROR_SUCCESS);

    retval = get_registry_mtime(hndl);

    assert_int_not_equal(retval, 0);
}

void test_get_subkey(void **state)
{
    char* test_vector_path[4] = {
        "HKEY_SOMETHING\\*\\A",
        "HKEY_SOMETHING\\A\\B\\*",
        "HKEY_SOMETHING\\A?",
        "HKEY_SOMETHING\\A\\B\\C?"
    };

    char* expected_subkey[4] = {
        "",
        "A\\B",
        "",
        "A\\B"
    };

    for (int scenario = 0; scenario < 4; scenario++) {
        char* result_function = get_subkey(test_vector_path[scenario]);
        assert_string_equal(result_function, expected_subkey[scenario]);
    }
}

void test_w_is_still_a_wildcard(void **state) {
    int ret;
    reg_path_struct** test_reg;
    int has_wildcard_vec[4] = {0, 1, 1, 0};
    int checked_vec[4] = {0, 1, 0, 1};
    int expected_result[4] = {0, 0, 1, 0};

    test_reg    = (reg_path_struct**)calloc(2, sizeof(reg_path_struct*));
    test_reg[0] = (reg_path_struct*)calloc(1, sizeof(reg_path_struct));
    test_reg[1] = NULL;

    for(int scenario = 0; scenario < 4; scenario++) {
        test_reg[0]->has_wildcard = has_wildcard_vec[scenario];
        test_reg[0]->checked = checked_vec[scenario];
        ret = w_is_still_a_wildcard(test_reg);
        assert_int_equal(expected_result[scenario], ret);
    }

    os_free(test_reg[0]);
    os_free(test_reg);
}

void test_w_list_all_keys_subkey_notnull(void** state) {
    HKEY root_key = HKEY_LOCAL_MACHINE;
    HKEY keyhandle;
    FILETIME last_write_time = { 0, 1000 };

    char* subkey = "HARDWARE";
    char* result[4] = {
        "ACPI",
        "DESCRIPTION",
        "DEVICEMAP",
        "RESOURCEMAP"
    };

    expect_RegOpenKeyEx_call(root_key, subkey, 0, KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(4, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("ACPI", 5, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("DESCRIPTION", 12, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("DEVICEMAP", 10, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("RESOURCEMAP", 12, ERROR_SUCCESS);

    char** query_result = w_list_all_keys(root_key, subkey);

    for (int idx = 0; idx < 4; idx++) {
        assert_string_equal(query_result[idx], result[idx]);
        os_free(query_result[idx]);
    }
}

void test_w_list_all_keys_subkey_null(void** state) {
    HKEY root_key = HKEY_LOCAL_MACHINE;
    HKEY keyhandle;
    FILETIME last_write_time = { 0, 1000 };

    char* subkey = "";
    char* result[6] = {
        "BCD00000000",
        "HARDWARE",
        "SAM",
        "SECURITY",
        "SOFTWARE",
        "SYSTEM",
    };

    expect_RegOpenKeyEx_call(root_key, subkey, 0, KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(6, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("BCD00000000", 12, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("HARDWARE", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SAM", 4, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SECURITY", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SOFTWARE", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SYSTEM", 7, ERROR_SUCCESS);

    char** query_result = w_list_all_keys(root_key, subkey);

    for (int idx = 0; idx < 6; idx++) {
        assert_string_equal(query_result[idx], result[idx]);
        os_free(query_result[idx]);
    }
}

void test_w_switch_root_key(void** state) {
    char* root_key_valid_lm = "HKEY_LOCAL_MACHINE";
    char* root_key_valid_cr = "HKEY_CLASSES_ROOT";
    char* root_key_valid_cc = "HKEY_CURRENT_CONFIG";
    char* root_key_valid_us = "HKEY_USERS";
    char* root_key_valid_cu = "HKEY_CURRENT_USER";

    char* root_key_invalid  = "HKEY_SOMETHING";

    expect_any_always(__wrap__mdebug1, formatted_msg);

    HKEY ret;

    ret = w_switch_root_key(root_key_valid_lm);
    assert_int_equal(ret, HKEY_LOCAL_MACHINE);

    ret = w_switch_root_key(root_key_valid_cr);
    assert_int_equal(ret, HKEY_CLASSES_ROOT);

    ret = w_switch_root_key(root_key_valid_cc);
    assert_int_equal(ret, HKEY_CURRENT_CONFIG);

    ret = w_switch_root_key(root_key_valid_us);
    assert_int_equal(ret, HKEY_USERS);

    ret = w_switch_root_key(root_key_valid_cu);
    assert_int_equal(ret, HKEY_CURRENT_USER);

    ret = w_switch_root_key(root_key_invalid);
    assert_null(ret);
}

void test_expand_wildcard_registers_star_only(void **state){
    char* entry     = "HKEY_LOCAL_MACHINE\\*";
    char** paths    = NULL;
    os_calloc(OS_SIZE_1024, sizeof(char*), paths);
    char* subkey    = "";
    HKEY root_key   = HKEY_LOCAL_MACHINE;

    char* result[6] = {
        "HKEY_LOCAL_MACHINE\\BCD00000000",
        "HKEY_LOCAL_MACHINE\\HARDWARE",
        "HKEY_LOCAL_MACHINE\\SAM",
        "HKEY_LOCAL_MACHINE\\SECURITY",
        "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "HKEY_LOCAL_MACHINE\\SYSTEM",
    };

    HKEY keyhandle;
    FILETIME last_write_time = { 0, 1000 };

    expect_RegOpenKeyEx_call(root_key, subkey, 0, KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(6, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("BCD00000000", 12, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("HARDWARE", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SAM", 4, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SECURITY", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SOFTWARE", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SYSTEM", 7, ERROR_SUCCESS);

    expand_wildcard_registers(entry, paths);

    int i = 0;
    while(*paths != NULL){
        assert_string_equal(*paths, result[i]);
        os_free(*paths);
        paths++;
        i++;
    }
}

void test_expand_wildcard_registers_invalid_path(void **state){
    char* entry     = "HKEY_LOCAL_MACHINE\\????";
    char** paths    = NULL;
    os_calloc(OS_SIZE_1024, sizeof(char*), paths);
    char* subkey    = "";
    HKEY root_key   = HKEY_LOCAL_MACHINE;

    FILETIME last_write_time = { 0, 1000 };

    expect_RegOpenKeyEx_call(root_key, subkey, 0, KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(6, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("BCD00000000", 12, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("HARDWARE", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SAM", 4, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SECURITY", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SOFTWARE", 9, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("SYSTEM", 7, ERROR_SUCCESS);

    expand_wildcard_registers(entry, paths);

    assert_null(*paths);
    os_free(paths);

}

#endif


int main(int argc, char *argv[]) {
    const struct CMUnitTest tests[] = {
        /* remove_empty_folders tests */
        cmocka_unit_test(test_remove_empty_folders_success),
        cmocka_unit_test(test_remove_empty_folders_recursive_success),
        cmocka_unit_test(test_remove_empty_folders_null_input),
        cmocka_unit_test(test_remove_empty_folders_relative_path),
        cmocka_unit_test(test_remove_empty_folders_absolute_path),
        cmocka_unit_test(test_remove_empty_folders_non_empty_dir),
        cmocka_unit_test(test_remove_empty_folders_error_removing_dir),

#ifndef TEST_WINAGENT
        /* get_user tests */
        cmocka_unit_test_teardown(test_get_user_success, teardown_string),
        cmocka_unit_test_teardown(test_get_user_uid_not_found, teardown_string),
        cmocka_unit_test_teardown(test_get_user_error, teardown_string),

        /* get_group tests */
        cmocka_unit_test(test_get_group_success),
        cmocka_unit_test(test_get_group_no_group),
        cmocka_unit_test_teardown(test_get_group_error, teardown_string),

        /* ag_send_syscheck tests */
        cmocka_unit_test(test_ag_send_syscheck_success),
        cmocka_unit_test(test_ag_send_syscheck_unable_to_connect),
        cmocka_unit_test(test_ag_send_syscheck_error_sending_message),
#else
        cmocka_unit_test(test_get_group),
        cmocka_unit_test(test_ag_send_syscheck),
#endif

        /* decode_win_attributes tests */
        cmocka_unit_test(test_decode_win_attributes_all_attributes),
        cmocka_unit_test(test_decode_win_attributes_no_attributes),
        cmocka_unit_test(test_decode_win_attributes_some_attributes),

        /* decode_win_acl_json */
        cmocka_unit_test(test_decode_win_acl_json_null_json),
        cmocka_unit_test_teardown(test_decode_win_acl_fail_creating_object, teardown_cjson),
        cmocka_unit_test_teardown(test_decode_win_acl_json_allowed_ace_only, teardown_cjson),
        cmocka_unit_test_teardown(test_decode_win_acl_json_denied_ace_only, teardown_cjson),
        cmocka_unit_test_teardown(test_decode_win_acl_json_both_ace_types, teardown_cjson),
        cmocka_unit_test_teardown(test_decode_win_acl_json_empty_acl, teardown_cjson),
        cmocka_unit_test_teardown(test_decode_win_acl_json_empty_ace, teardown_cjson),
        cmocka_unit_test_teardown(test_decode_win_acl_json_multiple_aces, teardown_cjson),

#ifdef TEST_WINAGENT
        /* get_file_user tests */
        cmocka_unit_test_setup_teardown(test_get_file_user_CreateFile_error_access_denied, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_file_user_CreateFile_error_sharing_violation, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_file_user_CreateFile_error_generic, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_file_user_GetSecurityInfo_error, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_file_user_LookupAccountSid_error, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_file_user_LookupAccountSid_error_none_mapped, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_get_file_user_success, setup_string_array, teardown_string_array),

        /* w_get_account_info tests */
        cmocka_unit_test_setup_teardown(test_w_get_account_info_LookupAccountSid_error_insufficient_buffer, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_w_get_account_info_LookupAccountSid_error_second_call, setup_string_array, teardown_string_array),
        cmocka_unit_test_setup_teardown(test_w_get_account_info_success, setup_string_array, teardown_string_array),

        /* w_get_file_permissions tests */
        cmocka_unit_test(test_w_get_file_permissions_GetFileSecurity_error_on_size),
        cmocka_unit_test(test_w_get_file_permissions_GetFileSecurity_error),
        cmocka_unit_test(test_w_get_file_permissions_create_cjson_error),
        cmocka_unit_test(test_w_get_file_permissions_GetSecurityDescriptorDacl_error),
        cmocka_unit_test(test_w_get_file_permissions_no_dacl),
        cmocka_unit_test(test_w_get_file_permissions_GetAclInformation_error),
        cmocka_unit_test(test_w_get_file_permissions_GetAce_error),
        cmocka_unit_test(test_w_get_file_permissions_success),
        cmocka_unit_test(test_w_get_file_permissions_process_ace_info_error),

        /* w_get_file_attrs tests */
        cmocka_unit_test(test_w_get_file_attrs_error),
        cmocka_unit_test(test_w_get_file_attrs_success),

        /* w_directory_exists tests */
        cmocka_unit_test(test_w_directory_exists_null_path),
        cmocka_unit_test(test_w_directory_exists_error_getting_attrs),
        cmocka_unit_test(test_w_directory_exists_path_is_not_dir),
        cmocka_unit_test(test_w_directory_exists_path_is_dir),

        /* get_registry_group tests */
        cmocka_unit_test_setup_teardown(test_get_registry_group_GetSecurityInfo_fails, setup_get_registry_group, teardown_get_registry_group),
        cmocka_unit_test_setup_teardown(test_get_registry_group_ConvertSidToStringSid_fails, setup_get_registry_group, teardown_get_registry_group),
        cmocka_unit_test_setup_teardown(test_get_registry_group_LookupAccountSid_fails, setup_get_registry_group, teardown_get_registry_group),
        cmocka_unit_test_setup_teardown(test_get_registry_group_LookupAccountSid_not_found, setup_get_registry_group, teardown_get_registry_group),
        cmocka_unit_test_setup_teardown(test_get_registry_group_success, setup_get_registry_group, teardown_get_registry_group),

        /* get_registry_permissions tests */
        cmocka_unit_test(test_get_registry_permissions_RegGetKeySecurity_insufficient_buffer),
        cmocka_unit_test(test_get_registry_permissions_RegGetKeySecurity_fails),
        cmocka_unit_test(test_get_registry_permissions_GetSecurityDescriptorDacl_fails),
        cmocka_unit_test(test_get_registry_permissions_GetSecurityDescriptorDacl_no_DACL),
        cmocka_unit_test(test_get_registry_permissions_GetAclInformation_fails),
        cmocka_unit_test(test_get_registry_permissions_GetAce_fails),
        cmocka_unit_test(test_get_registry_permissions_success),

        /* get_registry_mtime tests */
        cmocka_unit_test(test_get_registry_mtime_RegQueryInfoKeyA_fails),
        cmocka_unit_test(test_get_registry_mtime_success),

        /* expand_wildcard_register */
        cmocka_unit_test(test_get_subkey),
        cmocka_unit_test(test_w_is_still_a_wildcard),
        cmocka_unit_test(test_w_list_all_keys_subkey_notnull),
        cmocka_unit_test(test_w_list_all_keys_subkey_null),
        cmocka_unit_test(test_w_switch_root_key),
        cmocka_unit_test(test_expand_wildcard_registers_star_only),
        cmocka_unit_test(test_expand_wildcard_registers_invalid_path),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
