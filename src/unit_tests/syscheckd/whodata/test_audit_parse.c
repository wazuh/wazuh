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

#include "../../wrappers/common.h"
#include "../../../syscheckd/include/syscheck.h"
#include "../../../syscheckd/src/whodata/syscheck_audit.h"

#include "wrappers/externals/audit/libaudit_wrappers.h"
#include "wrappers/externals/procpc/readproc_wrappers.h"
#include "wrappers/libc/stdio_wrappers.h"
#include "wrappers/libc/stdlib_wrappers.h"
#include "wrappers/posix/unistd_wrappers.h"
#include "wrappers/wazuh/shared/audit_op_wrappers.h"
#include "wrappers/wazuh/shared/debug_op_wrappers.h"
#include "wrappers/wazuh/shared/file_op_wrappers.h"
#include "wrappers/wazuh/syscheckd/audit_rule_handling_wrappers.h"


#define PERMS (AUDIT_PERM_WRITE | AUDIT_PERM_ATTR)

extern unsigned int count_reload_retries;
audit_key_type filterkey_audit_events(char *buffer);

/* setup/teardown */
static int setup_group(void **state) {
    (void) state;
    test_mode = 1;
    init_regex();

    return 0;
}

static int teardown_group(void **state) {
    (void) state;
    memset(&syscheck, 0, sizeof(syscheck_config));
    Free_Syscheck(&syscheck);
    clean_regex();
    test_mode = 0;
    return 0;
}

static int setup_config(void **state) {
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    directory_t *directory0 = fim_create_directory("/var/test", WHODATA_ACTIVE, NULL, 512, NULL, 1024, 0);

    syscheck.directories = OSList_Create();
    if (syscheck.directories == NULL) {
        return -1;
    }

    OSList_InsertData(syscheck.directories, NULL, directory0);

    return 0;
}

static int teardown_config(void **state) {
    OSListNode *node_it;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    if (syscheck.directories) {
        OSList_foreach(node_it, syscheck.directories) {
            free_directory(node_it->data);
            node_it->data = NULL;
        }
        OSList_Destroy(syscheck.directories);
        syscheck.directories = NULL;
    }

    return 0;
}

static int free_string(void **state) {
    char * string = *state;
    free(string);
    return 0;
}

static int setup_custom_key(void **state) {
    syscheck.audit_key = calloc(2, sizeof(char *));
    if (syscheck.audit_key == NULL) {
        return 1;
    }

    syscheck.audit_key[0] = calloc(OS_SIZE_64, sizeof(char));
    if (syscheck.audit_key[0] == NULL) {
        return 1;
    }
    return 0;
}

static int teardown_custom_key(void **state) {
    free(syscheck.audit_key[0]);
    free(syscheck.audit_key);
    syscheck.audit_key = NULL;
    return 0;
}


void test_filterkey_audit_events_custom(void **state) {
    (void) state;
    audit_key_type ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"test_key\"";
    char *key = "test_key";
    char buff[OS_SIZE_128] = {0};

    snprintf(syscheck.audit_key[0], strlen(key) + 1, "%s", key);

    snprintf(buff, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, key);
    expect_string(__wrap__mdebug2, formatted_msg, buff);

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_CUSTOM_KEY);
}


void test_filterkey_audit_events_discard(void **state) {
    (void) state;

    char *key = "test_key";
    audit_key_type ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"test_invalid_key\"";

    syscheck.audit_key = calloc(2, sizeof(char *));
    syscheck.audit_key[0] = calloc(strlen(key) + 2, sizeof(char));
    snprintf(syscheck.audit_key[0], strlen(key) + 1, "%s", key);

    ret = filterkey_audit_events(event);

    free(syscheck.audit_key[0]);
    free(syscheck.audit_key);

    assert_int_equal(ret, FIM_AUDIT_UNKNOWN_KEY);
}


void test_filterkey_audit_events_hc(void **state) {
    (void) state;

    audit_key_type ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"wazuh_hc\"";
    char buff[OS_SIZE_128] = {0};

    snprintf(buff, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_hc");
    expect_string(__wrap__mdebug2, formatted_msg, buff);

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_HC_KEY);
}


void test_filterkey_audit_events_fim(void **state) {
    (void) state;

    audit_key_type ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"wazuh_fim\"";
    char audit_key_msg[OS_SIZE_128] = {0};

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_KEY);
}

void test_filterkey_audit_events_missing_whitespace(void **state) {
    (void) state;

    audit_key_type ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57key=\"wazuh_fim\"";

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_UNKNOWN_KEY);
}

void test_filterkey_audit_events_missing_equal_sign(void **state) {
    (void) state;

    audit_key_type ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key\"wazuh_fim\"";

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_UNKNOWN_KEY);
}

void test_filterkey_audit_events_no_key(void **state) {
    (void) state;

    audit_key_type ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57";

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_UNKNOWN_KEY);
}

void test_filterkey_audit_events_key_at_the_beggining(void **state) {
    (void) state;

    audit_key_type ret;
    char * event = "key=\"wazuh_fim\" type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57";

    char audit_key_msg[OS_SIZE_128] = {0};
    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_KEY);
}

void test_filterkey_audit_events_key_end_line(void **state) {
    (void) state;

    audit_key_type ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 \nkey=\"wazuh_fim\"";

    char audit_key_msg[OS_SIZE_128] = {0};
    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_KEY);
}

void test_filterkey_audit_events_hex_coded_key_no_fim(void **state) {
    (void) state;

    audit_key_type ret;
    snprintf(syscheck.audit_key[0], OS_SIZE_64, "key_1");

    // The decoded key in the event is "key_1\001key_2"
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=6B65795F31016B65795F32";

    char audit_key_msg[OS_SIZE_128] = {0};
    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "key_1");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_CUSTOM_KEY);
}

void test_filterkey_audit_events_hex_coded_key_no_fim_second_key(void **state) {
    (void) state;

    audit_key_type ret;
    snprintf(syscheck.audit_key[0], OS_SIZE_64, "key_2");
    // The decoded key in the event is "key_1\001key_2"
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=6B65795F31016B65795F32";

    char audit_key_msg[OS_SIZE_128] = {0};
    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "key_2");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_CUSTOM_KEY);
}

void test_filterkey_audit_events_hex_coded_key_fim(void **state) {
    (void) state;

    audit_key_type ret;
    // The decoded key of the event is "wazuh_fim\001key_2\001key_1"
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=77617A75685F66696D016B65795F32016B65795F31 ";

    char audit_key_msg[OS_SIZE_128] = {0};
    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_KEY);
}

void test_filterkey_audit_events_path_named_key(void **state) {
    (void) state;

    audit_key_type ret;
    snprintf(syscheck.audit_key[0], OS_SIZE_64, "key_1");
    // The decoded key in the event is "key_1\001key_2"
    char * event = "path=\"key\" type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=6B65795F31016B65795F32";

    char audit_key_msg[OS_SIZE_128] = {0};
    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "key_1");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_CUSTOM_KEY);
}

void test_filterkey_audit_events_separator(void **state) {
    (void) state;

    audit_key_type ret;
    // The decoded key of the event is "wazuh_fim\001key_2\001key_1"
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=77617A75685F66696D016B65795F32016B65795F31\035ARCH= ";

    char audit_key_msg[OS_SIZE_128] = {0};
    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_KEY);
}

void test_filterkey_audit_events_separator_in_key(void **state) {
    (void) state;

    audit_key_type ret;
    // The decoded key of the event is "wazuh_f`5\001key_2\001key_1"
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=77617A75685F666035016B65795F32016B65795F31\035ARCH= ";
    snprintf(syscheck.audit_key[0], OS_SIZE_64, "wazuh_f`5");

    char audit_key_msg[OS_SIZE_128] = {0};
    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_f`5");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, FIM_AUDIT_CUSTOM_KEY);
}


void test_gen_audit_path(void **state) {
    (void) state;

    char * cwd = "/root";
    char * path0 = "/root/test/";
    char * path1 = "/root/test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path2(void **state) {
    (void) state;

    char * cwd = "/root";
    char * path0 = "./test/";
    char * path1 = "./test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path3(void **state) {
    (void) state;

    char * cwd = "/";
    char * path0 = "root/test/";
    char * path1 = "root/test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path4(void **state) {
    (void) state;

    char * cwd = "/";
    char * path0 = "/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, NULL);
    *state = ret;

    assert_string_equal(ret, "/file");
}


void test_gen_audit_path5(void **state) {
    (void) state;

    char * cwd = "/root/test";
    char * path0 = "../test/";
    char * path1 = "../test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path6(void **state) {
    (void) state;

    char * cwd = "/root";
    char * path0 = "./file";

    char * ret;
    ret = gen_audit_path(cwd, path0, NULL);
    *state = ret;

    assert_string_equal(ret, "/root/file");
}


void test_gen_audit_path7(void **state) {
    (void) state;

    char * cwd = "/root";
    char * path0 = "../file";

    char * ret;
    ret = gen_audit_path(cwd, path0, NULL);
    *state = ret;

    assert_string_equal(ret, "/file");
}


void test_gen_audit_path8(void **state) {
    (void) state;

    char * cwd = "/root";
    char * path0 = "file";

    char * ret;
    ret = gen_audit_path(cwd, path0, NULL);
    *state = ret;

    assert_string_equal(ret, "/root/file");
}

void test_get_process_parent_info_failed(void **state) {
    (void) state;

    char *parent_name;
    char *parent_cwd;

    parent_name = malloc(10);
    parent_cwd = malloc(10);
    errno = 17;
    will_return(__wrap_readlink, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Failure to obtain the name of the process: '1515'. Error: File exists");

    will_return(__wrap_readlink, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Failure to obtain the cwd of the process: '1515'. Error: File exists");
    get_parent_process_info("1515", &parent_name, &parent_cwd);
    errno = 0;

    assert_string_equal(parent_name, "");
    assert_string_equal(parent_cwd, "");

    if (parent_name != NULL) {
        free(parent_name);
        parent_name = NULL;
    }

    if (parent_cwd != NULL) {
        free(parent_cwd);
        parent_cwd = NULL;
    }
}

void test_get_process_parent_info_passsed(void **state) {
    (void) state;

    char *parent_name;
    char *parent_cwd;

    parent_name = malloc(10);
    parent_cwd = malloc(10);

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    get_parent_process_info("1515", &parent_name, &parent_cwd);

    assert_string_equal(parent_name, "");
    assert_string_equal(parent_cwd, "");

    if (parent_name != NULL) {
        free(parent_name);
        parent_name = NULL;
    }

    if (parent_cwd != NULL) {
        free(parent_cwd);
        parent_cwd = NULL;
    }
}

void test_audit_parse(void **state) {
    (void) state;
    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=SYSCALL msg=audit(1571914029.306:3004254): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c5f8170490 a2=0 a3=7ff365c5eca0 items=2 ppid=3211 pid=44082 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"test\" exe=\"74657374C3B1\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571914029.306:3004254): cwd=\"/root/test\" \
        type=PATH msg=audit(1571914029.306:3004254): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571914029.306:3004254): item=1 name=\"test\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571914029.306:3004254): proctitle=726D0074657374 \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_INVALID_AUID);

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, strdup("root"));

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=root, auid=, euid=root, gid=root, pid=44082, ppid=3211, inode=19, path=/root/test/test, pname=74657374C3B1");

    expect_string(__wrap_realpath, path, "/root/test/test");
    will_return(__wrap_realpath, strdup("/root/test/test"));

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 44082);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "74657374C3B1");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/test");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "19");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3211);

    audit_parse(buffer);
}


void test_audit_parse3(void **state) {
    (void) state;
    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=SYSCALL msg=audit(1571914029.306:3004254): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c5f8170490 a2=0 a3=7ff365c5eca0 items=3 ppid=3211 pid=44082 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"test\" exe=\"74657374C3B1\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571914029.306:3004254): cwd=\"/root/test\" \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=\"./\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=\"folder/\" inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=\"./test\" inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571914029.306:3004254): proctitle=726D0074657374 \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, strdup("root"));

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=root, auid=, euid=root, gid=root, pid=44082, ppid=3211, inode=28, path=/root/test/test, pname=74657374C3B1");

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 44082);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "74657374C3B1");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/test");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "28");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3211);

    audit_parse(buffer);
}


void test_audit_parse4(void **state) {
    (void) state;
    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=SYSCALL msg=audit(1571923546.947:3004294): arch=c000003e syscall=316 success=yes exit=0 a0=ffffff9c a1=7ffe425fc770 a2=ffffff9c a3=7ffe425fc778 items=4 ppid=3212 pid=51452 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"mv\" exe=66696C655FC3B1 key=\"wazuh_fim\" \
        type=CWD msg=audit(1571923546.947:3004294): cwd=2F726F6F742F746573742F74657374C3B1 \
        type=PATH msg=audit(1571923546.947:3004294): item=0 name=\"./\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=1 name=\"folder/\" inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=2 name=\"./test\" inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=3 name=\"folder/test\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571923546.947:3004294): proctitle=6D760066696C655FC3B1002E2E2F74657374C3B1322F66696C655FC3B163 \
    ";
    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, strdup("root"));

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6248): audit_event_1/2: uid=root, auid=root, euid=root, gid=root, pid=51452, ppid=3212, inode=19, path=/root/test/testñ/test, pname=file_ñ");
    expect_string(__wrap__mdebug2, formatted_msg,
        "(6249): audit_event_2/2: uid=root, auid=root, euid=root, gid=root, pid=51452, ppid=3212, inode=19, path=/root/test/testñ/folder/test, pname=file_ñ");

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 51452);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/testñ/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "19");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3212);

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 51452);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/testñ/folder/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "19");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3212);

    audit_parse(buffer);
}


void test_audit_parse_hex(void **state) {
    (void) state;
    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=SYSCALL msg=audit(1571923546.947:3004294): arch=c000003e syscall=316 success=yes exit=0 a0=ffffff9c a1=7ffe425fc770 a2=ffffff9c a3=7ffe425fc778 items=4 ppid=3212 pid=51452 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"mv\" exe=66696C655FC3B1 key=\"wazuh_fim\" \
        type=CWD msg=audit(1571923546.947:3004294): cwd=2F726F6F742F746573742F74657374C3B1 \
        type=PATH msg=audit(1571923546.947:3004294): item=0 name=2F726F6F742F746573742F74657374C3B1 inode=19 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=1 name=2E2E2F74657374C3B1322F inode=30 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=2 name=66696C655FC3B1 inode=29 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=3 name=2E2E2F74657374C3B1322F66696C655FC3B163 inode=29 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571923546.947:3004294): proctitle=6D760066696C655FC3B1002E2E2F74657374C3B1322F66696C655FC3B163 \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, strdup("root"));

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6248): audit_event_1/2: uid=root, auid=root, euid=root, gid=root, pid=51452, ppid=3212, inode=29, path=/root/test/testñ/file_ñ, pname=file_ñ");
    expect_string(__wrap__mdebug2, formatted_msg,
        "(6249): audit_event_2/2: uid=root, auid=root, euid=root, gid=root, pid=51452, ppid=3212, inode=29, path=/root/test/testñ2/file_ñc, pname=file_ñ");

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 51452);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/testñ/file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "29");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3212);

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 51452);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/testñ2/file_ñc");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "29");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3212);

    audit_parse(buffer);
}


void test_audit_parse_empty_fields(void **state) {
    (void) state;
    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=SYSCALL msg=audit(1571914029.306:3004254): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c5f8170490 a2=0 a3=7ff365c5eca0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"test\" key=\"wazuh_fim\" \
        type=PROCTITLE msg=audit(1571914029.306:3004254): proctitle=726D0074657374 \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    audit_parse(buffer);
}


void test_audit_parse_delete(void **state) {
    (void) state;
    char audit_key_msg[OS_SIZE_128] = {0};


    char * buffer = "type=CONFIG_CHANGE msg=audit(1571920603.069:3004276): auid=0 ses=5 op=\"remove_rule\" key=\"wazuh_fim\" list=4 res=1";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    will_return(__wrap_fim_manipulated_audit_rules, 0);
    expect_string(__wrap__mwarn, formatted_msg, "(6911): Detected Audit rules manipulation: Audit rules removed.");

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Audit rules removed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);
    expect_function_call(__wrap_fim_audit_reload_rules);

    audit_parse(buffer);
}


void test_audit_parse_delete_recursive(void **state) {
    char * buffer = "type=CONFIG_CHANGE msg=audit(1571920603.069:3004276): auid=0 ses=5 op=remove_rule key=\"wazuh_fim\" list=4 res=1";

    syscheck.max_audit_entries = 100;
    char audit_key_msg[OS_SIZE_128] = {0};

    count_reload_retries = 0;
    // In audit_reload_rules()
    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string_count(__wrap__mdebug2, formatted_msg, audit_key_msg, 5);

    will_return_count(__wrap_fim_manipulated_audit_rules, 0, 5);
    expect_string_count(__wrap__mwarn, formatted_msg, FIM_WARN_AUDIT_RULES_MODIFIED, 5);
    expect_function_calls(__wrap_fim_audit_reload_rules, 4);

    expect_value(__wrap_atomic_int_set, atomic, &audit_thread_active);
    will_return(__wrap_atomic_int_set, 0);

    expect_string_count(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Audit rules removed", 5);
    expect_string_count(__wrap_SendMSG, locmsg, SYSCHECK, 6);
    expect_value_count(__wrap_SendMSG, loc, LOCALFILE_MQ, 6);
    will_return_always(__wrap_SendMSG, 1);

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Max rules reload retries");
    int i;
    for (i = 0; i < 5; i++) {
        audit_parse(buffer);
    }

    count_reload_retries = 0;
}


void test_audit_parse_mv(void **state) {
    (void) state;

    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=SYSCALL msg=audit(1571925844.299:3004308): arch=c000003e syscall=82 success=yes exit=0 a0=7ffdbb76377e a1=556c16f6c2e0 a2=0 a3=100 items=5 ppid=3210 pid=52277 auid=20 uid=30 gid=40 euid=50 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"mv\" exe=\"/usr/bin/mv\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571925844.299:3004308): cwd=\"/root/test\" \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=\"./\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=\"folder/\" inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=\"./test\" inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=3 name=\"folder/test\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=4 name=\"folder/test\" inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571925844.299:3004308): proctitle=6D76002E2F7465737400666F6C646572 \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    expect_value(__wrap_get_user, uid, 30);
    will_return(__wrap_get_user, strdup("user30"));
    expect_value(__wrap_get_user, uid, 20);
    will_return(__wrap_get_user, strdup("user20"));
    expect_value(__wrap_get_user, uid, 50);
    will_return(__wrap_get_user, strdup("user50"));

    expect_value(__wrap_get_group, gid, 40);
    will_return(__wrap_get_group, strdup("src"));

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=user30, auid=user20, euid=user50, gid=src, pid=52277, ppid=3210, inode=28, path=/root/test/folder/test, pname=/usr/bin/mv");

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 52277);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "30");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "40");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/mv");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/folder/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "20");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "50");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "28");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3210);

    audit_parse(buffer);
}


void test_audit_parse_mv_hex(void **state) {
    (void) state;

    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=SYSCALL msg=audit(1571925844.299:3004308): arch=c000003e syscall=82 success=yes exit=0 a0=7ffdbb76377e a1=556c16f6c2e0 a2=0 a3=100 items=5 ppid=3210 pid=52277 auid=20 uid=30 gid=40 euid=50 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"mv\" exe=\"/usr/bin/mv\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571925844.299:3004308): cwd=\"/root/test\" \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=\"./\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=\"folder/\" inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=\"./test\" inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=3 name=666F6C6465722F74657374 inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=4 name=666F6C6465722F74657374 inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571925844.299:3004308): proctitle=6D76002E2F7465737400666F6C646572 \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    expect_value(__wrap_get_user, uid, 30);
    will_return(__wrap_get_user, strdup("user30"));
    expect_value(__wrap_get_user, uid, 20);
    will_return(__wrap_get_user, strdup("user20"));
    expect_value(__wrap_get_user, uid, 50);
    will_return(__wrap_get_user, strdup("user50"));

    expect_value(__wrap_get_group, gid, 40);
    will_return(__wrap_get_group, strdup("src"));

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=user30, auid=user20, euid=user50, gid=src, pid=52277, ppid=3210, inode=28, path=/root/test/folder/test, pname=/usr/bin/mv");

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 52277);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "30");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "40");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/mv");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/folder/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "20");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "50");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "28");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3210);

    audit_parse(buffer);
}


void test_audit_parse_rm(void **state) {
    (void) state;

    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=SYSCALL msg=audit(1571988027.797:3004340): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55578e6d8490 a2=200 a3=7f9cd931bca0 items=3 ppid=3211 pid=56650 auid=2 uid=30 gid=5 euid=2 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"rm\" exe=\"/usr/bin/rm\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571988027.797:3004340): cwd=\"/root/test\" \
        type=PATH msg=audit(1571988027.797:3004340): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=1 name=(null) inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=2 name=(null) inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571988027.797:3004340): proctitle=726D002D726600666F6C6465722F \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    expect_value(__wrap_get_user, uid, 30);
    will_return(__wrap_get_user, strdup("user30"));
    expect_value(__wrap_get_user, uid, 2);
    will_return(__wrap_get_user, strdup("daemon"));
    expect_value(__wrap_get_user, uid, 2);
    will_return(__wrap_get_user, strdup("daemon"));

    expect_value(__wrap_get_group, gid, 5);
    will_return(__wrap_get_group, strdup("tty"));

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=user30, auid=daemon, euid=daemon, gid=tty, pid=56650, ppid=3211, inode=24, path=/root/test/, pname=/usr/bin/rm");

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 56650);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "30");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "5");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/rm");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "2");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "2");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "24");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3211);

    audit_parse(buffer);
}


void test_audit_parse_chmod(void **state) {
    (void) state;

    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=SYSCALL msg=audit(1571992092.822:3004348): arch=c000003e syscall=268 success=yes exit=0 a0=ffffff9c a1=5648a8ab74c0 a2=1ff a3=fff items=1 ppid=3211 pid=58280 auid=4 uid=99 gid=78 euid=29 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"chmod\" exe=\"/usr/bin/chmod\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571992092.822:3004348): cwd=\"/root/test\" \
        type=PATH msg=audit(1571992092.822:3004348): item=0 name=\"/root/test/file\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571992092.822:3004348): proctitle=63686D6F6400373737002F726F6F742F746573742F66696C65 \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    expect_value(__wrap_get_user, uid, 99);
    will_return(__wrap_get_user, strdup("user99"));
    expect_value(__wrap_get_user, uid, 4);
    will_return(__wrap_get_user, strdup("lp"));
    expect_value(__wrap_get_user, uid, 29);
    will_return(__wrap_get_user, strdup("user29"));

    expect_value(__wrap_get_group, gid, 78);
    will_return(__wrap_get_group, NULL);

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=user99, auid=lp, euid=user29, gid=, pid=58280, ppid=3211, inode=19, path=/root/test/file, pname=/usr/bin/chmod");


    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 58280);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "99");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "78");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/chmod");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/file");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "4");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "29");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "19");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3211);

    audit_parse(buffer);
}


void test_audit_parse_rm_hc(void **state) {
    (void) state;

    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=SYSCALL msg=audit(1571988027.797:3004340): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55578e6d8490 a2=200 a3=7f9cd931bca0 items=3 ppid=3211 pid=56650 auid=2 uid=30 gid=5 euid=2 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"rm\" exe=\"/usr/bin/rm\" key=\"wazuh_hc\" \
        type=CWD msg=audit(1571988027.797:3004340): cwd=\"/root/test\" \
        type=PATH msg=audit(1571988027.797:3004340): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=1 name=(null) inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=2 name=(null) inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571988027.797:3004340): proctitle=726D002D726600666F6C6465722F \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_hc");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);
    expect_string(__wrap__mdebug2, formatted_msg, "(6253): Whodata health-check: Detected file deletion event (263)");

    audit_parse(buffer);
}


void test_audit_parse_add_hc(void **state) {
    (void) state;
    extern atomic_int_t audit_health_check_creation;
    char audit_key_msg[OS_SIZE_128] = {0};

    char * buffer = " \
        type=SYSCALL msg=audit(1571988027.797:3004340): arch=c000003e syscall=257 success=yes exit=0 a0=ffffff9c a1=55578e6d8490 a2=200 a3=7f9cd931bca0 items=3 ppid=3211 pid=56650 auid=2 uid=30 gid=5 euid=2 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"touch\" exe=\"/usr/bin/touch\" key=\"wazuh_hc\" \
        type=CWD msg=audit(1571988027.797:3004340): cwd=\"/root/test\" \
        type=PATH msg=audit(1571988027.797:3004340): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=1 name=(null) inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=2 name=(null) inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571988027.797:3004340): proctitle=726D002D726600666F6C6465722F \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_hc");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);
    expect_string(__wrap__mdebug2, formatted_msg, "(6252): Whodata health-check: Detected file creation event (257)");

    expect_value(__wrap_atomic_int_set, atomic, &audit_health_check_creation);
    will_return(__wrap_atomic_int_set, 1);

    audit_parse(buffer);
}


void test_audit_parse_unknown_hc(void **state) {
    (void) state;

    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=SYSCALL msg=audit(1571988027.797:3004340): arch=c000003e syscall=90 success=yes exit=0 a0=ffffff9c a1=55578e6d8490 a2=200 a3=7f9cd931bca0 items=3 ppid=3211 pid=56650 auid=2 uid=30 gid=5 euid=2 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"chmod\" exe=\"/usr/bin/chmod\" key=\"wazuh_hc\" \
        type=CWD msg=audit(1571988027.797:3004340): cwd=\"/root/test\" \
        type=PATH msg=audit(1571988027.797:3004340): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=1 name=(null) inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=2 name=(null) inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571988027.797:3004340): proctitle=726D002D726600666F6C6465722F \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_hc");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);
    expect_string(__wrap__mdebug2, formatted_msg, "(6254): Whodata health-check: Unrecognized event (90)");

    audit_parse(buffer);
}


void test_audit_parse_delete_folder(void **state) {
    (void) state;

    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=CONFIG_CHANGE msg=audit(1572878838.610:220): op=remove_rule dir=\"/root/test\" key=\"wazuh_fim\" list=4 res=1 \
        type=SYSCALL msg=audit(1572878838.610:220): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c2b7d7f490 a2=200 a3=7f2b8055bca0 items=2 ppid=4340 pid=62845 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=7 comm=\"rm\" exe=\"/usr/bin/rm\" key=(null) \
        type=CWD msg=audit(1572878838.610:220): cwd=\"/root\" \
        type=PATH msg=audit(1572878838.610:220): item=0 name=\"/root\" inode=655362 dev=08:02 mode=040700 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1572878838.610:220): item=1 name=\"test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1572878838.610:220): proctitle=726D002D72660074657374 \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);
    expect_string(__wrap__minfo, formatted_msg, "(6027): Monitored directory '/root/test' was removed: Audit rule removed.");

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, strdup("root"));

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6247): audit_event: uid=root, auid=root, euid=root, gid=root, pid=62845, ppid=4340, inode=110, path=/root/test, pname=/usr/bin/rm");

    expect_string(__wrap_realpath, path, "/root/test");
    will_return(__wrap_realpath, strdup("/root/test"));

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 62845);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/rm");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "110");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 4340);

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Monitored directory was removed: Audit rule removed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    audit_parse(buffer);
}


void test_audit_parse_delete_folder_hex(void **state) {
    (void) state;

    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=CONFIG_CHANGE msg=audit(1572878838.610:220): op=remove_rule dir=2F726F6F742F746573742F74657374C3B1 key=\"wazuh_fim\" list=4 res=1 \
        type=SYSCALL msg=audit(1572878838.610:220): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c2b7d7f490 a2=200 a3=7f2b8055bca0 items=2 ppid=4340 pid=62845 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=7 comm=\"rm\" exe=\"/usr/bin/rm\" key=(null) \
        type=CWD msg=audit(1572878838.610:220): cwd=\"/root\" \
        type=PATH msg=audit(1572878838.610:220): item=0 name=\"/root\" inode=655362 dev=08:02 mode=040700 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1572878838.610:220): item=1 name=\"test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1572878838.610:220): proctitle=726D002D72660074657374 \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);
    expect_string(__wrap__minfo, formatted_msg, "(6027): Monitored directory '/root/test/testñ' was removed: Audit rule removed.");

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, strdup("root"));

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6247): audit_event: uid=root, auid=root, euid=root, gid=root, pid=62845, ppid=4340, inode=110, path=/root/test, pname=/usr/bin/rm");

    expect_string(__wrap_realpath, path, "/root/test");
    will_return(__wrap_realpath, strdup("/root/test"));


    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 62845);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/rm");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "110");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 4340);

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Monitored directory was removed: Audit rule removed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    audit_parse(buffer);
}


void test_audit_parse_delete_folder_hex3_error(void **state) {
    (void) state;

    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=CONFIG_CHANGE msg=audit(1572878838.610:220): op=remove_rule dir=0 key=\"wazuh_fim\" list=4 res=1 \
        type=SYSCALL msg=audit(1572878838.610:220): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c2b7d7f490 a2=200 a3=7f2b8055bca0 items=3 ppid=4340 pid=62845 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=7 comm=\"rm\" exe=1 key=(null) \
        type=CWD msg=audit(1572878838.610:220): cwd=2 \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=3 inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=4 inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=5 inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1572878838.610:220): proctitle=726D002D72660074657374 \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '0'");

    will_return(__wrap_fim_manipulated_audit_rules, 0);
    expect_string(__wrap__mwarn, formatted_msg, "(6911): Detected Audit rules manipulation: Audit rules removed.");
    expect_function_call(__wrap_fim_audit_reload_rules);

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Audit rules removed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, strdup("root"));

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '1'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '2'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '3'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '4'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '5'");

    audit_parse(buffer);
}


void test_audit_parse_delete_folder_hex4_error(void **state) {
    (void) state;
    char audit_key_msg[OS_SIZE_128] = {0};

    char * buffer = " \
        type=CONFIG_CHANGE msg=audit(1572878838.610:220): op=remove_rule dir=0 key=\"wazuh_fim\" list=4 res=1 \
        type=SYSCALL msg=audit(1572878838.610:220): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c2b7d7f490 a2=200 a3=7f2b8055bca0 items=4 ppid=4340 pid=62845 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=7 comm=\"rm\" exe=1 key=(null) \
        type=CWD msg=audit(1572878838.610:220): cwd=2 \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=3 inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=4 inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=5 inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=3 name=6 inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1572878838.610:220): proctitle=726D002D72660074657374 \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '0'");

    will_return(__wrap_fim_manipulated_audit_rules, 0);
    expect_string(__wrap__mwarn, formatted_msg, "(6911): Detected Audit rules manipulation: Audit rules removed.");
    expect_function_call(__wrap_fim_audit_reload_rules);

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Audit rules removed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, strdup("root"));

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '1'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '2'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '3'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '4'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '5'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '6'");

    audit_parse(buffer);
}


void test_audit_parse_delete_folder_hex5_error(void **state) {
    (void) state;

    char audit_key_msg[OS_SIZE_128] = {0};
    char * buffer = " \
        type=CONFIG_CHANGE msg=audit(1572878838.610:220): op=remove_rule dir=0 key=\"wazuh_fim\" list=4 res=1 \
        type=SYSCALL msg=audit(1572878838.610:220): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c2b7d7f490 a2=200 a3=7f2b8055bca0 items=5 ppid=4340 pid=62845 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=7 comm=\"rm\" exe=1 key=(null) \
        type=CWD msg=audit(1572878838.610:220): cwd=2 \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=3 inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=4 inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=5 inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=3 name=6 inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=4 name=7 inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1572878838.610:220): proctitle=726D002D72660074657374 \
    ";

    snprintf(audit_key_msg, OS_SIZE_128, FIM_AUDIT_MATCH_KEY, "wazuh_fim");
    expect_string(__wrap__mdebug2, formatted_msg, audit_key_msg);

    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '0'");

    will_return(__wrap_fim_manipulated_audit_rules, 0);
    expect_string(__wrap__mwarn, formatted_msg, "(6911): Detected Audit rules manipulation: Audit rules removed.");
    expect_function_call(__wrap_fim_audit_reload_rules);

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Audit rules removed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, strdup("root"));

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '1'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '2'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '3'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '4'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '7'");

    audit_parse(buffer);
}
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_filterkey_audit_events_custom, setup_custom_key, teardown_custom_key),
        cmocka_unit_test(test_filterkey_audit_events_discard),
        cmocka_unit_test(test_filterkey_audit_events_fim),
        cmocka_unit_test(test_filterkey_audit_events_hc),
        cmocka_unit_test(test_filterkey_audit_events_missing_whitespace),
        cmocka_unit_test(test_filterkey_audit_events_missing_equal_sign),
        cmocka_unit_test(test_filterkey_audit_events_no_key),
        cmocka_unit_test(test_filterkey_audit_events_key_at_the_beggining),
        cmocka_unit_test(test_filterkey_audit_events_key_end_line),
        cmocka_unit_test(test_filterkey_audit_events_hex_coded_key_fim),
        cmocka_unit_test(test_filterkey_audit_events_separator),
        cmocka_unit_test_setup_teardown(test_filterkey_audit_events_separator_in_key, setup_custom_key, teardown_custom_key),
        cmocka_unit_test_setup_teardown(test_filterkey_audit_events_hex_coded_key_no_fim, setup_custom_key, teardown_custom_key),
        cmocka_unit_test_setup_teardown(test_filterkey_audit_events_hex_coded_key_no_fim_second_key, setup_custom_key, teardown_custom_key),
        cmocka_unit_test_setup_teardown(test_filterkey_audit_events_path_named_key, setup_custom_key, teardown_custom_key),
        cmocka_unit_test_teardown(test_gen_audit_path, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path2, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path3, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path4, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path5, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path6, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path7, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path8, free_string),
        cmocka_unit_test(test_get_process_parent_info_failed),
        cmocka_unit_test(test_get_process_parent_info_passsed),
        cmocka_unit_test(test_audit_parse),
        cmocka_unit_test(test_audit_parse3),
        cmocka_unit_test(test_audit_parse4),
        cmocka_unit_test(test_audit_parse_hex),
        cmocka_unit_test(test_audit_parse_empty_fields),
        cmocka_unit_test(test_audit_parse_delete),
        cmocka_unit_test_setup_teardown(test_audit_parse_delete_recursive, setup_config, teardown_config),
        cmocka_unit_test(test_audit_parse_mv),
        cmocka_unit_test(test_audit_parse_mv_hex),
        cmocka_unit_test(test_audit_parse_rm),
        cmocka_unit_test(test_audit_parse_chmod),
        cmocka_unit_test(test_audit_parse_rm_hc),
        cmocka_unit_test(test_audit_parse_add_hc),
        cmocka_unit_test(test_audit_parse_unknown_hc),
        cmocka_unit_test(test_audit_parse_delete_folder),
        cmocka_unit_test(test_audit_parse_delete_folder_hex),
        cmocka_unit_test(test_audit_parse_delete_folder_hex3_error),
        cmocka_unit_test(test_audit_parse_delete_folder_hex4_error),
        cmocka_unit_test(test_audit_parse_delete_folder_hex5_error),
        };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
