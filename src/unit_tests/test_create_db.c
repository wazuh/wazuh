/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
#include <string.h>

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

/* redefinitons/wrapping */


/* tests */

static int delete_json(void **state)
{
    cJSON *data = *state;
    cJSON_Delete(data);
    return 0;
}

static fim_entry_data *fill_entry_struct(
    unsigned int size,
    const char * perm,
    const char * attributes,
    const char * uid,
    const char * gid,
    const char * user_name,
    const char * group_name,
    unsigned int mtime,
    unsigned long int inode,
    const char * hash_md5,
    const char * hash_sha1,
    const char * hash_sha256,
    fim_event_mode mode,
    time_t last_event,
    const char * entry_type,
    const char * win_perm_mask,
    unsigned long int dev,
    unsigned int scanned,
    int options,
    os_sha1 checksum
) {
    fim_entry_data *data = calloc(1, sizeof(fim_entry_data));
    data->size = size;
    data->perm = strdup(perm);
    data->attributes = strdup(attributes);
    data->uid = strdup(uid);
    data->gid = strdup(gid);
    data->user_name = strdup(user_name);
    data->group_name = strdup(group_name);;
    data->mtime = mtime;
    data->inode = inode;
    strcpy(data->hash_md5, hash_md5);
    strcpy(data->hash_sha1, hash_sha1);
    strcpy(data->hash_sha256, hash_sha256);
    data->mode = mode;
    data->last_event = last_event;
    data->entry_type = entry_type;
    data->win_perm_mask = strdup(win_perm_mask);
    data->dev = dev;
    data->scanned = scanned;
    data->options = options;
    strcpy(data->checksum, checksum);
    return data;
}


void test_fim_json_event(void **state)
{
    (void) state;
    cJSON *ret;

    // Load syscheck default values
    read_internal(1);
    Read_Syscheck_Config("/var/ossec/etc/ossec.conf");

    fim_entry_data *old_data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        "xxx",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );

    fim_entry_data *new_data = fill_entry_struct(
        1501,
        "0666",
        "rw-rw-rw-",
        "101",
        "1001",
        "test1",
        "testing1",
        1570184224,
        606060,
        "3691689a513ace7e508297b583d7550d",
        "07f05add1049244e7e75ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e9959643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184221,
        "file",
        "xxx",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );

    ret = fim_json_event(
        "test.file",
        old_data,
        new_data,
        1,
        FIM_MODIFICATION,
        FIM_REALTIME,
        NULL
    );

    *state = ret;
    free_entry_data(old_data);
    free_entry_data(new_data);


    cJSON *data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);
    assert_int_equal(cJSON_GetArraySize(data), 7);
    assert_non_null(ret);
}

void test_fim_json_event_no_changes(void **state)
{
    (void) state;
    cJSON *ret;

    // Load syscheck default values
    read_internal(1);
    Read_Syscheck_Config("/var/ossec/etc/ossec.conf");

    fim_entry_data *data = fill_entry_struct(
        1500,
        "0664",
        "r--r--r--",
        "100",
        "1000",
        "test",
        "testing",
        1570184223,
        606060,
        "3691689a513ace7e508297b583d7050d",
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b",
        "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40",
        FIM_REALTIME,
        1570184220,
        "file",
        "xxx",
        12345678,
        123456,
        511,
        "07f05add1049244e7e71ad0f54f24d8094cd8f8b"
    );

    ret = fim_json_event(
        "test.file",
        data,
        data,
        1,
        FIM_MODIFICATION,
        FIM_WHODATA,
        NULL
    );

    *state = ret;

    free_entry_data(data);

    assert_null(ret);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_fim_json_event, delete_json),
        cmocka_unit_test_teardown(test_fim_json_event_no_changes, delete_json),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
