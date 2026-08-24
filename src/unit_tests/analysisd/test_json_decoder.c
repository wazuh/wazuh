/*
 * Copyright (C) 2026, Wazuh Inc.
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
#include <stdlib.h>
#include <string.h>

#include "../../analysisd/eventinfo.h"
#include "../../analysisd/config.h"
#include "../../analysisd/decoders/plugin_decoders.h"

/* Global configuration required by the decoder under test */
_Config Config;

#define TRACKED_MAX 64

/* Allocation tracking, used to detect values that fillData() replaces without releasing */

static void * tracked[TRACKED_MAX];
static int tracked_released[TRACKED_MAX];
static int tracked_count = 0;
static int tracking = 0;

extern char * __real_strdup(const char *s);
extern void __real_free(void *ptr);

char * __wrap_strdup(const char *s) {
    char * ptr = __real_strdup(s);

    if (tracking && ptr != NULL && tracked_count < TRACKED_MAX) {
        tracked[tracked_count] = ptr;
        tracked_released[tracked_count] = 0;
        tracked_count++;
    }

    return ptr;
}

void __wrap_free(void *ptr) {
    for (int i = 0; i < tracked_count; i++) {
        if (tracked[i] == ptr) {
            tracked_released[i] = 1;
        }
    }

    __real_free(ptr);
}

static void tracking_reset(void) {
    tracked_count = 0;
    tracking = 0;
}

static void track(void *ptr) {
    assert_true(tracked_count < TRACKED_MAX);
    tracked[tracked_count] = ptr;
    tracked_released[tracked_count] = 0;
    tracked_count++;
}

static int released(const void *ptr) {
    for (int i = 0; i < tracked_count; i++) {
        if (tracked[i] == ptr && tracked_released[i]) {
            return 1;
        }
    }

    return 0;
}

static int pending(void) {
    int count = 0;

    for (int i = 0; i < tracked_count; i++) {
        if (!tracked_released[i]) {
            count++;
        }
    }

    return count;
}

/* Static fields handled by fillData() */

typedef struct {
    const char * key;
    size_t offset;
} static_field_t;

static const static_field_t STATIC_FIELDS[] = {
    { "srcip", offsetof(Eventinfo, srcip) },
    { "dstip", offsetof(Eventinfo, dstip) },
    { "srcport", offsetof(Eventinfo, srcport) },
    { "dstport", offsetof(Eventinfo, dstport) },
    { "protocol", offsetof(Eventinfo, protocol) },
    { "action", offsetof(Eventinfo, action) },
    { "srcuser", offsetof(Eventinfo, srcuser) },
    { "dstuser", offsetof(Eventinfo, dstuser) },
    { "id", offsetof(Eventinfo, id) },
    { "status", offsetof(Eventinfo, status) },
    { "url", offsetof(Eventinfo, url) },
    { "data", offsetof(Eventinfo, data) },
    { "extra_data", offsetof(Eventinfo, extra_data) },
    { "systemname", offsetof(Eventinfo, systemname) },
};

#define STATIC_FIELDS_COUNT (sizeof(STATIC_FIELDS) / sizeof(STATIC_FIELDS[0]))

/* Setup / teardown */

static OSDecoderInfo decoder_info;

/* Releases the fields that fillData() owns. Mirrors the static field cleanup of
 * Free_Eventinfo(), which cannot be linked here because analysisd provides main().
 */
static void free_event(Eventinfo *lf) {
    for (unsigned int i = 0; i < STATIC_FIELDS_COUNT; i++) {
        char ** field = (char **) ((char *) lf + STATIC_FIELDS[i].offset);
        free(*field);
    }

    for (int i = 0; i < lf->nfields; i++) {
        free(lf->fields[i].key);
        free(lf->fields[i].value);
    }

    free(lf->fields);
    free(lf);
}

static int setup_group(void **state) {
    (void) state;

    memset(&Config, 0, sizeof(Config));
    Config.decoder_order_size = 32;

    memset(&decoder_info, 0, sizeof(decoder_info));
    decoder_info.plugin_offset = 0;
    decoder_info.name = "json";

    return 0;
}

static int setup_event(void **state) {
    tracking_reset();

    Eventinfo * lf = calloc(1, sizeof(Eventinfo));
    assert_non_null(lf);

    lf->fields = calloc(Config.decoder_order_size, sizeof(DynamicField));
    assert_non_null(lf->fields);
    lf->decoder_info = &decoder_info;

    *state = lf;

    return 0;
}

static int teardown_event(void **state) {
    Eventinfo * lf = *state;

    if (lf != NULL) {
        free_event(lf);
        *state = NULL;
    }

    tracking_reset();

    return 0;
}

/* Tests */

static void test_fillData_duplicate_static_field_releases_previous(void **state) {
    Eventinfo * lf = *state;

    for (unsigned int i = 0; i < STATIC_FIELDS_COUNT; i++) {
        char ** field = (char **) ((char *) lf + STATIC_FIELDS[i].offset);

        fillData(lf, STATIC_FIELDS[i].key, "first");
        assert_non_null(*field);
        assert_string_equal(*field, "first");

        char * previous = *field;
        track(previous);

        fillData(lf, STATIC_FIELDS[i].key, "second");

        assert_true(released(previous));
        assert_string_equal(*field, "second");
    }

    assert_int_equal(lf->nfields, 0);
}

static void test_fillData_duplicate_user_alias_releases_previous(void **state) {
    Eventinfo * lf = *state;

    fillData(lf, "user", "");
    assert_non_null(lf->dstuser);
    assert_string_equal(lf->dstuser, "");

    char * previous = lf->dstuser;
    track(previous);

    fillData(lf, "user", "root");

    assert_true(released(previous));
    assert_string_equal(lf->dstuser, "root");
    assert_int_equal(lf->nfields, 0);
}

static void test_JSON_Decoder_Exec_duplicate_static_fields_keeps_one_copy(void **state) {
    Eventinfo * lf = *state;
    static char event[] = "{\"id\":\"aaa\",\"id\":\"bbb\",\"id\":\"ccc\","
                          "\"srcip\":\"1.1.1.1\",\"srcip\":\"2.2.2.2\"}";

    lf->log = event;

    tracking = 1;
    JSON_Decoder_Exec(lf, NULL, NULL);
    tracking = 0;

    assert_string_equal(lf->id, "ccc");
    assert_string_equal(lf->srcip, "2.2.2.2");
    assert_int_equal(lf->nfields, 0);

    /* One key and one value allocated per member */
    assert_int_equal(tracked_count, 10);
    /* Only the surviving id and srcip must still be held */
    assert_int_equal(pending(), 2);
}

static void test_JSON_Decoder_Exec_unique_fields_keeps_every_value(void **state) {
    Eventinfo * lf = *state;
    static char event[] = "{\"id\":\"aaa\",\"srcip\":\"1.1.1.1\",\"custom\":\"value\"}";

    lf->log = event;

    tracking = 1;
    JSON_Decoder_Exec(lf, NULL, NULL);
    tracking = 0;

    assert_string_equal(lf->id, "aaa");
    assert_string_equal(lf->srcip, "1.1.1.1");
    assert_int_equal(lf->nfields, 1);
    assert_string_equal(lf->fields[0].key, "custom");
    assert_string_equal(lf->fields[0].value, "value");

    /* One key per member plus the values of id, srcip and the dynamic field, and its key */
    assert_int_equal(tracked_count, 7);
    /* id, srcip and the key and value of the dynamic field */
    assert_int_equal(pending(), 4);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_fillData_duplicate_static_field_releases_previous, setup_event, teardown_event),
        cmocka_unit_test_setup_teardown(test_fillData_duplicate_user_alias_releases_previous, setup_event, teardown_event),
        cmocka_unit_test_setup_teardown(test_JSON_Decoder_Exec_duplicate_static_fields_keeps_one_copy, setup_event, teardown_event),
        cmocka_unit_test_setup_teardown(test_JSON_Decoder_Exec_unique_fields_keeps_every_value, setup_event, teardown_event),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
