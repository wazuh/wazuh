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
#include "../../analysisd/decoders/decoder.h"

/* Global configuration required by the decoder under test */
_Config Config;

#define TRACKED_MAX 64

/* Allocation tracking, used to detect values that a static field setter replaces without releasing */

static void * tracked[TRACKED_MAX];
static int tracked_released[TRACKED_MAX];
static int tracked_count = 0;
static int tracking = 0;

extern void * __real_malloc(size_t size);
extern void __real_free(void *ptr);

void * __wrap_malloc(size_t size) {
    void * ptr = __real_malloc(size);

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

/* Static field setters used by the decoder <order> option */

typedef struct {
    const char * name;
    void * (*setter)(Eventinfo *, char *, const char *);
    size_t offset;
} static_field_t;

static const static_field_t STATIC_FIELDS[] = {
    { "dstuser", DstUser_FP, offsetof(Eventinfo, dstuser) },
    { "srcuser", SrcUser_FP, offsetof(Eventinfo, srcuser) },
    { "srcip", SrcIP_FP, offsetof(Eventinfo, srcip) },
    { "dstip", DstIP_FP, offsetof(Eventinfo, dstip) },
    { "srcport", SrcPort_FP, offsetof(Eventinfo, srcport) },
    { "dstport", DstPort_FP, offsetof(Eventinfo, dstport) },
    { "protocol", Protocol_FP, offsetof(Eventinfo, protocol) },
    { "action", Action_FP, offsetof(Eventinfo, action) },
    { "id", ID_FP, offsetof(Eventinfo, id) },
    { "url", Url_FP, offsetof(Eventinfo, url) },
    { "data", Data_FP, offsetof(Eventinfo, data) },
    { "extra_data", Extra_Data_FP, offsetof(Eventinfo, extra_data) },
    { "status", Status_FP, offsetof(Eventinfo, status) },
    { "system_name", SystemName_FP, offsetof(Eventinfo, systemname) },
};

#define STATIC_FIELDS_COUNT (sizeof(STATIC_FIELDS) / sizeof(STATIC_FIELDS[0]))

/* Setup / teardown */

/* Releases the fields that the decoder owns. Mirrors the static field cleanup of
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

    return 0;
}

static int setup_event(void **state) {
    tracking_reset();

    Eventinfo * lf = calloc(1, sizeof(Eventinfo));
    assert_non_null(lf);

    lf->fields = calloc(Config.decoder_order_size, sizeof(DynamicField));
    assert_non_null(lf->fields);

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

/* Builds a regex-only child decoder that stores its single capture with the given setter */
static OSDecoderInfo * create_child_decoder(const char * regex, void * (*setter)(Eventinfo *, char *, const char *)) {
    OSDecoderInfo * decoder = calloc(1, sizeof(OSDecoderInfo));
    assert_non_null(decoder);

    decoder->name = "sibling";
    w_calloc_expression_t(&decoder->regex, EXP_TYPE_OSREGEX);
    assert_true(w_expression_compile(decoder->regex, regex, OS_RETURN_SUBSTRING));

    decoder->order = calloc(2, sizeof(*decoder->order));
    assert_non_null(decoder->order);
    decoder->order[0] = setter;

    decoder->fields = calloc(2, sizeof(char *));
    assert_non_null(decoder->fields);

    return decoder;
}

static void free_child_decoder(OSDecoderInfo * decoder) {
    w_free_expression_t(&decoder->regex);
    free(decoder->order);
    free(decoder->fields);
    free(decoder);
}

/* Tests */

static void test_static_field_setter_releases_previous(void **state) {
    Eventinfo * lf = *state;

    for (unsigned int i = 0; i < STATIC_FIELDS_COUNT; i++) {
        char ** field = (char **) ((char *) lf + STATIC_FIELDS[i].offset);

        char * first = strdup("first");
        assert_non_null(first);
        STATIC_FIELDS[i].setter(lf, first, STATIC_FIELDS[i].name);
        assert_ptr_equal(*field, first);

        track(first);

        char * second = strdup("second");
        assert_non_null(second);
        STATIC_FIELDS[i].setter(lf, second, STATIC_FIELDS[i].name);

        assert_true(released(first));
        assert_ptr_equal(*field, second);
        assert_string_equal(*field, "second");
    }

    assert_int_equal(lf->nfields, 0);
}

static void test_static_field_setter_first_value(void **state) {
    Eventinfo * lf = *state;

    for (unsigned int i = 0; i < STATIC_FIELDS_COUNT; i++) {
        char ** field = (char **) ((char *) lf + STATIC_FIELDS[i].offset);
        char * value = strdup("value");
        assert_non_null(value);

        STATIC_FIELDS[i].setter(lf, value, STATIC_FIELDS[i].name);

        assert_ptr_equal(*field, value);
    }

    assert_int_equal(lf->nfields, 0);
}

static void test_DecodeEvent_sibling_decoders_same_static_field_keeps_one_copy(void **state) {
    Eventinfo * lf = *state;
    static char event[] = "host=10.0.0.5 src=10.0.0.6";

    OSDecoderInfo parent = { .name = "parent" };
    OSDecoderInfo * first = create_child_decoder("host=(\\S+)", SrcIP_FP);
    OSDecoderInfo * second = create_child_decoder("src=(\\S+)", SrcIP_FP);

    /* Siblings sharing a name: every one of them is evaluated */
    first->get_next = 1;

    OSDecoderNode second_node = { .osdecoder = second };
    OSDecoderNode first_node = { .next = &second_node, .osdecoder = first };
    OSDecoderNode parent_node = { .child = &first_node, .osdecoder = &parent };

    regex_matching decoder_match;
    memset(&decoder_match, 0, sizeof(decoder_match));

    lf->log = event;

    tracking = 1;
    DecodeEvent(lf, NULL, &decoder_match, &parent_node);
    tracking = 0;

    /* The last sibling wins */
    assert_non_null(lf->srcip);
    assert_string_equal(lf->srcip, "10.0.0.6");
    assert_int_equal(lf->nfields, 0);

    /* One capture allocated per sibling */
    assert_int_equal(tracked_count, 2);
    /* Only the surviving srcip must still be held */
    assert_int_equal(pending(), 1);

    OSRegex_free_regex_matching(&decoder_match);
    free_child_decoder(first);
    free_child_decoder(second);
}

static void test_DecodeEvent_sibling_decoders_different_static_fields_keeps_every_value(void **state) {
    Eventinfo * lf = *state;
    static char event[] = "host=10.0.0.5 user=root";

    OSDecoderInfo parent = { .name = "parent" };
    OSDecoderInfo * first = create_child_decoder("host=(\\S+)", SrcIP_FP);
    OSDecoderInfo * second = create_child_decoder("user=(\\S+)", DstUser_FP);

    first->get_next = 1;

    OSDecoderNode second_node = { .osdecoder = second };
    OSDecoderNode first_node = { .next = &second_node, .osdecoder = first };
    OSDecoderNode parent_node = { .child = &first_node, .osdecoder = &parent };

    regex_matching decoder_match;
    memset(&decoder_match, 0, sizeof(decoder_match));

    lf->log = event;

    tracking = 1;
    DecodeEvent(lf, NULL, &decoder_match, &parent_node);
    tracking = 0;

    assert_string_equal(lf->srcip, "10.0.0.5");
    assert_string_equal(lf->dstuser, "root");

    assert_int_equal(tracked_count, 2);
    /* Both captures are held by the event */
    assert_int_equal(pending(), 2);

    OSRegex_free_regex_matching(&decoder_match);
    free_child_decoder(first);
    free_child_decoder(second);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_static_field_setter_first_value, setup_event, teardown_event),
        cmocka_unit_test_setup_teardown(test_static_field_setter_releases_previous, setup_event, teardown_event),
        cmocka_unit_test_setup_teardown(test_DecodeEvent_sibling_decoders_same_static_field_keeps_one_copy, setup_event, teardown_event),
        cmocka_unit_test_setup_teardown(test_DecodeEvent_sibling_decoders_different_static_fields_keeps_every_value, setup_event, teardown_event),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
