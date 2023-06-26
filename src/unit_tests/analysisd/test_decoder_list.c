/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../headers/debug_op.h"
#include "../../analysisd/decoders/decoder.h"
#include "../error_messages/error_messages.h"
#include "../error_messages/debug_messages.h"
#include "../../analysisd/analysisd.h"

void os_remove_decoders_list(OSDecoderNode *decoderlist_pn, OSDecoderNode *decoderlist_npn);
void os_remove_decodernode(OSDecoderNode *node, OSDecoderInfo **decoders, int *pos, int *max_size);
void os_count_decoders(OSDecoderNode *node, int *num_decoders);

/* setup/teardown */



/* wraps */

void __wrap_FreeDecoderInfo(OSDecoderInfo *pi) {
    os_free(pi);
    return;
}

/* tests */

/* os_remove_decoders_list */
void os_count_decoders_no_child(void **state)
{
    OSDecoderNode * node;
    os_calloc(1, sizeof(OSDecoderNode), node);

    int num_decoders = 0;

    os_count_decoders(node, &num_decoders);

    os_free(node);

}

void os_count_decoders_child(void **state)
{
    OSDecoderNode * node;
    os_calloc(1, sizeof(OSDecoderNode), node);
    os_calloc(1, sizeof(OSDecoderNode), node->child);

    int num_decoders = 0;

    os_count_decoders(node, &num_decoders);

    os_free(node->child);
    os_free(node);

}

/* os_remove_decodernode */
void test_os_remove_decodernode_no_child(void **state)
{
    int pos = 0;
    int max_size = 2;

    OSDecoderNode * node;
    os_calloc(1, sizeof(OSDecoderNode), node);
    os_calloc(1, sizeof(OSDecoderInfo), node->osdecoder);
    node->osdecoder->internal_saving = false;

    OSDecoderInfo **decoders;
    os_calloc(1, sizeof(OSDecoderInfo *), decoders);

    int num_decoders = 0;

    os_remove_decodernode(node, decoders, &pos, &max_size);

    os_free(decoders[0]);
    os_free(decoders);

}

void test_os_remove_decodernode_child(void **state)
{
    int pos = 0;
    int max_size = 2;

    OSDecoderNode * node;
    os_calloc(1, sizeof(OSDecoderNode), node);
    os_calloc(1, sizeof(OSDecoderNode), node->child);
    os_calloc(1, sizeof(OSDecoderInfo), node->osdecoder);
    os_calloc(1, sizeof(OSDecoderInfo), node->child->osdecoder);
    node->osdecoder->internal_saving = false;
    node->child->osdecoder->internal_saving = false;

    OSDecoderInfo **decoders;
    os_calloc(2, sizeof(OSDecoderInfo *), decoders);

    int num_decoders = 0;

    os_remove_decodernode(node, decoders, &pos, &max_size);

    os_free(decoders[0]);
    os_free(decoders[1]);
    os_free(decoders);

}

/* os_remove_decoders_list */
void test_os_remove_decoders_list_OK(void **state)
{
    OSDecoderNode * decoderlist_pn;
    os_calloc(1, sizeof(OSDecoderNode), decoderlist_pn);
    os_calloc(1, sizeof(OSDecoderNode), decoderlist_pn->child);
    os_calloc(1, sizeof(OSDecoderInfo), decoderlist_pn->osdecoder);
    os_calloc(1, sizeof(OSDecoderInfo), decoderlist_pn->child->osdecoder);
    decoderlist_pn->osdecoder->internal_saving = false;
    decoderlist_pn->child->osdecoder->internal_saving = false;


    OSDecoderNode * decoderlist_npn;
    os_calloc(1, sizeof(OSDecoderNode), decoderlist_npn);
    os_calloc(1, sizeof(OSDecoderNode), decoderlist_npn->child);
    os_calloc(1, sizeof(OSDecoderInfo), decoderlist_npn->osdecoder);
    os_calloc(1, sizeof(OSDecoderInfo), decoderlist_npn->child->osdecoder);
    decoderlist_npn->osdecoder->internal_saving = false;
    decoderlist_npn->child->osdecoder->internal_saving = false;

    os_remove_decoders_list(decoderlist_pn, decoderlist_npn);

}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests os_count_decoders_no_child
        cmocka_unit_test(os_count_decoders_no_child),
        cmocka_unit_test(os_count_decoders_child),
        // Tests os_remove_decodernode
        cmocka_unit_test(test_os_remove_decodernode_no_child),
        cmocka_unit_test(test_os_remove_decodernode_child),
        // Tests os_remove_decoders_list
        cmocka_unit_test(test_os_remove_decoders_list_OK)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
