/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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


#include "../../headers/shared.h"
#include "os_regex/os_regex.h"
#include "os_xml/os_xml.h"
#include "../../analysisd/analysisd.h"
#include "../../analysisd/eventinfo.h"
#include "../../analysisd/decoders/decoder.h"
#include "../../analysisd/decoders/plugin_decoders.h"
#include "../../analysisd/config.h"


void FreeDecoderInfo(OSDecoderInfo *pi);

/* setup/teardown */

/* wraps */

/* tests */

/* FreeDecoderInfo */
void test_FreeDecoderInfo_NULL(void **state)
{
    OSDecoderInfo *info = NULL;

    FreeDecoderInfo(info);

}

void test_FreeDecoderInfo_OK(void **state)
{
    OSDecoderInfo *info;
    os_calloc(1, sizeof(OSDecoderInfo), info);

    os_calloc(1, sizeof(char), info->parent);
    os_calloc(1, sizeof(char), info->name);
    os_calloc(1, sizeof(char), info->ftscomment);
    os_calloc(1, sizeof(char), info->fts_fields);
    os_calloc(1, sizeof(char*), info->fields);
    os_calloc(1, sizeof(char), info->fields[0]);

    os_calloc(1, sizeof(OSRegex), info->regex);
    os_calloc(1, sizeof(OSRegex), info->prematch);
    os_calloc(1, sizeof(OSRegex), info->program_name);

    os_calloc(1, sizeof(void*), info->order);

    Config.decoder_order_size = 1;

    FreeDecoderInfo(info);
    
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests FreeDecoderInfo
        cmocka_unit_test(test_FreeDecoderInfo_NULL),
        cmocka_unit_test(test_FreeDecoderInfo_OK)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
