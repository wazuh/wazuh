/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "shared_download_wrappers.h"

remote_files_group * __wrap_w_parser_get_group(const char * name) {
    check_expected(name);
    return mock_type(remote_files_group *);
}
