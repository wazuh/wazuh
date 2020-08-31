/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "url_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_wurl_request(const char * url,
                        const char * dest,
                        const char *header,
                        const char *data,
                        const long timeout) {
    if (url) {
        check_expected(url);
    }

    if (dest) {
        check_expected(dest);
    }

    if (header) {
        check_expected(header);
    }

    if (data) {
        check_expected(data);
    }

    if (timeout) {
        check_expected(timeout);
    }

    return mock();
}
