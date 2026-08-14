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
#include "validate_op_wrappers.h"

int __wrap_getDefine_Int(__attribute__((unused)) const char *high_name,
                         __attribute__((unused)) const char *low_name,
                         __attribute__((unused)) int min,
                         __attribute__((unused)) int max) {
    // For SCA
    if (!strcmp(low_name, "commands_timeout")) {
        return 300;
    }

    return mock();
}

int __wrap_getDefine_Int_default(__attribute__((unused)) const char *high_name,
                                 const char *low_name,
                                 int min,
                                 int max,
                                 int default_val) {
    // For SCA
    if (!strcmp(low_name, "commands_timeout")) {
        return 300;
    }

    // Some options need tests to assert the exact min/max/default arguments
    // passed in, since clamp/reject behavior lives in the real (unmocked)
    // getDefine_Int_default, not in this wrapper.
    if (!strcmp(low_name, "legacy_task_polling_interval")) {
        check_expected(min);
        check_expected(max);
        check_expected(default_val);
    }

    return mock();
}

int __wrap_OS_IsValidIP(const char *ip_address, os_ip *final_ip) {
    check_expected(ip_address);
    check_expected(final_ip);

    int ret = mock();
    if(ret < 0){
        ret *= (-1);
        os_strdup(ip_address, final_ip->ip);
        if (ret == 2) {
            os_calloc(1, sizeof(os_ipv4), final_ip->ipv4);
            ret = 1;
        }
    }

    return ret;
}

int __wrap_OS_GetIPv4FromIPv6(char *ip_address, size_t size) {
    check_expected(ip_address);
    check_expected(size);
    return mock();
}

int __wrap_OS_ExpandIPv6(char *ip_address, size_t size) {
    check_expected(ip_address);
    check_expected(size);
    return mock();
}

int __wrap_OS_CIDRtoStr(const os_ip *ip, char *string, size_t size) {
    check_expected(ip);
    check_expected(size);

    char *str = mock_type(char *);
    if (str != NULL) {
        snprintf(string, size, "%s", str);
    }

    return mock();
}
