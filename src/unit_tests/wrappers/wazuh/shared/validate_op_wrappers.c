/* Copyright (C) Wazuh Inc.
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

int __wrap_getDefine_Int_default(const char *high_name,
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
    if (!strcmp(low_name, "legacy_task_polling_interval") ||
        (!strcmp(high_name, "remoted") && !strcmp(low_name, "rlimit_nofile"))) {
        check_expected(min);
        check_expected(max);
        check_expected(default_val);
    }

    // The vulnerability detection internal options: their tests pin which key is read with which
    // range, since that range is what `wazuh-modulesd -t` judges.
    if (!strcmp(high_name, "vulnerability-detection") ||
        (!strcmp(high_name, "wazuh_modules") &&
         (!strcmp(low_name, "indexer_bulk_size_bytes") || !strcmp(low_name, "indexer_flush_interval") ||
          !strcmp(low_name, "indexer_max_retry_attempts") ||
          !strcmp(low_name, "indexer_max_retry_duration_seconds") ||
          !strcmp(low_name, "manager_task_create_timeout")))) {
        check_expected(low_name);
        check_expected(min);
        check_expected(max);
        check_expected(default_val);
    }

    // Options a daemon used to read only after its `-t` returned (remoted's message counters, authd's
    // debug level): their tests pin which key is read with which range, on the path `-t` runs.
    if ((!strcmp(high_name, "remoted") &&
         (!strcmp(low_name, "recv_counter_flush") || !strcmp(low_name, "comp_average_printout"))) ||
        (!strcmp(high_name, "authd") && !strcmp(low_name, "debug"))) {
        check_expected(low_name);
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
        } else if (ret == 3) {
            /* -3: a parsed IPv4 host, as the real parser leaves it (full-length netmask), for callers
             * that read the netmask back (the registered form of an address). */
            os_calloc(1, sizeof(os_ipv4), final_ip->ipv4);
            final_ip->ipv4->netmask = 0xFFFFFFFF;
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
