/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "expression.h"


void w_calloc_expression_t(w_expression_t ** var, w_exp_type_t type) {

    os_calloc(1, sizeof(w_expression_t), *var);
    (*var)->exp_type = type;

    switch (type) {

        case EXP_TYPE_OSMATCH:
            os_calloc(1, sizeof(OSMatch), (*var)->match);
            break;

        case EXP_TYPE_OSREGEX:
            os_calloc(1, sizeof(OSRegex), (*var)->regex);
            break;
        
        default:
            break;
    }
}


bool w_expression_add_osip(w_expression_t ** var, char * ip) {

    unsigned int ip_s = 0;

    if((*var) == NULL) {
        w_calloc_expression_t(var, EXP_TYPE_OSIP_ARRAY);
    }

    while ((*var)->ips && (*var)->ips[ip_s]) {
        ip_s++;
    }

    os_realloc((*var)->ips, (ip_s + 2) * sizeof(os_ip *), (*var)->ips);
    os_calloc(1, sizeof(os_ip), (*var)->ips[ip_s]);
    (*var)->ips[ip_s + 1] = NULL;

    if (!OS_IsValidIP(ip, (*var)->ips[ip_s])) {

        for(int i = 0; (*var)->ips[i]; i++) {
            os_free((*var)->ips[i]->ip);
            os_free((*var)->ips[i]);
        }

        os_free((*var)->ips);
        os_free(*var);

        return false;
    }

    return true;
}
