/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "expression.h"

#ifdef WAZUH_UNIT_TESTING
#include "unit_tests/wrappers/externals/pcre2/pcre2_wrappers.h"
#else
#define w_pcre2_match_data_create_from_pattern pcre2_match_data_create_from_pattern
#define w_pcre2_match                          pcre2_match
#define w_pcre2_match_data_free                pcre2_match_data_free
#define w_pcre2_get_ovector_pointer            pcre2_get_ovector_pointer
#endif

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

        case EXP_TYPE_PCRE2:
            os_calloc(1, sizeof(w_pcre2_code_t), (*var)->pcre2);
            break;

        default:
            break;
    }
}

void w_free_expression_t(w_expression_t ** var) {

    if (var == NULL || *var == NULL) {
        return;
    }

    switch ((*var)->exp_type) {

        case EXP_TYPE_OSMATCH:
            OSMatch_FreePattern((*var)->match);
            os_free((*var)->match);
            break;

        case EXP_TYPE_OSREGEX:
            OSRegex_FreePattern((*var)->regex);
            os_free((*var)->regex);
            break;

        case EXP_TYPE_PCRE2:
            pcre2_code_free((*var)->pcre2->code);
            os_free((*var)->pcre2->raw_pattern);
            os_free((*var)->pcre2);
            break;

        case EXP_TYPE_STRING:
            os_free((*var)->string);
            break;

        case EXP_TYPE_OSIP_ARRAY:

            if ((*var)->ips == NULL) {
                break;
            }

            for (int i = 0; (*var)->ips[i]; i++) {
                w_free_os_ip((*var)->ips[i]);
            }
            os_free((*var)->ips);
            break;

        default:
            break;
    }
    os_free(*var);
}

void w_free_expression(w_expression_t * var) {
    w_free_expression_t(&var);
}

void w_free_expression_match(w_expression_t * expression, regex_matching **reg){
    if (expression == NULL) {
        return;
    }

    switch (expression->exp_type) {
         case EXP_TYPE_OSMATCH:
            OSRegex_free_regex_matching(*reg);
            os_free(*reg);
            break;

        case EXP_TYPE_OSREGEX:
            OSRegex_free_regex_matching(*reg);
            os_free(*reg);
            break;

        case EXP_TYPE_PCRE2:
            OSRegex_free_regex_matching(*reg);
            os_free(*reg);
            break;

        case EXP_TYPE_STRING:
            break;

        case EXP_TYPE_OSIP_ARRAY:
            break;

        default:
            break;
    }
}

bool w_expression_add_osip(w_expression_t ** var, char * ip) {

    unsigned int ip_s = 0;

    if ((*var) == NULL) {
        w_calloc_expression_t(var, EXP_TYPE_OSIP_ARRAY);
    }

    while ((*var)->ips && (*var)->ips[ip_s]) {
        ip_s++;
    }

    os_realloc((*var)->ips, (ip_s + 2) * sizeof(os_ip *), (*var)->ips);
    os_calloc(1, sizeof(os_ip), (*var)->ips[ip_s]);
    (*var)->ips[ip_s + 1] = NULL;

    if (!OS_IsValidIP(ip, (*var)->ips[ip_s])) {
        w_free_expression_t(var);
        return false;
    }

    return true;
}

bool w_expression_compile(w_expression_t * expression, const char * pattern, int flags) {

    bool retval = true;

    int errornumber = 0;
    PCRE2_SIZE erroroffset = 0;

    switch (expression->exp_type) {

        case EXP_TYPE_OSMATCH:
            if (!OSMatch_Compile(pattern, expression->match, flags)) {
                retval = false;
            }
            break;

        case EXP_TYPE_OSREGEX:
            if (!OSRegex_Compile(pattern, expression->regex, flags)) {
                retval = false;
            }
            break;

        case EXP_TYPE_PCRE2:
            expression->pcre2->code = pcre2_compile((PCRE2_SPTR) pattern, PCRE2_ZERO_TERMINATED,
                                               0, &errornumber, &erroroffset, NULL);
            os_strdup(pattern, expression->pcre2->raw_pattern);

            if (!expression->pcre2->code) {
                retval = false;
            }

            break;

        case EXP_TYPE_STRING:
            os_strdup(pattern, expression->string);
            break;

        default:
            break;
    }

    return retval;
}

bool w_expression_match(w_expression_t * expression, const char * str_test, const char ** end_match,
                        regex_matching * regex_match) {

    bool retval = false;
    const char * ret_match = NULL;

    regex_matching status_match = { .sub_strings = NULL };
    pcre2_match_data * match_data = NULL;
    PCRE2_SIZE * ovector = NULL;
    int captured_groups = 0;

    if (expression == NULL || str_test == NULL) {
        return retval;
    }

    switch (expression->exp_type) {

        case EXP_TYPE_OSMATCH:
            retval = (OSMatch_Execute(str_test, strlen(str_test), expression->match)) ? true : false;
            break;

        case EXP_TYPE_OSREGEX:
            if (regex_match == NULL) {
                regex_match = &status_match;
            }

            if (ret_match = OSRegex_Execute_ex(str_test, expression->regex, regex_match), ret_match) {
                retval = true;
            }

            if (status_match.sub_strings != NULL) {
                OSRegex_free_regex_matching(&status_match);
            }
            break;

        case EXP_TYPE_PCRE2:

            if (match_data = w_pcre2_match_data_create_from_pattern(expression->pcre2->code, NULL), !match_data) {
                break;
            }
            captured_groups = w_pcre2_match(expression->pcre2->code, (PCRE2_SPTR) str_test,
                                          strlen(str_test), 0, 0, match_data, NULL);

            /* successful match */
            if (captured_groups > 0) {
                retval = true;
                ovector = w_pcre2_get_ovector_pointer(match_data);
                ret_match = str_test + ovector[1] - 1;

                if (regex_match) {
                    w_expression_PCRE2_fill_regex_match(captured_groups, str_test, match_data, regex_match);
                }
            }
            w_pcre2_match_data_free(match_data);
            break;

        case EXP_TYPE_STRING:
            retval = (strcmp(expression->string, str_test) != 0) ? false : true;
            break;

        case EXP_TYPE_OSIP_ARRAY:
            retval = OS_IPFoundList(str_test, expression->ips) ? true: false;
            break;

        default:
            break;
    }

    if (end_match && ret_match) {
        *end_match = ret_match;
    }

    return retval;
}

void w_expression_PCRE2_fill_regex_match(int captured_groups, const char * str_test, pcre2_match_data * match_data,
                                         regex_matching * regex_match) {

    PCRE2_SIZE * ovector;
    char *** sub_strings;
    regex_dynamic_size * str_sizes;

    /* Check if captured at least one group besides matching */
    if (captured_groups < 2 || !str_test || !match_data || !regex_match) {
        return;
    }

    sub_strings = &regex_match->sub_strings;
    str_sizes = &regex_match->d_size;

    w_FreeArray(*sub_strings);
    os_realloc(*sub_strings, sizeof(char *) * captured_groups, *sub_strings);
    memset((void *) *sub_strings, 0, sizeof(char *) * captured_groups);
    str_sizes->sub_strings_size = sizeof(char *) * captured_groups;

    ovector = w_pcre2_get_ovector_pointer(match_data);
    for (int i = 1; i < captured_groups; i++) {
        size_t substring_length = ovector[2 * i + 1] - ovector[2 * i];
        regex_match->sub_strings[i - 1] = w_strndup(str_test + ovector[2 * i], substring_length);
    }
    regex_match->sub_strings[captured_groups - 1] = NULL;
}

const char * w_expression_get_regex_pattern(w_expression_t * expression) {

    const char * retval = NULL;

    if (!expression) {
        return retval;
    }

    switch (expression->exp_type) {

        case EXP_TYPE_OSREGEX:
            retval = expression->regex->raw;
            break;

        case EXP_TYPE_OSMATCH:
            retval = expression->match->raw;
            break;

        case EXP_TYPE_PCRE2:
            retval = expression->pcre2->raw_pattern;
            break;

        case EXP_TYPE_STRING:
            retval = expression->string;
            break;

        default:
            break;
    }

    return retval;
}

const char * w_expression_get_regex_type(w_expression_t * expression) {

    const char * retval = NULL;

    if (!expression) {
        return retval;
    }

    switch (expression->exp_type) {

        case EXP_TYPE_OSMATCH:
            retval = OSMATCH_STR;
            break;

        case EXP_TYPE_OSREGEX:
            retval = OSREGEX_STR;
            break;

        case EXP_TYPE_PCRE2:
            retval = PCRE2_STR;
            break;

        case EXP_TYPE_STRING:
            retval = STRING_STR;
            break;

        default:
            break;
    }

    return retval;
}
