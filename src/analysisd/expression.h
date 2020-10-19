/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef EXPRESSION_H_
#define EXPRESSION_H_
#define PCRE2_CODE_UNIT_WIDTH 8

#include "external/libpcre2/include/pcre2.h"
#include "shared.h"


/**
 * @brief Determine the types of expression allowed
 */
typedef enum { 
    EXP_TYPE_INVALID = -1,
    EXP_TYPE_OSREGEX,
    EXP_TYPE_OSMATCH,
    EXP_TYPE_STRING,
    EXP_TYPE_OSIP_ARRAY,
    EXP_TYPE_PCRE2
} w_exp_type_t;


/**
 * @brief Represent the expressions used in rules and decoders.
 *
 * It can be OSRegex, OSMatch, string or array of os_ip.
 */
typedef struct {

    w_exp_type_t exp_type;  ///< Determine the type of expression

    union {                 ///< The expression which analysisd works
        OSRegex * regex;
        OSMatch * match;
        char * string;
        os_ip ** ips;
        pcre2_code * pcre2;
    };

    bool negate;            ///< Determine if the expression is afirmative or negative
} w_expression_t;


/**
 * @brief Alloc memory for a w_expression_t variable
 * @param var variable to initialize
 * @param type type of expression.
 */
void w_calloc_expression_t(w_expression_t ** var, w_exp_type_t type);

/**
 * @brief Frees memory for a w_expression_t variable
 * @param var variable to free
 */
void w_free_expression_t(w_expression_t ** var);

/**
 * @brief add ip to os_ip array
 * @param ips array which save ip
 * @param ip ip to save
 * @return true on success, otherwise false
 */
bool w_expression_add_osip(w_expression_t ** var, char * ip);

/**
 * @brief Compile an expression to used later
 * @param expression Expression to compile
 * @param pattern Regular expression pattern
 * @param flags Compilation flags (dependent on expression type)
 * @return false on error. True otherwise
 */
bool w_expression_compile(w_expression_t * expression, char * pattern, int flags);

/**
 * @brief Test match a compiled pattern to string
 * @param expression expression with compiled pattern
 * @param str_test string to test
 * @param str_length  Size of str_test (only valid in osmatch)
 * @return true on match. false otherwise
 */
bool w_expression_test(w_expression_t * expression, char * str_test, size_t str_length);

#endif
