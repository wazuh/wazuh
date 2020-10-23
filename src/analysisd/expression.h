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

typedef struct {

   pcre2_code * code;
   char * raw_pattern;

} _w_pcre2_code;

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
        _w_pcre2_code * pcre2;
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
 * @return true on match. false otherwise
 */
bool w_expression_test(w_expression_t * expression, const char * str_test);

/**
 * @brief Execute a compiled pattern to string (only OSRegex & PCRE2)
 * @param expression expression with compiled pattern
 * @param str_test string to test
 * @param regex_match Structure to manage pattern matches
 * @return Returns end of matched str on success. NULL otherwise
 */
const char * w_expression_execute(w_expression_t * expression, const char * str_test, regex_matching * regex_match);

/**
 * @brief Fill a match_data with PCRE2 result
 * @param rc number of matches of PCRE2 execute
 * @param str_test string to test
 * @param match_data PCRE2 block data
 * @param regex_match to fill 
 */
void w_expression_PCRE2_fill_regex_match(int rc, const char * str_test, pcre2_match_data * match_data,
                                         regex_matching * regex_match);

/**
 * @brief Get regex pattern of the expression
 * @param expression expression with compiled pattern
 * @return Returns a copy of the raw regex pattern
 */
char * w_expression_get_regex_pattern(w_expression_t * expression);

/**
 * @brief Get regex type of the expression (string format)
 * @param expression expression with compiled pattern
 * @return Returns type of the expression
 */
char * w_expression_get_regex_type(w_expression_t * expression);

#endif
