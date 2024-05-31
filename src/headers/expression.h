/* Copyright (C) 2015, Wazuh Inc.
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

#include "../external/libpcre2/include/pcre2.h"
#include "../os_regex/os_regex.h"
#include "os_ip.h"

#define OSMATCH_STR  "osmatch"
#define OSREGEX_STR  "osregex"
#define PCRE2_STR    "pcre2"
#define STRING_STR   "string"

/**
 * @brief Determine the types of expression allowed
 */
typedef enum {
    EXP_TYPE_INVALID = -1,
    EXP_TYPE_OSREGEX,
    EXP_TYPE_OSMATCH,
    EXP_TYPE_STRING,
    EXP_TYPE_OSIP_ARRAY,
    EXP_TYPE_PCRE2,
} w_exp_type_t;

/**
 * @brief Store information regarding to PCRE2 regex.
 * Only for internal use in expression.c
 */
typedef struct {
   pcre2_code * code;
   char * raw_pattern;
} w_pcre2_code_t;

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
        w_pcre2_code_t * pcre2;
    };

    bool negate;            ///< Determine if the expression is afirmative or negative
} w_expression_t;


/**
 * @brief Allocate zero-initialized memory for a w_expression_t variable
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
 * @brief Call the free function w_free_expression_t with expression type reference
 * @param var variable to free
 */
void w_free_expression(w_expression_t * var);

/**
 * @brief add ip to os_ip array
 * @param ips array which save ip
 * @param ip ip to save
 * @return true on success, otherwise false
 */
bool w_expression_add_osip(w_expression_t ** var, char * ip);

/**
 * @brief Compile an expression
 * @param expression Expression to compile
 * @param pattern Regular expression pattern
 * @param flags Compilation flags (dependent on expression type)
 * @return false on error. True otherwise
 */
bool w_expression_compile(w_expression_t * expression, const char * pattern, int flags);

/**
 * @brief Test match a compiled pattern to string
 * @param expression expression with compiled pattern
 * @param str_test string to test
 * @param regex_match Structure to manage pattern matches. NULL is accepted
 * @param end_match if match, returns end of matched (Only PCRE2 & OSRegex). NULL is accepted
 * @return true if match. false otherwise
 */
bool w_expression_match(w_expression_t * expression, const char * str_test, const char ** end_match,
                        regex_matching * regex_match);

/**
 * @brief Frees regex_matching object
 * @param expression expression with compiled pattern
  * @param regex_match Structure to manage pattern matches.
 */
void w_free_expression_match(w_expression_t * expression, regex_matching **reg);

/**
 * @brief Fill a match_data with PCRE2 result
 * @param captured_groups number of matches of PCRE2 execute
 * @param str_test string to test
 * @param match_data PCRE2 block data
 * @param regex_match to fill
 */
void w_expression_PCRE2_fill_regex_match(int captured_groups, const char * str_test, pcre2_match_data * match_data,
                                         regex_matching * regex_match);

/**
 * @brief Get regex pattern of the expression
 * @param expression expression with compiled pattern
 * @return Returns raw regex pattern
 */
const char * w_expression_get_regex_pattern(w_expression_t * expression);

/**
 * @brief Get regex type of the expression (string format)
 * @param expression expression with compiled pattern
 * @return Returns type of the expression
 */
const char * w_expression_get_regex_type(w_expression_t * expression);

#endif
