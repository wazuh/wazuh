/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

/* Internal options default values */
#define LOGTEST_THREAD                  1
#define LOGTEST_LIMIT_THREAD            128
#define LOGTEST_MAX_SESSIONS            64
#define LOGTEST_LIMIT_MAX_SESSIONS      500
#define LOGTEST_SESSION_TIMEOUT         900
#define LOGTEST_LIMIT_SESSION_TIMEOUT   31536000

/**
 * @brief Struct to save the wazuh-logtest internal configuration
 */
typedef struct w_logtest_conf_t {

    bool enabled;
    int threads;
    int max_sessions;
    long int session_timeout;

} w_logtest_conf_t;

/**
 * @brief Global variable to save the configuration
 */
extern w_logtest_conf_t w_logtest_conf;


/**
 * @brief Return the rule_test configuration on demand
 * @return Configuration in JSON format
 */
cJSON *getRuleTestConfig();
