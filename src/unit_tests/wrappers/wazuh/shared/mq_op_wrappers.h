/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef MQ_OP_WRAPPERS_H
#define MQ_OP_WRAPPERS_H
#include <stdbool.h>

int __wrap_SendMSG(int queue, const char *message, const char *locmsg, char loc);

int __wrap_StartMQ(const char *path, short int type, short int n_attempts);

/**
 * @brief This function loads the expect and will_return calls for the function StartMQ
 */
void expect_StartMQ_call(const char *qpath, int type, int ret);

/**
 * @brief This function loads the expect and will_return calls for the function SendMSG
 */
void expect_SendMSG_call(const char *message, const char *locmsg, char loc, int ret);

int __wrap_SendMSGPredicated(int queue, const char *message, const char *locmsg, char loc, bool (*fn_ptr)());

/**
 * @brief This function loads the expect and will_return calls for the function SendMSGPredicated
 */
void expect_SendMSGPredicated_call(const char *message, const char *locmsg, char loc, bool (*fn_ptr)(), int ret);

#endif
