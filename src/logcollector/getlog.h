/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#ifndef GETLOG_H
#define GETLOG_H

#include "shared.h"

typedef struct{
    char * buffer;
    FILE * stream;
    void * ctxt;
    int length;
} getlog_params_t;

/**
 * @brief Function pointer typedef for functions that obtenins logs from files
 * 
 */
typedef char * (*getlog_t)(getlog_params_t * params);

/**
 * @brief Get single line log
 * 
 * @param params data needed to get log
 * @return char* readed log
 */
char *getlog_singleline(getlog_params_t * params);

/**
 * @brief Get multi line log
 * 
 * @param params data needed to get log
 * @return char* readed log
 */
char *getlog_multiline(getlog_params_t * params);

#endif /* GETLOG_H */
