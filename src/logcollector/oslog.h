/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OSLOG_H
#define OSLOG_H

/* ******************  INCLUDES  ****************** */

#include "shared.h"
#include "config/localfile-config.h"

/* ******************  DEFINES  ****************** */

///< macOS ULS milliseconds lenght i.e .123456
#define OS_LOGCOLLECTOR_TIMESTAMP_MS_LEN        7
///< macOS ULS timezone lenght i.e -0700
#define OS_LOGCOLLECTOR_TIMESTAMP_TZ_LEN        5
///< macOS ULS basic timestamp lenght i.e 2021-04-27 08:07:20
#define OS_LOGCOLLECTOR_BASIC_TIMESTAMP_LEN     19
///< macOS ULS short timestamp lenght i.e 2021-04-27 08:07:20-0700
#define OS_LOGCOLLECTOR_SHORT_TIMESTAMP_LEN     OS_LOGCOLLECTOR_BASIC_TIMESTAMP_LEN + OS_LOGCOLLECTOR_TIMESTAMP_TZ_LEN
///< macOS ULS full timestamp lenght i.e 2020-11-09 05:45:08.000000-0800
#define OS_LOGCOLLECTOR_FULL_TIMESTAMP_LEN      OS_LOGCOLLECTOR_SHORT_TIMESTAMP_LEN + OS_LOGCOLLECTOR_TIMESTAMP_MS_LEN

/* ******************  DATATYPES  ****************** */

typedef struct {
    pthread_mutex_t mutex;
    char timestamp[OS_LOGCOLLECTOR_SHORT_TIMESTAMP_LEN + 1];
} oslog_status_t;

/* ******************  PROTOTYPES  ****************** */

/**
 * @brief Creates the environment for collecting logs on MacOS Systems
 * @param oslog_array logreader structure with `log`'s input arguments and w_oslog_config_t structure to be set
 */
void w_oslog_create_env(logreader * current);


#endif /* OSLOGSTREAM_H */
