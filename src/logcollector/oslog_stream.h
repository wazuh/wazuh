/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OSLOG_STREAM_H
#define OSLOG_STREAM_H

#include "shared.h"
#include "config/localfile-config.h"

/**
 * @brief Creates the environment for collecting logs on MacOS Systems
 * @param oslog_array logreader structure with "log stream"'s input arguments and w_oslog_config_t structure to be set
 */
void w_logcollector_create_oslog_env(logreader * current);

#endif /* OSLOGSTREAM_H */
