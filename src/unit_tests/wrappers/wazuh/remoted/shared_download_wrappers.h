/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * April 3, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef SHARED_DOWNLOAD_WRAPPERS_H
#define SHARED_DOWNLOAD_WRAPPERS_H

#include "../../remoted/shared_download.h"

remote_files_group * __wrap_w_parser_get_group(const char * name);

#endif /* SHARED_DOWNLOAD_WRAPPERS_H */
