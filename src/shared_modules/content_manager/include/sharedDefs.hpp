/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SHARED_DEFS_H
#define _SHARED_DEFS_H

#include "conditionSync.hpp"
#include <atomic>
#include <functional>
#include <string>

#define WM_CONTENTUPDATER "wazuh-modulesd:content-updater"

#include "loggerHelper.h"

using FileProcessingResult = std::tuple<int, std::string, bool>;
using FileProcessingCallback = std::function<FileProcessingResult(const std::string& message)>;

#endif // _SHARED_DEFS_H
