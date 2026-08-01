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
#include "json.hpp"
#include <atomic>
#include <cstdint>
#include <exception>
#include <functional>
#include <string>

#define WM_CONTENTUPDATER "wazuh-manager-modulesd:content-updater"

#include "loggerHelper.h"

using FileProcessingResult = std::tuple<int, std::string, bool>;
using FileProcessingCallback = std::function<FileProcessingResult(nlohmann::json message)>;

struct ContentUpdateCallbacks
{
    std::function<void()> onStart;
    std::function<void()> onFailure;
};

inline void invokeContentUpdateCallback(const std::function<void()>& callback, const char* event) noexcept
{
    if (!callback)
    {
        return;
    }

    try
    {
        callback();
    }
    catch (const std::exception& e)
    {
        logError(WM_CONTENTUPDATER, "Content update %s callback failed: %s.", event, e.what());
    }
    catch (...)
    {
        logError(WM_CONTENTUPDATER, "Content update %s callback failed with an unknown exception.", event);
    }
}

#endif // _SHARED_DEFS_H
