/*
 * Wazuh remoted module - log sink of the unit-test executable
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// The test fakes run on the executable's own copy of the uds_http_server archive (makeUdsHttpServer() is
// local to libremoted_module.so, so the module's copy is out of reach). Every binary that embeds the archive
// must define Log::GLOBAL_LOG_FUNCTION: loggerHelper.h only declares it, with hidden visibility, so each binary
// keeps its own. Left empty on purpose: the fakes' transport diagnostics are not under test, and the module
// keeps logging through its own sink, which is what LogRecorder captures.

#include "loggerHelper.h"

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
} // namespace Log
