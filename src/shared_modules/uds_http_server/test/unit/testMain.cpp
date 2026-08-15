/*
 * Wazuh shared UDS HTTP server library - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "testLogRecorder.hpp"

#include "loggerHelper.h"

#include <gtest/gtest.h>

namespace Log
{
    // Storage for the `extern` declared in loggerHelper.h. Every DSO that pulls in that header
    // needs its own definition -- it is deliberately not `inline`, so GLOBAL_LOG_FUNCTION stays
    // private per-DSO. This test binary links the library as a static archive, so the archive's
    // LOGFN_* calls resolve into THIS definition.
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
} // namespace Log

int main(int argc, char** argv)
{
    // Point the sink at the shared recorder BEFORE any test constructs a server: log observation
    // is direct here, with none of the module-bootstrap machinery the .so-linked suites need.
    Log::GLOBAL_LOG_FUNCTION = [](const int level,
                                  const char* tag,
                                  const char* file,
                                  const int line,
                                  const char* func,
                                  const char* msg,
                                  va_list args)
    {
        wazuh::uds_http::test::testLogCallback(level, tag, file, line, func, msg, args);
    };

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
