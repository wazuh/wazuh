/*
 * Wazuh content manager - Component Tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include <cstdarg>
#include <functional>

namespace Log
{
    /**
     * @brief This binary's own copy of the module-wide log sink.
     *
     * `loggerHelper.h` declares `GLOBAL_LOG_FUNCTION` `extern` inside a
     * `#pragma GCC visibility push(hidden)` block, deliberately: each DSO must keep its own, or the
     * dynamic linker interposes the inline functions that read it across shared objects and one
     * DSO ends up executing another's copy against an unset global.
     *
     * The consequence for a test executable is that linking `content_manager.so` does NOT supply
     * the symbol — the library's definition is hidden inside it — so any translation unit here that
     * emits an inline logging helper needs this definition to link. That is not hypothetical: this
     * suite includes `contentModuleFacade.hpp` and `components/consumerGate.hpp`, both of which log.
     *
     * Left unset on purpose. `Log::isLevelEnabled` short-circuits on a null function, so the tests
     * run silently instead of needing a sink; a test that wants output calls
     * `Log::assignLogFunction` itself.
     */
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
}; // namespace Log

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
