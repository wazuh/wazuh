/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_TESTS_FAKE_TEST_TIME_SCALE_HPP
#define _INDEXER_CLIENT_TESTS_FAKE_TEST_TIME_SCALE_HPP

// The single time scale of the module's suites: every time bound of a test («< 1 s», a wait, an
// observation window) goes through scaled(), which multiplies it by INDEXER_CLIENT_TEST_TIME_SCALE (an integer 1-20,
// 1 when unset or empty) and by 3 under TSAN. The CI sets the variable per job (coverage, ASAN, TSAN); a value that is
// not an integer in range aborts the run instead of silently testing with 1. The environment is read on the first
// call, never during static initialization, so --gtest_list_tests and death tests that set it in the child work.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <optional>

#if defined(__SANITIZE_THREAD__)
#define INDEXER_CLIENT_TEST_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define INDEXER_CLIENT_TEST_TSAN 1
#else
#define INDEXER_CLIENT_TEST_TSAN 0
#endif
#else
#define INDEXER_CLIENT_TEST_TSAN 0
#endif

namespace indexer_client::testing
{
    constexpr const char* TIME_SCALE_ENV = "INDEXER_CLIENT_TEST_TIME_SCALE";
    constexpr int TIME_SCALE_MAX = 20;
    constexpr int SANITIZER_TIME_SCALE = INDEXER_CLIENT_TEST_TSAN ? 3 : 1;

    /// The value of INDEXER_CLIENT_TEST_TIME_SCALE: null or empty ⇒ 1; a decimal integer 1-20 ⇒ that integer;
    /// anything else (0, signs, spaces, trailing characters, out of range) ⇒ nullopt.
    inline std::optional<int> parseTimeScale(const char* value)
    {
        if (value == nullptr || *value == '\0')
        {
            return 1;
        }
        int parsed = 0;
        for (const char* c = value; *c != '\0'; ++c)
        {
            if (*c < '0' || *c > '9')
            {
                return std::nullopt;
            }
            parsed = parsed * 10 + (*c - '0');
            if (parsed > TIME_SCALE_MAX)
            {
                return std::nullopt;
            }
        }
        if (parsed < 1)
        {
            return std::nullopt;
        }
        return parsed;
    }

    /// The effective scale: the environment's (read once, on the first call) times SANITIZER_TIME_SCALE. An invalid
    /// value prints the reason and aborts.
    inline int timeScale()
    {
        static const int scale = []
        {
            const char* raw = std::getenv(TIME_SCALE_ENV);
            const auto parsed = parseTimeScale(raw);
            if (!parsed)
            {
                std::fprintf(stderr, "%s=\"%s\" is not an integer in 1-%d\n", TIME_SCALE_ENV, raw, TIME_SCALE_MAX);
                std::abort();
            }
            return *parsed * SANITIZER_TIME_SCALE;
        }();
        return scale;
    }

    /// A time bound of a test, multiplied by timeScale().
    inline std::chrono::milliseconds scaled(std::chrono::milliseconds bound)
    {
        return bound * timeScale();
    }
} // namespace indexer_client::testing

#endif // _INDEXER_CLIENT_TESTS_FAKE_TEST_TIME_SCALE_HPP
