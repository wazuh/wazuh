/*
 * Wazuh shared UDS HTTP server library - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UDS_HTTP_SERVER_TEST_SANITIZERS_HPP
#define _UDS_HTTP_SERVER_TEST_SANITIZERS_HPP

namespace wazuh::uds_http::test
{
    /**
     * @brief Whether this test binary is built with AddressSanitizer.
     *
     * Its operator new reports an allocation it cannot satisfy as a fatal error instead of throwing
     * std::bad_alloc, so a test that provokes one to check the std::bad_alloc handling skips itself there.
     */
#if defined(__SANITIZE_ADDRESS__)
    constexpr bool UNDER_ADDRESS_SANITIZER {true};
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
    constexpr bool UNDER_ADDRESS_SANITIZER {true};
#else
    constexpr bool UNDER_ADDRESS_SANITIZER {false};
#endif
#else
    constexpr bool UNDER_ADDRESS_SANITIZER {false};
#endif
} // namespace wazuh::uds_http::test

#endif // _UDS_HTTP_SERVER_TEST_SANITIZERS_HPP
