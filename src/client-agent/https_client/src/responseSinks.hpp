/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_RESPONSE_SINKS_HPP
#define _HC_RESPONSE_SINKS_HPP

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

/*
 * Where a response body goes, with the byte cap each sink enforces. Both write functions have
 * libcurl's CURLOPT_WRITEFUNCTION shape and take their sink as userData; a short count
 * aborts the transfer. curl's own CURLOPT_MAXFILESIZE_LARGE (curlHandle.cpp) is set to the same
 * cap and, since 8.20, runs first with the same rule, so these checks are the backstop.
 */

/// In-memory response sink with an optional byte cap; lives on the CurlHandle for the duration
/// of the transfer.
struct BodySink
{
    std::string* body {nullptr};
    uint64_t max {0}; // 0 = unlimited.
};

/// Appends to the BodySink, or returns 0 when the piece would take it past its max.
size_t writeToBodySink(char* data, size_t size, size_t nmemb, void* userData);

/// File response sink with an optional byte cap; lives on the CurlHandle for the duration of
/// the transfer.
struct FileSink
{
    std::FILE* file {nullptr};
    uint64_t written {0};
    uint64_t max {0}; // 0 = unlimited.
};

/// Writes to the FileSink, or returns 0 when the piece would take it past its max.
size_t writeToFileSink(char* data, size_t size, size_t nmemb, void* userData);

#endif // _HC_RESPONSE_SINKS_HPP
