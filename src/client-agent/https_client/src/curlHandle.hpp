/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CURL_HANDLE_HPP
#define _HC_CURL_HANDLE_HPP

#include "iCurlHandle.hpp"

/// Factory for the real libcurl-backed handle (one easy handle per request;
/// handles are never shared across threads). The concrete class lives in
/// curlHandle.cpp, the only translation unit including <curl/curl.h>.
CurlHandleFactory defaultCurlHandleFactory();

#endif // _HC_CURL_HANDLE_HPP
