/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_UDS_HTTP_SERVER_INTERFACE_SHIM_HPP
#define _INVSYNC_UDS_HTTP_SERVER_INTERFACE_SHIM_HPP

// TRANSITIONAL SHIM -- deleted by the rename commit of the extraction PR. The transport now
// lives in shared_modules/uds_http_server; this keeps invsync::http compiling untouched until
// every reference is mechanically renamed to wazuh::uds_http.
#include <uds_http_server/IUdsHttpServer.hpp>

namespace invsync::http
{
    using namespace wazuh::uds_http;
} // namespace invsync::http

#endif // _INVSYNC_UDS_HTTP_SERVER_INTERFACE_SHIM_HPP
