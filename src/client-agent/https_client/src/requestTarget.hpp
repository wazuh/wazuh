/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_REQUEST_TARGET_HPP
#define _HC_REQUEST_TARGET_HPP

#include <string>

/// #38492/#38491: joins the configured reverse-proxy path segment (already
/// normalized -- no leading/trailing '/', e.g. "wazuh-manager") with a bare
/// endpoint target (e.g. "/stateless") into "/wazuh-manager/stateless".
/// Returns target unchanged when endpoint is empty.
///
/// Purely a routing matter: the result is what gets appended to
/// ModuleConfig::baseUrl() for the wire URL, and the manager routes on it.
/// It takes no part in authentication -- the `wazuh-agent+jwt` bearer binds
/// the agent's identity, not the target -- so a prefix mismatch with the
/// manager surfaces as 404 (route not found), never as 401.
std::string prefixedTarget(const std::string& endpoint, const std::string& target);

#endif // _HC_REQUEST_TARGET_HPP
