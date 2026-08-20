/*
 * Wazuh remoted HTTPS source-address authorization
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <string_view>

namespace remoted::auth
{

    /**
     * @brief Whether a peer is allowed by an agent's `client.keys` address column (the HTTPS
     *        equivalent of the legacy OS_IsAllowedIP).
     *
     * @param allowedSpec The column: `any` (or empty), an IP, or CIDR/netmask. Fail-closed if unparseable.
     * @param peerAddress The peer address as remoted sees it (see HttpRequest::remoteIp).
     * @return true when the peer is allowed.
     */
    bool sourceAddressAllowed(std::string_view allowedSpec, std::string_view peerAddress);

} // namespace remoted::auth
