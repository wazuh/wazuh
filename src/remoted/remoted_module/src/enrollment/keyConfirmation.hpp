/*
 * Wazuh remoted module - keystore confirmation wiring for /enroll
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <memory>
#include <string>

#include "auth/keystore.hpp"
#include "enrollment/enrollmentEndpoint.hpp"

namespace remoted::enrollment
{
    /**
     * @brief The KeyConfirmFn the facade hands /enroll, decided by the node's role.
     *
     * Master: Keystore::confirm() on the issued credential -- authd held its answer until client.keys
     * carried the entry, so one reload of this node's table is what is left to close before the 200.
     * Worker: none. A worker's file arrives with the cluster synchronization, seconds later; a reload
     * now would only ever find the key missing and warn for every enrollment.
     *
     * The keystore is captured strongly on purpose: the facade resets the HTTP server (and with it every
     * route) before the keystore in stop(), so this only extends the keystore's life until the routes
     * are gone.
     */
    inline KeyConfirmFn keyConfirmationFor(bool workerNode, std::shared_ptr<remoted::auth::Keystore> keystore)
    {
        if (workerNode || !keystore)
        {
            return {};
        }
        return [keystore = std::move(keystore)](const std::string& id, const std::string& keyHex)
        {
            return keystore->confirm(id, keyHex);
        };
    }
} // namespace remoted::enrollment
