/*
 * Wazuh keystore
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _KEYSTORE_HPP
#define _KEYSTORE_HPP

#include <chrono>
#include <stdexcept>
#include <string>

/// Thrown when another handle or process kept the keystore locked for the whole wait. Nothing was
/// read or written: the operation can simply be run again.
class KeystoreLockTimeout final : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

class Keystore final
{

public:
    Keystore() = default;

    /// How long an operation waits for another handle or process to release the database lock
    /// before it gives up (throwing KeystoreLockTimeout). Daemons keep it short: they are
    /// serving requests, and their callers retry.
    static constexpr std::chrono::milliseconds DEFAULT_LOCK_WAIT {5000};

    /// The wait the wazuh-manager-keystore CLI uses. Longer than a daemon's: the CLI runs once, from
    /// an operator or a maintainer script, and a burst of daemon reads should delay it, not fail it.
    static constexpr std::chrono::milliseconds CLI_LOCK_WAIT {30000};

    /**
     * Insert or update a key-value pair in the specified column family.
     *
     * @param columnFamily The target column family.
     * @param key The key to be inserted or updated.
     * @param value The corresponding value.
     * @param lockWait How long to wait for the database lock before giving up.
     */
    static void put(const std::string& columnFamily,
                    const std::string& key,
                    const std::string& value,
                    std::chrono::milliseconds lockWait = DEFAULT_LOCK_WAIT);

    /**
     * Get the key value in the specified column family.
     *
     * @param columnFamily The target column family.
     * @param key The key to be inserted or updated.
     * @param value The corresponding value to be returned.
     * @param lockWait How long to wait for the database lock before giving up.
     */
    static void get(const std::string& columnFamily,
                    const std::string& key,
                    std::string& value,
                    std::chrono::milliseconds lockWait = DEFAULT_LOCK_WAIT);

    /**
     * Get the key value in the specified column family.
     *
     * @param columnFamily The target column family.
     * @param key The key to be inserted or updated.
     * @return The corresponding value to be returned.
     */
    static std::string get(const std::string& columnFamily, const std::string& key);
};

#endif // _KEYSTORE_HPP
