/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTENT_TOKEN_STORE_HPP
#define _CONTENT_TOKEN_STORE_HPP

#include <string>
#include <string_view>

namespace content_manager
{

/**
 * @brief Where a topic's change-detection token is kept between cycles.
 *
 * The token is whatever the configured detector produces: a monotonic cursor in `"cursor"` mode, a
 * content hash in `"hash"` mode. The library treats it as an opaque string and only compares it for
 * equality or emptiness, so a host is free to store it wherever its own state already lives — VD
 * keeps it in the updater RocksDB, the Engine in its `store::IStore` status documents.
 *
 * Implementations are called from the cycle thread only, and must not throw: a failure to persist
 * is reported by returning false, which the library maps to `CycleStatus::FailedSink` with
 * `AbortReason::TokenPersistFailed` — the safe direction, since the content is already live and the
 * next cycle simply re-fetches.
 */
class IContentTokenStore
{
public:
    virtual ~IContentTokenStore() = default;

    /**
     * @brief Read the token in force for a topic.
     *
     * @param topic Registered topic name.
     * @return The stored token, or "" when none has been committed yet.
     */
    virtual std::string load(std::string_view topic) noexcept = 0;

    /**
     * @brief Persist a token for a topic.
     *
     * @param topic Registered topic name.
     * @param token Token to store.
     * @return True when the write reached stable storage.
     */
    virtual bool store(std::string_view topic, std::string_view token) noexcept = 0;

    /**
     * @brief Drop the token for a topic so the next cycle performs a full reload.
     *
     * @param topic Registered topic name.
     * @return True when the write reached stable storage.
     */
    virtual bool clear(std::string_view topic) noexcept = 0;
};

} // namespace content_manager

#endif // _CONTENT_TOKEN_STORE_HPP
