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

#ifndef _INDEXER_CLIENT_MOCK_INDEXER_CLIENT_HPP
#define _INDEXER_CLIENT_MOCK_INDEXER_CLIENT_HPP

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <gmock/gmock.h>

#include "indexer_client/client.hpp"

namespace indexer_client
{
    class MockWriter : public IWriter
    {
    public:
        MOCK_METHOD(Submit, submit, (Op op, Callback cb), (override));
        MOCK_METHOD(Group, group, (), (override));
        MOCK_METHOD(CancelTicket, cancel, (std::string_view tag), (override));
    };

    class MockQuery : public IQuery
    {
    public:
        MOCK_METHOD(
            Outcome<nlohmann::json>,
            search,
            (std::string_view index, const nlohmann::json& body, const QueryOptions& options, Deadline deadline),
            (override));
        MOCK_METHOD(Outcome<Unit>,
                    searchAfter,
                    (std::string_view index,
                     nlohmann::json body,
                     (std::function<bool(const nlohmann::json&)> page),
                     const QueryOptions& options,
                     Deadline deadline),
                    (override));
        MOCK_METHOD(
            Outcome<Pit>,
            pit,
            (std::vector<std::string> indices, PitOptions pitOptions, const QueryOptions& options, Deadline deadline),
            (override));
        MOCK_METHOD(Outcome<nlohmann::json>,
                    deleteByQuery,
                    (std::vector<std::string> indices,
                     const nlohmann::json& query,
                     DbqOptions dbqOptions,
                     const QueryOptions& options,
                     Deadline deadline),
                    (override));
        MOCK_METHOD(Outcome<nlohmann::json>,
                    updateByQuery,
                    (std::vector<std::string> indices,
                     const nlohmann::json& query,
                     const QueryOptions& options,
                     Deadline deadline),
                    (override));
        MOCK_METHOD(Outcome<bool>,
                    indexExists,
                    (std::string_view index, const QueryOptions& options, Deadline deadline),
                    (override));
    };

    class MockClient : public IClient
    {
    public:
        MOCK_METHOD(std::shared_ptr<IWriter>, writer, (std::string_view bucket), (override));
        MOCK_METHOD(std::shared_ptr<IQuery>, query, (), (override));
        MOCK_METHOD(HealthView, health, (), (const, override));
        MOCK_METHOD(void, requestClose, (), (override));
        MOCK_METHOD(Outcome<CloseReport>, awaitClosed, (Deadline deadline), (override));
        MOCK_METHOD(ClientMetrics, metrics, (), (const, override));
    };
} // namespace indexer_client

#endif // _INDEXER_CLIENT_MOCK_INDEXER_CLIENT_HPP
