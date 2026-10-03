/*
 * Wazuh indexer client
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "indexer_client/client.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <utility>

#include "indexer_client/runtime.hpp"
#include "runtime/runtimeInternal.hpp"

namespace indexer_client
{
    namespace
    {
        constexpr const char* E1_UNAVAILABLE = "data path not implemented yet (E3b/E4)";

        class StubWriter final : public IWriter
        {
        public:
            StubWriter(std::shared_ptr<detail::ClientState> client, std::string bucket)
                : m_client(std::move(client))
                , m_bucket(std::move(bucket))
            {
            }

            Submit submit(Op /*op*/, Callback /*cb*/) override
            {
                Submit result;
                result.accepted = false;
                result.cause = Cause::Unavailable;
                return result;
            }

            Group group() override
            {
                return Group(std::make_shared<detail::GroupState>());
            }

            CancelTicket cancel(std::string_view /*tag*/) override
            {
                auto state = std::make_shared<detail::CancelState>();
                state->complete(Outcome<Unit>::failure(Cause::Unavailable, E1_UNAVAILABLE));
                return CancelTicket(std::move(state));
            }

        private:
            std::shared_ptr<detail::ClientState> m_client;
            std::string m_bucket;
        };

        class StubQuery final : public IQuery
        {
        public:
            explicit StubQuery(std::shared_ptr<detail::ClientState> client)
                : m_client(std::move(client))
            {
            }

            Outcome<nlohmann::json> search(std::string_view /*index*/,
                                           const nlohmann::json& /*body*/,
                                           const QueryOptions& /*options*/,
                                           Deadline /*deadline*/) override
            {
                return Outcome<nlohmann::json>::failure(Cause::Unavailable, E1_UNAVAILABLE);
            }

            Outcome<Unit> searchAfter(std::string_view /*index*/,
                                      nlohmann::json /*body*/,
                                      std::function<bool(const nlohmann::json&)> /*page*/,
                                      const QueryOptions& /*options*/,
                                      Deadline /*deadline*/) override
            {
                return Outcome<Unit>::failure(Cause::Unavailable, E1_UNAVAILABLE);
            }

            Outcome<Pit> pit(std::vector<std::string> /*indices*/,
                             PitOptions /*pitOptions*/,
                             const QueryOptions& /*options*/,
                             Deadline /*deadline*/) override
            {
                return Outcome<Pit>::failure(Cause::Unavailable, E1_UNAVAILABLE);
            }

            Outcome<nlohmann::json> deleteByQuery(std::vector<std::string> /*indices*/,
                                                  const nlohmann::json& /*query*/,
                                                  DbqOptions /*dbqOptions*/,
                                                  const QueryOptions& /*options*/,
                                                  Deadline /*deadline*/) override
            {
                return Outcome<nlohmann::json>::failure(Cause::Unavailable, E1_UNAVAILABLE);
            }

            Outcome<nlohmann::json> updateByQuery(std::vector<std::string> /*indices*/,
                                                  const nlohmann::json& /*query*/,
                                                  const QueryOptions& /*options*/,
                                                  Deadline /*deadline*/) override
            {
                return Outcome<nlohmann::json>::failure(Cause::Unavailable, E1_UNAVAILABLE);
            }

            Outcome<bool>
            indexExists(std::string_view /*index*/, const QueryOptions& /*options*/, Deadline /*deadline*/) override
            {
                return Outcome<bool>::failure(Cause::Unavailable, E1_UNAVAILABLE);
            }

        private:
            std::shared_ptr<detail::ClientState> m_client;
        };
    } // namespace

    namespace detail
    {
        std::shared_ptr<IWriter> makeStubWriter(std::shared_ptr<ClientState> client, std::string bucket)
        {
            return std::make_shared<StubWriter>(std::move(client), std::move(bucket));
        }

        std::shared_ptr<IQuery> makeStubQuery(std::shared_ptr<ClientState> client)
        {
            return std::make_shared<StubQuery>(std::move(client));
        }
    } // namespace detail

    Client::Client(std::shared_ptr<detail::ClientState> state)
        : m_state(std::move(state))
    {
    }

    Client::Client(Client&&) noexcept = default;

    Client& Client::operator=(Client&& other) noexcept
    {
        if (this != &other)
        {
            // The handle being replaced closes exactly as a destroyed one would.
            Client discarded(std::move(*this));
            m_state = std::move(other.m_state);
        }
        return *this;
    }

    Client::~Client()
    {
        if (!m_state)
        {
            return;
        }
        if (detail::testing::onRuntimeThread())
        {
            // Usage error (I37): a runtime thread must never wait for a client to drain. Logged and counted
            // (detail::testing::usageErrors()); never an abort, not even in debug builds.
            detail::countUsageError();
            std::fprintf(stderr,
                         "indexer_client: usage error: client '%s' destroyed from a runtime thread; "
                         "requesting close without waiting\n",
                         m_state->consumer.c_str());
            requestClose();
            return;
        }
        requestClose();
        const auto deadline = detail::runtimeShutdownDeadline(m_state->runtime, m_state->epoch)
                                  .value_or(std::chrono::steady_clock::now() + m_state->drain);
        awaitClosed(deadline);
    }

    std::shared_ptr<IWriter> Client::writer(std::string_view bucket)
    {
        if (!m_state || m_state->closeRequested.load())
        {
            return nullptr; // A closing client hands out no new handles (I37).
        }
        const auto found = std::find_if(m_state->buckets.cbegin(),
                                        m_state->buckets.cend(),
                                        [bucket](const BucketSpec& spec) { return spec.name == bucket; });
        if (found == m_state->buckets.cend())
        {
            return nullptr;
        }
        return detail::makeStubWriter(m_state, found->name);
    }

    std::shared_ptr<IQuery> Client::query()
    {
        if (!m_state || m_state->closeRequested.load())
        {
            return nullptr;
        }
        return detail::makeStubQuery(m_state);
    }

    HealthView Client::health() const
    {
        return {};
    }

    void Client::requestClose()
    {
        if (m_state)
        {
            m_state->closeRequested.store(true);
        }
    }

    Outcome<CloseReport> Client::awaitClosed(Deadline /*deadline*/)
    {
        if (detail::testing::onRuntimeThread())
        {
            return Outcome<CloseReport>::failure(Cause::Reentrancy, "awaitClosed() called from a runtime thread");
        }
        if (!m_state)
        {
            return Outcome<CloseReport>::failure(Cause::InvalidState, "empty client handle");
        }
        // E1 has no data path: nothing to drain. Closing frees the consumer name.
        m_state->closeRequested.store(true);
        m_state->releaseName();
        return Outcome<CloseReport>::success(CloseReport {});
    }

    bool Client::valid() const noexcept
    {
        return m_state != nullptr;
    }
} // namespace indexer_client
