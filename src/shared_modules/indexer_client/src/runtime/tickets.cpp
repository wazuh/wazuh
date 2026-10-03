/*
 * Wazuh indexer client
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <utility>

#include "indexer_client/client.hpp"
#include "indexer_client/runtime.hpp"
#include "runtime/runtimeInternal.hpp"

namespace indexer_client
{
    namespace
    {
        constexpr const char* E1_UNAVAILABLE = "data path not implemented yet (E3b/E4)";

        template<class T, class State>
        Outcome<T> waitOn(const std::shared_ptr<State>& state, Deadline deadline)
        {
            if (detail::testing::onRuntimeThread())
            {
                return Outcome<T>::failure(Cause::Reentrancy, "wait() called from a runtime thread");
            }
            if (!state)
            {
                return Outcome<T>::failure(Cause::InvalidState, "empty ticket");
            }
            return state->waitUntil(deadline);
        }
    } // namespace

    Ticket::Ticket(std::shared_ptr<detail::TicketState> state)
        : m_state(std::move(state))
    {
    }

    bool Ticket::ready() const
    {
        return m_state && m_state->isReady();
    }

    Outcome<OpResult> Ticket::wait(Deadline deadline) const
    {
        return waitOn<OpResult>(m_state, deadline);
    }

    GroupTicket::GroupTicket(std::shared_ptr<detail::GroupState> state)
        : m_state(std::move(state))
    {
    }

    bool GroupTicket::ready() const
    {
        return m_state && m_state->isReady();
    }

    Outcome<std::vector<OpResult>> GroupTicket::wait(Deadline deadline) const
    {
        return waitOn<std::vector<OpResult>>(m_state, deadline);
    }

    CancelTicket::CancelTicket(std::shared_ptr<detail::CancelState> state)
        : m_state(std::move(state))
    {
    }

    bool CancelTicket::ready() const
    {
        return m_state && m_state->isReady();
    }

    Outcome<Unit> CancelTicket::wait(Deadline deadline) const
    {
        return waitOn<Unit>(m_state, deadline);
    }

    Group::Group(std::shared_ptr<detail::GroupState> state)
        : m_state(std::move(state))
    {
    }

    Group::Group(Group&&) noexcept = default;
    Group& Group::operator=(Group&&) noexcept = default;
    Group::~Group() = default; // E1 reserves nothing, so abandoning a group releases nothing.

    Cause Group::add(Op /*op*/)
    {
        if (!m_state || m_state->committed.load())
        {
            return Cause::InvalidState;
        }
        return Cause::Unavailable;
    }

    GroupTicket Group::commit()
    {
        if (!m_state || m_state->committed.exchange(true))
        {
            // An empty or already committed group yields a ready ticket that reports the misuse.
            auto state = std::make_shared<detail::GroupState>();
            state->committed = true;
            state->complete(Outcome<std::vector<OpResult>>::failure(Cause::InvalidState, "group already committed"));
            return GroupTicket(std::move(state));
        }
        m_state->complete(Outcome<std::vector<OpResult>>::failure(Cause::Unavailable, E1_UNAVAILABLE));
        return GroupTicket(m_state);
    }

    PitSession::PitSession(std::shared_ptr<detail::CursorState> state)
        : m_state(std::move(state))
    {
    }

    Outcome<PitPage> PitSession::next(Deadline /*deadline*/)
    {
        if (detail::testing::onRuntimeThread())
        {
            return Outcome<PitPage>::failure(Cause::Reentrancy, "next() called from a runtime thread");
        }
        if (!m_state)
        {
            return Outcome<PitPage>::failure(Cause::InvalidState, "empty cursor");
        }
        return Outcome<PitPage>::failure(Cause::Unavailable, E1_UNAVAILABLE);
    }

    bool PitSession::exhausted() const
    {
        return !m_state || m_state->exhausted.load();
    }

    Pit::Pit(std::shared_ptr<detail::PitState> state)
        : m_state(std::move(state))
    {
    }

    PitSession Pit::cursor(CursorQuery /*query*/, std::optional<Slice> /*slice*/)
    {
        return PitSession(std::make_shared<detail::CursorState>());
    }

    Outcome<nlohmann::json> Pit::search(const nlohmann::json& /*body*/, Deadline /*deadline*/)
    {
        if (detail::testing::onRuntimeThread())
        {
            return Outcome<nlohmann::json>::failure(Cause::Reentrancy, "search() called from a runtime thread");
        }
        return Outcome<nlohmann::json>::failure(Cause::Unavailable, E1_UNAVAILABLE);
    }

    std::uint64_t Pit::generation() const
    {
        return m_state ? m_state->generation : 0;
    }
} // namespace indexer_client
