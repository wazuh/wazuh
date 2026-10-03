/*
 * Wazuh indexer client
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_CLIENT_CLIENT_HPP
#define _INDEXER_CLIENT_CLIENT_HPP

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "types.hpp"

namespace indexer_client
{
    namespace detail
    {
        struct TicketState;
        struct GroupState;
        struct CancelState;
        struct PitState;
        struct CursorState;
        struct ClientState;
    } // namespace detail

    // Waits are always the library's own; from a runtime thread they return Cause::Reentrancy (RF-27).

    class INDEXER_CLIENT_API Ticket final
    {
    public:
        Ticket() = default;
        explicit Ticket(std::shared_ptr<detail::TicketState> state);
        bool ready() const;
        Outcome<OpResult> wait(Deadline deadline) const;

    private:
        std::shared_ptr<detail::TicketState> m_state;
    };

    class INDEXER_CLIENT_API GroupTicket final
    {
    public:
        GroupTicket() = default;
        explicit GroupTicket(std::shared_ptr<detail::GroupState> state);
        bool ready() const;
        Outcome<std::vector<OpResult>> wait(Deadline deadline) const;

    private:
        std::shared_ptr<detail::GroupState> m_state;
    };

    class INDEXER_CLIENT_API CancelTicket final
    {
    public:
        CancelTicket() = default;
        explicit CancelTicket(std::shared_ptr<detail::CancelState> state);
        bool ready() const;
        Outcome<Unit> wait(Deadline deadline) const;

    private:
        std::shared_ptr<detail::CancelState> m_state;
    };

    struct Submit final
    {
        bool accepted {false};
        Cause cause {Cause::None};
        Ticket ticket;
    };

    class INDEXER_CLIENT_API Group final
    {
    public:
        Group() = default;
        explicit Group(std::shared_ptr<detail::GroupState> state);
        Group(Group&&) noexcept;
        Group& operator=(Group&&) noexcept;
        Group(const Group&) = delete;
        Group& operator=(const Group&) = delete;
        ~Group(); ///< Without commit() the group is abandoned and its reservation released.

        Cause add(Op op); ///< None | GroupTooLarge | QueueFull | SubmitTimeout | ...
        GroupTicket commit();

    private:
        std::shared_ptr<detail::GroupState> m_state;
    };

    class INDEXER_CLIENT_API PitSession final
    {
    public:
        PitSession() = default;
        explicit PitSession(std::shared_ptr<detail::CursorState> state);
        Outcome<PitPage> next(Deadline deadline);
        bool exhausted() const;

    private:
        std::shared_ptr<detail::CursorState> m_state;
    };

    /// Shared PIT id; lives while the handle lives, even without cursors (§4.9).
    class INDEXER_CLIENT_API Pit final
    {
    public:
        Pit() = default;
        explicit Pit(std::shared_ptr<detail::PitState> state);
        PitSession cursor(CursorQuery query, std::optional<Slice> slice = std::nullopt);
        Outcome<nlohmann::json> search(const nlohmann::json& body, Deadline deadline);
        std::uint64_t generation() const;

    private:
        std::shared_ptr<detail::PitState> m_state;
    };

    /// Abstract writer, for consumers' mocks (E7-E10).
    class INDEXER_CLIENT_API IWriter
    {
    public:
        virtual ~IWriter() = default;
        virtual Submit submit(Op op, Callback cb = {}) = 0;
        virtual Group group() = 0;
        virtual CancelTicket cancel(std::string_view tag) = 0;
    };

    /// Abstract query interface, for consumers' mocks (E7-E10).
    class INDEXER_CLIENT_API IQuery
    {
    public:
        virtual ~IQuery() = default;
        virtual Outcome<nlohmann::json>
        search(std::string_view index, const nlohmann::json& body, const QueryOptions& options, Deadline deadline) = 0;
        virtual Outcome<Unit> searchAfter(std::string_view index,
                                          nlohmann::json body,
                                          std::function<bool(const nlohmann::json&)> page,
                                          const QueryOptions& options,
                                          Deadline deadline) = 0;
        virtual Outcome<Pit> pit(std::vector<std::string> indices,
                                 PitOptions pitOptions,
                                 const QueryOptions& options,
                                 Deadline deadline) = 0;
        virtual Outcome<nlohmann::json> deleteByQuery(std::vector<std::string> indices,
                                                      const nlohmann::json& query,
                                                      DbqOptions dbqOptions,
                                                      const QueryOptions& options,
                                                      Deadline deadline) = 0;
        virtual Outcome<nlohmann::json> updateByQuery(std::vector<std::string> indices,
                                                      const nlohmann::json& query,
                                                      const QueryOptions& options,
                                                      Deadline deadline) = 0;
        virtual Outcome<bool> indexExists(std::string_view index, const QueryOptions& options, Deadline deadline) = 0;
    };

    /// Abstract client, for consumers' mocks (E7-E10).
    class INDEXER_CLIENT_API IClient
    {
    public:
        virtual ~IClient() = default;
        virtual std::shared_ptr<IWriter> writer(std::string_view bucket) = 0;
        virtual std::shared_ptr<IQuery> query() = 0;
        virtual HealthView health() const = 0;
        virtual void requestClose() = 0;
        virtual Outcome<CloseReport> awaitClosed(Deadline deadline) = 0;
    };

    /// A consumer's handle on the process runtime (I37). Destruction = requestClose() + awaitClosed(shutdown deadline
    /// or the default); destroying it from a runtime thread is a usage error.
    class INDEXER_CLIENT_API Client final : public IClient
    {
    public:
        Client() = default;
        explicit Client(std::shared_ptr<detail::ClientState> state);
        Client(Client&&) noexcept;
        Client& operator=(Client&&) noexcept;
        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;
        ~Client() override;

        std::shared_ptr<IWriter> writer(std::string_view bucket) override; ///< nullptr for an unknown bucket.
        std::shared_ptr<IQuery> query() override;
        HealthView health() const override;
        void requestClose() override;                                 ///< Never blocks; valid from any thread.
        Outcome<CloseReport> awaitClosed(Deadline deadline) override; ///< Consumer threads only.
        bool valid() const noexcept;

    private:
        std::shared_ptr<detail::ClientState> m_state;
    };
} // namespace indexer_client

#endif // _INDEXER_CLIENT_CLIENT_HPP
