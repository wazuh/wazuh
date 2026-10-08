/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * October 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_GUARDED_TLS_SOCKET_HPP
#define _REMOTED_HTTP_GUARDED_TLS_SOCKET_HPP

/**
 * @file guardedTlsSocket.hpp
 * @brief RESTinio's TLS socket with a deadline on the handshake and a per-source cap on handshakes
 *        in progress (issue #6883).
 *
 * PRIVATE to the transport: included by RestinioHttpServer.cpp and its tests only, never by a header
 * the rest of the module sees (RESTinio stays behind IHttpServer).
 *
 * THE GAP IT CLOSES. RESTinio 0.7.x (checked in 0.7.9 and 0.7.10) runs the TLS handshake with no
 * timer at all: connection_t::init() calls prepare_connection_and_start_read(), and only its success
 * callback arms the connection's timers (init_next_timeout_checking(), then the read guard in
 * wait_for_http_message()). read_next_http_message_timelimit therefore does NOT cover the handshake,
 * whatever this module used to say. A peer that connects and sends nothing kept its connection --
 * and with it one of max_parallel_connections' slots, taken at accept -- until IT chose to close.
 *
 * HOW, WITHOUT PATCHING RESTINIO. RESTinio picks everything socket-specific from the traits'
 * stream_socket_t, through three customization points this header provides for GuardedTlsSocket:
 *
 * 1. prepare_connection_and_start_read() -- found by argument-dependent lookup, and preferred over
 *    RESTinio's tls_socket_t overload because it matches the socket type exactly. It is RESTinio's
 *    own handshake plus a steady_timer, both completing on one strand.
 * 2. socket_type_dependent_settings_t -- the TLS settings plus handshake_guard(), which carries the
 *    policy below into the server settings.
 * 3. socket_supplier_t -- RESTinio's TLS socket pool, building every socket with that policy.
 *
 * Everything else (the state listener's tls_accessor_t, make_tls_socket_pointer_for_state_listener())
 * takes a tls_socket_t&, which GuardedTlsSocket is. Re-check all three points when RESTinio is
 * upgraded: a release that arms its own handshake timer, or renames one of them, changes this.
 *
 * WHAT THE DEADLINE DOES. On expiry the TCP socket is shut down in both directions. That is what
 * ends the handshake whatever state it is in: a read already pending completes with EOF, and one
 * the handshake issues afterwards fails at once -- a cancel() alone would miss an operation started
 * after it. The handshake then completes with an error, RESTinio's own failure path closes the
 * connection, and the slot is released. The socket is never closed here, so RESTinio's close()
 * finds it in the state it expects.
 */

#include "handshakeLedger.hpp"

// core.hpp first: tls.hpp specializes templates it declares, and does not include it itself.
#include <restinio/core.hpp>
#include <restinio/tls.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace remoted::http
{
    /**
     * @brief What every socket of one server run enforces, shared by all of them.
     */
    struct HandshakeGuardPolicy
    {
        /// How long a peer has to complete the TLS handshake (remoted.http_read_timeout).
        std::chrono::steady_clock::duration timeout {std::chrono::seconds {10}};
        /// Where handshakes are counted, and the per-source cap enforced. Never null.
        std::shared_ptr<HandshakeLedger> ledger;
        /// Told about a refused or timed-out handshake, with the peer address, so the transport can
        /// log it. Runs on an I/O thread: it must not block. May be empty.
        void (*onRefused)(const std::string& peer) {nullptr};
        void (*onTimedOut)(const std::string& peer) {nullptr};
    };

    /**
     * @brief restinio::impl::tls_socket_t that carries its server run's HandshakeGuardPolicy.
     */
    class GuardedTlsSocket : public restinio::impl::tls_socket_t
    {
    public:
        GuardedTlsSocket(restinio::asio_ns::io_context& ioContext,
                         context_handle_t tlsContext,
                         std::shared_ptr<const HandshakeGuardPolicy> policy)
            : tls_socket_t(ioContext, std::move(tlsContext))
            , m_policy {std::move(policy)}
        {
        }

        GuardedTlsSocket(GuardedTlsSocket&&) = default;
        GuardedTlsSocket& operator=(GuardedTlsSocket&&) = default;

        const HandshakeGuardPolicy& policy() const noexcept
        {
            return *m_policy;
        }

    private:
        std::shared_ptr<const HandshakeGuardPolicy> m_policy;
    };

    namespace detail
    {
        /**
         * @brief The state the handshake and its deadline share.
         *
         * Both completion handlers run on `strand`, so `finished`/`expired` need no atomics, and the
         * deadline can never act in the middle of a handshake step: the handshake's intermediate
         * handlers inherit the final handler's executor, which is this strand too.
         *
         * The destructor is the backstop that keeps the ledger exact when neither handler ever runs
         * (the io_context is destroyed with the handshake still pending, at shutdown).
         */
        struct HandshakeState
        {
            using Strand = restinio::asio_ns::strand<restinio::asio_ns::any_io_executor>;

            HandshakeState(const Strand& handlerStrand,
                           std::shared_ptr<HandshakeLedger> handshakeLedger,
                           std::uint64_t id,
                           std::string peerAddress)
                : strand {handlerStrand}
                , timer {handlerStrand}
                , ledger {std::move(handshakeLedger)}
                , connectionId {id}
                , peer {std::move(peerAddress)}
            {
            }

            ~HandshakeState()
            {
                ledger->finishHandshake(connectionId);
            }

            HandshakeState(const HandshakeState&) = delete;
            HandshakeState& operator=(const HandshakeState&) = delete;

            Strand strand;
            restinio::asio_ns::steady_timer timer;
            std::shared_ptr<HandshakeLedger> ledger;
            std::uint64_t connectionId;
            std::string peer;
            bool finished {false}; ///< The handshake completed (either way); the deadline is moot.
            bool expired {false};  ///< The deadline fired first; the handshake's error is ours.
        };
    } // namespace detail

    /**
     * @brief RESTinio customization point: the TLS handshake, under a deadline and the per-source cap.
     *
     * Called by restinio::impl::connection_t::init() exactly once per connection. `start_read_cb`
     * (notifies the state listener, arms RESTinio's timers, starts reading) or `failed_cb` (logs
     * and closes) is called exactly once, as with RESTinio's own overload.
     */
    template<typename Connection, typename Start_Read_CB, typename Failed_CB>
    void prepare_connection_and_start_read(GuardedTlsSocket& socket,
                                           Connection& con,
                                           Start_Read_CB start_read_cb,
                                           Failed_CB failed_cb)
    {
        namespace asio = restinio::asio_ns;

        const auto& policy = socket.policy();

        asio::error_code endpointError;
        const auto endpoint = socket.lowest_layer().remote_endpoint(endpointError);
        std::string peer = endpointError ? std::string {} : endpoint.address().to_string();

        if (!policy.ledger->beginHandshake(con.connection_id(), peer))
        {
            if (policy.onRefused != nullptr)
            {
                policy.onRefused(peer);
            }
            // RESTinio's failure path: logs (at debug) and closes, which releases the slot and
            // emits the closed notice that uncounts the connection.
            failed_cb(asio::error::make_error_code(asio::error::connection_refused));
            return;
        }

        auto state =
            std::make_shared<detail::HandshakeState>(asio::make_strand(asio::any_io_executor {socket.get_executor()}),
                                                     policy.ledger,
                                                     con.connection_id(),
                                                     std::move(peer));

        state->timer.expires_after(policy.timeout);
        // The connection is kept alive by both handlers, like RESTinio's own handshake handler does:
        // `socket` is one of its members.
        state->timer.async_wait(
            [state, &socket, onTimedOut = policy.onTimedOut, con = con.shared_from_this()](const asio::error_code& ec)
            {
                if (ec || state->finished)
                {
                    return; // cancelled by a completed handshake, or it completed in the meantime
                }
                state->expired = true;
                state->ledger->recordTimeout();
                if (onTimedOut != nullptr)
                {
                    onTimedOut(state->peer);
                }
                asio::error_code ignored;
                socket.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
                socket.lowest_layer().cancel(ignored);
            });

        socket.async_handshake(
            asio::ssl::stream_base::server,
            asio::bind_executor(state->strand,
                                [state,
                                 start_read_cb = std::move(start_read_cb),
                                 failed_cb = std::move(failed_cb),
                                 con = con.shared_from_this()](const asio::error_code& ec) mutable
                                {
                                    state->finished = true;
                                    state->timer.cancel();
                                    // Before the callbacks: the accepted notice start_read_cb emits
                                    // must find the connection no longer handshaking.
                                    state->ledger->finishHandshake(state->connectionId);

                                    if (!ec)
                                    {
                                        start_read_cb();
                                    }
                                    else
                                    {
                                        failed_cb(state->expired ? asio::error::make_error_code(asio::error::timed_out)
                                                                 : ec);
                                    }
                                }));
    }
} // namespace remoted::http

namespace restinio
{
    /**
     * @brief The TLS settings (tls_context(), giveaway_tls_context()) plus the handshake guard.
     */
    template<typename Settings>
    class socket_type_dependent_settings_t<Settings, remoted::http::GuardedTlsSocket>
        : public socket_type_dependent_settings_t<Settings, impl::tls_socket_t>
    {
    protected:
        ~socket_type_dependent_settings_t() = default;

    public:
        socket_type_dependent_settings_t() = default;
        socket_type_dependent_settings_t(socket_type_dependent_settings_t&&) = default;

        Settings& handshake_guard(std::shared_ptr<const remoted::http::HandshakeGuardPolicy> policy) &
        {
            m_handshakeGuard = std::move(policy);
            return static_cast<Settings&>(*this);
        }

        Settings&& handshake_guard(std::shared_ptr<const remoted::http::HandshakeGuardPolicy> policy) &&
        {
            return std::move(this->handshake_guard(std::move(policy)));
        }

        /// Intended for socket_supplier_t below.
        std::shared_ptr<const remoted::http::HandshakeGuardPolicy> handshake_guard() const
        {
            return m_handshakeGuard;
        }

    private:
        std::shared_ptr<const remoted::http::HandshakeGuardPolicy> m_handshakeGuard;
    };

    namespace impl
    {
        /**
         * @brief RESTinio's tls_socket_t pool, building GuardedTlsSockets.
         */
        template<>
        class socket_supplier_t<remoted::http::GuardedTlsSocket>
        {
        protected:
            template<typename Settings>
            socket_supplier_t(Settings& settings, asio_ns::io_context& io_context)
                : m_tls_context {settings.giveaway_tls_context()}
                , m_policy {settings.handshake_guard()}
                , m_io_context {io_context}
            {
                // A socket with no policy would dereference null on its first handshake.
                if (!m_policy || !m_policy->ledger)
                {
                    throw exception_t {"handshake guard is not specified"};
                }

                m_sockets.reserve(settings.concurrent_accepts_count());
                while (m_sockets.size() < settings.concurrent_accepts_count())
                {
                    m_sockets.emplace_back(m_io_context, m_tls_context, m_policy);
                }
            }

            virtual ~socket_supplier_t() = default;

            remoted::http::GuardedTlsSocket& socket(std::size_t idx)
            {
                return m_sockets.at(idx);
            }

            auto move_socket(std::size_t idx)
            {
                remoted::http::GuardedTlsSocket res {m_io_context, m_tls_context, m_policy};
                std::swap(res, m_sockets.at(idx));
                return res;
            }

            auto concurrent_accept_sockets_count() const
            {
                return m_sockets.size();
            }

        private:
            std::shared_ptr<asio_ns::ssl::context> m_tls_context;
            std::shared_ptr<const remoted::http::HandshakeGuardPolicy> m_policy;
            asio_ns::io_context& m_io_context;
            std::vector<remoted::http::GuardedTlsSocket> m_sockets;
        };
    } // namespace impl
} // namespace restinio

#endif // _REMOTED_HTTP_GUARDED_TLS_SOCKET_HPP
