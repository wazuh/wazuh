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

// asio io_context (one network thread) <-> libcurl multi_socket_action. Ported from the second pass of the E0 spike
// (D26) onto the transport contract (plan 18, anexos/e2a-1/contrato-transport.md):
//  - CURLMOPT_SOCKETFUNCTION -> stream_descriptor::async_wait (read/write), re-armed after every readiness while curl
//    still wants that direction.
//  - CURLMOPT_TIMERFUNCTION -> steady_timer with a generation: a handler that already completed when curl changed or
//    cancelled its timeout sees an old generation and never calls curl (D28).
//  - CURLOPT_OPENSOCKETFUNCTION / CLOSESOCKETFUNCTION are ours: on close the descriptor is cancelled and released
//    (deregistered, not closed) before ::close(). Descriptors curl registers without opening them through us (the
//    multi's wake-up pair, the resolver's) are only watched and released, never closed (H8).
//  - Every CURLM/CURL call happens on the loop's thread. Handlers capture the shared_ptr of the loop state, never a
//    raw pointer; a closed loop refuses posts. No exception leaves a C callback or an asio handler.
//  - Results are never delivered here: TransportShared::resolve posts them to the CPU pool.

#include "transport/curlLoop.hpp"

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <sys/socket.h>
#include <unistd.h>

#include <asio/io_context.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>

#include "transport/seams.hpp"

namespace indexer_client::detail
{
    namespace
    {
        /// Per-host connection cap of every multi (constant of E2a-1; the real window is E5's).
        constexpr long MAX_HOST_CONNECTIONS = 8;
        /// Idle easy handles kept per loop for reuse.
        constexpr std::size_t MAX_IDLE_EASY = 64;
        /// A Retry-After value longer than this is malformed for sure; it is kept as an empty (invalid) value.
        constexpr std::size_t MAX_RETRY_AFTER_LENGTH = 128;

        constexpr bool isOws(char c)
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }

        std::string_view trimView(std::string_view s)
        {
            while (!s.empty() && isOws(s.front()))
            {
                s.remove_prefix(1);
            }
            while (!s.empty() && isOws(s.back()))
            {
                s.remove_suffix(1);
            }
            return s;
        }

        bool equalsIgnoreCase(std::string_view a, std::string_view lowercase)
        {
            return a.size() == lowercase.size() &&
                   std::equal(a.begin(),
                              a.end(),
                              lowercase.begin(),
                              [](char x, char y)
                              { return (x >= 'A' && x <= 'Z' ? static_cast<char>(x + 32) : x) == y; });
        }

        /// Reads the transfer's timings (microseconds) into `timings`; on a cancelled or stopped transfer too.
        void readTimings(CURL* easy, TransferTimings& timings)
        {
            curl_off_t value = 0;
            if (curl_easy_getinfo(easy, CURLINFO_TOTAL_TIME_T, &value) == CURLE_OK)
            {
                timings.total = std::chrono::microseconds(value);
            }
            if (curl_easy_getinfo(easy, CURLINFO_CONNECT_TIME_T, &value) == CURLE_OK)
            {
                timings.connect = std::chrono::microseconds(value);
            }
            if (curl_easy_getinfo(easy, CURLINFO_APPCONNECT_TIME_T, &value) == CURLE_OK)
            {
                timings.appConnect = std::chrono::microseconds(value);
            }
        }

        struct SocketInfo final
        {
            SocketInfo(asio::io_context& io, int descriptor, bool openedByUs)
                : sd(io, descriptor)
                , fd(descriptor)
                , ours(openedByUs)
            {
            }

            asio::posix::stream_descriptor sd;
            int fd;
            bool ours;    ///< Opened by our OPENSOCKETFUNCTION (else: a descriptor curl owns).
            int what {0}; ///< Last CURL_POLL_* curl asked for.
            bool readArmed {false};
            bool writeArmed {false};
            bool closed {false};

            /// Stops watching the descriptor and gives it back without closing it.
            void release()
            {
                closed = true;
                what = 0;
                asio::error_code ignored;
                sd.cancel(ignored);
                sd.release();
            }
        };
    } // namespace

    struct CurlLoop::Impl final : std::enable_shared_from_this<CurlLoop::Impl>
    {
        Impl(asio::io_context& context, std::uint32_t loopIndex, std::shared_ptr<TransportShared> transportShared)
            : io(context)
            , index(loopIndex)
            , shared(std::move(transportShared))
            , timer(std::in_place, context)
        {
            closedFuture = closedPromise.get_future().share();
            multi = curl_multi_init();
            if (multi == nullptr)
            {
                throw std::runtime_error("curl_multi_init failed");
            }
            CURLMcode rc = CURLM_OK;
            const auto set = [&rc](CURLMcode result)
            {
                if (rc == CURLM_OK)
                {
                    rc = result;
                }
            };
            set(curl_multi_setopt(multi, CURLMOPT_SOCKETFUNCTION, &Impl::socketCb));
            set(curl_multi_setopt(multi, CURLMOPT_SOCKETDATA, this));
            set(curl_multi_setopt(multi, CURLMOPT_TIMERFUNCTION, &Impl::timerCb));
            set(curl_multi_setopt(multi, CURLMOPT_TIMERDATA, this));
            set(curl_multi_setopt(multi, CURLMOPT_MAX_HOST_CONNECTIONS, MAX_HOST_CONNECTIONS));
            // curl_multi_cleanup does not join a resolver thread stuck in getaddrinfo (I38b).
            set(curl_multi_setopt(multi, CURLMOPT_QUICK_EXIT, 1L));
            if (rc != CURLM_OK)
            {
                curl_multi_cleanup(multi);
                throw std::runtime_error(std::string("curl_multi_setopt failed: ") + curl_multi_strerror(rc));
            }
        }

        /// Only reached with a live multi when the loop never ran (a failed Transport::create): no descriptor was ever
        /// registered, so the cleanup touches no asio object.
        ~Impl()
        {
            if (multi != nullptr)
            {
                curl_multi_setopt(multi, CURLMOPT_SOCKETFUNCTION, nullptr);
                curl_multi_setopt(multi, CURLMOPT_TIMERFUNCTION, nullptr);
                curl_multi_cleanup(multi);
            }
            for (auto* easy : idle)
            {
                curl_easy_cleanup(easy);
            }
        }

        // ------------------------------------------------------------------------------------------- any thread

        template<class Handler>
        bool post(Handler&& handler)
        {
            std::lock_guard<std::mutex> lock(postMutex);
            if (closing)
            {
                rejectedPosts.fetch_add(1);
                seams::onPostRejected();
                return false;
            }
            asio::post(io, std::forward<Handler>(handler));
            return true;
        }

        // ------------------------------------------------------------------------------------ loop thread only

        CURL* takeEasy()
        {
            if (!idle.empty())
            {
                CURL* easy = idle.back();
                idle.pop_back();
                curl_easy_reset(easy); // Options start from scratch; connections belong to the multi.
                return easy;
            }
            return curl_easy_init();
        }

        void giveBackEasy(CURL* easy)
        {
            if (easy == nullptr)
            {
                return;
            }
            if (!stopped && idle.size() < MAX_IDLE_EASY)
            {
                try
                {
                    idle.push_back(easy);
                    return;
                }
                catch (...)
                {
                }
            }
            curl_easy_cleanup(easy);
        }

        static void freeHeaders(TransferState& state)
        {
            if (state.headers != nullptr)
            {
                curl_slist_free_all(state.headers);
                state.headers = nullptr;
            }
        }

        /// The method and the body are set on every use of the easy (after curl_easy_reset), never inherited.
        CURLcode configure(CURL* easy, TransferState& state)
        {
            CURLcode rc = CURLE_OK;
            const auto set = [&rc](CURLcode result)
            {
                if (rc == CURLE_OK)
                {
                    rc = result;
                }
            };
            const auto& request = state.request;
            const auto& body = request.body;

            set(curl_easy_setopt(easy, CURLOPT_URL, request.url.c_str()));
            set(curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, "http,https"));
            set(curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L));

            // TLS (I48): material in memory (CURL_BLOB_NOCOPY over TransportShared, alive until the last
            // curl_multi_cleanup), no CA directory, verification always on, TLS 1.2 or newer. No insecure mode.
            const auto& tls = shared->tls;
            if (!tls.caBundle.empty())
            {
                curl_blob ca {const_cast<char*>(tls.caBundle.data()), tls.caBundle.size(), CURL_BLOB_NOCOPY};
                set(curl_easy_setopt(easy, CURLOPT_CAINFO_BLOB, &ca));
            }
            else
            {
                // No CA: never curl's compiled-in bundle (https is not admitted then anyway; defence in depth).
                set(curl_easy_setopt(easy, CURLOPT_CAINFO, nullptr));
            }
            set(curl_easy_setopt(easy, CURLOPT_CAPATH, nullptr));
            set(curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L));
            set(curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L));
            set(curl_easy_setopt(easy, CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2)));
            if (tls.mutual())
            {
                // The whole certificate file, so that the intermediates travel with the leaf.
                curl_blob certificate {
                    const_cast<char*>(tls.certificateChain.data()), tls.certificateChain.size(), CURL_BLOB_NOCOPY};
                curl_blob key {const_cast<char*>(tls.privateKey.data()), tls.privateKey.size(), CURL_BLOB_NOCOPY};
                set(curl_easy_setopt(easy, CURLOPT_SSLCERTTYPE, "PEM"));
                set(curl_easy_setopt(easy, CURLOPT_SSLCERT_BLOB, &certificate));
                set(curl_easy_setopt(easy, CURLOPT_SSLKEYTYPE, "PEM"));
                set(curl_easy_setopt(easy, CURLOPT_SSLKEY_BLOB, &key));
            }

            // Credentials (I55): separate options, so a ':' in the password travels as is; never USERPWD.
            set(curl_easy_setopt(easy, CURLOPT_USERNAME, shared->credentials.user.c_str()));
            set(curl_easy_setopt(easy, CURLOPT_PASSWORD, shared->credentials.password.c_str()));
            set(curl_easy_setopt(easy, CURLOPT_PROXY, "")); // Never a proxy from the environment.
            set(curl_easy_setopt(easy, CURLOPT_TCP_NODELAY, 1L));
            set(curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, static_cast<long>(state.timeout.count())));
            set(curl_easy_setopt(easy, CURLOPT_PRIVATE, &state));
            set(curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &Impl::writeCb));
            set(curl_easy_setopt(easy, CURLOPT_WRITEDATA, &state));
            set(curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, &Impl::headerCb));
            set(curl_easy_setopt(easy, CURLOPT_HEADERDATA, &state));
            set(curl_easy_setopt(easy, CURLOPT_PREREQFUNCTION, &Impl::prereqCb));
            set(curl_easy_setopt(easy, CURLOPT_PREREQDATA, &state));
            set(curl_easy_setopt(easy, CURLOPT_OPENSOCKETFUNCTION, &Impl::openSocketCb));
            set(curl_easy_setopt(easy, CURLOPT_OPENSOCKETDATA, this));
            set(curl_easy_setopt(easy, CURLOPT_CLOSESOCKETFUNCTION, &Impl::closeSocketCb));
            set(curl_easy_setopt(easy, CURLOPT_CLOSESOCKETDATA, this));

            const auto setBody = [&]()
            {
                const auto size = body ? static_cast<curl_off_t>(body->size()) : static_cast<curl_off_t>(0);
                set(curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE, size));
                set(curl_easy_setopt(easy, CURLOPT_POSTFIELDS, body ? body->data() : ""));
            };
            bool sendsBody = false;
            switch (request.method)
            {
                case HttpMethod::Head: set(curl_easy_setopt(easy, CURLOPT_NOBODY, 1L)); break;
                case HttpMethod::Get:
                    set(curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L));
                    if (body)
                    {
                        setBody();
                        set(curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, "GET"));
                        sendsBody = true;
                    }
                    break;
                case HttpMethod::Post:
                    set(curl_easy_setopt(easy, CURLOPT_POST, 1L));
                    setBody();
                    sendsBody = true;
                    break;
                case HttpMethod::Put:
                    set(curl_easy_setopt(easy, CURLOPT_POST, 1L));
                    setBody();
                    set(curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, "PUT"));
                    sendsBody = true;
                    break;
                case HttpMethod::Delete:
                    set(curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L));
                    if (body)
                    {
                        setBody();
                        sendsBody = true;
                    }
                    set(curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, "DELETE"));
                    break;
            }

            // An explicit or suppressed Content-Type (curl would add a form type). `Expect` is left to curl, as the v1
            // does: 100-continue on bodies over 1 MiB, so the node can refuse (401, 413, 429) before the body is sent;
            // measured in E2c at +18 % (TLS) and +5 % (clear) on a 4 MiB bulk against the fake (plan 18, I60).
            const auto append = [&state](const std::string& line)
            {
                auto* list = curl_slist_append(state.headers, line.c_str());
                if (list == nullptr)
                {
                    return false;
                }
                state.headers = list;
                return true;
            };
            if (sendsBody && !append((body ? "Content-Type: " + request.contentType : std::string("Content-Type:"))))
            {
                return CURLE_OUT_OF_MEMORY;
            }
            set(curl_easy_setopt(easy, CURLOPT_HTTPHEADER, state.headers));
            return rc;
        }

        /// A start that did not reach the multi: the easy goes back to the free-list and the result is LocalError.
        void failStart(const std::shared_ptr<TransferState>& state, int curlCode)
        {
            freeHeaders(*state);
            giveBackEasy(state->easy);
            state->easy = nullptr;
            HttpResult result;
            result.curlCode = curlCode;
            result.cause = classifyCurlCode(curlCode, false);
            result.nodeAttributable = nodeAttributable(result.cause);
            shared->resolve(state, std::move(result));
        }

        void start(const std::shared_ptr<TransferState>& state) noexcept
        {
            if (state->claimed.load())
            {
                return; // Cancelled before it started.
            }
            if (stopped)
            {
                HttpResult result;
                result.cause = TransportCause::Shutdown;
                shared->resolve(state, std::move(result));
                return;
            }
            bool registered = false;
            try
            {
                state->easy = takeEasy();
                if (state->easy == nullptr)
                {
                    failStart(state, CURLE_FAILED_INIT);
                    return;
                }
                if (const auto rc = configure(state->easy, *state); rc != CURLE_OK)
                {
                    failStart(state, rc);
                    return;
                }
                active.emplace(state.get(), state);
                registered = true;
                seams::throwOnAdd();
                if (curl_multi_add_handle(multi, state->easy) != CURLM_OK)
                {
                    active.erase(state.get());
                    failStart(state, CURLE_FAILED_INIT);
                    return;
                }
                inFlightCount.fetch_add(1);
                // curl_multi_add_handle armed the timer; the first socket_action comes from its handler.
            }
            catch (...)
            {
                if (registered)
                {
                    active.erase(state.get());
                }
                failStart(state, CURLE_FAILED_INIT);
            }
        }

        /// Takes a transfer out of the multi for good (cancel, stop, multi error): its connection is closed, its
        /// half-used easy is destroyed, and what it had sent is recorded.
        void detach(const std::shared_ptr<TransferState>& state, HttpResult& result)
        {
            curl_off_t uploaded = 0;
            curl_easy_getinfo(state->easy, CURLINFO_SIZE_UPLOAD_T, &uploaded);
            result.uploadedBytes = uploaded > 0 ? static_cast<std::uint64_t>(uploaded) : 0;
            result.mayHaveSent = state->mayHaveSent;
            readTimings(state->easy, result.timings);
            curl_multi_remove_handle(multi, state->easy);
            curl_easy_cleanup(state->easy);
            state->easy = nullptr;
            freeHeaders(*state);
            inFlightCount.fetch_sub(1);
        }

        void cancel(const std::shared_ptr<TransferState>& state) noexcept
        {
            if (state->claimed.load())
            {
                return; // Completion (or a start failure) won.
            }
            HttpResult result;
            result.cause = TransportCause::Cancelled;
            if (state->easy != nullptr)
            {
                active.erase(state.get());
                detach(state, result); // Out of the multi before resolving (D27).
            }
            shared->resolve(state, std::move(result));
        }

        void checkDone() noexcept
        {
            int pending = 0;
            while (CURLMsg* message = curl_multi_info_read(multi, &pending))
            {
                if (message->msg != CURLMSG_DONE)
                {
                    continue;
                }
                CURL* easy = message->easy_handle;
                const CURLcode code = message->data.result;
                TransferState* raw = nullptr;
                curl_easy_getinfo(easy, CURLINFO_PRIVATE, &raw);
                const auto it = active.find(raw);
                if (it == active.end())
                {
                    continue;
                }
                auto state = it->second;
                active.erase(it);

                HttpResult result;
                result.curlCode = code;
                result.cause = classifyCurlCode(code, state->capTripped);
                result.nodeAttributable = nodeAttributable(result.cause);
                result.mayHaveSent = state->mayHaveSent;
                curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &result.status);
                readTimings(easy, result.timings);
                curl_off_t value = 0;
                curl_easy_getinfo(easy, CURLINFO_SIZE_UPLOAD_T, &value);
                result.uploadedBytes = value > 0 ? static_cast<std::uint64_t>(value) : 0;
                result.body = std::move(state->response);
                auto retryAfter = std::move(state->retryAfter);

                curl_multi_remove_handle(multi, easy);
                inFlightCount.fetch_sub(1);
                freeHeaders(*state);
                giveBackEasy(easy);
                state->easy = nullptr;
                shared->resolve(state, std::move(result), std::move(retryAfter));
            }
        }

        /// curl_multi_socket_action (or the injected seam) failed: the multi's view of its transfers is no longer
        /// trustworthy. Whatever finished is delivered; every other transfer fails once as LocalError (D27). The multi
        /// stays usable for new work.
        void handleMultiError() noexcept
        {
            checkDone();
            auto failed = std::move(active);
            active.clear();
            for (auto& [raw, state] : failed)
            {
                HttpResult result;
                detach(state, result);
                result.curlCode = CURLE_FAILED_INIT;
                result.cause = TransportCause::LocalError;
                result.nodeAttributable = false;
                shared->resolve(state, std::move(result));
            }
        }

        void socketAction(curl_socket_t fd, int flags) noexcept
        {
            int running = 0;
            auto rc = curl_multi_socket_action(multi, fd, flags, &running);
            rc = static_cast<CURLMcode>(seams::injectMultiError(static_cast<int>(rc)));
            if (rc != CURLM_OK)
            {
                handleMultiError();
                return;
            }
            checkDone();
        }

        void arm(const std::shared_ptr<SocketInfo>& info)
        {
            if (info->closed)
            {
                return;
            }
            auto self = shared_from_this();
            if ((info->what & CURL_POLL_IN) && !info->readArmed)
            {
                info->readArmed = true;
                info->sd.async_wait(asio::posix::stream_descriptor::wait_read,
                                    [self, info](const asio::error_code& ec)
                                    { self->onReady(info, CURL_CSELECT_IN, ec); });
            }
            if ((info->what & CURL_POLL_OUT) && !info->writeArmed)
            {
                info->writeArmed = true;
                info->sd.async_wait(asio::posix::stream_descriptor::wait_write,
                                    [self, info](const asio::error_code& ec)
                                    { self->onReady(info, CURL_CSELECT_OUT, ec); });
            }
        }

        void onReady(const std::shared_ptr<SocketInfo>& info, int flag, const asio::error_code& ec) noexcept
        {
            const int want = flag == CURL_CSELECT_IN ? CURL_POLL_IN : CURL_POLL_OUT;
            (flag == CURL_CSELECT_IN ? info->readArmed : info->writeArmed) = false;
            if (info->closed || stopped)
            {
                return;
            }
            if (!ec && (info->what & want))
            {
                socketAction(info->fd, flag);
            }
            else if (ec && ec != asio::error::operation_aborted)
            {
                socketAction(info->fd, CURL_CSELECT_ERR); // An error on the descriptor: curl fails its transfer.
            }
            try
            {
                arm(info); // No-op if closed meanwhile or curl no longer wants this direction.
            }
            catch (...)
            {
                handlerExceptions.fetch_add(1);
            }
        }

        void onTimer(std::uint64_t generation, const asio::error_code& ec) noexcept
        {
            try
            {
                seams::onTimerHandler(generation, timerGeneration);
            }
            catch (...)
            {
                handlerExceptions.fetch_add(1);
            }
            if (ec || stopped || generation != timerGeneration)
            {
                return; // Aborted, or curl replaced/cancelled this timeout after it had completed: never call curl.
            }
            socketAction(CURL_SOCKET_TIMEOUT, 0);
        }

        void releaseSocket(const std::shared_ptr<SocketInfo>& info)
        {
            info->release();
            if (!info->ours)
            {
                foreignWatchedCount.fetch_sub(1);
                foreignReleasedCount.fetch_add(1);
            }
        }

        /// Contract stop, steps 2 and 3, on this loop's thread: every transfer out of the multi and resolved as
        /// Shutdown, the multi cleaned up (CURLMOPT_QUICK_EXIT: no resolver join), the remaining descriptors released
        /// and every asio object of the loop destroyed here, so that nothing outlives the io_context.
        void shutdownOnLoop() noexcept
        {
            stopped = true;
            try
            {
                auto pending = std::move(active);
                active.clear();
                for (auto& [raw, state] : pending)
                {
                    HttpResult result;
                    result.cause = TransportCause::Shutdown;
                    detach(state, result);
                    shared->resolve(state, std::move(result));
                }
                for (auto* easy : idle)
                {
                    curl_easy_cleanup(easy);
                }
                idle.clear();
                curl_multi_cleanup(multi); // Pooled connections close through closeSocketCb.
                multi = nullptr;
                for (auto& [fd, info] : sockets)
                {
                    releaseSocket(info); // curl-owned descriptors: released, never closed.
                }
                sockets.clear();
                ++timerGeneration;
                timer.reset(); // A pending wait completes with operation_aborted.
            }
            catch (...)
            {
                handlerExceptions.fetch_add(1);
            }
            closedPromise.set_value();
        }

        // ------------------------------------------------------------------------------ curl callbacks (noexcept)

        static int socketCb(CURL* /*easy*/, curl_socket_t fd, int what, void* userp, void* /*socketp*/) noexcept
        {
            auto* self = static_cast<Impl*>(userp);
            try
            {
                const auto it = self->sockets.find(fd);
                if (what == CURL_POLL_REMOVE)
                {
                    if (it != self->sockets.end())
                    {
                        auto info = it->second;
                        info->what = 0;
                        asio::error_code ignored;
                        info->sd.cancel(ignored); // Pending waits complete with operation_aborted.
                        if (!info->ours)
                        {
                            // curl owns and closes this descriptor itself: only stop watching it.
                            self->releaseSocket(info);
                            self->sockets.erase(it);
                        }
                    }
                    return 0;
                }
                std::shared_ptr<SocketInfo> info;
                if (it == self->sockets.end())
                {
                    info = std::make_shared<SocketInfo>(self->io, fd, false);
                    self->sockets.emplace(fd, info);
                    self->foreignWatchedCount.fetch_add(1);
                }
                else
                {
                    info = it->second;
                }
                info->what = what;
                self->arm(info);
                return 0;
            }
            catch (...)
            {
                self->handlerExceptions.fetch_add(1);
                return -1;
            }
        }

        static int timerCb(CURLM* /*multi*/, long timeoutMs, void* userp) noexcept
        {
            auto* self = static_cast<Impl*>(userp);
            try
            {
                const std::uint64_t generation = ++self->timerGeneration;
                if (!self->timer)
                {
                    return 0;
                }
                if (timeoutMs < 0)
                {
                    self->timer->cancel();
                    return 0;
                }
                // A 0 timeout is deferred through asio as well: never call socket_action from inside curl.
                self->timer->expires_after(std::chrono::milliseconds(timeoutMs));
                self->timer->async_wait([impl = self->shared_from_this(), generation](const asio::error_code& ec)
                                        { impl->onTimer(generation, ec); });
                return 0;
            }
            catch (...)
            {
                self->handlerExceptions.fetch_add(1);
                return -1;
            }
        }

        static curl_socket_t openSocketCb(void* clientp, curlsocktype purpose, struct curl_sockaddr* address) noexcept
        {
            auto* self = static_cast<Impl*>(clientp);
            if (purpose != CURLSOCKTYPE_IPCXN)
            {
                return CURL_SOCKET_BAD;
            }
            int fd = CURL_SOCKET_BAD;
            try
            {
                if (const auto forced = seams::openSocket())
                {
                    if (*forced == CURL_SOCKET_BAD)
                    {
                        return CURL_SOCKET_BAD; // Test seam: a connect failure before any byte (I36).
                    }
                    fd = *forced;
                }
            }
            catch (...)
            {
                self->handlerExceptions.fetch_add(1);
                return CURL_SOCKET_BAD;
            }
            if (fd == CURL_SOCKET_BAD)
            {
                fd = ::socket(address->family, address->socktype | SOCK_CLOEXEC, address->protocol);
                if (fd < 0)
                {
                    return CURL_SOCKET_BAD;
                }
            }
            try
            {
                const auto it = self->sockets.find(fd);
                if (it != self->sockets.end())
                {
                    // A stale entry with this number is a close we never saw: drop it without closing (the number
                    // now belongs to the new socket).
                    self->releaseSocket(it->second);
                    self->sockets.erase(it);
                }
                self->sockets.emplace(fd, std::make_shared<SocketInfo>(self->io, fd, true));
            }
            catch (...)
            {
                self->handlerExceptions.fetch_add(1);
                ::close(fd);
                return CURL_SOCKET_BAD;
            }
            return fd;
        }

        static int closeSocketCb(void* clientp, curl_socket_t fd) noexcept
        {
            auto* self = static_cast<Impl*>(clientp);
            try
            {
                const auto it = self->sockets.find(fd);
                if (it != self->sockets.end())
                {
                    it->second->release(); // Deregistered from epoll, given back without closing it...
                    self->sockets.erase(it);
                }
            }
            catch (...)
            {
                self->handlerExceptions.fetch_add(1);
            }
            return ::close(fd); // ...and closed exactly once, here.
        }

        /// The response cap lives only here (no CURLOPT_MAXFILESIZE_LARGE, no CURLOPT_ACCEPT_ENCODING): crossing it
        /// sets the flag and returns a short count, so curl fails with 23 and classify reports ResponseTooLarge.
        static size_t writeCb(char* data, size_t size, size_t count, void* userdata) noexcept
        {
            auto* state = static_cast<TransferState*>(userdata);
            const size_t length = size * count;
            if (state->response.size() + length > state->maxResponseBytes)
            {
                state->capTripped = true;
                return 0;
            }
            try
            {
                state->response.append(data, length);
                return length;
            }
            catch (...)
            {
                return 0; // 23 without the cap flag: LocalError.
            }
        }

        static size_t headerCb(char* buffer, size_t size, size_t count, void* userdata) noexcept
        {
            auto* state = static_cast<TransferState*>(userdata);
            const size_t length = size * count;
            try
            {
                const std::string_view line(buffer, length);
                if (line.substr(0, 5) == "HTTP/")
                {
                    state->retryAfter.reset(); // A new response (e.g. after a 1xx): only the last one counts.
                    return length;
                }
                const auto colon = line.find(':');
                if (colon != std::string_view::npos && equalsIgnoreCase(trimView(line.substr(0, colon)), "retry-after"))
                {
                    const auto value = trimView(line.substr(colon + 1));
                    state->retryAfter = value.size() <= MAX_RETRY_AFTER_LENGTH ? std::string(value) : std::string();
                }
            }
            catch (...)
            {
                state->retryAfter.reset();
            }
            return length;
        }

        /// The connection is ready and the request is about to be written (I36): conservative "may have sent".
        static int
        prereqCb(void* clientp, char* /*primaryIp*/, char* /*localIp*/, int /*primaryPort*/, int /*localPort*/) noexcept
        {
            static_cast<TransferState*>(clientp)->mayHaveSent = true;
            return CURL_PREREQFUNC_OK;
        }

        asio::io_context& io;
        const std::uint32_t index;
        const std::shared_ptr<TransportShared> shared;

        std::mutex postMutex; ///< Guards `closing` and orders every accepted post before the shutdown handler.
        bool closing {false};
        std::promise<void> closedPromise;
        std::shared_future<void> closedFuture;

        std::atomic<std::uint64_t> inFlightCount {0};
        std::atomic<std::uint64_t> rejectedPosts {0};
        std::atomic<std::uint64_t> foreignWatchedCount {0};
        std::atomic<std::uint64_t> foreignReleasedCount {0};
        std::atomic<std::uint64_t> handlerExceptions {0};

        // Loop thread only.
        CURLM* multi {nullptr};
        std::optional<asio::steady_timer> timer;
        std::uint64_t timerGeneration {0};
        bool stopped {false};
        std::unordered_map<int, std::shared_ptr<SocketInfo>> sockets;
        std::unordered_map<TransferState*, std::shared_ptr<TransferState>> active;
        std::vector<CURL*> idle;
    };

    CurlLoop::CurlLoop(asio::io_context& context, std::uint32_t index, std::shared_ptr<TransportShared> shared)
        : m_impl(std::make_shared<Impl>(context, index, std::move(shared)))
    {
    }

    CurlLoop::~CurlLoop() = default;

    bool CurlLoop::postStart(std::shared_ptr<TransferState> state)
    {
        auto impl = m_impl;
        try
        {
            return impl->post([impl, state]() { impl->start(state); });
        }
        catch (...)
        {
            // The post itself failed (allocation): the request still gets its single result.
            HttpResult result;
            result.curlCode = CURLE_OUT_OF_MEMORY;
            result.cause = classifyCurlCode(result.curlCode, false);
            impl->shared->resolve(state, std::move(result));
            return true;
        }
    }

    bool CurlLoop::postCancel(std::shared_ptr<TransferState> state)
    {
        auto impl = m_impl;
        try
        {
            return impl->post([impl, state]() { impl->cancel(state); });
        }
        catch (...)
        {
            return false;
        }
    }

    std::shared_future<void> CurlLoop::close()
    {
        auto impl = m_impl;
        std::lock_guard<std::mutex> lock(impl->postMutex);
        if (!impl->closing)
        {
            impl->closing = true;
            try
            {
                asio::post(impl->io, [impl]() { impl->shutdownOnLoop(); });
            }
            catch (...)
            {
                // E.g. bad_alloc: the loop cannot run its cleanup (the multi leaks), but stop() must not wait forever.
                impl->handlerExceptions.fetch_add(1);
                impl->closedPromise.set_value();
            }
        }
        return impl->closedFuture;
    }

    std::uint64_t CurlLoop::inFlight() const
    {
        return m_impl->inFlightCount.load();
    }

    std::uint64_t CurlLoop::postsRejected() const
    {
        return m_impl->rejectedPosts.load();
    }

    std::uint64_t CurlLoop::foreignWatched() const
    {
        return m_impl->foreignWatchedCount.load();
    }

    std::uint64_t CurlLoop::foreignReleased() const
    {
        return m_impl->foreignReleasedCount.load();
    }
} // namespace indexer_client::detail
