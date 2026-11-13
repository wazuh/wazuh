/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRY_BYTE_STREAM_HPP
#define _REGISTRY_BYTE_STREAM_HPP

#include "byte_stream.hpp"
#include "registry_transport.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief Default ceiling on the compressed bytes of one layer blob.
    constexpr std::uint64_t MAX_BLOB_BYTES {2ULL * 1024 * 1024 * 1024};

    /// @brief A layer blob as the reader sees it: its bytes, and what became of the transfer.
    ///
    /// Separate from the cURL implementation so a test can stand in for the network. The
    /// layer retry cannot otherwise be reached from a unit test.
    class IBlobStream : public IByteStream
    {
        public:
            /// @brief True when the transfer did not complete.
            virtual bool failed() const = 0;

            /// @brief Why the transfer did not complete. Never carries a credential.
            virtual const std::string& error() const = 0;

            /// @brief Status of the last response seen, or 0 when none arrived.
            virtual long status() const = 0;

            /// @brief Bytes handed to the caller so far.
            virtual std::uint64_t bytesDelivered() const = 0;

            /// @brief True when this side ended the transfer: a stop request, the idle
            /// bound, or the byte ceiling. Such a transfer is not retried, since another
            /// attempt would only reach the same limit.
            virtual bool abortedLocally() const = 0;

            /// @brief The `Retry-After` of the last response seen, empty when it had none.
            virtual const std::string& retryAfter() const = 0;
    };

    /// @brief Builds the stream for one attempt at a layer.
    using BlobStreamFactory = std::function<std::unique_ptr<IBlobStream>(const TransportConfig& config,
                                                                         const std::string& url,
                                                                         const std::vector<std::string>& headers,
                                                                         std::uint64_t maxBytes,
                                                                         const std::atomic<bool>* stopRequested)>;

    /// @brief How long a transfer may wait for its next bytes.
    ///
    /// Counts only the time spent waiting on the network. The caller restarts it when a
    /// wait begins, and it is restarted when bytes arrive, so the time a slow caller
    /// spends between reads is never charged to the transfer, and neither is the time the
    /// transfer is suspended for the caller to catch up.
    class IdleBound final
    {
        public:
            explicit IdleBound(const std::chrono::milliseconds window)
                : m_window {window}
            {
            }

            /// @brief Start counting from @p now.
            void restart(const std::chrono::steady_clock::time_point now)
            {
                m_since = now;
            }

            /// @brief True when the wait has outlasted the window. Never while @p paused.
            bool expired(const std::chrono::steady_clock::time_point now, const bool paused) const
            {
                return !paused && now - m_since > m_window;
            }

        private:
            std::chrono::milliseconds m_window;
            std::chrono::steady_clock::time_point m_since {};
    };

    /// @brief A layer blob, read as a stream rather than downloaded.
    ///
    /// This is the class the byte-stream interface was written for: its comment already
    /// named "a remote blob once registries are supported". A blob plugs into the
    /// existing `LayerByteStream` -> `LayerComposer` -> parser chain with no change
    /// downstream, so a registry image is read exactly as an on-disk one is, and nothing
    /// is ever materialised.
    ///
    /// ## How the push becomes a pull
    ///
    /// libcurl delivers received bytes by calling a write callback; the layer chain asks
    /// for bytes by calling `read()`. The two are bridged with the cURL multi interface
    /// driven from inside `read()`: the transfer is advanced only when the caller wants
    /// more, and the write callback answers `CURL_WRITEFUNC_PAUSE` once the buffer is
    /// full, which suspends the transfer until the caller has drained it. That is
    /// libcurl's own idiom for turning a transfer into a pull stream, and it needs no
    /// second thread and no locking: everything happens on the caller's thread.
    class RegistryByteStream final : public IBlobStream
    {
        public:
            /// @param config   Transport settings. Its certificate bundle is required.
            /// @param url      Absolute https URL of the blob.
            /// @param headers  Request headers, as "Name: value".
            /// @param maxBytes Ceiling on the bytes this blob may deliver.
            /// @param stopRequested Polled between reads; the transfer is abandoned when
            ///                       it is set. May be null.
            RegistryByteStream(TransportConfig config,
                               std::string url,
                               std::vector<std::string> headers,
                               std::uint64_t maxBytes = MAX_BLOB_BYTES,
                               const std::atomic<bool>* stopRequested = nullptr);

            ~RegistryByteStream() override;

            RegistryByteStream(const RegistryByteStream&) = delete;
            RegistryByteStream& operator=(const RegistryByteStream&) = delete;

            /// @copydoc IByteStream::read
            ///
            /// Returns 0 at the end of the blob and also when the transfer failed, so a
            /// caller that only reads bytes cannot tell the two apart on purpose: the
            /// layer chain has no business deciding what a network failure means. Ask
            /// @ref failed() afterwards, which is what the reader does before it treats
            /// an empty read as an empty layer.
            std::size_t read(char* buffer, std::size_t size) override;

            bool failed() const override
            {
                return m_failed;
            }

            const std::string& error() const override
            {
                return m_error;
            }

            long status() const override
            {
                return m_status;
            }

            std::uint64_t bytesDelivered() const override
            {
                return m_delivered;
            }

            bool abortedLocally() const override
            {
                return m_abortedLocally;
            }

            const std::string& retryAfter() const override
            {
                return m_retryAfter;
            }

        private:
            /// @brief cURL write callback. Buffers, or pauses when the buffer is full.
            static std::size_t onWrite(char* data, std::size_t size, std::size_t members, void* userdata);

            /// @brief cURL header callback, kept only to learn the final status and its `Retry-After`.
            static std::size_t onHeader(char* data, std::size_t size, std::size_t members, void* userdata);

            /// @brief Advance the transfer once.
            void pump();

            /// @brief Bytes buffered and not yet handed out.
            std::size_t buffered() const;

            /// @brief Start the transfer, at the first read rather than at construction.
            bool start();

            TransportConfig m_config;
            const std::atomic<bool>* m_stopRequested {nullptr};
            IdleBound m_idle;
            std::string m_url;
            std::vector<std::string> m_headers;
            std::uint64_t m_maxBytes;

            void* m_multi {nullptr};       ///< CURLM*
            void* m_handle {nullptr};      ///< CURL*
            void* m_headerList {nullptr};  ///< curl_slist*

            std::string m_buffer;
            std::size_t m_offset {0};
            std::uint64_t m_received {0};
            std::uint64_t m_delivered {0};

            bool m_started {false};
            bool m_running {false};
            bool m_paused {false};
            bool m_failed {false};
            bool m_overLimit {false};
            bool m_abortedLocally {false};
            long m_status {0};
            std::string m_retryAfter;
            std::string m_error;
    };
} // namespace containerimages

#endif // _REGISTRY_BYTE_STREAM_HPP
