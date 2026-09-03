/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "registry_byte_stream.hpp"

#include <algorithm>
#include <cstdlib>
#include <utility>

#include <curl/curl.h>

namespace
{
    /// @brief Buffered bytes at which the transfer is suspended.
    ///
    /// Large enough that the transfer is not suspended and resumed for every tar block,
    /// small enough that a blob is never held in memory in any meaningful quantity. The
    /// whole point of streaming is that this number, not the blob size, is the memory
    /// cost of reading a layer.
    constexpr std::size_t HIGH_WATER {256 * 1024};

    /// @brief Buffered bytes at which it is resumed.
    constexpr std::size_t LOW_WATER {64 * 1024};

    /// @brief How long one wait for socket activity may last.
    constexpr int POLL_MS {200};

    /// @brief Offset past which the buffer is compacted rather than grown.
    constexpr std::size_t COMPACT_THRESHOLD {64 * 1024};
} // namespace

namespace containerimages
{
    RegistryByteStream::RegistryByteStream(TransportConfig config,
                                           std::string url,
                                           std::vector<std::string> headers,
                                           const std::uint64_t maxBytes,
                               const std::atomic<bool>* stopRequested)
        : m_config {std::move(config)}
        , m_stopRequested {stopRequested}
        , m_url {std::move(url)}
        , m_headers {std::move(headers)}
        , m_maxBytes {maxBytes}
    {
        ensureCurlInitialized();
    }

    RegistryByteStream::~RegistryByteStream()
    {
        if (m_multi != nullptr && m_handle != nullptr)
        {
            curl_multi_remove_handle(static_cast<CURLM*>(m_multi), static_cast<CURL*>(m_handle));
        }

        if (m_handle != nullptr)
        {
            curl_easy_cleanup(static_cast<CURL*>(m_handle));
        }

        if (m_multi != nullptr)
        {
            curl_multi_cleanup(static_cast<CURLM*>(m_multi));
        }

        if (m_headerList != nullptr)
        {
            curl_slist_free_all(static_cast<curl_slist*>(m_headerList));
        }
    }

    std::size_t RegistryByteStream::buffered() const
    {
        return m_buffer.size() - m_offset;
    }

    std::size_t RegistryByteStream::onWrite(char* data,
                                            const std::size_t size,
                                            const std::size_t members,
                                            void* userdata)
    {
        auto* stream {static_cast<RegistryByteStream*>(userdata)};
        const auto bytes {size * members};

        if (stream == nullptr)
        {
            return 0;
        }

        // A response that is not the blob must never be read as image data. The final
        // response's headers arrive before its body, so the status is already known here.
        if (stream->m_status != 0 && (stream->m_status < 200 || stream->m_status > 299))
        {
            stream->m_failed = true;
            stream->m_error = "the registry answered " + std::to_string(stream->m_status);

            return 0;
        }

        if (stream->m_received + bytes > stream->m_maxBytes)
        {
            // A short return aborts the transfer. The ceiling is enforced while the blob
            // is arriving, which is the only place it can be: Content-Length is the
            // image's own claim about itself.
            stream->m_overLimit = true;

            return 0;
        }

        if (stream->buffered() + bytes > HIGH_WATER)
        {
            // Not consumed. libcurl suspends the transfer and delivers this same data
            // again once the transfer is resumed, so nothing is dropped and nothing is
            // duplicated. Returning a short count here instead would abort the transfer.
            stream->m_paused = true;

            return CURL_WRITEFUNC_PAUSE;
        }

        stream->m_buffer.append(data, bytes);
        stream->m_received += bytes;

        return bytes;
    }

    std::size_t RegistryByteStream::onHeader(char* data,
                                             const std::size_t size,
                                             const std::size_t members,
                                             void* userdata)
    {
        auto* stream {static_cast<RegistryByteStream*>(userdata)};
        const auto bytes {size * members};

        if (stream == nullptr)
        {
            return bytes;
        }

        const std::string line {data, bytes};

        // Only the status line is of interest. A redirect contributes its own, and the
        // last one seen is the response whose body actually arrives.
        if (line.rfind("HTTP/", 0) == 0)
        {
            const auto firstSpace {line.find(' ')};

            if (firstSpace != std::string::npos)
            {
                stream->m_status = std::strtol(line.c_str() + firstSpace + 1, nullptr, 10);
            }
        }

        return bytes;
    }

    bool RegistryByteStream::start()
    {
        m_started = true;
        m_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds {m_config.blobTimeoutMs};

        if (m_config.caBundle.empty())
        {
            m_failed = true;
            m_error = "no certificate bundle is available, so the registry cannot be verified";

            return false;
        }

        m_multi = curl_multi_init();
        m_handle = curl_easy_init();

        if (m_multi == nullptr || m_handle == nullptr)
        {
            m_failed = true;
            m_error = "the HTTP client could not be created";

            return false;
        }

        auto* handle {static_cast<CURL*>(m_handle)};

        curl_easy_setopt(handle, CURLOPT_URL, m_url.c_str());
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, &RegistryByteStream::onWrite);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, this);
        curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, &RegistryByteStream::onHeader);
        curl_easy_setopt(handle, CURLOPT_HEADERDATA, this);

        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(handle, CURLOPT_CAINFO, m_config.caBundle.c_str());

        curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR, "https");
        curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS_STR, "https");

        // A blob request is answered with a redirect to a content host. It has to be
        // followed, and the token must not go with it: that host does not need it, the
        // URL it hands out is already signed, and sending it there would disclose the
        // credential to a third party. Off is the default; it is set anyway so the
        // decision is visible next to the redirect that makes it matter.
        curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 5L);
        curl_easy_setopt(handle, CURLOPT_UNRESTRICTED_AUTH, 0L);

        curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, m_config.connectTimeoutMs);

        // Deliberately no CURLOPT_TIMEOUT_MS: that ceiling counts wall-clock time, and
        // this transfer is suspended on purpose whenever the caller is slower than the
        // network, so it would abort a healthy read of a large layer.
        //
        // The stall detector below is not sufficient on its own either. It only fires
        // when the average rate falls below its limit, so a server trickling a couple of
        // bytes a second satisfies it indefinitely. The bound that actually holds is
        // m_deadline, checked in pump(), because a module thread that will not return
        // starves the shutdown budget shared by every module.
        curl_easy_setopt(handle, CURLOPT_LOW_SPEED_LIMIT, 1024L);
        curl_easy_setopt(handle, CURLOPT_LOW_SPEED_TIME, m_config.requestTimeoutMs / 1000);

        curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(handle, CURLOPT_USERAGENT, "Wazuh-Agent-ContainerImages");
        curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "");

        for (const auto& header : m_headers)
        {
            m_headerList = curl_slist_append(static_cast<curl_slist*>(m_headerList), header.c_str());
        }

        if (m_headerList != nullptr)
        {
            curl_easy_setopt(handle, CURLOPT_HTTPHEADER, static_cast<curl_slist*>(m_headerList));
        }

        if (curl_multi_add_handle(static_cast<CURLM*>(m_multi), handle) != CURLM_OK)
        {
            m_failed = true;
            m_error = "the transfer could not be started";

            return false;
        }

        m_running = true;

        return true;
    }

    void RegistryByteStream::pump()
    {
        // Both checks live here rather than in read(), because pump() is the only place
        // that blocks and therefore the only place a stalled transfer can be caught.
        if (m_stopRequested != nullptr && m_stopRequested->load())
        {
            m_failed = true;
            m_error = "the module was asked to stop";
            m_running = false;

            return;
        }

        if (std::chrono::steady_clock::now() > m_deadline)
        {
            m_failed = true;
            m_error = "the layer transfer exceeded its " + std::to_string(m_config.blobTimeoutMs) +
                      " millisecond limit";
            m_running = false;

            return;
        }

        auto* multi {static_cast<CURLM*>(m_multi)};

        int running {0};

        const auto result {curl_multi_perform(multi, &running)};

        if (result != CURLM_OK)
        {
            m_failed = true;
            m_error = curl_multi_strerror(result);
            m_running = false;

            return;
        }

        if (running != 0)
        {
            // Only wait when the transfer is actually waiting on the network. While it is
            // suspended there is nothing to wait for, and polling would just sleep.
            if (!m_paused)
            {
                int descriptors {0};
                curl_multi_poll(multi, nullptr, 0, POLL_MS, &descriptors);
            }

            return;
        }

        // The transfer is over. Its outcome is in the message queue, and it is the only
        // place a cURL-level failure is reported.
        m_running = false;

        CURLMsg* message {nullptr};
        int remaining {0};

        while ((message = curl_multi_info_read(multi, &remaining)) != nullptr)
        {
            if (message->msg != CURLMSG_DONE)
            {
                continue;
            }

            if (message->data.result != CURLE_OK)
            {
                m_failed = true;

                if (m_overLimit)
                {
                    m_error = "the layer exceeded the " + std::to_string(m_maxBytes) + " byte limit";
                }
                else if (m_error.empty())
                {
                    m_error = curl_easy_strerror(message->data.result);
                }
            }
        }

        if (!m_failed && (m_status < 200 || m_status > 299))
        {
            m_failed = true;
            m_error = "the registry answered " + std::to_string(m_status);
        }
    }

    std::size_t RegistryByteStream::read(char* buffer, const std::size_t size)
    {
        if (buffer == nullptr || size == 0)
        {
            return 0;
        }

        if (!m_started && !start())
        {
            return 0;
        }

        // Advance the transfer only while the caller has nothing to consume. This is what
        // makes the pull model work: a fast network does not run ahead of the parser, and
        // a slow one does not spin.
        while (buffered() == 0 && m_running && !m_failed)
        {
            pump();
        }

        if (m_failed)
        {
            return 0;
        }

        const auto available {std::min(size, buffered())};

        if (available == 0)
        {
            return 0;
        }

        std::copy_n(m_buffer.begin() + static_cast<std::string::difference_type>(m_offset), available, buffer);

        m_offset += available;
        m_delivered += available;

        // Reclaim what has been handed out rather than letting the buffer grow for the
        // length of the blob.
        if (m_offset >= COMPACT_THRESHOLD)
        {
            m_buffer.erase(0, m_offset);
            m_offset = 0;
        }

        if (m_paused && buffered() <= LOW_WATER)
        {
            m_paused = false;

            if (curl_easy_pause(static_cast<CURL*>(m_handle), CURLPAUSE_CONT) != CURLE_OK)
            {
                m_failed = true;
                m_error = "the transfer could not be resumed";
            }
        }

        return available;
    }
} // namespace containerimages
