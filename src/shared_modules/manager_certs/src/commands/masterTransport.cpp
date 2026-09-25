/*
 * Wazuh manager certs tool - the master fetch, over libcurl
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "masterTransport.hpp"

#include <curl/curl.h>

#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace manager_certs
{
    namespace
    {
        /// Where the body is accumulated, with the cap it may not cross.
        struct BodySink
        {
            std::string* body {nullptr};
            std::size_t limit {0};
            bool overflow {false}; ///< A chunk was dropped for crossing the cap.
        };

        /// Where the one header we care about is kept, plus the name to match.
        struct HeaderSink
        {
            std::string name;                            ///< Matched case-insensitively (RFC 9110).
            std::optional<std::string>* value {nullptr}; ///< Of the LAST response seen (C39a, §4).
        };

        bool equalsIgnoreCase(std::string_view left, std::string_view right)
        {
            if (left.size() != right.size())
            {
                return false;
            }
            for (std::size_t index = 0; index < left.size(); ++index)
            {
                const char leftByte = static_cast<char>(
                    (left[index] >= 'A' && left[index] <= 'Z') ? left[index] - 'A' + 'a' : left[index]);
                const char rightByte = static_cast<char>(
                    (right[index] >= 'A' && right[index] <= 'Z') ? right[index] - 'A' + 'a' : right[index]);
                if (leftByte != rightByte)
                {
                    return false;
                }
            }
            return true;
        }

        /// Optional whitespace around a field value (RFC 9110 §5.5), and the line's own CRLF.
        std::string_view trimFieldValue(std::string_view value)
        {
            const auto isSpace = [](char byte)
            {
                return byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n';
            };
            while (!value.empty() && isSpace(value.front()))
            {
                value.remove_prefix(1);
            }
            while (!value.empty() && isSpace(value.back()))
            {
                value.remove_suffix(1);
            }
            return value;
        }

        /**
         * @brief The cap, checked BEFORE the chunk is appended (C39c, §6).
         *
         * libcurl hands over whole chunks and there is no way to ask for part of one, so the only
         * place the limit can be honoured exactly is here: a chunk that would cross it is dropped
         * WHOLE and the transfer aborted (returning a count different from the one received is
         * libcurl's abort signal, CURLE_WRITE_ERROR). Never one byte past the cap in the buffer,
         * and never a truncated bundle mistaken for a small one.
         */
        std::size_t collectBody(char* data, std::size_t size, std::size_t items, void* userdata)
        {
            auto* sink = static_cast<BodySink*>(userdata);
            if (sink == nullptr || sink->body == nullptr)
            {
                return 0; // Aborts: without a sink there is nowhere to put this safely.
            }

            const std::size_t bytes = size * items;
            if (bytes == 0)
            {
                return 0; // Nothing offered, nothing consumed: not an abort.
            }
            if (bytes > sink->limit - sink->body->size())
            {
                sink->overflow = true;
                return 0;
            }

            sink->body->append(data, bytes);
            return bytes;
        }

        /**
         * @brief Keeps the generation header of the LAST response seen (C39a, §4).
         *
         * A proxy's `CONNECT` answer, or any other intermediate response, carries its own header
         * block, and a value taken from one of those would be a number this master never
         * announced -- one that, being arbitrarily large, would lock this node out of every
         * legitimate publication afterwards by the monotonicity rule. Proxies are off and redirects
         * are not followed, so there should only ever be one response here; resetting on every new
         * status line is what makes that true instead of assumed.
         */
        std::size_t collectHeader(char* data, std::size_t size, std::size_t items, void* userdata)
        {
            const std::size_t bytes = size * items;
            auto* sink = static_cast<HeaderSink*>(userdata);
            if (sink == nullptr || sink->value == nullptr)
            {
                return bytes; // Nothing to collect into; the transfer itself is still fine.
            }

            std::string_view line {data, bytes};
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            {
                line.remove_suffix(1);
            }

            if (line.size() >= 5 && equalsIgnoreCase(line.substr(0, 5), "HTTP/"))
            {
                sink->value->reset();
                return bytes;
            }

            const auto colon = line.find(':');
            if (colon == std::string_view::npos)
            {
                return bytes;
            }
            if (!equalsIgnoreCase(line.substr(0, colon), sink->name))
            {
                return bytes;
            }

            *sink->value = std::string {trimFieldValue(line.substr(colon + 1))};
            return bytes;
        }

        CURL* realInit()
        {
            // Explicit and checked, rather than left to curl_easy_init()'s implicit one: a failed
            // global init is the one way a handle can come back usable with its TLS backend not
            // started.
            if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
            {
                return nullptr;
            }
            return curl_easy_init();
        }

        /// The port with every empty field filled in with the real libcurl call.
        CurlPort effectivePort(CurlPort port)
        {
            if (!port.init)
            {
                port.init = &realInit;
            }
            if (!port.setLong)
            {
                port.setLong = [](CURL* handle, CURLoption option, long value)
                {
                    return curl_easy_setopt(handle, option, value);
                };
            }
            if (!port.setPointer)
            {
                port.setPointer = [](CURL* handle, CURLoption option, const void* value)
                {
                    return curl_easy_setopt(handle, option, value);
                };
            }
            if (!port.setCallback)
            {
                port.setCallback = [](CURL* handle, CURLoption option, curl_write_callback value)
                {
                    return curl_easy_setopt(handle, option, value);
                };
            }
            if (!port.perform)
            {
                port.perform = [](CURL* handle)
                {
                    return curl_easy_perform(handle);
                };
            }
            if (!port.getLong)
            {
                port.getLong = [](CURL* handle, CURLINFO info, long* value)
                {
                    return curl_easy_getinfo(handle, info, value);
                };
            }
            if (!port.cleanup)
            {
                port.cleanup = [](CURL* handle)
                {
                    curl_easy_cleanup(handle);
                };
            }
            return port;
        }

        /// Closes the handle however the port says to, on every path out.
        class HandleGuard
        {
        public:
            HandleGuard(CURL* handle, const std::function<void(CURL*)>& cleanup)
                : m_handle {handle}
                , m_cleanup {cleanup}
            {
            }
            HandleGuard(const HandleGuard&) = delete;
            HandleGuard& operator=(const HandleGuard&) = delete;
            ~HandleGuard()
            {
                if (m_handle != nullptr && m_cleanup)
                {
                    m_cleanup(m_handle);
                }
            }

        private:
            CURL* m_handle;
            const std::function<void(CURL*)>& m_cleanup;
        };

        MasterFetchResult fetch(const CurlPort& port, const MasterFetch& request)
        {
            MasterFetchResult result;

            CURL* handle = port.init();
            if (handle == nullptr)
            {
                result.failure = MasterFetchFailure::preparation;
                result.message = "libcurl could not be initialised";
                return result;
            }
            const HandleGuard guard {handle, port.cleanup};

            std::string body;
            BodySink bodySink {&body, request.maxBodyBytes, false};
            HeaderSink headerSink {request.headerName, &result.generation};

            curl_blob trustBlob {};
            trustBlob.data = const_cast<char*>(request.trustBundle.data());
            trustBlob.len = request.trustBundle.size();
            trustBlob.flags = CURL_BLOB_COPY;

            // One place to fail, so no option can ever be set without its return being looked at
            // (C39a): the first refusal ends the run with the option named, and nothing is sent.
            std::string refusal;
            const auto check = [&refusal](const char* option, CURLcode code)
            {
                if (code == CURLE_OK)
                {
                    return true;
                }
                if (refusal.empty())
                {
                    refusal = std::string {"cannot pin "} + option + ": libcurl refused it (CURLcode " +
                              std::to_string(static_cast<int>(code)) + ", " + curl_easy_strerror(code) + ")";
                }
                return false;
            };

            const bool prepared =
                check("CURLOPT_URL", port.setPointer(handle, CURLOPT_URL, request.url.c_str())) &&
                // The local bundle, and nothing else, decides what this connection trusts (CA-33).
                check("CURLOPT_CAINFO_BLOB", port.setPointer(handle, CURLOPT_CAINFO_BLOB, &trustBlob)) &&
                // Cleared, not merely unset: on a build whose configure found a system CA directory
                // it is a trust source of its own, which the blob does not replace (§3).
                check("CURLOPT_CAPATH", port.setPointer(handle, CURLOPT_CAPATH, nullptr)) &&
                check("CURLOPT_SSL_VERIFYPEER", port.setLong(handle, CURLOPT_SSL_VERIFYPEER, 1L)) &&
                check("CURLOPT_SSL_VERIFYHOST", port.setLong(handle, CURLOPT_SSL_VERIFYHOST, 2L)) &&
                // No inherited https_proxy/ALL_PROXY: an intermediate's own response could carry a
                // generation header of its own (§4).
                check("CURLOPT_PROXY", port.setPointer(handle, CURLOPT_PROXY, "")) &&
                check("CURLOPT_FOLLOWLOCATION", port.setLong(handle, CURLOPT_FOLLOWLOCATION, 0L)) &&
                check("CURLOPT_TIMEOUT", port.setLong(handle, CURLOPT_TIMEOUT, request.timeoutSeconds)) &&
                check("CURLOPT_WRITEFUNCTION", port.setCallback(handle, CURLOPT_WRITEFUNCTION, &collectBody)) &&
                check("CURLOPT_WRITEDATA", port.setPointer(handle, CURLOPT_WRITEDATA, &bodySink)) &&
                check("CURLOPT_HEADERFUNCTION", port.setCallback(handle, CURLOPT_HEADERFUNCTION, &collectHeader)) &&
                check("CURLOPT_HEADERDATA", port.setPointer(handle, CURLOPT_HEADERDATA, &headerSink));

            if (!prepared)
            {
                result.failure = MasterFetchFailure::preparation;
                result.message = refusal;
                result.generation.reset();
                return result;
            }

            const CURLcode performed = port.perform(handle);
            if (performed != CURLE_OK)
            {
                result.failure = MasterFetchFailure::transfer;
                result.message = bodySink.overflow ? "the master's answer is larger than the " +
                                                         std::to_string(request.maxBodyBytes) + " byte cap"
                                                   : std::string {curl_easy_strerror(performed)} + " (CURLcode " +
                                                         std::to_string(static_cast<int>(performed)) + ")";
                result.generation.reset();
                return result;
            }

            long status = 0;
            if (port.getLong(handle, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK)
            {
                result.failure = MasterFetchFailure::transfer;
                result.message = "libcurl could not report the response code";
                result.generation.reset();
                return result;
            }
            result.httpStatus = status;

            // Only a 200 from the final response counts (C39b): libcurl reports a 302, a 206 or a
            // 500 as a successful transfer, and their body -- and any header they carry -- must
            // never be read as a published bundle. GET /cacerts publishes only as 200
            // (src/remoted/remoted_module/src/endpoints/cacertsEndpoint.cpp:62).
            if (status != 200)
            {
                result.failure = MasterFetchFailure::transfer;
                result.message = "the master answered HTTP " + std::to_string(status) + ", not 200";
                result.generation.reset();
                return result;
            }

            result.body = std::move(body);
            return result;
        }
    } // namespace

    MasterTransport curlMasterTransport(CurlPort port)
    {
        MasterTransport transport;
        transport.get = [effective = effectivePort(std::move(port))](const MasterFetch& request)
        {
            return fetch(effective, request);
        };
        return transport;
    }

} // namespace manager_certs
