/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "compressingResponder.hpp"

#include "compressingByteSource.hpp"

#include <cctype>
#include <utility>

namespace
{
    bool isOws(char c)
    {
        return c == ' ' || c == '\t';
    }

    std::string_view trimOws(std::string_view value)
    {
        while (!value.empty() && isOws(value.front()))
        {
            value.remove_prefix(1);
        }
        while (!value.empty() && isOws(value.back()))
        {
            value.remove_suffix(1);
        }
        return value;
    }

    bool ciEqualsAscii(std::string_view a, std::string_view b)
    {
        if (a.size() != b.size())
        {
            return false;
        }
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            {
                return false;
            }
        }
        return true;
    }

    /// Whether an element's parameters carry q=0 (any of "0", "0.0", "0.00", "0.000"), which per
    /// RFC 9110 means "not acceptable". Anything unparseable counts as acceptable: the only client
    /// is our own agent, and a garbled q must not silently disable the feature fleet-wide.
    bool qualityIsZero(std::string_view params)
    {
        while (!params.empty())
        {
            const auto next = params.find(';');
            auto param = trimOws(params.substr(0, next));
            params = next == std::string_view::npos ? std::string_view {} : params.substr(next + 1);

            const auto equals = param.find('=');
            if (equals == std::string_view::npos)
            {
                continue;
            }
            const auto name = trimOws(param.substr(0, equals));
            const auto value = trimOws(param.substr(equals + 1));
            if (!ciEqualsAscii(name, "q"))
            {
                continue;
            }

            // qvalue grammar: 0 [ "." 0*3DIGIT ] -- zero iff it starts with '0' and every digit
            // after the optional dot is also '0'.
            if (value.empty() || value.front() != '0')
            {
                return false;
            }
            for (const char c : value.substr(1))
            {
                if (c != '.' && c != '0')
                {
                    return false;
                }
            }
            return true;
        }
        return false;
    }
} // namespace

namespace remoted::http
{

    bool acceptsZstdResponseEncoding(std::string_view acceptEncoding)
    {
        while (!acceptEncoding.empty())
        {
            const auto next = acceptEncoding.find(',');
            auto element = acceptEncoding.substr(0, next);
            acceptEncoding = next == std::string_view::npos ? std::string_view {} : acceptEncoding.substr(next + 1);

            const auto semicolon = element.find(';');
            const auto token = trimOws(element.substr(0, semicolon));
            const auto params =
                semicolon == std::string_view::npos ? std::string_view {} : element.substr(semicolon + 1);

            if (ciEqualsAscii(token, "zstd") && !qualityIsZero(params))
            {
                return true;
            }
        }
        return false;
    }

    ZstdCompressingResponder::ZstdCompressingResponder(std::shared_ptr<IHttpResponder> inner, InFlightBudget* budget)
        : m_inner {std::move(inner)}
        , m_budget {budget}
    {
    }

    void ZstdCompressingResponder::send(HttpResponse response)
    {
        m_inner->send(std::move(response));
    }

    void ZstdCompressingResponder::stream(StreamResponse response)
    {
        // A null source is the inner responder's programming-error path (it answers 500); opting
        // out (compressible=false) and a missing budget both mean "serve plain exactly as today".
        if (!response.compressible || !response.source || m_budget == nullptr)
        {
            m_inner->stream(std::move(response));
            return;
        }

        // The compressor's working memory is auxiliary to an already-admitted request: a refusal
        // is not a shed, it just downgrades this response to plain (the agent handles plain
        // responses regardless -- that is what makes the degradation free).
        auto reservation = m_budget->tryReserveUncounted(ZstdCompressingByteSource::workingMemoryBytes());
        if (!reservation)
        {
            m_inner->stream(std::move(response));
            return;
        }

        // Wrap into a local first: if constructing the compressor throws, the original source is
        // still intact to serve the response plain.
        std::shared_ptr<IByteSource> wrapped;
        try
        {
            wrapped = std::make_shared<ZstdCompressingByteSource>(response.source, std::move(*reservation));
        }
        catch (...)
        {
            m_inner->stream(std::move(response));
            return;
        }

        response.source = std::move(wrapped);
        response.headers.emplace_back("Content-Encoding", "zstd");
        m_inner->stream(std::move(response));
    }

} // namespace remoted::http
