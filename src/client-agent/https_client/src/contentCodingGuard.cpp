/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "contentCodingGuard.hpp"
#include "headerField.hpp"

#include <algorithm>
#include <cctype>

namespace
{
    constexpr std::string_view SPACE {" \t\r\n"};
    constexpr std::string_view BLANK {" \t"};
    constexpr std::string_view HTTP_PREFIX {"HTTP/"};
    constexpr std::string_view CONTENT_ENCODING {"Content-Encoding"};
    /// A coding is a short token: past this, a refused value is the peer's noise, not information.
    constexpr size_t REFUSAL_EXCERPT {64};

    std::string_view trimmed(std::string_view text)
    {
        const auto begin = text.find_first_not_of(SPACE);
        return begin == std::string_view::npos ? std::string_view {} :
               text.substr(begin, text.find_last_not_of(SPACE) - begin + 1);
    }

    /// A coding as curl names it (content_encoding.c, Curl_build_unencoding_stack): without the bytes
    /// around it that can't belong to a token. curl trims control bytes and spaces, so a token made
    /// only of them names nothing; a byte past ASCII never names a coding curl decodes.
    std::string_view codingName(std::string_view token)
    {
        const auto outside = [](char byte)
        {
            const auto value = static_cast<unsigned char>(byte);
            return value <= 0x20 || value >= 0x7f;
        };
        const auto begin = std::find_if_not(token.begin(), token.end(), outside);
        const auto end = std::find_if_not(token.rbegin(), token.rend(), outside).base();
        return begin < end ? token.substr(static_cast<size_t>(begin - token.begin()), static_cast<size_t>(end - begin)) :
               std::string_view {};
    }

    bool blankAt(std::string_view text, size_t at)
    {
        return at < text.size() && BLANK.find(text[at]) != std::string_view::npos;
    }

    /// The three digits `text` starts with, as a number; 0 if it doesn't start with three.
    long threeDigitCode(std::string_view text)
    {
        if (text.size() < 3)
        {
            return 0;
        }

        long code = 0;

        for (const char digit : text.substr(0, 3))
        {
            if (!std::isdigit(static_cast<unsigned char>(digit)))
            {
                return 0;
            }

            code = code * 10 + (digit - '0');
        }

        return code;
    }

    /// After "HTTP/": "1.0" or "1.1", one space or tab, three digits.
    long http1Code(std::string_view version)
    {
        const bool known = version.size() > 3 && version[0] == '1' && version[1] == '.' &&
                           (version[2] == '0' || version[2] == '1') && blankAt(version, 3);
        return known ? threeDigitCode(version.substr(4)) : 0;
    }

    /// After "HTTP/": "2" or "3", one space or tab, three digits and a space or tab. Over HTTP/2 and
    /// HTTP/3 curl writes the status line itself, as "HTTP/2 200 \r\n" (http2.c, vquic/curl_ngtcp2.c).
    long http2Or3Code(std::string_view version)
    {
        const bool known = !version.empty() && (version[0] == '2' || version[0] == '3') && blankAt(version, 1) &&
                           blankAt(version, 5);
        return known ? threeDigitCode(version.substr(2)) : 0;
    }

    /// The status code of a status line read the way curl 8.20 reads it (http.c, http_rw_hd). 0 for
    /// anything else, which curl either refuses or reports as a 200: a response with a body either way.
    long statusCode(std::string_view line)
    {
        if (line.substr(0, HTTP_PREFIX.size()) != HTTP_PREFIX)
        {
            return 0;
        }

        const auto version = line.substr(HTTP_PREFIX.size());
        const long http1 = http1Code(version);
        return http1 != 0 ? http1 : http2Or3Code(version);
    }

    /// The empty line that ends a header block, as curl tells it apart (http.c, http_rw_hd).
    bool endsBlock(std::string_view line)
    {
        return line.empty() || line.front() == '\r' || line.front() == '\n';
    }

    /// Calls `visit` with every non-empty coding of a comma-separated list, until it returns false.
    /// @return false if `visit` did.
    template<typename Visit>
    bool everyCoding(std::string_view list, Visit visit)
    {
        for (;;)
        {
            const auto comma = list.find(',');
            const auto coding = codingName(list.substr(0, comma));

            if (!coding.empty() && !visit(coding))
            {
                return false;
            }

            if (comma == std::string_view::npos)
            {
                return true;
            }

            list.remove_prefix(comma + 1);
        }
    }

    /// `value` as a refusal note may show it: at most REFUSAL_EXCERPT bytes, each byte outside printable
    /// ASCII as \xHH, and "..." when cut, since a peer can fill a header with terminal escapes.
    std::string refusalExcerpt(std::string_view value)
    {
        static constexpr char HEX[] = "0123456789abcdef";
        std::string shown;

        for (const unsigned char byte : value.substr(0, REFUSAL_EXCERPT))
        {
            if (byte >= 0x20 && byte < 0x7f)
            {
                shown += static_cast<char>(byte);
            }
            else
            {
                shown += {'\\', 'x', HEX[byte >> 4], HEX[byte & 0x0f]};
            }
        }

        return value.size() > REFUSAL_EXCERPT ? shown + "..." : shown;
    }
} // namespace

bool ContentCodingGuard::admitHeader(std::string_view line) noexcept
{
    if (m_expecting == Expecting::Trailers)
    {
        return true; // curl builds no decoder from a chunked trailer.
    }

    if (endsBlock(line))
    {
        m_expecting = m_informational ? Expecting::StatusLine : Expecting::Trailers;
        return true;
    }

    if (m_expecting == Expecting::StatusLine)
    {
        startResponse(line);
        return true;
    }

    const auto codings = headerValue(line, CONTENT_ENCODING);
    return !codings || admitCodings(*codings);
}

bool ContentCodingGuard::refused() const noexcept
{
    return m_refused;
}

const std::string& ContentCodingGuard::refusalNote() const
{
    return m_refusalNote;
}

void ContentCodingGuard::startResponse(std::string_view statusLine) noexcept
{
    const long code = statusCode(statusLine);
    m_informational = code >= 100 && code < 200;
    m_bodyless = m_informational || code == 204 || code == 304;
    m_codings = 0;
    m_expecting = Expecting::Headers;
}

bool ContentCodingGuard::admitCodings(std::string_view value) noexcept
{
    if (m_bodyless)
    {
        return true;
    }

    const bool admitted = everyCoding(value, [this](std::string_view coding)
    {
        return admitCoding(coding);
    });

    if (!admitted)
    {
        noteRefused(value);
    }

    return admitted;
}

bool ContentCodingGuard::admitCoding(std::string_view coding) noexcept
{
    // curl's identity writer, under either name, passes the body through: it costs no window.
    return sameToken(coding, "identity") || sameToken(coding, "none") || ++m_codings == 1;
}

void ContentCodingGuard::noteRefused(std::string_view value) noexcept
{
    m_refused = true;

    try
    {
        m_refusalNote = "; refused Content-Encoding '" + refusalExcerpt(trimmed(value)) + "': more than one coding";
    }
    catch (...)
    {
        m_refusalNote.clear(); // LCOV_EXCL_LINE: allocation failure; refused() still says so.
    }
}
