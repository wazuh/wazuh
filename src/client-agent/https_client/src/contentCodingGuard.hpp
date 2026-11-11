/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CONTENT_CODING_GUARD_HPP
#define _HC_CONTENT_CODING_GUARD_HPP

#include <cstddef>
#include <string>
#include <string_view>

/**
 * @brief Holds a reply to a single content coding (#38514).
 *
 * Once CURLOPT_ACCEPT_ENCODING is set, libcurl builds one decoder per coding a reply's
 * Content-Encoding lines list (up to four), and each zstd decoder gets its own window of up to
 * 128 MiB once the body arrives. Shown the reply's header lines, this admits one coding for the
 * final response ("identity" aside) and refuses a second, so one reply costs at most one window;
 * a refused line has already had its decoders built, without windows. Like curl, it reads only the
 * first line of a header block as a status line, ignores the codings of a response that carries no
 * body (1xx, 204, 304), and builds nothing from the trailers that follow a chunked body.
 */
class ContentCodingGuard final
{
    public:
        /// Shows it one header line as curl hands it over, CRLF included.
        /// @return false once the final response has named a second coding.
        bool admitHeader(std::string_view line) noexcept;

        /// Whether admitHeader() refused the reply.
        bool refused() const noexcept;

        /// Says what was refused, for a log line ("; refused Content-Encoding '...': ..."), with the
        /// peer's bytes cut short and escaped. Empty while nothing was refused.
        const std::string& refusalNote() const;

    private:
        void startResponse(std::string_view statusLine) noexcept;
        bool admitCodings(std::string_view value) noexcept;
        bool admitCoding(std::string_view coding) noexcept;
        void noteRefused(std::string_view value) noexcept;

        /// Where the next header line falls: a block's status line, one of its headers, or a trailer.
        enum class Expecting
        {
            StatusLine,
            Headers,
            Trailers
        };

        Expecting m_expecting {Expecting::StatusLine};
        bool m_informational {false};
        bool m_bodyless {false};
        size_t m_codings {0};
        bool m_refused {false};
        std::string m_refusalNote;
};

#endif // _HC_CONTENT_CODING_GUARD_HPP
