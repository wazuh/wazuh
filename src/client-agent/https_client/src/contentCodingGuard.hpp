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
 * @brief Holds a reply to one of the codings its request offered (#38514).
 *
 * Once CURLOPT_ACCEPT_ENCODING is set, libcurl decodes any coding it was built with, offered or
 * not, and stacks one decoder per coding the reply lists, each zstd decoder with its own window
 * of up to 128 MiB. Fed the reply's Content-Encoding lines, this admits a single offered coding
 * ("identity" aside), so one reply costs at most one decoder.
 */
class ContentCodingGuard final
{
    public:
        /// @param offered The request's Accept-Encoding, a comma-separated list of codings.
        explicit ContentCodingGuard(std::string offered);

        /// Feeds the value of one Content-Encoding header line.
        /// @return false once the reply has named a second coding, or one that wasn't offered.
        bool admit(std::string_view value);

        /// The Content-Encoding value admit() refused, empty while it refused none.
        const std::string& refused() const;

    private:
        bool admitCoding(std::string_view coding);
        bool offers(std::string_view coding) const;

        std::string m_offered;
        size_t m_codings {0};
        std::string m_refused;
};

#endif // _HC_CONTENT_CODING_GUARD_HPP
