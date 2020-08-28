/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * August 25, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RSYNC_EXCEPTION_H
#define _RSYNC_EXCEPTION_H
#include <stdexcept>
#include <string>

constexpr auto INVALID_HANDLE       { std::make_pair(1, "Invalid handle value.") };

namespace RSync
{
    /**
     *   This class should be used by concrete types to report errors.
    */
    class rsync_error : public std::exception
    {
      public:
        __attribute__((__returns_nonnull__))
        const char* what() const noexcept override
        {
            return m_error.what();
        }

        int id() const noexcept
        {
            return m_id;
        }

        rsync_error(const int id,
                    const std::string& whatArg)
        : m_id{ id }
        , m_error{ whatArg }
        {}

        explicit rsync_error(const std::pair<int, std::string>& exceptionInfo)
        : m_id{ exceptionInfo.first }
        , m_error{ exceptionInfo.second }
        {}

      private:
        /// an exception object as storage for error messages
        const int m_id;
        std::runtime_error m_error;
    };
}

#endif // _RSYNC_EXCEPTION_H