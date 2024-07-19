/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
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


namespace RSync
{
    constexpr auto INVALID_HANDLE
    {
        std::make_pair(1, "Invalid handle value.")
    };
    constexpr auto FACTORY_INSTANTATION
    {
        std::make_pair(2, "Unspecified type during factory instantiation")
    };
    constexpr auto INVALID_HEADER
    {
        std::make_pair(3, "Invalid message header.")
    };
    constexpr auto INVALID_OPERATION
    {
        std::make_pair(4, "Invalid message operation.")
    };
    constexpr auto UNEXPECTED_SIZE
    {
        std::make_pair(5, "Unexpected size value during sync process.")
    };
    constexpr auto ERROR_IN_SELECT_DATA
    {
        std::make_pair(6, "Error during the select of data." )
    };
    constexpr auto NOT_SPECIALIZED_FUNCTION
    {
        std::make_pair(7, "Function not specialized." )
    };
    constexpr auto INPUT_JSON_INCOMPLETE
    {
        std::make_pair(8, "Incomplete json provided." )
    };
    constexpr auto COMPONENT_ALREADY_REGISTERED
    {
        std::make_pair(9, "Component already registered." )
    };
    constexpr auto HANDLE_NOT_FOUND
    {
        std::make_pair(10, "Handle not found." )
    };

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
}// namespace RSync

#endif // _RSYNC_EXCEPTION_H
