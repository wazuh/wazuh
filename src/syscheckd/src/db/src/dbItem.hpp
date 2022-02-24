/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DBITEM_HPP
#define _DBITEM_HPP
#include "syscheck.h"
#include "json.hpp"
#ifdef WIN32
#include "encodingWindowsHelper.h"
#endif

class DBItem
{
    public:
        DBItem(const std::string& identifier,
               const unsigned int& scanned,
               const time_t& lastEvent,
               const std::string& checksum,
               const fim_event_mode& mode)
            : m_identifier( identifier )
            , m_scanned( scanned )
            , m_lastEvent( lastEvent )
            , m_checksum( checksum )
            , m_mode( mode )
        {
#ifdef WIN32
            m_identifier = Utils::EncodingWindowsHelper::stringAnsiToStringUTF8(m_identifier);
#endif
        }

        // LCOV_EXCL_START
        virtual ~DBItem() = default;
        // LCOV_EXCL_STOP
        virtual fim_entry* toFimEntry() = 0;
        virtual const nlohmann::json* toJSON() const = 0;
        bool state()
        {
            return m_scanned;
        };

    protected:
        std::string             m_identifier;
        unsigned int            m_scanned;
        time_t                  m_lastEvent;
        std::string             m_checksum;
        fim_event_mode          m_mode;
        bool                    m_oldData;
};
#endif //_DBITEM_HPP
