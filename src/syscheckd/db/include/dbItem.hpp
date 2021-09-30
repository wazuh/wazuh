/*
 * Wazuh Syscheckd
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
#include "syscheck-config.h"

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

class EXPORTED DBItem {
public:
    DBItem();
    virtual ~DBItem();
    virtual fim_entry* toFimEntry() = 0;
    virtual nlohmann::json* toJSON() = 0;
    bool getState() { return m_scanned; };

protected:
    std::string             m_identifier;
    unsigned int            m_scanned;
    time_t                  m_lastEvent;
    std::string             m_checksum;
    int                     m_mode;
};
#endif //_DBITEM_HPP
