/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DBITEM_HPP
#define _DBITEM_HPP
#include "fimDBSpecialization.h"
#include "json.hpp"
#include "syscheck.h"

class DBItem
{
public:
    DBItem(const std::string& identifier, const std::string& checksum)
        : m_identifier(identifier)
        , m_checksum(checksum)
    {
        FIMDBCreator<OS_TYPE>::encodeString(m_identifier);
        m_oldData = false;
    }

    // LCOV_EXCL_START
    virtual ~DBItem() = default;
    // LCOV_EXCL_STOP
    virtual fim_entry* toFimEntry() = 0;
    virtual const nlohmann::json* toJSON() const = 0;

protected:
    std::string m_identifier;
    std::string m_checksum;
    bool m_oldData;
};
#endif //_DBITEM_HPP
