/**
 * @file db_item.hpp
 * @brief
 * @date 2021-09-22
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef _DBITEM_HPP
#define _DBITEM_HPP
#include "shared.h"

class DBItem {
public:
    virtual fim_entry* toFimEntry() = 0;
    virtual nlohmann::json* toJSON() = 0;
    bool getState() { return m_scanned; };

protected:
    std::string m_identifier;
    bool m_scanned;
    time_t m_lastEvent;
    std::string m_checksum;
    int mode;

}
#endif //_DBITEM_HPP