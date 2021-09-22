/**
 * @file db_fim_db_wrapper.hpp
 * @brief 
 * @date 2021-09-22
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef _DBITEMWRAPPER_HPP
#define _DBITEMWRAPPER_HPP
#include "fim_db.hpp"
#include "fim_item.hpp"
#include "shared.h"

class DBItemWrapper {
    public:
        DBItemWrapper();
        ~DBItemWrapper();
        int setAllScanned();
        int setScanned();
        int removeFromDB(DBItem);
        int insertItem(DBItem);
        bool isFull();
        int getCount(std::string identifier);
        int getDataChecksum(std::string);
        int getChecksumRange();
        fim_entry* getEntryFromSyncMsg(std::string);
        int getPath(std::string identifier);
        int getNotScanned();
        std::vector<DBItem> getDBItem(std::string identifier);
        std::vector<DBItem> getFromPattern(std::string pattern);
        int updateItem(DBItem);
    private:
        FimDB m_fim_db;
}
#endif //_DBITEMWRAPPER_HPP