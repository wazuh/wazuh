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

#ifndef _DBITEMWRAPPER_HPP
#define _DBITEMWRAPPER_HPP
#include "fim_db.hpp"
#include "db_item.hpp"
#include "shared.h"

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

class EXPORTED DBItemWrapper {
    public:
        DBItemWrapper();
        ~DBItemWrapper();
        int setAllScanned();
        int setScanned();
        int removeFromDB(DBItem*);
        int insertItem(DBItem*);
        bool isFull();
        int getCount(std::string identifier);
        int getDataChecksum(std::string);
        int getChecksumRange();
        fim_entry* getEntryFromSyncMsg(std::string);
        int getPath(std::string identifier);
        int getNotScanned();
        std::vector<DBItem*> getDBItem(std::string identifier);
        std::vector<DBItem*> getFromPattern(std::string pattern);
        int updateItem(DBItem*);
    private:
        FIMDB m_fim_db;
}
#endif //_DBITEMWRAPPER_HPP
