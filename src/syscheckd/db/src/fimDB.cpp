/*
 * Wazuh SysCollector
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 27, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _FIMDB_CPP
#define _FIMDB_CPP
#include "fimDB.hpp"
#include "dbsync.hpp"
#include "rsync.hpp"
#include "syscheck.h"
#include "db_statements.hpp"
#include "loggingHelper.h"


std::string FIMDB::createStatement()
{
    std::string ret = CREATE_FILE_DB_STATEMENT;
#ifdef WIN32
    ret += CREATE_REGISTRY_KEY_DB_STATEMENT;
    ret += CREATE_REGISTRY_VALUE_DB_STATEMENT;
#endif

    return ret;
}

void FIMDB::setFileLimit()
{
    m_dbsyncHandler->setTableMaxRow("file_entry", m_max_rows_file);
}

#ifdef WIN32
void FIMDB::setRegistryLimit()
{
    m_dbsyncHandler->setTableMaxRow("registry_key", m_max_rows_registry);
}

void FIMDB::setValueLimit()
{
    m_dbsyncHandler->setTableMaxRow("registry_data", m_max_rows_registry);
}
#endif

#ifdef WIN32
void FIMDB::init(const std::string& dbPath, const unsigned int interval_synchronization, const unsigned int max_rows_file, const unsigned int max_rows_registry)
#else
void FIMDB::init(const std::string& dbPath, const unsigned int interval_synchronization, const unsigned int max_rows_file)
#endif
{
    m_interval_synchronization = interval_synchronization
    m_max_rows_file = max_rows_file;
#ifdef WIN32
    m_max_rows_registry = max_rows_registry;
#endif
    m_dbsyncHandler = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, dbPath, createStatement());
    m_rsyncHandler = std::make_unique<RemoteSync>();

    setFileLimit();
#ifdef WIN32
    setRegistryLimit();
    setValueLimit();
#endif
}

int FIMDB::insertItem(DBItem const &item)
{
    try
    {
        m_dbsyncHandler->insertData(item.toJson());
    }
    catch(const DbSync::max_rows_error &ex)
    {
        loggingFunction(LOG_INFO, ex.what());
        return 1;
    }
    catch(const std::exception &ex)
    {
        loggingFunction(LOG_ERROR, ex.what());
        return 2;
    }

    return 0;
}

int FIMDB::removeItem(DBItem const &item)
{
    try
    {
        m_dbsyncHandler->deleteRows(item.toJson());
    }
    catch(const DbSync::max_rows_error &ex)
    {
        loggingFunction(LOG_INFO, ex.what());
        return 1;
    }
    catch(const std::exception &ex)
    {
        loggingFunction(LOG_ERROR, ex.what());
        return 2;
    }

    return 0;
}

int FIMDB::updateItem(DBItem const &item, ResultCallbackData callbackData)
{
    try
    {
        m_dbsyncHandler->syncRow(item.toJson(), callbackData);
    }
    catch(const DbSync::max_rows_error &ex)
    {
        loggingFunction(LOG_INFO, ex.what());
        return 1;
    }
    catch(const std::exception &ex)
    {
        loggingFunction(LOG_ERROR, ex.what());
        return 2;
    }

    return 0;
}

void FIMDB::registerRsync()
{
}

void FIMDB::loopRsync()
{
}

#endif
