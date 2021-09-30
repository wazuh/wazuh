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
#include "syscheck.h"
#include "db_statements.hpp"


std::string createStatement()
{
    std::string ret = CREATE_FILE_DB_STATEMENT;
#ifdef WIN32
    ret += CREATE_REGISTRY_KEY_DB_STATEMENT;
    ret += CREATE_REGISTRY_VALUE_DB_STATEMENT;
#endif

    return ret;
}

void setFileLimit()
{
    m_dbsyncHandler->setTableMaxRow("file_entry", syscheck.file_limit);
}

void setRegistryLimit()
{
    m_dbsyncHandler->setTableMaxRow("registry_key", syscheck.value_limit);
}

void setValueLimit()
{
    m_dbsyncHandler->setTableMaxRow("registry_data", syscheck.value_limit);
}

void FIMDB::init(const std::string& dbPath)
{
    m_dbsyncHandler = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, dbPath, createStatement());
    m_rsyncHandler = std::make_unique<RemoteSync>();

    setFileLimit();
#ifdef WIN32
    setRegistryLimit();
    setValueLimit();
#endif
}

int insertItem(DBItem* item)
{
    assert (m_dbsyncHandler != NULL);
    assert (item != NULL);

    m_dbsyncHandler->insertData(item.toJson());
}

int removeItem(DBItem* item)
{
    assert (m_dbsyncHandler != NULL);
    assert (item != NULL);

    m_dbsyncHandler->deleteRows(item.toJson());
}

int updateItem(DBItem* item)
{
    assert (m_dbsyncHandler != NULL);
    assert (item != NULL);
    nlohmann::json ret = NULL;

    m_dbsyncHandler->updateWithSnapshot(item.toJson(), &ret);
}

void syncDB();

int setAllUnscanned();

int executeQuery();


#endif
