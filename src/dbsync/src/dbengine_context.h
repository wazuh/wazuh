/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once
#include <memory>
#include <atomic>
#include "dbengine.h"
#include "typedef.h"

class DbEngineContext {
public:
  DbEngineContext(
    std::unique_ptr<DbEngine>& dbengine, 
    const HostType host_type, 
    const DbEngineType db_type) : 
    m_dbengine(std::move(dbengine)),
    m_host_type(host_type),
    m_dbengine_type(db_type) {}

  const std::unique_ptr<DbEngine>& GetDbEngine() const { return m_dbengine; }
  const HostType& GetHostType() const { return m_host_type; }
  const DbEngineType& GetDbEngineType() const { return m_dbengine_type; }
private:
  const std::unique_ptr<DbEngine> m_dbengine;
  const HostType m_host_type;
  const DbEngineType m_dbengine_type;
};