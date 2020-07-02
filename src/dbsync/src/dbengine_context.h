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

namespace DbSync
{
    class DbEngineContext
    {
    public:
        DbEngineContext(std::unique_ptr<IDbEngine>& dbengine,
                        const HostType hostType,
                        const DbEngineType dbType)
        : m_dbEngine{ std::move(dbengine) }
        , m_hostType{ hostType }
        , m_dbEngineType{ dbType }
        {}
        const std::unique_ptr<IDbEngine>& dbEngine() const
        {
            return m_dbEngine;
        }
        const HostType& hostType() const
        {
            return m_hostType;
        }
        const DbEngineType& dbEngineType() const
        {
            return m_dbEngineType;
        }
    private:
        const std::unique_ptr<IDbEngine> m_dbEngine;
        const HostType m_hostType;
        const DbEngineType m_dbEngineType;
    };
}// namespace DbSync