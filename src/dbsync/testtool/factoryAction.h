/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 21, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_ACTION_H
#define _FACTORY_ACTION_H
#include <iostream>
#include <memory>

class FactoryAction
{
public:
    static std::unique_ptr<IAction> create(const std::string& actionCode)
    {
        if (0 == actionCode.compare("dbsync_update_with_snapshot"))
        {
            return std::make_unique<UpdateWithSnapshotAction>();
        }
        else if (0 == actionCode.compare("dbsync_create_txn"))
        {
            return std::make_unique<CreateTransactionAction>();
        }
        else if (0 == actionCode.compare("dbsync_close_txn"))
        {
            return std::make_unique<CloseTransactionAction>();
        }
        else if (0 == actionCode.compare("dbsync_set_table_max_rows"))
        {
            return std::make_unique<SetMaxRowsAction>();
        }
        else if (0 == actionCode.compare("dbsync_sync_row"))
        {
            return std::make_unique<SyncRowAction>();
        }
        else
        {
            throw std::runtime_error { "Invalid action: " + actionCode };
        }
    }
};

#endif //_FACTORY_ACTION_H