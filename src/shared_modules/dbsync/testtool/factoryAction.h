/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
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
            if (0 == actionCode.compare("dbsync_insert_data"))
            {
                return std::make_unique<InsertDataAction>();
            }

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
            else if (0 == actionCode.compare("dbsync_get_deleted_rows"))
            {
                return std::make_unique<GetDeletedRowsAction>();
            }
            else if (0 == actionCode.compare("dbsync_sync_row"))
            {
                return std::make_unique<SyncRowAction>();
            }
            else if (0 == actionCode.compare("dbsync_sync_txn_row"))
            {
                return std::make_unique<SyncTxnRowsAction>();
            }
            else if (0 == actionCode.compare("dbsync_delete_rows"))
            {
                return std::make_unique<DeleteRowsAction>();
            }
            else if (0 == actionCode.compare("dbsync_select_rows"))
            {
                return std::make_unique<SelectRowsAction>();
            }
            else if (0 == actionCode.compare("dbsync_add_table_relationship"))
            {
                return std::make_unique<AddTableRelationship>();
            }
            // C++ Interface
            else if (0 == actionCode.compare("insertData"))
            {
                return std::make_unique<InsertDataCPP>();
            }
            else if (0 == actionCode.compare("updateWithSnapshot"))
            {
                return std::make_unique<UpdateWithSnapshotActionCPP>();
            }
            else if (0 == actionCode.compare("createTxn"))
            {
                return std::make_unique<CreateTransactionActionCPP>();
            }
            else if (0 == actionCode.compare("setTableMaxRows"))
            {
                return std::make_unique<SetMaxRowsActionCPP>();
            }
            else if (0 == actionCode.compare("addTableRelationship"))
            {
                return std::make_unique<AddTableRelationshipCPP>();
            }
            else if (0 == actionCode.compare("getDeletedRows"))
            {
                return std::make_unique<GetDeletedRowsActionCPP>();
            }
            else if (0 == actionCode.compare("syncRow"))
            {
                return std::make_unique<SyncRowActionCPP>();
            }
            else if (0 == actionCode.compare("syncTxnRow"))
            {
                return std::make_unique<SyncTxnRowsActionCPP>();
            }
            else if (0 == actionCode.compare("deleteRows"))
            {
                return std::make_unique<DeleteRowsActionCPP>();
            }
            else if (0 == actionCode.compare("selectRows"))
            {
                return std::make_unique<SelectRowsActionCPP>();
            }
            else
            {
                throw std::runtime_error { "Invalid action: " + actionCode };
            }
        }
};

#endif //_FACTORY_ACTION_H