/*
 * Wazuh Syscheck - Test tool
 * Copyright (C) 2015, Wazuh Inc.
 * January 23, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_ACTION_H
#define _FACTORY_ACTION_H
#include <memory>
#include "action.h"

class FactoryAction
{
    public:
        static std::unique_ptr<IAction> create(const std::string& actionCode)
        {
            if (0 == actionCode.compare("RemoveFile"))
            {
                return std::make_unique<RemoveFileAction>();
            }
            else if (0 == actionCode.compare("GetFile"))
            {
                return std::make_unique<GetFileAction>();
            }
            else if (0 == actionCode.compare("CountEntries"))
            {
                return std::make_unique<CountEntriesAction>();
            }
            else if (0 == actionCode.compare("UpdateFile"))
            {
                return std::make_unique<UpdateFileAction>();
            }
            else if (0 == actionCode.compare("SearchFile"))
            {
                return std::make_unique<SearchFileAction>();
            }
            else if (0 == actionCode.compare("RunIntegrity"))
            {
                return std::make_unique<RunIntegrityAction>();
            }
            else if (0 == actionCode.compare("PushMessage"))
            {
                return std::make_unique<PushMessageAction>();
            }
            else if (0 == actionCode.compare("StartTransaction"))
            {
                return std::make_unique<StartTransactionAction>();
            }
            else if (0 == actionCode.compare("SyncTxnRows"))
            {
                return std::make_unique<SyncTxnRowsAction>();
            }
            else if (0 == actionCode.compare("GetDeletedRows"))
            {
                return std::make_unique<GetDeletedRowsAction>();
            }
            else
            {
                throw std::runtime_error { "Invalid action: " + actionCode };
            }
        }
};

#endif //_FACTORY_ACTION_H
