/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * September 5, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MESSAGE_CREATOR_FACTORY_H
#define _MESSAGE_CREATOR_FACTORY_H

#include "messageChecksum.h"
#include "messageRowData.h"
#include "rsync_exception.h"
#include "commonDefs.h"
#include <iostream>

namespace RSync
{
    enum MessageType
    {
        CHECKSUM,
        ROW_DATA
    };
    
    template <class Type, MessageType mType>
    class FactoryMessageCreator final
    {
    public:
        static std::shared_ptr<IMessageCreator<Type>> create()
        {
            if (CHECKSUM == mType)
            {
                return std::make_shared<MessageChecksum<Type>>();
            }
            else if (ROW_DATA == mType)
            {
                return std::make_shared<MessageRowData<Type>>();
            }
            throw rsync_error
            {
                FACTORY_INSTANTATION
            };
        }
    };

    
}// namespace RSync

#endif // _MESSAGE_CREATOR_FACTORY_H
