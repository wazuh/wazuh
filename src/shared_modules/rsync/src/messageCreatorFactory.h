/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * September 5, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MESSAGE_CREATOR_FACTORY_H
#define _MESSAGE_CREATOR_FACTORY_H

#include <memory>
#include "messageChecksum.h"
#include "messageRowData.h"
#include "rsync_exception.h"
#include "commonDefs.h"

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
                throw rsync_error
                {
                    FACTORY_INSTANTATION
                };
            }
    };

    template <class Type>
    class FactoryMessageCreator<Type, MessageType::CHECKSUM> final
    {
        public:
            static std::shared_ptr<IMessageCreator<Type>> create()
            {
                return std::make_shared<MessageChecksum<Type>>();
            }
    };

    template <class Type>
    class FactoryMessageCreator<Type, MessageType::ROW_DATA> final
    {
        public:
            static std::shared_ptr<IMessageCreator<Type>> create()
            {
                return std::make_shared<MessageRowData<Type>>();
            }
    };
}// namespace RSync

#endif // _MESSAGE_CREATOR_FACTORY_H
