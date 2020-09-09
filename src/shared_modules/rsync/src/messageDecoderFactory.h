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

#ifndef _DECODER_FACTORY_H
#define _DECODER_FACTORY_H

#include "messageDecoderJSON.h"
#include "rsync_exception.h"
#include "commonDefs.h"
#include <iostream>

namespace RSync
{
    enum SyncMsgBodyType
    {
        SYNC_RANGE_JSON,
    };
    
    class FactoryDecoder final
    {
    public:
        static std::shared_ptr<IMessageDecoder> create(const SyncMsgBodyType sync_message_type)
        {
            if (SyncMsgBodyType::SYNC_RANGE_JSON == sync_message_type)
            {
                return std::make_shared<JSONMessageDecoder>();
            }
            throw rsync_error
            {
                FACTORY_INSTANTATION
            };
        }
    };
}// namespace RSync

#endif // _DECODER_FACTORY_H
