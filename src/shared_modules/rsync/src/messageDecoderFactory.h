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

#ifndef _DECODER_FACTORY_H
#define _DECODER_FACTORY_H

#include "messageDecoderJSON.h"
#include "rsync_exception.h"
#include "commonDefs.h"

namespace RSync
{
    enum SyncMsgBodyType
    {
        SYNC_RANGE_JSON,
    };

    class FactoryDecoder final
    {
        public:
            static std::shared_ptr<IMessageDecoder> create(const SyncMsgBodyType syncMessageType)
            {
                std::shared_ptr<IMessageDecoder> retVal;

                if (SyncMsgBodyType::SYNC_RANGE_JSON == syncMessageType)
                {
                    retVal = std::make_shared<JSONMessageDecoder>();
                }

                return retVal;
            }
    };
}// namespace RSync

#endif // _DECODER_FACTORY_H
