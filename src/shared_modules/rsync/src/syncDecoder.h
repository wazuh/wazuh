/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * September 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MSGDECODER_SYNC_H
#define _MSGDECODER_SYNC_H

#include "commonDefs.h"
#include "rsync_exception.h"
#include "messageDecoderFactory.h"

namespace RSync
{
    class SyncDecoder
    {
        std::map<std::string, std::shared_ptr<IMessageDecoder>> m_decodersRegistered;
        std::mutex m_mutex;
         
    public:
        std::pair<std::string, SyncInputData> decode (const std::pair<void*, size_t>& rawData)
        {
            const std::string rawDataString(reinterpret_cast<char*>(rawData.first), rawData.second);
            const auto firstToken { rawDataString.find(' ') };
            std::string header;

            if (std::string::npos != firstToken)
            {
                header = rawDataString.substr(0, firstToken);
                std::lock_guard<std::mutex> lock{ m_mutex };
                return std::make_pair(header, m_decodersRegistered.at(header)->decode(rawData));
            }
            else
            {
                throw INVALID_HEADER;
            }
            return {};
        }

        void setMessageDecoderType(const std::string& messageHeaderId, 
                                   const SyncMsgBodyType syncMessageType)
        {
            std::lock_guard<std::mutex> lock{ m_mutex };
            m_decodersRegistered[messageHeaderId] = FactoryDecoder::create(syncMessageType);
        }
    };

}// namespace RSync

#endif // _DECODER_FACTORY_H