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

#ifndef _MSGDECODERSYNCJSON_H
#define _MSGDECODERSYNCJSON_H

#include "imessageDecoder.h"
#include "json.hpp"

namespace RSync
{
    class JSONMessageDecoder final : public IMessageDecoder
    {
    public:
        SyncInputData decode(const std::vector<unsigned char>& rawData) override 
        {
            SyncInputData retVal{};
            const std::string rawDataString(reinterpret_cast<const char*>(rawData.data()), rawData.size());
            const auto firstToken { rawDataString.find(' ') };

            if (std::string::npos != firstToken)
            {
                const auto rawDataStringFromFirst { rawDataString.substr(firstToken + 1, rawDataString.length() - firstToken - 1) };
                const auto secondToken { rawDataStringFromFirst.find(' ') };
                if (std::string::npos != secondToken)
                {
                    retVal.command = rawDataStringFromFirst.substr(0, secondToken);
                    
                    const auto rawDataStringFromSecond { rawDataStringFromFirst.substr(secondToken + 1, rawDataStringFromFirst.length() - secondToken - 1) };
                    const auto& json { nlohmann::json::parse(rawDataStringFromSecond) };
                    
                    retVal.begin = json.at("begin").get_ref<const std::string&>() ;
                    retVal.end = json.at("end").get_ref<const std::string&>() ;
                    retVal.id = json.at("id").get<int32_t>();
                }
            }
            return retVal;
        }
    };
}// namespace RSync

#endif // _MSGDECODERSYNCJSON_H