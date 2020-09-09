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
        SyncInputData decode(const std::pair<void*, size_t>& rawData) override 
        {
            SyncInputData retVal;
            const std::string rawDataString(reinterpret_cast<char*>(rawData.first), rawData.second);
            const auto firstToken { rawDataString.find(' ') };

            if (std::string::npos != firstToken)
            {
                retVal.command = rawDataString.substr(0, firstToken);
                const auto rawDataStringJson { rawDataString.substr(firstToken, rawDataString.length() - firstToken) };
                const auto& json { nlohmann::json::parse(rawDataStringJson)[0] };

                retVal.begin = json.at("begin").get_ref<const std::string&>() ;
                retVal.end = json.at("end").get_ref<const std::string&>() ;
                retVal.id = json.at("id").get<int64_t>();
            }
            return retVal;
        }
    };
}// namespace RSync

#endif // _MSGDECODERSYNCJSON_H