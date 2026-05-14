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

#ifndef _JSON_MESSAGE_DECODER_H
#define _JSON_MESSAGE_DECODER_H

#include "imessageDecoder.h"
#include "json.hpp"

namespace RSync
{
    class JSONMessageDecoder final : public IMessageDecoder
    {
        public:
            // LCOV_EXCL_START
            ~JSONMessageDecoder() = default;
            // LCOV_EXCL_STOP
            SyncInputData decode(const std::vector<unsigned char>& rawData) override
            {
                SyncInputData retVal{};
                const std::string rawDataString { reinterpret_cast<const char*>(rawData.data()), rawData.size() };
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
                        const auto& begin{json.at("begin")};
                        const auto& end{json.at("end")};

                        if (begin.is_string())
                        {
                            retVal.begin = begin;
                            retVal.end = end;
                        }
                        else
                        {
                            const auto beginNumber{begin.get<unsigned long>()};
                            const auto endNumber{end.get<unsigned long>()};
                            const auto beginString{std::to_string(beginNumber)};
                            const auto endString{std::to_string(endNumber)};
                            retVal.begin = beginString;
                            retVal.end = endString;
                        }

                        retVal.id = json.at("id").get<int32_t>();
                    }
                }

                return retVal;
            }
    };
}// namespace RSync

#endif // _JSON_MESSAGE_DECODER_H