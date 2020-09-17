/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * September 10, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MESSAGEROWDATA_H
#define _MESSAGEROWDATA_H

#include "imessageCreator.h"

namespace RSync
{
    template <class Type>
    class MessageRowData final : public IMessageCreator<Type>
    {
    public:
        void send(const ResultCallback /*callback*/, const nlohmann::json& /*config*/, const Type& /*data*/) override
        {
            throw rsync_error { NOT_SPECIALIZED_FUNCTION };   
        }
    };
    template <>
    class MessageRowData<nlohmann::json> final : public IMessageCreator<nlohmann::json>
    {
    public:
        void send(const ResultCallback callback, const nlohmann::json& config, const nlohmann::json& data) override
        {
            nlohmann::json outputMessage;
            outputMessage["component"] = config.at("component");
            outputMessage["type"] = "state";
            
            nlohmann::json outputData;
            outputData["index"] = data.at(config.at("index").get_ref<const std::string&>());
            outputData["timestamp"] = data.at(config.at("last_event").get_ref<const std::string&>());
            outputData["attributes"] = data;

            outputMessage["data"] = outputData;

            callback(outputMessage.dump());
        }
    };
};// namespace RSync

#endif //_MESSAGEROWDATA_H