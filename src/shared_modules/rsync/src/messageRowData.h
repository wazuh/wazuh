/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * September 10, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MESSAGE_ROW_DATA_H
#define _MESSAGE_ROW_DATA_H

#include "imessageCreator.h"

namespace RSync
{
    template <class Type>
    class MessageRowData final : public IMessageCreator<Type>
    {
        public:
            // LCOV_EXCL_START
            ~MessageRowData() = default;
            void send(const ResultCallback /*callback*/, const nlohmann::json& /*config*/, const Type& /*data*/) override
            {
                throw rsync_error { NOT_SPECIALIZED_FUNCTION };
            }
            // LCOV_EXCL_STOP
    };
    template <>
    class MessageRowData<nlohmann::json> final : public IMessageCreator<nlohmann::json>
    {
        public:
            // LCOV_EXCL_START
            ~MessageRowData() = default;
            // LCOV_EXCL_STOP
            void send(const ResultCallback callback, const nlohmann::json& config, const nlohmann::json& data) override
            {
                nlohmann::json outputMessage;
                outputMessage["component"] = config.at("component");
                outputMessage["type"] = "state";

                nlohmann::json outputData;
                outputData["index"] = data.at(config.at("index").get_ref<const std::string&>());
                const auto lastEvent = config.find("last_event");
                outputData["timestamp"] = (lastEvent != config.end()) ? data.at(lastEvent->get_ref<const std::string&>()) : "";
                outputData["attributes"] = data;

                outputMessage["data"] = outputData;

                callback(outputMessage.dump());
            }
    };
};// namespace RSync

#endif //_MESSAGE_ROW_DATA_H
