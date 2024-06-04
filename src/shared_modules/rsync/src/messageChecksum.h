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

#ifndef _MESSAGE_CHECKSUM_H
#define _MESSAGE_CHECKSUM_H

#include "imessageCreator.h"

namespace RSync
{
    template <class Type>
    class MessageChecksum final : public IMessageCreator<Type>
    {
        public:
            void send(const ResultCallback /*callback*/, const nlohmann::json& /*config*/, const Type& /*data*/) override
            {
                throw rsync_error { NOT_SPECIALIZED_FUNCTION };
            }
    };
    template <>
    class MessageChecksum<SplitContext> final : public IMessageCreator<SplitContext>
    {
        public:
            // LCOV_EXCL_START
            ~MessageChecksum() = default;
            // LCOV_EXCL_STOP
            void send(const ResultCallback callback, const nlohmann::json& config, const SplitContext& data) override
            {

                const auto& it { IntegrityCommands.find(data.type)};

                if (IntegrityCommands.end() != it)
                {
                    nlohmann::json outputMessage;
                    outputMessage["component"] = config.at("component");
                    outputMessage["type"] = it->second;

                    nlohmann::json outputData;
                    outputData["id"] = data.id;

                    if (INTEGRITY_CLEAR != data.type)
                    {
                        outputData["begin"] = data.begin;
                        outputData["end"] = data.end;

                        if (INTEGRITY_CHECK_LEFT == data.type)
                        {
                            outputData["tail"] = data.tail;
                        }

                        outputData["checksum"] = data.checksum;
                    }

                    outputMessage["data"] = outputData;

                    if (!data.checksum.empty() || INTEGRITY_CLEAR == data.type)
                    {
                        callback(outputMessage.dump());
                    }
                }
                // LCOV_EXCL_START
                else
                {
                    throw rsync_error { INVALID_OPERATION };
                }

                // LCOV_EXCL_STOP
            }
    };
};// namespace RSync

#endif //_MESSAGE_CHECKSUM_H
