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

#ifndef _MESSAGECHECKSUM_H
#define _MESSAGECHECKSUM_H

#include "imessageCreator.h"

namespace RSync
{
    template <class Type>
    class MessageChecksum final : public IMessageCreator<Type>
    {
    public:
        void send(const ResultCallback /*callback*/, const Type& /*data*/) override
        {
            throw rsync_error { NOT_SPECIALIZED_FUNCTION };
        }
    };
    template <>
    class MessageChecksum<std::string> : public IMessageCreator<std::string>
    {
    public:
        void send(const ResultCallback callback, const std::string& data) override
        {
            callback(data.c_str());
        }
    };
};

#endif //_MESSAGECHECKSUM_H