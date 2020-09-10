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
    class MessageRowData : public IMessageCreator<Type>
    {
    public:
        void send(const ResultCallback /*callback*/, const Type& /*data*/) override
        {
            throw rsync_error { NOT_SPECIALIZED_FUNCTION };   
        }
    };
    template <>
    class MessageRowData<nlohmann::json> : public IMessageCreator<nlohmann::json>
    {
    public:
        void send(const ResultCallback callback, const nlohmann::json& data) override
        {
            callback(data.dump());
        }
    };
};

#endif //_MESSAGEROWDATA_H