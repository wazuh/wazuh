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

#ifndef _IMESSAGECREATOR_H
#define _IMESSAGECREATOR_H


namespace RSync
{
    template <typename Type>
    class IMessageCreator
    {
    public:
        // LCOV_EXCL_START
        virtual ~IMessageCreator() = default;
        // LCOV_EXCL_STOP
        virtual void send(const ResultCallback callback, const nlohmann::json& config, const Type& data) = 0;
    };
};// namespace RSync

#endif //_IMESSAGECREATOR_H