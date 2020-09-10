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
    template
    <
    typename Type
    >
    class IMessageCreator
    {
    public:
        virtual void send(const ResultCallback callback, const Type& data) = 0;
    };
};

#endif //_IMESSAGECREATOR_H