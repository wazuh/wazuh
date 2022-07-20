/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 18, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _IREQUEST_IMPLEMENTATOR_HPP
#define _IREQUEST_IMPLEMENTATOR_HPP

#include <string>

enum OPTION_REQUEST_TYPE
{
    OPT_URL,
    OPT_CAINFO,
    OPT_TIMEOUT,
    OPT_WRITEDATA,
    OPT_USERAGENT,
    OPT_POSTFIELDS,
    OPT_WRITEFUNCTION,
    OPT_POSTFIELDSIZE,
    OPT_CUSTOMREQUEST,
    OPT_UNIX_SOCKET_PATH,
    OPT_FAILONERROR,
};

class IRequestImplementator
{
    public:
        virtual ~IRequestImplementator() = default;
        virtual void setOption(const OPTION_REQUEST_TYPE optIndex, void *ptr) = 0;
        virtual void setOption(const OPTION_REQUEST_TYPE optIndex, const std::string &opt) = 0;
        virtual void setOption(const OPTION_REQUEST_TYPE optIndex, const long opt) = 0;
        virtual void execute() = 0;
        virtual inline const std::string response() = 0;
        virtual void appendHeader(const std::string &header) = 0;
};

#endif // _IREQUEST_IMPLEMENTATOR_HPP
