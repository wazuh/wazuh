/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2020, Wazuh Inc.
 * December 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PKG_WRAPPER_H
#define _PKG_WRAPPER_H

#include "ipackageWrapper.h"
#include "sharedDefs.h"

class PKGWrapper final : public IPackageWrapper
{
    public:
    explicit PKGWrapper(const std::string& /*fileName*/)
    { }

    ~PKGWrapper() = default;

    std::string name() const override
    {
        return DEFAULT_STRING_VALUE;
    }
    std::string version() const override
    {
        return DEFAULT_STRING_VALUE;
    }
    std::string groups() const override
    {
        return DEFAULT_STRING_VALUE;
    }
    std::string description() const override
    {
        return DEFAULT_STRING_VALUE;
    }
    std::string architecture() const override
    {
        return DEFAULT_STRING_VALUE;
    }
    std::string format() const override
    {
        return DEFAULT_STRING_VALUE;
    }
    std::string osPatch() const override
    {
        return DEFAULT_STRING_VALUE;
    }
};

#endif //_PKG_WRAPPER_H