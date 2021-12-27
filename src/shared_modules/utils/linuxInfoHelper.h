/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 10, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _LINUXPROCESS_HELPER_H
#define _LINUXPROCESS_HELPER_H

#include <cstdint>   //uint64_t
#include <string>    //std::stoul

#include <unistd.h>  //sysconf

#include <vector>
#include "filesystemHelper.h" //getFileContent


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    static uint64_t getBootTime(void)
    {
        static uint64_t btime;

        try
        {
            if (0UL == btime)
            {
                const std::string key {"btime "};
                const auto file { Utils::getFileContent("/proc/stat") };

                btime = std::stoul(file.substr(file.find(key) + key.length()));
            }
         }
         catch(...)
         {
         }

         return btime;
    }

    static uint64_t getClockTick(void)
    {
       static uint64_t tick = static_cast<uint64_t>(sysconf(_SC_CLK_TCK));

       return tick;
    }

    static uint64_t timeTick2unixTime(const uint64_t startTime)
    {
        return (startTime / getClockTick()) + getBootTime();
    }
}


#endif // _LINUXPROCESS_HELPER_H