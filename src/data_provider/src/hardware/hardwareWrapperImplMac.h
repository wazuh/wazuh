/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * May 4, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HARDWARE_WRAPPER_IMPL_MAC_H
#define _HARDWARE_WRAPPER_IMPL_MAC_H

#include <sys/sysctl.h>
#include "hardwareWrapperInterface.h"
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "stringHelper.h"
#include "defer.hpp"
#include "osPrimitivesInterfaceMac.h"
#include "utilsWrapperMac.hpp"
#include "sharedDefs.h"


double getMhz(IOsPrimitivesMac* osPrimitives = nullptr);

template <class TOsPrimitivesMac>
class OSHardwareWrapperMac final : public IOSHardwareWrapper, public TOsPrimitivesMac
{
    public:
        // LCOV_EXCL_START
        virtual ~OSHardwareWrapperMac() = default;
        // LCOV_EXCL_STOP

        std::string boardSerial() const
        {
            std::string ret{UNKNOWN_VALUE};
            const auto rawData{UtilsWrapperMac::exec("system_profiler SPHardwareDataType | grep Serial")};

            if (!rawData.empty())
                ret = Utils::trim(rawData.substr(rawData.find(":")), " :\t\r\n");

            return ret;
        }

        std::string cpuName() const
        {
            size_t len{0};
            auto ret{this->sysctlbyname("machdep.cpu.brand_string", nullptr, &len, nullptr, 0)};

            if (ret)
            {
                throw std::system_error
                {
                    ret,
                    std::system_category(),
                    "Error getting cpu name size."
                };
            }

            const auto spBuff{std::make_unique<char[]>(len + 1)};

            if (!spBuff)
            {
                throw std::runtime_error
                {
                    "Error allocating memory to read the cpu name."
                };
            }

            ret = this->sysctlbyname("machdep.cpu.brand_string", spBuff.get(), &len, nullptr, 0);

            if (ret)
            {
                throw std::system_error
                {
                    ret,
                    std::system_category(),
                    "Error getting cpu name"
                };
            }

            spBuff.get()[len] = 0;
            return std::string{reinterpret_cast<const char*>(spBuff.get())};
        }

        int cpuCores() const
        {
            int cores{0};
            size_t len{sizeof(cores)};
            const std::vector<int> mib{CTL_HW, HW_NCPU};
            const auto ret{this->sysctl(const_cast<int*>(mib.data()), mib.size(), &cores, &len, nullptr, 0)};

            if (ret)
            {
                throw std::system_error
                {
                    ret,
                    std::system_category(),
                    "Error reading cpu cores number."
                };
            }

            return cores;
        }

        double cpuMhz()
        {
            return getMhz(static_cast<IOsPrimitivesMac*>(this));
        }

        uint64_t ramTotal() const
        {
            uint64_t ramTotal{0};
            size_t len{sizeof(ramTotal)};
            auto ret{this->sysctlbyname("hw.memsize", &ramTotal, &len, nullptr, 0)};

            if (ret)
            {
                throw std::system_error
                {
                    ret,
                    std::system_category(),
                    "Error reading total RAM."
                };
            }

            return ramTotal / KByte;
        }

        uint64_t ramFree() const
        {
            u_int pageSize{0};
            size_t len{sizeof(pageSize)};
            auto ret{this->sysctlbyname("vm.pagesize", &pageSize, &len, nullptr, 0)};

            if (ret)
            {
                throw std::system_error
                {
                    ret,
                    std::system_category(),
                    "Error reading page size."
                };
            }

            uint64_t freePages{0};
            len = sizeof(freePages);
            ret = this->sysctlbyname("vm.page_free_count", &freePages, &len, nullptr, 0);

            if (ret)
            {
                throw std::system_error
                {
                    ret,
                    std::system_category(),
                    "Error reading pages free count."
                };
            }

            return (freePages * pageSize) / KByte;
        }

        uint64_t ramUsage() const
        {
            uint64_t ret{0};
            const auto ramTotal{this->ramTotal()};

            if (ramTotal)
            {
                ret = 100 - (100 * ramFree() / ramTotal);
            }

            return ret;
        }
};


#endif // _HARDWARE_WRAPPER_IMPL_MAC_H
