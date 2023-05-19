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
#include "data_provider/include/sysInfo.hpp"
#include "shared_modules/utils/cmdHelper.h"
#include "shared_modules/utils/stringHelper.h"
#include "shared_modules/utils/defer.hpp"
#include "shared_modules/utils/osPrimitivesInterfaceMac.h"
#include "utilsWrapperMac.hpp"

#if (MAC_OS_X_VERSION_MAX_ALLOWED < 120000) // Before macOS 12 Monterey
#define kIOMainPortDefault kIOMasterPortDefault
#endif

template <class TOsPrimitivesMac>
class OSHardwareWrapperMac final : public IOSHardwareWrapper, public TOsPrimitivesMac
{
    public:
        // LCOV_EXCL_START
        virtual ~OSHardwareWrapperMac() = default;
        // LCOV_EXCL_STOP

        std::string boardSerial() const
        {
            const auto rawData{UtilsWrapperMac::exec("system_profiler SPHardwareDataType | grep Serial")};
            return Utils::trim(rawData.substr(rawData.find(":")), " :\t\r\n");
        }

        std::string cpuName() const
        {
            const std::vector<int> mib{CTL_HW, HW_MODEL};
            size_t len{0};
            auto ret{this->sysctl(const_cast<int*>(mib.data()), mib.size(), nullptr, &len, nullptr, 0)};

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

            ret = this->sysctl(const_cast<int*>(mib.data()), mib.size(), spBuff.get(), &len, nullptr, 0);

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

        uint64_t getCpuHzAarch64() const
        {
            uint64_t cpuHz = 0;

            auto matching = this->IOServiceMatching("AppleARMIODevice");

            if (matching == nullptr)
            {
                throw std::system_error
                {
                    0,
                    std::system_category(),
                    "Error on library function call IOServiceMatching."
                };
            }

            io_iterator_t device_it = 0;
            auto kr = this->IOServiceGetMatchingServices(kIOMainPortDefault, matching, &device_it);

            if (kr != KERN_SUCCESS)
            {
                throw std::system_error
                {
                    kr,
                    std::system_category(),
                    "Error on library function call IOServiceGetMatchingServices."
                };
            }

            DEFER([this, device_it]()
            {
                this->IOObjectRelease(device_it);
            });

            io_object_t device = 0;

            while ((device = this->IOIteratorNext(device_it)))
            {
                DEFER([this, device]()
                {
                    this->IOObjectRelease(device);
                });

                io_name_t buf;
                kr = this->IORegistryEntryGetName(device, buf);

                if (kr != KERN_SUCCESS)
                {
                    continue;
                }

                std::string name(buf);

                if (name.compare("pmgr"))
                {
                    continue;
                }

                CFMutableDictionaryRef properties;
                kr = this->IORegistryEntryCreateCFProperties(device, &properties, kCFAllocatorDefault, kNilOptions);

                if (kr != KERN_SUCCESS)
                {
                    throw std::system_error
                    {
                        kr,
                        std::system_category(),
                        "Error on library function call IORegistryEntryCreateCFProperties."
                    };
                }

                DEFER([this, properties]()
                {
                    this->CFRelease(properties);
                });

                // voltage-states5-sram contains the performance cores available frequencies
                CFStringRef cfkey = this->CFStringCreateWithCString(kCFAllocatorDefault, "voltage-states5-sram", kCFStringEncodingUTF8);
                DEFER([this, cfkey]()
                {
                    this->CFRelease(cfkey);
                });

                auto p_cores_freq_property = static_cast<CFDataRef>(this->CFDictionaryGetValue(properties, cfkey));

                if (p_cores_freq_property == nullptr)
                {
                    throw std::system_error
                    {
                        0,
                        std::system_category(),
                        "Error on library function call CFDictionaryGetValue."
                    };
                }

                auto p_cores_freq_type = this->CFGetTypeID(p_cores_freq_property);

                if (p_cores_freq_type != this->CFDataGetTypeID())
                {
                    throw std::system_error
                    {
                        0,
                        std::system_category(),
                        "CF type id of p_cores_freq_property is not Data type id."
                    };
                }

                size_t length = this->CFDataGetLength(p_cores_freq_property);

                // The frequencies are in hz, saved in an array as little endian 4 byte integers
                for (size_t i = 0; i < length - 3; i += sizeof(uint32_t))
                {
                    uint32_t cur_freq = 0;
                    this->CFDataGetBytes(p_cores_freq_property, this->CFRangeMake(i, sizeof(uint32_t)), reinterpret_cast<UInt8*>(&cur_freq));

                    if (cpuHz < cur_freq)
                    {
                        cpuHz = cur_freq;
                    }
                }
            }

            return cpuHz;
        }

        double cpuMhz() const
        {
            constexpr auto MHz{1000000};
            uint64_t cpuHz{0};
            size_t len{sizeof(cpuHz)};
            int ret{this->sysctlbyname("hw.cpufrequency", &cpuHz, &len, nullptr, 0)};

            if (ret)
            {
                try
                {
                    cpuHz = getCpuHzAarch64();
                }
                catch (std::system_error& e)
                {
                    throw e;
                }
                catch (...)
                {
                    throw std::system_error
                    {
                        ret,
                        std::system_category(),
                        "Error reading cpu frequency."
                    };
                }
            }

            return static_cast<double>(cpuHz) / MHz;
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
            return 100 - (100 * ramFree() / ramTotal());
        }
};
#endif // _HARDWARE_WRAPPER_IMPL_MAC_H
