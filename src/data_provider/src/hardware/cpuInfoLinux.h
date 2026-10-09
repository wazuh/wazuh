/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 9, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CPU_INFO_LINUX_H
#define _CPU_INFO_LINUX_H

#include <array>
#include <map>
#include <string>
#include "sharedDefs.h"

namespace CpuInfoLinux
{
    struct ArmImplementer
    {
        std::string name;
        std::map<int, std::string> parts;
    };

    /**
     * @brief Known ARM implementers and the 64-bit core parts each one designs, as
     *        listed by util-linux (lscpu). 32-bit kernels already report a "model name".
     */
    inline const std::map<int, ArmImplementer>& armImplementers()
    {
        static const std::map<int, ArmImplementer> IMPLEMENTERS
        {
            {
                0x41, {
                    "ARM", {
                        {0xd01, "Cortex-A32"}, {0xd02, "Cortex-A34"}, {0xd03, "Cortex-A53"},
                        {0xd04, "Cortex-A35"}, {0xd05, "Cortex-A55"}, {0xd06, "Cortex-A65"},
                        {0xd07, "Cortex-A57"}, {0xd08, "Cortex-A72"}, {0xd09, "Cortex-A73"},
                        {0xd0a, "Cortex-A75"}, {0xd0b, "Cortex-A76"}, {0xd0c, "Neoverse-N1"},
                        {0xd0d, "Cortex-A77"}, {0xd0e, "Cortex-A76AE"}, {0xd40, "Neoverse-V1"},
                        {0xd41, "Cortex-A78"}, {0xd42, "Cortex-A78AE"}, {0xd43, "Cortex-A65AE"},
                        {0xd44, "Cortex-X1"}, {0xd46, "Cortex-A510"}, {0xd47, "Cortex-A710"},
                        {0xd48, "Cortex-X2"}, {0xd49, "Neoverse-N2"}, {0xd4a, "Neoverse-E1"},
                        {0xd4b, "Cortex-A78C"}, {0xd4c, "Cortex-X1C"}, {0xd4d, "Cortex-A715"},
                        {0xd4e, "Cortex-X3"}, {0xd4f, "Neoverse-V2"}, {0xd80, "Cortex-A520"},
                        {0xd81, "Cortex-A720"}, {0xd82, "Cortex-X4"}, {0xd83, "Neoverse-V3AE"},
                        {0xd84, "Neoverse-V3"}, {0xd85, "Cortex-X925"}, {0xd87, "Cortex-A725"},
                        {0xd88, "Cortex-A520AE"}, {0xd89, "Cortex-A720AE"}, {0xd8a, "C1-Nano"},
                        {0xd8b, "C1-Pro"}, {0xd8c, "C1-Ultra"}, {0xd8e, "Neoverse-N3"},
                        {0xd8f, "Cortex-A320"}, {0xd90, "C1-Premium"}
                    }
                }
            },
            {0x42, {"Broadcom", {{0x100, "Brahma-B53"}, {0x516, "ThunderX2"}}}},
            {
                0x43, {
                    "Cavium", {
                        {0x0a0, "ThunderX"}, {0x0a1, "ThunderX-88XX"}, {0x0a2, "ThunderX-81XX"},
                        {0x0a3, "ThunderX-83XX"}, {0x0af, "ThunderX2-99xx"}, {0x0b0, "OcteonTX2"},
                        {0x0b1, "OcteonTX2-98XX"}, {0x0b2, "OcteonTX2-96XX"}, {0x0b3, "OcteonTX2-95XX"},
                        {0x0b4, "OcteonTX2-95XXN"}, {0x0b5, "OcteonTX2-95XXMM"}, {0x0b6, "OcteonTX2-95XXO"},
                        {0x0b8, "ThunderX3-T110"}
                    }
                }
            },
            {0x46, {"FUJITSU", {{0x001, "A64FX"}, {0x003, "MONAKA"}}}},
            {
                0x48, {
                    "HiSilicon", {
                        {0xd01, "Kunpeng-920"}, {0xd02, "Kunpeng-920"}, {0xd03, "Kunpeng-920"},
                        {0xd06, "Kunpeng-950"}, {0xd22, "Kunpeng-920"}, {0xd40, "Cortex-A76"},
                        {0xd41, "Cortex-A77"}
                    }
                }
            },
            {0x4e, {"NVIDIA", {{0x000, "Denver"}, {0x003, "Denver-2"}, {0x004, "Carmel"}, {0x010, "Olympus"}}}},
            {0x50, {"APM", {{0x000, "X-Gene"}}}},
            {
                0x51, {
                    "Qualcomm", {
                        {0x001, "Oryon"}, {0x002, "Oryon-2"}, {0x201, "Kryo"}, {0x205, "Kryo"},
                        {0x211, "Kryo"}, {0x800, "Falkor-V1/Kryo"}, {0x801, "Kryo-V2"},
                        {0x802, "Kryo-3XX-Gold"}, {0x803, "Kryo-3XX-Silver"}, {0x804, "Kryo-4XX-Gold"},
                        {0x805, "Kryo-4XX-Silver"}, {0xc00, "Falkor"}, {0xc01, "Saphira"}
                    }
                }
            },
            {0x53, {"Samsung", {{0x001, "exynos-m1"}, {0x002, "exynos-m3"}, {0x003, "exynos-m4"}, {0x004, "exynos-m5"}}}},
            {0x56, {"Marvell", {}}},
            {
                0x61, {
                    "Apple", {
                        {0x020, "Icestorm-A14"}, {0x021, "Firestorm-A14"}, {0x022, "Icestorm-M1"},
                        {0x023, "Firestorm-M1"}, {0x024, "Icestorm-M1-Pro"}, {0x025, "Firestorm-M1-Pro"},
                        {0x026, "Thunder-M10"}, {0x028, "Icestorm-M1-Max"}, {0x029, "Firestorm-M1-Max"},
                        {0x030, "Blizzard-A15"}, {0x031, "Avalanche-A15"}, {0x032, "Blizzard-M2"},
                        {0x033, "Avalanche-M2"}, {0x034, "Blizzard-M2-Pro"}, {0x035, "Avalanche-M2-Pro"},
                        {0x036, "Sawtooth-A16"}, {0x037, "Everest-A16"}, {0x038, "Blizzard-M2-Max"},
                        {0x039, "Avalanche-M2-Max"}
                    }
                }
            },
            {0x6d, {"Microsoft", {{0xd49, "Azure-Cobalt-100"}}}},
            {
                0x70, {
                    "Phytium", {
                        {0x303, "FTC310"}, {0x660, "FTC660"}, {0x661, "FTC661"}, {0x662, "FTC662"},
                        {0x663, "FTC663"}, {0x664, "FTC664"}, {0x862, "FTC862"}
                    }
                }
            },
            {0xc0, {"Ampere", {{0xac3, "Ampere-1"}, {0xac4, "Ampere-1a"}}}}
        };
        return IMPLEMENTERS;
    }

    inline bool parseHexId(const std::string& value, int& id)
    {
        try
        {
            size_t parsed {0};
            id = std::stoi(value, &parsed, 16);
            return parsed == value.size();
        }
        catch (...)
        {
            return false;
        }
    }

    /**
     * @brief Names the core from the "CPU implementer" and "CPU part" ids that arm64
     *        kernels print instead of a "model name".
     *
     * @param cpuInfo /proc/cpuinfo key-value pairs.
     *
     * @return The core name (e.g. "Neoverse-N1"), "<vendor> <part id>" when only the
     *         implementer is known, or UNKNOWN_VALUE.
     */
    inline std::string armCpuName(const std::map<std::string, std::string>& cpuInfo)
    {
        const auto itImplementer {cpuInfo.find("CPU implementer")};
        const auto itPart {cpuInfo.find("CPU part")};
        int implementerId {0};

        if (itImplementer == cpuInfo.end() || !parseHexId(itImplementer->second, implementerId))
        {
            return UNKNOWN_VALUE;
        }

        const auto itKnownImplementer {armImplementers().find(implementerId)};

        if (itKnownImplementer == armImplementers().end())
        {
            return UNKNOWN_VALUE;
        }

        const auto& implementer {itKnownImplementer->second};
        int partId {0};

        if (itPart == cpuInfo.end() || !parseHexId(itPart->second, partId))
        {
            return implementer.name;
        }

        const auto itKnownPart {implementer.parts.find(partId)};

        return itKnownPart != implementer.parts.end() ? itKnownPart->second : implementer.name + " " + itPart->second;
    }

    /**
     * @brief Gets the CPU name out of /proc/cpuinfo, whose key for it depends on the architecture.
     *
     * @param cpuInfo /proc/cpuinfo key-value pairs.
     *
     * @return The CPU name, or UNKNOWN_VALUE.
     */
    inline std::string cpuName(const std::map<std::string, std::string>& cpuInfo)
    {
        // x86 and 32-bit ARM print "model name", POWER prints "cpu".
        constexpr std::array<const char*, 2> NAME_KEYS {"model name", "cpu"};

        for (const auto& key : NAME_KEYS)
        {
            const auto it {cpuInfo.find(key)};

            if (it != cpuInfo.end() && !it->second.empty())
            {
                return it->second;
            }
        }

        return armCpuName(cpuInfo);
    }
}

#endif // _CPU_INFO_LINUX_H
