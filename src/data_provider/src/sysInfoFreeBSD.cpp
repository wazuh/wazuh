/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "stringHelper.h"
#include "timeHelper.h"
#include "osinfo/sysOsParsers.h"
#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#include <sys/utsname.h>
#include "sharedDefs.h"

static void getMemory(nlohmann::json& info)
{
    constexpr auto vmFree{"vm.stats.vm.v_free_count"};
    constexpr auto vmInactive{"vm.stats.vm.v_inactive_count"};
    constexpr auto vmPageSize{"vm.stats.vm.v_page_size"};
    constexpr auto vmTotal{"hw.physmem"};
    uint64_t ram{0};
    size_t len{sizeof(ram)};
    auto ret{sysctlbyname(vmTotal, &ram, &len, nullptr, 0)};

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading total RAM."
        };
    }

    const auto ramTotal{ram / KByte};
    info["ram_total"] = ramTotal;
    u_int pageSize{0};
    len = sizeof(pageSize);
    ret = sysctlbyname(vmPageSize, &pageSize, &len, nullptr, 0);

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading page size."
        };
    }

    uint64_t freeMem{0};
    len = sizeof(freeMem);
    ret = sysctlbyname(vmFree, &freeMem, &len, nullptr, 0);

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading free memory size."
        };
    }

    uint64_t inactiveMem{0};
    len = sizeof(inactiveMem);
    ret = sysctlbyname(vmInactive, &inactiveMem, &len, nullptr, 0);

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading inactive memory size."
        };
    }

    const auto ramFree{(freeMem + inactiveMem) * pageSize / KByte};
    info["ram_free"] = ramFree;
    info["ram_usage"] = 100 - (100 * ramFree / ramTotal);
}


static int getCpuMHz()
{
    unsigned long cpuMHz{0};
    constexpr auto clockRate{"hw.clockrate"};
    size_t len{sizeof(cpuMHz)};
    const auto ret{sysctlbyname(clockRate, &cpuMHz, &len, nullptr, 0)};

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading cpu frequency."
        };
    }

    return cpuMHz;
}

static std::string getSerialNumber()
{
    return UNKNOWN_VALUE;
}

static int getCpuCores()
{
    int cores{0};
    size_t len{sizeof(cores)};
    const std::vector<int> mib{CTL_HW, HW_NCPU};
    const auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), &cores, &len, nullptr, 0)};

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

static std::string getCpuName()
{
    const std::vector<int> mib{CTL_HW, HW_MODEL};
    size_t len{0};
    auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), nullptr, &len, nullptr, 0)};

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

    ret = sysctl(const_cast<int*>(mib.data()), mib.size(), spBuff.get(), &len, nullptr, 0);

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

nlohmann::json SysInfo::getHardware() const
{
    nlohmann::json hardware;
    hardware["board_serial"] = getSerialNumber();
    hardware["cpu_name"] = getCpuName();
    hardware["cpu_cores"] = getCpuCores();
    hardware["cpu_mhz"] = double(getCpuMHz());
    getMemory(hardware);
    return hardware;
}

nlohmann::json SysInfo::getPackages() const
{
    nlohmann::json ret;
    getPackages([&ret](nlohmann::json & data)
    {
        ret.push_back(data);
    });
    return ret;
}

nlohmann::json SysInfo::getProcessesInfo() const
{
    nlohmann::json ret;
    getProcessesInfo([&ret](nlohmann::json & data)
    {
        ret.push_back(data);
    });
    return ret;
}

nlohmann::json SysInfo::getOsInfo() const
{
    nlohmann::json ret;
    struct utsname uts {};
    const auto spParser{FactorySysOsParser::create("bsd")};

    if (!spParser->parseUname(Utils::exec("uname -r"), ret))
    {
        ret["os_platform"] = "bsd";
        ret["os_version"] = UNKNOWN_VALUE;
    }

    ret["os_name"] = "FreeBSD";

    if (uname(&uts) >= 0)
    {
        ret["sysname"] = uts.sysname;
        ret["hostname"] = uts.nodename;
        ret["version"] = uts.version;
        ret["architecture"] = uts.machine;
        ret["release"] = uts.release;
    }

    return ret;
}

nlohmann::json SysInfo::getPorts() const
{
    const auto query{Utils::exec(R"(sockstat -46qs)")};
    nlohmann::json ports {};

    if (!query.empty())
    {
        const auto lines{Utils::split(Utils::trimToOneSpace(query), '\n')};

        for (const auto& line : lines)
        {
            std::string localip = "";
            std::string localport = "";
            std::string remoteip = "";
            std::string remoteport = "";
            const auto data{Utils::split(line, ' ')};
            auto localdata{Utils::split(data[5], ':')};
            auto remotedata{Utils::split(data[6], ':')};
            auto statedata{Utils::toLowerCase(data[7])};

            localip = localdata[0];
            localport = localdata[1];
            remoteip = remotedata[0];
            remoteport = remotedata[1];

            if(statedata == "listen") {
              statedata = "listening";
            }

            if(localdata.size() == 4) {
              localip = localdata[0] + ":"+ localdata[1] + ":" + localdata[2];
              localport = localdata[3];
            } else if(localip == "*") {
              if((data[4] == "tcp6") || (data[4] == "udp6")) {
                localip = "0:0:0:0:0:0:0:0";
              } else {
                localip = "0.0.0.0";
              }
            }

            if(remotedata.size() == 4) {
              remoteip = remotedata[0] + ":"+ remotedata[1] + ":" + remotedata[2];
              remoteport = remotedata[3];
            } else if(remoteport == "*") {
                remoteip = "";
                remoteport = "";
            }

            if(data[0] != "?") {
              nlohmann::json port {};
              port["protocol"] = data[4];
              port["local_ip"] = localip;
              port["local_port"] = localport;
              port["remote_ip"] = remoteip;
              port["remote_port"] = remoteport;
              port["tx_queue"] = 0;
              port["rx_queue"] = 0;
              port["inode"] = data[3];
              port["state"] = statedata;
              port["pid"] = data[2];
              port["process"] = data[1];

              ports.push_back(port);
            }
        }
    }

    return ports;
}

void SysInfo::getProcessesInfo(std::function<void(nlohmann::json&)> callback) const
{
    const auto query{Utils::exec(R"(ps -ax -w -o pid,comm,state,ppid,usertime,systime,user,ruser,svuid,group,rgroup,svgid,pri,nice,ssiz,vsz,rss,pmem,etimes,sid,pgid,tpgid,tty,cpu,nlwp,args --libxo json)")};

    if (!query.empty())
    {
      nlohmann::json psjson;
      psjson = nlohmann::json::parse(query);
      auto &processes = psjson["process-information"]["process"];

      for(auto &process : processes) {
          std::string user_time{""};
          std::string system_time{""};

          user_time = process["user-time"].get<std::string>();
          system_time = process["system-time"].get<std::string>();

          nlohmann::json jsProcessInfo{};
          jsProcessInfo["pid"]        = process["pid"].get<std::string>();
          jsProcessInfo["name"]       = process["command"].get<std::string>();
          jsProcessInfo["state"]      = process["state"].get<std::string>();
          jsProcessInfo["ppid"]       = process["ppid"].get<std::string>();
          jsProcessInfo["utime"]      = Utils::timeToSeconds(user_time);
          jsProcessInfo["stime"]      = Utils::timeToSeconds(system_time);
          jsProcessInfo["cmd"]        = process["command"].get<std::string>();
          jsProcessInfo["argvs"]      = process["arguments"].get<std::string>();
          jsProcessInfo["euser"]      = process["user"].get<std::string>();
          jsProcessInfo["ruser"]      = process["real-user"].get<std::string>();
          jsProcessInfo["suser"]      = process["saved-uid"].get<std::string>();
          jsProcessInfo["egroup"]     = process["group"].get<std::string>();
          jsProcessInfo["rgroup"]     = process["real-group"].get<std::string>();
          jsProcessInfo["sgroup"]     = process["saved-gid"].get<std::string>();
          jsProcessInfo["fgroup"]     = process["group"].get<std::string>();
          jsProcessInfo["priority"]   = process["priority"].get<std::string>();
          jsProcessInfo["nice"]       = process["nice"].get<std::string>();
          jsProcessInfo["size"]       = process["stack-size"].get<std::string>();
          jsProcessInfo["vm_size"]    = process["virtual-size"].get<std::string>();
          jsProcessInfo["resident"]   = process["rss"].get<std::string>();
          jsProcessInfo["share"]      = process["percent-memory"].get<std::string>();
          jsProcessInfo["start_time"] = process["elapsed-times"].get<std::string>();
          jsProcessInfo["pgrp"]       = process["process-group"].get<std::string>();
          jsProcessInfo["session"]    = process["sid"].get<std::string>();
          jsProcessInfo["tgid"]       = process["terminal-process-gid"].get<std::string>();
          //jsProcessInfo["tty"]        = process["tty"].get<std::string>(); // this field should be TEXT into local.db
          jsProcessInfo["processor"]  = process["on-cpu"].get<std::string>();
          jsProcessInfo["nlwp"]       = process["threads"].get<std::string>();

          callback(jsProcessInfo);
      }
    }
}

void SysInfo::getPackages(std::function<void(nlohmann::json&)> callback) const
{
    const auto query{Utils::exec(R"(pkg query -a "%n|%m|%v|%q|%c|%sb|%t|%R|%o")")};

    if (!query.empty())
    {
        const auto lines{Utils::split(query, '\n')};

        for (const auto& line : lines)
        {
            const auto data{Utils::split(line, '|')};
            const auto archdata{Utils::split(data[3], ':')};
            const auto sectiondata{Utils::split(data[8], '/')};

            nlohmann::json package;
            package["name"] = data[0];
            package["vendor"] = data[1];
            package["version"] = data[2];
            package["install_time"] = data[6];
            package["location"] = UNKNOWN_VALUE;
            package["architecture"] = archdata[2];
            package["groups"] = UNKNOWN_VALUE;
            package["description"] = data[4];
            package["size"] = data[5];
            package["priority"] = UNKNOWN_VALUE;
            package["source"] = data[7];
            package["section"] = sectiondata[0];
            package["format"] = "pkg";
            // The multiarch field won't have a default value

            callback(package);
        }
    }
}

nlohmann::json SysInfo::getHotfixes() const
{
    // Currently not supported for this OS.
    return nlohmann::json();
}
