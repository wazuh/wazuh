/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_BENCH_COMMON_HPP
#define _INDEXER_CLIENT_BENCH_COMMON_HPP

// Helpers shared by both benchmark executables (plan 18, E2c, I58): command line, the 4 MiB bulk body, CPU time from
// /proc, the affinity and the libwazuhext the process really mapped (provenance), and the CSV row.

#include <openssl/evp.h>

#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "benchFake.hpp"

namespace bench
{
    constexpr std::size_t BODY_BYTES {4u * 1024u * 1024u};
    constexpr long TIMEOUT_MS {60000};
    constexpr int DRAIN_SECONDS {120};
    /// Basic auth both sides send (the v2 requires credentials; the normative v1 sends the same pair).
    inline const std::string BENCH_USER {"bench"};
    inline const std::string BENCH_PASSWORD {"bench-secret"};

    /// `--name value` and `--flag` arguments. Unknown names are rejected by the caller through `unused()`.
    class Args final
    {
    public:
        Args(int argc, char** argv, const std::vector<std::string>& flags)
        {
            for (int i = 1; i < argc; ++i)
            {
                const std::string arg = argv[i];
                if (arg.rfind("--", 0) != 0)
                {
                    throw std::invalid_argument("unexpected argument '" + arg + "'");
                }
                const auto name = arg.substr(2);
                bool isFlag = false;
                for (const auto& flag : flags)
                {
                    isFlag = isFlag || flag == name;
                }
                if (isFlag)
                {
                    m_values[name] = "1";
                }
                else if (i + 1 < argc)
                {
                    m_values[name] = argv[++i];
                }
                else
                {
                    throw std::invalid_argument("missing value for " + arg);
                }
            }
        }

        std::string get(const std::string& name, const std::string& fallback)
        {
            m_used[name] = true;
            const auto it = m_values.find(name);
            return it == m_values.end() ? fallback : it->second;
        }

        int getInt(const std::string& name, int fallback)
        {
            const auto value = get(name, std::to_string(fallback));
            std::size_t used = 0;
            const int parsed = std::stoi(value, &used);
            if (used != value.size())
            {
                throw std::invalid_argument("--" + name + " expects an integer, got '" + value + "'");
            }
            return parsed;
        }

        bool flag(const std::string& name)
        {
            return get(name, "") == "1";
        }

        /// Throws on any argument nobody asked for.
        void rejectUnused() const
        {
            for (const auto& [name, value] : m_values)
            {
                if (m_used.find(name) == m_used.end())
                {
                    throw std::invalid_argument("unknown option --" + name);
                }
            }
        }

    private:
        std::map<std::string, std::string> m_values;
        std::map<std::string, bool> m_used;
    };

    /// The same NDJSON body for every run: {"index":...}\n{document}\n repeated up to `bytes`.
    inline std::shared_ptr<const std::string> makeBulk(std::size_t bytes)
    {
        std::string body;
        body.reserve(bytes + 512);
        const std::string meta = "{\"index\":{\"_index\":\"bench\"}}\n";
        const std::string doc = R"({"agent":{"id":"001","name":"bench"},"message":")" + std::string(900, 'x') + "\"}\n";
        while (body.size() + meta.size() + doc.size() <= bytes)
        {
            body += meta;
            body += doc;
        }
        return std::make_shared<const std::string>(std::move(body));
    }

    /// utime + stime (clock ticks) of /proc/self/task/<tid>/stat (tid <= 0: the whole process); -1 if unreadable.
    inline long long cpuTicks(int tid)
    {
        const std::string path = tid > 0 ? "/proc/self/task/" + std::to_string(tid) + "/stat" : "/proc/self/stat";
        std::ifstream file(path);
        if (!file)
        {
            return -1;
        }
        const std::string stat((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        const auto paren = stat.rfind(')');
        if (paren == std::string::npos || paren + 2 > stat.size())
        {
            return -1;
        }
        std::istringstream fields(stat.substr(paren + 2));
        std::vector<std::string> tokens;
        std::string token;
        while (fields >> token)
        {
            tokens.push_back(token);
        }
        // tokens[0] is field 3 (state): utime (field 14) = tokens[11], stime (field 15) = tokens[12].
        if (tokens.size() < 13)
        {
            return -1;
        }
        try
        {
            return std::stoll(tokens[11]) + std::stoll(tokens[12]);
        }
        catch (...)
        {
            return -1;
        }
    }

    /// Tids of this process whose name starts with `prefix` (/proc/self/task/<tid>/comm).
    inline std::vector<int> threadsNamed(const std::string& prefix)
    {
        std::vector<int> tids;
        for (const auto& entry : std::filesystem::directory_iterator("/proc/self/task"))
        {
            std::ifstream comm(entry.path() / "comm");
            std::string name;
            if (std::getline(comm, name) && name.rfind(prefix, 0) == 0)
            {
                tids.push_back(std::stoi(entry.path().filename().string()));
            }
        }
        return tids;
    }

    /// `Cpus_allowed_list` of /proc/self/status, with ',' written as ';' so the CSV column stays one field.
    inline std::string cpusAllowed()
    {
        std::ifstream status("/proc/self/status");
        std::string line;
        while (std::getline(status, line))
        {
            if (line.rfind("Cpus_allowed_list:", 0) == 0)
            {
                auto value = line.substr(line.find(':') + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                for (auto& c : value)
                {
                    c = c == ',' ? ';' : c;
                }
                return value;
            }
        }
        return "unknown";
    }

    /// Path of the libwazuhext the process mapped (/proc/self/maps), or empty.
    inline std::string loadedWazuhext()
    {
        std::ifstream maps("/proc/self/maps");
        std::string line;
        while (std::getline(maps, line))
        {
            const auto slash = line.find('/');
            if (slash != std::string::npos && line.find("libwazuhext", slash) != std::string::npos)
            {
                return line.substr(slash);
            }
        }
        return {};
    }

    /// Lower-case hex sha256 of a file, or "unknown".
    inline std::string sha256Of(const std::string& path)
    {
        std::ifstream file(path, std::ios::binary);
        if (path.empty() || !file)
        {
            return "unknown";
        }
        std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
        if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
        {
            return "unknown";
        }
        std::vector<char> buffer(1 << 20);
        while (file)
        {
            file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            if (file.gcount() > 0 &&
                EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<std::size_t>(file.gcount())) != 1)
            {
                return "unknown";
            }
        }
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
        if (EVP_DigestFinal_ex(ctx.get(), digest, &length) != 1)
        {
            return "unknown";
        }
        std::ostringstream hex;
        for (unsigned int i = 0; i < length; ++i)
        {
            hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
        }
        return hex.str();
    }

    /// One CSV row (I58 column order). Empty optional = empty field (the v1 has no transfer timings).
    struct Row final
    {
        std::string mode;
        std::string headers;
        std::string side;
        int c {1};
        int pair {0};
        std::uint64_t requests {0};
        std::uint64_t bytes {0};
        double secs {0};
        std::optional<double> reqMsMean;
        std::optional<double> xferMsMean;
        std::optional<double> connectMsSum;
        std::optional<double> appConnectMsSum;
        double threadCpu {-1};
        double procCpu {-1};
        std::string cpus;
        std::string wazuhextSha256;
        std::uint64_t errors {0};
        std::uint64_t serverBytes {0};
        bool valid {false};
    };

    inline const char* csvHeader()
    {
        return "mode,headers,side,c,pair,requests,bytes,secs,mib_s,req_ms_mean,xfer_ms_mean,connect_ms_sum,"
               "appconnect_ms_sum,thread_cpu,proc_cpu,cpus,wazuhext_sha256,errors,server_bytes,valid";
    }

    inline std::string fixed(double value, int precision)
    {
        std::ostringstream out;
        out << std::fixed << std::setprecision(precision) << value;
        return out.str();
    }

    inline std::string optionalField(const std::optional<double>& value)
    {
        return value ? fixed(*value, 3) : std::string();
    }

    inline void printRow(const Row& row)
    {
        const double mibs = row.secs > 0 ? static_cast<double>(row.bytes) / 1048576.0 / row.secs : 0;
        std::cout << "ROW," << row.mode << ',' << row.headers << ',' << row.side << ',' << row.c << ',' << row.pair
                  << ',' << row.requests << ',' << row.bytes << ',' << fixed(row.secs, 3) << ',' << fixed(mibs, 3)
                  << ',' << optionalField(row.reqMsMean) << ',' << optionalField(row.xferMsMean) << ','
                  << optionalField(row.connectMsSum) << ',' << optionalField(row.appConnectMsSum) << ','
                  << fixed(row.threadCpu, 1) << ',' << fixed(row.procCpu, 1) << ',' << row.cpus << ','
                  << row.wazuhextSha256 << ',' << row.errors << ',' << row.serverBytes << ',' << (row.valid ? 1 : 0)
                  << std::endl;
    }

    /// `HEADER <name>: <value>` per header of the first measured `/_bulk`; the Host port (one fake per process) is
    /// dropped so that both executables can be compared.
    inline void printHeaders(const BenchFake& fake)
    {
        for (auto [name, value] : fake.firstBulkHeaders())
        {
            if (name == "host")
            {
                value = value.substr(0, value.rfind(':'));
            }
            std::cout << "HEADER " << name << ": " << value << "\n";
        }
        std::cout.flush();
    }

    /// Percent of one CPU between two tick samples over `secs`; -1 when a sample is missing.
    inline double cpuPercent(long long before, long long after, double secs)
    {
        if (before < 0 || after < 0 || after < before || secs <= 0)
        {
            return -1;
        }
        return 100.0 * static_cast<double>(after - before) / static_cast<double>(::sysconf(_SC_CLK_TCK)) / secs;
    }
} // namespace bench

#endif // _INDEXER_CLIENT_BENCH_COMMON_HPP
