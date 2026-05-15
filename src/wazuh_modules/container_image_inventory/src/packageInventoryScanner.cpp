/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "packageInventoryScanner.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "sqlite3.h"

namespace container_image_inventory
{
    namespace
    {
        std::string trim(const std::string& s)
        {
            size_t b = 0;
            while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n'))
            {
                ++b;
            }
            size_t e = s.size();
            while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n'))
            {
                --e;
            }
            return s.substr(b, e - b);
        }

        std::vector<std::string> split_blocks(const std::string& content)
        {
            std::vector<std::string> blocks;
            std::string cur;
            std::istringstream ss(content);
            std::string line;
            bool prev_blank = false;
            while (std::getline(ss, line))
            {
                if (!line.empty() && line.back() == '\r')
                {
                    line.pop_back();
                }
                if (line.empty())
                {
                    if (!cur.empty() && prev_blank == false)
                    {
                        blocks.push_back(cur);
                        cur.clear();
                    }
                    prev_blank = true;
                }
                else
                {
                    if (!cur.empty())
                    {
                        cur.push_back('\n');
                    }
                    cur += line;
                    prev_blank = false;
                }
            }
            if (!cur.empty())
            {
                blocks.push_back(cur);
            }
            return blocks;
        }
    } // namespace

    std::vector<Package> parse_dpkg(const std::string& content)
    {
        std::vector<Package> out;
        const auto blocks = split_blocks(content);
        for (const auto& block : blocks)
        {
            std::map<std::string, std::string> info;
            std::string current_key;
            std::istringstream ss(block);
            std::string line;
            while (std::getline(ss, line))
            {
                if (line.empty())
                {
                    continue;
                }
                if (line[0] == ' ' || line[0] == '\t')
                {
                    if (!current_key.empty())
                    {
                        info[current_key] += "\n" + trim(line);
                    }
                }
                else
                {
                    auto pos = line.find(':');
                    if (pos != std::string::npos)
                    {
                        current_key = trim(line.substr(0, pos));
                        info[current_key] = trim(line.substr(pos + 1));
                    }
                }
            }
            auto st_it = info.find("Status");
            auto pkg_it = info.find("Package");
            if (st_it == info.end() || pkg_it == info.end())
            {
                continue;
            }
            if (st_it->second.find("ok installed") == std::string::npos)
            {
                continue;
            }

            Package p;
            p.name = pkg_it->second;
            auto get = [&](const char* k, const std::string& def) -> std::string {
                auto it = info.find(k);
                return it == info.end() ? def : it->second;
            };
            p.version_ = get("Version", UNKNOWN_VALUE);
            p.architecture = get("Architecture", UNKNOWN_VALUE);
            try
            {
                const auto isize = info.find("Installed-Size");
                if (isize != info.end())
                {
                    p.size = static_cast<int64_t>(std::stoll(isize->second)) * 1024;
                }
            }
            catch (const std::exception&)
            {
                p.size = 0;
            }
            std::string desc = get("Description", UNKNOWN_VALUE);
            auto nl = desc.find('\n');
            if (nl != std::string::npos)
            {
                desc.resize(nl);
            }
            p.description = desc;
            p.priority = get("Priority", UNKNOWN_VALUE);
            p.category = get("Section", UNKNOWN_VALUE);
            p.source = get("Source", UNKNOWN_VALUE);
            p.multiarch = get("Multi-Arch", "");
            p.vendor = get("Maintainer", UNKNOWN_VALUE);
            p.installed = UNKNOWN_VALUE;
            p.path = UNKNOWN_VALUE;
            p.type = "deb";
            out.push_back(std::move(p));
        }
        return out;
    }

    std::vector<Package> parse_apk(const std::string& content)
    {
        std::vector<Package> out;
        const auto blocks = split_blocks(content);
        for (const auto& block : blocks)
        {
            std::map<char, std::string> data;
            std::istringstream ss(block);
            std::string line;
            while (std::getline(ss, line))
            {
                if (line.size() < 3 || line[1] != ':')
                {
                    continue;
                }
                char key = line[0];
                data[key] = trim(line.substr(2));
            }
            auto p_it = data.find('P');
            auto v_it = data.find('V');
            if (p_it == data.end() || v_it == data.end())
            {
                continue;
            }
            Package p;
            p.name = p_it->second;
            p.version_ = v_it->second;
            auto a_it = data.find('A');
            if (a_it != data.end())
            {
                p.architecture = a_it->second;
            }
            auto i_it = data.find('I');
            if (i_it != data.end())
            {
                try { p.size = std::stoll(i_it->second); } catch (...) { p.size = 0; }
            }
            auto t_it = data.find('T');
            if (t_it != data.end())
            {
                p.description = t_it->second;
            }
            p.type = "apk";
            p.vendor = "Alpine Linux";
            out.push_back(std::move(p));
        }
        return out;
    }

    // RPM header tag IDs (matches packageLinuxParserRpm.cpp).
    constexpr uint32_t RPM_TAG_NAME = 1000;
    constexpr uint32_t RPM_TAG_VERSION = 1001;
    constexpr uint32_t RPM_TAG_RELEASE = 1002;
    constexpr uint32_t RPM_TAG_EPOCH = 1003;
    constexpr uint32_t RPM_TAG_SUMMARY = 1004;
    constexpr uint32_t RPM_TAG_INSTALLTIME = 1008;
    constexpr uint32_t RPM_TAG_SIZE = 1009;
    constexpr uint32_t RPM_TAG_VENDOR = 1011;
    constexpr uint32_t RPM_TAG_GROUP = 1016;
    constexpr uint32_t RPM_TAG_ARCH = 1022;
    constexpr uint32_t RPM_TAG_SOURCERPM = 1044;

    constexpr uint32_t RPM_TYPE_INT32 = 4;
    constexpr uint32_t RPM_TYPE_STRING = 6;
    constexpr uint32_t RPM_TYPE_STRING_ARRAY = 8;
    constexpr uint32_t RPM_TYPE_I18NSTRING = 9;

    static uint32_t be32(const unsigned char* p)
    {
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
    }

    static bool parse_rpm_header_blob(const unsigned char* blob, size_t len, Package& out)
    {
        if (len < 8)
        {
            return false;
        }
        uint32_t index_size = be32(blob);
        uint32_t data_size = be32(blob + 4);
        if (index_size == 0 || index_size > 65535)
        {
            return false;
        }
        const size_t index_start = 8;
        const size_t data_start = index_start + 16 * static_cast<size_t>(index_size);
        if (data_start + data_size > len)
        {
            return false;
        }
        const unsigned char* data = blob + data_start;

        std::string name, version, release, summary, vendor, group, arch, sourcerpm, installtime;
        int64_t size_bytes = 0;
        uint32_t epoch = 0;
        bool has_epoch = false;
        bool has_name = false;

        for (uint32_t i = 0; i < index_size; ++i)
        {
            const unsigned char* e = blob + index_start + 16 * i;
            const uint32_t tag = be32(e);
            const uint32_t typ = be32(e + 4);
            const uint32_t off_in_data = be32(e + 8);
            // const uint32_t count = be32(e + 12); // unused

            auto read_string = [&](std::string& dst) {
                if (off_in_data >= data_size)
                {
                    return;
                }
                size_t end = off_in_data;
                while (end < data_size && data[end] != 0)
                {
                    ++end;
                }
                dst.assign(reinterpret_cast<const char*>(data + off_in_data), end - off_in_data);
            };

            auto read_int32 = [&](int64_t& dst) {
                if (off_in_data + 4 > data_size)
                {
                    return;
                }
                dst = static_cast<int64_t>(be32(data + off_in_data));
            };

            switch (tag)
            {
                case RPM_TAG_NAME:
                    if (typ == RPM_TYPE_STRING || typ == RPM_TYPE_I18NSTRING || typ == RPM_TYPE_STRING_ARRAY)
                    {
                        read_string(name);
                        has_name = !name.empty();
                    }
                    break;
                case RPM_TAG_VERSION:
                    if (typ == RPM_TYPE_STRING || typ == RPM_TYPE_I18NSTRING || typ == RPM_TYPE_STRING_ARRAY)
                        read_string(version);
                    break;
                case RPM_TAG_RELEASE:
                    if (typ == RPM_TYPE_STRING || typ == RPM_TYPE_I18NSTRING || typ == RPM_TYPE_STRING_ARRAY)
                        read_string(release);
                    break;
                case RPM_TAG_EPOCH:
                    if (typ == RPM_TYPE_INT32 && off_in_data + 4 <= data_size)
                    {
                        epoch = be32(data + off_in_data);
                        has_epoch = true;
                    }
                    break;
                case RPM_TAG_SUMMARY:
                    if (typ == RPM_TYPE_STRING || typ == RPM_TYPE_I18NSTRING || typ == RPM_TYPE_STRING_ARRAY)
                        read_string(summary);
                    break;
                case RPM_TAG_INSTALLTIME:
                    if (typ == RPM_TYPE_INT32)
                    {
                        int64_t t = 0;
                        read_int32(t);
                        installtime = std::to_string(t);
                    }
                    break;
                case RPM_TAG_SIZE:
                    if (typ == RPM_TYPE_INT32)
                        read_int32(size_bytes);
                    break;
                case RPM_TAG_VENDOR:
                    if (typ == RPM_TYPE_STRING || typ == RPM_TYPE_I18NSTRING || typ == RPM_TYPE_STRING_ARRAY)
                        read_string(vendor);
                    break;
                case RPM_TAG_GROUP:
                    if (typ == RPM_TYPE_STRING || typ == RPM_TYPE_I18NSTRING || typ == RPM_TYPE_STRING_ARRAY)
                        read_string(group);
                    break;
                case RPM_TAG_ARCH:
                    if (typ == RPM_TYPE_STRING || typ == RPM_TYPE_I18NSTRING || typ == RPM_TYPE_STRING_ARRAY)
                        read_string(arch);
                    break;
                case RPM_TAG_SOURCERPM:
                    if (typ == RPM_TYPE_STRING || typ == RPM_TYPE_I18NSTRING || typ == RPM_TYPE_STRING_ARRAY)
                        read_string(sourcerpm);
                    break;
                default:
                    break;
            }
        }

        if (!has_name)
        {
            return false;
        }

        std::string version_full;
        if (has_epoch && epoch != 0)
        {
            version_full = std::to_string(epoch) + ":" + version + "-" + release;
        }
        else if (!release.empty())
        {
            version_full = version + "-" + release;
        }
        else
        {
            version_full = version;
        }

        out.name = name;
        out.version_ = version_full.empty() ? std::string(UNKNOWN_VALUE) : version_full;
        out.architecture = arch.empty() ? std::string(UNKNOWN_VALUE) : arch;
        out.size = size_bytes;
        out.description = summary.empty() ? std::string(UNKNOWN_VALUE) : summary;
        out.priority = UNKNOWN_VALUE;
        out.category = group.empty() ? std::string(UNKNOWN_VALUE) : group;
        out.source = sourcerpm.empty() ? std::string(UNKNOWN_VALUE) : sourcerpm;
        out.multiarch = UNKNOWN_VALUE;
        out.vendor = vendor.empty() ? std::string(UNKNOWN_VALUE) : vendor;
        out.installed = installtime.empty() ? std::string(UNKNOWN_VALUE) : installtime;
        out.path = UNKNOWN_VALUE;
        out.type = "rpm";
        return true;
    }

    std::vector<Package> parse_rpm_sqlite(const std::string& sqlite_path)
    {
        std::vector<Package> out;
        sqlite3* db = nullptr;
        const std::string uri = "file:" + sqlite_path + "?immutable=1";
        if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK)
        {
            if (db)
            {
                sqlite3_close(db);
            }
            throw std::runtime_error("sqlite open failed");
        }
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT blob FROM Packages", -1, &stmt, nullptr) != SQLITE_OK)
        {
            sqlite3_close(db);
            throw std::runtime_error("sqlite prepare failed");
        }
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            const void* data = sqlite3_column_blob(stmt, 0);
            int sz = sqlite3_column_bytes(stmt, 0);
            if (data == nullptr || sz <= 0)
            {
                continue;
            }
            Package pkg;
            if (parse_rpm_header_blob(static_cast<const unsigned char*>(data), static_cast<size_t>(sz), pkg))
            {
                out.push_back(std::move(pkg));
            }
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return out;
    }

    // -----------------------------------------------------------------------
    // Minimal Berkeley DB 4 hash walker (mirrors poc_rpm_extract.py).
    // -----------------------------------------------------------------------

    namespace
    {
        constexpr uint32_t BDB_HASH_MAGIC = 0x00061561;
        constexpr uint8_t PG_HASH = 13;
        constexpr uint8_t PG_HASH_UNSORTED = 2;
        constexpr uint8_t PG_OVERFLOW = 7;
        constexpr uint8_t H_KEYDATA = 1;
        constexpr uint8_t H_OFFPAGE = 3;

        struct Endian
        {
            bool be{true};
            uint16_t u16(const unsigned char* p) const
            {
                return be ? uint16_t((uint16_t(p[0]) << 8) | uint16_t(p[1]))
                          : uint16_t((uint16_t(p[1]) << 8) | uint16_t(p[0]));
            }
            uint32_t u32(const unsigned char* p) const
            {
                return be ? ((uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) |
                             uint32_t(p[3]))
                          : ((uint32_t(p[3]) << 24) | (uint32_t(p[2]) << 16) | (uint32_t(p[1]) << 8) |
                             uint32_t(p[0]));
            }
        };

        std::vector<unsigned char> read_file_all(const std::string& path)
        {
            std::ifstream f(path, std::ios::binary);
            if (!f)
            {
                throw std::runtime_error("cannot open BDB file: " + path);
            }
            f.seekg(0, std::ios::end);
            std::streamoff len = f.tellg();
            f.seekg(0, std::ios::beg);
            std::vector<unsigned char> buf(static_cast<size_t>(len));
            if (len > 0)
            {
                f.read(reinterpret_cast<char*>(buf.data()), len);
            }
            return buf;
        }
    } // namespace

    std::vector<Package> parse_rpm_bdb(const std::string& bdb_path)
    {
        const auto buf = read_file_all(bdb_path);
        if (buf.size() < 32)
        {
            throw std::runtime_error("BDB file too small");
        }

        Endian en;
        const uint32_t magic_be = (uint32_t(buf[12]) << 24) | (uint32_t(buf[13]) << 16) |
                                  (uint32_t(buf[14]) << 8) | uint32_t(buf[15]);
        const uint32_t magic_le = (uint32_t(buf[15]) << 24) | (uint32_t(buf[14]) << 16) |
                                  (uint32_t(buf[13]) << 8) | uint32_t(buf[12]);
        if (magic_be == BDB_HASH_MAGIC)
        {
            en.be = true;
        }
        else if (magic_le == BDB_HASH_MAGIC)
        {
            en.be = false;
        }
        else
        {
            throw std::runtime_error("Not a BDB hash file");
        }

        const uint32_t page_size = en.u32(buf.data() + 20);
        if (page_size < 512 || page_size > 65536)
        {
            throw std::runtime_error("Implausible BDB page size");
        }

        const size_t num_pages = buf.size() / page_size;
        std::vector<Package> out;

        auto read_overflow = [&](uint32_t first_pgno, uint32_t total_len) -> std::vector<unsigned char> {
            std::vector<unsigned char> chain;
            uint32_t pgno = first_pgno;
            uint32_t remaining = total_len;
            while (remaining > 0 && pgno != 0)
            {
                if (static_cast<size_t>(pgno) * page_size + page_size > buf.size())
                {
                    break;
                }
                const unsigned char* page = buf.data() + static_cast<size_t>(pgno) * page_size;
                if (page[25] != PG_OVERFLOW)
                {
                    break;
                }
                const uint32_t next_pgno = en.u32(page + 16);
                const size_t chunk_max = page_size - 26;
                const size_t take = std::min<size_t>(remaining, chunk_max);
                chain.insert(chain.end(), page + 26, page + 26 + take);
                remaining -= static_cast<uint32_t>(take);
                pgno = next_pgno;
            }
            return chain;
        };

        for (size_t pgno = 1; pgno < num_pages; ++pgno)
        {
            const unsigned char* page = buf.data() + pgno * page_size;
            if (page + 26 > buf.data() + buf.size())
            {
                continue;
            }
            const uint8_t ptype = page[25];
            if (ptype != PG_HASH && ptype != PG_HASH_UNSORTED)
            {
                continue;
            }
            const uint16_t num_entries = en.u16(page + 20);
            if (num_entries == 0 || num_entries > (page_size / 2))
            {
                continue;
            }
            std::vector<uint16_t> offsets;
            offsets.reserve(num_entries);
            for (uint16_t i = 0; i < num_entries; ++i)
            {
                const size_t off_pos = 26 + 2 * i;
                if (off_pos + 2 > page_size)
                {
                    break;
                }
                offsets.push_back(en.u16(page + off_pos));
            }

            auto process_value = [&](std::vector<unsigned char>&& blob) {
                if (blob.empty())
                {
                    return;
                }
                Package pkg;
                if (parse_rpm_header_blob(blob.data(), blob.size(), pkg))
                {
                    out.push_back(std::move(pkg));
                }
            };

            for (size_t i = 1; i < offsets.size(); i += 2)
            {
                const uint16_t entry_off = offsets[i];
                if (entry_off + 1 > page_size)
                {
                    continue;
                }
                const uint8_t etype = page[entry_off];
                if (etype == H_KEYDATA)
                {
                    uint16_t end_off = page_size;
                    for (uint16_t o : offsets)
                    {
                        if (o > entry_off && o < end_off)
                        {
                            end_off = o;
                        }
                    }
                    if (end_off <= entry_off + 1 || end_off > page_size)
                    {
                        continue;
                    }
                    process_value(std::vector<unsigned char>(page + entry_off + 1, page + end_off));
                }
                else if (etype == H_OFFPAGE)
                {
                    if (entry_off + 12 > page_size)
                    {
                        continue;
                    }
                    const uint32_t first_pgno = en.u32(page + entry_off + 4);
                    const uint32_t tot_len = en.u32(page + entry_off + 8);
                    if (first_pgno == 0 || tot_len == 0 || tot_len > 50000000)
                    {
                        continue;
                    }
                    process_value(read_overflow(first_pgno, tot_len));
                }
            }
        }
        return out;
    }
} // namespace container_image_inventory
