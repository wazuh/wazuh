/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * December 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PKG_WRAPPER_H
#define _PKG_WRAPPER_H

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <functional>
#include <fstream>
#include <istream>
#include <regex>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <utility>
#include "stringHelper.h"
#include "ipackageWrapper.h"
#include "sharedDefs.h"
#include "plist/plist.h"
#include "filesystemHelper.h"

static const std::string APP_INFO_PATH      { "Contents/Info.plist" };
static const std::string PLIST_BINARY_START { "bplist00"            };
static const std::string UTILITIES_FOLDER   { "/Utilities"          };
const std::set<std::string> excludedCategories = {"pkg", "x86_64", "arm64"};

class PKGWrapper final : public IPackageWrapper
{
    public:
        using ReceiptLivenessFn =
            std::function<bool(const std::string& receiptPath, const std::string& installPrefix)>;

        static void setReceiptLivenessChecker(ReceiptLivenessFn fn)
        {
            s_receiptLivenessChecker() = std::move(fn);
        }

        static void resetReceiptLivenessChecker()
        {
            s_receiptLivenessChecker() = &PKGWrapper::defaultReceiptLivenessChecker;
        }

        explicit PKGWrapper(const PackageContext& ctx)
            : m_version{UNKNOWN_VALUE}
            , m_groups{UNKNOWN_VALUE}
            , m_description {UNKNOWN_VALUE}
            , m_architecture{UNKNOWN_VALUE}
            , m_format{"pkg"}
            , m_source {UNKNOWN_VALUE}
            , m_location {UNKNOWN_VALUE}
            , m_priority {UNKNOWN_VALUE}
            , m_size {0}
            , m_vendor{UNKNOWN_VALUE}
            , m_installTime {UNKNOWN_VALUE}
        {
            if (Utils::endsWith(ctx.package, ".app"))
            {
                getPkgData(ctx.filePath + "/" + ctx.package + "/" + APP_INFO_PATH);
            }
            else
            {
                getPkgDataRcp(ctx.filePath + "/" + ctx.package);
            }
        }

        ~PKGWrapper() = default;

        std::string name() const override
        {
            return m_name;
        }
        std::string version() const override
        {
            return m_version;
        }
        std::string groups() const override
        {
            return m_groups;
        }
        std::string description() const override
        {
            return m_description;
        }
        std::string architecture() const override
        {
            return m_architecture;
        }
        std::string format() const override
        {
            return m_format;
        }
        std::string osPatch() const override
        {
            return m_osPatch;
        }
        std::string source() const override
        {
            return m_source;
        }
        std::string location() const override
        {
            return m_location;
        }
        std::string vendor() const override
        {
            return m_vendor;
        }

        std::string priority() const override
        {
            return m_priority;
        }

        int64_t size() const override
        {
            return m_size;
        }

        std::string install_time() const override
        {
            return m_installTime;
        }

        std::string multiarch() const override
        {
            return m_multiarch;
        }

    private:
        static bool extractPlistScalarValue(const std::string& line,
                                            const std::string& tag,
                                            std::string& value)
        {
            const std::string startTag { "<" + tag + ">" };
            const std::string endTag { "</" + tag + ">" };

            const auto start { line.find(startTag) };

            if (start == std::string::npos)
            {
                return false;
            }

            const auto contentStart { start + startTag.size() };
            const auto end { line.find(endTag, contentStart) };

            if (end == std::string::npos)
            {
                return false;
            }

            value = line.substr(contentStart, end - contentStart);
            return true;
        }

        static bool readPlistValue(std::istream& data,
                                   const std::string& line,
                                   const std::string& keyTag,
                                   std::string& value)
        {
            const auto keyPos { line.find(keyTag) };

            if (keyPos == std::string::npos)
            {
                return false;
            }

            const auto readScalarValue =
                [&value](const std::string & candidate)
            {
                return extractPlistScalarValue(candidate, "string", value) ||
                       extractPlistScalarValue(candidate, "date", value);
            };

            if (readScalarValue(line.substr(keyPos + keyTag.size())))
            {
                return true;
            }

            std::string nextLine;

            while (std::getline(data, nextLine))
            {
                nextLine = Utils::trim(nextLine, " \t");

                if (nextLine.empty())
                {
                    continue;
                }

                return readScalarValue(nextLine);
            }

            return false;
        }

        void getPkgData(const std::string& filePath)
        {
            const auto isBinaryFnc
            {
                [&filePath]()
                {
                    // If first line is "bplist00" it's a binary plist file
                    std::fstream file {filePath, std::ios_base::in};
                    std::string line;
                    return std::getline(file, line) && Utils::startsWith(line, PLIST_BINARY_START);
                }
            };
            const auto isBinary { isBinaryFnc() };
            constexpr auto BUNDLEID_PATTERN{R"(^[^.]+\.([^.]+).*$)"};
            static std::regex bundleIdRegex{BUNDLEID_PATTERN};

            const auto getDataFnc
            {
                [this, &filePath](std::istream & data)
                {
                    std::string line;
                    std::string bundleShortVersionString;
                    std::string bundleVersion;
                    std::string value;

                    while (std::getline(data, line))
                    {
                        line = Utils::trim(line, " \t");

                        if (readPlistValue(data, line, "<key>CFBundleName</key>", value))
                        {
                            m_name = value;
                        }
                        else if (m_name.empty() &&
                                 readPlistValue(data, line, "<key>CFBundleExecutable</key>", value))
                        {
                            m_name = value;
                        }
                        else if (readPlistValue(data, line, "<key>CFBundleShortVersionString</key>", value))
                        {
                            bundleShortVersionString = value;
                        }
                        else if (readPlistValue(data, line, "<key>CFBundleVersion</key>", value))
                        {
                            bundleVersion = value;
                        }
                        else if (readPlistValue(data, line, "<key>LSApplicationCategoryType</key>", value))
                        {
                            auto groups = value;

                            if (!groups.empty())
                            {
                                m_groups = groups;
                            }
                        }
                        else if (readPlistValue(data, line, "<key>CFBundleIdentifier</key>", value))
                        {
                            auto description = value;

                            if (!description.empty())
                            {
                                m_description = description;
                                std::string vendor;

                                if (Utils::findRegexInString(m_description, vendor, bundleIdRegex, 1))
                                {
                                    m_vendor = vendor;

                                    if (m_vendor.size() > 0 && islower(m_vendor[0]))
                                    {
                                        m_vendor[0] = toupper(m_vendor[0]);
                                    }
                                }
                            }
                        }
                    }

                    if (!bundleShortVersionString.empty())
                    {
                        if (Utils::startsWith(bundleVersion, bundleShortVersionString))
                        {
                            m_version = bundleVersion;
                        }
                        else
                        {
                            m_version = bundleShortVersionString;
                        }
                    }

                    m_architecture = UNKNOWN_VALUE;
                    m_multiarch = UNKNOWN_VALUE;
                    m_priority = UNKNOWN_VALUE;
                    m_size = 0;
                    m_installTime = UNKNOWN_VALUE;
                    m_source = filePath.find(UTILITIES_FOLDER) ? "utilities" : "applications";
                    m_location = filePath;
                }
            };

            if (isBinary)
            {
                auto xmlContent { binaryToXML(filePath) };
                getDataFnc(xmlContent);
            }
            else
            {
                std::fstream file { filePath, std::ios_base::in };

                if (file.is_open())
                {
                    getDataFnc(file);
                }
            }
        }

        void getPkgDataRcp(const std::string& filePath)
        {
            const auto isBinaryFnc
            {
                [&filePath]()
                {
                    // If first line is "bplist00" it's a binary plist file
                    std::fstream file {filePath, std::ios_base::in};
                    std::string line;
                    return std::getline(file, line) && Utils::startsWith(line, PLIST_BINARY_START);
                }
            };
            const auto isBinary { isBinaryFnc() };

            const auto getDataFncRcp
            {
                [this, &filePath](std::istream & data)
                {
                    std::string line;
                    std::string value;

                    while (std::getline(data, line))
                    {
                        line = Utils::trim(line, " \t");

                        if (readPlistValue(data, line, "<key>PackageIdentifier</key>", value))
                        {
                            m_description = value;
                            auto reverseDomainName = Utils::split(m_description, '.');

                            for (size_t i = 0; i < reverseDomainName.size(); i++)
                            {
                                if (i == 1)
                                {
                                    m_vendor = reverseDomainName[i];

                                    if (m_vendor.size() > 0 && islower(m_vendor[0]))
                                    {
                                        m_vendor[0] = toupper(m_vendor[0]);
                                    }
                                }
                                else if (i > 1)
                                {
                                    const std::string& current = reverseDomainName[i];

                                    if (excludedCategories.find(current) == excludedCategories.end())
                                    {
                                        if (!m_name.empty())
                                        {
                                            m_name += ".";
                                        }

                                        m_name += current;
                                    }
                                }
                            }
                        }
                        else if (readPlistValue(data, line, "<key>PackageVersion</key>", value))
                        {
                            m_version = value;
                        }
                        else if (readPlistValue(data, line, "<key>InstallDate</key>", value))
                        {
                            m_installTime = value;
                        }
                        else if (readPlistValue(data, line, "<key>InstallPrefixPath</key>", value))
                        {
                            m_installPrefix = value;
                        }
                    }

                    m_multiarch = UNKNOWN_VALUE;
                    m_source = "receipts";
                    m_location = filePath;
                }
            };

            if (isBinary)
            {
                auto xmlContent { binaryToXML(filePath) };
                getDataFncRcp(xmlContent);
            }
            else
            {
                std::fstream file { filePath, std::ios_base::in };

                if (file.is_open())
                {
                    getDataFncRcp(file);
                }
            }

            const auto& checker = s_receiptLivenessChecker();

            if (checker)
            {
                const std::string prefix { (m_installPrefix.empty() || m_installPrefix == ".") ? "/" : m_installPrefix };

                if (!checker(filePath, prefix))
                {
                    m_name.clear();
                }
            }
        }

        static bool defaultReceiptLivenessChecker(const std::string& receiptPath,
                                                  const std::string& installPrefix)
        {
            // Locate companion BOM (<pkgid>.bom next to <pkgid>.plist).
            static const std::string PLIST_EXT { ".plist" };
            static const std::string BOM_EXT   { ".bom" };

            if (!Utils::endsWith(receiptPath, PLIST_EXT))
            {
                return true;
            }

            std::string bomPath { receiptPath.substr(0, receiptPath.size() - PLIST_EXT.size()) };
            bomPath += BOM_EXT;

            struct stat st {};

            if (::stat(bomPath.c_str(), &st) != 0)
            {
                return (errno != ENOENT && errno != ENOTDIR) ? true : false;
            }

            std::string escaped;
            escaped.reserve(bomPath.size());

            for (char c : bomPath)
            {
                if (c == '\'')
                {
                    escaped += "'\\''";
                }
                else
                {
                    escaped += c;
                }
            }

            const std::string cmd { "/usr/bin/lsbom -s '" + escaped + "' 2>/dev/null" };

            FILE* pipe { ::popen(cmd.c_str(), "r") };

            if (!pipe)
            {
                return true;
            }

            constexpr int MAX_PROBES { 16 };
            int probes { 0 };
            bool alive { false };
            char buffer[4096];

            const auto prefix = (installPrefix.empty() || installPrefix == ".") ? std::string{"/"} :
                                installPrefix;

            while (probes < MAX_PROBES && std::fgets(buffer, sizeof(buffer), pipe) != nullptr)
            {
                std::string line { buffer };

                while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                {
                    line.pop_back();
                }

                // Skip the BOM root entry (".") and empty lines.
                if (line.empty() || line == ".")
                {
                    continue;
                }

                if (line.front() == '.')
                {
                    line.erase(0, 1);
                }

                std::string absolute { prefix };

                if (!absolute.empty() && absolute.back() == '/' && !line.empty() && line.front() == '/')
                {
                    absolute.pop_back();
                }

                absolute += line;

                struct stat childSt {};

                if (::lstat(absolute.c_str(), &childSt) == 0)
                {
                    alive = true;
                    break;
                }

                ++probes;
            }

            const int pcStatus { ::pclose(pipe) };

            if (pcStatus != 0 && !alive)
            {
                return true;
            }

            return alive;
        }

        static ReceiptLivenessFn& s_receiptLivenessChecker()
        {
            static ReceiptLivenessFn instance { &PKGWrapper::defaultReceiptLivenessChecker };
            return instance;
        }

        std::stringstream binaryToXML(const std::string& filePath)
        {
            std::string xmlContent;
            plist_t rootNode { nullptr };
            const auto binaryContent { Utils::getBinaryContent(filePath) };

            // plist C++ APIs calls - to be used when Makefile and external are updated.
            // const auto dataFromBin { PList::Structure::FromBin(binaryContent) };
            // const auto xmlContent { dataFromBin->ToXml() };

            // Content binary file to plist representation
            plist_from_bin(binaryContent.data(), binaryContent.size(), &rootNode);

            if (nullptr != rootNode)
            {
                char* xml { nullptr };
                uint32_t length { 0 };
                // plist binary representation to XML
                plist_to_xml(rootNode, &xml, &length);

                if (nullptr != xml)
                {
                    xmlContent.assign(xml, xml + length);
                    plist_to_xml_free(xml);
                    plist_free(rootNode);
                }
            }

            return std::stringstream{xmlContent};
        }

        std::string m_name;
        std::string m_version;
        std::string m_groups;
        std::string m_description;
        std::string m_architecture;
        const std::string m_format;
        std::string m_osPatch;
        std::string m_source;
        std::string m_location;
        std::string m_multiarch;
        std::string m_priority;
        int64_t m_size;
        std::string m_vendor;
        std::string m_installTime;
        std::string m_installPrefix;
};

#endif //_PKG_WRAPPER_H
