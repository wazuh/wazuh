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

#include <fstream>
#include <istream>
#include <regex>
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

            static const auto getValueFnc
            {
                [](const std::string & val)
                {
                    const auto start{val.find(">")};
                    const auto end{val.rfind("<")};
                    return val.substr(start + 1, end - start - 1);
                }
            };

            const auto getDataFnc
            {
                [this, &filePath](std::istream & data)
                {
                    std::string line;
                    std::string bundleShortVersionString;
                    std::string bundleVersion;

                    while (std::getline(data, line))
                    {
                        line = Utils::trim(line, " \t");

                        if (line == "<key>CFBundleName</key>" &&
                                std::getline(data, line))
                        {
                            m_name = getValueFnc(line);
                        }
                        else if (line == "<key>CFBundleExecutable</key>" &&
                                 m_name.empty() && std::getline(data, line))
                        {
                            m_name = getValueFnc(line);
                        }
                        else if (line == "<key>CFBundleShortVersionString</key>" &&
                                 std::getline(data, line))
                        {
                            bundleShortVersionString = getValueFnc(line);
                        }
                        else if (line == "<key>CFBundleVersion</key>" &&
                                 std::getline(data, line))
                        {
                            bundleVersion = getValueFnc(line);
                        }
                        else if (line == "<key>LSApplicationCategoryType</key>" &&
                                 std::getline(data, line))
                        {
                            auto groups = getValueFnc(line);

                            if (!groups.empty())
                            {
                                m_groups = groups;
                            }
                        }
                        else if (line == "<key>CFBundleIdentifier</key>" &&
                                 std::getline(data, line))
                        {
                            auto description = getValueFnc(line);

                            if (!description.empty())
                            {
                                m_description = description;
                                std::string vendor;

                                if (Utils::findRegexInString(m_description, vendor, bundleIdRegex, 1))
                                {
                                    m_vendor = vendor;
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

            static const auto getValueFnc
            {
                [](const std::string & val)
                {
                    const auto start{val.find(">")};
                    const auto end{val.rfind("<")};
                    return val.substr(start + 1, end - start - 1);
                }
            };

            const auto getDataFncRcp
            {
                [this, &filePath](std::istream & data)
                {
                    std::string line;

                    while (std::getline(data, line))
                    {
                        line = Utils::trim(line, " \t");

                        if (line == "<key>PackageIdentifier</key>" &&
                                std::getline(data, line))
                        {
                            m_description = getValueFnc(line);
                            auto reverseDomainName = Utils::split(m_description, '.');

                            for (size_t i = 0; i < reverseDomainName.size(); i++)
                            {
                                if (i == 1)
                                {
                                    m_vendor = reverseDomainName[i];
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
                        else if (line == "<key>PackageVersion</key>" &&
                                 std::getline(data, line))
                        {
                            m_version = getValueFnc(line);
                        }
                        else if (line == "<key>InstallDate</key>" &&
                                 std::getline(data, line))
                        {
                            m_installTime = getValueFnc(line);
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
};

#endif //_PKG_WRAPPER_H
