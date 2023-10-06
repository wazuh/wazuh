/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * August 7, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RCP_WRAPPER_H
#define _RCP_WRAPPER_H

#include <fstream>
#include "stringHelper.h"
#include "ipackageWrapper.h"
#include "sharedDefs.h"
#include "plist/plist.h"
#include "filesystemHelper.h"

class RCPWrapper final : public IPackageWrapper
{
    public:
        static constexpr auto INFO_PLIST_PATH { "Contents/Info.plist" };

        explicit RCPWrapper(const PackageContext& ctx)
            : m_groups {UNKNOWN_VALUE}
            , m_description {UNKNOWN_VALUE}
            , m_architecture {UNKNOWN_VALUE}
            , m_format {"rcp"}
            , m_source {UNKNOWN_VALUE}
            , m_location {UNKNOWN_VALUE}
            , m_priority {UNKNOWN_VALUE}
            , m_size {0}
            , m_vendor {UNKNOWN_VALUE}
            , m_installTime {UNKNOWN_VALUE}
        {
            std::string pathInstallPlistFile { ctx.filePath + "/" + ctx.package + ".plist" };
            getPlistData(pathInstallPlistFile);

            if (m_installPrefixPath.empty())
            {
                m_installPrefixPath = "/";
            }

            std::string pathPlistFile;
            std::string pathBomFile { ctx.filePath + "/" + ctx.package + ".bom" };

            if (Utils::existsRegular(pathBomFile))
            {
                getBomData(pathBomFile);

                std::string infoPlistEndingApp { std::string(".app/") + INFO_PLIST_PATH };
                std::string infoPlistEndingService { std::string(".service/") + INFO_PLIST_PATH };
                size_t numSubdirectoriesMin = (size_t) -1;

                for ( const auto& bomPath : m_bomPaths)
                {
                    if (Utils::endsWith(bomPath, infoPlistEndingApp) || Utils::endsWith(bomPath, infoPlistEndingService))
                    {
                        size_t numSubdirectoriesCurrent = Utils::split(bomPath, '/').size();

                        if (numSubdirectoriesCurrent < numSubdirectoriesMin)
                        {
                            numSubdirectoriesMin = numSubdirectoriesCurrent;
                            pathPlistFile = bomPath;
                        }
                    }
                }
            }

            if (!pathPlistFile.empty() && Utils::existsRegular(pathPlistFile))
            {
                getPlistData(pathPlistFile);
            }
        }

        ~RCPWrapper() = default;

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

        int size() const override
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

        std::string installPrefixPath() const
        {
            return m_installPrefixPath;
        }

        std::deque<std::string> bomPaths() const
        {
            return m_bomPaths;
        }

    private:
        static constexpr auto PLIST_BINARY_HEADER { "bplist00" };
        static constexpr auto UTILITIES_FOLDER { "/Utilities" };

        void getBomData(const std::string& filePath)
        {
            struct BOMHeader
            {
                // Always "BOMStore"
                char magic[8];
                // Always 1
                uint32_t version;
                // Number of non-null entries in BOMBlockTable
                uint32_t numberOfBlocks;
                uint32_t indexOffset;
                uint32_t indexLength;
                uint32_t varsOffset;
                uint32_t varsLength;
            } __attribute__((packed));

            struct BOMPointer
            {
                uint32_t address;
                uint32_t length;
            } __attribute__((packed));

            struct BOMBlockTable
            {
                // See header for number of non-null blocks
                uint32_t count;
                // First entry must always be a null entry
                BOMPointer blockPointers[];
            } __attribute__((packed));

            struct BOMTree
            {
                // Always "tree"
                char tree[4];
                // Always 1
                uint32_t version;
                // Index for BOMPaths
                uint32_t child;
                // Always 4096
                uint32_t blockSize;
                // Total number of paths in all leaves combined
                uint32_t pathCount;
                uint8_t unknown3;
            } __attribute__((packed));

            struct BOMVar
            {
                uint32_t index;
                uint8_t length;
                char name[];
            } __attribute__((packed));

            struct BOMVars
            {
                uint32_t count;
                BOMVar list[];
            } __attribute__((packed));

            struct BOMPathIndices
            {
                // for leaf: points to BOMPathInfo1, for branch points to BOMPaths
                uint32_t index0;
                // always points to BOMFile
                uint32_t index1;
            } __attribute__((packed));

            struct BOMPaths
            {
                uint16_t isLeaf;
                uint16_t count;
                uint32_t forward;
                uint32_t backward;
                BOMPathIndices indices[];
            } __attribute__((packed));

            struct BOMPathInfo2
            {
                uint8_t type;
                uint8_t unknown0;
                uint16_t architecture;
                uint16_t mode;
                uint32_t user;
                uint32_t group;
                uint32_t modtime;
                uint32_t size;
                uint8_t unknown1;
                union
                {
                    uint32_t checksum;
                    uint32_t devType;
                };
                uint32_t linkNameLength;
                char linkName[];
            } __attribute__((packed));

            struct BOMPathInfo1
            {
                uint32_t id;
                // Pointer to BOMPathInfo2
                uint32_t index;
            } __attribute__((packed));

            struct BOMFile
            {
                // Parent BOMPathInfo1->id
                uint32_t parent;
                char name[];
            } __attribute__((packed));

            size_t varsOffset { 0 };
            size_t tableOffset { 0 };
            const BOMHeader* pHeader { nullptr };
            const BOMBlockTable* pTable { nullptr };
            const BOMVars* pVars { nullptr };
            std::vector<char> fileContent;

            const auto getVariable
            {
                [](size_t& offset, size_t varsOffset, const BOMVars* pVars, std::vector<char>& fileContent) -> const BOMVar*
                {
                    if (fileContent.size() < varsOffset + offset + sizeof(BOMVar))
                    {
                        offset = 0;
                        return nullptr;
                    }

                    auto pVar = reinterpret_cast<const BOMVar*>((char*)pVars->list + offset);

                    if (pVar == nullptr)
                    {
                        offset = 0;
                        return nullptr;
                    }

                    offset += sizeof(BOMVar) + pVar->length;

                    if (fileContent.size() < varsOffset + offset)
                    {
                        offset = 0;
                        return nullptr;
                    }

                    return pVar;
                }
            };

            const auto getPointer
            {
                [&](int index, size_t& length) -> const char*
                {
                    if (ntohl(index) >= ntohl(pTable->count))
                    {
                        length = 0;
                        return nullptr;
                    }

                    const BOMPointer* pointer = pTable->blockPointers + ntohl(index);
                    uint32_t addr = ntohl(pointer->address);
                    length = ntohl(pointer->length);

                    if (addr > UINT32_MAX - length || fileContent.size() < addr + length)
                    {
                        length = 0;
                        return nullptr;
                    }

                    return fileContent.data() + addr;
                }
            };

            const auto getPaths
            {
                [&](int index) -> const BOMPaths*
                {
                    size_t pathsSize = 0;
                    auto paths = reinterpret_cast<const BOMPaths*>(getPointer(index, pathsSize));

                    if (paths == nullptr || pathsSize < sizeof(BOMPaths))
                    {
                        return nullptr;
                    }

                    if (pathsSize < ntohs(paths->count) * sizeof(BOMPathIndices))
                    {
                        return nullptr;
                    }

                    return paths;
                }
            };

            const auto generatePathString
            {
                [&](const BOMPaths * paths)
                {
                    std::map<uint32_t, std::string> filenames;
                    std::map<uint32_t, uint32_t> parents;

                    while (paths != nullptr)
                    {
                        for (unsigned j = 0; j < ntohs(paths->count); j++)
                        {
                            uint32_t index0 = paths->indices[j].index0;
                            uint32_t index1 = paths->indices[j].index1;

                            size_t info1Size;
                            auto info1 = reinterpret_cast<const BOMPathInfo1*>(getPointer(index0, info1Size));

                            if (info1 == nullptr)
                            {
                                return;
                            }

                            size_t info2Size;
                            auto info2 = reinterpret_cast<const BOMPathInfo2*>(getPointer(info1->index, info2Size));

                            if (info2 == nullptr)
                            {
                                return;
                            }

                            // Compute full name using pointer size.
                            size_t fileSize;
                            auto file = reinterpret_cast<const BOMFile*>(getPointer(index1, fileSize));

                            if (file == nullptr || fileSize <= sizeof(BOMFile))
                            {
                                return;
                            }

                            std::string filename(file->name, fileSize - sizeof(BOMFile));
                            filename = std::string(filename.c_str());

                            // Maintain a lookup from BOM file index to filename.
                            filenames[info1->id] = filename;

                            if (file->parent)
                            {
                                parents[info1->id] = file->parent;
                            }

                            auto it = parents.find(info1->id);

                            while (it != parents.end())
                            {
                                filename = filenames[it->second] + "/" + filename;
                                it = parents.find(it->second);
                            }

                            if (filename == ".")
                            {
                                continue;
                            }

                            if (m_installPrefixPath == "/")
                            {
                                filename = filename.substr(1);
                            }
                            else
                            {
                                filename = m_installPrefixPath + "/" + filename.substr(1);
                            }

                            m_bomPaths.push_back(filename);
                        }

                        if (paths->forward == htonl(0))
                        {
                            return;
                        }
                        else
                        {
                            paths = getPaths(paths->forward);
                        }
                    }
                }
            };

            m_bomPaths.clear();
            fileContent = Utils::getBinaryContent(filePath);

            // Check file headers integrity
            if (fileContent.size() < sizeof(BOMHeader))
            {
                return;
            }

            pHeader = reinterpret_cast<const BOMHeader*>(fileContent.data());

            if (std::string(pHeader->magic, 8) != "BOMStore")
            {
                return;
            }

            if (fileContent.size() < ntohl(pHeader->indexOffset) + sizeof(BOMBlockTable))
            {
                return;
            }

            pTable = reinterpret_cast<const BOMBlockTable*>(fileContent.data() + ntohl(pHeader->indexOffset));
            tableOffset = ntohl(pHeader->indexOffset) + sizeof(BOMBlockTable);

            if (fileContent.size() < tableOffset + ntohl(pTable->count) * sizeof(BOMPointer))
            {
                return;
            }

            if (fileContent.size() < ntohl(pHeader->varsOffset) + sizeof(BOMVars))
            {
                return;
            }

            pVars = reinterpret_cast<const BOMVars*>(fileContent.data() + ntohl(pHeader->varsOffset));
            varsOffset = ntohl(pHeader->varsOffset) + sizeof(BOMVars);

            if (fileContent.size() < varsOffset + ntohl(pVars->count) * sizeof(BOMVar))
            {
                return;
            }

            // Read only path variables
            size_t varOffset = 0;

            for (uint32_t varsIdx = 0; varsIdx < ntohl(pVars->count); varsIdx++)
            {
                auto pVar = getVariable(varOffset, varsOffset, pVars, fileContent);

                if (pVar == nullptr)
                {
                    break;
                }

                size_t varSize;
                auto pVarData = getPointer(pVar->index, varSize);

                if (pVarData == nullptr || varSize < sizeof(BOMTree) || varSize < pVar->length)
                {
                    break;
                }

                std::string varName = std::string(pVar->name, pVar->length);

                if (varName != "Paths")
                {
                    continue;
                }

                auto pTree = reinterpret_cast<const BOMTree*>(pVarData);
                auto pPaths = getPaths(pTree->child);

                while (pPaths != nullptr && pPaths->isLeaf == htons(0))
                {
                    if ((BOMPathIndices*)pPaths->indices == nullptr)
                    {
                        break;
                    }

                    pPaths = getPaths(pPaths->indices[0].index0);
                }

                generatePathString(pPaths);
                break;
            }
        }

        void getPlistData(const std::string& filePath)
        {
            const auto isBinaryFnc
            {
                [&filePath]()
                {
                    // If first bytes are "bplist00" it's a binary plist file
                    std::array < char, (sizeof(PLIST_BINARY_HEADER) - 1) > headerBuffer;
                    std::ifstream ifs {filePath, std::ios::binary};
                    ifs.read(headerBuffer.data(), sizeof(headerBuffer));
                    return !std::memcmp(headerBuffer.data(), PLIST_BINARY_HEADER, sizeof(PLIST_BINARY_HEADER) - 1);
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

                    m_location = filePath;
                    m_source = (filePath.find(UTILITIES_FOLDER) != std::string::npos) ? "utilities" : "applications";

                    while (std::getline(data, line))
                    {
                        line = Utils::trim(line, " \t");

                        if (line == "<key>CFBundleName</key>" &&
                                std::getline(data, line))
                        {
                            m_name = getValueFnc(line);
                        }
                        else if ((line == "<key>CFBundleShortVersionString</key>" ||
                                  line == "<key>PackageVersion</key>") &&
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
                            m_groups = getValueFnc(line);
                        }
                        else if (line == "<key>CFBundleIdentifier</key>" &&
                                 std::getline(data, line))
                        {
                            m_description = getValueFnc(line);

                            std::string vendor;

                            if (Utils::findRegexInString(m_description, vendor, bundleIdRegex, 1))
                            {
                                m_vendor = vendor;
                            }
                        }
                        else if (line == "<key>InstallPrefixPath</key>" &&
                                 std::getline(data, line))
                        {
                            m_installPrefixPath = getValueFnc(line);
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

        std::stringstream binaryToXML(const std::string& filePath)
        {
            std::string xmlContent;
            plist_t rootNode { nullptr };
            const auto binaryContent { Utils::getBinaryContent(filePath) };

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
        int m_size;
        std::string m_vendor;
        std::string m_installTime;
        std::string m_installPrefixPath;
        std::deque<std::string> m_bomPaths;
};

#endif //_RCP_WRAPPER_H
