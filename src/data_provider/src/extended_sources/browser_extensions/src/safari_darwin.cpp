#include "safari_darwin.hpp"
#include "filesystemHelper.h"
#include <iostream>
#include <algorithm>
#include <plist/plist.h>
#include <fstream>
#include <unistd.h>

const std::vector<std::string> EXTENSIONS_APP_DIRS_TO_EXCLUDE =
{
    "/Xcode.app",
    "/Safari.app",
};

BrowserExtensionsProvider::BrowserExtensionsProvider(
    std::shared_ptr<IBrowserExtensionsWrapper> browserExtensionsWrapper) :
    m_browserExtensionsWrapper(std::move(browserExtensionsWrapper)) {}

BrowserExtensionsProvider::BrowserExtensionsProvider() :
    m_browserExtensionsWrapper(std::make_shared<BrowserExtensionsWrapper>()) {}

nlohmann::json BrowserExtensionsProvider::toJson(const BrowserExtensionsData& extensions)
{
    nlohmann::json results = nlohmann::json::array();

    for (auto& extension : extensions)
    {
        nlohmann::json entry;
        entry["bundle_version"] = extension.bundle_version;
        entry["copyright"] = extension.copyright;
        entry["description"] = extension.description;
        entry["identifier"] = extension.identifier;
        entry["name"] = extension.name;
        entry["path"] = extension.path;
        entry["sdk"] = extension.sdk;
        entry["uid"] = extension.uid;
        entry["version"] = extension.version;
        results.push_back(std::move(entry));
    }

    return results;
}

nlohmann::json BrowserExtensionsProvider::collect()
{
    // Check if applicationsPathString exists
    const std::string applicationsPathString = m_browserExtensionsWrapper->getApplicationsPath();

    if (!Utils::existsDir(applicationsPathString))
    {
        std::cerr << "Path does not exist: " << applicationsPathString << std::endl;
    }

    BrowserExtensionsData browserExtensions;

    // Create list of directories inside of applicationsPathString
    for (auto& appPath : Utils::enumerateDir(applicationsPathString))
    {
        appPath = applicationsPathString + "/" + appPath;

        // For each app directory, exclude the ones in EXTENSIONS_APP_DIRS_TO_EXCLUDE
        std::string appName = "/" + Utils::getFilename(appPath);

        if (std::find(EXTENSIONS_APP_DIRS_TO_EXCLUDE.begin(), EXTENSIONS_APP_DIRS_TO_EXCLUDE.end(), appName) != EXTENSIONS_APP_DIRS_TO_EXCLUDE.end())
        {
            continue;
        }

        if (Utils::existsDir(appPath)) // check if it's a directory
        {
            auto appPluginsPath = appPath + "/" + APP_PLUGINS_PATH;

            if (!Utils::existsDir(appPluginsPath))
            {
                continue;
            }

            for (auto& element : Utils::enumerateDir(appPluginsPath))
            {
                element = appPluginsPath + element;

                if (Utils::getFileExtension(element) != ".appex")
                {
                    continue;
                }

                auto appPluginPlistPath = element + "/" + APP_PLUGIN_PLIST_PATH;

                if (!Utils::existsRegular(appPluginPlistPath))
                {
                    continue;
                }

                std::string extensionPath = appPluginPlistPath;

                std::ifstream plistFile(extensionPath, std::ios::binary | std::ios::ate);

                if (!plistFile)
                {
                    // TODO: Improve error handling
                    // std::cerr << "Failed to open file.\n";
                }

                std::streamsize fileSize = plistFile.tellg();
                plistFile.seekg(0);
                std::vector<char> readBuffer(fileSize);

                if (!plistFile.read(readBuffer.data(), fileSize))
                {
                    // TODO: Improve error handling
                    // std::cerr << "Failed to read file\n";
                }

                plist_t plistDict = nullptr;
                plist_from_memory(readBuffer.data(), readBuffer.size(), &plistDict);

                if (!plistDict || plist_get_node_type(plistDict) != PLIST_DICT)
                {
                    // TODO: Improve error handling
                    // std::cerr << "Failed to parse plist\n";
                }

                // Let's filter out the ones that are not Safari Extensions
                plist_t nsExtensionNode = plist_dict_get_item(plistDict, "NSExtension");

                if (nsExtensionNode && plist_get_node_type(nsExtensionNode) == PLIST_DICT)
                {
                    plist_t extensionTypeNode = plist_dict_get_item(nsExtensionNode, "NSExtensionPointIdentifier");

                    if (extensionTypeNode && plist_get_node_type(extensionTypeNode) == PLIST_STRING)
                    {
                        char* extensionType = nullptr;
                        plist_get_string_val(extensionTypeNode, &extensionType);
                        std::string extensionTypeString(extensionType);
                        free(extensionType);

                        if (!(extensionTypeString.find(SAFARI_FILTER_STRING) != std::string::npos))
                        {
                            continue; // Not a Safari extension
                        }

                        plist_t identifierNode = plist_dict_get_item(plistDict, "CFBundleIdentifier");
                        plist_t nameNode = plist_dict_get_item(plistDict, "CFBundleDisplayName");
                        plist_t sdkNode = plist_dict_get_item(plistDict, "CFBundleInfoDictionaryVersion");
                        plist_t versionStringNode = plist_dict_get_item(plistDict, "CFBundleShortVersionString");
                        plist_t bundleVersionNode = plist_dict_get_item(plistDict, "CFBundleVersion");
                        plist_t copyrightNode = plist_dict_get_item(plistDict, "NSHumanReadableCopyright");
                        plist_t descriptionNode = plist_dict_get_item(plistDict, "NSHumanReadableDescription");

                        // Creating an BrowserExtensionData object
                        BrowserExtensionData browserExtensionData;
                        browserExtensionData.path = extensionPath;
                        browserExtensionData.uid = std::to_string(getuid());

                        if (identifierNode && plist_get_node_type(identifierNode) == PLIST_STRING)
                        {
                            char* identifierString = nullptr;
                            plist_get_string_val(identifierNode, &identifierString);
                            browserExtensionData.identifier = identifierString;
                            free(identifierString);
                        }
                        else
                        {
                            browserExtensionData.identifier = "";
                        }

                        if (nameNode && plist_get_node_type(nameNode) == PLIST_STRING)
                        {
                            char* nameString = nullptr;
                            plist_get_string_val(nameNode, &nameString);
                            browserExtensionData.name = nameString;
                            free(nameString);
                        }
                        else
                        {
                            browserExtensionData.name = "";
                        }

                        if (sdkNode && plist_get_node_type(sdkNode) == PLIST_STRING)
                        {
                            char* sdkString = nullptr;
                            plist_get_string_val(sdkNode, &sdkString);
                            browserExtensionData.sdk = sdkString;
                            free(sdkString);
                        }
                        else
                        {
                            browserExtensionData.sdk = "";
                        }

                        if (versionStringNode && plist_get_node_type(versionStringNode) == PLIST_STRING)
                        {
                            char* versionString = nullptr;
                            plist_get_string_val(versionStringNode, &versionString);
                            browserExtensionData.version = versionString;
                            free(versionString);
                        }
                        else
                        {
                            browserExtensionData.version = "";
                        }

                        if (bundleVersionNode && plist_get_node_type(bundleVersionNode) == PLIST_STRING)
                        {
                            char* bundleVersionString = nullptr;
                            plist_get_string_val(bundleVersionNode, &bundleVersionString);
                            browserExtensionData.bundle_version = bundleVersionString;
                            free(bundleVersionString);
                        }
                        else
                        {
                            browserExtensionData.bundle_version = "";
                        }

                        if (copyrightNode && plist_get_node_type(copyrightNode) == PLIST_STRING)
                        {
                            char* copyrightString = nullptr;
                            plist_get_string_val(copyrightNode, &copyrightString);
                            browserExtensionData.copyright = copyrightString;
                            free(copyrightString);
                        }
                        else
                        {
                            browserExtensionData.copyright = "";
                        }

                        if (descriptionNode && plist_get_node_type(descriptionNode) == PLIST_STRING)
                        {
                            char* descriptionString = nullptr;
                            plist_get_string_val(descriptionNode, &descriptionString);
                            browserExtensionData.description = descriptionString;
                            free(descriptionString);
                        }
                        else
                        {
                            browserExtensionData.description = "";
                        }

                        // Add to array of extensions
                        browserExtensions.emplace_back(browserExtensionData);
                    }
                    else
                    {
                        // TODO: Improve error handling
                        // std::cerr << "Failed to parse NSExtensionPointIdentifier" << std::endl;
                    }
                }
                else
                {
                    // TODO: Improve error handling
                    // std::cerr << "Failed to parse NSExtension" << std::endl;
                }

                // Only the root plist dictionary needs to be freed, the children will be
                // handled automatically.
                if (plistDict)
                {
                    plist_free(plistDict); // Free the plist dictionary
                }
            }
        }
    }

    return toJson(browserExtensions);
}
