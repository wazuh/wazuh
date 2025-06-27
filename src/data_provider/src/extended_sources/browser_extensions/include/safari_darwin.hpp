/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <string>
#include <vector>
#include "json.hpp"
#include "browser_extensions_wrapper.hpp"

#define APP_PLUGINS_PATH "Contents/PlugIns/"
#define APP_PLUGIN_PLIST_PATH "Contents/Info.plist"
#define SAFARI_FILTER_STRING "com.apple.Safari"

struct BrowserExtensionData
{
    std::string bundle_version; // CF Bundle Version
    std::string copyright;      // NS Human Readable Copyright
    std::string description;    // Human Readable Description
    std::string identifier;     // Extension Identifier
    std::string name;           // Extension Name
    std::string path;           // Extension Plist path
    std::string sdk;            // Extension SDK Version
    std::string uid;            // User id
    std::string version;        // Extension Version
};

using BrowserExtensionsData = std::vector<BrowserExtensionData>;

/// @brief Provides methods to collect browser extensions data.
/// This class interacts with a browser extensions wrapper to gather information about installed browser extensions,
/// such as their paths, identifiers, names, versions, and other relevant metadata.
/// It formats the collected data into a structured JSON format for easy consumption and further processing.
class SafariExtensionsProvider
{
    public:
        /// @brief Constructs a SafariExtensionsProvider with the given browser extensions wrapper.
        /// @param browserExtensionsWrapper A shared pointer to an IBrowserExtensionsWrapper instance.
        /// This constructor initializes the SafariExtensionsProvider with a specific IBrowserExtensionsWrapper,
        /// allowing it to interact with the browser extensions data source. The wrapper is expected to provide
        /// methods for accessing browser extensions information, such as retrieving paths, identifiers, and other
        /// relevant details about the extensions installed in the browser.
        /// This constructor is useful when you have a specific implementation of IBrowserExtensionsWrapper that you
        /// want to use for collecting browser extensions data. It allows for flexibility in choosing the underlying
        /// implementation of the browser extensions wrapper, enabling the provider to work with different browser
        /// extensions sources or configurations as needed.
        explicit SafariExtensionsProvider(
            std::shared_ptr<IBrowserExtensionsWrapper> browserExtensionsWrapper);
        /// @brief Default constructor for SafariExtensionsProvider, initializes with a default IBrowserExtensionsWrapper.
        /// This constructor creates a SafariExtensionsProvider instance using a default-constructed shared pointer to an
        /// IBrowserExtensionsWrapper, allowing the provider to function without requiring an explicit wrapper instance.
        /// This is useful for scenarios where the wrapper is not provided externally, such as in unit tests or simple use cases.
        /// The default constructor ensures that the SafariExtensionsProvider can be instantiated without any parameters,
        /// while still maintaining the ability to collect and manage browser extensions data.
        SafariExtensionsProvider();
        /// @brief Collects browser extensions data and returns it as a JSON object.
        /// @return A JSON object containing browser extensions data.
        /// The JSON object includes details such as bundle version, copyright, description, identifier, name,
        /// path, SDK version, user ID, and version for each extension.
        /// The data is collected from the browser extensions wrapper and formatted into a structured JSON format.
        /// The JSON structure is designed to be easily readable and includes all relevant information about each browser
        /// extension, making it suitable for further processing or display.
        nlohmann::json collect();
    private:
        /// @brief Converts the collected browser extensions data into a JSON format.
        /// @param extensions A vector of BrowserExtensionData containing the extensions to be converted.
        /// @return A JSON object representing the browser extensions data.
        /// This method iterates through the provided vector of BrowserExtensionData and constructs a JSON object
        /// for each extension, including fields such as bundle version, copyright, description, identifier,
        /// name, path, SDK version, user ID, and version. The resulting JSON object
        /// is an array of these extension objects, allowing for easy serialization and transmission of the data.
        /// The JSON format is designed to be compatible with various applications and services that consume browser
        /// extensions data, providing a standardized way to represent the information.
        /// @note This method is private and intended for internal use within the SafariExtensionsProvider class.
        /// It is called by the collect method to format the collected data before returning it as a JSON object.
        /// The method ensures that the data is structured correctly and includes all necessary fields for
        /// representing browser extensions in a JSON format.
        nlohmann::json toJson(const BrowserExtensionsData& extensions);
        std::shared_ptr<IBrowserExtensionsWrapper> m_browserExtensionsWrapper;
};
