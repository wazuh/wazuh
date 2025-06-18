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

struct BrowserExtensionData {
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

class BrowserExtensionsProvider
{
  public:
  explicit BrowserExtensionsProvider(
    std::shared_ptr<IBrowserExtensionsWrapper> browser_extensions_wrapper);
  /// @brief Default constructor.
  BrowserExtensionsProvider();
  nlohmann::json collect();
  void printExtensions(const nlohmann::json& extensions_json);
  private:
  void printExtensions(const BrowserExtensionsData& extensions);
  nlohmann::json toJson(const BrowserExtensionsData& extensions);
  std::shared_ptr<IBrowserExtensionsWrapper> browser_extensions_wrapper_;
};
