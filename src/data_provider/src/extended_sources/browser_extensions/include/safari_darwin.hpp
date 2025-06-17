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

struct ExtensionData {
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

using ExtensionsData = std::vector<ExtensionData>;

class BrowsersProvider
{
  public:
  /// @brief Default constructor.
  BrowsersProvider();

  nlohmann::json collect();
  private:
  void printExtensions(const ExtensionsData& extensions);
  void printExtensions(const nlohmann::json& extensions_json);
  nlohmann::json toJson(const ExtensionsData& extensions);
};
