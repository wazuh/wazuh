#include "safari_darwin.hpp"
#include <iostream>
#include <filesystem>
#include <algorithm>
#include <plist/plist.h>
#include <fstream>
#include <unistd.h>

#define kAppPluginsPath "Contents/PlugIns/"
#define kAppPluginPlistPath "Contents/Info.plist"
#define kSafariFilterString "com.apple.Safari"

const std::vector<std::string> kExtensionsAppDirsToExclude = {
    "/Xcode.app",
    "/Safari.app",
};

BrowserExtensionsProvider::BrowserExtensionsProvider(
  std::shared_ptr<IBrowserExtensionsWrapper> browser_extensions_wrapper) : 
  browser_extensions_wrapper_(std::move(browser_extensions_wrapper)) {}

BrowserExtensionsProvider::BrowserExtensionsProvider() : 
  browser_extensions_wrapper_(std::make_shared<BrowserExtensionsWrapper>()) {}

void BrowserExtensionsProvider::printExtensions(const BrowserExtensionsData& extensions) {
  for(auto& data : extensions){
    std::cout << std::endl;
    std::cout << data.bundle_version << std::endl;
    std::cout << data.copyright << std::endl;
    std::cout << data.description << std::endl;
    std::cout << data.identifier << std::endl;
    std::cout << data.name << std::endl;
    std::cout << data.path << std::endl;
    std::cout << data.sdk << std::endl;
    std::cout << data.uid << std::endl;
    std::cout << data.version << std::endl;
  }
}

void BrowserExtensionsProvider::printExtensions(const nlohmann::json& extensions_json) {
  std::cout << extensions_json.dump(4) << std::endl;
}

nlohmann::json BrowserExtensionsProvider::toJson(const BrowserExtensionsData& extensions) {
  nlohmann::json results = nlohmann::json::array();
  for(auto& extension : extensions) {
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

nlohmann::json BrowserExtensionsProvider::collect() {
  // Check if applications_path exists
  const std::string applications_path = browser_extensions_wrapper_->getApplicationsPath();
  std::filesystem::path apps_path{applications_path};
  if(!std::filesystem::exists(apps_path)){
    std::cout << "Path does not exist: " << apps_path << std::endl;
  }

  BrowserExtensionsData browser_extensions;
  // Create list of directories inside of applications_path
  for(auto& app_path : std::filesystem::directory_iterator(apps_path)){
    // For each app directory, exclude the ones in kExtensionsAppDirsToExclude
    std::string app_name = "/" + app_path.path().filename().string();
    if(std::find(kExtensionsAppDirsToExclude.begin(), kExtensionsAppDirsToExclude.end(), app_name) != kExtensionsAppDirsToExclude.end()){
      continue;
    }

    if(app_path.is_directory()){
      auto app_plugins_path = app_path.path() / std::filesystem::path(kAppPluginsPath);
      if(!std::filesystem::exists(app_plugins_path)){
        continue;
      }
      for(auto& element : std::filesystem::directory_iterator(app_plugins_path)){
        if(element.path().extension().string() != ".appex") {
          continue;
        }

        auto app_plugin_plist_path = element.path() / std::filesystem::path(kAppPluginPlistPath);
        if(!std::filesystem::exists(app_plugin_plist_path)){
          continue;
        }

        std::string extension_path = app_plugin_plist_path.string();
        std::ifstream plist_file(extension_path, std::ios::binary | std::ios::ate);
        if (!plist_file) {
          // TODO: Improve error handling
          std::cerr << "Failed to open file.\n";
        }

        std::streamsize file_size = plist_file.tellg();
        plist_file.seekg(0);
        std::vector<char> read_buffer(file_size);

        if (!plist_file.read(read_buffer.data(), file_size)) {
          // TODO: Improve error handling
          std::cerr << "Failed to read file\n";
        }

        plist_t plist_dict = nullptr;
        plist_from_memory(read_buffer.data(), read_buffer.size(), &plist_dict);
        if (!plist_dict || plist_get_node_type(plist_dict) != PLIST_DICT) {
          // TODO: Improve error handling
          std::cerr << "Failed to parse plist\n";
        }
        
        // Let's filter out the ones that are not Safari Extensions
        plist_t ns_extension_node = plist_dict_get_item(plist_dict, "NSExtension");
        if (ns_extension_node && plist_get_node_type(ns_extension_node) == PLIST_DICT) {
          plist_t extension_type_node = plist_dict_get_item(ns_extension_node, "NSExtensionPointIdentifier");
          if (extension_type_node && plist_get_node_type(extension_type_node) == PLIST_STRING) {
            char* extension_type = nullptr;
            plist_get_string_val(extension_type_node, &extension_type);
            std::string extension_type_str(extension_type);
            free(extension_type);
            
            if (!(extension_type_str.find(kSafariFilterString) != std::string::npos)) {
              continue; // Not a Safari extension
            }

            plist_t identifier_node = plist_dict_get_item(plist_dict, "CFBundleIdentifier");
            plist_t name_node = plist_dict_get_item(plist_dict, "CFBundleDisplayName");
            plist_t sdk_node = plist_dict_get_item(plist_dict, "CFBundleInfoDictionaryVersion");
            plist_t version_string_node = plist_dict_get_item(plist_dict, "CFBundleShortVersionString");
            plist_t bundle_version_node = plist_dict_get_item(plist_dict, "CFBundleVersion");
            plist_t copyright_node = plist_dict_get_item(plist_dict, "NSHumanReadableCopyright");
            plist_t description_node = plist_dict_get_item(plist_dict, "NSHumanReadableDescription");
            
            // Creating an BrowserExtensionData object
            BrowserExtensionData browser_extension_data;
            browser_extension_data.path = extension_path;
            browser_extension_data.uid = std::to_string(getuid());
            if(identifier_node && plist_get_node_type(identifier_node) == PLIST_STRING){
              char* identifier_str = nullptr;
              plist_get_string_val(identifier_node, &identifier_str);
              browser_extension_data.identifier = identifier_str;
              free(identifier_str);
            } else {
              browser_extension_data.identifier = "";
            }

            if(name_node && plist_get_node_type(name_node) == PLIST_STRING){
              char* name_str = nullptr;
              plist_get_string_val(name_node, &name_str);
              browser_extension_data.name = name_str;
              free(name_str);
            } else {
              browser_extension_data.name = "";
            }

            if(sdk_node && plist_get_node_type(sdk_node) == PLIST_STRING){
              char* sdk_str = nullptr;
              plist_get_string_val(sdk_node, &sdk_str);
              browser_extension_data.sdk = sdk_str;
              free(sdk_str);
            } else {
              browser_extension_data.sdk = "";
            }

            if(version_string_node && plist_get_node_type(version_string_node) == PLIST_STRING){
              char* version_string_str = nullptr;
              plist_get_string_val(version_string_node, &version_string_str);
              browser_extension_data.version = version_string_str;
              free(version_string_str);
            } else {
              browser_extension_data.version = "";
            }

            if(bundle_version_node && plist_get_node_type(bundle_version_node) == PLIST_STRING){
              char* bundle_version_str = nullptr;
              plist_get_string_val(bundle_version_node, &bundle_version_str);
              browser_extension_data.bundle_version = bundle_version_str;
              free(bundle_version_str);
            } else {
              browser_extension_data.bundle_version = "";
            }

            if(copyright_node && plist_get_node_type(copyright_node) == PLIST_STRING){
              char* copyright_str = nullptr;
              plist_get_string_val(copyright_node, &copyright_str);
              browser_extension_data.copyright = copyright_str;
              free(copyright_str);
            } else {
              browser_extension_data.copyright = "";
            }

            if(description_node && plist_get_node_type(description_node) == PLIST_STRING){
              char* description_str = nullptr;
              plist_get_string_val(description_node, &description_str);
              browser_extension_data.description = description_str;
              free(description_str);
            } else {
              browser_extension_data.description = "";
            }

            // Add to array of extensions
            browser_extensions.emplace_back(browser_extension_data);
          } else {
            // TODO: Improve error handling
            std::cerr << "Failed to parse NSExtensionPointIdentifier" << std::endl;
          }
        } else {
          // TODO: Improve error handling
          std::cerr << "Failed to parse NSExtension" << std::endl;
        }
      }
    }
  }

  return toJson(browser_extensions);
}
