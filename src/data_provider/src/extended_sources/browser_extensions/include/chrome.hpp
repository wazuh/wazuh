#include <vector>
#include <string>
#include <tuple>

namespace chrome {

struct ChromeExtension {
  std::string browser_type;
  std::string uid;
  std::string name;
  std::string profile;
  std::string profile_path;
  std::string referenced_identifier;
  std::string identifier;
  std::string version;
  std::string description;
  std::string default_locale;
  std::string current_locale;
  std::string update_url;
  std::string author;
  std::string persistent;
  std::string path;
  std::string permissions;
  std::string permissions_json;
  std::string optional_permissions;
  std::string optional_permissions_json;
  std::string manifest_hash;
  std::string referenced;
  std::string from_webstore;
  std::string state;
  std::string install_time;
  std::string install_timestamp;
  std::string manifest_json;
  std::string key;
};

/// One of the possible Chrome-based browser names
enum class ChromeBrowserType {
  GoogleChrome,
  GoogleChromeBeta,
  GoogleChromeDev,
  GoogleChromeCanary,
  Brave,
  Chromium,
  Yandex,
  Opera,
  Edge,
  EdgeBeta,
  Vivaldi,
  Arc,
};

/// A list of possible path suffixes for each browser type
using ChromePathSuffixMap = std::vector<std::tuple<ChromeBrowserType, std::string>>;
using ChromeExtensionList = std::vector<ChromeExtension>;
using ChromeUserProfileList = std::vector<std::filesystem::path>;

/// A list of path suffixes for each Chrome-based browser on Windows
const ChromePathSuffixMap kLinuxPathList = {
	{ChromeBrowserType::GoogleChrome, ".config/google-chrome"},
	{ChromeBrowserType::GoogleChromeBeta, ".config/google-chrome-beta"},
	{ChromeBrowserType::GoogleChromeDev, ".config/google-chrome-unstable"},
	{ChromeBrowserType::Brave, ".config/BraveSoftware/Brave-Browser"},
	{ChromeBrowserType::Chromium, ".config/chromium"},
	{ChromeBrowserType::Chromium, "snap/chromium/common/chromium"},
	{ChromeBrowserType::Yandex, ".config/yandex-browser-beta"},
	{ChromeBrowserType::Opera, ".config/opera"},
	{ChromeBrowserType::Vivaldi, ".config/vivaldi"},
};

// const ExtensionPropertyMap kExtensionPropertyList = {
//     {ExtensionProperty::Type::String, "name", "name"},
//     {ExtensionProperty::Type::String, "update_url", "update_url"},
//     {ExtensionProperty::Type::String, "version", "version"},
//     {ExtensionProperty::Type::String, "author", "author"},
//     {ExtensionProperty::Type::String, "default_locale", "default_locale"},
//     {ExtensionProperty::Type::String, "current_locale", "current_locale"},
//     {ExtensionProperty::Type::String, "background.persistent", "persistent"},
//     {ExtensionProperty::Type::String, "description", "description"},
//     {ExtensionProperty::Type::StringArray, "permissions", "permissions"},

//     {ExtensionProperty::Type::StringArray,
//      "optional_permissions",
//      "optional_permissions"},

//     {ExtensionProperty::Type::String, "key", "key"},
// };

const std::vector<std::string> kPossibleConfigFileNames = {"Preferences", "Secure Preferences"};
const std::string kExtensionsFolderName{"Extensions"};
const std::string kExtensionManifestName{"manifest.json"};

class ChromeExtensions {
	public:
	ChromeExtensions() = default;
	private:
};

} // namespace chrome