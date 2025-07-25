#include <string>
#include <vector>
#include <filesystem>
#include "json.hpp"
#include "chrome_extensions_wrapper.hpp"

namespace chrome
{

    struct ChromeExtension
    {
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
    enum class ChromeBrowserType
    {
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
    const ChromePathSuffixMap kLinuxPathList =
    {
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

    const std::vector<std::string> kPossibleConfigFileNames = {"Preferences", "Secure Preferences"};
    const std::string kExtensionsFolderName{"Extensions"};
    const std::string kExtensionManifestName{"manifest.json"};
    const std::string kExtensionLocalesDir{"_locales"};
    const std::string kExtensionLocaleFile{"messages.json"};

    class ChromeExtensionsProvider
    {
        public:
            explicit ChromeExtensionsProvider(
                std::shared_ptr<IChromeExtensionsWrapper> chromeExtensionsWrapper);
            ChromeExtensionsProvider();
            void printExtensions(const chrome::ChromeExtensionList& extensions);
            nlohmann::json collect();

        private:
            chrome::ChromeUserProfileList getProfileDirs();
            void getExtensionsFromProfiles(chrome::ChromeExtensionList& extensions, const chrome::ChromeUserProfileList& profilePaths);
            nlohmann::json toJson(const chrome::ChromeExtensionList& extensions);
            // std::filesystem::path getHomePath();
            bool isValidChromeProfile(const std::filesystem::path& profilePath);
            std::string jsonArrayToString(const nlohmann::json& jsonArray);
            std::string remove_substring(const std::string& input, const std::string& to_remove);
            bool is_snake_case(const std::string& s);
            void to_lowercase(std::string& str);
            void localizeParameters(chrome::ChromeExtension& extension);
            std::string hashToLetterString(const uint8_t* hash, size_t length);
            std::string hashToHexString(const uint8_t* hash, size_t length);
            std::string webkitToUnixTime(std::string webkit_timestamp);
            std::string generateIdentifier(const std::string& key);
            std::string sha256_file(const std::filesystem::path& filepath);
            void parseManifest(nlohmann::json& manifestJson, chrome::ChromeExtension& extension);
            void parsePreferenceSettings(chrome::ChromeExtension& extension, const std::string& key, const nlohmann::json& value);
            void getCommonSettings(chrome::ChromeExtension& extension, const std::filesystem::path& manifestPath, const nlohmann::json& preferencesJson);
            chrome::ChromeExtensionList getReferencedExtensions(const std::filesystem::path& profilePath);
            chrome::ChromeExtensionList getUnreferencedExtensions(const std::filesystem::path& profilePath);
            void getExtensionsFromPath(chrome::ChromeExtensionList& extensions, const std::filesystem::path& path);

            std::shared_ptr<IChromeExtensionsWrapper> m_chromeExtensionsWrapper;
    };

} // namespace chrome