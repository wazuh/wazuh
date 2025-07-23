#include "chrome.hpp"
#include <tuple>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <algorithm>
#include "cppcodec/base64_rfc4648.hpp"
#include "openssl/sha.h"

namespace chrome {

std::vector<std::string> ChromeExtensions::getUsers(){
	std::vector<std::string> users;
	for (const auto& entry : std::filesystem::directory_iterator("/home")) {
		if (entry.is_directory()) {
			users.push_back(entry.path().filename().string());
		}
	}
	return users;
}

bool ChromeExtensions::isValidChromeProfile(const std::filesystem::path& profilePath) {
	return std::filesystem::is_regular_file(profilePath / "Preferences") ||
				std::filesystem::is_regular_file(profilePath / "Secure Preferences");
}

std::string ChromeExtensions::jsonArrayToString(const nlohmann::json& jsonArray) {
	std::string result;
	for (const auto& item : jsonArray) {
		result += item.get<std::string>() + ", ";
	}
	if (result.back() == ' ') {
		result.pop_back(); // Remove trailing comma
		result.pop_back();
	}
	return result;
}

std::string ChromeExtensions::remove_substring(const std::string& input, const std::string& to_remove) {
		std::string result = input;
		size_t pos;
		while ((pos = result.find(to_remove)) != std::string::npos) {
				result.erase(pos, to_remove.length());
		}
		return result;
}

bool ChromeExtensions::is_snake_case(const std::string& s) {
	if (s.empty() || s.front() == '_' || s.back() == '_') return false;

	bool has_underscore = false;
	bool last_was_underscore = false;

	for (char c : s) {
		if (c == '_') {
			if (last_was_underscore) return false; // no double underscores
			has_underscore = true;
			last_was_underscore = true;
		} else {
			if (!std::isalnum(static_cast<unsigned char>(c))) return false;
			last_was_underscore = false;
		}
	}

	return has_underscore; // must contain at least one underscore
}

void ChromeExtensions::to_lowercase(std::string& str) {
		std::transform(str.begin(), str.end(), str.begin(),
									[](unsigned char c) { return std::tolower(c); });
}

void ChromeExtensions::localizeParameters(chrome::ChromeExtension& extension){
	std::filesystem::path extensionPath(extension.path);
	std::filesystem::path localesPath = extensionPath / chrome::kExtensionLocalesDir;
	std::filesystem::path defaultLocalePath = localesPath / extension.default_locale;
	std::filesystem::path messagesFilePath = defaultLocalePath / chrome::kExtensionLocaleFile;
	if(std::filesystem::exists(messagesFilePath)){
		std::string nameKey = remove_substring(remove_substring(extension.name, "__MSG_"), "__");
		std::string descriptionKey = remove_substring(remove_substring(extension.description, "__MSG_"), "__");

		if(is_snake_case(nameKey)) {
			to_lowercase(nameKey);
		}
		if(is_snake_case(descriptionKey)) {
			to_lowercase(descriptionKey);
		}
		
		std::ifstream messagesFile(messagesFilePath);
		nlohmann::json messagesJson = nlohmann::json::parse(messagesFile);
		extension.name = messagesJson.contains(nameKey) ? messagesJson[nameKey]["message"].get<std::string>() : extension.name;
		extension.description = messagesJson.contains(descriptionKey) ? messagesJson[descriptionKey]["message"].get<std::string>() : extension.description;
	} else {
		std::cerr << "Default locale file does not exist: " << messagesFilePath << std::endl;
	}
}

std::string ChromeExtensions::hash_to_hex_string(const uint8_t* hash, size_t length) {
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (size_t i = 0; i < length; ++i) {
			ss << std::setw(2) << static_cast<int>(hash[i]);
	}
	return ss.str();
}

int ChromeExtensions::hexCharToInt(char c) {
		if ('0' <= c && c <= '9') return c - '0';
		else if ('a' <= c && c <= 'f') return 10 + (c - 'a');
		else if ('A' <= c && c <= 'F') return 10 + (c - 'A');
		else throw std::invalid_argument("Invalid hex digit");
}

std::string ChromeExtensions::webkitToUnixTime(std::string webkit_timestamp) {
	int64_t timestamp = std::stoll(webkit_timestamp);
	std::time_t unix_timestap = (timestamp - 11644473600000000LL) / 1000000;
	return std::to_string(unix_timestap);
}

// Converts a hex string to a string of letters 'a'..'p'
std::string ChromeExtensions::hexToLetters(const std::string& hex) {
		std::string result;
		result.reserve(hex.size());

		for (char c : hex) {
				int value = hexCharToInt(c);
				// Map 0-15 to 'a' - 'p'
				char letter = 'a' + value;
				result.push_back(letter);
		}

		return result;
}

std::string ChromeExtensions::generateIdentifier(const std::string& key){
	std::vector<uint8_t> decodedVector = cppcodec::base64_rfc4648::decode(key);
	uint8_t hash[SHA256_DIGEST_LENGTH];
	SHA256(decodedVector.data(), decodedVector.size(), hash);
	std::string letters_string = hexToLetters(hash_to_hex_string(hash, SHA256_DIGEST_LENGTH));
	return letters_string.substr(0, 32);
}

std::string ChromeExtensions::sha256_file(const std::filesystem::path& filepath) {
		std::ifstream file(filepath, std::ios::binary);
		if (!file) {
				throw std::runtime_error("Cannot open file: " + filepath.string());
		}

		SHA256_CTX sha256;
		SHA256_Init(&sha256);

		std::vector<char> buffer(8192);
		while (file.good()) {
				file.read(buffer.data(), buffer.size());
				std::streamsize bytes_read = file.gcount();
				if (bytes_read > 0) {
						SHA256_Update(&sha256, buffer.data(), bytes_read);
				}
		}

		std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
		SHA256_Final(hash.data(), &sha256);

		std::ostringstream oss;
		oss << std::hex << std::setfill('0');
		for (unsigned char byte : hash) {
				oss << std::setw(2) << (int)byte;
		}
		return oss.str();
}

void ChromeExtensions::parseManifest(nlohmann::json& manifestJson, chrome::ChromeExtension& extension) {
	extension.name = manifestJson.contains("name") ? manifestJson["name"].get<std::string>() : "";
	extension.update_url = manifestJson.contains("update_url") ? manifestJson["update_url"].get<std::string>() : "";
	extension.version = manifestJson.contains("version") ? manifestJson["version"].get<std::string>() : "";
	extension.author = (manifestJson.contains("author") && manifestJson["author"].is_string()) ? manifestJson["author"].get<std::string>() : "";
	extension.default_locale = manifestJson.contains("default_locale") ? manifestJson["default_locale"].get<std::string>() : "";
	extension.current_locale = manifestJson.contains("current_locale") ? manifestJson["current_locale"].get<std::string>() : "";
	if(manifestJson.contains("background") && manifestJson["background"].contains("persistent")) {
		bool isPersistent = manifestJson["background"]["persistent"].get<bool>();
		extension.persistent = isPersistent ? "1" : "0";
	} else {
		extension.persistent = "0";
	}
	extension.description = manifestJson.contains("description") ? manifestJson["description"].get<std::string>() : "";
	extension.permissions = manifestJson.contains("permissions") ? jsonArrayToString(manifestJson["permissions"]) : "";
	extension.optional_permissions = manifestJson.contains("optional_permissions") ? jsonArrayToString(manifestJson["optional_permissions"]) : "";
	extension.key = manifestJson.contains("key") ? manifestJson["key"].get<std::string>() : "";

	localizeParameters(extension);
}

void ChromeExtensions::parsePreferenceSettings(chrome::ChromeExtension& extension, const std::string& key, const nlohmann::json& value){
	extension.state = value.contains("state") ? value["state"].get<std::string>() : "";
	if(value.contains("from_webstore")) {
		extension.from_webstore = value["from_webstore"].get<bool>() ? "true" : "false";
	} else {
		extension.from_webstore = "";
	}
	extension.install_time = value.contains("first_install_time") ? value["first_install_time"].get<std::string>() : "0";
	extension.install_timestamp = webkitToUnixTime(extension.install_time);
	extension.referenced_identifier = key;
}

void ChromeExtensions::getCommonSettings(chrome::ChromeExtension& extension, const std::filesystem::path& manifestPath, const nlohmann::json& preferencesJson){
	extension.browser_type = "chrome"; // TODO: Improve this for all chrome types
	extension.profile = (preferencesJson.contains("profile") && preferencesJson["profile"].contains("name")) ? preferencesJson["profile"]["name"].get<std::string>() : "";
	extension.uid = std::to_string(getuid()); // TODO: Make sure this is the correct way to get this property
	extension.manifest_hash = sha256_file(manifestPath);
}

chrome::ChromeExtensionList ChromeExtensions::getReferencedExtensions(const std::filesystem::path& profilePath) {
	std::filesystem::path configFilePath = profilePath / "Preferences";
	if(!std::filesystem::exists(configFilePath)) {
		// TODO: Improve handling this error.
		std::cerr << "Preferences file does not exist: " << configFilePath << std::endl;
		return chrome::ChromeExtensionList();
	}
	std::ifstream preferencesFile(configFilePath);
	nlohmann::json preferencesJson = nlohmann::json::parse(preferencesFile);

	// TODO: If extensions.settings doesn't exist, then try extensions.opsettings
	const nlohmann::json& settings = preferencesJson["extensions"]["settings"];
	chrome::ChromeExtensionList extensions;
	for(const auto& item : settings.items()) {
		if(item.value().contains("path")){
			std::filesystem::path extensionPath(item.value()["path"]);
			if(extensionPath.is_relative()) {
				extensionPath = profilePath / chrome::kExtensionsFolderName / extensionPath;
			}
			std::filesystem::path manifestPath = extensionPath / chrome::kExtensionManifestName;
			if(std::filesystem::exists(extensionPath) && std::filesystem::exists(manifestPath)){
				chrome::ChromeExtension extension;

				extension.profile_path = profilePath.string();
				// extension.manifest_json // This is hidden
				// extension.permissions_json // TODO: this is hidden
				// extension.optional_permissions_json = "[]"; // TODO: this is hidden
				extension.path = extensionPath.string();
				extension.referenced = std::to_string(1);

				getCommonSettings(extension, manifestPath, preferencesJson);
				parsePreferenceSettings(extension, item.key(), item.value());

				std::ifstream manifestFile(manifestPath);
				nlohmann::json manifestJson = nlohmann::json::parse(manifestFile);
				parseManifest(manifestJson, extension);
				
				extension.identifier = generateIdentifier(extension.key);

				extensions.emplace_back(extension);
			}
		}
	}

	return extensions;
}

chrome::ChromeExtensionList ChromeExtensions::getUnreferencedExtensions(const std::filesystem::path& profilePath){
	std::filesystem::path extensionPath = profilePath / chrome::kExtensionsFolderName;
	if(!std::filesystem::exists(extensionPath)) {
		// TODO: Improve handling this error.
		std::cerr << "Extensions folder does not exist: " << extensionPath << std::endl;
		return chrome::ChromeExtensionList();
	}
	std::filesystem::path configFilePath = profilePath / "Preferences";
	if(!std::filesystem::exists(configFilePath)) {
		// TODO: Improve handling this error.
		std::cerr << "Preferences file does not exist: " << configFilePath << std::endl;
		return chrome::ChromeExtensionList();
	}
	std::ifstream preferencesFile(configFilePath);
	nlohmann::json preferencesJson = nlohmann::json::parse(preferencesFile);

	chrome::ChromeExtensionList extensions;
	for(const auto& subDir : std::filesystem::directory_iterator(extensionPath)) {
		if(subDir.is_directory()){
			for(const auto& subSubDir : std::filesystem::directory_iterator(subDir.path())) {
				if(subSubDir.is_directory()) {
					std::filesystem::path manifestPath = subSubDir.path() / chrome::kExtensionManifestName;
					if(std::filesystem::exists(manifestPath)) {
						chrome::ChromeExtension extension;

						extension.profile_path = profilePath.string();
						extension.path = subSubDir.path().string();
						extension.referenced = "0";
						extension.install_timestamp = "0";

						getCommonSettings(extension, manifestPath, preferencesJson);

						std::ifstream manifestFile(manifestPath);
						nlohmann::json manifestJson = nlohmann::json::parse(manifestFile);
						parseManifest(manifestJson, extension);

						extension.identifier = generateIdentifier(extension.key);

						extensions.emplace_back(extension);
					} else {
						std::cerr << "Manifest file does not exist in: " << subSubDir.path() << std::endl;
					}
				}
			}
		}
	}

	return extensions;
}

chrome::ChromeUserProfileList ChromeExtensions::getUserProfile(){
	chrome::ChromeUserProfileList userProfiles;
	for(const auto& user : getUsers()){
		const std::filesystem::path userHomePath("/home/" + user);
		if(!std::filesystem::exists(userHomePath)) {
			std::cerr << "Directory does not exist: " << user << std::endl;
			continue;
		}
		const std::filesystem::path profilePath = userHomePath / ".config/google-chrome";
		if(!std::filesystem::exists(profilePath)) {
			std::cerr << "Chrome path does not exist\n";
			continue;
		}
		userProfiles.emplace_back(profilePath);
	}
	return userProfiles;
}

void ChromeExtensions::printExtensions(const chrome::ChromeExtensionList& extensions){
	for(const auto& extension : extensions){
		std::cout << "<-------------------------------Extension----------------------------->" << std::endl
		<< extension.author << std::endl
		<< extension.browser_type << std::endl
		<< extension.current_locale << std::endl
		<< extension.default_locale << std::endl
		<< extension.description << std::endl
		<< extension.from_webstore << std::endl
		<< extension.identifier << std::endl
		<< extension.install_time << std::endl
		<< extension.install_timestamp << std::endl
		<< extension.manifest_hash << std::endl
		<< extension.name << std::endl
		<< extension.optional_permissions << std::endl
		<< extension.path << std::endl
		<< extension.permissions << std::endl
		<< extension.persistent << std::endl
		<< extension.profile << std::endl
		<< extension.profile_path << std::endl
		<< extension.referenced << std::endl
		<< extension.referenced_identifier << std::endl
		<< extension.state << std::endl
		<< extension.uid << std::endl
		<< extension.update_url << std::endl
		<< extension.version << std::endl
		<< extension.permissions_json << std::endl
		<< extension.optional_permissions_json << std::endl
		<< extension.manifest_json << std::endl
		<< extension.key << std::endl;
	}
}

nlohmann::json ChromeExtensions::toJson(const chrome::ChromeExtensionList& extensions)
{
	nlohmann::json results = nlohmann::json::array();

	for (auto& extension : extensions) {
		nlohmann::json entry;
		entry["author"] = extension.author;
		entry["browser_type"] = extension.browser_type;
		entry["current_locale"] = extension.current_locale;
		entry["default_locale"] = extension.default_locale;
		entry["description"] = extension.description;
		entry["from_webstore"] = extension.from_webstore;
		entry["identifier"] = extension.identifier;
		entry["install_time"] = extension.install_time;
		entry["install_timestamp"] = extension.install_timestamp;
		entry["manifest_hash"] = extension.manifest_hash;
		entry["name"] = extension.name;
		entry["optional_permissions"] = extension.optional_permissions;
		entry["path"] = extension.path;
		entry["permissions"] = extension.permissions;
		entry["persistent"] = extension.persistent;
		entry["profile"] = extension.profile;
		entry["profile_path"] = extension.profile_path;
		entry["referenced"] = extension.referenced;
		entry["referenced_identifier"] = extension.referenced_identifier;
		entry["state"] = extension.state;
		entry["uid"] = extension.uid;
		entry["update_url"] = extension.update_url;
		entry["version"] = extension.version;
		entry["permissions_json"] = extension.permissions_json;
		results.push_back(std::move(entry));
	}

	return results;
}

void ChromeExtensions::getExtensionsFromPath(chrome::ChromeExtensionList& extensions, const std::filesystem::path& path) {
	chrome::ChromeExtensionList referencedExtensions = getReferencedExtensions(path);
	extensions.insert(extensions.end(), referencedExtensions.begin(), referencedExtensions.end());

	chrome::ChromeExtensionList unreferencedExtensions = getUnreferencedExtensions(path);

	// Only add to extension list the unreferenced extensions that are not already in the list
	for(const auto& unreferencedExtension : unreferencedExtensions){
		auto it = std::find_if(referencedExtensions.begin(), referencedExtensions.end(), [&unreferencedExtension](const auto& referencedExtension){
			return referencedExtension.path == unreferencedExtension.path;
		});

		if(it == referencedExtensions.end()){
			// This extension should be added to list
			extensions.emplace_back(unreferencedExtension);
		}
	}
}

void ChromeExtensions::getExtensionsFromProfiles(chrome::ChromeExtensionList& extensions, const chrome::ChromeUserProfileList& profilePaths){
	for(auto& profilePath : profilePaths) {
		if(isValidChromeProfile(profilePath)) {
			getExtensionsFromPath(extensions, profilePath);
		} else {
			for(const auto& subDirectory : std::filesystem::directory_iterator(profilePath)) {
				if(subDirectory.is_directory() && isValidChromeProfile(subDirectory.path())) {
					getExtensionsFromPath(extensions, subDirectory.path());
				}
			}
		}
	}
}

} // namespace chrome