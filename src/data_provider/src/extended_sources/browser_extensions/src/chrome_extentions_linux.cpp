#include <iostream>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include "chrome.hpp"
#include "json.hpp"

std::vector<std::string> getUsers(){
	std::vector<std::string> users;
	for (const auto& entry : std::filesystem::directory_iterator("/home")) {
		if (entry.is_directory()) {
			users.push_back(entry.path().filename().string());
		}
	}
	return users;
}

bool isValidChromeProfile(const std::filesystem::path& profilePath) {
	return std::filesystem::is_regular_file(profilePath / "Preferences") ||
	       std::filesystem::is_regular_file(profilePath / "Secure Preferences");
}

chrome::ChromeExtensionList getUnreferencedExtensions(const std::filesystem::path& profilePath){
	std::filesystem::path extensionPath = profilePath / chrome::kExtensionsFolderName;
	if(!std::filesystem::exists(extensionPath)) {
		// TODO: Improve handling this error.
		std::cerr << "Extensions folder does not exist: " << extensionPath << std::endl;
		return chrome::ChromeExtensionList();
	}


	chrome::ChromeExtensionList extensions;
	for(const auto& subDir : std::filesystem::directory_iterator(extensionPath)) {
		if(subDir.is_directory()){
			for(const auto& subSubDir : std::filesystem::directory_iterator(subDir.path())) {
				if(subSubDir.is_directory()) {
					std::filesystem::path manifestPath = subSubDir.path() / chrome::kExtensionManifestName;
					if(std::filesystem::exists(manifestPath)) {
						std::ifstream manifestFile(manifestPath);
						nlohmann::json manifestJson = nlohmann::json::parse(manifestFile);
						chrome::ChromeExtension extension;
						// TODO: Get the following properties from the manifest
						// "name", "name"
						// "update_url", "update_url"
						// "version", "version"
						// "author", "author"
						// "default_locale", "default_locale"
						// "current_locale", "current_locale"
						// "background.persistent", "persistent"
						// "description", "description"
						// "permissions", "permissions"
						// "optional_permissions", "optional_permissions"
						// "key", "key"

						extension.browser_type = "chrome"; // TODO: Improve this for all chrome types
						extension.uid = std::to_string(getuid()); // TODO: Make sure this is the correct way to get this property
						// extension.profile = preferencesJson["profile"]["name"].get<std::string>();
						extension.profile_path = profilePath.string();
						extension.name = manifestJson.contains("name") ? manifestJson["name"].get<std::string>() : "default_name";
						extension.version = manifestJson.contains("version") ? manifestJson["version"].get<std::string>() : "default_version";
						extension.author = "a"; // TODO: Figure out why this is always empty
						// // extension.manifest_json // This is hidden
						extension.update_url = manifestJson.value("update_url", "default_update_url");
						extension.default_locale = manifestJson.contains("default_locale") ? manifestJson["default_locale"].get<std::string>() : "default_locale";
						// extension.current_locale = manifestJson["current_locale"].get<std::string>();
						extension.permissions = "[]"; // TODO: convert permissions to string
						// // extension.permissions_json // TODO: this is hidden
						extension.optional_permissions = "[]"; // TODO: convert optional_permissions to string
						extension.optional_permissions_json = "[]"; // TODO: this is hidden
						extension.persistent = "a"; // TODO: figure this out
						extension.description = manifestJson.contains("description") ? manifestJson["description"].get<std::string>() : "default_description";
						extension.path = subSubDir.path().string();
						extension.manifest_hash = "a"; // TODO: figure this out
						extension.referenced = std::to_string(0);
						extension.state = "a"; // TODO: Figure this out
						// if(item.value().contains("from_webstore")) {
						// 	extension.from_webstore = item.value()["from_webstore"].get<bool>() ? "true" : "false";
						// } else {
						// 	extension.from_webstore = "";
						// }
						// extension.install_time = item.value()["first_install_time"].get<std::string>();
						// extension.install_timestamp = item.value()["first_install_time"].get<std::string>();
						extension.referenced_identifier = "a"; // TODO: figure this one out
						extension.identifier = "a"; // TODO: figure this one out
						extension.key = manifestJson.contains("key") ? manifestJson["key"].get<std::string>() : "default_key";

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

chrome::ChromeExtensionList parsePreferences(nlohmann::json& preferencesJson, const std::filesystem::path& profilePath){
	// TODO: If extensions.settings doesn't exist, then try extensions.opsettings
	const nlohmann::json& settings = preferencesJson["extensions"]["settings"];
	chrome::ChromeExtensionList extensions;
	for(const auto& item : settings.items()) {
		if(item.value().contains("path") && item.value().contains("manifest")){
			std::filesystem::path extensionPath(item.value()["path"]);
			if(extensionPath.is_relative()) {
				extensionPath = profilePath / chrome::kExtensionsFolderName / extensionPath; // Make it absolute
			}
			if(std::filesystem::exists(extensionPath)){
				chrome::ChromeExtension extension;
				extension.browser_type = "chrome"; // TODO: Improve this for all chrome types
				extension.uid = std::to_string(getuid()); // TODO: Make sure this is the correct way to get this property
				extension.profile = preferencesJson["profile"]["name"].get<std::string>();
				extension.profile_path = profilePath.string();
				extension.name = item.value()["manifest"]["name"].get<std::string>();
				extension.version = item.value()["manifest"]["version"].get<std::string>();
				extension.author = "a"; // TODO: Figure out why this is always empty
				// extension.manifest_json // This is hidden
				extension.update_url = item.value()["manifest"]["update_url"].get<std::string>();
				extension.default_locale = item.value()["manifest"]["default_locale"].get<std::string>();
				extension.current_locale = item.value()["manifest"]["current_locale"].get<std::string>();
				extension.permissions = "[]"; // TODO: convert permissions to string
				// extension.permissions_json // TODO: this is hidden
				extension.optional_permissions = "[]"; // TODO: convert optional_permissions to string
				// extension.optional_permissions_json = "[]"; // TODO: this is hidden
				extension.persistent = "a"; // TODO: figure this out
				extension.description = item.value()["manifest"]["description"].get<std::string>();
				extension.path = extensionPath.string();
				extension.manifest_hash = "a"; // TODO: figure this out
				extension.referenced = std::to_string(1);
				extension.state = "a"; // TODO: Figure this out
				if(item.value().contains("from_webstore")) {
					extension.from_webstore = item.value()["from_webstore"].get<bool>() ? "true" : "false";
				} else {
					extension.from_webstore = "";
				}
				extension.install_time = item.value()["first_install_time"].get<std::string>();
				extension.install_timestamp = item.value()["first_install_time"].get<std::string>();
				extension.referenced_identifier = "a"; // TODO: figure this one out
				extension.identifier = "a"; // TODO: figure this one out

				extensions.emplace_back(extension);
			}
		}
	}

	return extensions;
}

chrome::ChromeExtensionList getReferencedExtensions(const std::filesystem::path& profilePath) {
	std::filesystem::path configFilePath = profilePath / "Preferences";
	if(!std::filesystem::exists(configFilePath)) {
		// TODO: Improve handling this error.
		std::cerr << "Preferences file does not exist: " << configFilePath << std::endl;
		return chrome::ChromeExtensionList();
	}

	std::ifstream preferencesFile(configFilePath);
	nlohmann::json preferencesJson = nlohmann::json::parse(preferencesFile);

	return parsePreferences(preferencesJson, profilePath);
}

chrome::ChromeUserProfileList getUserProfile(){
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

void printExtensions(const chrome::ChromeExtensionList& extensions){
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

void getExtensionsFromProfile(chrome::ChromeExtensionList& extensions, const std::filesystem::path profilePath){
	chrome::ChromeExtensionList unreferencedExtensions = getUnreferencedExtensions(profilePath);
	extensions.insert(extensions.end(), unreferencedExtensions.begin(), unreferencedExtensions.end());

	chrome::ChromeExtensionList dirExtensions = getReferencedExtensions(profilePath);
	extensions.insert(extensions.end(), dirExtensions.begin(), dirExtensions.end());
}

int main() {
	auto profilePaths = getUserProfile();
	chrome::ChromeExtensionList extensions;
	for(auto& profilePath : profilePaths) {
		if(isValidChromeProfile(profilePath)) {
			getExtensionsFromProfile(extensions, profilePath);
		} else {
			for(const auto& subDirectory : std::filesystem::directory_iterator(profilePath)) {
				if(subDirectory.is_directory() && isValidChromeProfile(subDirectory.path())) {
					getExtensionsFromProfile(extensions, subDirectory.path());
				}
			}
		}
	}

	printExtensions(extensions);

	return 0;
}