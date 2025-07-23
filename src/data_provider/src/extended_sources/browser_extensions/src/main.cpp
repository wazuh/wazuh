#include <iostream>
#include "chrome.hpp"

int main() {
	chrome::ChromeExtensions chromeExtensions;

	auto profilePaths = chromeExtensions.getUserProfile();
	chrome::ChromeExtensionList extensions;
	chromeExtensions.getExtensionsFromProfiles(extensions, profilePaths);

	// chromeExtensions.printExtensions(extensions);
	std::cout << chromeExtensions.toJson(extensions) << std::endl;

	return 0;
}