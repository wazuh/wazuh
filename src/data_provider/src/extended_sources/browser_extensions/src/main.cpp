#include <iostream>
#include "chrome_linux.hpp"

class MockChromeExtensionsWrapper : public IChromeExtensionsWrapper
{
	public:
	std::filesystem::path getHomePath() override
	{
		std::filesystem::path mockHomePath = std::filesystem::path(__FILE__).parent_path() / "../tests/mock_home";
		return mockHomePath;
	}
};

int main() {
	auto mockExtensionsWrapper = std::make_shared<MockChromeExtensionsWrapper>();
	chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
	std::cout << chromeExtensionsProvider.collect() << std::endl;

	return 0;
}