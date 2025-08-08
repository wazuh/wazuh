#include "chrome_windows.hpp"
#include <iostream>

int main()
{
    chrome::ChromeExtensionsProvider chromeExtensionsProvider;
    std::cout << chromeExtensionsProvider.collect().dump(4) << std::endl;
    return 0;
}