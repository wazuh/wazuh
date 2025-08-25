#include "ie_explorer.hpp"

int main(){
    IEExtensionsProvider ieExtensionsProvider;

		std::cout << ieExtensionsProvider.collect().dump(4) << std::endl;

    return 0;
}
