#include <gtest/gtest.h>
#include <typeinfo>
#include <string>
#include <map>
#include "../../source/registry.cpp"

using std::string;

std::map<string,string> mapStringStringType;
int intType = 1;
Registry reg;
std::map<string,string> mapStringString = reg.getRegistry();
string demo = reg.getBuilder("decoder");
string builderdemo = "construir decoder asi";


TEST (RegistryTests, RegistryType) {
    EXPECT_STREQ(typeid(mapStringString).name(), typeid(mapStringStringType).name());
}

TEST (RegistryTests, RegistryTypeFail) {
    EXPECT_STREQ(typeid(mapStringString).name(), typeid(intType).name());
}

TEST (RegistryTests, RegistryIsEmpty) {
    EXPECT_TRUE(reg.getRegistry().empty());
}

TEST (RegistryTests, RegistryNotEmpty) {
    EXPECT_FALSE(reg.getRegistry().empty());
}



int main(int argc, char **argv) {

    reg.registerItem(demo,builderdemo);

    cout << reg.getBuilder("decoder")<< endl;

    ::testing::InitGoogleTest(&argc,argv);
    return RUN_ALL_TESTS();
}