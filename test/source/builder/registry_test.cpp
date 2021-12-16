#include <gtest/gtest.h>
#include <typeinfo>
#include <string>
#include <map>
#include "registry.h"

using std::string;

/*TEST (RegistryTests, RegistryType) {

    Registry reg;
    std::map<string,string> mapStringStringType;

    EXPECT_STREQ(typeid(reg.getRegistry()).name(), typeid(mapStringStringType).name());
}

TEST (RegistryTests, RegistryTypeFail) {

    Registry reg;
    int intType = 1;

    EXPECT_STREQ(typeid(reg.getRegistry()).name(), typeid(intType).name());
}*/

string name = "decoder";
string builder = "asi se buildea este decoder";

TEST (RegistryTests, RegistryIsEmpty) {

    Registry reg;

    EXPECT_TRUE(reg.isEmpty());
}

TEST (RegistryTests, RegistryNotEmpty) {

    Registry reg;

    reg.registerBuilder(name, builder);

    EXPECT_FALSE(reg.isEmpty());
}

TEST (RegistryTests, RegisterNewBuilder) {

    Registry reg;

    EXPECT_NO_THROW(reg.registerBuilder(name, builder));

}

TEST (RegistryTests, RegisterExistingBuilder) {

    Registry reg;

    reg.registerBuilder(name, builder);

    EXPECT_THROW(reg.registerBuilder(name, builder),invalid_argument);
}

TEST (RegistryTests, RegisterBuilderGetBuilder) {

    Registry reg;

    reg.registerBuilder(name, builder);

    EXPECT_EQ(builder, reg.getBuilder(name));

}

TEST (RegistryTests, getExistingBuilder) {

    Registry reg;

    reg.registerBuilder(name, builder);

    EXPECT_NO_THROW(reg.getBuilder(name));

}

TEST (RegistryTests, getNonExistingBuilder) {

    Registry reg;

    EXPECT_THROW(reg.getBuilder(name),invalid_argument);
    
}