#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <typeinfo>
#include <string>
#include <map>

#include "registry.hpp"

using json = nlohmann::json;
using namespace rxcpp;
using namespace std;

namespace
{
    observable<json> decoder_build(const observable<json>& obs, const vector<json>& decoders)
    {
        return obs;
    }
    builder::MultiJsonBuilder decoder_builder("decoder_engine", &decoder_build);
}

string builder_id = "decoder";
builder::Registry &reg = builder::Registry::instance();

TEST (RegistryTests, RegisterNewBuilder) {

    EXPECT_NO_THROW(reg.register_builder(builder_id,decoder_builder));

}

TEST (RegistryTests, RegisterExistingBuilder) {

    EXPECT_THROW(reg.register_builder(builder_id,decoder_builder),invalid_argument);

}

TEST (RegistryTests, getExistingBuilder) {

    EXPECT_NO_THROW(reg.get_builder(builder_id));

}

TEST (RegistryTests, getNonExistingBuilder) {

    EXPECT_THROW(reg.get_builder("none"),out_of_range);
    
}
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