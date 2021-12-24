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

string builder_id = "test_decoder";
builder::Registry &reg = builder::Registry::instance();

TEST (RegistryTests, RegisterNewBuilder) {

    ASSERT_NO_THROW(reg.register_builder(builder_id,decoder_builder));

}

TEST (RegistryTests, RegisterExistingBuilder) {

    ASSERT_THROW(reg.register_builder(builder_id,decoder_builder),invalid_argument);

}

TEST (RegistryTests, getExistingBuilder) {

    ASSERT_NO_THROW(reg.get_builder(builder_id));

}

TEST (RegistryTests, getNonExistingBuilder) {

    ASSERT_THROW(reg.get_builder("none"),out_of_range);
    
}