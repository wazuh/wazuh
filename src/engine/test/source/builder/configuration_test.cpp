#include <gtest/gtest.h>
#include <vector>
#include <string>

#include "configuration.h"

using namespace std;
// Given a list of ids for different objects a Configuration object is built correctly with the same ids present
TEST(ConfigurationTest, InitializesCorrectly)
{
    // Decoders list
    vector<string_view> decoder_ids;

    for (int i = 0; i < 10; i++)
    {
        decoder_ids.push_back("decoder_" + to_string(i));
    }

    // Construct Configuration
    Configuration configuration;
    configuration.add_engine("decoder", decoder_ids);
    for (auto it = configuration.cbegin(); it != configuration.cend(); it++){
        ASSERT_EQ(it->name, "decoder");
        ASSERT_EQ(it->components.size(), decoder_ids.size());
        for (auto it_i = it->components.cbegin(), it_j = decoder_ids.cbegin(); it_i != it->components.cend(); it_i++ ){
            ASSERT_EQ(*it_i, *it_j);
        }
    }
}
