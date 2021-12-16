#include <gtest/gtest.h>

#include "builder.h"
#include "configuration.h"
#include "processor.h"


// Acceptance test
// Builder returns proper engine object when a configuration is given to it
TEST(BuilderTest, BuilderBuilds)
{
    // Given a configuration describing the object to be built
    Configuration configuration;
    vector<string_view> decoder_ids;

    for (int i = 0; i < 10; i++)
    {
        decoder_ids.push_back("decoder_" + to_string(i));
    }
    configuration.add_engine("decoder", decoder_ids);

    // A configuration is passed to the builder and the builder returns a processor object
    Processor processor = Builder(configuration);
}
