#include "Catalog_test.hpp"


TEST(Catalog, get_decoder_valid)
{
    EXPECT_STREQ("decVal", "dec_Val");
}
