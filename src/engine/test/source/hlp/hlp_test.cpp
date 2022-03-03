#include "gtest/gtest.h"

#include <hlp/hlp.hpp>

TEST(hlpTests, newarq)
{
    const char *logQl ="<_map/MAP/ /=>";
    const char *event ="key1=Value1 Key2=Value2";

    ParserOp parseOp = getParserOp(logQl);
    ParserResult result;
    result.SetObject();
    bool success = parseOp(event, result);

    ASSERT_EQ("{\"key1\":\"Value1\",\"Key2\":\"Value2\"}", result["_map"]);

}