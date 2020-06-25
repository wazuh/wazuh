#include "gtest/gtest.h"

class StringHelperTest : public ::testing::Test {

protected:

    StringHelperTest() = default;
    virtual ~StringHelperTest() = default;

    virtual void SetUp();
    virtual void TearDown();
};