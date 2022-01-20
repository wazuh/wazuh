#include <gtest/gtest.h>
#include <string>

#include "builder.hpp"
#include "builder_test.hpp"
#include "connectable.hpp"
#include "rxcpp/rx.hpp"

TEST(Builder, Build)
{
    auto builder = builder::Builder<FakeCatalog>(FakeCatalog());
    auto root = builder.build("environment_0");
}
