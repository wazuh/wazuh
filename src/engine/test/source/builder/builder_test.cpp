#include <gtest/gtest.h>
#include <string>

#include "builder.hpp"
#include "builder_test.hpp"
#include "connectable.hpp"
#include "rxcpp/rx.hpp"



TEST(Builder, Constructor)
{
  auto builder = builder::Builder<FakeCatalog>(FakeCatalog());
}

TEST(Builder, Build)
{
  auto builder = builder::Builder<FakeCatalog>(FakeCatalog());
  builder.build("environment_0");
}
