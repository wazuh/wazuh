#include <gtest/gtest.h>

#include "environment.hpp"

using namespace router;

TEST(Environment, test)
{
    Environment env {base::Expression {}, nullptr};

    ASSERT_TRUE(env.isAccepted(base::Event {}));
}
