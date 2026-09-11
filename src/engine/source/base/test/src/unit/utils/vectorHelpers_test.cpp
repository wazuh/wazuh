#include <base/utils/vectorHelpers.hpp>

#include <algorithm>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace
{

std::vector<std::string> sorted(std::vector<std::string> values)
{
    std::sort(values.begin(), values.end());
    return values;
}

} // namespace

// Removing a middle element must leave the other elements present, regardless of the physical reordering
// performed by the swap-remove.
TEST(VectorHelpersTest, EraseFirstBySwapRemovesMiddleElement)
{
    std::vector<std::string> values {"a", "b", "c"};

    const auto erased = base::utils::eraseFirstBySwap(values, [](const std::string& v) { return v == "b"; });

    EXPECT_TRUE(erased);
    EXPECT_EQ(sorted(values), (std::vector<std::string> {"a", "c"}));
}

// No match: returns false and leaves the container untouched.
TEST(VectorHelpersTest, EraseFirstBySwapReturnsFalseWhenNoMatch)
{
    std::vector<std::string> values {"a", "b", "c"};

    const auto erased = base::utils::eraseFirstBySwap(values, [](const std::string& v) { return v == "missing"; });

    EXPECT_FALSE(erased);
    EXPECT_EQ(values, (std::vector<std::string> {"a", "b", "c"}));
}

// Regression: the match being the last element must be a safe no-op for the self-swap case, and must not
// corrupt the remaining elements.
TEST(VectorHelpersTest, EraseFirstBySwapHandlesLastElementWithoutCorruption)
{
    std::vector<std::string> values {"a", "b", "c"};

    const auto erased = base::utils::eraseFirstBySwap(values, [](const std::string& v) { return v == "c"; });

    EXPECT_TRUE(erased);
    EXPECT_EQ(sorted(values), (std::vector<std::string> {"a", "b"}));
}

// Removing the only element must leave an empty container without corruption.
TEST(VectorHelpersTest, EraseFirstBySwapHandlesOnlyElement)
{
    std::vector<std::string> values {"only"};

    const auto erased = base::utils::eraseFirstBySwap(values, [](const std::string& v) { return v == "only"; });

    EXPECT_TRUE(erased);
    EXPECT_TRUE(values.empty());
}
