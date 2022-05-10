#include "testUtils.hpp"

#include "_builder/event.hpp"

TEST(Event, test) {
    Event<int> event{1};
    ASSERT_EQ(event.payload(), 1);
    auto other = std::move(event);
    ASSERT_EQ(other.payload(), 1);
}
