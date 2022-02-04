#include <algorithm>
#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <vector>

#include "builders/filter.hpp"
#include "test_utils.hpp"

using namespace builder::internals::builders;

TEST(FilterBuilderTest, Builds)
{
    // Fake entry point
    auto entry_point = observable<>::empty<event_t>();

    // Fake input json
    auto fake_jstring = R"(
    {
      "name": "test_filter",
      "after": [],
      "allow": [
        {"field": 1}
      ]
    }
    )";
    json::Document fake_j{fake_jstring};

    ASSERT_NO_THROW(auto op = buildFilter(fake_j));
}

TEST(FilterBuilderTest, BuildsErrorNoName)
{
    // Fake entry point
    auto entry_point = observable<>::empty<event_t>();

    // Fake input json
    auto fake_jstring = R"(
    {
      "after": [],
      "allow": [
        {"field": 1}
      ]
    }
    )";
    json::Document fake_j{fake_jstring};

    ASSERT_THROW(auto op = buildFilter(fake_j), invalid_argument);
}

TEST(FilterBuilderTest, BuildsErrorNoAllow)
{
    // Fake entry point
    auto entry_point = observable<>::empty<event_t>();

    // Fake input json
    auto fake_jstring = R"(
    {
      "name": "test_filter",
      "after": []
    }
    )";
    json::Document fake_j{fake_jstring};

    ASSERT_THROW(auto op = buildFilter(fake_j), invalid_argument);
}

TEST(FilterBuilderTest, OperatesAndConnects)
{
    // Fake entry point
    observable<event_t> entry_point = observable<>::create<event_t>(
        [](subscriber<event_t> o)
        {
            o.on_next(json::Document{R"(
      {
              "field": 1
      }
  )"});
            o.on_next(json::Document{R"(
      {
              "field": 2
      }
  )"});
            o.on_next(json::Document{R"(
      {
              "field": 1
      }
  )"});
        });

    // Fake input json
    auto fake_jstring = R"(
    {
      "name": "test_filter",
      "after": [],
      "allow": [
        {"field": 1}
      ]
    }
    )";
    json::Document fake_j{fake_jstring};

    // Build
    auto connectable = buildFilter(fake_j);

    // Fake subscriber
    vector<event_t> observed;
    auto on_next = [&observed](event_t j) { observed.push_back(j); };
    auto on_completed = []() {};
    auto subscriber = make_subscriber<event_t>(on_next, on_completed);

    // Operate
    ASSERT_NO_THROW(connectable.op(entry_point).subscribe(subscriber));
    // ASSERT_NO_THROW(entry_point.subscribe(connectable.input()));
    ASSERT_EQ(observed.size(), 2);
    for_each(begin(observed), end(observed), [](event_t j) { ASSERT_EQ(j.get(".field")->GetInt(), 1); });
}
