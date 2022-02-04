#include <algorithm>
#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <vector>

#include "builders/rule.hpp"
#include "test_utils.hpp"

using namespace builder::internals::builders;

TEST(RuleBuilderTest, Builds)
{
    // Fake entry point
    auto entry_point = observable<>::empty<event_t>();

    // Fake input json
    auto fake_jstring = R"(
    {
      "name": "test_rule",
      "parents": [],
      "check": [
        {"field": 1}
      ],
      "normalize": [
        {"mapped_field": 1}
      ]
    }
  )";
    json::Document fake_j{fake_jstring};

    ASSERT_NO_THROW(auto con = buildRule(fake_j));
}

TEST(RuleBuilderTest, BuildsErrorNoName)
{
    // Fake entry point
    auto entry_point = observable<>::empty<event_t>();

    // Fake input json
    auto fake_jstring = R"(
    {
      "parents": [],
      "check": [
        {"field": 1}
      ],
      "normalize": [
        {"mapped_field": 1}
      ]
    }
  )";
    json::Document fake_j{fake_jstring};

    ASSERT_THROW(auto con = buildRule(fake_j), invalid_argument);
}

TEST(RuleBuilderTest, BuildsErrorNoCheck)
{
    // Fake entry point
    auto entry_point = observable<>::empty<event_t>();

    // Fake input json
    auto fake_jstring = R"(
    {
      "name": "name",
      "parents": [],
      "normalize": [
        {"mapped_field": 1}
      ]
    }
  )";
    json::Document fake_j{fake_jstring};

    ASSERT_THROW(auto con = buildRule(fake_j), invalid_argument);
}

TEST(RuleBuilderTest, OperatesAndConnects)
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
      "name": "test_decoder",
      "parents": [],
      "check": [
        {"field": 1}
      ],
      "normalize": [
        {"mapped_field": 1}
      ]
    }
  )";
    json::Document fake_j{fake_jstring};

    // Build
    auto con = buildRule(fake_j);

    // Fake subscriber
    vector<event_t> observed;
    auto on_next = [&observed](event_t j) { observed.push_back(j); };
    auto on_completed = []() {};
    auto subscriber = make_subscriber<event_t>(on_next, on_completed);

    // Operate
    ASSERT_NO_THROW(con.op(entry_point).subscribe(subscriber));
    // ASSERT_NO_THROW(entry_point.subscribe(connectable.input()));
    ASSERT_EQ(observed.size(), 2);
    for_each(begin(observed), end(observed), [](event_t j) { ASSERT_EQ(j.get(".mapped_field")->GetInt(), 1); });
}
