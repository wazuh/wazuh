#include <algorithm>
#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <vector>

#include "map_value.hpp"
#include "test_utils.hpp"

using namespace builder::internals::builders;

TEST(MapValueTest, Builds)
{
    // Fake entry point
    auto entry_point = observable<>::empty<event_t>();

    // Fake input json
    auto fake_jstring = R"(
      {
          "check": {
              "mapped_field": 1
          }
      }
  )";
    json::Document fake_j{fake_jstring};

    // Build
    auto _observable = mapValueBuilder(entry_point, fake_j.get(".check"));
}

TEST(MapValueTest, Operates)
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
              "field": "1"
      }
  )"});
            o.on_next(json::Document{R"(
      {
              "otherfield": 1
      }
  )"});
        });

    // Fake input json
    auto fake_jstring = R"(
      {
          "check": {
              "mapped_field": 1
          }
      }
  )";
    json::Document fake_j{fake_jstring};

    // Build
    auto _observable = mapValueBuilder(entry_point, fake_j.get(".check"));

    // Fake subscriber
    vector<event_t> observed;
    auto on_next = [&observed](event_t j) { observed.push_back(j); };
    auto on_completed = []() {};
    auto subscriber = make_subscriber<event_t>(on_next, on_completed);

    // Operate
    ASSERT_NO_THROW(_observable.subscribe(subscriber));
    ASSERT_EQ(observed.size(), 3);
    for_each(begin(observed), end(observed), [](event_t j) { ASSERT_EQ(j.get(".mapped_field")->GetInt(), 1); });
}
