#include <algorithm>
#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <vector>

#include "stage.hpp"
#include "buildMap.hpp"
#include "test_utils.hpp"

using namespace builder::internals::builders;

TEST(NormalizeStageTest, Builds)
{
    // Fake entry point
    auto entry_point = observable<>::empty<event_t>();

    // Fake input json
    auto fake_jstring = R"(
    {
      "name": "test_normalize_stage",
      "map": [
        {"mapped": 2}
      ]
    }
    )";
    json::Document fake_j{fake_jstring};

    // Build
    ASSERT_NO_THROW(auto _op = buildStageChain(fake_j.get(".map"), buildMap));
}

TEST(NormalizeStageTest, BuildsErrorExpectsArray)
{
    // Fake entry point
    auto entry_point = observable<>::empty<event_t>();

    // Fake input json
    auto fake_jstring = R"(
    {
      "name": "test_normalize_stage",
      "map":
        {"mapped": 2}
    }
    )";
    json::Document fake_j{fake_jstring};

    // Build
    ASSERT_THROW(auto _op = buildStageChain(fake_j.get(".map"), buildMap), std::invalid_argument);
}

TEST(NormalizeStageTest, Operates)
{
    // Fake entry point
    observable<event_t> entry_point = observable<>::create<event_t>(
        [](subscriber<event_t> o)
        {
            o.on_next(json::Document{R"(
      {
              "field": 2
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
      "name": "test_normalize_stage",
      "map": [
        {"mapped": 1}
      ]
    }
    )";
    json::Document fake_j{fake_jstring};

    // Build
    auto _op =  buildStageChain(fake_j.get(".map"), buildMap);

    // Fake subscriber
    vector<event_t> observed;
    auto on_next = [&observed](event_t j) { observed.push_back(j); };
    auto on_completed = []() {};
    auto subscriber = make_subscriber<event_t>(on_next, on_completed);

    // Operate
    ASSERT_NO_THROW(_op(entry_point).subscribe(subscriber));
    ASSERT_EQ(observed.size(), 3);
    for_each(begin(observed), end(observed), [](event_t j) { ASSERT_EQ(j.get(".mapped")->GetInt(), 1); });
}
