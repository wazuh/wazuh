#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <vector>

#include "buildCheck.hpp"
#include "test_utils.hpp"

using namespace builder::internals::builders;

TEST(ConditionBuilderTest, BuildsConditionValue)
{
    // Fake entry point
    observable<event_t> entry_point = observable<>::create<event_t>(
        [](subscriber<event_t> o)
        {
            o.on_next(event_t{R"(
      {
              "field": 1
      }
  )"});
            o.on_next(event_t{R"(
      {
              "field": "1"
      }
  )"});
            o.on_next(event_t{R"(
      {
              "otherfield": 1
      }
  )"});
            o.on_completed();
        });

    // Fake input json
    auto fake_jstring = R"(
      {
          "check": {
              "field": 1
          }
      }
  )";
    json::Document fake_j{fake_jstring};

    // Build
    auto conditionObs = buildCheck(*fake_j.get(".check"));
    auto expectedObs = buildCheckVal(*fake_j.get(".check"));

    // Fake subscribers
    vector<event_t> observed;
    auto subscriber = make_subscriber<event_t>([&observed](event_t j) { observed.push_back(j); }, []() {});

    vector<event_t> observedExpected;
    auto subscriberExpected =
        make_subscriber<event_t>([&observedExpected](event_t j) { observedExpected.push_back(j); }, []() {});

    // Operate
    ASSERT_NO_THROW(conditionObs(entry_point).subscribe(subscriber));
    ASSERT_NO_THROW(expectedObs(entry_point).subscribe(subscriberExpected));
    ASSERT_EQ(observed.size(), observedExpected.size());
    for (auto i = 0; i < observed.size(); i++)
    {
        ASSERT_EQ(observed[i].get(".field")->GetInt(), observedExpected[i].get(".field")->GetInt());
    }
}

// TEST(ConditionBuilderTest, BuildsHelperExists)
// {
//     // Fake entry point
//     observable<event_t> entry_point = observable<>::create<event_t>(
//         [](subscriber<event_t> o)
//         {
//             o.on_next(event_t{R"(
//       {
//               "field": 1
//       }
//   )"});
//             o.on_next(event_t{R"(
//       {
//               "field": "1"
//       }
//   )"});
//             o.on_next(event_t{R"(
//       {
//               "otherfield": 1
//       }
//   )"});
//             o.on_completed();
//         });

//     // Fake input json
//     auto fake_jstring = R"(
//       {
//           "check": {
//               "field": "+exists"
//           }
//       }
//   )";
//     json::Document fake_j{fake_jstring};

//     // Build
//     auto conditionObs = conditionBuilder(entry_point, fake_j.get(".check"));
//     auto expectedObs = helperExistsBuilder(entry_point, fake_j.get(".check"));

//     // Fake subscribers
//     vector<event_t> observed;
//     auto subscriber = make_subscriber<event_t>([&observed](event_t j) { observed.push_back(j); }, []() {});

//     vector<event_t> observedExpected;
//     auto subscriberExpected =
//         make_subscriber<event_t>([&observedExpected](event_t j) { observedExpected.push_back(j); }, []() {});

//     // Operate
//     ASSERT_NO_THROW(conditionObs.subscribe(subscriber));
//     ASSERT_NO_THROW(expectedObs.subscribe(subscriberExpected));
//     ASSERT_EQ(observed.size(), observedExpected.size());
// }

// TEST(ConditionBuilderTest, BuildsHelperNotExists)
// {
//     // Fake entry point
//     observable<event_t> entry_point = observable<>::create<event_t>(
//         [](subscriber<event_t> o)
//         {
//             o.on_next(event_t{R"(
//       {
//               "field": 1
//       }
//   )"});
//             o.on_next(event_t{R"(
//       {
//               "field": "1"
//       }
//   )"});
//             o.on_next(event_t{R"(
//       {
//               "otherfield": 1
//       }
//   )"});
//             o.on_completed();
//         });

//     // Fake input json
//     auto fake_jstring = R"(
//       {
//           "check": {
//               "field": "+not_exists"
//           }
//       }
//   )";
//     json::Document fake_j{fake_jstring};

//     // Build
//     auto conditionObs = conditionBuilder(entry_point, fake_j.get(".check"));
//     auto expectedObs = helperNotExistsBuilder(entry_point, fake_j.get(".check"));

//     // Fake subscribers
//     vector<event_t> observed;
//     auto subscriber = make_subscriber<event_t>([&observed](event_t j) { observed.push_back(j); }, []() {});

//     vector<event_t> observedExpected;
//     auto subscriberExpected =
//         make_subscriber<event_t>([&observedExpected](event_t j) { observedExpected.push_back(j); }, []() {});

//     // Operate
//     ASSERT_NO_THROW(conditionObs.subscribe(subscriber));
//     ASSERT_NO_THROW(expectedObs.subscribe(subscriberExpected));
//     ASSERT_EQ(observed.size(), observedExpected.size());
// }
