#include <csignal>
#include <gtest/gtest.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>
#include <string>
#include <vector>

#include "operation.hpp"

using json = nlohmann::json;
using namespace std;
using namespace rxcpp;

TEST(Operation, Initializes) {
  ASSERT_NO_THROW(operation::Operation<int> op("test_operation",
                                               [](int v) { return v + 1; }));
}

TEST(Operation, Lifts) {
  operation::Operation<int> op("test_operation", [](int v) { return v + 1; });

  auto input = observable<>::just<int>(1);

  ASSERT_NO_THROW(op.to_lift());
  ASSERT_NO_THROW(input.lift<int>(op.to_lift()));
}

TEST(Operation, Pipes) {
  operation::Operation<int> op("test_operation", [](int v) { return v + 1; });

  auto input = observable<>::just<int>(1);

  ASSERT_NO_THROW(op.to_operator());
  ASSERT_NO_THROW(input | op.to_operator());
}

TEST(Operation, OnNextLifted) {
  operation::Operation<int> op("test_operation", [](int v) { return v + 1; });

  auto input = observable<>::from(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
  auto end = input.lift<int>(op.to_lift());

  vector<int> results;
  end.subscribe(
      make_subscriber<int>([&](int v) { results.push_back(v); }, []() {}));

  ASSERT_EQ(results.size(), 10);
  for (auto i = 0; i < 10; i++) {
    ASSERT_EQ(results[i], i + 1);
  }
}

TEST(Operation, OnNextPiped) {
  operation::Operation<int> op("test_operation", [](int v) { return v + 1; });

  auto input = observable<>::from(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
  auto end = input | op.to_operator();

  vector<int> results;
  end.subscribe(
      make_subscriber<int>([&](int v) { results.push_back(v); }, []() {}));

  ASSERT_EQ(results.size(), 10);
  for (auto i = 0; i < 10; i++) {
    ASSERT_EQ(results[i], i + 1);
  }
}

// --TODO-- more use cases and combinators //
