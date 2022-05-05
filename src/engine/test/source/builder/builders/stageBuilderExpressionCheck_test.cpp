#include <gtest/gtest.h>

#include "register.hpp"
#include "stageBuilderExpressionCheck.hpp"
#include "testUtils.hpp"

auto fakeTracer = [](string s) {
};

TEST(StageBuilderExpressionCheck, Operates)
{
    registerBuilders();
    auto checkDef = json::Document(
        R"({"check": "field==value AND other.field==$field OR +exists/field1"})");
    base::Lifter lifter;
    ASSERT_NO_THROW(lifter = builders::stageBuilderExpressionCheck(
                        checkDef.getObject()["check"], fakeTracer));

    auto input = observable<>::create<base::Event>(
        [](auto s)
        {
            s.on_next(createSharedEvent(R"({
                "field": 10,
                "other": {
                    "field": 20
                }
            })"));
            s.on_next(createSharedEvent(R"({
                "field": 10,
                "other": {
                    "field": 10
                }
            })"));
            s.on_next(createSharedEvent(R"({
                    "field": 10,
                    "other": {
                        "field": 11
                    },
                    "field1": "value"
                })"));
            s.on_next(createSharedEvent(R"({
                "field": "value",
                "other": {
                    "field": "value"
                }
            })"));
            s.on_next(createSharedEvent(R"({
                "field": "value",
                "other": {
                    "field": 10
                }
            })"));
            s.on_completed();
        });

    std::vector<base::Event> results;
    lifter(input).subscribe([&](base::Event e) { results.push_back(e); });

    ASSERT_EQ(results.size(), 2);
    for (auto& e : results)
    {
        ASSERT_TRUE(e->getEvent()->exists("/field1") ||
                    (e->getEvent()->equals("/field", "/other/field") &&
                     e->getEvent()->get("/field").GetString() == std::string("value")));
    }
}
