#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace
{
auto ctxExpected()
{
    return [](const Mocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, context());
        return None {};
    };
}

auto customRefExpected()
{
    return [](const Mocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema());
        EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto typeRefExpected(schemf::Type type, bool success = true)
{
    return [=](const Mocks& mocks)
    {
        if (!success)
        {
            EXPECT_CALL(*mocks.ctx, context());
        }
        EXPECT_CALL(*mocks.ctx, schema()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.schema, getType(DotPath("ref"))).WillRepeatedly(testing::Return(type));
        return None {};
    };
}

} // namespace

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterBuilderTest,
    testing::Values(
        /*** IntEqual ***/
        // Wrong number of arguments
        FilterT({makeValue("1"), makeValue("1")}, opfilter::opBuilderHelperIntEqual, FAILURE(ctxExpected())),
        FilterT({}, opfilter::opBuilderHelperIntEqual, FAILURE(ctxExpected())),
        // Values
        FilterT({makeValue("1")}, opfilter::opBuilderHelperIntEqual, SUCCESS()),
        FilterT({makeValue(R"("1")")}, opfilter::opBuilderHelperIntEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(1.1)")}, opfilter::opBuilderHelperIntEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(1.0)")}, opfilter::opBuilderHelperIntEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(true)")}, opfilter::opBuilderHelperIntEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(false)")}, opfilter::opBuilderHelperIntEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"([])")}, opfilter::opBuilderHelperIntEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"({})")}, opfilter::opBuilderHelperIntEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperIntEqual, FAILURE(ctxExpected())),
        // References
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperIntEqual, SUCCESS(customRefExpected())),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperIntEqual, SUCCESS(typeRefExpected(schemf::Type::INTEGER))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperIntEqual,
                FAILURE(typeRefExpected(schemf::Type::TEXT, false))),
        /*** IntGreaterThan ***/
        // Wrong number of arguments
        FilterT({makeValue("1"), makeValue("1")}, opfilter::opBuilderHelperIntGreaterThan, FAILURE(ctxExpected())),
        FilterT({}, opfilter::opBuilderHelperIntGreaterThan, FAILURE(ctxExpected())),
        // Values
        FilterT({makeValue("1")}, opfilter::opBuilderHelperIntGreaterThan, SUCCESS()),
        FilterT({makeValue(R"("1")")}, opfilter::opBuilderHelperIntGreaterThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(1.1)")}, opfilter::opBuilderHelperIntGreaterThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(1.0)")}, opfilter::opBuilderHelperIntGreaterThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(true)")}, opfilter::opBuilderHelperIntGreaterThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(false)")}, opfilter::opBuilderHelperIntGreaterThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"([])")}, opfilter::opBuilderHelperIntGreaterThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"({})")}, opfilter::opBuilderHelperIntGreaterThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperIntGreaterThan, FAILURE(ctxExpected())),
        // References
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperIntGreaterThan, SUCCESS(customRefExpected())),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperIntGreaterThan,
                SUCCESS(typeRefExpected(schemf::Type::INTEGER))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperIntGreaterThan,
                FAILURE(typeRefExpected(schemf::Type::TEXT, false))),
        /*** IntGreaterThanOrEqual ***/
        // Wrong number of arguments
        FilterT({makeValue("1"), makeValue("1")}, opfilter::opBuilderHelperIntGreaterThanEqual, FAILURE(ctxExpected())),
        FilterT({}, opfilter::opBuilderHelperIntGreaterThanEqual, FAILURE(ctxExpected())),
        // Values
        FilterT({makeValue("1")}, opfilter::opBuilderHelperIntGreaterThanEqual, SUCCESS()),
        FilterT({makeValue(R"("1")")}, opfilter::opBuilderHelperIntGreaterThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(1.1)")}, opfilter::opBuilderHelperIntGreaterThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(1.0)")}, opfilter::opBuilderHelperIntGreaterThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(true)")}, opfilter::opBuilderHelperIntGreaterThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(false)")}, opfilter::opBuilderHelperIntGreaterThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"([])")}, opfilter::opBuilderHelperIntGreaterThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"({})")}, opfilter::opBuilderHelperIntGreaterThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperIntGreaterThanEqual, FAILURE(ctxExpected())),
        // References
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperIntGreaterThanEqual, SUCCESS(customRefExpected())),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperIntGreaterThanEqual,
                SUCCESS(typeRefExpected(schemf::Type::INTEGER))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperIntGreaterThanEqual,
                FAILURE(typeRefExpected(schemf::Type::TEXT, false))),
        /*** IntLessThan ***/
        // Wrong number of arguments
        FilterT({makeValue("1"), makeValue("1")}, opfilter::opBuilderHelperIntLessThan, FAILURE(ctxExpected())),
        FilterT({}, opfilter::opBuilderHelperIntLessThan, FAILURE(ctxExpected())),
        // Values
        FilterT({makeValue("1")}, opfilter::opBuilderHelperIntLessThan, SUCCESS()),
        FilterT({makeValue(R"("1")")}, opfilter::opBuilderHelperIntLessThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(1.1)")}, opfilter::opBuilderHelperIntLessThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(1.0)")}, opfilter::opBuilderHelperIntLessThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(true)")}, opfilter::opBuilderHelperIntLessThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(false)")}, opfilter::opBuilderHelperIntLessThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"([])")}, opfilter::opBuilderHelperIntLessThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"({})")}, opfilter::opBuilderHelperIntLessThan, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperIntLessThan, FAILURE(ctxExpected())),
        // References
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperIntLessThan, SUCCESS(customRefExpected())),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperIntLessThan,
                SUCCESS(typeRefExpected(schemf::Type::INTEGER))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperIntLessThan,
                FAILURE(typeRefExpected(schemf::Type::TEXT, false))),
        /*** IntLessThanOrEqual ***/
        // Wrong number of arguments
        FilterT({makeValue("1"), makeValue("1")}, opfilter::opBuilderHelperIntLessThanEqual, FAILURE(ctxExpected())),
        FilterT({}, opfilter::opBuilderHelperIntLessThanEqual, FAILURE(ctxExpected())),
        // Values
        FilterT({makeValue("1")}, opfilter::opBuilderHelperIntLessThanEqual, SUCCESS()),
        FilterT({makeValue(R"("1")")}, opfilter::opBuilderHelperIntLessThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(1.1)")}, opfilter::opBuilderHelperIntLessThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(1.0)")}, opfilter::opBuilderHelperIntLessThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(true)")}, opfilter::opBuilderHelperIntLessThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(false)")}, opfilter::opBuilderHelperIntLessThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"([])")}, opfilter::opBuilderHelperIntLessThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"({})")}, opfilter::opBuilderHelperIntLessThanEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperIntLessThanEqual, FAILURE(ctxExpected())),
        // References
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperIntLessThanEqual, SUCCESS(customRefExpected())),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperIntLessThanEqual,
                SUCCESS(typeRefExpected(schemf::Type::INTEGER))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperIntLessThanEqual,
                FAILURE(typeRefExpected(schemf::Type::TEXT, false))),
        /*** IntNotEqual ***/
        // Wrong number of arguments
        FilterT({makeValue("1"), makeValue("1")}, opfilter::opBuilderHelperIntNotEqual, FAILURE(ctxExpected())),
        FilterT({}, opfilter::opBuilderHelperIntNotEqual, FAILURE(ctxExpected())),
        // Values
        FilterT({makeValue("1")}, opfilter::opBuilderHelperIntNotEqual, SUCCESS()),
        FilterT({makeValue(R"("1")")}, opfilter::opBuilderHelperIntNotEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(1.1)")}, opfilter::opBuilderHelperIntNotEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(1.0)")}, opfilter::opBuilderHelperIntNotEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(true)")}, opfilter::opBuilderHelperIntNotEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(false)")}, opfilter::opBuilderHelperIntNotEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"([])")}, opfilter::opBuilderHelperIntNotEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"({})")}, opfilter::opBuilderHelperIntNotEqual, FAILURE(ctxExpected())),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperIntNotEqual, FAILURE(ctxExpected())),
        // References
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperIntNotEqual, SUCCESS(customRefExpected())),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperIntNotEqual,
                SUCCESS(typeRefExpected(schemf::Type::INTEGER))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperIntNotEqual,
                FAILURE(typeRefExpected(schemf::Type::TEXT, false)))),
    testNameFormatter<FilterBuilderTest>("IntCmp"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterOperationTest,
    testing::Values(
        /*** IntEqual ***/
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntEqual, "target", {makeValue("1")}, SUCCESS()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntEqual, "target", {makeValue("2")}, FAILURE()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntEqual, "notTarget", {makeValue("1")}, FAILURE()),
        FilterT(R"({"target": "1"})", opfilter::opBuilderHelperIntEqual, "target", {makeValue("1")}, FAILURE()),
        FilterT(R"({"target": 1, "ref": 1})",
                opfilter::opBuilderHelperIntEqual,
                "target",
                {makeRef("ref")},
                SUCCESS(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 2})",
                opfilter::opBuilderHelperIntEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 1})",
                opfilter::opBuilderHelperIntEqual,
                "notTarget",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "notRef": 1})",
                opfilter::opBuilderHelperIntEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": "1", "ref": 1})",
                opfilter::opBuilderHelperIntEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": "1"})",
                opfilter::opBuilderHelperIntEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        /*** IntGreaterThan ***/
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntGreaterThan, "target", {makeValue("0")}, SUCCESS()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntGreaterThan, "target", {makeValue("1")}, FAILURE()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntGreaterThan, "target", {makeValue("2")}, FAILURE()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntGreaterThan, "notTarget", {makeValue("0")}, FAILURE()),
        FilterT(R"({"target": "1"})", opfilter::opBuilderHelperIntGreaterThan, "target", {makeValue("0")}, FAILURE()),
        FilterT(R"({"target": 1, "ref": 0})",
                opfilter::opBuilderHelperIntGreaterThan,
                "target",
                {makeRef("ref")},
                SUCCESS(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 1})",
                opfilter::opBuilderHelperIntGreaterThan,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 2})",
                opfilter::opBuilderHelperIntGreaterThan,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 0})",
                opfilter::opBuilderHelperIntGreaterThan,
                "notTarget",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "notRef": 0})",
                opfilter::opBuilderHelperIntGreaterThan,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": "1", "ref": 0})",
                opfilter::opBuilderHelperIntGreaterThan,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": "0"})",
                opfilter::opBuilderHelperIntGreaterThan,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        /*** IntGreaterThanOrEqual ***/
        FilterT(
            R"({"target": 1})", opfilter::opBuilderHelperIntGreaterThanEqual, "target", {makeValue("0")}, SUCCESS()),
        FilterT(
            R"({"target": 1})", opfilter::opBuilderHelperIntGreaterThanEqual, "target", {makeValue("1")}, SUCCESS()),
        FilterT(
            R"({"target": 1})", opfilter::opBuilderHelperIntGreaterThanEqual, "target", {makeValue("2")}, FAILURE()),
        FilterT(
            R"({"target": 1})", opfilter::opBuilderHelperIntGreaterThanEqual, "notTarget", {makeValue("0")}, FAILURE()),
        FilterT(
            R"({"target": "1"})", opfilter::opBuilderHelperIntGreaterThanEqual, "target", {makeValue("0")}, FAILURE()),
        FilterT(R"({"target": 1, "ref": 0})",
                opfilter::opBuilderHelperIntGreaterThanEqual,
                "target",
                {makeRef("ref")},
                SUCCESS(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 1})",
                opfilter::opBuilderHelperIntGreaterThanEqual,
                "target",
                {makeRef("ref")},
                SUCCESS(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 2})",
                opfilter::opBuilderHelperIntGreaterThanEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 0})",
                opfilter::opBuilderHelperIntGreaterThanEqual,
                "notTarget",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "notRef": 0})",
                opfilter::opBuilderHelperIntGreaterThanEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": "1", "ref": 0})",
                opfilter::opBuilderHelperIntGreaterThanEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": "0"})",
                opfilter::opBuilderHelperIntGreaterThanEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        /*** IntLessThan ***/
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntLessThan, "target", {makeValue("2")}, SUCCESS()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntLessThan, "target", {makeValue("1")}, FAILURE()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntLessThan, "target", {makeValue("0")}, FAILURE()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntLessThan, "notTarget", {makeValue("2")}, FAILURE()),
        FilterT(R"({"target": "1"})", opfilter::opBuilderHelperIntLessThan, "target", {makeValue("2")}, FAILURE()),
        FilterT(R"({"target": 1, "ref": 2})",
                opfilter::opBuilderHelperIntLessThan,
                "target",
                {makeRef("ref")},
                SUCCESS(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 1})",
                opfilter::opBuilderHelperIntLessThan,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 0})",
                opfilter::opBuilderHelperIntLessThan,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 2})",
                opfilter::opBuilderHelperIntLessThan,
                "notTarget",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "notRef": 2})",
                opfilter::opBuilderHelperIntLessThan,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": "1", "ref": 2})",
                opfilter::opBuilderHelperIntLessThan,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": "2"})",
                opfilter::opBuilderHelperIntLessThan,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        /*** IntLessThanOrEqual ***/
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntLessThanEqual, "target", {makeValue("2")}, SUCCESS()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntLessThanEqual, "target", {makeValue("1")}, SUCCESS()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntLessThanEqual, "target", {makeValue("0")}, FAILURE()),
        FilterT(
            R"({"target": 1})", opfilter::opBuilderHelperIntLessThanEqual, "notTarget", {makeValue("2")}, FAILURE()),
        FilterT(R"({"target": "1"})", opfilter::opBuilderHelperIntLessThanEqual, "target", {makeValue("2")}, FAILURE()),
        FilterT(R"({"target": 1, "ref": 2})",
                opfilter::opBuilderHelperIntLessThanEqual,
                "target",
                {makeRef("ref")},
                SUCCESS(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 1})",
                opfilter::opBuilderHelperIntLessThanEqual,
                "target",
                {makeRef("ref")},
                SUCCESS(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 0})",
                opfilter::opBuilderHelperIntLessThanEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 2})",
                opfilter::opBuilderHelperIntLessThanEqual,
                "notTarget",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "notRef": 2})",
                opfilter::opBuilderHelperIntLessThanEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": "1", "ref": 2})",
                opfilter::opBuilderHelperIntLessThanEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": "2"})",
                opfilter::opBuilderHelperIntLessThanEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        /*** IntNotEqual ***/
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntNotEqual, "target", {makeValue("2")}, SUCCESS()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntNotEqual, "target", {makeValue("1")}, FAILURE()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperIntNotEqual, "notTarget", {makeValue("2")}, FAILURE()),
        FilterT(R"({"target": "1"})", opfilter::opBuilderHelperIntNotEqual, "target", {makeValue("2")}, FAILURE()),
        FilterT(R"({"target": 1, "ref": 2})",
                opfilter::opBuilderHelperIntNotEqual,
                "target",
                {makeRef("ref")},
                SUCCESS(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 1})",
                opfilter::opBuilderHelperIntNotEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": 2})",
                opfilter::opBuilderHelperIntNotEqual,
                "notTarget",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "notRef": 2})",
                opfilter::opBuilderHelperIntNotEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": "1", "ref": 2})",
                opfilter::opBuilderHelperIntNotEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected())),
        FilterT(R"({"target": 1, "ref": "2"})",
                opfilter::opBuilderHelperIntNotEqual,
                "target",
                {makeRef("ref")},
                FAILURE(customRefExpected()))),
    testNameFormatter<FilterOperationTest>("IntCmp"));
}
