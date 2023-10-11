#include <gtest/gtest.h>

#include <bk/taskf/controller.hpp>

using namespace bk::taskf;

/********************************************
 *
 * Struct of result of each term
 *
 * { "name": "termName", "result": true/false}
 *
 * The expected result is an array of this struct, in evaluation order, like:
 * [{ "name": "term1", "result": true}]
 ********************************************/
const std::string PATH_NAME = "/name";
const std::string PATH_RESULT = "/result";

const std::string SUCCES_TRACE = "Fake trace success";
const std::string FAILURE_TRACE = "Fake trace failure";

class EasyExp
{
public:
    base::Expression m_expression;

    EasyExp() = default;

    static auto term(const std::string& name, bool success) -> base::Expression
    {
        return base::Term<base::EngineOp>::create(name,
                                                  [success, name](const auto& e)
                                                  {
                                                      json::Json result {};
                                                      result.setString(name, PATH_NAME);
                                                      result.setBool(success, PATH_RESULT);
                                                      e->appendJson(result);
                                                      if (success)
                                                      {
                                                          return base::result::makeSuccess(e, SUCCES_TRACE);
                                                      }
                                                      return base::result::makeFailure(e, FAILURE_TRACE);
                                                  });
    }

    // The name of the term is the 'name' field + _ + the index of the term in the vector
    static auto broadcast(const std::string& name, const std::vector<bool>& expResult) -> base::Expression
    {
        auto expr = base::Broadcast::create(name, {});
        auto& broadcastExpr = expr->getOperands();
        for (std::size_t i = 0; i < expResult.size(); ++i)
        {
            broadcastExpr.emplace_back(term(name + "_" + std::to_string(i), expResult[i]));
        }
        return expr;
    }

    // The name of the term is the 'name' field + _ + the index of the term in the vector
    static auto chain(const std::string& name, const std::vector<bool>& expResult) -> base::Expression
    {
        auto expr = base::Chain::create(name, {});
        auto& chainExpr = expr->getOperands();
        for (std::size_t i = 0; i < expResult.size(); ++i)
        {
            chainExpr.emplace_back(term(name + "_" + std::to_string(i), expResult[i]));
        }
        return expr;
    }

    // The name of the term is the 'name' field + _0 for the condition and _imp for the implication
    static auto implication(const std::string& name, bool condition, bool implication) -> base::Expression
    {
        auto expr = base::Implication::create(name, term(name + "_cond", condition), term(name + "_imp", implication));
        return expr;
    }

    // The name of the term is the 'name' field + _ + the index of the term in the vector
    static auto or_(const std::string& name, const std::vector<bool>& expResult) -> base::Expression
    {
        auto expr = base::Or::create(name, {});
        auto& orExpr = expr->getOperands();
        for (std::size_t i = 0; i < expResult.size(); ++i)
        {
            orExpr.emplace_back(term(name + "_" + std::to_string(i), expResult[i]));
        }
        return expr;
    }

    // The name of the term is the 'name' field + _ + the index of the term in the vector
    static auto and_(const std::string& name, const std::vector<bool>& expResult) -> base::Expression
    {
        auto expr = base::And::create(name, {});
        auto& andExpr = expr->getOperands();
        for (std::size_t i = 0; i < expResult.size(); ++i)
        {
            andExpr.emplace_back(term(name + "_" + std::to_string(i), expResult[i]));
        }
        return expr;
    }

    // Cast operator to base::Expression
    operator base::Expression() const { return m_expression; }
};

// Test parameters: Expression, expected result (name + term result)
using BKexpParams = std::tuple<base::Expression, std::vector<std::pair<std::string, bool>>>;
class BKTaskFlowControllerTest : public ::testing::TestWithParam<BKexpParams>
{
};

TEST_P(BKTaskFlowControllerTest, buildAndIngest)
{
    auto [expr, expResult] = GetParam();
    auto counter = 0;
    auto controller =
        bk::taskf::Controller(expr,
                              {},
                              [&]()
                              {
                                  ++counter;
                                  ASSERT_EQ(counter, 1)
                                      << "Only one event is send but the end callback received more than one event";
                              });
    auto event = std::make_shared<json::Json>();
    ASSERT_NO_THROW(event = controller.ingestGet(std::move(event)));

    auto jResult = event->getArray();
    ASSERT_TRUE(jResult) << "The result is not an array: " << event->prettyStr();

    ASSERT_EQ(jResult->size(), expResult.size())
        << "The result size is not the expected: " << event->prettyStr() << "\nDot Graph:\n"
        << controller.printGraph() << "\n";

    // Check for each parcial result for each term (in order of eval)
    for (std::size_t i = 0; i < expResult.size(); ++i)
    {
        const auto& jTermResult = jResult->at(i);
        const auto& [name, result] = expResult[i];

        ASSERT_TRUE(jTermResult.isObject()) << "The result is not an object: " << jTermResult.prettyStr();
        ASSERT_TRUE(jTermResult.isString(PATH_NAME)) << "The result has no name field: " << jTermResult.prettyStr();
        ASSERT_TRUE(jTermResult.isBool(PATH_RESULT)) << "The result has no result field: " << jTermResult.prettyStr();

        ASSERT_EQ(jTermResult.getString(PATH_NAME).value(), name)
            << "The name is not the expected: " << jTermResult.prettyStr() << "\nFull order: " << event->prettyStr()
            << "\nDot Graph:\n"
            << controller.printGraph() << "\n";
        ASSERT_EQ(jTermResult.getBool(PATH_RESULT).value(), result)
            << "The result is not the expected: " << jTermResult.prettyStr() << "\nFull order: " << event->prettyStr()
            << "\nDot Graph:\n"
            << controller.printGraph() << "\n";
    }
}

INSTANTIATE_TEST_SUITE_P(
    BKTaskFlow,
    BKTaskFlowControllerTest,
    ::testing::Values(
        // [2] Basic: Term
        BKexpParams {EasyExp::term("term", true), {{"term", true}}},
        BKexpParams {EasyExp::term("term", false), {{"term", false}}},
        // Basic: Broadcast (The order is not important in broadcast, use chain instead for order) By default the
        // [5] scheduler in taskflow invert the order
        BKexpParams {EasyExp::broadcast("broadcast", {true, true, true, true, true}),
                     {{"broadcast_4", true},
                      {"broadcast_3", true},
                      {"broadcast_2", true},
                      {"broadcast_1", true},
                      {"broadcast_0", true}}},
        BKexpParams {EasyExp::broadcast("broadcast", {true, true, false, true, true}),
                     {{"broadcast_4", true},
                      {"broadcast_3", true},
                      {"broadcast_2", false},
                      {"broadcast_1", true},
                      {"broadcast_0", true}}},
        BKexpParams {EasyExp::broadcast("broadcast", {false, false, false, false, false}),
                     {{"broadcast_4", false},
                      {"broadcast_3", false},
                      {"broadcast_2", false},
                      {"broadcast_1", false},
                      {"broadcast_0", false}}},
        BKexpParams {EasyExp::broadcast("broadcast", {false}), {{"broadcast_0", false}}},
        BKexpParams {EasyExp::broadcast("broadcast", {true}), {{"broadcast_0", true}}},
        // [5] basic: Chain
        BKexpParams {EasyExp::chain("chain", {true, true, true, true, true}),
                     {{"chain_0", true}, {"chain_1", true}, {"chain_2", true}, {"chain_3", true}, {"chain_4", true}}},
        BKexpParams {EasyExp::chain("chain", {true, true, false, true, true}),
                     {{"chain_0", true}, {"chain_1", true}, {"chain_2", false}, {"chain_3", true}, {"chain_4", true}}},
        BKexpParams {
            EasyExp::chain("chain", {false, false, false, false, false}),
            {{"chain_0", false}, {"chain_1", false}, {"chain_2", false}, {"chain_3", false}, {"chain_4", false}}},
        BKexpParams {EasyExp::chain("chain", {false}), {{"chain_0", false}}},
        BKexpParams {EasyExp::chain("chain", {true}), {{"chain_0", true}}},
        // [4] Basic: Implication
        BKexpParams {EasyExp::implication("implication", true, true),
                     {{"implication_cond", true}, {"implication_imp", true}}},
        BKexpParams {EasyExp::implication("implication", true, false),
                     {{"implication_cond", true}, {"implication_imp", false}}},
        BKexpParams {EasyExp::implication("implication", false, true), {{"implication_cond", false}}},
        BKexpParams {EasyExp::implication("implication", false, false), {{"implication_cond", false}}},
        // [5] Basic: Or
        BKexpParams {EasyExp::or_("or", {true, true, true, true, true}), {{"or_0", true}}},
        BKexpParams {EasyExp::or_("or", {false, false, true, true, true}),
                     {{"or_0", false}, {"or_1", false}, {"or_2", true}}},
        BKexpParams {EasyExp::or_("or", {false, false, false, false, false}),
                     {{"or_0", false}, {"or_1", false}, {"or_2", false}, {"or_3", false}, {"or_4", false}}},
        BKexpParams {EasyExp::or_("or", {false}), {{"or_0", false}}},
        BKexpParams {EasyExp::or_("or", {true}), {{"or_0", true}}},
        // [5] Basic: and
        BKexpParams {EasyExp::and_("and", {true, true, true, true, true}),
                     {{"and_0", true}, {"and_1", true}, {"and_2", true}, {"and_3", true}, {"and_4", true}}},
        BKexpParams {EasyExp::and_("and", {true, true, false, true, true}),
                     {{"and_0", true}, {"and_1", true}, {"and_2", false}}},
        BKexpParams {EasyExp::and_("and", {false, false, false, false, false}), {{"and_0", false}}},
        BKexpParams {EasyExp::and_("and", {false}), {{"and_0", false}}},
        BKexpParams {EasyExp::and_("and", {true}), {{"and_0", true}}},
        /*********************************************** BROADCAST TEST ***********************************************/
        // [2] Complex: Broadcast of broadcast
        BKexpParams {
            base::Broadcast::create("broadcast",
                                    {EasyExp::broadcast("broadcast_0", {true, true}),
                                     EasyExp::broadcast("broadcast_1", {true, true})}),
            {{"broadcast_1_1", true}, {"broadcast_1_0", true}, {"broadcast_0_1", true}, {"broadcast_0_0", true}}},
        BKexpParams {
            base::Broadcast::create("broadcast",
                                    {EasyExp::broadcast("broadcast_0", {true, false}),
                                     EasyExp::broadcast("broadcast_1", {false, true})}),
            {{"broadcast_1_1", true}, {"broadcast_1_0", false}, {"broadcast_0_1", false}, {"broadcast_0_0", true}}},
        // [2] Complex: Broadcast of chain
        BKexpParams {
            base::Broadcast::create("broadcast",
                                    {EasyExp::chain("chain_0", {true, true}), EasyExp::chain("chain_1", {true, true})}),
            {{"chain_1_0", true}, {"chain_1_1", true}, {"chain_0_0", true}, {"chain_0_1", true}}},
        BKexpParams {base::Broadcast::create("broadcast",
                                             {EasyExp::chain("chain_0", {true, false}),
                                              EasyExp::chain("chain_1", {false, true})}),
                     {{"chain_1_0", false}, {"chain_1_1", true}, {"chain_0_0", true}, {"chain_0_1", false}}},
        // [4] Complex: Broadcast of implication
        BKexpParams {base::Broadcast::create("broadcast",
                                             {EasyExp::implication("implication_0", true, true),
                                              EasyExp::implication("implication_1", true, true)}),
                     {{"implication_1_cond", true},
                      {"implication_1_imp", true},
                      {"implication_0_cond", true},
                      {"implication_0_imp", true}}},
        BKexpParams {base::Broadcast::create("broadcast",
                                             {EasyExp::implication("implication_0", true, false),
                                              EasyExp::implication("implication_1", false, true)}),
                     {{"implication_1_cond", false}, {"implication_0_cond", true}, {"implication_0_imp", false}}},
        BKexpParams {base::Broadcast::create("broadcast",
                                             {EasyExp::implication("implication_0", false, true),
                                              EasyExp::implication("implication_1", true, false)}),
                     {{"implication_1_cond", true}, {"implication_1_imp", false}, {"implication_0_cond", false}}},
        BKexpParams {base::Broadcast::create("broadcast",
                                             {EasyExp::implication("implication_0", false, true),
                                              EasyExp::implication("implication_1", false, true)}),
                     {{"implication_1_cond", false}, {"implication_0_cond", false}}},
        // [3] Complex: Broadcast of or
        BKexpParams {base::Broadcast::create("broadcastXYZ",
                                             {EasyExp::or_("or_0", {true, true}), EasyExp::or_("or_1", {true, true})}),
                     {{"or_1_0", true}, {"or_0_0", true}}},
        BKexpParams {base::Broadcast::create(
                         "broadcast", {EasyExp::or_("or_0", {true, false}), EasyExp::or_("or_1", {false, true})}),
                     {{"or_1_0", false}, {"or_1_1", true}, {"or_0_0", true}}},
        BKexpParams {base::Broadcast::create(
                         "broadcast", {EasyExp::or_("or_0", {false, false}), EasyExp::or_("or_1", {false, false})}),
                     {{"or_1_0", false}, {"or_1_1", false}, {"or_0_0", false}, {"or_0_1", false}}},

        // [2] Complex: Broadcast of and
        BKexpParams {base::Broadcast::create(
                         "broadcast", {EasyExp::and_("and_0", {true, true}), EasyExp::and_("and_1", {true, true})}),
                     {{"and_1_0", true}, {"and_1_1", true}, {"and_0_0", true}, {"and_0_1", true}}},
        BKexpParams {base::Broadcast::create(
                         "broadcast", {EasyExp::and_("and_0", {false, false}), EasyExp::and_("and_1", {false, false})}),
                     {{"and_1_0", false}, {"and_0_0", false}}},
        /*********************************************** CHAIN TEST ***********************************************/
        // [3] Complex: Chain of broadcast
        BKexpParams {
            base::Chain::create("chain",
                                {EasyExp::broadcast("broadcast_0", {true, true}),
                                 EasyExp::broadcast("broadcast_1", {true, true})}),
            {{"broadcast_0_1", true}, {"broadcast_0_0", true}, {"broadcast_1_1", true}, {"broadcast_1_0", true}}},
        BKexpParams {
            base::Chain::create("chain",
                                {EasyExp::broadcast("broadcast_0", {false, false}),
                                 EasyExp::broadcast("broadcast_1", {false, false})}),
            {{"broadcast_0_1", false}, {"broadcast_0_0", false}, {"broadcast_1_1", false}, {"broadcast_1_0", false}}},
        BKexpParams {
            base::Chain::create("chain",
                                {EasyExp::broadcast("broadcast_0", {false, true}),
                                 EasyExp::broadcast("broadcast_1", {true, false})}),
            {{"broadcast_0_1", true}, {"broadcast_0_0", false}, {"broadcast_1_1", false}, {"broadcast_1_0", true}}},
        // [2] Complex: Chain of chain
        BKexpParams {base::Chain::create(
                         "chain", {EasyExp::chain("chain_0", {true, true}), EasyExp::chain("chain_1", {true, true})}),
                     {{"chain_0_0", true}, {"chain_0_1", true}, {"chain_1_0", true}, {"chain_1_1", true}}},
        BKexpParams {base::Chain::create(
                         "chain", {EasyExp::chain("chain_0", {true, false}), EasyExp::chain("chain_1", {false, true})}),
                     {{"chain_0_0", true}, {"chain_0_1", false}, {"chain_1_0", false}, {"chain_1_1", true}}},
        // [4] Complex: Chain of implication
        BKexpParams {base::Chain::create("chain",
                                         {EasyExp::implication("implication_0", true, true),
                                          EasyExp::implication("implication_1", true, true)}),
                     {{"implication_0_cond", true},
                      {"implication_0_imp", true},
                      {"implication_1_cond", true},
                      {"implication_1_imp", true}}},
        BKexpParams {base::Chain::create("chain",
                                         {EasyExp::implication("implication_0", true, false),
                                          EasyExp::implication("implication_1", true, false)}),
                     {{"implication_0_cond", true},
                      {"implication_0_imp", false},
                      {"implication_1_cond", true},
                      {"implication_1_imp", false}}},
        BKexpParams {base::Chain::create("chain",
                                         {EasyExp::implication("implication_0", false, true),
                                          EasyExp::implication("implication_1", true, false)}),
                     {{"implication_0_cond", false}, {"implication_1_cond", true}, {"implication_1_imp", false}}},
        BKexpParams {base::Chain::create("chain",
                                         {EasyExp::implication("implication_0", false, true),
                                          EasyExp::implication("implication_1", false, true)}),
                     {{"implication_0_cond", false}, {"implication_1_cond", false}}},
        // [3] Complex: Chain of or
        BKexpParams {
            base::Chain::create("chain", {EasyExp::or_("or_0", {true, true}), EasyExp::or_("or_1", {true, true})}),
            {{"or_0_0", true}, {"or_1_0", true}}},
        BKexpParams {
            base::Chain::create("chain", {EasyExp::or_("or_0", {true, false}), EasyExp::or_("or_1", {false, true})}),
            {{"or_0_0", true}, {"or_1_0", false}, {"or_1_1", true}}},
        BKexpParams {
            base::Chain::create("chain", {EasyExp::or_("or_0", {false, false}), EasyExp::or_("or_1", {false, false})}),
            {{"or_0_0", false}, {"or_0_1", false}, {"or_1_0", false}, {"or_1_1", false}}},
        // [2] Complex: Chain of and
        BKexpParams {
            base::Chain::create("chain", {EasyExp::and_("and_0", {true, true}), EasyExp::and_("and_1", {true, true})}),
            {{"and_0_0", true}, {"and_0_1", true}, {"and_1_0", true}, {"and_1_1", true}}},
        BKexpParams {base::Chain::create(
                         "chain", {EasyExp::and_("and_0", {false, false}), EasyExp::and_("and_1", {false, false})}),
                     {{"and_0_0", false}, {"and_1_0", false}}},
        /********************************************** IMPLICATION TEST **********************************************/
        // [2] Complex: Implication of broadcast - its always true
        BKexpParams {
            base::Implication::create("implication",
                                      EasyExp::broadcast("broadcast_0", {true, true}),
                                      EasyExp::broadcast("broadcast_1", {true, true})),
            {{"broadcast_0_1", true}, {"broadcast_0_0", true}, {"broadcast_1_1", true}, {"broadcast_1_0", true}}},
        BKexpParams {
            base::Implication::create("implication",
                                      EasyExp::broadcast("broadcast_0", {false, false}),
                                      EasyExp::broadcast("broadcast_1", {false, false})),
            {{"broadcast_0_1", false}, {"broadcast_0_0", false}, {"broadcast_1_1", false}, {"broadcast_1_0", false}}},
        // [] Implication of chain
        BKexpParams {base::Implication::create("implication",
                                               EasyExp::chain("chain_0", {true, true}),
                                               EasyExp::chain("chain_1", {true, true})),
                     {{"chain_0_0", true}, {"chain_0_1", true}, {"chain_1_0", true}, {"chain_1_1", true}}},
        BKexpParams {base::Implication::create("implication",
                                               EasyExp::chain("chain_0", {true, false}),
                                               EasyExp::chain("chain_1", {false, true})),
                     {{"chain_0_0", true}, {"chain_0_1", false}, {"chain_1_0", false}, {"chain_1_1", true}}},
        // [] Implication of implication - if the condition is true, the result is true independently of the result of
        // the implication
        BKexpParams {base::Implication::create("implication",
                                               EasyExp::implication("implication_0", true, true),
                                               EasyExp::implication("implication_1", true, true)),
                     {{"implication_0_cond", true},
                      {"implication_0_imp", true},
                      {"implication_1_cond", true},
                      {"implication_1_imp", true}}},
        BKexpParams {base::Implication::create("implication",
                                               EasyExp::implication("implication_0", true, false),
                                               EasyExp::implication("implication_1", true, false)),
                     {{"implication_0_cond", true},
                      {"implication_0_imp", false},
                      {"implication_1_cond", true},
                      {"implication_1_imp", false}}},
        BKexpParams {base::Implication::create("implication",
                                               EasyExp::implication("implication_0", false, true),
                                               EasyExp::implication("implication_1", true, false)),
                     {{"implication_0_cond", false}}},
        BKexpParams {base::Implication::create("implication",
                                               EasyExp::implication("implication_0", false, true),
                                               EasyExp::term("term", true)),
                     {{"implication_0_cond", false}}},
        BKexpParams {base::Implication::create(
                         "implication", EasyExp::implication("implication_0", true, true), EasyExp::term("term", true)),
                     {{"implication_0_cond", true}, {"implication_0_imp", true}, {"term", true}}},
        BKexpParams {base::Implication::create("implication",
                                               EasyExp::term("term", true),
                                               EasyExp::implication("implication_0", false, true)),
                     {{"term", true}, {"implication_0_cond", false}}},
        BKexpParams {base::Implication::create("implication",
                                               EasyExp::term("term", false),
                                               EasyExp::implication("implication_0", false, true)),
                     {{"term", false}}},
        // Implication of or
        BKexpParams {base::Implication::create(
                         "implication", EasyExp::or_("or_0", {true, true}), EasyExp::or_("or_1", {true, true})),
                     {{"or_0_0", true}, {"or_1_0", true}}},
        BKexpParams {base::Implication::create(
                         "implication", EasyExp::or_("or_0", {true, false}), EasyExp::or_("or_1", {false, true})),
                     {{"or_0_0", true}, {"or_1_0", false}, {"or_1_1", true}}},
        BKexpParams {base::Implication::create(
                         "implication", EasyExp::or_("or_0", {false, false}), EasyExp::or_("or_1", {false, false})),
                     {{"or_0_0", false}, {"or_0_1", false}}},
        // Implication of and
        BKexpParams {base::Implication::create(
                         "implication", EasyExp::and_("and_0", {true, true}), EasyExp::and_("and_1", {true, true})),
                     {{"and_0_0", true}, {"and_0_1", true}, {"and_1_0", true}, {"and_1_1", true}}},
        BKexpParams {base::Implication::create(
                         "implication", EasyExp::and_("and_0", {false, false}), EasyExp::and_("and_1", {false, false})),
                     {{"and_0_0", false}}},
        BKexpParams {base::Implication::create(
                         "implication", EasyExp::and_("and_0", {true, true}), EasyExp::and_("and_1", {false, false})),
                     {{"and_0_0", true}, {"and_0_1", true}, {"and_1_0", false}}},
        /********************************************** OR TEST **********************************************/
        // [2] Complex: Or of broadcast
        BKexpParams {base::Or::create("or",
                                      {EasyExp::broadcast("broadcast_0", {true, true}),
                                       EasyExp::broadcast("broadcast_1", {true, true})}),
                     {{"broadcast_0_1", true}, {"broadcast_0_0", true}}},
        BKexpParams {base::Or::create("or",
                                      {EasyExp::broadcast("broadcast_0", {false, false}),
                                       EasyExp::broadcast("broadcast_1", {false, false})}),
                     {{"broadcast_0_1", false}, {"broadcast_0_0", false}}},
        // [2] Complex: Or of chain
        BKexpParams {
            base::Or::create("or", {EasyExp::chain("chain_0", {true, true}), EasyExp::chain("chain_1", {true, true})}),
            {{"chain_0_0", true}, {"chain_0_1", true}}},
        BKexpParams {base::Or::create(
                         "or", {EasyExp::chain("chain_0", {true, false}), EasyExp::chain("chain_1", {false, true})}),
                     {{"chain_0_0", true}, {"chain_0_1", false}}},
        // [4] Complex: Or of implication
        BKexpParams {base::Or::create("or",
                                      {EasyExp::implication("implication_0", true, true),
                                       EasyExp::implication("implication_1", true, true)}),
                     {{"implication_0_cond", true}, {"implication_0_imp", true}}},
        BKexpParams {base::Or::create("or",
                                      {EasyExp::implication("implication_0", true, false),
                                       EasyExp::implication("implication_1", true, false)}),
                     {{"implication_0_cond", true}, {"implication_0_imp", false}}},
        BKexpParams {base::Or::create("or",
                                      {EasyExp::implication("implication_0", false, true),
                                       EasyExp::implication("implication_1", true, false)}),
                     {{"implication_0_cond", false}, {"implication_1_cond", true}, {"implication_1_imp", false}}},
        BKexpParams {base::Or::create("or",
                                      {EasyExp::implication("implication_0", false, true),
                                       EasyExp::implication("implication_1", false, true)}),
                     {{"implication_0_cond", false}, {"implication_1_cond", false}}},
        // [3] Complex: Or of or
        BKexpParams {base::Or::create("or", {EasyExp::or_("or_0", {true, true}), EasyExp::or_("or_1", {true, true})}),
                     {{"or_0_0", true}}},
        BKexpParams {
            base::Or::create("or", {EasyExp::or_("or_0", {false, false}), EasyExp::or_("or_1", {false, true})}),
            {{"or_0_0", false}, {"or_0_1", false}, {"or_1_0", false}, {"or_1_1", true}}},
        BKexpParams {
            base::Or::create("or", {EasyExp::or_("or_0", {false, false}), EasyExp::or_("or_1", {false, false})}),
            {{"or_0_0", false}, {"or_0_1", false}, {"or_1_0", false}, {"or_1_1", false}}},
        BKexpParams {
            base::Or::create("or", {EasyExp::or_("or_0", {false, false}), EasyExp::or_("or_1", {true, false})}),
            {{"or_0_0", false}, {"or_0_1", false}, {"or_1_0", true}}},
        // [2] Complex: Or of and
        BKexpParams {
            base::Or::create("or", {EasyExp::and_("and_0", {true, true}), EasyExp::and_("and_1", {true, true})}),
            {{"and_0_0", true}, {"and_0_1", true}}},
        BKexpParams {
            base::Or::create("or", {EasyExp::and_("and_0", {false, false}), EasyExp::and_("and_1", {false, false})}),
            {{"and_0_0", false}, {"and_1_0", false}}},
        BKexpParams {
            base::Or::create("or", {EasyExp::and_("and_0", {true, true}), EasyExp::and_("and_1", {false, false})}),
            {{"and_0_0", true}, {"and_0_1", true}}},
        BKexpParams {
            base::Or::create("or", {EasyExp::and_("and_0", {false, false}), EasyExp::and_("and_1", {true, false})}),
            {{"and_0_0", false}, {"and_1_0", true}, {"and_1_1", false}}},
        /********************************************** AND TEST **********************************************/
        // [2] Complex: And of broadcast
        BKexpParams {
            base::And::create("and",
                              {EasyExp::broadcast("broadcast_0", {true, true}),
                               EasyExp::broadcast("broadcast_1", {true, true})}),
            {{"broadcast_0_1", true}, {"broadcast_0_0", true}, {"broadcast_1_1", true}, {"broadcast_1_0", true}}},
        BKexpParams {
            base::And::create("and",
                              {EasyExp::broadcast("broadcast_0", {false, false}),
                               EasyExp::broadcast("broadcast_1", {false, false})}),
            {{"broadcast_0_1", false}, {"broadcast_0_0", false}, {"broadcast_1_1", false}, {"broadcast_1_0", false}}},
        // [2] Complex: And of chain
        BKexpParams {base::And::create(
                         "and", {EasyExp::chain("chain_0", {true, true}), EasyExp::chain("chain_1", {true, true})}),
                     {{"chain_0_0", true}, {"chain_0_1", true}, {"chain_1_0", true}, {"chain_1_1", true}}},
        BKexpParams {base::And::create(
                         "and", {EasyExp::chain("chain_0", {true, false}), EasyExp::chain("chain_1", {false, true})}),
                     {{"chain_0_0", true}, {"chain_0_1", false}, {"chain_1_0", false}, {"chain_1_1", true}}},
        // [4] Complex: And of implication
        BKexpParams {base::And::create("and",
                                       {EasyExp::implication("implication_0", true, true),
                                        EasyExp::implication("implication_1", true, true)}),
                     {{"implication_0_cond", true},
                      {"implication_0_imp", true},
                      {"implication_1_cond", true},
                      {"implication_1_imp", true}}},
        BKexpParams {base::And::create("and",
                                       {EasyExp::implication("implication_0", true, false),
                                        EasyExp::implication("implication_1", true, false)}),
                     {{"implication_0_cond", true},
                      {"implication_0_imp", false},
                      {"implication_1_cond", true},
                      {"implication_1_imp", false}}},
        BKexpParams {base::And::create("and",
                                       {EasyExp::implication("implication_0", false, true),
                                        EasyExp::implication("implication_1", true, false)}),
                     {{"implication_0_cond", false}}},
        BKexpParams {base::And::create("and",
                                       {EasyExp::implication("implication_0", true, true),
                                        EasyExp::implication("implication_1", false, true)}),
                     {{"implication_0_cond", true}, {"implication_0_imp", true}, {"implication_1_cond", false}}},
        BKexpParams {base::And::create("and",
                                       {EasyExp::implication("implication_0", false, true),
                                        EasyExp::implication("implication_1", false, true)}),
                     {{"implication_0_cond", false}}},
        // [3] Complex: And of or
        BKexpParams {base::And::create("and", {EasyExp::or_("or_0", {true, true}), EasyExp::or_("or_1", {true, true})}),
                     {{"or_0_0", true}, {"or_1_0", true}}},
        BKexpParams {
            base::And::create("and", {EasyExp::or_("or_0", {false, true}), EasyExp::or_("or_1", {false, true})}),
            {{"or_0_0", false}, {"or_0_1", true}, {"or_1_0", false}, {"or_1_1", true}}},
        BKexpParams {
            base::And::create("and", {EasyExp::or_("or_0", {false, false}), EasyExp::or_("or_1", {false, false})}),
            {{"or_0_0", false}, {"or_0_1", false}}},
        // [2] Complex: And of and
        BKexpParams {
            base::And::create("and", {EasyExp::and_("and_0", {true, true}), EasyExp::and_("and_1", {true, true})}),
            {{"and_0_0", true}, {"and_0_1", true}, {"and_1_0", true}, {"and_1_1", true}}},
        BKexpParams {
            base::And::create("and", {EasyExp::and_("and_0", {false, false}), EasyExp::and_("and_1", {false, false})}),
            {{"and_0_0", false}}},
        BKexpParams {
            base::And::create("and", {EasyExp::and_("and_0", {true, true}), EasyExp::and_("and_1", {false, false})}),
            {{"and_0_0", true}, {"and_0_1", true}, {"and_1_0", false}}} // End
        ));

struct Subscriber
{
    std::vector<std::string> traces;
    auto getSubscriber()
    {
        return [&](auto trace, bool)
        {
            traces.emplace_back(trace);
        };
    }

    void checkTraceActivation(Controller& controller, const std::vector<std::string>& expected)
    {
        auto event = std::make_shared<json::Json>();
        ASSERT_NO_THROW(controller.ingest(std::move(event)));
        ASSERT_EQ(traces, expected);
    }
};

TEST(BKTaskFlowTraceTest, Subscribe)
{
    Controller c(FakePolicy {EasyExp::term("term", true), {"term"}});
    Subscriber s;
    auto subRes = c.subscribe("term", s.getSubscriber());
    ASSERT_FALSE(base::isError(subRes)) << "Error subscribing: " << base::getError(subRes).message;
    s.checkTraceActivation(c, {SUCCES_TRACE});
}

TEST(BKTaskFlowTraceTest, SubscribeTraceableNotFound)
{
    Controller c(FakePolicy {EasyExp::term("term", true), {"term"}});
    Subscriber s;
    auto subRes = c.subscribe("term2", s.getSubscriber());
    ASSERT_TRUE(base::isError(subRes));
    s.checkTraceActivation(c, {});
}

TEST(BKTaskFlowTraceTest, MultipleSubscribers)
{
    Controller c(FakePolicy {EasyExp::term("term", true), {"term"}});
    Subscriber s;
    auto subRes = c.subscribe("term", s.getSubscriber());
    ASSERT_FALSE(base::isError(subRes)) << "Error subscribing: " << base::getError(subRes).message;
    auto subRes2 = c.subscribe("term", s.getSubscriber());
    ASSERT_FALSE(base::isError(subRes2)) << "Error subscribing: " << base::getError(subRes2).message;
    s.checkTraceActivation(c, {SUCCES_TRACE, SUCCES_TRACE});
}

TEST(BKTaskFlowTraceTest, Unsubscribe)
{
    Controller c(FakePolicy {EasyExp::term("term", true), {"term"}});
    Subscriber s;
    auto subRes = c.subscribe("term", s.getSubscriber());
    ASSERT_FALSE(base::isError(subRes)) << "Error subscribing: " << base::getError(subRes).message;
    ASSERT_NO_THROW(c.unsubscribe("term", base::getResponse<bk::Subscription>(subRes)));
    s.checkTraceActivation(c, {});
}

TEST(BKTaskFlowTraceTest, UnsubscribeNotExists)
{
    Controller c(FakePolicy {EasyExp::term("term", true), {"term"}});
    Subscriber s;
    auto subRes = c.subscribe("term", s.getSubscriber());
    ASSERT_FALSE(base::isError(subRes)) << "Error subscribing: " << base::getError(subRes).message;
    ASSERT_NO_THROW(c.unsubscribe("term", base::getResponse<bk::Subscription>(subRes)));
    ASSERT_NO_THROW(c.unsubscribe("term", base::getResponse<bk::Subscription>(subRes)));
    ASSERT_NO_THROW(c.unsubscribe("other", base::getResponse<bk::Subscription>(subRes)));
    s.checkTraceActivation(c, {});
}
