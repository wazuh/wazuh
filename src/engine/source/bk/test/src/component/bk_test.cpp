#include <gtest/gtest.h>

#include <bk/rx/controller.hpp>
#include <bk/taskf/controller.hpp>
#include <bk/mockController.hpp> // Force mock compilation

#include "bk_test.hpp"

using namespace bk::test;
using namespace base;

const std::string PATH_NAME = "/name";
const std::string PATH_RESULT = "/result";

static const std::string SUCCES_TRACE = "Fake trace success";
static const std::string FAILURE_TRACE = "Fake trace failure";

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

    // Cast operator to base::Expression
    operator base::Expression() const { return m_expression; }
};

using PipelineParams = std::tuple<std::string, base::Expression, Path>;
class PipelineTest : public ::testing::TestWithParam<PipelineParams>
{
};

template<typename BackEnd>
inline void buildIngestTest(const base::Expression& expression, const Path& expected)
{
    auto counter = 0;
    auto controller = BackEnd(expression, {}, [&]() { ++counter; });
    auto event = std::make_shared<json::Json>();
    ASSERT_NO_THROW(event = controller.ingestGet(std::move(event)));

    ASSERT_EQ(counter, 1) << "Only one event was sent but the end callback received more than one event";

    expected.check(event);
}

TEST_P(PipelineTest, TfProcessEvent)
{
    auto [name, expression, expectedPath] = GetParam();
    auto testExpression = getTestExpression(expression);
    buildIngestTest<bk::taskf::Controller>(testExpression, expectedPath);
}

TEST_P(PipelineTest, TfProcessTraces)
{
    GTEST_SKIP(); // TODO
}

TEST_P(PipelineTest, RxProessEvent)
{
    auto [name, expression, expectedPath] = GetParam();
    auto testExpression = getTestExpression(expression);
    buildIngestTest<bk::rx::Controller>(testExpression, expectedPath);
}

TEST_P(PipelineTest, RxProcessTraces)
{
    GTEST_SKIP(); // TODO
}

INSTANTIATE_TEST_SUITE_P(
    BK,
    PipelineTest,
    ::testing::Values(
        // Basic: Term
        PipelineParams {"Basic: Term", build::term("t", true), Path(term("t", true))},
        PipelineParams {"Basic: Term", build::term("t", false), Path(term("t", false))},
        // Basic: Broadcast
        PipelineParams {"Basic: Broadcast",
                        Broadcast::create("broadcast",
                                          {build::term("t0", true),
                                           build::term("t1", true),
                                           build::term("t2", true),
                                           build::term("t3", true),
                                           build::term("t4", true)}),
                        Path(unord("broadcast",
                                   term("t0", true),
                                   term("t1", true),
                                   term("t2", true),
                                   term("t3", true),
                                   term("t4", true)))},
        PipelineParams {"Basic: Broadcast",
                        Broadcast::create("broadcast",
                                          {build::term("t0", true),
                                           build::term("t1", true),
                                           build::term("t2", false),
                                           build::term("t3", true),
                                           build::term("t4", true)}),
                        Path(unord("broadcast",
                                   term("t0", true),
                                   term("t1", true),
                                   term("t2", false),
                                   term("t3", true),
                                   term("t4", true)))},
        PipelineParams {"Basic: Broadcast",
                        Broadcast::create("broadcast",
                                          {build::term("t0", false),
                                           build::term("t1", false),
                                           build::term("t2", false),
                                           build::term("t3", false),
                                           build::term("t4", false)}),
                        Path(unord("broadcast",
                                   term("t0", false),
                                   term("t1", false),
                                   term("t2", false),
                                   term("t3", false),
                                   term("t4", false)))},
        PipelineParams {"Basic: Broadcast",
                        Broadcast::create("broadcast", {build::term("t0", false)}),
                        Path(unord("broadcast", term("t0", false)))},
        PipelineParams {"Basic: Broadcast",
                        Broadcast::create("broadcast", {build::term("t0", true)}),
                        Path(unord("broadcast", term("t0", true)))},
        // Basic: Chain
        PipelineParams {
            "Basic: Chain",
            Chain::create("chain",
                          {build::term("t0", true),
                           build::term("t1", true),
                           build::term("t2", true),
                           build::term("t3", true),
                           build::term("t4", true)}),
            Path(order(
                "chain", term("t0", true), term("t1", true), term("t2", true), term("t3", true), term("t4", true)))},
        PipelineParams {
            "Basic: Chain",
            Chain::create("chain",
                          {build::term("t0", true),
                           build::term("t1", true),
                           build::term("t2", false),
                           build::term("t3", true),
                           build::term("t4", true)}),
            Path(order(
                "chain", term("t0", true), term("t1", true), term("t2", false), term("t3", true), term("t4", true)))},
        PipelineParams {"Basic: Chain",
                        Chain::create("chain",
                                      {build::term("t0", false),
                                       build::term("t1", false),
                                       build::term("t2", false),
                                       build::term("t3", false),
                                       build::term("t4", false)}),
                        Path(order("chain",
                                   term("t0", false),
                                   term("t1", false),
                                   term("t2", false),
                                   term("t3", false),
                                   term("t4", false)))},
        PipelineParams {"Basic: Chain",
                        Chain::create("chain", {build::term("t0", false)}),
                        Path(order("chain", term("t0", false)))},
        PipelineParams {
            "Basic: Chain", Chain::create("chain", {build::term("t0", true)}), Path(order("chain", term("t0", true)))},
        // Basic: Implication
        PipelineParams {"Basic: Implication",
                        Implication::create("implication", build::term("cond", true), build::term("imp", true)),
                        Path(order("implication", term("cond", true), term("imp", true)))},
        PipelineParams {"Basic: Implication",
                        Implication::create("implication", build::term("cond", true), build::term("imp", false)),
                        Path(order("implication", term("cond", true), term("imp", false)))},
        PipelineParams {"Basic: Implication",
                        Implication::create("implication", build::term("cond", false), build::term("imp", true)),
                        Path(order("implication", term("cond", false)))},
        PipelineParams {"Basic: Implication",
                        Implication::create("implication", build::term("cond", false), build::term("imp", false)),
                        Path(order("implication", term("cond", false)))},
        // Basic: Or
        PipelineParams {"Basic: Or",
                        Or::create("or",
                                   {build::term("t0", true),
                                    build::term("t1", true),
                                    build::term("t2", true),
                                    build::term("t3", true),
                                    build::term("t4", true)}),
                        Path(order("or", term("t0", true)))},
        PipelineParams {"Basic: Or",
                        Or::create("or",
                                   {build::term("t0", false),
                                    build::term("t1", false),
                                    build::term("t2", true),
                                    build::term("t3", true),
                                    build::term("t4", true)}),
                        Path(order("or", term("t0", false), term("t1", false), term("t2", true)))},
        PipelineParams {
            "Basic: Or",
            Or::create("or",
                       {build::term("t0", false),
                        build::term("t1", false),
                        build::term("t2", false),
                        build::term("t3", false),
                        build::term("t4", false)}),
            Path(order(
                "or", term("t0", false), term("t1", false), term("t2", false), term("t3", false), term("t4", false)))},
        PipelineParams {
            "Basic: Or", Or::create("or", {build::term("t0", false)}), Path(order("or", term("t0", false)))},
        PipelineParams {"Basic: Or", Or::create("or", {build::term("t0", true)}), Path(order("or", term("t0", true)))},
        // Basic: And
        PipelineParams {
            "Basic: And",
            And::create("and",
                        {build::term("t0", true),
                         build::term("t1", true),
                         build::term("t2", true),
                         build::term("t3", true),
                         build::term("t4", true)}),
            Path(
                order(
                    "and", term("t0", true), term("t1", true), term("t2", true), term("t3", true), term("t4", true)))},
        PipelineParams {"Basic: And",
                        And::create("and",
                                    {build::term("t0", true),
                                     build::term("t1", true),
                                     build::term("t2", false),
                                     build::term("t3", true),
                                     build::term("t4", true)}),
                        Path(order("and", term("t0", true), term("t1", true), term("t2", false)))},
        PipelineParams {"Basic: And",
                        And::create("and",
                                    {build::term("t0", false),
                                     build::term("t1", false),
                                     build::term("t2", false),
                                     build::term("t3", false),
                                     build::term("t4", false)}),
                        Path(order("and", term("t0", false)))},
        PipelineParams {
            "Basic: And", And::create("and", {build::term("t0", false)}), Path(order("and", term("t0", false)))},
        PipelineParams {
            "Basic: And", And::create("and", {build::term("t0", true)}), Path(order("and", term("t0", true)))},
        /*********************************************** BROADCAST TEST ***********************************************/
        // Complex: Broadcast of broadcast
        PipelineParams {
            "Complex: Broadcast of broadcast",
            Broadcast::create("broadcast",
                              {Broadcast::create("broadcast_0", {build::term("t00", true), build::term("t01", true)}),
                               Broadcast::create("broadcast_1", {build::term("t10", true), build::term("t11", true)})}),
            Path(unord("broadcast",
                       unord("broadcast_0", term("t00", true), term("t01", true)),
                       unord("broadcast_1", term("t10", true), term("t11", true))))},
        PipelineParams {"Complex: Broadcast of broadcast",
                        Broadcast::create(
                            "broadcast",
                            {Broadcast::create("broadcast_0", {build::term("t00", true), build::term("t01", false)}),
                             Broadcast::create("broadcast_1", {build::term("t10", false), build::term("t11", true)})}),
                        Path(unord("broadcast",
                                   unord("broadcast_0", term("t00", true), term("t01", false)),
                                   unord("broadcast_1", term("t10", false), term("t11", true))))},
        // Complex: Broadcast of chain
        PipelineParams {
            "Complex: Broadcast of chain",
            Broadcast::create("broadcast",
                              {Chain::create("chain_0", {build::term("t00", true), build::term("t01", true)}),
                               Chain::create("chain_1", {build::term("t10", true), build::term("t11", true)})}),
            Path(unord("broadcast",
                       order("chain_0", term("t00", true), term("t01", true)),
                       order("chain_1", term("t10", true), term("t11", true))))},
        PipelineParams {
            "Complex: Broadcast of chain",
            Broadcast::create("broadcast",
                              {Chain::create("chain_0", {build::term("t00", true), build::term("t01", false)}),
                               Chain::create("chain_1", {build::term("t10", false), build::term("t11", true)})}),
            Path(unord("broadcast",
                       order("chain_0", term("t00", true), term("t01", false)),
                       order("chain_1", term("t10", false), term("t11", true))))},
        // Complex: Broadcast of implication
        PipelineParams {
            "Complex: Broadcast of implication",
            Broadcast::create(
                "broadcast",
                {Implication::create("implication_0", build::term("cond0", true), build::term("imp0", true)),
                 Implication::create("implication_1", build::term("cond1", true), build::term("imp1", true))}),
            Path(unord("broadcast",
                       order("implication_0", term("cond0", true), term("imp0", true)),
                       order("implication_1", term("cond1", true), term("imp1", true))))},
        PipelineParams {
            "Complex: Broadcast of implication",
            Broadcast::create(
                "broadcast",
                {Implication::create("implication_0", build::term("cond0", true), build::term("imp0", false)),
                 Implication::create("implication_1", build::term("cond1", false), build::term("imp1", true))}),
            Path(unord("broadcast",
                       order("implication_0", term("cond0", true), term("imp0", false)),
                       order("implication_1", term("cond1", false))))},
        PipelineParams {
            "Complex: Broadcast of implication",
            Broadcast::create(
                "broadcast",
                {Implication::create("implication_0", build::term("cond0", false), build::term("imp0", true)),
                 Implication::create("implication_1", build::term("cond1", true), build::term("imp1", false))}),
            Path(unord("broadcast",
                       order("implication_0", term("cond0", false)),
                       order("implication_1", term("cond1", true), term("imp1", false))))},
        PipelineParams {
            "Complex: Broadcast of implication",
            Broadcast::create(
                "broadcast",
                {Implication::create("implication_0", build::term("cond0", false), build::term("imp0", true)),
                 Implication::create("implication_1", build::term("cond1", false), build::term("imp1", true))}),
            Path(unord("broadcast",
                       order("implication_0", term("cond0", false)),
                       order("implication_1", term("cond1", false))))},
        // Complex: Broadcast of or
        PipelineParams {"Complex: Broadcast of or",
                        Broadcast::create("broadcast",
                                          {Or::create("or_0", {build::term("t00", true), build::term("t01", true)}),
                                           Or::create("or_1", {build::term("t10", true), build::term("t11", true)})}),
                        Path(unord("broadcast", order("or_0", term("t00", true)), order("or_1", term("t10", true))))},
        PipelineParams {"Complex: Broadcast of or",
                        Broadcast::create("broadcast",
                                          {Or::create("or_0", {build::term("t00", true), build::term("t01", false)}),
                                           Or::create("or_1", {build::term("t10", false), build::term("t11", true)})}),
                        Path(unord("broadcast",
                                   order("or_0", term("t00", true)),
                                   order("or_1", term("t10", false), term("t11", true))))},
        PipelineParams {"Complex: Broadcast of or",
                        Broadcast::create("broadcast",
                                          {Or::create("or_0", {build::term("t00", false), build::term("t01", false)}),
                                           Or::create("or_1", {build::term("t10", false), build::term("t11", false)})}),
                        Path(unord("broadcast",
                                   order("or_0", term("t00", false), term("t01", false)),
                                   order("or_1", term("t10", false), term("t11", false))))},
        // Complex: Broadcast of and
        PipelineParams {"Complex: Broadcast of and",
                        Broadcast::create("broadcast",
                                          {And::create("and_0", {build::term("t00", true), build::term("t01", true)}),
                                           And::create("and_1", {build::term("t10", true), build::term("t11", true)})}),
                        Path(unord("broadcast",
                                   order("and_0", term("t00", true), term("t01", true)),
                                   order("and_1", term("t10", true), term("t11", true))))},
        PipelineParams {
            "Complex: Broadcast of and",
            Broadcast::create("broadcast",
                              {And::create("and_0", {build::term("t00", true), build::term("t01", false)}),
                               And::create("and_1", {build::term("t10", false), build::term("t11", true)})}),
            Path(unord("broadcast",
                       order("and_0", term("t00", true), term("t01", false)),
                       order("and_1", term("t10", false))))},
        PipelineParams {
            "Complex: Broadcast of and",
            Broadcast::create("broadcast",
                              {And::create("and_0", {build::term("t00", false), build::term("t01", false)}),
                               And::create("and_1", {build::term("t10", false), build::term("t11", false)})}),
            Path(unord("broadcast", order("and_0", term("t00", false)), order("and_1", term("t10", false))))},
        /*********************************************** CHAIN TEST ***************************************************/
        // Complex: Chain of broadcast
        PipelineParams {
            "Complex: Chain of broadcast",
            Chain::create("chain",
                          {Broadcast::create("broadcast_0", {build::term("t00", true), build::term("t01", true)}),
                           Broadcast::create("broadcast_1", {build::term("t10", true), build::term("t11", true)})}),
            Path(order("chain",
                       unord("broadcast_0", term("t00", true), term("t01", true)),
                       unord("broadcast_1", term("t10", true), term("t11", true))))},
        PipelineParams {
            "Complex: Chain of broadcast",
            Chain::create("chain",
                          {Broadcast::create("broadcast_0", {build::term("t00", false), build::term("t01", false)}),
                           Broadcast::create("broadcast_1", {build::term("t10", false), build::term("t11", false)})}),
            Path(order("chain",
                       unord("broadcast_0", term("t00", false), term("t01", false)),
                       unord("broadcast_1", term("t10", false), term("t11", false))))},
        PipelineParams {
            "Complex: Chain of broadcast",
            Chain::create("chain",
                          {Broadcast::create("broadcast_0", {build::term("t00", true), build::term("t01", false)}),
                           Broadcast::create("broadcast_1", {build::term("t10", false), build::term("t11", true)})}),
            Path(order("chain",
                       unord("broadcast_0", term("t00", true), term("t01", false)),
                       unord("broadcast_1", term("t10", false), term("t11", true))))},
        // Complex: Chain of chain
        PipelineParams {"Complex: Chain of chain",
                        Chain::create("chain",
                                      {Chain::create("chain_0", {build::term("t00", true), build::term("t01", true)}),
                                       Chain::create("chain_1", {build::term("t10", true), build::term("t11", true)})}),
                        Path(order("chain",
                                   order("chain_0", term("t00", true), term("t01", true)),
                                   order("chain_1", term("t10", true), term("t11", true))))},
        PipelineParams {
            "Complex: Chain of chain",
            Chain::create("chain",
                          {Chain::create("chain_0", {build::term("t00", false), build::term("t01", false)}),
                           Chain::create("chain_1", {build::term("t10", false), build::term("t11", false)})}),
            Path(order("chain",
                       order("chain_0", term("t00", false), term("t01", false)),
                       order("chain_1", term("t10", false), term("t11", false))))},
        PipelineParams {
            "Complex: Chain of chain",
            Chain::create("chain",
                          {Chain::create("chain_0", {build::term("t00", true), build::term("t01", false)}),
                           Chain::create("chain_1", {build::term("t10", false), build::term("t11", true)})}),
            Path(order("chain",
                       order("chain_0", term("t00", true), term("t01", false)),
                       order("chain_1", term("t10", false), term("t11", true))))},
        // Complex: Chain of implication
        PipelineParams {
            "Complex: Chain of implication",
            Chain::create(
                "chain",
                {Implication::create("implication_0", build::term("cond0", true), build::term("imp0", true)),
                 Implication::create("implication_1", build::term("cond1", true), build::term("imp1", true))}),
            Path(order("chain",
                       order("implication_0", term("cond0", true), term("imp0", true)),
                       order("implication_1", term("cond1", true), term("imp1", true))))},
        PipelineParams {
            "Complex: Chain of implication",
            Chain::create(
                "chain",
                {Implication::create("implication_0", build::term("cond0", true), build::term("imp0", false)),
                 Implication::create("implication_1", build::term("cond1", true), build::term("imp1", false))}),
            Path(order("chain",
                       order("implication_0", term("cond0", true), term("imp0", false)),
                       order("implication_1", term("cond1", true), term("imp1", false))))},
        PipelineParams {
            "Complex: Chain of implication",
            Chain::create(
                "chain",
                {Implication::create("implication_0", build::term("cond0", false), build::term("imp0", false)),
                 Implication::create("implication_1", build::term("cond1", false), build::term("imp1", false))}),
            Path(order(
                "chain", order("implication_0", term("cond0", false)), order("implication_1", term("cond1", false))))},
        PipelineParams {
            "Complex: Chain of implication",
            Chain::create(
                "chain",
                {Implication::create("implication_0", build::term("cond0", true), build::term("imp0", false)),
                 Implication::create("implication_1", build::term("cond1", false), build::term("imp1", true))}),
            Path(order("chain",
                       order("implication_0", term("cond0", true), term("imp0", false)),
                       order("implication_1", term("cond1", false))))},
        // Complex: Chain of or
        PipelineParams {"Complex: Chain of or",
                        Chain::create("chain",
                                      {Or::create("or_0", {build::term("t00", true), build::term("t01", true)}),
                                       Or::create("or_1", {build::term("t10", true), build::term("t11", true)})}),
                        Path(order("chain", order("or_0", term("t00", true)), order("or_1", term("t10", true))))},
        PipelineParams {"Complex: Chain of or",
                        Chain::create("chain",
                                      {Or::create("or_0", {build::term("t00", true), build::term("t01", false)}),
                                       Or::create("or_1", {build::term("t10", false), build::term("t11", true)})}),
                        Path(order("chain",
                                   order("or_0", term("t00", true)),
                                   order("or_1", term("t10", false), term("t11", true))))},
        PipelineParams {"Complex: Chain of or",
                        Chain::create("chain",
                                      {Or::create("or_0", {build::term("t00", false), build::term("t01", false)}),
                                       Or::create("or_1", {build::term("t10", false), build::term("t11", false)})}),
                        Path(order("chain",
                                   order("or_0", term("t00", false), term("t01", false)),
                                   order("or_1", term("t10", false), term("t11", false))))},
        // Complex: Chain of and
        PipelineParams {"Complex: Chain of and",
                        Chain::create("chain",
                                      {And::create("and_0", {build::term("t00", true), build::term("t01", true)}),
                                       And::create("and_1", {build::term("t10", true), build::term("t11", true)})}),
                        Path(order("chain",
                                   order("and_0", term("t00", true), term("t01", true)),
                                   order("and_1", term("t10", true), term("t11", true))))},
        PipelineParams {"Complex: Chain of and",
                        Chain::create("chain",
                                      {And::create("and_0", {build::term("t00", true), build::term("t01", false)}),
                                       And::create("and_1", {build::term("t10", false), build::term("t11", true)})}),
                        Path(order("chain",
                                   order("and_0", term("t00", true), term("t01", false)),
                                   order("and_1", term("t10", false))))},
        PipelineParams {"Complex: Chain of and",
                        Chain::create("chain",
                                      {And::create("and_0", {build::term("t00", false), build::term("t01", false)}),
                                       And::create("and_1", {build::term("t10", false), build::term("t11", false)})}),
                        Path(order("chain", order("and_0", term("t00", false)), order("and_1", term("t10", false))))},
        /*********************************************** IMPLICATION TEST *********************************************/
        // Complex: Implication of broadcast
        // its always true
        PipelineParams {"Complex: Implication of broadcast",
                        Implication::create(
                            "implication",
                            Broadcast::create("broadcast_cond", {build::term("t00", true), build::term("t01", true)}),
                            Broadcast::create("broadcast_imp", {build::term("t10", true), build::term("t11", true)})),
                        Path(order("implication",
                                   unord("broadcast_cond", term("t00", true), term("t01", true)),
                                   unord("broadcast_imp", term("t10", true), term("t11", true))))},
        PipelineParams {"Complex: Implication of broadcast",
                        Implication::create(
                            "implication",
                            Broadcast::create("broadcast_cond", {build::term("t00", false), build::term("t01", false)}),
                            Broadcast::create("broadcast_imp", {build::term("t10", false), build::term("t11", false)})),
                        Path(order("implication",
                                   unord("broadcast_cond", term("t00", false), term("t01", false)),
                                   unord("broadcast_imp", term("t10", false), term("t11", false))))},
        // Complex: Implication of chain
        // its always true
        PipelineParams {
            "Complex: Implication of chain",
            Implication::create("implication",
                                Chain::create("chain_cond", {build::term("t00", true), build::term("t01", true)}),
                                Chain::create("chain_imp", {build::term("t10", true), build::term("t11", true)})),
            Path(order("implication",
                       order("chain_cond", term("t00", true), term("t01", true)),
                       order("chain_imp", term("t10", true), term("t11", true))))},
        PipelineParams {
            "Complex: Implication of chain",
            Implication::create("implication",
                                Chain::create("chain_cond", {build::term("t00", true), build::term("t01", false)}),
                                Chain::create("chain_imp", {build::term("t10", false), build::term("t11", true)})),
            Path(order("implication",
                       order("chain_cond", term("t00", true), term("t01", false)),
                       order("chain_imp", term("t10", false), term("t11", true))))},
        // Complex: Implication of implication
        // if the condition is true, the result is true independently of the
        // result of the implication
        PipelineParams {
            "Complex: Implication of implication",
            Implication::create(
                "implication",
                Implication::create("implication_cond", build::term("cond0", true), build::term("imp0", true)),
                Implication::create("implication_imp", build::term("cond1", true), build::term("imp1", true))),
            Path(order("implication",
                       order("implication_cond", term("cond0", true), term("imp0", true)),
                       order("implication_imp", term("cond1", true), term("imp1", true))))},
        PipelineParams {
            "Complex: Implication of implication",
            Implication::create(
                "implication",
                Implication::create("implication_cond", build::term("cond0", true), build::term("imp0", false)),
                Implication::create("implication_imp", build::term("cond1", true), build::term("imp1", false))),
            Path(order("implication",
                       order("implication_cond", term("cond0", true), term("imp0", false)),
                       order("implication_imp", term("cond1", true), term("imp1", false))))},
        PipelineParams {
            "Complex: Implication of implication",
            Implication::create(
                "implication",
                Implication::create("implication_cond", build::term("cond0", false), build::term("imp0", true)),
                Implication::create("implication_imp", build::term("cond1", true), build::term("imp1", false))),
            Path(order("implication", order("implication_cond", term("cond0", false))))},
        PipelineParams {
            "Complex: Implication of implication",
            Implication::create(
                "implication",
                Implication::create("implication_cond", build::term("cond0", false), build::term("imp0", true)),
                Implication::create("implication_imp", build::term("cond1", false), build::term("imp1", true))),
            Path(order("implication", order("implication_cond", term("cond0", false))))},
        // Complex: Implication of or
        PipelineParams {
            "Complex: Implication of or",
            Implication::create("implication",
                                Or::create("or_cond", {build::term("t00", true), build::term("t01", true)}),
                                Or::create("or_imp", {build::term("t10", true), build::term("t11", true)})),
            Path(order("implication", order("or_cond", term("t00", true)), order("or_imp", term("t10", true))))},
        PipelineParams {
            "Complex: Implication of or",
            Implication::create("implication",
                                Or::create("or_cond", {build::term("t00", true), build::term("t01", false)}),
                                Or::create("or_imp", {build::term("t10", false), build::term("t11", true)})),
            Path(order("implication",
                       order("or_cond", term("t00", true)),
                       order("or_imp", term("t10", false), term("t11", true))))},
        PipelineParams {
            "Complex: Implication of or",
            Implication::create("implication",
                                Or::create("or_cond", {build::term("t00", false), build::term("t01", false)}),
                                Or::create("or_imp", {build::term("t10", false), build::term("t11", false)})),
            Path(order("implication", order("or_cond", term("t00", false), term("t01", false))))},
        // Complex: Implication of and
        PipelineParams {
            "Complex: Implication of and",
            Implication::create("implication",
                                And::create("and_cond", {build::term("t00", true), build::term("t01", true)}),
                                And::create("and_imp", {build::term("t10", true), build::term("t11", true)})),
            Path(order("implication",
                       order("and_cond", term("t00", true), term("t01", true)),
                       order("and_imp", term("t10", true), term("t11", true))))},
        PipelineParams {
            "Complex: Implication of and",
            Implication::create("implication",
                                And::create("and_cond", {build::term("t00", true), build::term("t01", false)}),
                                And::create("and_imp", {build::term("t10", false), build::term("t11", true)})),
            Path(order("implication", order("and_cond", term("t00", true), term("t01", false))))},
        PipelineParams {
            "Complex: Implication of and",
            Implication::create("implication",
                                And::create("and_cond", {build::term("t00", false), build::term("t01", false)}),
                                And::create("and_imp", {build::term("t10", false), build::term("t11", false)})),
            Path(order("implication", order("and_cond", term("t00", false))))},
        /*********************************************** OR TEST ******************************************************/
        // Complex: Or of broadcast
        PipelineParams {
            "Complex: Or of broadcast",
            Or::create("or",
                       {Broadcast::create("broadcast_0", {build::term("t00", true), build::term("t01", true)}),
                        Broadcast::create("broadcast_1", {build::term("t10", true), build::term("t11", true)})}),
            Path(order("or", unord("broadcast_0", term("t00", true), term("t01", true))))},
        PipelineParams {
            "Complex: Or of broadcast",
            Or::create("or",
                       {Broadcast::create("broadcast_0", {build::term("t00", false), build::term("t01", false)}),
                        Broadcast::create("broadcast_1", {build::term("t10", false), build::term("t11", false)})}),
            Path(order("or", unord("broadcast_0", term("t00", false), term("t01", false))))},
        // Complex: Or of chain
        PipelineParams {"Complex: Or of chain",
                        Or::create("or",
                                   {Chain::create("chain_0", {build::term("t00", true), build::term("t01", true)}),
                                    Chain::create("chain_1", {build::term("t10", true), build::term("t11", true)})}),
                        Path(order("or", order("chain_0", term("t00", true), term("t01", true))))},
        PipelineParams {"Complex: Or of chain",
                        Or::create("or",
                                   {Chain::create("chain_0", {build::term("t00", false), build::term("t01", false)}),
                                    Chain::create("chain_1", {build::term("t10", false), build::term("t11", false)})}),
                        Path(order("or", order("chain_0", term("t00", false), term("t01", false))))},
        // Complex: Or of implication
        PipelineParams {
            "Complex: Or of implication",
            Or::create("or",
                       {Implication::create("implication_0", build::term("cond0", true), build::term("imp0", true)),
                        Implication::create("implication_1", build::term("cond1", true), build::term("imp1", true))}),
            Path(order("or", order("implication_0", term("cond0", true), term("imp0", true))))},
        PipelineParams {
            "Complex: Or of implication",
            Or::create("or",
                       {Implication::create("implication_0", build::term("cond0", true), build::term("imp0", false)),
                        Implication::create("implication_1", build::term("cond1", true), build::term("imp1", false))}),
            Path(order("or", order("implication_0", term("cond0", true), term("imp0", false))))},
        PipelineParams {
            "Complex: Or of implication",
            Or::create("or",
                       {Implication::create("implication_0", build::term("cond0", false), build::term("imp0", true)),
                        Implication::create("implication_1", build::term("cond1", true), build::term("imp1", false))}),
            Path(order("or",
                       order("implication_0", term("cond0", false)),
                       order("implication_1", term("cond1", true), term("imp1", false))))},
        PipelineParams {
            "Complex: Or of implication",
            Or::create("or",
                       {Implication::create("implication_0", build::term("cond0", false), build::term("imp0", false)),
                        Implication::create("implication_1", build::term("cond1", false), build::term("imp1", false))}),
            Path(order(
                "or", order("implication_0", term("cond0", false)), order("implication_1", term("cond1", false))))},
        PipelineParams {
            "Complex: Or of implication",
            Or::create("or",
                       {Implication::create("implication_0", build::term("cond0", false), build::term("imp0", false)),
                        Implication::create("implication_1", build::term("cond1", true), build::term("imp1", false))}),
            Path(order("or",
                       order("implication_0", term("cond0", false)),
                       order("implication_1", term("cond1", true), term("imp1", false))))},
        // Complex: Or of or
        PipelineParams {"Complex: Or of or",
                        Or::create("or",
                                   {Or::create("or_0", {build::term("t00", true), build::term("t01", true)}),
                                    Or::create("or_1", {build::term("t10", true), build::term("t11", true)})}),
                        Path(order("or", order("or_0", term("t00", true))))},
        PipelineParams {"Complex: Or of or",
                        Or::create("or",
                                   {Or::create("or_0", {build::term("t00", false), build::term("t01", false)}),
                                    Or::create("or_1", {build::term("t10", false), build::term("t11", true)})}),
                        Path(order("or",
                                   order("or_0", term("t00", false), term("t01", false)),
                                   order("or_1", term("t10", false), term("t11", true))))},
        PipelineParams {"Complex: Or of or",
                        Or::create("or",
                                   {Or::create("or_0", {build::term("t00", false), build::term("t01", false)}),
                                    Or::create("or_1", {build::term("t10", false), build::term("t11", false)})}),
                        Path(order("or",
                                   order("or_0", term("t00", false), term("t01", false)),
                                   order("or_1", term("t10", false), term("t11", false))))},
        PipelineParams {
            "Complex: Or of or",
            Or::create("or",
                       {Or::create("or_0", {build::term("t00", false), build::term("t01", false)}),
                        Or::create("or_1", {build::term("t10", true), build::term("t11", false)})}),
            Path(order("or", order("or_0", term("t00", false), term("t01", false)), order("or_1", term("t10", true))))},
        // Complex: Or of and
        PipelineParams {"Complex: Or of and",
                        Or::create("or",
                                   {And::create("and_0", {build::term("t00", true), build::term("t01", true)}),
                                    And::create("and_1", {build::term("t10", true), build::term("t11", true)})}),
                        Path(order("or", order("and_0", term("t00", true), term("t01", true))))},
        PipelineParams {"Complex: Or of and",
                        Or::create("or",
                                   {And::create("and_0", {build::term("t00", false), build::term("t01", false)}),
                                    And::create("and_1", {build::term("t10", false), build::term("t11", false)})}),
                        Path(order("or", order("and_0", term("t00", false)), order("and_1", term("t10", false))))},
        PipelineParams {"Complex: Or of and",
                        Or::create("or",
                                   {And::create("and_0", {build::term("t00", false), build::term("t01", false)}),
                                    And::create("and_1", {build::term("t10", false), build::term("t11", true)})}),
                        Path(order("or", order("and_0", term("t00", false)), order("and_1", term("t10", false))))},
        PipelineParams {"Complex: Or of and",
                        Or::create("or",
                                   {And::create("and_0", {build::term("t00", false), build::term("t01", false)}),
                                    And::create("and_1", {build::term("t10", true), build::term("t11", false)})}),
                        Path(order("or",
                                   order("and_0", term("t00", false)),
                                   order("and_1", term("t10", true), term("t11", false))))},
        PipelineParams {"Complex: Or of and",
                        Or::create("or",
                                   {And::create("and_0", {build::term("t00", false), build::term("t01", false)}),
                                    And::create("and_1", {build::term("t10", true), build::term("t11", true)})}),
                        Path(order("or",
                                   order("and_0", term("t00", false)),
                                   order("and_1", term("t10", true), term("t11", true))))},
        /********************************************** AND TEST ******************************************************/
        // Complex: And of broadcast
        PipelineParams {
            "Complex: And of broadcast",
            And::create("and",
                        {Broadcast::create("broadcast_0", {build::term("t00", true), build::term("t01", true)}),
                         Broadcast::create("broadcast_1", {build::term("t10", true), build::term("t11", true)})}),
            Path(order("and",
                       unord("broadcast_0", term("t00", true), term("t01", true)),
                       unord("broadcast_1", term("t10", true), term("t11", true))))},
        PipelineParams {
            "Complex: And of broadcast",
            And::create("and",
                        {Broadcast::create("broadcast_0", {build::term("t00", false), build::term("t01", false)}),
                         Broadcast::create("broadcast_1", {build::term("t10", false), build::term("t11", false)})}),
            Path(order("and",
                       unord("broadcast_0", term("t00", false), term("t01", false)),
                       unord("broadcast_1", term("t10", false), term("t11", false))))},
        // Complex: And of chain
        PipelineParams {"Complex: And of chain",
                        And::create("and",
                                    {Chain::create("chain_0", {build::term("t00", true), build::term("t01", true)}),
                                     Chain::create("chain_1", {build::term("t10", true), build::term("t11", true)})}),
                        Path(order("and",
                                   order("chain_0", term("t00", true), term("t01", true)),
                                   order("chain_1", term("t10", true), term("t11", true))))},
        PipelineParams {"Complex: And of chain",
                        And::create("and",
                                    {Chain::create("chain_0", {build::term("t00", true), build::term("t01", false)}),
                                     Chain::create("chain_1", {build::term("t10", false), build::term("t11", true)})}),
                        Path(order("and",
                                   order("chain_0", term("t00", true), term("t01", false)),
                                   order("chain_1", term("t10", false), term("t11", true))))},
        // Complex: And of implication
        PipelineParams {
            "Complex: And of implication",
            And::create("and",
                        {Implication::create("implication_0", build::term("cond0", true), build::term("imp0", true)),
                         Implication::create("implication_1", build::term("cond1", true), build::term("imp1", true))}),
            Path(order("and",
                       order("implication_0", term("cond0", true), term("imp0", true)),
                       order("implication_1", term("cond1", true), term("imp1", true))))},
        PipelineParams {
            "Complex: And of implication",
            And::create("and",
                        {Implication::create("implication_0", build::term("cond0", true), build::term("imp0", false)),
                         Implication::create("implication_1", build::term("cond1", true), build::term("imp1", false))}),
            Path(order("and",
                       order("implication_0", term("cond0", true), term("imp0", false)),
                       order("implication_1", term("cond1", true), term("imp1", false))))},
        PipelineParams {
            "Complex: And of implication",
            And::create("and",
                        {Implication::create("implication_0", build::term("cond0", false), build::term("imp0", true)),
                         Implication::create("implication_1", build::term("cond1", true), build::term("imp1", false))}),
            Path(order("and", order("implication_0", term("cond0", false))))},
        PipelineParams {
            "Complex: And of implication",
            And::create("and",
                        {Implication::create("implication_0", build::term("cond0", true), build::term("imp0", false)),
                         Implication::create("implication_1", build::term("cond1", false), build::term("imp1", true))}),
            Path(order("and",
                       order("implication_0", term("cond0", true), term("imp0", false)),
                       order("implication_1", term("cond1", false))))},
        PipelineParams {
            "Complex: And of implication",
            And::create(
                "and",
                {Implication::create("implication_0", build::term("cond0", false), build::term("imp0", false)),
                 Implication::create("implication_1", build::term("cond1", false), build::term("imp1", false))}),
            Path(order("and", order("implication_0", term("cond0", false))))},
        // Complex: And of or
        PipelineParams {"Complex: And of or",
                        And::create("and",
                                    {Or::create("or_0", {build::term("t00", true), build::term("t01", true)}),
                                     Or::create("or_1", {build::term("t10", true), build::term("t11", true)})}),
                        Path(order("and", order("or_0", term("t00", true)), order("or_1", term("t10", true))))},
        PipelineParams {"Complex: And of or",
                        And::create("and",
                                    {Or::create("or_0", {build::term("t00", false), build::term("t01", true)}),
                                     Or::create("or_1", {build::term("t10", false), build::term("t11", true)})}),
                        Path(order("and",
                                   order("or_0", term("t00", false), term("t01", true)),
                                   order("or_1", term("t10", false), term("t11", true))))},
        PipelineParams {"Complex: And of or",
                        And::create("and",
                                    {Or::create("or_0", {build::term("t00", false), build::term("t01", false)}),
                                     Or::create("or_1", {build::term("t10", false), build::term("t11", false)})}),
                        Path(order("and", order("or_0", term("t00", false), term("t01", false))))},
        // Complex: And of and
        PipelineParams {"Complex: And of and",
                        And::create("and",
                                    {And::create("and_0", {build::term("t00", true), build::term("t01", true)}),
                                     And::create("and_1", {build::term("t10", true), build::term("t11", true)})}),
                        Path(order("and",
                                   order("and_0", term("t00", true), term("t01", true)),
                                   order("and_1", term("t10", true), term("t11", true))))},
        PipelineParams {"Complex: And of and",
                        And::create("and",
                                    {And::create("and_0", {build::term("t00", false), build::term("t01", false)}),
                                     And::create("and_1", {build::term("t10", false), build::term("t11", false)})}),
                        Path(order("and", order("and_0", term("t00", false))))},
        PipelineParams {"Complex: And of and",
                        And::create("and",
                                    {And::create("and_0", {build::term("t00", true), build::term("t01", true)}),
                                     And::create("and_1", {build::term("t10", false), build::term("t11", false)})}),
                        Path(order("and",
                                   order("and_0", term("t00", true), term("t01", true)),
                                   order("and_1", term("t10", false))))}));

template <typename Controller>
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

template<typename Controller>
void subscribeTest()
{
    Controller c(EasyExp::term("term", true), {"term"});
    Subscriber<Controller> s;
    auto subRes = c.subscribe("term", s.getSubscriber());
    ASSERT_FALSE(base::isError(subRes)) << "Error subscribing: " << base::getError(subRes).message;
    s.checkTraceActivation(c, {SUCCES_TRACE});
}

TEST(BKTraceTest, Subscribe)
{
    subscribeTest<bk::taskf::Controller>();
    subscribeTest<bk::rx::Controller>();
}

template<typename Controller>
void subscribeTraceableNotFoundTest()
{
    Controller c(EasyExp::term("term", true), {"term"});
    Subscriber<Controller> s;
    auto subRes = c.subscribe("term2", s.getSubscriber());
    ASSERT_TRUE(base::isError(subRes));
    s.checkTraceActivation(c, {});
}

TEST(BKTraceTest, SubscribeTraceableNotFound)
{
    subscribeTraceableNotFoundTest<bk::taskf::Controller>();
    subscribeTraceableNotFoundTest<bk::rx::Controller>();
}

template<typename Controller>
void multipleSubscribersTest()
{
    Controller c(EasyExp::term("term", true), {"term"});
    Subscriber<Controller> s;
    auto subRes = c.subscribe("term", s.getSubscriber());
    ASSERT_FALSE(base::isError(subRes)) << "Error subscribing: " << base::getError(subRes).message;
    auto subRes2 = c.subscribe("term", s.getSubscriber());
    ASSERT_FALSE(base::isError(subRes2)) << "Error subscribing: " << base::getError(subRes2).message;
    s.checkTraceActivation(c, {SUCCES_TRACE, SUCCES_TRACE});
}

TEST(BKTraceTest, MultipleSubscribers)
{
    multipleSubscribersTest<bk::taskf::Controller>();
    multipleSubscribersTest<bk::rx::Controller>();
}

template<typename Controller>
void unsubscribeTest()
{
    Controller c(EasyExp::term("term", true), {"term"});
    Subscriber<Controller> s;
    auto subRes = c.subscribe("term", s.getSubscriber());
    ASSERT_FALSE(base::isError(subRes)) << "Error subscribing: " << base::getError(subRes).message;
    ASSERT_NO_THROW(c.unsubscribe("term", base::getResponse<bk::Subscription>(subRes)));
    s.checkTraceActivation(c, {});
}

TEST(BKTraceTest, Unsubscribe)
{
    unsubscribeTest<bk::taskf::Controller>();
    unsubscribeTest<bk::rx::Controller>();
}

template<typename Controller>
void unsubscribeNotExistsTest()
{
    Controller c(EasyExp::term("term", true), {"term"});
    Subscriber<Controller> s;
    auto subRes = c.subscribe("term", s.getSubscriber());
    ASSERT_FALSE(base::isError(subRes)) << "Error subscribing: " << base::getError(subRes).message;
    ASSERT_NO_THROW(c.unsubscribe("term", base::getResponse<bk::Subscription>(subRes)));
    ASSERT_NO_THROW(c.unsubscribe("term", base::getResponse<bk::Subscription>(subRes)));
    ASSERT_NO_THROW(c.unsubscribe("other", base::getResponse<bk::Subscription>(subRes)));
    s.checkTraceActivation(c, {});
}

TEST(BKTraceTest, UnsubscribeNotExists)
{
    unsubscribeNotExistsTest<bk::taskf::Controller>();
    unsubscribeNotExistsTest<bk::rx::Controller>();
}
