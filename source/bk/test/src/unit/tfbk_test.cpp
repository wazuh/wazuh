#include <gtest/gtest.h>

#include <bk/taskf/controller.hpp>

static int gs_term_ID = 0;
static int gs_op_counter = 0;

auto getFakeTerm(const std::string& name, bool success) -> std::shared_ptr<base::Term<base::EngineOp>>
{

    return base::Term<base::EngineOp>::create(name + "_" + std::to_string(++gs_term_ID),
                                              [success, tid = gs_term_ID](const auto& e)
                                              {
                                                  std::string path {"/info_"};
                                                  path += std::to_string(tid);
                                                  e->setInt(++gs_op_counter, path);
                                                  if (success)
                                                  {
                                                      return base::result::makeSuccess(e, "Fake trace success");
                                                  }
                                                  return base::result::makeFailure(e, "Fake trace failure");
                                              });
}

TEST(TF_Controller_build_Test, term)
{

    auto expr = getFakeTerm("term", true);
    auto event = std::make_shared<json::Json>();
    auto tfbk = bk::taskf::Controller(expr);
    event = tfbk.ingestGet(std::move(event));

    std::cout << event->prettyStr() << std::endl;
}

TEST(TfBkTest, MethodTest_broadcasExecution)
{
    // GTEST_SKIP();

    auto expr = base::Broadcast::create("broadcast", {});
    {
        auto& broadcastExpr = expr->getOperands();
        broadcastExpr.emplace_back(getFakeTerm("term1", true));
        broadcastExpr.emplace_back(getFakeTerm("term2", true));
        broadcastExpr.emplace_back(getFakeTerm("term3", false));
        broadcastExpr.emplace_back(getFakeTerm("term4", false));
        broadcastExpr.emplace_back(getFakeTerm("term5", true));
    }
    bk::taskf::Controller controller {expr};

    auto event = std::make_shared<json::Json>();

    std::cout << "Built taskflow" << std::endl;
    // std::cout << controller.print() << std::endl;

    auto e = controller.ingestGet(std::move(event));

    std::cout << e->prettyStr() << std::endl;
}
/*
TEST(TfBkTest, MethodTest_chainExecution)
{
    //GTEST_SKIP();

    TfBkMethodTest tfbk;

    auto expr = base::Chain::create("chain", {});
    {
        auto& broadcastExpr = expr->getOperands();
        broadcastExpr.emplace_back(getFakeTerm("term0", false));
        broadcastExpr.emplace_back(getFakeTerm("term1", true));
        broadcastExpr.emplace_back(getFakeTerm("term2", true));
        broadcastExpr.emplace_back(getFakeTerm("term3", false));
        broadcastExpr.emplace_back(getFakeTerm("term4", false));
        broadcastExpr.emplace_back(getFakeTerm("term5", true));
    }

    auto event = std::make_shared<json::Json>();
    tfbk.build(expr);

    std::cout << "Built taskflow" << std::endl;
    std::cout << tfbk.print() << std::endl;

    tfbk.ingest(std::move(event));

    std::cout << tfbk.getEvent().getData()->prettyStr() << std::endl;

    for (auto& trace : tfbk.getEvent().getTraces())
    {
        std::cout << "Trace: " << trace << std::endl;
    }
}


TEST(TfBkTest, MethodTest_implication)
{

    TfBkMethodTest tfbk;

    auto expr = base::Implication::create("implicationn", getFakeTerm("term0", false), getFakeTerm("term1", true));

    auto event = std::make_shared<json::Json>();
    tfbk.build(expr);

    std::cout << "Built taskflow" << std::endl;
    std::cout << tfbk.print() << std::endl;

    tfbk.ingest(std::move(event));

    std::cout << tfbk.getEvent().getData()->prettyStr() << std::endl;

    for (auto& trace : tfbk.getEvent().getTraces())
    {
        std::cout << "Trace: " << trace << std::endl;
    }
}

TEST(TfBkTest, MethodTest_or)
{
    TfBkMethodTest tfbk;

    auto expr = base::Or::create("or", {});

    {
        auto& orExpr = expr->getOperands();
        orExpr.emplace_back(getFakeTerm("term0", false));
        orExpr.emplace_back(getFakeTerm("term1", false));
        orExpr.emplace_back(getFakeTerm("term2", true));
        orExpr.emplace_back(getFakeTerm("term3", false));
        orExpr.emplace_back(getFakeTerm("term4", false));
        orExpr.emplace_back(getFakeTerm("term5", true));
    }

    auto event = std::make_shared<json::Json>();
    tfbk.build(expr);

    std::cout << "Built taskflow" << std::endl;
    std::cout << tfbk.print() << std::endl;

    tfbk.ingest(std::move(event));

    std::cout << tfbk.getEvent().getData()->prettyStr() << std::endl;

    for (auto& trace : tfbk.getEvent().getTraces())
    {
        std::cout << "Trace: " << trace << std::endl;
    }
}

TEST(TfBkTest, MethodTest_and)
{
    TfBkMethodTest tfbk;

    auto expr = base::And::create("and", {});

    {
        auto& andExpr = expr->getOperands();
        andExpr.emplace_back(getFakeTerm("term0", true));
        andExpr.emplace_back(getFakeTerm("term1", true));
        andExpr.emplace_back(getFakeTerm("term2", true));
        andExpr.emplace_back(getFakeTerm("term3", false));
        andExpr.emplace_back(getFakeTerm("term4", false));
        andExpr.emplace_back(getFakeTerm("term5", true));
    }

    auto event = std::make_shared<json::Json>();
    tfbk.build(expr);

    std::cout << "Built taskflow" << std::endl;
    std::cout << tfbk.print() << std::endl;

    tfbk.ingest(std::move(event));

    std::cout << tfbk.getEvent().getData()->prettyStr() << std::endl;

    for (auto& trace : tfbk.getEvent().getTraces())
    {
        std::cout << "Trace: " << trace << std::endl;
    }
}*/
