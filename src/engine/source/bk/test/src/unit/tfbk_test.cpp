#include <gtest/gtest.h>

#include <tfbk/tfbk.hpp>

static int counter = 0;

auto getFakeTerm(const std::string& name, bool success) -> std::shared_ptr<base::Term<base::EngineOp>>
{

    return base::Term<base::EngineOp>::create(name,
                                              [success](const auto& e)
                                              {
                                                  std::string path {"/test_"};
                                                  path += std::to_string(++counter);
                                                  e->setString("holis", path);
                                                  if (success)
                                                  {
                                                      return base::result::makeSuccess(e, "Fake trace success");
                                                  }
                                                  return base::result::makeFailure(e, "Fake trace failure");
                                              });
}

// Test protected methods
class TfBkMethodTest : public tfbk::TfBk<std::shared_ptr<json::Json>>
{
};

TEST(TfBkTest, MethodTest_termExecution)
{
    GTEST_SKIP();
    TfBkMethodTest tfbk;
    auto expr = getFakeTerm("term", true);
    auto event = std::make_shared<json::Json>();
    tfbk.build(expr);
    tfbk.ingest(std::move(event));

    std::cout << tfbk.getEvent().getData()->prettyStr() << std::endl;

    for (auto& trace : tfbk.getEvent().getTraces())
    {
        std::cout << "Trace: " << trace << std::endl;
    }
}

TEST(TfBkTest, MethodTest_broadcasExecution)
{
    TfBkMethodTest tfbk;
    //GTEST_SKIP();

    auto expr = base::Broadcast::create("broadcast", {});
    {
        auto& broadcastExpr = expr->getOperands();
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
}