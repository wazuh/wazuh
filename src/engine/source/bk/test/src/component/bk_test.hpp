#ifndef _BK_TEST_HPP
#define _BK_TEST_HPP

#include <gtest/gtest.h>

#include <base/expression.hpp>
#include <fmt/format.h>
#include <base/utils/stringUtils.hpp>

namespace bk::test
{
inline base::Expression getTestExpression(const base::Expression& expression,
                                          const std::vector<std::string>& pathParts = {})
{
    auto testExpression = expression;
    if (testExpression->isTerm())
    {
        auto fullName = testExpression->getName();
        auto parts = base::utils::string::split(fullName, ':');

        if (parts.size() != 2)
        {
            throw std::runtime_error {
                fmt::format("Expected term name to be in the form <NAME:SUCCESS|FAILURE> but got {}", fullName)};
        }

        auto name = parts[0];
        auto value = parts[1] == "SUCCESS";

        auto path = base::utils::string::join(pathParts, "/", true);
        path += std::string("/") + name;

        // Generate the function
        auto fn = [path, value, pathParts](const base::Event& event)
        {
            event->setBool(value, path);

            if (value)
            {
                return base::result::makeSuccess(event);
            }

            return base::result::makeFailure(event);
        };

        testExpression->getPtr<base::Term<base::EngineOp>>()->setFn(fn);
    }
    else
    {
        auto op = testExpression->getPtr<base::Operation>();
        auto nestedPathParts = pathParts;
        nestedPathParts.emplace_back(op->getName());
        for (const auto& child : op->getOperands())
        {
            getTestExpression(child, nestedPathParts);
        }
    }

    return testExpression;
}

class Step : public std::enable_shared_from_this<Step>
{
protected:
    std::string m_name;

    Step(const std::string& name)
        : m_name(std::string("/") + name)
    {
    }

public:
    virtual ~Step() = default;
    virtual bool isTerm() const = 0;
    virtual bool isOperation() const = 0;
    virtual bool isOrdered() const = 0;
    virtual void check(const json::Json& data) const = 0;

    std::string name() const { return m_name; }
};

class TermStep final : public Step
{
private:
    bool m_value;

public:
    TermStep(const std::string& name, bool value)
        : Step(name)
        , m_value(value)
    {
    }

    bool isTerm() const override { return true; }

    bool isOperation() const override { return false; }

    bool isOrdered() const override { throw std::runtime_error("TermStep has no order"); }

    void check(const json::Json& data) const override
    {
        ASSERT_TRUE(data.isObject());
        ASSERT_TRUE(data.exists(m_name)) << fmt::format("Expected {} to exist but got:\n{}", m_name, data.prettyStr());
        ASSERT_TRUE(data.isBool(m_name)) << fmt::format(
            "Expected {} to be a term but got:\n{}", m_name, data.prettyStr());
        ASSERT_EQ(data.getBool(m_name).value(), m_value)
            << fmt::format("Expected {} to be {} but got:\n{}", m_name, m_value, data.prettyStr());
    }
};

class OperationStep : public Step
{
private:
    std::vector<std::shared_ptr<Step>> m_steps;
    bool m_ordered;

public:
    template<typename... Steps>
    OperationStep(const std::string& name, bool ordered, Steps&&... steps)
        : Step(name)
        , m_ordered(ordered)
    {
        (
            [&]
            {
                m_steps.emplace_back(steps);
            }(),
            ...);
    }

    bool isTerm() const override { return false; }

    bool isOperation() const override { return true; }

    bool isOrdered() const override { return m_ordered; }

    void check(const json::Json& data) const override
    {
        ASSERT_TRUE(data.isObject());
        ASSERT_TRUE(data.exists(m_name)) << fmt::format("Expected {} to exist but got:\n{}", m_name, data.prettyStr());
        ASSERT_TRUE(data.isObject(m_name)) << fmt::format(
            "Expected {} to be an object but got:\n{}", m_name, data.prettyStr());
        ASSERT_EQ(data.size(m_name), m_steps.size())
            << fmt::format("Expected {} to have {} items but got:\n{}", m_name, m_steps.size(), data.prettyStr());

        if (m_ordered)
        {
            auto asObject = data.getObject(m_name).value();
            auto i = 0;
            for (const auto& step : m_steps)
            {
                auto [key, value] = asObject[i++];
                json::Json nextData{};
                auto path = std::string("/") + key;
                nextData.set(path, value);
                step->check(nextData);
            }
        }
        else
        {
            auto nextData = data.getJson(m_name).value();
            for (const auto& step : m_steps)
            {
                step->check(nextData);
            }
        }
    }
};

[[nodiscard]] inline std::shared_ptr<TermStep> term(const std::string& name, bool value)
{
    return std::make_shared<TermStep>(name, value);
}

template<typename... Steps>
[[nodiscard]] inline std::shared_ptr<OperationStep> order(const std::string& name, Steps&&... steps)
{
    return std::make_shared<OperationStep>(name, true, steps...);
}

template<typename... Steps>
[[nodiscard]] inline std::shared_ptr<OperationStep> unord(const std::string& name, Steps&&... steps)
{
    return std::make_shared<OperationStep>(name, false, steps...);
}

class Path
{
private:
    std::shared_ptr<Step> m_root;

public:
    Path() = default;

    Path(std::shared_ptr<Step> root)
        : m_root(root)
    {
    }

    void check(base::Event event) const { m_root->check(*event); }
};

namespace build
{
base::Expression term(const std::string& name, bool success)
{
    auto fullName = name + ":" + (success ? "SUCCESS" : "FAILURE");
    return base::Term<base::EngineOp>::create(fullName, nullptr);
}
} // namespace build

} // namespace bk::test

#endif // _BK_TEST_HPP
