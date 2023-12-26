#ifndef _BUILDER_BUILDERS_ARGUMENT_HPP
#define _BUILDER_BUILDERS_ARGUMENT_HPP

#include <memory>
#include <string>

#include <json/json.hpp>

#include "syntax.hpp"

namespace builder::builders
{

class Reference;
class Value;

class Argument : public std::enable_shared_from_this<Argument>
{
public:
    virtual ~Argument() = default;
    virtual bool isReference() const { return false; }
    virtual bool isValue() const { return false; }
    virtual std::string str() const { return ""; }

protected:
    Argument() = default;
};

class Reference : public Argument
{
private:
    std::string m_dotPath;
    std::string m_jsonPath;

public:
    Reference() = default;

    void set(const std::string& dotPath)
    {
        m_dotPath = dotPath;
        m_jsonPath = json::Json::formatJsonPath(dotPath);
    }

    explicit Reference(const std::string& dotPath) { set(dotPath); }

    const std::string& dotPath() const { return m_dotPath; }
    const std::string& jsonPath() const { return m_jsonPath; }

    bool isReference() const override { return true; }
    std::string str() const override { return std::string {syntax::field::REF_ANCHOR} + m_dotPath; }
};

class Value : public Argument
{
private:
    json::Json m_value;

public:
    Value() = default;

    void set(const json::Json& value)
    {
        auto tmp = json::Json(value);
        m_value = std::move(tmp);
    }

    explicit Value(const json::Json& value) { set(value); }

    const json::Json& value() const { return m_value; }

    bool isValue() const override { return true; }
    std::string str() const override { return m_value.str(); }
};

using OpArg = std::shared_ptr<Argument>;

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_ARGUMENT_HPP
