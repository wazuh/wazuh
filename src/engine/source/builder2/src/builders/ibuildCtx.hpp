#ifndef _BUILDER_BUILDERS_IBUILDCTX_HPP
#define _BUILDER_BUILDERS_IBUILDCTX_HPP

#include "iregistry.hpp"

#include <baseTypes.hpp>
#include <defs/idefinitions.hpp>
#include <expression.hpp>
#include <schemf/ischema.hpp>
#include <schemval/ivalidator.hpp>

#include "syntax.hpp"

namespace builder::builders
{

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

    Reference(const std::string& dotPath) { set(dotPath); }

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

    Value(const json::Json& value) { set(value); }

    const json::Json& value() const { return m_value; }

    bool isValue() const override { return true; }
    std::string str() const override { return m_value.str(); }
};

using OpArg = std::shared_ptr<Argument>;

class ValidationToken
{
public:
    ValidationToken() = default;
    virtual ~ValidationToken() = default;

    virtual bool needsRuntimeValidation() const { return true; }

    virtual bool isPartial() const { return false; }
    virtual json::Json::Type jType() const { throw std::runtime_error("Validation token does not have a type"); }

    virtual bool isFull() const { return false; }
    virtual bool hasType() const { return false; }
    virtual bool hasValue() const { return false; }
    virtual schemf::Type sType() const { throw std::runtime_error("Validation token does not have a type"); }
    virtual const json::Json& jValue() const { throw std::runtime_error("Validation token does not have a value"); }

    virtual bool isDynamic() const { return false; }
    virtual std::shared_ptr<ValidationToken> resolve(const std::vector<OpArg>& opArgs) const { return nullptr; }
};

class StaticPartial : public ValidationToken
{
private:
    json::Json::Type type;

public:
    StaticPartial(json::Json::Type type)
        : type(type)
    {
    }

    bool isPartial() const override { return true; }
    json::Json::Type jType() const override { return type; }
};

class StaticFull : public ValidationToken
{
private:
    schemf::Type type;

public:
    StaticFull(schemf::Type type)
        : type(type)
    {
    }

    bool isFull() const override { return true; }
    bool hasType() const override { return true; }
    schemf::Type sType() const override { return type; }
};

class StaticValueFull : public ValidationToken
{
private:
    json::Json value;

public:
    StaticValueFull(const json::Json& value)
        : value(value)
    {
    }

    bool isFull() const override { return true; }
    bool hasValue() const override { return true; }
    bool hasType() const override { return true; }
    json::Json::Type jType() const override { return value.type(); }
    const json::Json& jValue() const override { return value; }
};

class Dynamic : public ValidationToken
{
private:
    std::function<std::shared_ptr<ValidationToken>(const std::vector<OpArg>&)> resolver;

public:
    Dynamic(std::function<std::shared_ptr<ValidationToken>(const std::vector<OpArg>&)> resolver)
        : resolver(resolver)
    {
    }

    bool isDynamic() const override { return true; }
    std::shared_ptr<ValidationToken> resolve(const std::vector<OpArg>& opArgs) const override
    {
        return resolver(opArgs);
    }
};

class IBuildCtx;

using MapResult = base::result::Result<json::Json>;
using MapOp = std::function<MapResult(base::ConstEvent)>;
using MapBuilder = std::function<MapOp(const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&)>;

using TransformResult = base::result::Result<base::Event>;
using TransformOp = std::function<TransformResult(base::Event)>;
using TransformBuilder =
    std::function<TransformOp(const Reference&, const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&)>;

using FilterResult = base::result::Result<bool>;
using FilterOp = std::function<FilterResult(base::ConstEvent)>;
using FilterBuilder =
    std::function<FilterOp(const Reference&, const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&)>;

using Op = std::variant<MapOp, TransformOp, FilterOp>;
using OpBuilder = std::variant<MapBuilder, TransformBuilder, FilterBuilder>;
using OpBuilderEntry = std::tuple<std::shared_ptr<ValidationToken>, OpBuilder>;

using StageBuilder = std::function<base::Expression(const json::Json&, const std::shared_ptr<const IBuildCtx>&)>;

using RegistryType = MetaRegistry<OpBuilderEntry, StageBuilder>;

/**
 * @brief Control flags for the runtime
 *
 */
struct RunState
{
    bool trace;   // Active/Inactive trace messages
    bool sandbox; // Active/Inactive test mode
    bool check;   // Active/Inactive hard type enforcement mode
};

/**
 * @brief Context for the builder
 *
 */
struct Context
{
    std::string assetName;  // Name of the current asset being built
    std::string policyName; // Name of the current policy being built
    std::string stageName;  // Name of the current stage being built
    std::string opName;     // Name of the current operation being built
};

class IBuildCtx
{
public:
    virtual ~IBuildCtx() = default;
    virtual std::shared_ptr<IBuildCtx> clone() const = 0;

    virtual const defs::IDefinitions& definitions() const = 0;
    virtual void setDefinitions(const std::shared_ptr<defs::IDefinitions>& definitions) = 0;

    virtual const RegistryType& registry() const = 0;
    virtual void setRegistry(const std::shared_ptr<const RegistryType>& registry) = 0;

    virtual const schemval::IValidator& validator() const = 0;
    virtual void setValidator(const std::shared_ptr<const schemval::IValidator>& validator) = 0;

    virtual const Context& context() const = 0;
    virtual Context& context() = 0;

    virtual std::shared_ptr<const RunState> runState() const = 0;
};

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_IBUILDCTX_HPP
