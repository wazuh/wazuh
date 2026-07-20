#ifndef _BUILDER_BUILDERS_ARGUMENT_HPP
#define _BUILDER_BUILDERS_ARGUMENT_HPP

#include <memory>
#include <string>

#include <base/json.hpp>

#include "syntax.hpp"

namespace builder::builders
{

class Reference;
class Value;

/**
 * @brief Base class for operation arguments (either a reference or a value).
 */
class Argument : public std::enable_shared_from_this<Argument>
{
public:
    virtual ~Argument() = default;
    /** @brief Check if this argument is a reference. */
    virtual bool isReference() const { return false; }
    /** @brief Check if this argument is a value. */
    virtual bool isValue() const { return false; }
    /** @brief Get the string representation of the argument. */
    virtual std::string str() const { return ""; }

protected:
    Argument() = default;
};

/**
 * @brief An argument that refers to an event field by dot-path.
 */
class Reference : public Argument
{
private:
    std::string m_dotPath;  ///< Dot-separated field path.
    std::string m_jsonPath; ///< JSON-pointer field path.

public:
    Reference() = default;

    /**
     * @brief Set the reference path.
     * @param dotPath Dot-separated field path.
     */
    void set(const std::string& dotPath)
    {
        m_dotPath = dotPath;
        m_jsonPath = json::Json::formatJsonPath(dotPath);
    }

    /**
     * @brief Construct a Reference from a dot-separated path.
     * @param dotPath Dot-separated field path.
     */
    explicit Reference(const std::string& dotPath) { set(dotPath); }

    /** @brief Get the dot-separated field path. */
    const std::string& dotPath() const { return m_dotPath; }
    /** @brief Get the JSON-pointer field path. */
    const std::string& jsonPath() const { return m_jsonPath; }

    /** @copydoc Argument::isReference */
    bool isReference() const override { return true; }
    /** @copydoc Argument::str */
    std::string str() const override { return std::string {syntax::field::REF_ANCHOR} + m_dotPath; }
};

/**
 * @brief An argument holding a literal JSON value.
 */
class Value : public Argument
{
private:
    json::Json m_value; ///< The JSON value.

public:
    Value() = default;

    /**
     * @brief Set the value.
     * @param value JSON value to store.
     */
    void set(const json::Json& value)
    {
        auto tmp = json::Json(value);
        m_value = std::move(tmp);
    }

    /**
     * @brief Construct a Value from a JSON value.
     * @param value JSON value to store.
     */
    explicit Value(const json::Json& value) { set(value); }

    /** @brief Get the stored JSON value. */
    const json::Json& value() const { return m_value; }

    /** @copydoc Argument::isValue */
    bool isValue() const override { return true; }
    /** @copydoc Argument::str */
    std::string str() const override { return m_value.str(); }
};

using OpArg = std::shared_ptr<Argument>; ///< Shared pointer to an operation argument.

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_ARGUMENT_HPP
