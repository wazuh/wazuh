#ifndef _BUILDER_BUILDERS_ARGUMENT_HPP
#define _BUILDER_BUILDERS_ARGUMENT_HPP

#include <memory>
#include <string>
#include <variant>

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
 *
 * Stores either a json::Json (for complex values like objects, arrays, numbers, bools)
 * or a plain std::string (for string-only values), avoiding the overhead of a full
 * rapidjson::Document when only a string is needed.
 */
class Value : public Argument
{
private:
    /// Storage: either a shared json::Json or a plain string.
    std::variant<std::shared_ptr<const json::Json>, std::string> m_value;

public:
    Value()
        : m_value(std::make_shared<const json::Json>())
    {
    }

    /**
     * @brief Construct a Value from a JSON value (compact copy).
     *
     * Stored as a compact document (json::Json::compact — small allocator, ~4 KB instead
     * of the default 64 KB chunk), since the shared value may be captured into
     * policy-lifetime operation closures via sharedValue().
     *
     * @param value JSON value to store.
     */
    explicit Value(const json::Json& value)
        : m_value(std::make_shared<const json::Json>(value.compact()))
    {
    }

    /**
     * @brief Construct a Value from a JSON value (compact copy; the source is discarded).
     * @param value JSON value to store.
     */
    explicit Value(json::Json&& value)
        : m_value(std::make_shared<const json::Json>(value.compact()))
    {
    }

    /**
     * @brief Construct a Value from a string (no json::Json overhead).
     * @param str String value to store.
     */
    explicit Value(std::string&& str)
        : m_value(std::move(str))
    {
    }

    /**
     * @brief Construct a Value from a string (copy).
     * @param str String value to store.
     */
    explicit Value(const std::string& str)
        : m_value(str)
    {
    }

    /** @brief Check if this Value stores a string directly (without json::Json). */
    bool isStringValue() const { return std::holds_alternative<std::string>(m_value); }

    /**
     * @brief Get the string value referencing internal storage (zero-copy), mirroring
     * json::Json::getString.
     *
     * On success @p out references this Value's own storage and stays valid only while the
     * Value is alive and unmodified. Copy the view into an owned std::string before storing
     * it in a long-lived object or capturing it in a per-event operation.
     *
     * @param out Output string_view, only assigned on success.
     * @return json::RetGet::Success if the Value holds a string, otherwise
     *         json::RetGet::WrongType / NotFound (delegated to json::Json::getString).
     */
    json::RetGet getString(std::string_view& out) const
    {
        if (std::holds_alternative<std::string>(m_value))
        {
            out = std::get<std::string>(m_value);
            return json::RetGet::Success;
        }
        return std::get<std::shared_ptr<const json::Json>>(m_value)->getString(out);
    }

    /** @brief Get the JSON type without triggering lazy json::Json creation for string Values. */
    json::Json::Type type() const
    {
        if (std::holds_alternative<std::string>(m_value))
        {
            return json::Json::Type::String;
        }
        return std::get<std::shared_ptr<const json::Json>>(m_value)->type();
    }

    /** @brief Get the stored JSON value. Materializes a json::Json for string-only Values.
     *
     * Returned by value; string-only Values keep their lightweight std::string storage.
     * Only used at build time, so the per-call materialization is not on the hot path.
     * Do not bind the result to a const reference; keep it by value if it must outlive
     * the full expression.
     */
    [[nodiscard]] json::Json value() const
    {
        if (std::holds_alternative<std::shared_ptr<const json::Json>>(m_value))
        {
            return *std::get<std::shared_ptr<const json::Json>>(m_value);
        }
        json::Json j;
        j.setString(std::get<std::string>(m_value));
        return j;
    }

    /** @brief Get a shared json::Json for the value (zero-copy for the json variant).
     *
     * The string variant is materialized as a compact document, since callers capture the
     * result into policy-lifetime operation closures (a standard document would pin a
     * 64 KB chunk per captured value).
     */
    [[nodiscard]] std::shared_ptr<const json::Json> sharedValue() const
    {
        if (std::holds_alternative<std::shared_ptr<const json::Json>>(m_value))
        {
            return std::get<std::shared_ptr<const json::Json>>(m_value);
        }
        json::Json j;
        j.setString(std::get<std::string>(m_value));
        return std::make_shared<const json::Json>(j.compact());
    }

    /** @copydoc Argument::isValue */
    bool isValue() const override { return true; }
    /** @copydoc Argument::str */
    std::string str() const override
    {
        if (std::holds_alternative<std::shared_ptr<const json::Json>>(m_value))
        {
            return std::get<std::shared_ptr<const json::Json>>(m_value)->str();
        }
        json::Json j;
        j.setString(std::get<std::string>(m_value));
        return j.str();
    }
};

using OpArg = std::shared_ptr<Argument>; ///< Shared pointer to an operation argument.

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_ARGUMENT_HPP
