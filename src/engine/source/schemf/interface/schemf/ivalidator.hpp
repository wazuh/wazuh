#ifndef _SCHEMF_IVALIDATOR_HPP
#define _SCHEMF_IVALIDATOR_HPP

#include <functional>
#include <memory>

#include <base/error.hpp>
#include <base/json.hpp>
#include <schemf/ischema.hpp>
#include <schemf/type.hpp>

namespace schemf
{

/**
 * @brief This token only holds the is array information. It is the base class for all other tokens.
 *
 */
class BaseToken : public std::enable_shared_from_this<BaseToken>
{
protected:
    bool m_isArray;
    BaseToken()
        : m_isArray(false)
    {
    }

    explicit BaseToken(bool isArray)
        : m_isArray(isArray)
    {
    }

public:
    /**
     * @brief Create a new BaseToken. Specifies whether the token is an array.
     *
     * @param isArray Default is false.
     * @return std::shared_ptr<BaseToken>
     */
    [[nodiscard]] static std::shared_ptr<BaseToken> create(bool isArray = false)
    {
        return std::shared_ptr<BaseToken>(new BaseToken(isArray));
    }

    virtual ~BaseToken() = default;

    bool isArray() const { return m_isArray; }

    virtual bool isJType() const { return false; }
    virtual bool isSType() const { return false; }
    virtual bool isValue() const { return false; }
};

/**
 * @brief Token that holds a JSON type.
 *
 */
class JTypeToken final : public BaseToken
{
private:
    explicit JTypeToken(json::Json::Type type, bool isArray)
        : BaseToken(isArray)
        , m_type(type)
    {
        if (type == json::Json::Type::Array)
        {
            throw std::invalid_argument("JTypeToken cannot be of type Array");
        }
    }

    json::Json::Type m_type;

public:
    /**
     * @brief Create a new JTypeToken. Specifies the JSON type and whether the token is an array.
     *
     * @param type The JSON type. Array is not allowed.
     * @param isArray Default is false.
     * @return std::shared_ptr<JTypeToken>
     */
    [[nodiscard]] static std::shared_ptr<JTypeToken> create(json::Json::Type type, bool isArray = false)
    {
        return std::shared_ptr<JTypeToken>(new JTypeToken(type, isArray));
    }

    bool isJType() const override { return true; }
    json::Json::Type type() const { return m_type; }
};

/**
 * @brief Token that holds a schema type.
 *
 */
class STypeToken final : public BaseToken
{
private:
    explicit STypeToken(Type type, bool isArray)
        : BaseToken(isArray)
        , m_type(type)
    {
    }

    Type m_type;

public:
    /**
     * @brief Create a new STypeToken. Specifies the schema type and whether the token is an array.
     *
     * @param type The schema type.
     * @param isArray Default is false.
     * @return std::shared_ptr<STypeToken>
     */
    [[nodiscard]] static std::shared_ptr<STypeToken> create(Type type, bool isArray = false)
    {
        return std::shared_ptr<STypeToken>(new STypeToken(type, isArray));
    }

    bool isSType() const override { return true; }
    Type type() const { return m_type; }
};

/**
 * @brief Token that holds a JSON value.
 *
 */
class ValueToken final : public BaseToken
{
private:
    explicit ValueToken(const json::Json& value)
        : BaseToken(value.type() == json::Json::Type::Array)
        , m_value(value)
    {
    }

    json::Json m_value;

public:
    /**
     * @brief Create a new ValueToken. Specifies the JSON value. Whether the token is an array is inferred from the
     * value.
     *
     * @param value The JSON value.
     * @return std::shared_ptr<ValueToken>
     */
    [[nodiscard]] static std::shared_ptr<ValueToken> create(const json::Json& value)
    {
        return std::shared_ptr<ValueToken>(new ValueToken(value));
    }

    bool isValue() const override { return true; }
    const json::Json& value() const { return m_value; }
};

using ValueValidator = std::function<base::OptError(const json::Json&)>;
using ValidationToken = std::shared_ptr<BaseToken>;

inline ValueValidator asArray(const ValueValidator& validator)
{
    if (validator == nullptr)
    {
        return nullptr;
    }

    return [validator](const json::Json& value) -> base::OptError
    {
        if (!value.isArray())
        {
            return base::Error {"Value must be an array"};
        }

        // TODO: Update when iterator over json::Json is available
        auto array = value.getArray().value();
        for (const auto& item : array)
        {
            auto res = validator(item);
            if (base::isError(res))
            {
                return res;
            }
        }

        return base::noError();
    };
}

/**
 * @brief Result of a build-time validation.
 *
 * Specifies if the runtime validation is needed and the runtime validation function.
 *
 */
class ValidationResult
{
private:
    ValueValidator m_validator;

public:
    explicit ValidationResult(const ValueValidator& validator = nullptr)
        : m_validator(validator)
    {
    }

    bool needsRuntimeValidation() const { return m_validator != nullptr; }

    ValueValidator getValidator() const { return m_validator; }
};

/**
 * @brief Interface for a schema validator.
 *
 */
class IValidator : public ISchema
{
public:
    virtual ~IValidator() = default;

    /**
     * @brief Check if an operation is valid for a field.
     *
     * @param name Name of the field.
     * @param token Information about the operation intent on the field.
     * @return base::OptError
     */
    virtual base::RespOrError<ValidationResult> validate(const DotPath& name, const ValidationToken& token) const = 0;
};

/**
 * @brief Token that forces runtime validation. Build-time validation is always successful.
 *
 * @return ValidationToken
 */
inline ValidationToken runtimeValidation()
{
    return nullptr;
}

/**
 * @brief Token that checks if the field is an array. Always needs runtime validation.
 *
 * @return ValidationToken
 */
inline ValidationToken isArrayToken()
{
    return BaseToken::create(true);
}

/**
 * @brief Token that checks if the field is not an array. Always needs runtime validation.
 *
 * @return ValidationToken
 */
inline ValidationToken isNotArrayToken()
{
    return BaseToken::create(false);
}

/**
 * @brief Create a schema type token from a reference. If the field does not exist, runtime validation is forced.
 *
 * @param reference Reference to the field.
 * @param validator The schema validator to get the type from.
 * @return ValidationToken
 */
inline ValidationToken tokenFromReference(const DotPath& reference, const IValidator& validator)
{
    if (!validator.hasField(reference))
    {
        return runtimeValidation();
    }

    return STypeToken::create(validator.getType(reference), validator.isArray(reference));
}

} // namespace schemf
#endif // _SCHEMF_IVALIDATOR_HPP
