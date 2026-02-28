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
 * @brief It is the base class for all other tokens.
 *
 */
class BaseToken : public std::enable_shared_from_this<BaseToken>
{
protected:
    BaseToken() = default;

public:
    /**
     * @brief Create a new BaseToken.
     *
     * @return std::shared_ptr<BaseToken>
     */
    [[nodiscard]] static std::shared_ptr<BaseToken> create()
    {
        return std::shared_ptr<BaseToken>(new BaseToken());
    }

    virtual ~BaseToken() = default;

    /** @brief Check if this token holds a JSON type. */
    virtual bool isJType() const { return false; }
    /** @brief Check if this token holds a schema type. */
    virtual bool isSType() const { return false; }
    /** @brief Check if this token holds a JSON value. */
    virtual bool isValue() const { return false; }
};

/**
 * @brief Token that holds a JSON type.
 *
 */
class JTypeToken final : public BaseToken
{
private:
    explicit JTypeToken(json::Json::Type type)
        : m_type(type)
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
     * @return std::shared_ptr<JTypeToken>
     */
    [[nodiscard]] static std::shared_ptr<JTypeToken> create(json::Json::Type type)
    {
        return std::shared_ptr<JTypeToken>(new JTypeToken(type));
    }

    /** @copydoc BaseToken::isJType */
    bool isJType() const override { return true; }
    /** @brief Get the JSON type held by this token. */
    json::Json::Type type() const { return m_type; }
};

/**
 * @brief Token that holds a schema type.
 *
 */
class STypeToken final : public BaseToken
{
private:
    explicit STypeToken(Type type)
        : m_type(type)
    {
    }

    Type m_type;

public:
    /**
     * @brief Create a new STypeToken. Specifies the schema type and whether the token is an array.
     *
     * @param type The schema type.
     * @return std::shared_ptr<STypeToken>
     */
    [[nodiscard]] static std::shared_ptr<STypeToken> create(Type type)
    {
        return std::shared_ptr<STypeToken>(new STypeToken(type));
    }

    /** @copydoc BaseToken::isSType */
    bool isSType() const override { return true; }
    /** @brief Get the schema type held by this token. */
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
        : m_value(value)
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

    /** @copydoc BaseToken::isValue */
    bool isValue() const override { return true; }
    /** @brief Get the JSON value held by this token. */
    const json::Json& value() const { return m_value; }
};

using ValueValidator = std::function<base::OptError(const json::Json&)>; ///< Validates a JSON value.
using ValidationToken = std::shared_ptr<BaseToken>;                    ///< Token describing a validation intent.

/**
 * @brief Wrap a ValueValidator so it validates each element of an array individually.
 *
 * @param validator The per-element validator.
 * @return ValueValidator A validator that applies the original validator to each array element,
 *         or to the value directly if it is not an array. Returns nullptr if the input is nullptr.
 */
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
            return validator(value);
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
    /**
     * @brief Construct a new ValidationResult.
     *
     * @param validator Runtime validator, or nullptr if no runtime validation is needed.
     */
    explicit ValidationResult(const ValueValidator& validator = nullptr)
        : m_validator(validator)
    {
    }

    /**
     * @brief Check if runtime validation is required.
     *
     * @return true if a runtime validator is present.
     */
    bool needsRuntimeValidation() const { return m_validator != nullptr; }

    /**
     * @brief Get the runtime validator function.
     *
     * @return ValueValidator The validator, or nullptr.
     */
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
 * @brief Request validation for array elements instead of the whole array.
 *
 * Used by builders that operate on individual entries (e.g. append/contains) to ensure we keep the runtime validator
 * associated with the item type and still detect array/type mismatches during build time.
 *
 * @return ValidationToken
 */
inline ValidationToken elementValidationToken()
{
    return BaseToken::create();
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

    return STypeToken::create(validator.getType(reference));
}

} // namespace schemf
#endif // _SCHEMF_IVALIDATOR_HPP
