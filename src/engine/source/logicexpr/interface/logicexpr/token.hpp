#ifndef _LOGICEXPR_TOKEN_HPP
#define _LOGICEXPR_TOKEN_HPP

#include <memory>
#include <stdexcept>

/**
 * @brief Defines the base token class and its derived classes for the logic expression parser.
 *
 * This file defines the BaseToken class, which is the base class for all tokens used in the logic expression parser.
 * It also defines the derived classes for the different types of tokens, such as TermToken, OpToken, UnaryOpToken, BinaryOpToken, OrToken, AndToken, NotToken, ParenthesisOpenToken, and ParenthesisCloseToken.
 *
 * The BaseToken class provides virtual functions to check the type of the token, as well as functions to get the token's text and position.
 * It also provides overloaded operators to compare tokens based on their text and position, and to compare their precedence.
 *
 * The derived classes provide additional functionality specific to their type of token, such as the buildToken function in TermToken, and the precedence function in OpToken.
 */

namespace logicexpr::parser
{

/**
 * @brief Base class for all tokens used in the logic expression parser.
 *
 */
class BaseToken : public std::enable_shared_from_this<BaseToken>
{
protected:
    /**
     * @brief Construct new Token
     *
     * @param text Token text
     * @param pos Text position of the token in the expression
     */
    BaseToken(std::string&& text, size_t pos)
        : m_text {std::move(text)}
        , m_pos {pos}
    {
    }

    std::string m_text; ///< Token text
    size_t m_pos;      ///< Text position of the token in the expression

public:
    virtual ~BaseToken() = default;

    /**
     * @brief Returns a shared pointer to a derived class of BaseToken.
     *
     * This function returns a shared pointer to a derived class of BaseToken, specified by the template parameter Derived.
     * It performs a dynamic cast of the shared pointer to the derived class, and throws a runtime_error if the cast fails.
     *
     * @tparam Derived The derived class of BaseToken to cast the shared pointer to.
     * @return std::shared_ptr<Derived> A shared pointer to the derived class of BaseToken.
     * @throws std::runtime_error if the dynamic cast fails.
     */
    template<typename Derived>
    std::shared_ptr<Derived> getPtr()
    {
        static_assert(std::is_base_of_v<BaseToken, Derived>, "Derived must be a subclass of BaseToken");
        std::shared_ptr<Derived> ptr = std::dynamic_pointer_cast<Derived>(shared_from_this());
        if (!ptr)
        {
            throw std::runtime_error("Tried to get sibling token instead of derived token");
        }

        return ptr;
    }

    /**
     * @brief Checks if the token is a operator.
     *
     * @return true if the token is a operator, false otherwise.
     */
    virtual bool isOperator() const { return false; }

    /**
     * @brief Checks if the token is a unary operator.
     *
     * @return true if the token is a unary operator, false otherwise.
     */
    virtual bool isUnaryOperator() const { return false; }

    /**
     * @brief Checks if the token is a binary operator.
     *
     * @return true if the token is a binary operator, false otherwise.
     */
    virtual bool isBinaryOperator() const { return false; }

    /**
     * @brief Checks if the token is an OR operator.
     *
     * @return true if the token is an OR operator, false otherwise.
     */
    virtual bool isOr() const { return false; }

    /**
     * @brief Checks if the token is an AND operator.
     *
     * @return true if the token is an AND operator, false otherwise.
     */
    virtual bool isAnd() const { return false; }

    /**
     * @brief Checks if the token is a NOT operator.
     *
     * @return true if the token is a NOT operator, false otherwise.
     */
    virtual bool isNot() const { return false; }

    /**
     * @brief Checks if the token is a term.
     *
     * @return true if the token is a term, false otherwise.
     */
    virtual bool isTerm() const { return false; }

    /**
     * @brief Checks if the token is an open parenthesis.
     *
     * @return true if the token is an open parenthesis, false otherwise.
     */
    virtual bool isParenthesisOpen() const { return false; }

    /**
     * @brief Checks if the token is a close parenthesis.
     *
     * @return true if the token is a close parenthesis, false otherwise.
     */
    virtual bool isParenthesisClose() const { return false; }

    /**
     * @brief Returns the text of the token.
     *
     * @return const std::string& The text of the token.
     */
    const std::string& text() const { return m_text; }

    /**
     * @brief Returns the position of the token in the expression.
     *
     * @return size_t The position of the token in the expression.
     */
    size_t pos() const { return m_pos; }

    /**
     * @brief Overloaded operator to compare two tokens based on their text and position.
     *
     * @param lhs The left-hand side token to compare.
     * @param rhs The right-hand side token to compare.
     * @return true if the tokens are equal, false otherwise.
     */
    inline friend bool operator==(const BaseToken& lhs, const BaseToken& rhs)
    {
        return lhs.text() == rhs.text() && lhs.pos() == rhs.pos();
    }

};
/**
 * @brief A class representing a term token in a logical expression.
 *
 * This class inherits from BaseToken and represents a term token in a logical expression.
 * It contains a BuildToken object and provides a method to create a shared pointer to a TermToken object.
 *
 * @tparam BuildToken The type of the BuildToken object.
 */
template<typename BuildToken>
class TermToken final : public BaseToken
{
private:
    BuildToken m_buildToken;

    /**
     * @brief Constructs a TermToken object.
     *
     * Constructs a TermToken object with a BuildToken object, a text string and a position.
     *
     * @param buildToken The BuildToken object.
     * @param text The text string.
     * @param pos The position.
     */
    TermToken(BuildToken&& buildToken, std::string&& text, size_t pos)
        : BaseToken(std::move(text), pos)
        , m_buildToken {std::move(buildToken)}
    {
    }

public:
    ~TermToken() = default;

    /**
     * @brief Creates a shared pointer to a TermToken object.
     *
     * Creates a shared pointer to a TermToken object with a BuildToken object, a text string and a position.
     *
     * @param buildToken The BuildToken object.
     * @param text The text string.
     * @param pos The position.
     * @return std::shared_ptr<TermToken> A shared pointer to a TermToken object.
     */
    [[nodiscard]] static std::shared_ptr<TermToken> create(BuildToken&& buildToken, const std::string& text, size_t pos)
    {
        return std::shared_ptr<TermToken>(new TermToken(std::move(buildToken), std::string(text), pos));
    }

    /**
     * @brief Checks if the token is a term token.
     *
     * Overrides the isTerm() method of the BaseToken class to return true.
     *
     * @return true if the token is a term token, false otherwise.
     */
    bool isTerm() const override { return true; }

    /**
     * @brief Returns the BuildToken object.
     *
     * Returns the BuildToken object contained in the TermToken object.
     *
     * @return BuildToken& The BuildToken object.
     */
    BuildToken& buildToken() { return m_buildToken; }
};

namespace details
{
/**
 * @brief A class representing an operator token in a logical expression.
 *
 * This class inherits from BaseToken and represents an operator token in a logical expression.
 * It contains a PrecedencePolicy object and provides methods to create shared pointers to OrToken, AndToken and NotToken objects.
 *
 * @tparam PrecedencePolicy The type of the PrecedencePolicy object.
 */
template<typename PrecedencePolicy>
class OpToken : public BaseToken
{
protected:
    /**
     * @brief Constructs an OpToken object.
     *
     * Constructs an OpToken object with a text string and a position.
     *
     * @param text The text string.
     * @param pos The position.
     */
    OpToken(std::string&& text, size_t pos)
        : BaseToken(std::move(text), pos)
    {
    }

public:
    virtual ~OpToken() = default;

    /**
     * @brief Checks if the token is an operator token.
     *
     * Overrides the isOperator() method of the BaseToken class to return true.
     *
     * @return true if the token is an operator token, false otherwise.
     */
    bool isOperator() const override { return true; }

    /**
     * @brief Returns the precedence of the operator token.
     *
     * Returns the precedence of the operator token using the PrecedencePolicy object.
     *
     * @return size_t The precedence of the operator token.
     */
    size_t precedence() const { return PrecedencePolicy::precedence(*this); }
};

/**
 * @brief A class representing a unary operator token in a logical expression.
 *
 * This class inherits from OpToken and represents a unary operator token in a logical expression.
 *
 * @tparam PrecedencePolicy The type of the PrecedencePolicy object.
 */
template<typename PrecedencePolicy>
class UnaryOpToken : public OpToken<PrecedencePolicy>
{
protected:
    /**
     * @brief Constructs a UnaryOpToken object.
     *
     * Constructs a UnaryOpToken object with a text string and a position.
     *
     * @param text The text string.
     * @param pos The position.
     */
    UnaryOpToken(std::string&& text, size_t pos)
        : OpToken<PrecedencePolicy>(std::move(text), pos)
    {
    }

public:
    virtual ~UnaryOpToken() = default;

    /**
     * @brief Checks if the token is a unary operator token.
     *
     * Overrides the isUnaryOperator() method of the OpToken class to return true.
     *
     * @return true if the token is a unary operator token, false otherwise.
     */
    bool isUnaryOperator() const override { return true; }
};

/**
 * @brief A class representing a binary operator token in a logical expression.
 *
 * This class inherits from OpToken and represents a binary operator token in a logical expression.
 *
 * @tparam PrecedencePolicy The type of the PrecedencePolicy object.
 */
template<typename PrecedencePolicy>
class BinaryOpToken : public OpToken<PrecedencePolicy>
{
protected:
    /**
     * @brief Constructs a BinaryOpToken object.
     *
     * Constructs a BinaryOpToken object with a text string and a position.
     *
     * @param text The text string.
     * @param pos The position.
     */
    BinaryOpToken(std::string&& text, size_t pos)
        : OpToken<PrecedencePolicy>(std::move(text), pos)
    {
    }

public:
    virtual ~BinaryOpToken() = default;

    /**
     * @brief Checks if the token is a binary operator token.
     *
     * Overrides the isBinaryOperator() method of the OpToken class to return true.
     *
     * @return true if the token is a binary operator token, false otherwise.
     */
    bool isBinaryOperator() const override { return true; }
};

/**
 * @brief A class representing an OR operator token in a logical expression.
 *
 * This class inherits from BinaryOpToken and represents an OR operator token in a logical expression.
 *
 * @tparam PrecedencePolicy The type of the PrecedencePolicy object.
 */
template<typename PrecedencePolicy>
class OrToken final : public BinaryOpToken<PrecedencePolicy>
{
private:
    /**
     * @brief Constructs an OrToken object.
     *
     * Constructs an OrToken object with a text string and a position.
     *
     * @param text The text string.
     * @param pos The position.
     */
    OrToken(std::string&& text, size_t pos)
        : BinaryOpToken<PrecedencePolicy>(std::move(text), pos)
    {
    }

public:
    ~OrToken() = default;

    /**
     * @brief Creates a shared pointer to an OrToken object.
     *
     * Creates a shared pointer to an OrToken object with a text string and a position.
     *
     * @param text The text string.
     * @param pos The position.
     * @return std::shared_ptr<OrToken> A shared pointer to an OrToken object.
     */
    [[nodiscard]] static std::shared_ptr<OrToken> create(const std::string& text, size_t pos)
    {
        return std::shared_ptr<OrToken>(new OrToken(std::string(text), pos));
    }

    /**
     * @brief Checks if the token is an OR operator token.
     *
     * Overrides the isOr() method of the BinaryOpToken class to return true.
     *
     * @return true if the token is an OR operator token, false otherwise.
     */
    bool isOr() const override { return true; }
};

/**
 * @brief A class representing an AND operator token in a logical expression.
 *
 * This class inherits from BinaryOpToken and represents an AND operator token in a logical expression.
 *
 * @tparam PrecedencePolicy The type of the PrecedencePolicy object.
 */
template<typename PrecedencePolicy>
class AndToken final : public BinaryOpToken<PrecedencePolicy>
{
private:
    /**
     * @brief Constructs an AndToken object.
     *
     * Constructs an AndToken object with a text string and a position.
     *
     * @param text The text string.
     * @param pos The position.
     */
    AndToken(std::string&& text, size_t pos)
        : BinaryOpToken<PrecedencePolicy>(std::move(text), pos)
    {
    }

public:
    ~AndToken() = default;

    /**
     * @brief Creates a shared pointer to an AndToken object.
     *
     * Creates a shared pointer to an AndToken object with a text string and a position.
     *
     * @param text The text string.
     * @param pos The position.
     * @return std::shared_ptr<AndToken> A shared pointer to an AndToken object.
     */
    [[nodiscard]] static std::shared_ptr<AndToken> create(const std::string& text, size_t pos)
    {
        return std::shared_ptr<AndToken>(new AndToken(std::string(text), pos));
    }

    /**
     * @brief Checks if the token is an AND operator token.
     *
     * Overrides the isAnd() method of the BinaryOpToken class to return true.
     *
     * @return true if the token is an AND operator token, false otherwise.
     */
    bool isAnd() const override { return true; }
};

/**
 * @brief A class representing a NOT operator token in a logical expression.
 *
 * This class inherits from UnaryOpToken and represents a NOT operator token in a logical expression.
 *
 * @tparam PrecedencePolicy The type of the PrecedencePolicy object.
 */
template<typename PrecedencePolicy>
class NotToken final : public UnaryOpToken<PrecedencePolicy>
{
private:
    /**
     * @brief Constructs a NotToken object.
     *
     * Constructs a NotToken object with a text string and a position.
     *
     * @param text The text string.
     * @param pos The position.
     */
    NotToken(std::string&& text, size_t pos)
        : UnaryOpToken<PrecedencePolicy>(std::move(text), pos)
    {
    }

public:
    ~NotToken() = default;

    /**
     * @brief Creates a shared pointer to a NotToken object.
     *
     * Creates a shared pointer to a NotToken object with a text string and a position.
     *
     * @param text The text string.
     * @param pos The position.
     * @return std::shared_ptr<NotToken> A shared pointer to a NotToken object.
     */
    [[nodiscard]] static std::shared_ptr<NotToken> create(const std::string& text, size_t pos)
    {
        return std::shared_ptr<NotToken>(new NotToken(std::string(text), pos));
    }

    /**
     * @brief Checks if the token is a NOT operator token.
     *
     * Overrides the isNot() method of the UnaryOpToken class to return true.
     *
     * @return true if the token is a NOT operator token, false otherwise.
     */
    bool isNot() const override { return true; }
};

/**
 * @brief A struct representing the default precedence policy for logical expression tokens.
 *
 * This struct defines the default precedence policy for logical expression tokens. It provides a static method
 * to get the precedence of a given token based on its type. The precedence values are defined as follows:
 * - OR operator: 1
 * - AND operator: 2
 * - NOT operator: 3
 *
 * @tparam PrecedencePolicy The type of the PrecedencePolicy object.
 */
struct DefaultPrecedencePolicy
{
    /**
     * @brief Gets the precedence of a given token based on its type.
     *
     * Gets the precedence of a given token based on its type. The precedence values are defined as follows:
     * - OR operator: 1
     * - AND operator: 2
     * - NOT operator: 3
     *
     * @param token The token.
     * @return size_t The precedence of the token.
     * @throws std::logic_error if the token is not a defined operator.
     */
    static size_t precedence(const BaseToken& token)
    {
        if (token.isOr())
        {
            return 1;
        }
        else if (token.isAnd())
        {
            return 2;
        }
        else if (token.isNot())
        {
            return 3;
        }
        else
        {
            throw std::logic_error("Tried to get precedence of not defined operator");
        }
    }
};

} // namespace details


/**
 * @brief A class representing a left parenthesis token.
 *
 * This class represents a left parenthesis token in a logical expression. It inherits from the BaseToken class
 * and overrides the isParenthesisOpen() method to return true. It also provides a static create() method to create
 * a shared pointer to a ParenthOpenToken object.
 */
class ParenthOpenToken final : public BaseToken
{
private:
    ParenthOpenToken(std::string&& text, size_t pos)
        : BaseToken(std::move(text), pos)
    {
    }

public:
    ~ParenthOpenToken() = default;

    /**
     * @brief Creates a shared pointer to a ParenthOpenToken object.
     *
     * Creates a shared pointer to a ParenthOpenToken object with a text string and a position.
     *
     * @param text The text string.
     * @param pos The position.
     * @return std::shared_ptr<ParenthOpenToken> A shared pointer to a ParenthOpenToken object.
     */
    [[nodiscard]] static std::shared_ptr<ParenthOpenToken> create(const std::string& text, size_t pos)
    {
        return std::shared_ptr<ParenthOpenToken>(new ParenthOpenToken(std::string(text), pos));
    }

    /**
     * @brief Checks if the token is a left parenthesis token.
     *
     * Overrides the isParenthesisOpen() method of the BaseToken class to return true.
     *
     * @return true if the token is a left parenthesis token, false otherwise.
     */
    bool isParenthesisOpen() const override { return true; }
};

/**
 * @brief A class representing a right parenthesis token.
 *
 * This class represents a right parenthesis token in a logical expression. It inherits from the BaseToken class
 * and overrides the isParenthesisClose() method to return true. It also provides a static create() method to create
 * a shared pointer to a ParenthCloseToken object.
 */
class ParenthCloseToken final : public BaseToken
{
private:
    ParenthCloseToken(std::string&& text, size_t pos)
        : BaseToken(std::move(text), pos)
    {
    }

public:
    ~ParenthCloseToken() = default;

    /**
     * @brief Creates a shared pointer to a ParenthCloseToken object.
     *
     * Creates a shared pointer to a ParenthCloseToken object with a text string and a position.
     *
     * @param text The text string.
     * @param pos The position.
     * @return std::shared_ptr<ParenthCloseToken> A shared pointer to a ParenthCloseToken object.
     */
    [[nodiscard]] static std::shared_ptr<ParenthCloseToken> create(const std::string& text, size_t pos)
    {
        return std::shared_ptr<ParenthCloseToken>(new ParenthCloseToken(std::string(text), pos));
    }

    /**
     * @brief Checks if the token is a right parenthesis token.
     *
     * Overrides the isParenthesisClose() method of the BaseToken class to return true.
     *
     * @return true if the token is a right parenthesis token, false otherwise.
     */
    bool isParenthesisClose() const override { return true; }
};

using Token = std::shared_ptr<BaseToken>;

using OpToken = details::OpToken<details::DefaultPrecedencePolicy>;
using UnaryOpToken = details::UnaryOpToken<details::DefaultPrecedencePolicy>;
using BinaryOpToken = details::BinaryOpToken<details::DefaultPrecedencePolicy>;
using OrToken = details::OrToken<details::DefaultPrecedencePolicy>;
using AndToken = details::AndToken<details::DefaultPrecedencePolicy>;
using NotToken = details::NotToken<details::DefaultPrecedencePolicy>;

/**
 * @brief Namespace containing traits for logical expression tokens.
 */
namespace traits
{
    /**
     * @brief Trait to check if a token is a term token.
     *
     * This trait is used to check if a token is a term token. It is implemented using std::false_type as the default
     * value and std::true_type for std::shared_ptr<TermToken<T>>.
     *
     * @tparam T The type of the token.
     */
    template<typename T>
    struct is_term_token : std::false_type
    {
    };

    /**
     * @brief Trait specialization for std::shared_ptr<TermToken<T>>.
     *
     * This trait specialization is used to set std::true_type for std::shared_ptr<TermToken<T>>.
     *
     * @tparam T The type of the token.
     */
    template<typename T>
    struct is_term_token<std::shared_ptr<TermToken<T>>> : std::true_type
    {
    };
} // namespace traits

} // namespace logicexpr::parser

#endif // _LOGICEXPR_TOKEN_HPP
