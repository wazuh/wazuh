#ifndef _LOGIC_EXPRESSION_PARSER_H
#define _LOGIC_EXPRESSION_PARSER_H

#include <functional>
#include <memory>
#include <sstream>
#include <stack>
#include <string>
#include <string_view>

#include <fmt/format.h>

namespace
{
constexpr int ERROR_TOKEN_START = -1;
constexpr int TOKEN_START = 0;
constexpr int OPERATOR_TOKEN_START = 10;
} // namespace

/**
 * @brief Namespace containing parsing logic expressions functionality
 */
namespace logicExpression
{
namespace parser
{

/**
 * @brief Identifies token type.
 *
 * Operators are ordered by ascendent precedence.
 */
enum TokenType
{
    ERROR_TYPE = ERROR_TOKEN_START,
    TERM = TOKEN_START,
    PARENTHESIS_OPEN,
    PARENTHESIS_CLOSE,
    OPERATOR_OR = OPERATOR_TOKEN_START,
    OPERATOR_AND,
    OPERATOR_NOT,
};

/**
 * @brief Represents a token.
 */
struct Token
{
    // Token type
    TokenType m_type;

    // Parsed token string
    std::string m_text;

    // Token position in the input string, used for error reporting
    size_t m_position;

    /**
     * @brief Construct a new Token object
     *
     * @param type token type
     * @param text token string
     * @param position position in the input string
     */
    Token(TokenType type, std::string_view text, size_t position)
        : m_type {type}
        , m_text {text}
        , m_position {position}
    {
    }

    /**
     * @brief Construct a new empty Token object with error type
     *
     */
    Token()
        : m_type {ERROR_TYPE}
    {
    }

    /**
     * @brief Construct a new Token object from a token string
     *
     * @param text token string
     * @param position position in the input string
     * @return Token
     *
     * @throws std::runtime_error if token string is invalid
     */
    static Token parseToken(std::string_view text, size_t position)
    {
        if (text.empty())
        {
            throw std::runtime_error(
                "Engine logic expression parser: Got an empty token.");
        }

        if (text == "(")
        {
            return Token {TokenType::PARENTHESIS_OPEN, text, position};
        }
        else if (text == ")")
        {
            return Token {TokenType::PARENTHESIS_CLOSE, text, position};
        }
        else if (text == "AND")
        {
            return Token {TokenType::OPERATOR_AND, text, position};
        }
        else if (text == "OR")
        {
            return Token {TokenType::OPERATOR_OR, text, position};
        }
        else if (text == "NOT")
        {
            return Token {TokenType::OPERATOR_NOT, text, position};
        }
        else
        {
            return Token {TokenType::TERM, text, position};
        }
    }

    /**
     * @brief Check if this token is an operator
     *
     * @return true if this token is an operator
     * @return false otherwise
     */
    bool isOperator() const { return m_type >= OPERATOR_TOKEN_START; }

    /**
     * @brief Check if this token is a unary operator
     *
     * @return true if this token is a unary operator
     * @return false otherwise
     */
    bool isUnaryOperator() const
    {
        return isOperator() && (m_type == TokenType::OPERATOR_NOT);
    }

    /**
     * @brief Check if this token is a binary operator
     *
     * @return true if this token is a binary operator
     * @return false otherwise
     */
    bool isBinaryOperator() const
    {
        return isOperator()
               && (m_type == TokenType::OPERATOR_OR || m_type == TokenType::OPERATOR_AND);
    }

    /**
     * @brief Compare precedence with other Token operator
     *
     * @param other Token operator to be compared
     * @return true if this Token has higher or equal precedence than other
     * @return false otherwise
     *
     * @throw std::logic_error if other or this is not an operator
     */
    bool operator>=(const Token& other) const
    {
        if (!isOperator() || !other.isOperator())
        {
            throw std::logic_error(fmt::format(
                "Engine logic expression parser: Comparing precendence between something "
                "that is not an operator: Comparing \"{}\" and \"{}\".",
                m_text,
                other.m_text));
        }

        return m_type >= other.m_type;
    }

    /**
     * @brief Returns a string representation of this token
     *
     * @return std::string
     */
    std::string toString() const { return m_text; }
};

/**
 * @brief Represents an expression node, where the whole expression is a binary
 * tree linked by m_left and m_right.
 *
 */
class Expression : public std::enable_shared_from_this<Expression>
{
public:
    // Token of this node
    Token m_token;
    // Childs if any
    std::shared_ptr<Expression> m_left, m_right;

    /**
     * @brief Get the Ptr object
     *
     * @return std::shared_ptr<Expression>
     */
    std::shared_ptr<Expression> getPtr() { return shared_from_this(); }

    /**
     * @brief Get the const Ptr object
     *
     * @return std::shared_ptr<const Expression>
     */
    std::shared_ptr<const Expression> getPtr() const { return shared_from_this(); }

    /**
     * @brief Create a new Expression object from a postfix token stack
     *
     * @param postfix stack with all tokens if postfix notation
     * @return std::shared_ptr<Expression> root of the expression tree
     * @throw std::logic_error if the stack is empty or contains an unbalanced
     * expression
     */
    [[nodiscard]] static std::shared_ptr<Expression> create(std::stack<Token>& postfix)
    {
        return std::shared_ptr<Expression>(new Expression(postfix));
    }

    /**
     * @brief Creates empty expression
     *
     * @return std::shared_ptr<Expression>
     */
    [[nodiscard]] static std::shared_ptr<Expression> create()
    {
        return std::shared_ptr<Expression>(new Expression());
    }

    /**
     * @brief Visit Expression tree in pre-order
     *
     * @param expr Expression root of the tree to be visited
     * @param visitor visitor function
     */
    static void visitPreOrder(const std::shared_ptr<const Expression>& expr,
                              std::function<void(const Expression&)> visitor)
    {
        if (expr)
        {
            visitor(*expr);
            if (expr->m_left)
            {
                visitPreOrder(expr->m_left, visitor);
            }
            if (expr->m_right)
            {
                visitPreOrder(expr->m_right, visitor);
            }
        }
    }

    /**
     * @brief Obtains the graphviz representation string of the expression tree
     *
     * @param root root of the expression tree
     * @return std::string
     */
    static std::string toDotString(const std::shared_ptr<const Expression>& root)
    {
        // Not using visitPreOrder because we need to handle repeated names and
        // we need to now if current node is left or right child
        std::stringstream ss;
        ss << "digraph G {" << std::endl;

        auto visit = [&ss](const std::shared_ptr<const Expression>& root,
                           int depth,
                           int width,
                           auto& visit_ref) -> void
        {
            ss << fmt::format("{}_{}{};", root->m_token.m_text, depth, width)
               << std::endl;
            if (root->m_left)
            {
                ss << fmt::format("{}_{}{} -> {}_{}{};",
                                  root->m_token.m_text,
                                  depth,
                                  width,
                                  root->m_left->m_token.m_text,
                                  depth + 1,
                                  0)
                   << std::endl;

                visit_ref(root->m_left, depth + 1, 0, visit_ref);
            }
            if (root->m_right)
            {
                ss << fmt::format("{}_{}{} -> {}_{}{};",
                                  root->m_token.m_text,
                                  depth,
                                  width,
                                  root->m_right->m_token.m_text,
                                  depth + 1,
                                  1)
                   << std::endl;

                visit_ref(root->m_right, depth + 1, 1, visit_ref);
            }
        };

        visit(root, 0, 0, visit);
        ss << "}" << std::endl;
        return ss.str();
    }

private:
    // Made private so that only create() can be used to create an Expression
    Expression(std::stack<Token>& postfix)

    {
        if (postfix.empty())
        {
            throw std::logic_error(
                "Engine logic expression parser: Got unbalanced expression.");
        }
        if (postfix.top().m_type == TokenType::ERROR_TYPE)
        {
            throw std::logic_error(
                "Engine logic expression parser: Got invalid token with \"ERROR_TYPE\".");
        }
        if (postfix.top().m_type == TokenType::PARENTHESIS_OPEN
            || postfix.top().m_type == TokenType::PARENTHESIS_CLOSE)
        {
            throw std::logic_error("Engine logic expression parser: Got invalid token "
                                   "with \"PARENTHESIS_OPEN\" or \"PARENTHESIS_CLOSE\".");
        }

        m_token = std::move(postfix.top());
        postfix.pop();

        if (m_token.isUnaryOperator())
        {
            m_left = Expression::create(postfix);
        }
        else if (m_token.isBinaryOperator())
        {
            m_left = Expression::create(postfix);
            m_right = Expression::create(postfix);
        }
    }

    // Made private so that only create() can be used to create an Expression
    Expression() = default;
};

/**
 * @brief Creates and returns a new Expression binary tree from a raw string
 *
 * @param rawExpression raw string expression in infix notation
 * @return std::shared_ptr<Expression> root of the expression tree
 *
 * @throw std::logic_exception if the expression is not valid
 */
std::shared_ptr<Expression> parse(const std::string& rawExpression);

} // namespace parser
} // namespace logicExpression

#endif // _LOGIC_EXPRESSION_PARSER_H
