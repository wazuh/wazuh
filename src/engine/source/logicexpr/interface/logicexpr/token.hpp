#ifndef _LOGICEXPR_TOKEN_HPP
#define _LOGICEXPR_TOKEN_HPP

#include <memory>
#include <stdexcept>

namespace logicexpr::parser
{

class BaseToken : public std::enable_shared_from_this<BaseToken>
{
protected:
    BaseToken(std::string&& text, size_t pos)
        : m_text {std::move(text)}
        , m_pos {pos}
    {
    }

    std::string m_text;
    size_t m_pos;

public:
    virtual ~BaseToken() = default;

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

    virtual bool isOperator() const { return false; }
    virtual bool isUnaryOperator() const { return false; }
    virtual bool isBinaryOperator() const { return false; }

    virtual bool isOr() const { return false; }
    virtual bool isAnd() const { return false; }
    virtual bool isNot() const { return false; }

    virtual bool isTerm() const { return false; }

    virtual bool isParenthesisOpen() const { return false; }
    virtual bool isParenthesisClose() const { return false; }

    const std::string& text() const { return m_text; }
    size_t pos() const { return m_pos; }

    inline friend bool operator==(const BaseToken& lhs, const BaseToken& rhs)
    {
        return lhs.text() == rhs.text() && lhs.pos() == rhs.pos();
    }
};

template<typename BuildToken>
class TermToken final : public BaseToken
{
private:
    BuildToken m_buildToken;

    TermToken(BuildToken&& buildToken, std::string&& text, size_t pos)
        : BaseToken(std::move(text), pos)
        , m_buildToken {std::move(buildToken)}
    {
    }

public:
    ~TermToken() = default;

    [[nodiscard]] static std::shared_ptr<TermToken> create(BuildToken&& buildToken, const std::string& text, size_t pos)
    {
        return std::shared_ptr<TermToken>(new TermToken(std::move(buildToken), std::string(text), pos));
    }

    bool isTerm() const override { return true; }

    BuildToken& buildToken() { return m_buildToken; }
};

namespace details
{

template<typename PrecedencePolicy>
class OpToken : public BaseToken
{
protected:
    OpToken(std::string&& text, size_t pos)
        : BaseToken(std::move(text), pos)
    {
    }

public:
    virtual ~OpToken() = default;

    bool isOperator() const override { return true; }

    size_t precedence() const { return PrecedencePolicy::precedence(*this); }
};

template<typename PrecedencePolicy>
class UnaryOpToken : public OpToken<PrecedencePolicy>
{
protected:
    UnaryOpToken(std::string&& text, size_t pos)
        : OpToken<PrecedencePolicy>(std::move(text), pos)
    {
    }

public:
    virtual ~UnaryOpToken() = default;

    bool isUnaryOperator() const override { return true; }
};

template<typename PrecedencePolicy>
class BinaryOpToken : public OpToken<PrecedencePolicy>
{
protected:
    BinaryOpToken(std::string&& text, size_t pos)
        : OpToken<PrecedencePolicy>(std::move(text), pos)
    {
    }

public:
    virtual ~BinaryOpToken() = default;

    bool isBinaryOperator() const override { return true; }
};

template<typename PrecedencePolicy>
class OrToken final : public BinaryOpToken<PrecedencePolicy>
{
private:
    OrToken(std::string&& text, size_t pos)
        : BinaryOpToken<PrecedencePolicy>(std::move(text), pos)
    {
    }

public:
    ~OrToken() = default;

    [[nodiscard]] static std::shared_ptr<OrToken> create(const std::string& text, size_t pos)
    {
        return std::shared_ptr<OrToken>(new OrToken(std::string(text), pos));
    }

    bool isOr() const override { return true; }
};

template<typename PrecedencePolicy>
class AndToken final : public BinaryOpToken<PrecedencePolicy>
{
private:
    AndToken(std::string&& text, size_t pos)
        : BinaryOpToken<PrecedencePolicy>(std::move(text), pos)
    {
    }

public:
    ~AndToken() = default;

    [[nodiscard]] static std::shared_ptr<AndToken> create(const std::string& text, size_t pos)
    {
        return std::shared_ptr<AndToken>(new AndToken(std::string(text), pos));
    }

    bool isAnd() const override { return true; }
};

template<typename PrecedencePolicy>
class NotToken final : public UnaryOpToken<PrecedencePolicy>
{
private:
    NotToken(std::string&& text, size_t pos)
        : UnaryOpToken<PrecedencePolicy>(std::move(text), pos)
    {
    }

public:
    ~NotToken() = default;

    [[nodiscard]] static std::shared_ptr<NotToken> create(const std::string& text, size_t pos)
    {
        return std::shared_ptr<NotToken>(new NotToken(std::string(text), pos));
    }

    bool isNot() const override { return true; }
};

struct DefaultPrecedencePolicy
{
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

class ParenthOpenToken final : public BaseToken
{
private:
    ParenthOpenToken(std::string&& text, size_t pos)
        : BaseToken(std::move(text), pos)
    {
    }

public:
    ~ParenthOpenToken() = default;

    [[nodiscard]] static std::shared_ptr<ParenthOpenToken> create(const std::string& text, size_t pos)
    {
        return std::shared_ptr<ParenthOpenToken>(new ParenthOpenToken(std::string(text), pos));
    }

    bool isParenthesisOpen() const override { return true; }
};

class ParenthCloseToken final : public BaseToken
{
private:
    ParenthCloseToken(std::string&& text, size_t pos)
        : BaseToken(std::move(text), pos)
    {
    }

public:
    ~ParenthCloseToken() = default;

    [[nodiscard]] static std::shared_ptr<ParenthCloseToken> create(const std::string& text, size_t pos)
    {
        return std::shared_ptr<ParenthCloseToken>(new ParenthCloseToken(std::string(text), pos));
    }

    bool isParenthesisClose() const override { return true; }
};

using Token = std::shared_ptr<BaseToken>;

using OpToken = details::OpToken<details::DefaultPrecedencePolicy>;
using UnaryOpToken = details::UnaryOpToken<details::DefaultPrecedencePolicy>;
using BinaryOpToken = details::BinaryOpToken<details::DefaultPrecedencePolicy>;
using OrToken = details::OrToken<details::DefaultPrecedencePolicy>;
using AndToken = details::AndToken<details::DefaultPrecedencePolicy>;
using NotToken = details::NotToken<details::DefaultPrecedencePolicy>;

namespace traits
{
    template<typename T>
    struct is_term_token : std::false_type
    {
    };

    template<typename T>
    struct is_term_token<std::shared_ptr<TermToken<T>>> : std::true_type
    {
    };
}

} // namespace logicexpr::parser

#endif // _LOGICEXPR_TOKEN_HPP
