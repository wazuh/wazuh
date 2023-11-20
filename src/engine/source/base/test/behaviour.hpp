#ifndef _BASE_TEST_BEHAVIOUR_HPP
#define _BASE_TEST_BEHAVIOUR_HPP

#include <functional>
#include <memory>
#include <variant>

namespace base::test
{

struct None{};

template<typename R, typename... A>
class InnerExpected
{
public:
    using Ret = R;
    using Behaviour = std::function<Ret(A...)>;
    using Param = std::variant<Behaviour, Ret>;
    using OptParam = std::optional<Param>;

private:
    Behaviour m_behaviour;
    Ret m_fixedRet;

public:
    InnerExpected(Behaviour behaviour, Ret fixedRet)
        : m_behaviour(behaviour)
        , m_fixedRet(fixedRet)
    {
    }

    template<typename... Args>
    Ret operator()(Args... args) const
    {
        if (m_behaviour)
        {
            return m_behaviour(std::forward<Args>(args)...);
        }

        return m_fixedRet;
    }

    void operator()() const {}
};

template<typename Success, typename Failure>
class Expected
{
private:
    std::shared_ptr<Success> m_success;
    std::shared_ptr<Failure> m_failure;

public:
    Expected()
        : m_success(nullptr)
        , m_failure(nullptr)
    {
    }

    Expected(std::shared_ptr<Success>&& success, std::shared_ptr<Failure>&& failure)
        : m_success(std::move(success))
        , m_failure(std::move(failure))
    {
    }

    explicit operator bool() const { return m_success != nullptr; }

    const Success& succCase() const
    {
        if (m_success == nullptr)
        {
            throw std::runtime_error("Expected success but got failure");
        }
        return *m_success;
    }

    const Failure& failCase() const
    {
        if (m_failure == nullptr)
        {
            throw std::runtime_error("Expected failure but got success");
        }
        return *m_failure;
    }

    static auto success()
    {
        return [](typename Success::OptParam optParam = std::nullopt) -> Expected
        {
            std::shared_ptr<Success> success;
            if (!optParam)
            {
                success = std::make_shared<Success>(nullptr, typename Success::Ret {});
            }
            else
            {
                auto param = *optParam;

                if (std::holds_alternative<typename Success::Behaviour>(param))
                {
                    success = std::make_shared<Success>(std::get<typename Success::Behaviour>(param),
                                                        typename Success::Ret {});
                }
                else
                {
                    success = std::make_shared<Success>(nullptr, std::get<typename Success::Ret>(param));
                }
            }

            return Expected(std::move(success), nullptr);
        };
    }

    static auto failure()
    {
        return [](typename Failure::OptParam optParam = std::nullopt) -> Expected
        {
            std::shared_ptr<Failure> failure;
            if (!optParam)
            {
                failure = std::make_shared<Failure>(nullptr, typename Failure::Ret {});
            }
            else
            {
                auto param = *optParam;

                if (std::holds_alternative<typename Failure::Behaviour>(param))
                {
                    failure = std::make_shared<Failure>(std::get<typename Failure::Behaviour>(param),
                                                        typename Failure::Ret {});
                }
                else
                {
                    failure = std::make_shared<Failure>(nullptr, std::get<typename Failure::Ret>(param));
                }
            }

            return Expected(nullptr, std::move(failure));
        };
    }
};

} // namespace base::test

#endif // _BASE_TEST_BEHAVIOUR_HPP
