#ifndef _CHAIN_OF_RESPONSABILITY_HPP
#define _CHAIN_OF_RESPONSABILITY_HPP

#include <memory>

template<typename T>
/**
 * @brief Template handle class for the steps on the chain
 *
 */
class Handler
{
public:
    virtual ~Handler() = default;

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    virtual std::shared_ptr<Handler> setNext(const std::shared_ptr<Handler> handler) = 0;

    /**
     * @brief Triggers handler action
     *
     * @param data template type used by the handler
     * @return T next handler on the chain
     */
    virtual T handleRequest(T data) = 0;
};

template<typename T>
/**
 * @brief AbstractHandler class
 *
 */
class AbstractHandler : public Handler<T>
{
private:
    /**
     * @brief Next handler on the chain
     *
     */
    std::shared_ptr<Handler<T>> m_next;

public:
    AbstractHandler() = default;

    virtual ~AbstractHandler() = default;

    /**
     * @brief Set the next handler on the chain
     *
     * @param requestNext handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler<T>> the same handler that has been set as
     * next
     */
    virtual std::shared_ptr<Handler<T>> setNext(const std::shared_ptr<Handler<T>> requestNext) override
    {
        m_next = requestNext;
        return requestNext;
    }

    /**
     * @brief Triggers handler action
     *
     * @param data template type used by the handler
     * @return T next handler on the chain if exists, data otherwise
     */
    virtual T handleRequest(T data) override
    {
        if (m_next)
        {
            return m_next->handleRequest(data);
        }
        return data;
    }

    /**
     * @brief Get next step on the chain
     *
     * @return std::shared_ptr<AbstractHandler> next handler on the chain
     */
    std::shared_ptr<AbstractHandler> next() const
    {
        return m_next;
    }
};

#endif // _CHAIN_OF_RESPONSABILITY_HPP
