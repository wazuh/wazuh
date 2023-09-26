#ifndef BK_IBK_HPP
#define BK_IBK_HPP

#include <memory>
#include <string>

#include <expression.hpp> // TODO Should move this to backend interface?

namespace bk
{

/**
 * @brief Represents an backend event produced by the backend.
 * Contains the result of the processing of the data and the traces
 * generated during the analysis.
 *
 * @tparam T The type of the data that is ingested.
 */
template<typename T = std::string>
class IEvent
{

public:
public:
    virtual IEvent& setData(T&& data) = 0;
    virtual const T& getData() const = 0;

    virtual IEvent& addTrace(std::string&& trace) = 0;
    virtual const std::list<std::string>& getTraces() const = 0;
    virtual void clearTraces() = 0;

    virtual ~IEvent() = default; 
};

/**
 * @brief Interface for the backend.
 *
 * @tparam T The type of the data that is ingested.
 */
template<typename T = std::string>
class IBk
{

public:
    /**
     * @brief Build the backend from the expression.
     *
     * @param expression The expression to build the backend from.
     */
    virtual void build(const base::Expression& expression) = 0;

    /**
     * @brief Ingest the data into the backend.
     *
     * @param data The data to ingest.
     *
     * @throw std::runtime_error If the backend is not built.
     * TODO: blocking or non-blocking?, should return a future, status, IEvent or something else?
     * TODO: should be thread safe?
     */
    virtual void ingest(T&& data) = 0;

    /**
     * @brief Get The last event produced by the backend.
     *
     * @return const IEvent<T>& The last event produced by the backend.
     * @throw std::runtime_error If the backend is not built.
     */
    virtual const IEvent<T>& getEvent() const = 0;

    /**
     * @brief Get the reference to the last event produced by the backend.
     * @return IEvent<T>& The reference to the last event produced by the backend.
     * @throw std::runtime_error If the backend is not built.
     */
    virtual IEvent<T>& getEvent() = 0;

    /**
     * @brief Print the graph of the backend.
     *
     * @return std::string
     */
    virtual std::string print() const = 0;

    /**
     * @brief Close the backend and free the resources. 
     *
     * After calling this method, the backend is not usable anymore.
     */
    virtual void close() = 0;

    /**
     * @brief Check if the backend is already built.
     *
     */
    virtual bool isBuilded() const = 0;
};

} // namespace bk

#endif