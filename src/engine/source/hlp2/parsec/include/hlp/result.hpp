#ifndef _HLP_RESULT_HPP
#define _HLP_RESULT_HPP

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <hlp/trace.hpp>

namespace parsec
{
/**
 * @brief Return type of parser
 *
 * @tparam T type of the contained value
 */
template<typename T>
class Result
{
private:
    /* value */
    std::optional<T> m_value;
    /* trace */
    std::shared_ptr<Trace> m_trace;

public:
    Result() = default;
    ~Result() = default;
    Result(std::optional<T>&& value, std::shared_ptr<Trace>&& trace)
        : m_value {std::move(value)}
        , m_trace {std::move(trace)}

    {
    }
    Result(const Result<T>& other)
        : m_value {other.m_value}
        , m_trace {other.m_trace}
    {
    }
    Result(Result<T>&& other) noexcept
        : m_value {std::move(other.m_value)}
        , m_trace {std::move(other.m_trace)}
    {
    }
    Result<T>& operator=(const Result<T>& other)
    {
        m_value = other.m_value;
        m_trace = other.m_trace;
        return *this;
    }
    Result<T>& operator=(Result<T>&& other) noexcept
    {
        m_value = std::move(other.m_value);
        m_trace = std::move(other.m_trace);
        return *this;
    }

    bool operator==(const Result<T>& other) const
    {
        return m_value == other.m_value && m_trace == other.m_trace;
    }
    bool operator!=(const Result<T>& other) const { return !(*this == other); }

    /**
     * @brief Check if the result is a success
     *
     * @return true if res contains a value
     * @return false if res contains an error
     * @throw std::runtime_error if the result is not initialized
     */
    bool success() const { return m_trace->success(); }

    /**
     * @brief Check if the result is a failure
     *
     * @return true if res contains an error
     * @return false if res contains a value
     * @throw std::runtime_error if the result is not initialized
     */
    bool failure() const { return !success(); }

    /**
     * @brief Get the value
     *
     * @return const T& the value
     *
     * @pre success() == true
     * @throws std::bad_optional_access if success() == false
     */
    const T& value() const { return *m_value; }

    /**
     * @brief Get the value
     *
     * @return T&& the value
     *
     * @pre success() == true
     * @throws std::bad_optional_access if success() == false
     */
    T&& value() { return std::move(*m_value); }

    /**
     * @brief Get the error
     *
     * @return const std::string& the error
     *
     * @pre failure() == true
     * @throw std::bad_optional_access if failure() == false
     */
    const std::string& error() const { return m_trace->message().value(); }

    /**
     * @brief Get the trace
     *
     * @return const Trace& the trace
     *
     * @pre m_trace != nullptr
     * @throw segfault if m_trace == nullptr
     */
    const Trace& trace() const { return *m_trace; }

    /**
     * @brief Get the trace ptr
     *
     * @return std::shared_ptr<Trace>&& the trace ptr
     * @warning this object is left in undefined state
     */
    std::shared_ptr<Trace>&& getTracePtr() { return std::move(m_trace); }

    /**
     * @brief Get the index
     *
     * @return size_t the index
     */
    size_t index() const { return m_trace->index(); }
};

namespace internal
{
// Helper to assert that all arguments are rvalues in variadic templates
// Abuses the fact that only rvalues can be casted to const rvalues
// ref:
// https://stackoverflow.com/questions/45514116/have-rvalue-reference-instead-of-forwarding-reference-with-variadic-template
// TLDR: use in discarded decltype of varidaic template function
template<typename... Rvalues>
void assertRvalues(const Rvalues&&...) {};
} // namespace internal

/**
 * @brief Create a success result
 *
 * @tparam T type of the value returned by the parser
 * @tparam Traces Variadic template parameter for inner traces
 * @param value value returned by the parser
 * @param index index pointing to the next character not consumed by the parser
 * @param trace optional trace for this result (if any)
 * @param traces traces of combinated parsers (if any)
 *
 * @return Result<T> success result
 */
template<typename T, typename... Traces>
auto makeSuccess(T&& value,
                 size_t index,
                 Trace::messageT&& trace = std::nullopt,
                 Traces&&... traces)
    -> decltype(internal::assertRvalues(std::forward<Traces>(traces)...), Result<T> {})
{
    // Generate innerTrace list with move semantics using tuple folding expression
    // ref:
    // https://stackoverflow.com/questions/1198260/how-can-you-iterate-over-the-elements-of-an-stdtuple
    // https://en.cppreference.com/w/cpp/language/fold
    // Since tuples cannot be iterated with range-based for loop, we use a fold expression
    // Initialization lists will force to include {} in the api instead of variadic
    // arguments

    // Do only if there is at least one innerTrace
    Trace::nestedTracesT innerTrace = std::nullopt;
    auto size = sizeof...(traces);
    if (size >= 1)
    {
        innerTrace = Trace::traceContainerT {};
        // Move-Fold expression, since we assert only rvalues are passed
        (innerTrace.value().push_back(std::forward<Traces>(traces)), ...);
    }

    return Result<T> {
        std::make_optional<T>(std::move(value)),
        std::make_shared<Trace>(true, index, std::move(trace), std::move(innerTrace))};
}

/**
 * @brief Create a failure result
 *
 * @tparam T type of the value returned by the parser
 * @tparam Traces Variadic template parameter for inner traces
 * @param error error message
 * @param index index pointing to the next character not consumed by the parser
 * @param traces traces of combinated parsers (if any)
 *
 * @return Result<T> failure result
 */
template<typename T, typename... Traces>
auto makeError(std::string&& error, size_t index, Traces&&... traces)
    -> decltype(internal::assertRvalues(std::forward<Traces>(traces)...), Result<T> {})
{
    // Use fold expression as explained in makeSuccess
    auto size = sizeof...(traces);
    Trace::nestedTracesT innerTrace = std::nullopt;
    if (size >= 1)
    {
        innerTrace = Trace::traceContainerT {};
        (innerTrace.value().push_back(std::forward<Traces>(traces)), ...);
    }

    return Result<T> {
        std::nullopt,
        std::make_shared<Trace>(false,
                                index,
                                std::make_optional<std::string>(std::move(error)),
                                std::move(innerTrace))};
}

/**
 * @brief Create a success result
 *
 * @tparam T type of the value returned by the parser
 * @param valuePtr value returned by the parser
 * @param index index pointing to the next character not consumed by the parser
 * @param trace optional with trace (if any)
 * @param innerTrace traces of combinated parsers (if any)
 *
 * @return Result<T> success result
 */
template<typename T>
Result<T> makeSuccessFromList(T&& value,
                      size_t index,
                      Trace::messageT&& trace = std::nullopt,
                      Trace::nestedTracesT&& innerTrace = std::nullopt)
{
    return Result<T> {
        std::make_optional<T>(std::move(value)),
        std::make_shared<Trace>(true, index, std::move(trace), std::move(innerTrace))};
}
} // namespace parsec

#endif // _HLP_RESULT_HPP
