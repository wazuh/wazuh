#include <type_traits>
#include <string>
#include <iostream>

namespace utils {
/**
 * @brief check wether a type has a method which complies with the required signature.
 * This tool is based on https://codereview.stackexchange.com/questions/92993/template-method-checker
 * and it is here to help get proper error messages from the compiler.
 * 
 * @tparam ypename 
 * @tparam typename 
 * @tparam T 
 */
template <typename, typename, typename T>
struct has_method
{
    static_assert(std::integral_constant<T, false>::value,
                  "Third template parameter needs to be of function type.");
};

template <typename C, class caller, typename Ret, typename... Args>
struct has_method<C, caller, Ret(Args...)>
{
private:
    template <typename T>
    static constexpr auto check(T *) ->
        typename std::is_same<decltype(std::declval<caller>().template call<T>(
                                  std::declval<Args>()...)),
                              Ret>::type
    {
        return typename std::is_same<
            decltype(std::declval<caller>().template call<T>(
                std::declval<Args>()...)),
            Ret>::type();
        // return to surpresswarnings
    }

    template <typename>
    static constexpr std::false_type check(...)
    {
        return std::false_type();
    };

    typedef decltype(check<C>(0)) type;

public:
    static constexpr bool value = type::value;
};

struct existent_caller
{
    template <class T, typename... Args>
    constexpr auto call(Args... args) const
        -> decltype(std::declval<T>().existent(args...))
    {
        return decltype(std::declval<T>().existent(args...))();
        // return to surpresswarnings
    }
};

struct nonexsistent_caller
{
    template <class T, typename... Args>
    constexpr auto call(Args... args) const
        -> decltype(std::declval<T>().nonexsistent(args...));
};

} // namespace utils