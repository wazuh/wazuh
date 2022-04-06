#ifndef _H_BASE_MACROS
#define _H_BASE_MACROS
#include <utility>

#define WAZUH_DISABLE_COPY(ClassName)                                          \
    ClassName(const ClassName &) = delete;                                     \
    ClassName(ClassName &&) = delete;

#define WAZUH_DISABLE_ASSIGN(ClassName)                                        \
    const ClassName &operator=(const ClassName &) = delete;                    \
    void operator=(ClassName &&) = delete;

#define WAZUH_DISABLE_COPY_ASSIGN(ClassName)                                   \
    ClassName(const ClassName &) = delete;                                     \
    ClassName(ClassName &&) = delete;                                          \
    const ClassName &operator=(const ClassName &) = delete;                    \
    void operator=(ClassName &&) = delete;

#define CONCAT1(x, y) x##y
#define CONCAT(x, y) CONCAT1(x, y)

// Utility macro to defer something to the end of the scope
template<typename Func>
struct _deferImpl
{
    Func f;
    _deferImpl(Func &&func)
        : f(std::move(func))
    {
    }
    ~_deferImpl()
    {
        f();
    }
};

template<class F>
inline _deferImpl<F> _deferFunc(F &&f)
{
    return _deferImpl<F>(std::forward<F>(f));
}

#define _defer(x) auto CONCAT(annon, __LINE__) = _deferFunc([&] x);
#endif
