#ifndef _H_BASE_MACROS
#define _H_BASE_MACROS
#include <utility>

#define CONCAT1(x, y) x##y
#define CONCAT(x, y)  CONCAT1(x, y)
#define STRINGIFY(x)  STRINGIFY2(x)
#define STRINGIFY2(x) #x

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

#ifdef WAZUH_DEBUG
void wazuhAssertImpl(const char *, const char *, const char *, int);
void wazuhAssertMsgImpl(const char *expr,
                        const char *file,
                        const char *func,
                        int line,
                        const char *fmt,
                        ...);

// TODO __FILE_NAME__ is gcc specific
#define WAZUH_ASSERT(expr)                                                     \
    do                                                                         \
    {                                                                          \
        if (!(expr))                                                           \
            wazuhAssertImpl(                                                   \
                STRINGIFY(expr), __BASE_FILE__, __func__, __LINE__);           \
        else                                                                   \
            ((void)0);                                                         \
    } while (0);

#define WAZUH_ASSERT_MSG(expr, msg, ...)                                       \
    do                                                                         \
    {                                                                          \
        if (!(expr))                                                           \
            wazuhAssertMsgImpl(STRINGIFY(expr),                                \
                               __BASE_FILE__,                                  \
                               __func__,                                       \
                               __LINE__,                                       \
                               msg,                                            \
                               ##__VA_ARGS__);                                 \
        else                                                                   \
            ((void)0);                                                         \
    } while (0);

#define WAZUH_VERIFY(expr) WAZUH_ASSERT(expr);
#define WAZUH_VERIFY_MSG(expr, msg, ...)                                       \
    WAZUH_ASSERT_MSG(expr, msg, ##__VA_ARGS__)

#else
#define WAZUH_ASSERT(x)
#define WAZUH_ASSERT_MSG(x, y, ...)
#define WAZUH_VERIFY(x)             x
#define WAZUH_VERIFY_MSG(x, y, ...) x
// TODO Implement FAIL macros if they are needed/useful
#endif

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
